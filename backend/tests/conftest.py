"""Shared test helpers.

- make_events_parquet(tmp_path, rows) -> RunContext: canonical rows -> partitioned Parquet + `events` view
  (for detection / link tests that must not depend on ingest).
- run_ingest(raw_dir, tmp_path) -> RunContext: Stage 0 + Stage 1 exactly as run.py calls them.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest

from attacklens import config, db
from attacklens.context import RunContext
from attacklens.schemas import CANONICAL_COLUMNS, PARTITION_COLUMNS

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _install_config_cache() -> None:
    """load_config() parses ~10 YAML/JSON files (~125 ms) and tests build hundreds of contexts. Cache the parsed
    result per (config dir, file mtimes) and hand out deep copies: every caller still gets an independent dict,
    and an edit to config/ during the session invalidates the cache."""
    import copy
    import functools

    real = config.load_config

    @functools.lru_cache(maxsize=8)
    def _parsed(key: tuple) -> dict[str, Any]:
        return real(Path(key[0]))

    def cached(config_dir: Path | None = None) -> dict[str, Any]:
        d = Path(config_dir or config.CONFIG_DIR).resolve()
        stamp = tuple(sorted((p.name, p.stat().st_mtime_ns) for p in d.glob("*") if p.is_file()))
        return copy.deepcopy(_parsed((str(d), stamp)))

    cached.__wrapped__ = real  # type: ignore[attr-defined]
    config.load_config = cached


_install_config_cache()


# Default integration paths (config/integrations.yaml spool.*, live watch_dir/siem). Tests must point every
# connector / sink / status path at tmp_path (test_integrations.integrations() does); a test that falls back to
# these defaults pollutes the real status the API shows.
_REPO = Path(__file__).resolve().parents[2]
GUARDED_DIRS = (_REPO / "data" / "spool", _REPO / "data" / "raw" / "live" / "siem")


def _guarded_state() -> list[tuple[str, int, int]]:
    out = []
    for root in GUARDED_DIRS:
        if root.exists():
            out += [(p.as_posix(), p.stat().st_size, p.stat().st_mtime_ns) for p in root.rglob("*") if p.is_file()]
    return sorted(out)


@pytest.fixture(autouse=True)
def _repo_spool_untouched() -> Iterator[None]:
    """Fails the test that creates or modifies anything under data/spool or data/raw/live/siem."""
    before = _guarded_state()
    yield
    after = _guarded_state()
    if after != before:
        changed = sorted(set(after) ^ set(before))
        pytest.fail("test wrote to the repo's default integration paths (point spool.* / state / status at "
                    f"tmp_path; or another process is using data/spool right now): {changed[:5]}")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "slow: > ~5 s, not an L3 accuracy test; opt-in with -m slow or RUN_SLOW=1")
    config.addinivalue_line("markers", "sigma: runs the SigmaHQ pack (config/sigma); every other test runs with "
                                       "ATTACKLENS_SIGMA=0")
    config.addinivalue_line("markers", "live: real vendor software in Docker (tools/live, backend/tests/live); "
                                       "deselected unless -m mentions `live` or RUN_LIVE=1")


def _sigma_env(mp: pytest.MonkeyPatch, on: bool) -> None:
    if on:
        mp.delenv("ATTACKLENS_SIGMA", raising=False)
    else:
        mp.setenv("ATTACKLENS_SIGMA", "0")


# Sigma (~1700 community predicates per Stage 2) is off unless the test carries @pytest.mark.sigma, so tests that do
# not concern Sigma stay fast and exact; marked tests always run it, whatever the caller's environment. Three layers,
# because pytest sets up wider-scoped fixtures first: a module-scoped pipeline fixture (e.g. the L3 `run`) runs before
# any function fixture, so it follows its module's marker (`pytestmark = pytest.mark.sigma`) instead.
@pytest.fixture(scope="session", autouse=True)
def _sigma_off_for_session() -> Iterator[None]:
    mp = pytest.MonkeyPatch()
    _sigma_env(mp, False)
    yield
    mp.undo()


@pytest.fixture(scope="module", autouse=True)
def _sigma_per_module(request: pytest.FixtureRequest) -> Iterator[None]:
    marks = getattr(request.module, "pytestmark", None) or []
    mp = pytest.MonkeyPatch()
    _sigma_env(mp, any(m.name == "sigma" for m in (marks if isinstance(marks, list) else [marks])))
    yield
    mp.undo()


@pytest.fixture(autouse=True)
def _sigma_only_when_marked(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    _sigma_env(monkeypatch, request.node.get_closest_marker("sigma") is not None)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """`slow` tests are skipped unless selected explicitly (keeps `pytest -m "not stress"` under its budget).
    `live` tests (Docker + real vendors) are DESELECTED unless the -m expression names `live` or RUN_LIVE=1, so
    `pytest backend -m "not stress"` never starts a container."""
    import os
    markexpr = config.getoption("markexpr") or ""
    if "live" not in markexpr and os.environ.get("RUN_LIVE") != "1":
        live = [i for i in items if i.get_closest_marker("live") is not None]
        if live:
            config.hook.pytest_deselected(items=live)
            items[:] = [i for i in items if i.get_closest_marker("live") is None]
    if "slow" in markexpr or os.environ.get("RUN_SLOW") == "1":
        return
    skip = pytest.mark.skip(reason="slow: run with -m slow (or RUN_SLOW=1)")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)


def insert_rows(con: Any, table: str, col_types: list[tuple[str, str]], rows: list[list[Any]]) -> None:
    """INSERT rows (lists in col_types order) as ONE columnar statement: unnest(list::TYPE[]) per column. Same values
    as executemany (checked incl. NULLs, lists, UBIGINT > 2^63), but executemany costs ~0.5-5 ms per row."""
    if not rows:
        return
    sel = ", ".join(f'unnest(${i + 1}::{t}[]) AS "{c}"' for i, (c, t) in enumerate(col_types))
    con.execute(f"INSERT INTO {table} SELECT {sel}", [list(col) for col in zip(*rows)])


def _new_ctx(tmp_path: Path, set_name: str = "fx", raw_dir: Path | None = None) -> RunContext:
    con = db.connect(memory_limit="1GB", threads=2, temp_directory=tmp_path / "spill")
    return RunContext(set_name=set_name, raw_dir=raw_dir or tmp_path / "raw", parquet_dir=tmp_path / "pq",
                      out_dir=tmp_path / "out", con=con, cfg=config.load_config())


def make_events_parquet(tmp_path: Path, rows: list[dict[str, Any]], set_name: str = "fx") -> RunContext:
    """Write canonical rows to tmp/pq/events/source_type=…/ts_ok=…/event_day=YYYY-MM-DD/data.parquet.

    Missing columns are NULL; types come from schemas.CANONICAL_COLUMNS. Defaults: source_type 'ecs_json',
    ts_ok = ts_ms IS NOT NULL, event_day = UTC date of ts_ms, source_seq = deterministic hash of the row index,
    raw_line = JSON of the row. Returns a RunContext whose connection already has the `events` view.
    """
    unknown = {k for r in rows for k in r} - set(CANONICAL_COLUMNS)
    if unknown:
        raise KeyError(f"not canonical columns: {sorted(unknown)}")
    ctx = _new_ctx(tmp_path, set_name)
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for i, r in enumerate(rows):
        r = dict(r)
        r.setdefault("source_type", "ecs_json")
        r.setdefault("ts_ok", r.get("ts_ms") is not None)
        if "event_day" not in r:
            r["event_day"] = (datetime.fromtimestamp(r["ts_ms"] / 1000, tz=timezone.utc).date().isoformat()
                              if r.get("ts_ms") is not None else "1970-01-01")
        r.setdefault("source_seq", int.from_bytes(hashlib.sha1(f"row{i}".encode()).digest()[:8], "big"))
        r.setdefault("raw_line", json.dumps({k: v for k, v in r.items() if k != "raw_line"}, default=str,
                                            sort_keys=True))
        groups[(r["source_type"], bool(r["ts_ok"]), str(r["event_day"]))].append(r)

    data_cols = [c for c in CANONICAL_COLUMNS if c not in PARTITION_COLUMNS]
    con = ctx.con
    for (st, ok, day), grp in sorted(groups.items()):
        d = ctx.parquet_dir / "events" / f"source_type={st}" / f"ts_ok={str(ok).lower()}" / f"event_day={day}"
        d.mkdir(parents=True, exist_ok=True)
        con.execute("CREATE OR REPLACE TEMP TABLE _fx (" +
                    ", ".join(f'"{c}" {CANONICAL_COLUMNS[c]}' for c in data_cols) + ")")
        insert_rows(con, "_fx", [(c, CANONICAL_COLUMNS[c]) for c in data_cols],
                    [[r.get(c) for c in data_cols] for r in grp])
        con.execute(f"COPY _fx TO '{(d / 'data.parquet').as_posix()}' (FORMAT PARQUET)")
        con.execute("DROP TABLE _fx")
    db.register_events(con, ctx.events_glob)
    return ctx


EPISODE_TYPES: dict[str, str] = {  # DEVELOPMENT.md §15.4 episodes (subset every downstream stage reads)
    "episode_id": "VARCHAR", "rule_id": "VARCHAR", "technique_id": "VARCHAR", "sub_technique_id": "VARCHAR",
    "technique_name": "VARCHAR", "tactic": "VARCHAR", "tactic_idx": "INTEGER", "severity": "INTEGER",
    "ts_ms": "BIGINT", "last_ts_ms": "BIGINT", "source_seq": "UBIGINT", "host": "VARCHAR", "subject_host": "VARCHAR",
    "src_host": "VARCHAR", "dst_host": "VARCHAR", "src_user": "VARCHAR", "target_user": "VARCHAR",
    "src_ip": "VARCHAR", "dst_ip": "VARCHAR", "raw_alert_count": "BIGINT", "merged_alert_count": "BIGINT",
    "evidence_lines": "VARCHAR[]", "source_keys": "UBIGINT[]", "user": "VARCHAR", "bucket": "BIGINT",
    "rarity": "DOUBLE", "confidence": "DOUBLE", "is_seed": "BOOLEAN",
}


def write_episodes(ctx: RunContext, eps: list[dict[str, Any]], hubs: list[str] | None = None) -> Path:
    """Write ctx.work_dir/episodes.parquet from partial dicts (defaults filled) and optional background_hubs.

    Defaults: subject_host = host, user = coalesce(target_user, src_user), tactic_idx from the tactic, severity 80,
    confidence = severity, rarity 1.0, merged/raw count 1, last_ts_ms = ts_ms, source_seq = index + 1.
    """
    from attacklens.schemas import TACTIC_IDX
    rows = []
    for k, e in enumerate(eps):
        r = {c: None for c in EPISODE_TYPES}
        r.update({"rule_id": "fx_rule", "technique_id": "T0000", "severity": 80, "rarity": 1.0,
                  "merged_alert_count": 1, "raw_alert_count": 1, "source_seq": k + 1,
                  "evidence_lines": [f"evidence {e['episode_id']}"]})
        r.update(e)
        r.setdefault("subject_host", r["host"])
        r["subject_host"] = r["subject_host"] or r["host"]
        r["tactic_idx"] = r["tactic_idx"] or TACTIC_IDX.get(r["tactic"] or "", 0)
        r["last_ts_ms"] = r["last_ts_ms"] or r["ts_ms"]
        r["user"] = r["user"] or r["target_user"] or r["src_user"]
        r["confidence"] = float(r["severity"]) if r["confidence"] is None else r["confidence"]
        r["is_seed"] = r["confidence"] >= 65 if r["is_seed"] is None else r["is_seed"]
        r["source_keys"] = r["source_keys"] or [r["source_seq"]]
        r["bucket"] = r["bucket"] if r["bucket"] is not None else r["ts_ms"] // 300000
        rows.append(r)
    cols = list(EPISODE_TYPES)
    con = ctx.con
    con.execute("CREATE OR REPLACE TEMP TABLE _eps (" + ", ".join(f'"{c}" {t}' for c, t in EPISODE_TYPES.items())
                + ")")
    insert_rows(con, "_eps", list(EPISODE_TYPES.items()), [[r[c] for c in cols] for r in rows])
    out = ctx.work_dir / "episodes.parquet"
    con.execute(f"COPY _eps TO '{out.as_posix()}' (FORMAT PARQUET)")
    con.execute("DROP TABLE _eps")
    con.execute("CREATE OR REPLACE TEMP TABLE _hubs_fx (entity VARCHAR)")
    insert_rows(con, "_hubs_fx", [("entity", "VARCHAR")], [[h] for h in hubs or []])
    con.execute(f"COPY _hubs_fx TO '{(ctx.work_dir / 'background_hubs.parquet').as_posix()}' (FORMAT PARQUET)")
    con.execute("DROP TABLE _hubs_fx")
    return out


def run_ingest(raw_dir: Path, tmp_path: Path, set_name: str = "fx") -> RunContext:
    """Stage 0 + Stage 1 the way run.py calls them, then register the `events` view."""
    from attacklens import ingest, profile  # plain import: a broken module must fail loudly, never skip
    ctx = _new_ctx(tmp_path, set_name, raw_dir=raw_dir)
    profile.run(ctx)
    ingest.run(ctx)
    db.register_events(ctx.con, ctx.events_glob)
    return ctx


def accounting(ctx: RunContext) -> dict[str, dict[str, int]]:
    """ingest_accounting.json summed per source_type -> {source_type: {rows_in, rows_ok, dropped}}."""
    rows = json.loads((ctx.out_dir / "ingest_accounting.json").read_text(encoding="utf-8"))
    if isinstance(rows, dict):  # tolerate {"sources": [...]} wrapping
        rows = rows.get("sources", rows.get("accounting", []))
    out: dict[str, dict[str, int]] = defaultdict(lambda: {"rows_in": 0, "rows_ok": 0, "dropped": 0})
    for r in rows:
        for k in ("rows_in", "rows_ok", "dropped"):
            out[r["source_type"]][k] += int(r[k])
    return dict(out)


def query(ctx: RunContext, sql: str, params: list | None = None) -> list[dict[str, Any]]:
    cur = ctx.con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


@pytest.fixture
def events_ctx(tmp_path: Path) -> Iterator[Callable[[list[dict[str, Any]]], RunContext]]:
    """Factory fixture: events_ctx(rows) -> RunContext (connection closed at teardown)."""
    made: list[RunContext] = []

    def _make(rows: list[dict[str, Any]]) -> RunContext:
        ctx = make_events_parquet(tmp_path / f"ev{len(made)}", rows)
        made.append(ctx)
        return ctx

    yield _make
    for c in made:
        c.con.close()
