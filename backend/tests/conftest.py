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


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "slow: > ~5 s, not an L3 accuracy test; opt-in with -m slow or RUN_SLOW=1")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """`slow` tests are skipped unless selected explicitly (keeps `pytest -m "not stress"` under its budget)."""
    import os
    if "slow" in (config.getoption("markexpr") or "") or os.environ.get("RUN_SLOW") == "1":
        return
    skip = pytest.mark.skip(reason="slow: run with -m slow (or RUN_SLOW=1)")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)


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
        con.executemany(f"INSERT INTO _fx VALUES ({', '.join('?' for _ in data_cols)})",
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
    if rows:
        con.executemany(f"INSERT INTO _eps VALUES ({', '.join('?' for _ in cols)})", [[r[c] for c in cols]
                                                                                    for r in rows])
    out = ctx.work_dir / "episodes.parquet"
    con.execute(f"COPY _eps TO '{out.as_posix()}' (FORMAT PARQUET)")
    con.execute("DROP TABLE _eps")
    con.execute("CREATE OR REPLACE TEMP TABLE _hubs_fx (entity VARCHAR)")
    if hubs:
        con.executemany("INSERT INTO _hubs_fx VALUES (?)", [(h,) for h in hubs])
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
