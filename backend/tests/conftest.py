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


def run_ingest(raw_dir: Path, tmp_path: Path, set_name: str = "fx") -> RunContext:
    """Stage 0 + Stage 1 the way run.py calls them, then register the `events` view."""
    profile = pytest.importorskip("attacklens.profile", reason="attacklens.profile not written yet (BB-ingest)")
    ingest = pytest.importorskip("attacklens.ingest", reason="attacklens.ingest not written yet (BB-ingest)")
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
