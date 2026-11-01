"""Stage 1 post-COPY checks over the canonical Parquet (DEVELOPMENT.md §4 Stage 1, no silent data loss).

1. Timestamp pile-up (sources.yaml ingest_checks.ts_pileup): ONE UTC second that holds >= max_share_of_rows of a
   source's rows AND >= min_rows rows, while the source spans >= min_span_s, AND (require_edge_or_clamped) that
   second is the source's last second or >= clamped_min_share of its rows carry the clamped fraction .999. On the
   organiser's n10 / n30 sets 68.96 % / 70.23 % of all rows carried the file's last second (.999999000).
   Small files and attack bursts never meet all of these at once. Those rows are re-marked ts_ok=false (ts_ms kept as
   evidence), so no window, baseline or link uses them; they are counted as `timestamp_pileup`.
2. Direction orientation (sources.yaml kv_sources.<source>.direction_fix): a row whose interface roles say
   internal -> wan while its src_ip is public and its dst_ip private has the two IPs swapped back (ports and byte
   counters already follow the interface direction). Counted as `direction_swapped`.
3. Exact duplicates (sources.yaml ingest_checks.duplicates): byte-identical lines of one file share source_seq =
   hash(file, line), so duplicates = rows - distinct source_seq per source (one bounded aggregate). Counted only,
   never dropped; `in_ts_ok` = the copies rules can still see (pile-up rows are already ts_ok=false).

Both only rewrite the (source_type, ts_ok, event_day) partitions that hold affected rows, in DuckDB: one bounded
GROUP BY per check, then one COPY per affected partition set. Every row is still written exactly once.
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import shutil
from pathlib import Path
from typing import Any

import duckdb

from attacklens.db import HIVE_TYPES, sql_path, sql_str
from attacklens.schemas import CANONICAL_COLUMNS, PARTITION_COLUMNS

log = logging.getLogger(__name__)

DEFAULT_INTERNAL_RE = r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|::1$|f[cd]|fe80:)"
IS_IP = r"regexp_full_match({x}, '[0-9]{{1,3}}(\.[0-9]{{1,3}}){{3}}|[0-9a-f:]*:[0-9a-f:]+')"


def _events(glob: str) -> str:
    return f"read_parquet({glob}, hive_partitioning=true, hive_types={HIVE_TYPES})"


def _pileup_cfg(cfg: dict[str, Any]) -> dict[str, Any] | None:
    c = ((cfg.get("sources") or {}).get("ingest_checks") or {}).get("ts_pileup") or {}
    if not c or not c.get("enabled", True):
        return None
    return {"share": float(c.get("max_share_of_rows", 0.05)), "min_rows": int(c.get("min_rows", 100000)),
            "span_s": int(c.get("min_span_s", 3600)), "edge": bool(c.get("require_edge_or_clamped", True)),
            "clamped": float(c.get("clamped_min_share", 0.9))}


def _swap_cfgs(cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out = {}
    for st, kcfg in ((cfg.get("sources") or {}).get("kv_sources") or {}).items():
        d = (kcfg or {}).get("direction_fix") or {}
        if d and d.get("enabled", True):
            out[str(st)] = d
    return out


def _swap_cond(d: dict[str, Any]) -> str:
    rx = sql_str(str(d.get("internal_ip_regex") or DEFAULT_INTERNAL_RE))
    src_roles = ", ".join(sql_str(str(x).lower()) for x in d.get("src_zone_in") or ["lan", "dmz"])
    dst_roles = ", ".join(sql_str(str(x).lower()) for x in d.get("dst_zone_in") or ["wan"])
    return (f"(src_zone IN ({src_roles}) AND dst_zone IN ({dst_roles}) AND src_ip IS NOT NULL AND dst_ip IS NOT NULL "
            f"AND coalesce({IS_IP.format(x='src_ip')}, FALSE) AND coalesce({IS_IP.format(x='dst_ip')}, FALSE) "
            f"AND NOT regexp_matches(src_ip, {rx}) AND regexp_matches(dst_ip, {rx}))")


def _part_dir(events_dir: Path, st: str, ok: bool, day: Any) -> Path:
    return events_dir / f"source_type={st}" / f"ts_ok={'true' if ok else 'false'}" / f"event_day={day}"


def find_pileups(con: duckdb.DuckDBPyConnection, ev: str, pc: dict[str, Any] | None) -> None:
    """Read-only: fill temp table _pile(source_type, sec, n) with the pile-up seconds (empty when pc is None)."""
    con.execute("CREATE OR REPLACE TEMP TABLE _pile (source_type VARCHAR, sec BIGINT, n BIGINT)")
    if pc:
        con.execute(f"""
            INSERT INTO _pile
            WITH t AS (SELECT source_type, count(*) AS n, max(ts_ms) // 1000 AS last_sec,
                              (max(ts_ms) - min(ts_ms)) // 1000 AS span_s FROM {ev} WHERE ts_ok GROUP BY 1),
                 s AS (SELECT source_type, ts_ms // 1000 AS sec, count(*) AS n,
                              count(*) FILTER (WHERE ts_ms % 1000 = 999) AS clamped
                       FROM {ev} WHERE ts_ok GROUP BY ALL HAVING count(*) >= {pc['min_rows']})
            SELECT s.source_type, s.sec, s.n FROM s JOIN t USING (source_type)
            WHERE s.n >= {pc['share']} * t.n AND t.span_s >= {pc['span_s']}
              AND ({'FALSE' if pc['edge'] else 'TRUE'} OR s.sec = t.last_sec OR s.clamped >= {pc['clamped']} * s.n)""")


def run(con: duckdb.DuckDBPyConnection, cfg: dict[str, Any], events_dir: Path) -> dict[str, Any]:
    """Detect and fix in place. Returns {ts_pileup: {source: {rows, seconds: [{second_utc, rows}]}},
    direction_swapped: {source: rows}}; empty dicts when nothing was found or the checks are off."""
    out: dict[str, Any] = {"ts_pileup": {}, "direction_swapped": {}, "duplicates": {}}
    if not any(events_dir.rglob("*.parquet")):
        return out
    glob = sql_path(events_dir / "**" / "*.parquet")
    ev = _events(glob)
    pc, swaps = _pileup_cfg(cfg), _swap_cfgs(cfg)
    find_pileups(con, ev, pc)
    parts: set[tuple[str, bool, Any]] = set()
    for st, sec, n, day in con.execute("SELECT source_type, sec, n, CAST(epoch_ms(sec * 1000) AS DATE) FROM _pile "
                                       "ORDER BY 1, 2").fetchall():
        e = out["ts_pileup"].setdefault(st, {"rows": 0, "seconds": []})
        e["rows"] += int(n)
        e["seconds"].append({"second_utc": _iso(int(sec)), "rows": int(n)})
        parts.add((st, True, day))
    swap_sql = {st: _swap_cond(d) for st, d in swaps.items()}
    for st, cond in swap_sql.items():
        rows = con.execute(f"SELECT ts_ok, event_day, count(*) FROM {ev} WHERE source_type = {sql_str(st)} AND {cond} "
                           "GROUP BY ALL").fetchall()
        n = sum(int(r[2]) for r in rows)
        if n:
            out["direction_swapped"][st] = n
            parts |= {(st, bool(ok), day) for ok, day, _ in rows}
    if parts:
        _rewrite(con, events_dir, sorted(parts, key=str), swap_sql, cfg)
    con.execute("DROP TABLE IF EXISTS _pile")
    if (((cfg.get("sources") or {}).get("ingest_checks") or {}).get("duplicates") or {}).get("enabled", False):
        out["duplicates"] = _duplicates(con, ev)
    for st, e in out["ts_pileup"].items():
        log.warning("ingest: %s timestamp pile-up: %d rows in %d second(s) re-marked ts_ok=false "
                    "(timestamp_pileup)", st, e["rows"], len(e["seconds"]))
    for st, n in out["direction_swapped"].items():
        log.warning("ingest: %s %d rows had src/dst IPs against their interface roles; swapped (direction_swapped)",
                    st, n)
    return out


def _duplicates(con: duckdb.DuckDBPyConnection, ev: str) -> dict[str, dict[str, int]]:
    """{source: {lines, in_ts_ok}}: extra copies of byte-identical lines (same file), total and among ts_ok rows."""
    out = {}
    for st, n, d, n_ok, d_ok in con.execute(
            f"SELECT source_type, count(*), count(DISTINCT source_seq), count(*) FILTER (WHERE ts_ok), "
            f"count(DISTINCT source_seq) FILTER (WHERE ts_ok) FROM {ev} WHERE action <> 'malformed' "
            "GROUP BY 1 ORDER BY 1").fetchall():
        if int(n) - int(d):
            out[str(st)] = {"lines": int(n) - int(d), "in_ts_ok": int(n_ok) - int(d_ok)}
            log.warning("ingest: %s %d exact duplicate lines (%d among ts_ok rows); counted, kept", st,
                        int(n) - int(d), int(n_ok) - int(d_ok))
    return out


def _iso(sec: int) -> str:
    return dt.datetime.fromtimestamp(sec, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rewrite(con: duckdb.DuckDBPyConnection, events_dir: Path, parts: list[tuple[str, bool, Any]],
             swap_sql: dict[str, str], cfg: dict[str, Any]) -> None:
    """Rewrite each affected partition with plain streaming COPYs (no partitioned writer: one 8.5 M-row partition
    with raw_line ran out of memory through PARTITION_BY): rows staying in the partition, and (ts_ok=true
    partitions) the pile-up rows moved to the ts_ok=false partition of the same day. Staged, then swapped in;
    every row is written exactly once. Files carry no partition columns, like the ingest COPY."""
    ing = (cfg.get("pipeline") or {}).get("ingest") or {}
    opts = (f"FORMAT PARQUET, COMPRESSION {ing.get('compression', 'ZSTD')}, "
            f"ROW_GROUP_SIZE {int(ing.get('row_group_size', 122880))}")
    stage = events_dir.parent / "events_fix_tmp"
    if stage.exists():
        shutil.rmtree(stage)
    secs: dict[str, list[int]] = {}
    for st, sec in con.execute("SELECT source_type, sec FROM _pile").fetchall():
        secs.setdefault(str(st), []).append(int(sec))
    moves: list[tuple[Path, Path]] = []
    originals: list[Path] = []
    for k, (st, ok, day) in enumerate(parts):
        files = sorted(_part_dir(events_dir, st, ok, day).glob("*.parquet"))
        if not files:
            continue
        originals += files
        sw = f"coalesce({swap_sql[st]}, FALSE)" if st in swap_sql else "FALSE"
        cols = [f"CASE WHEN {sw} THEN dst_ip ELSE src_ip END AS src_ip" if c == "src_ip" else
                f"CASE WHEN {sw} THEN src_ip ELSE dst_ip END AS dst_ip" if c == "dst_ip" else c
                for c in CANONICAL_COLUMNS if c not in PARTITION_COLUMNS]
        src = "read_parquet([" + ", ".join(sql_str(f.as_posix()) for f in files) + "])"
        pile = (f"(ts_ms // 1000) IN ({', '.join(str(x) for x in secs[st])})"
                if ok and secs.get(st) else "FALSE")
        outs = [(ok, f"NOT {pile}")] + ([(False, pile)] if pile != "FALSE" else [])
        for ok_out, where in outs:
            tmp = stage / f"p{k}_{int(ok_out)}.parquet"
            tmp.parent.mkdir(parents=True, exist_ok=True)
            n = con.execute(f"COPY (SELECT {', '.join(cols)} FROM {src} WHERE {where}) TO {sql_path(tmp)} ({opts})"
                            ).fetchone()
            if n and int(n[0]):
                moves.append((tmp, _part_dir(events_dir, st, ok_out, day) / f"fix_{k}_{int(ok_out)}.parquet"))
    for f in originals:
        f.unlink()
    for tmp, dest in moves:
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, dest)
    shutil.rmtree(stage, ignore_errors=True)
