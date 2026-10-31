"""Stage 1: one DuckDB COPY of every profiled raw file into partitioned canonical Parquet.

Writes <parquet_dir>/events/source_type=*/ts_ok=*/event_day=*/ and out_dir/ingest_accounting.json.
Malformed lines are kept in the ts_ok=false partition with action='malformed' (raw_line NULL) so that
rows_in can be counted from the same single scan; rows without a parseable timestamp are kept with
ts_ok=false. Both count as dropped (not usable by detection) with a reason.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from attacklens import ingest_sql as q
from attacklens import profile as profile_stage
from attacklens.context import RunContext
from attacklens.db import line_reader, sql_list
from attacklens.schemas import CANONICAL_COLUMNS

log = logging.getLogger(__name__)


def _load_profile(ctx: RunContext) -> dict[str, Any]:
    if isinstance(ctx.stats.get("profile"), dict):
        return ctx.stats["profile"]
    p = ctx.out_dir / "source_profile.json"
    if p.exists():
        prof = json.loads(p.read_text(encoding="utf-8"))
        if Path(prof.get("raw_dir", "")) == Path(ctx.raw_dir).resolve():
            return prof
    log.info("no source profile for %s; running Stage 0", ctx.raw_dir)
    profile_stage.run(ctx)
    return ctx.stats["profile"]


def build_selects(prof: dict[str, Any], cfg: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    """One SELECT per (format, source_type[, csv header]) group; returns (selects, csv_groups)."""
    sources = cfg.get("sources") or {}
    pipe = cfg.get("pipeline") or {}
    formats = list((pipe.get("ingest") or {}).get("ts_formats") or [])
    root = prof["raw_dir"]
    groups: dict[tuple[Any, ...], list[str]] = {}
    for f in prof.get("files", []):
        fmt = f.get("format")
        if fmt == "unrecognized":
            continue
        key: tuple[Any, ...] = (fmt, f["source_type"])
        if fmt == "csv":
            key += (f["delimiter"], tuple(f["columns"]))
        groups.setdefault(key, []).append(f["path"])
    selects: list[str] = []
    csv_groups: list[dict[str, Any]] = []
    for key, files in groups.items():
        fmt, stype = key[0], key[1]
        if fmt == "json":
            scfg = (sources.get("json_sources") or {}).get(stype) or {}
            selects.append(q.json_select(stype, files, root, scfg, sources, formats))
        elif fmt == "cef":
            selects.append(q.cef_select(files, root, sources.get("cef") or {}, formats))
        elif fmt == "syslog":
            ing = pipe.get("ingest") or {}
            selects.append(q.syslog_select(files, root, sources.get("syslog") or {},
                                           int(pipe.get("baseline_year", 2026)),
                                           ing.get("syslog_ts_format", "%Y %b %d %H:%M:%S"), formats))
        elif fmt == "csv":
            ccfg = (sources.get("csv_sources") or {}).get(stype) or {}
            selects.append(q.csv_select(stype, files, root, key[2], list(key[3]), ccfg, formats))
            csv_groups.append({"source_type": stype, "files": files})
    return selects, csv_groups


def copy_sql(selects: list[str], cfg: dict[str, Any], events_dir: Path) -> str:
    union = " UNION ALL BY NAME ".join(f"({s})" for s in selects)
    norm = q.normalize_sql(union, cfg.get("sources") or {})
    typed = ", ".join(f"CAST({c} AS {t}) AS {c}" for c, t in CANONICAL_COLUMNS.items())
    comp = ((cfg.get("pipeline") or {}).get("ingest") or {}).get("compression", "ZSTD")
    return (f"COPY (SELECT {typed} FROM ({norm})) TO '{events_dir.as_posix()}' "
            f"(FORMAT PARQUET, PARTITION_BY (source_type, ts_ok, event_day), COMPRESSION {comp}, "
            f"OVERWRITE_OR_IGNORE)")


def _accounting(ctx: RunContext, events_dir: Path, csv_groups: list[dict[str, Any]],
                prof: dict[str, Any]) -> list[dict[str, Any]]:
    glob = (events_dir / "**" / "*.parquet").as_posix()
    rows = []
    if any(events_dir.rglob("*.parquet")):
        rows = ctx.con.execute(
            f"SELECT source_type, count(*), count(*) FILTER (WHERE ts_ok), "
            f"count(*) FILTER (WHERE action = 'malformed'), "
            f"count(*) FILTER (WHERE NOT ts_ok AND action <> 'malformed') "
            f"FROM read_parquet('{glob}', hive_partitioning=true, hive_types={{'source_type': 'VARCHAR', "
            f"'ts_ok': 'BOOLEAN', 'event_day': 'DATE'}}) GROUP BY 1 ORDER BY 1").fetchall()
    csv_in: dict[str, int] = {}
    for g in csv_groups:  # CSV rows the reader rejected never reach Parquet: count physical lines
        n = ctx.con.execute(f"SELECT count(*) FROM {line_reader(g['files'], filename=False)} "
                            f"WHERE line IS NOT NULL AND trim(line) <> ''").fetchone()[0]
        csv_in[g["source_type"]] = csv_in.get(g["source_type"], 0) + int(n) - len(g["files"])
    out: list[dict[str, Any]] = []
    for stype, written, ok, bad, nots in rows:
        rows_in = csv_in.pop(stype, int(written))
        reasons: dict[str, int] = {}
        if bad:
            reasons["malformed_line (kept in ts_ok=false, action=malformed)"] = int(bad)
        if nots:
            reasons["missing_or_unparseable_timestamp (kept in ts_ok=false)"] = int(nots)
        if rows_in > written:
            reasons["csv_parse_error (rejected by reader)"] = int(rows_in - written)
        out.append({"source_type": stype, "rows_in": int(rows_in), "rows_ok": int(ok),
                    "dropped": int(rows_in - ok), "drop_reasons": reasons,
                    "quarantined": int(written - ok)})
    for stype, n in csv_in.items():  # csv group with no surviving rows
        out.append({"source_type": stype, "rows_in": n, "rows_ok": 0, "dropped": n,
                    "drop_reasons": {"csv_parse_error (rejected by reader)": n} if n else {},
                    "quarantined": 0})
    if prof.get("unrecognized"):
        out.append({"source_type": "unrecognized", "rows_in": 0, "rows_ok": 0, "dropped": 0,
                    "drop_reasons": {"unrecognized_files": len(prof["unrecognized"])},
                    "files": [u["path"] for u in prof["unrecognized"]]})
    return out


def run(ctx: RunContext) -> dict[str, Any]:
    prof = _load_profile(ctx)
    events_dir = Path(ctx.parquet_dir) / "events"
    if events_dir.exists():
        shutil.rmtree(events_dir)
    events_dir.parent.mkdir(parents=True, exist_ok=True)
    selects, csv_groups = build_selects(prof, ctx.cfg)
    written = 0
    if selects:
        sql = copy_sql(selects, ctx.cfg, events_dir)
        log.debug("ingest SQL: %s", sql)
        res = ctx.con.execute(sql).fetchone()
        written = int(res[0]) if res else 0
    else:
        log.warning("ingest: no recognized source files under %s", ctx.raw_dir)
    acc = _accounting(ctx, events_dir, csv_groups, prof)
    ctx.out_dir.mkdir(parents=True, exist_ok=True)
    (ctx.out_dir / "ingest_accounting.json").write_text(json.dumps(acc, indent=2), encoding="utf-8")
    rows_in = sum(a["rows_in"] for a in acc)
    rows_ok = sum(a["rows_ok"] for a in acc)
    for a in acc:
        if a["rows_in"] and a["dropped"] / a["rows_in"] > 0.001:
            log.warning("ingest: %s dropped %d of %d rows: %s", a["source_type"], a["dropped"],
                        a["rows_in"], a["drop_reasons"])
    stats = {"rows_in": rows_in, "rows_ok": rows_ok, "rows_written": written,
             "dropped": rows_in - rows_ok, "bytes_in": sum(f.get("size", 0) for f in prof.get("files", [])
                                                         if f.get("format") != "unrecognized"),
             "sources": {a["source_type"]: a["rows_ok"] for a in acc}}
    log.info("ingest: %s", stats)
    return stats


__all__ = ["run", "build_selects", "copy_sql", "sql_list"]
