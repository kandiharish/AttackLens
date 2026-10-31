"""Stage 1: one DuckDB COPY of every profiled raw file into partitioned canonical Parquet.

Writes <parquet_dir>/events/source_type=*/ts_ok=*/event_day=*/ and out_dir/ingest_accounting.json.

Accounting (no line is ever lost uncounted):
- malformed lines are kept in the ts_ok=false partition with action='malformed' and their original text;
- rows without a parseable timestamp are kept with ts_ok=false;
- lines the reader cannot decode (invalid UTF-8) or CSV records with missing columns are recorded in DuckDB
  rejects tables (one per reader) and counted as dropped with a reason;
- unrecognized files: their non-blank lines are counted as rows_in and dropped (reason unrecognized_format).
rows_in = rows written + rejected lines; rows_ok = rows with ts_ok; dropped = rows_in - rows_ok.

Known limitation: source_seq = hash(relative file, line). DuckDB 2.0 text readers expose no per-file row
number (file_row_number is "not supported by this reader") and a window over the input is not allowed, so
byte-identical duplicate lines inside one file share a source_seq.
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
from attacklens.db import HIVE_TYPES, count_rejects, drop_rejects, line_reader, sql_path, sql_str
from attacklens.schemas import CANONICAL_COLUMNS

log = logging.getLogger(__name__)

REJECT_REASONS = {"INVALID ENCODING": "decode_error", "MISSING COLUMNS": "csv_missing_columns",
                  "TOO MANY COLUMNS": "csv_too_many_columns", "UNQUOTED VALUE": "csv_parse_error",
                  "LINE SIZE OVER MAXIMUM": "line_too_long", "CAST": "csv_parse_error"}


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
    """One SELECT per (format, source_type[, csv header]) group.

    Returns (selects, groups); each group = {source_type, format, files, rejects[, delimiter, columns]} where
    `rejects` names the DuckDB rejects tables of that group's reader.
    """
    sources = cfg.get("sources") or {}
    pipe = cfg.get("pipeline") or {}
    ing = pipe.get("ingest") or {}
    formats = list(ing.get("ts_formats") or [])
    root = prof["raw_dir"]
    grouped: dict[tuple[Any, ...], list[str]] = {}
    for f in prof.get("files", []):
        fmt = f.get("format")
        if fmt == "unrecognized":
            continue
        key: tuple[Any, ...] = (fmt, f["source_type"])
        if fmt == "csv":
            key += (f["delimiter"], tuple(f["columns"]))
        grouped.setdefault(key, []).append(f["path"])
    selects: list[str] = []
    groups: list[dict[str, Any]] = []
    for n, (key, files) in enumerate(grouped.items()):
        fmt, stype = key[0], key[1]
        rj = f"rej_ingest_{n}"
        g: dict[str, Any] = {"source_type": stype, "format": fmt, "files": files, "rejects": rj}
        if fmt == "json":
            scfg = (sources.get("json_sources") or {}).get(stype) or {}
            selects.append(q.json_select(stype, files, root, scfg, sources, formats, rejects=rj))
        elif fmt == "cef":
            selects.append(q.cef_select(files, root, sources.get("cef") or {}, formats, rejects=rj))
        elif fmt == "syslog":
            selects.append(q.syslog_select(files, root, sources.get("syslog") or {},
                                           int(pipe.get("baseline_year", 2026)),
                                           ing.get("syslog_ts_format", "%Y %b %d %H:%M:%S"), formats, rejects=rj))
        elif fmt == "csv":
            ccfg = (sources.get("csv_sources") or {}).get(stype) or {}
            selects.append(q.csv_select(stype, files, root, key[2], list(key[3]), ccfg, formats, rejects=rj))
            g.update(delimiter=key[2], columns=list(key[3]))
        else:
            continue
        groups.append(g)
    return selects, groups


def copy_sql(selects: list[str], cfg: dict[str, Any], events_dir: Path) -> str:
    union = " UNION ALL BY NAME ".join(f"({s})" for s in selects)
    norm = q.normalize_sql(union, cfg.get("sources") or {})
    typed = ", ".join(f"CAST({c} AS {t}) AS {c}" for c, t in CANONICAL_COLUMNS.items())
    comp = ((cfg.get("pipeline") or {}).get("ingest") or {}).get("compression", "ZSTD")
    return (f"COPY (SELECT {typed} FROM ({norm})) TO {sql_path(events_dir)} "
            f"(FORMAT PARQUET, PARTITION_BY (source_type, ts_ok, event_day), COMPRESSION {comp}, "
            f"OVERWRITE_OR_IGNORE)")


def _truncated_csv(ctx: RunContext, g: dict[str, Any]) -> int:
    """Physical CSV lines (without quotes) with more fields than the header: the reader drops the extras."""
    d, ncols = g["delimiter"], len(g["columns"])
    return int(ctx.con.execute(
        f"SELECT count(*) FROM {line_reader(g['files'], filename=False)} WHERE line IS NOT NULL "
        f"AND NOT contains(line, '\"') AND length(line) - length(replace(line, {sql_str(d)}, '')) > {ncols - 1}"
    ).fetchone()[0])


def _unrecognized(ctx: RunContext, prof: dict[str, Any]) -> dict[str, Any] | None:
    files = [f["path"] for f in prof.get("files", []) if f.get("format") == "unrecognized"]
    if not files:
        return None
    drop_rejects(ctx.con, "rej_unrec")
    n = int(ctx.con.execute(f"SELECT count(*) FROM {line_reader(files, filename=False, rejects='rej_unrec')} "
                            f"WHERE line IS NOT NULL AND trim(line) <> ''").fetchone()[0])
    n += sum(c for _, _, c in count_rejects(ctx.con, "rej_unrec"))
    return {"source_type": "unrecognized", "rows_in": n, "rows_ok": 0, "dropped": n,
            "drop_reasons": {"unrecognized_format": n} if n else {}, "quarantined": 0,
            "files": [u["path"] for u in prof.get("unrecognized", [])]}


def _accounting(ctx: RunContext, events_dir: Path, groups: list[dict[str, Any]],
                prof: dict[str, Any]) -> list[dict[str, Any]]:
    per: dict[str, dict[str, Any]] = {}

    def entry(st: str) -> dict[str, Any]:
        return per.setdefault(st, {"source_type": st, "rows_in": 0, "rows_ok": 0, "dropped": 0,
                                   "drop_reasons": {}, "quarantined": 0})

    if any(events_dir.rglob("*.parquet")):
        glob = sql_path(events_dir / "**" / "*.parquet")
        for st, written, ok, bad, nots in ctx.con.execute(
                f"SELECT source_type, count(*), count(*) FILTER (WHERE ts_ok), "
                f"count(*) FILTER (WHERE action = 'malformed'), "
                f"count(*) FILTER (WHERE NOT ts_ok AND action <> 'malformed') "
                f"FROM read_parquet({glob}, hive_partitioning=true, hive_types={HIVE_TYPES}) GROUP BY 1").fetchall():
            e = entry(st)
            e.update(rows_in=int(written), rows_ok=int(ok), quarantined=int(written - ok))
            if bad:
                e["drop_reasons"]["malformed_line (kept in ts_ok=false, action=malformed)"] = int(bad)
            if nots:
                e["drop_reasons"]["missing_or_unparseable_timestamp (kept in ts_ok=false)"] = int(nots)
    for g in groups:
        e = entry(g["source_type"])
        for _, etype, n in count_rejects(ctx.con, g["rejects"]):
            reason = REJECT_REASONS.get(etype, f"read_error ({etype.lower()})")
            e["rows_in"] += n
            e["drop_reasons"][reason] = e["drop_reasons"].get(reason, 0) + n
        if g["format"] == "csv":
            t = _truncated_csv(ctx, g)
            if t:
                e.setdefault("notes", {})["truncated_columns (extra fields dropped, row kept)"] = t
                log.warning("ingest: %d %s rows had more fields than the header; extras dropped",
                            t, g["source_type"])
    out = sorted(per.values(), key=lambda a: a["source_type"])
    for e in out:
        e["dropped"] = e["rows_in"] - e["rows_ok"]
    unrec = _unrecognized(ctx, prof)
    if unrec:
        out.append(unrec)
    return out


def run(ctx: RunContext) -> dict[str, Any]:
    prof = _load_profile(ctx)
    events_dir = Path(ctx.parquet_dir) / "events"
    if events_dir.exists():
        shutil.rmtree(events_dir)
    events_dir.parent.mkdir(parents=True, exist_ok=True)
    selects, groups = build_selects(prof, ctx.cfg)
    for g in groups:
        drop_rejects(ctx.con, g["rejects"])
    written = 0
    if selects:
        sql = copy_sql(selects, ctx.cfg, events_dir)
        log.debug("ingest SQL: %s", sql)
        res = ctx.con.execute(sql).fetchone()
        written = int(res[0]) if res else 0
    else:
        log.warning("ingest: no recognized source files under %s", ctx.raw_dir)
    acc = _accounting(ctx, events_dir, groups, prof)
    ctx.out_dir.mkdir(parents=True, exist_ok=True)
    (ctx.out_dir / "ingest_accounting.json").write_text(json.dumps(acc, indent=2), encoding="utf-8")
    rows_in = sum(a["rows_in"] for a in acc)
    rows_ok = sum(a["rows_ok"] for a in acc)
    for a in acc:
        if a["rows_in"] and a["dropped"] / a["rows_in"] > 0.001:
            log.warning("ingest: %s dropped %d of %d rows: %s", a["source_type"], a["dropped"],
                        a["rows_in"], a["drop_reasons"])
    stats = {"rows_in": rows_in, "rows_ok": rows_ok, "rows_written": written, "dropped": rows_in - rows_ok,
             "bytes_in": sum(f.get("size", 0) for f in prof.get("files", []) if f.get("format") != "unrecognized"),
             "sources": {a["source_type"]: a["rows_ok"] for a in acc}}
    log.info("ingest: %s", stats)
    return stats
