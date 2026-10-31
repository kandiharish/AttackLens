"""Stage 1: DuckDB COPY (in byte-budget batches) of every profiled raw file into partitioned canonical Parquet.

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
import re
import shutil
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any

from attacklens import ingest_sql as q
from attacklens import profile as profile_stage
from attacklens.context import RunContext
from attacklens.db import (HIVE_TYPES, MAX_LINE_SIZE, count_rejects, drop_rejects, line_reader, sql_path,
                           sql_str)
from attacklens.schemas import CANONICAL_COLUMNS

log = logging.getLogger(__name__)

REJECT_REASONS = {"INVALID ENCODING": "decode_error", "MISSING COLUMNS": "csv_missing_columns",
                  "TOO MANY COLUMNS": "csv_too_many_columns", "UNQUOTED VALUE": "csv_parse_error",
                  "LINE SIZE OVER MAXIMUM": "line_too_long", "CAST": "csv_parse_error"}


# key=value sources: a line that is not a log line (e.g. a URL header) is "unparseable", not malformed JSON.
MALFORMED_AS_UNPARSEABLE = frozenset({"fortigate_kv"})


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


def _chunks(files: list[dict[str, Any]], budget: int) -> list[list[dict[str, Any]]]:
    """Split one group's files into runs of <= budget bytes (a single bigger file is its own run)."""
    out: list[list[dict[str, Any]]] = []
    cur: list[dict[str, Any]] = []
    size = 0
    for f in files:
        if cur and size + int(f.get("size", 0)) > budget:
            out.append(cur)
            cur, size = [], 0
        cur.append(f)
        size += int(f.get("size", 0))
    if cur:
        out.append(cur)
    return out


def build_units(prof: dict[str, Any], cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """One reader unit per (format, source_type[, csv header]) group and byte-budget chunk of its files.

    Each unit = {source_type, format, files, bytes, rejects, select[, delimiter, columns]}; `rejects` names the
    DuckDB rejects tables of that unit's reader, `select` is its intermediate SELECT.
    """
    sources = cfg.get("sources") or {}
    pipe = cfg.get("pipeline") or {}
    ing = pipe.get("ingest") or {}
    formats = list(ing.get("ts_formats") or [])
    budget = int(float(ing.get("batch_bytes", 2e9)))
    root = prof["raw_dir"]
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for f in prof.get("files", []):
        fmt = f.get("format")
        if fmt == "unrecognized":
            continue
        key: tuple[Any, ...] = (fmt, f["source_type"])
        if fmt == "csv":
            key += (f["delimiter"], tuple(f["columns"]))
        grouped.setdefault(key, []).append(f)
    units: list[dict[str, Any]] = []
    for key, gfiles in grouped.items():
        fmt, stype = key[0], key[1]
        for chunk in _chunks(gfiles, budget):
            files = [f["path"] for f in chunk]
            # rejects tables only for CSV (quote-aware record counts); line formats are counted physically
            rj = f"rej_ingest_{len(units)}" if fmt == "csv" else None
            u: dict[str, Any] = {"source_type": stype, "format": fmt, "files": files, "rejects": rj,
                                 "rejects_key": f"unit_{len(units)}",
                                 "bytes": sum(int(f.get("size", 0)) for f in chunk)}
            if fmt == "json":
                scfg = (sources.get("json_sources") or {}).get(stype) or {}
                u["select"] = q.json_select(stype, files, root, scfg, sources, formats, rejects=rj)
            elif fmt == "cef":
                u["select"] = q.cef_select(files, root, sources.get("cef") or {}, formats, rejects=rj)
            elif fmt == "syslog":
                u["select"] = q.syslog_select(files, root, sources.get("syslog") or {},
                                              int(pipe.get("baseline_year", 2026)),
                                              ing.get("syslog_ts_format", "%Y %b %d %H:%M:%S"), formats,
                                              rejects=rj)
            elif fmt == "kv":
                kcfg = (sources.get("kv_sources") or {}).get(stype) or {}
                u["select"] = q.kv_select(stype, files, root, kcfg, rejects=rj)
            elif fmt == "csv":
                ccfg = (sources.get("csv_sources") or {}).get(stype) or {}
                u["select"] = q.csv_select(stype, files, root, key[2], list(key[3]), ccfg, formats, rejects=rj)
                u.update(delimiter=key[2], columns=list(key[3]))
            else:
                continue
            units.append(u)
    return units


def plan_batches(units: list[dict[str, Any]], budget: int) -> list[list[dict[str, Any]]]:
    """Pack units into COPY batches of <= budget bytes (small sources share a batch, big ones get their own)."""
    batches: list[list[dict[str, Any]]] = []
    cur: list[dict[str, Any]] = []
    size = 0
    for u in units:
        if cur and size + u["bytes"] > budget:
            batches.append(cur)
            cur, size = [], 0
        cur.append(u)
        size += u["bytes"]
    if cur:
        batches.append(cur)
    return batches


def copy_sql(selects: list[str], cfg: dict[str, Any], events_dir: Path, batch: int = 0) -> str:
    """One COPY of the given intermediate SELECTs into the shared hive layout (file names unique per batch)."""
    union = " UNION ALL BY NAME ".join(f"({s})" for s in selects)
    norm = q.normalize_sql(union, cfg.get("sources") or {})
    cols = ", ".join(CANONICAL_COLUMNS)  # normalize_sql already emits every canonical column, typed
    ing = (cfg.get("pipeline") or {}).get("ingest") or {}
    comp = ing.get("compression", "ZSTD")
    rg = int(ing.get("row_group_size", 122880))
    return (f"COPY (SELECT {cols} FROM ({norm})) TO {sql_path(events_dir)} "
            f"(FORMAT PARQUET, PARTITION_BY (source_type, ts_ok, event_day), COMPRESSION {comp}, "
            f"ROW_GROUP_SIZE {rg}, OVERWRITE_OR_IGNORE, FILENAME_PATTERN 'b{batch:05d}_{{i}}')")


def _copy_settings(ctx: RunContext) -> list[str]:
    """Bound the partitioned writer's buffers for the COPY only (pipeline.yaml ingest.*)."""
    ing = (ctx.cfg.get("pipeline") or {}).get("ingest") or {}
    out = []
    if ing.get("partitioned_write_flush_threshold"):
        out.append(f"SET partitioned_write_flush_threshold={int(ing['partitioned_write_flush_threshold'])}")
    if ing.get("partitioned_write_max_open_files"):
        out.append(f"SET partitioned_write_max_open_files={int(ing['partitioned_write_max_open_files'])}")
    if ing.get("threads"):
        out.append(f"SET threads={int(ing['threads'])}")
    return out


def _run_copies(ctx: RunContext, units: list[dict[str, Any]], events_dir: Path) -> int:
    ing = (ctx.cfg.get("pipeline") or {}).get("ingest") or {}
    budget = int(float(ing.get("batch_bytes", 2e9)))
    old_threads = ctx.con.execute("SELECT current_setting('threads')").fetchone()[0]
    old_flush = ctx.con.execute("SELECT current_setting('partitioned_write_flush_threshold')").fetchone()[0]
    old_open = ctx.con.execute("SELECT current_setting('partitioned_write_max_open_files')").fetchone()[0]
    for st in _copy_settings(ctx):
        ctx.con.execute(st)
    written = 0
    try:
        batches = plan_batches(units, budget)
        for b, batch in enumerate(batches):
            sql = copy_sql([u["select"] for u in batch], ctx.cfg, events_dir, batch=b)
            log.debug("ingest batch %d SQL: %s", b, sql)
            res = ctx.con.execute(sql).fetchone()
            written += int(res[0]) if res else 0
            log.info("ingest batch %d/%d: %d files, %.1f MB, %d rows so far", b + 1, len(batches),
                     sum(len(u["files"]) for u in batch), sum(u["bytes"] for u in batch) / 1e6, written)
    finally:
        ctx.con.execute(f"SET threads={int(old_threads)}")
        ctx.con.execute(f"SET partitioned_write_flush_threshold={int(old_flush)}")
        ctx.con.execute(f"SET partitioned_write_max_open_files={int(old_open)}")
    return written


def _truncated_csv(ctx: RunContext, g: dict[str, Any]) -> int:
    """Physical CSV lines (without quotes) with more fields than the header: the reader drops the extras."""
    d, ncols = g["delimiter"], len(g["columns"])
    return int(ctx.con.execute(
        f"SELECT count(*) FROM {line_reader(g['files'], filename=False)} WHERE line IS NOT NULL "
        f"AND NOT contains(line, '\"') AND length(line) - length(replace(line, {sql_str(d)}, '')) > {ncols - 1}"
    ).fetchone()[0])


# linear-time patterns: runs of non-terminator bytes, and runs that are only spaces (blank lines)
_LINES = re.compile(rb"[^\r\n]+")
_BLANK = re.compile(rb"(?<![^\r\n]) +(?![^\r\n])")


def _nonempty(body: bytes) -> int:
    return len(_LINES.findall(body)) - len(_BLANK.findall(body))


def scan_lines(files: list[str], chunk: int = 1 << 24, limit: int = MAX_LINE_SIZE) -> tuple[int, int]:
    """(non-empty physical lines, lines longer than `limit`) over raw bytes, split like the DuckDB line reader
    (LF, CRLF, lone CR).

    Byte-level and encoding-agnostic (never throws on invalid UTF-8 / NUL), bounded memory (one chunk at a time,
    no per-event objects). Fast path: a chunk without CR, blank or space-led lines is just count(b"\n").
    With chunk <= limit only the line that is open across a chunk boundary can exceed the limit, so its length is
    tracked exactly. Rows written + over-long lines + undecodable lines = physical lines.
    """
    chunk = min(chunk, limit)
    n = too_long = 0
    for f in files:
        rest = b""
        open_len = 0  # bytes of the line still open at the end of the previous chunk
        with open(f, "rb") as fh:
            while True:
                raw = fh.read(chunk)
                if not raw:
                    break
                hits = [i for i in (raw.find(b"\n"), raw.find(b"\r")) if i >= 0]
                buf = rest + raw
                if not hits:  # no terminator: keep only whether the open line is non-empty (bounded memory)
                    open_len += len(raw)
                    rest = buf if len(buf) <= chunk else (b"x" if buf.strip(b" ") else b"")
                    continue
                if open_len + min(hits) > limit:
                    too_long += 1
                cut = max(buf.rfind(b"\n"), buf.rfind(b"\r"))
                body, rest = buf[:cut + 1], buf[cut + 1:]
                open_len = len(rest)
                if b"\r" in body or b"\n\n" in body or b"\n " in body or body.startswith((b"\n", b" ")):
                    n += _nonempty(body)
                else:
                    n += body.count(b"\n")
        if open_len > limit:
            too_long += 1
        if rest.strip(b" "):
            n += _nonempty(rest)
    return n, too_long


def physical_lines(files: list[str], chunk: int = 1 << 24) -> int:
    """Non-empty physical lines (see scan_lines)."""
    return scan_lines(files, chunk)[0]


def _unrecognized(ctx: RunContext, prof: dict[str, Any]) -> dict[str, Any] | None:
    files = [f["path"] for f in prof.get("files", []) if f.get("format") == "unrecognized"]
    if not files:
        return None
    n = physical_lines(files)
    return {"source_type": "unrecognized", "rows_in": n, "rows_ok": 0, "dropped": n,
            "drop_reasons": {"unrecognized_format": n} if n else {}, "quarantined": 0,
            "files": [u["path"] for u in prof.get("unrecognized", [])]}


def _accounting(ctx: RunContext, events_dir: Path, groups: list[dict[str, Any]],
                prof: dict[str, Any], line_counts: dict[str, Future[tuple[int, int]]] | None = None) -> list[dict[str, Any]]:
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
                what = "unparseable_line" if st in MALFORMED_AS_UNPARSEABLE else "malformed_line"
                e["drop_reasons"][f"{what} (kept in ts_ok=false, action=malformed)"] = int(bad)
            if nots:
                e["drop_reasons"]["missing_or_unparseable_timestamp (kept in ts_ok=false)"] = int(nots)
    phys: dict[str, tuple[int, int]] = {}
    for g in groups:
        e = entry(g["source_type"])
        if g["format"] != "csv":
            fut = (line_counts or {}).get(g["rejects_key"])
            n, lng = fut.result() if fut is not None else scan_lines(g["files"])
            pn, pl = phys.get(g["source_type"], (0, 0))
            phys[g["source_type"]] = (pn + n, pl + lng)
            continue
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
    for st, (n, lng) in phys.items():
        e = entry(st)
        if n > e["rows_in"]:  # lines the reader skipped never reached Parquet
            missing = n - e["rows_in"]
            too_long = min(lng, missing)
            if too_long:
                e["drop_reasons"][f"line_too_long (> {MAX_LINE_SIZE} bytes, skipped by reader)"] = too_long
            if missing - too_long:
                e["drop_reasons"]["decode_error (invalid UTF-8, line not readable)"] = missing - too_long
            e["rows_in"] = n
        elif n < e["rows_in"]:
            log.warning("ingest: %s physical line count %d < rows written %d", st, n, e["rows_in"])
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
    units = build_units(prof, ctx.cfg)
    for u in units:
        if u["rejects"]:
            drop_rejects(ctx.con, u["rejects"])
    written = 0
    # physical line counts run on a worker thread while DuckDB (GIL released) does the COPY
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="linecount") as pool:
        counts = {u["rejects_key"]: pool.submit(scan_lines, u["files"]) for u in units if u["format"] != "csv"}
        if units:
            written = _run_copies(ctx, units, events_dir)
        else:
            log.warning("ingest: no recognized source files under %s", ctx.raw_dir)
        acc = _accounting(ctx, events_dir, units, prof, counts)
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
