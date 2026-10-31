"""Stage 0: sniff every raw file by content and profile it -> out_dir/source_profile.json.

Routing is by the first non-empty line only (never by extension):
  '{'                         -> JSON lines (ecs_json / win_json decided from sampled field paths)
  'CEF:' (maybe after syslog) -> cef
  syslog header               -> syslog
  delimited header            -> csv source whose aliases match (e.g. firewall_csv), else unrecognized
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import duckdb

from attacklens.context import RunContext
from attacklens.db import line_reader, sql_str

log = logging.getLogger(__name__)

BOM = "\ufeff"
CEF_RE = re.compile(r"^(?:<\d+>)?(?:.*?\s)?CEF:\d+\|")
SYSLOG_RES = (
    re.compile(r"^(?:<\d+>)?[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d \S+ "),
    re.compile(r"^(?:<\d+>)?(?:1 )?\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\S* \S+ \S+"),
)
CSV_DELIMS = (",", "\t", ";", "|")


def _skip(path: Path, root: Path, pcfg: dict[str, Any]) -> str | None:
    rel = path.relative_to(root)
    if any(part in pcfg.get("skip_dir_components", ["ground_truth"]) for part in rel.parts[:-1]):
        return "ground_truth"
    if path.name in pcfg.get("skip_names", ["manifest.json"]):
        return "manifest"
    if path.suffix.lower() in pcfg.get("skip_suffixes", [".md"]):
        return "markdown"
    return None


def first_lines(path: Path, nbytes: int = 65536, n: int = 10) -> list[str] | None:
    """First n non-empty lines (BOM and CR stripped); None if the file is binary."""
    with path.open("rb") as fh:
        chunk = fh.read(nbytes)
    if chunk[:4096].count(b"\x00") * 20 > len(chunk[:4096]):  # >5 % NUL: binary / UTF-16, not a text log
        return None
    text = chunk.replace(b"\x00", b"").decode("utf-8", errors="replace")
    if text.startswith(BOM):
        text = text[1:]
    lines = [ln.strip(BOM).rstrip("\r") for ln in text.splitlines() if ln.strip()]
    if len(chunk) == nbytes and len(lines) > 1:
        lines = lines[:-1]  # the last line may be cut by the byte budget
    return lines[:n]


def first_line(path: Path, nbytes: int = 65536) -> str | None:
    """First non-empty line (BOM and CR stripped), or None if the file has none / is binary."""
    lines = first_lines(path, nbytes, 1)
    return lines[0] if lines else None


def sniff_lines(lines: list[str] | None, sources_cfg: dict[str, Any]) -> dict[str, Any]:
    """Sniff the first few non-empty lines: the first line in a known format decides, so one stray header line
    (e.g. a URL) does not make the file unrecognized. A CSV header only counts on the first line."""
    if not lines:
        return sniff(None, sources_cfg)
    first = sniff(lines[0], sources_cfg)
    if first["format"] != "unrecognized":
        return first
    for i, line in enumerate(lines[1:], start=1):
        info = sniff(line, sources_cfg)
        if info["format"] not in ("unrecognized", "csv"):
            log.info("format decided by non-empty line %d; earlier lines are counted as dropped", i + 1)
            return {**info, "sniff_line": i + 1}
    return first


def _csv_header(line: str) -> tuple[str, list[str]] | None:
    best = max(CSV_DELIMS, key=line.count)
    if line.count(best) == 0:
        return None
    cols = [c.strip().strip('"').strip() for c in line.split(best)]
    return best, cols


def sniff(line: str | None, sources_cfg: dict[str, Any]) -> dict[str, Any]:
    """Return {'format': json|cef|syslog|csv|unrecognized, ...}."""
    if line is None:
        return {"format": "unrecognized", "reason": "no text line found (empty or binary)"}
    s = line.lstrip()
    if s.startswith("{"):
        return {"format": "json"}
    if CEF_RE.match(s):
        return {"format": "cef", "source_type": "cef"}
    if any(r.match(s) for r in SYSLOG_RES):
        return {"format": "syslog", "source_type": "syslog"}
    for name, kcfg in (sources_cfg.get("kv_sources") or {}).items():
        if any(re.match(rx, s) for rx in kcfg.get("detect_regex") or []):
            return {"format": "kv", "source_type": name}
    hdr = _csv_header(s)
    if hdr:
        delim, cols = hdr
        lower = {c.lower() for c in cols}
        for name, scfg in (sources_cfg.get("csv_sources") or {}).items():
            hits = lower & {a.lower() for a in scfg.get("detect_any", [])}
            if len(hits) >= int(scfg.get("min_matches", 1)):
                return {"format": "csv", "source_type": name, "delimiter": delim, "columns": cols}
        return {"format": "unrecognized", "reason": f"delimited header matches no csv source: {cols[:12]}"}
    return {"format": "unrecognized", "reason": "first line matches no known format"}


def _flatten(struct: Any, prefix: str = "") -> list[str]:
    """Field paths from a DuckDB json_structure value (lists are transparent)."""
    out: list[str] = []
    if isinstance(struct, dict):
        for k, v in struct.items():
            p = f"{prefix}.{k}" if prefix else k
            out.append(p)
            out.extend(_flatten(v, p))
    elif isinstance(struct, list) and struct:
        out.extend(_flatten(struct[0], prefix))
    return out


def profile_json(con: duckdb.DuckDBPyConnection, path: Path, sample: int,
                 sources_cfg: dict[str, Any]) -> dict[str, Any]:
    """Sample up to `sample` lines with DuckDB; field path counts, source type, actions / event ids."""
    src = line_reader([path.as_posix()], filename=False)
    rows = con.execute(
        f"SELECT json_structure(line) s, count(*) FROM (SELECT line FROM {src} "
        f"WHERE line IS NOT NULL AND json_valid(line) LIMIT {int(sample)}) GROUP BY 1").fetchall()
    fields: dict[str, int] = {}
    for s, n in rows:
        try:
            for p in _flatten(json.loads(s)):
                fields[p] = fields.get(p, 0) + int(n)
        except (TypeError, ValueError):
            continue
    stype = None
    for name, scfg in (sources_cfg.get("json_sources") or {}).items():
        if any(d in fields for d in scfg.get("detect_any", [])):
            stype = name
            break
    out: dict[str, Any] = {"source_type": stype, "sampled_rows": sum(int(n) for _, n in rows),
                           "fields": dict(sorted(fields.items()))}
    if stype:
        f = sources_cfg["json_sources"][stype]["fields"]
        for key, alias in (("actions", "event_action"), ("event_ids", "event_id")):
            paths = f.get(alias) or []
            if not paths:
                continue
            expr = "coalesce(" + ", ".join(f"json_extract_string(line, {sql_str(p)})" for p in paths) + ")"
            vals = con.execute(
                f"SELECT {expr} v, count(*) FROM (SELECT line FROM {src} WHERE line IS NOT NULL "
                f"AND json_valid(line) LIMIT {int(sample)}) GROUP BY 1 ORDER BY 2 DESC LIMIT 200").fetchall()
            out[key] = {str(v): int(n) for v, n in vals}
    return out


def profile_kv(con: duckdb.DuckDBPyConnection, path: Path, sample: int,
               count_keys: list[str]) -> dict[str, Any]:
    """Bounded sample of a key=value file: key frequencies and value counts of a few low-cardinality keys."""
    src = line_reader([path.as_posix()], filename=False)
    smp = f"(SELECT line FROM {src} WHERE line IS NOT NULL AND trim(line) <> '' LIMIT {int(sample)})"
    rows = con.execute(f"SELECT k, count(*) FROM (SELECT unnest(list_distinct(regexp_extract_all(line, "
                       f"'(?:^| )([a-z_0-9]+)=', 1))) k FROM {smp}) GROUP BY 1 ORDER BY 2 DESC").fetchall()
    out: dict[str, Any] = {"sampled_rows": int(con.execute(f"SELECT count(*) FROM {smp}").fetchone()[0]),
                           "fields": {str(k): int(n) for k, n in rows}}
    if count_keys:
        ex = ", ".join(f"trim(nullif(regexp_extract(line, {sql_str('(?:^| )' + k + '=(' + chr(34) + '[^' + chr(34) + ']*' + chr(34) + '|[^ ]*)')}, 1), ''), "
                       f"'{chr(34)}') AS {k}" for k in count_keys)
        vals = con.execute(f"SELECT {', '.join(count_keys)}, count(*) FROM (SELECT {ex} FROM {smp}) "
                           f"GROUP BY ALL ORDER BY {len(count_keys) + 1} DESC LIMIT 200").fetchall()
        out["value_counts"] = [{**dict(zip(count_keys, r[:-1])), "n": int(r[-1])} for r in vals]
    return out


def run(ctx: RunContext) -> dict[str, Any]:
    root = Path(ctx.raw_dir)
    pcfg = (ctx.cfg.get("pipeline") or {}).get("profile") or {}
    sources_cfg = ctx.cfg.get("sources") or {}
    sample = int(pcfg.get("sample_lines", 20000))
    files: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    empty: list[str] = []
    unrecognized: list[dict[str, str]] = []
    if not root.exists():
        raise FileNotFoundError(f"raw dir not found: {root}")
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        reason = _skip(path, root, pcfg)
        if reason:
            skipped.append({"path": rel, "reason": reason})
            continue
        size = path.stat().st_size
        if size == 0:
            empty.append(rel)
            continue
        try:
            info = sniff_lines(first_lines(path, int(pcfg.get("sniff_bytes", 65536)),
                                           int(pcfg.get("sniff_lines", 10))), sources_cfg)
            if info["format"] == "kv":
                info.update(profile_kv(ctx.con, path, sample, list(pcfg.get("kv_count_keys") or [])))
            elif info["format"] == "json":
                info.update(profile_json(ctx.con, path, sample, sources_cfg))
                if not info.get("source_type"):
                    info = {"format": "unrecognized", "reason": "JSON with no known source fields",
                            "fields": info.get("fields", {})}
        except Exception as exc:  # never crash on a strange file
            log.warning("profile failed for %s: %s", rel, exc)
            info = {"format": "unrecognized", "reason": f"profile error: {exc}"}
        entry = {"path": path.resolve().as_posix(), "rel": rel, "size": size, **info}
        if info["format"] == "unrecognized":
            log.warning("unrecognized file %s: %s", rel, info.get("reason"))
            unrecognized.append({"path": rel, "reason": str(info.get("reason"))})
        files.append(entry)
    by_type: dict[str, list[str]] = {}
    for f in files:
        if f["format"] != "unrecognized":
            by_type.setdefault(f["source_type"], []).append(f["rel"])
    profile = {"raw_dir": root.resolve().as_posix(), "files": files, "files_per_source": by_type,
               "skipped": skipped, "empty_files": empty, "unrecognized": unrecognized}
    ctx.out_dir.mkdir(parents=True, exist_ok=True)
    (ctx.out_dir / "source_profile.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")
    ctx.stats["profile"] = profile
    stats = {"files": len(files), "bytes": sum(f["size"] for f in files),
             "per_source": {k: len(v) for k, v in by_type.items()},
             "skipped": len(skipped), "empty": len(empty), "unrecognized": len(unrecognized)}
    log.info("profile: %s", stats)
    return stats
