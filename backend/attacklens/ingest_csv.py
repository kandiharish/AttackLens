"""CSV readers for Stage 1 ingest (config/sources.yaml csv_sources, csv_dialect, ingest_checks.csv_field_count).

- The source-file pseudo-column is read as db.SRC_FILE_COL ('__al_src_file'), never `filename`: DuckDB compares
  column names case-insensitively, so a header with a FileName column (MDE, proxy, DLP exports) would clash.
- Quote / escape are explicit (csv_dialect, overridable per source): with strict_mode=false DuckDB does not apply a
  sniffed '"' escape, so RFC 4180 doubled quotes (Excel, Purview AuditData JSON) cut the field at the first "".
- json_columns: a column holding a JSON document (Purview AuditData) is read with JSONPaths per intermediate field,
  after the header aliases; the source's value maps (ingest_maps.apply_source_maps) then apply.
- field_count_sql: rows with MORE fields than the header (the lax reader drops the extras) are counted by a second,
  quote-aware read with one overflow column; rows with fewer fields are rejected by the main reader and counted
  from its rejects tables. Both are reported as field_count_mismatch in ingest_accounting.json.
"""

from __future__ import annotations

import logging
from typing import Any

from attacklens.db import SRC_FILE_COL, sql_list, sql_str
from attacklens.ingest_maps import apply_source_maps
from attacklens.ingest_sql import _clean, _fcols, _rel, ts_expr

log = logging.getLogger(__name__)

RFC4180 = {"quote": '"', "escape": '"'}


def _q(c: str) -> str:
    return '"' + c.replace('"', '""') + '"'


def dialect(sources: dict[str, Any], ccfg: dict[str, Any]) -> dict[str, str]:
    """quote / escape for one csv source: sources.yaml csv_dialect, then the source's own keys."""
    base = {**RFC4180, **{k: v for k, v in (sources.get("csv_dialect") or {}).items() if k in RFC4180}}
    return {k: str(ccfg[k]) if ccfg.get(k) is not None else str(base[k]) for k in RFC4180}


def _dialect_opts(d: dict[str, str]) -> str:
    return "".join(f", {k}={sql_str(d[k])}" for k in ("quote", "escape") if k in d)


def csv_reader(files: list[str], delim: str, d: dict[str, str], rejects: str | None = None) -> str:
    """Quote-aware read_csv: header row, all VARCHAR, strict_mode=false (mixed CRLF/LF, quoted newlines), no
    null_padding (the parallel scanner refuses it with quoted newlines). Missing-column / bad-encoding rows go to
    the rejects tables (when `rejects` is set); the source file is the column SRC_FILE_COL."""
    rj = (f", store_rejects=true, rejects_table={sql_str(rejects + '_err')}, "
          f"rejects_scan={sql_str(rejects + '_scan')}") if rejects else ""
    return (f"read_csv({sql_list([str(f).replace(chr(92), '/') for f in files])}, header=true, "
            f"delim={sql_str(delim)}, all_varchar=true, filename={sql_str(SRC_FILE_COL)}, strict_mode=false, "
            f"ignore_errors=true, compression='none'{_dialect_opts(d)}{rj})")


def field_count_sql(files: list[str], delim: str, ncols: int, d: dict[str, str]) -> str:
    """SELECT count(*) of records with more fields than the header (ncols). Same dialect as csv_reader but one
    overflow column: a record that fills it had extras the main reader dropped. Records with exactly ncols fields
    fail the read here (missing column) and are skipped without a rejects table (no memory per row)."""
    cols = "{" + ", ".join(f"'c{i}': 'VARCHAR'" for i in range(ncols)) + ", '__al_overflow': 'VARCHAR'}"
    return (f"SELECT count(*) FROM read_csv({sql_list([str(f).replace(chr(92), '/') for f in files])}, "
            f"columns={cols}, header=true, auto_detect=false, delim={sql_str(delim)}, strict_mode=false, "
            f"ignore_errors=true, compression='none'{_dialect_opts(d)}) WHERE __al_overflow IS NOT NULL")


def _json_cols(by_lower: dict[str, str], ccfg: dict[str, Any]) -> dict[str, list[str]]:
    """field -> [SQL per JSONPath] for the json_columns present in this file's header."""
    out: dict[str, list[str]] = {}
    for col, fields in (ccfg.get("json_columns") or {}).items():
        hit = by_lower.get(str(col).lower())
        if not hit:
            continue
        for f, paths in (fields or {}).items():
            out.setdefault(f, []).extend(_clean(f"try(json_extract_string({_q(hit)}, {sql_str(p)}))")
                                         for p in paths or [])
    return out


def csv_select(stype: str, files: list[str], root: str, delim: str, columns: list[str], ccfg: dict[str, Any],
               formats: list[str], d: dict[str, str], rejects: str | None = None) -> str:
    """Intermediate SELECT for one CSV group (same header). raw_line is rebuilt from the parsed fields."""
    by_lower = {c.lower(): c for c in columns}
    exprs: dict[str, list[str]] = {}
    for f, aliases in (ccfg.get("fields") or {}).items():
        exprs[f] = [_clean(_q(by_lower[a.lower()])) for a in aliases or [] if a.lower() in by_lower]
    for f, js in _json_cols(by_lower, ccfg).items():
        exprs.setdefault(f, []).extend(js)
    vals = {f: "coalesce(" + ", ".join(e) + ")" for f, e in exprs.items() if e}
    # per-source value maps (outcome_map / action_map / value_regex / ip_fields); ts_policy is JSON-only
    vals = apply_source_maps(vals, {k: v for k, v in ccfg.items() if k != "ts_policy"})
    raw = f"concat_ws({sql_str(delim)}, " + ", ".join(f"coalesce({_q(c)}, '')" for c in columns) + ")"
    return (f"SELECT {sql_str(stype)} AS source_type, rel, raw AS line, raw AS raw_line, false AS malformed, "
            f"{ts_expr('f_ts', formats)} AS ts_ms, * EXCLUDE (rel, raw) FROM ("
            f"SELECT {_rel(root, SRC_FILE_COL)} AS rel, {raw} AS raw, {_fcols(vals)} "
            f"FROM {csv_reader(files, delim, d, rejects)})")
