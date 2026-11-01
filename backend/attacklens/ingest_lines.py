"""Stage 0/1 for line-oriented text logs (config/line_sources.yaml): two config-driven source kinds.

- line sources: one RE2 regex with named groups per format (Apache / nginx access and error, Squid, Windows DNS
  debug). Sniff (Python `re`) and parse (DuckDB RE2) use the same regex, so routing and parsing cannot disagree.
- directive sources: header-defined TSV whose column list comes from a directive line in the file (Zeek
  '#fields', W3C / IIS '#Fields:'). A file whose blocks carry different schemas is split once per schema
  (plan_directive), so every reader unit has exactly one schema.

Every builder returns the intermediate SELECT of attacklens.ingest_sql (f_* VARCHAR + source_type, rel, line,
raw_line, malformed, ts_ms), ready for normalize_sql / copy_sql. Accounting: header lines are header_line (not
rows); a non-header line the regex / schema does not fit is a row with malformed=true (unparseable_line).
"""

from __future__ import annotations

import gzip
import logging
import re
from pathlib import Path
from typing import Any, Callable

import duckdb

from attacklens.db import line_reader, sql_list, sql_str
from attacklens.ingest_sql import FIELDS

log = logging.getLogger(__name__)

NONEMPTY = "line IS NOT NULL AND trim(line) <> ''"
NULL = "CAST(NULL AS VARCHAR)"
Getter = Callable[[str], "str | None"]


def lines_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """The line_sources.yaml dict from a full load_config() result (or the dict itself)."""
    v = cfg.get("line_sources")
    return v if isinstance(v, dict) and ("line_sources" in v or "directive_sources" in v) else cfg


def _ls(lcfg: dict[str, Any]) -> dict[str, Any]:
    return lcfg.get("line_sources") or {}


def _ds(lcfg: dict[str, Any]) -> dict[str, Any]:
    return lcfg.get("directive_sources") or {}


def source_types(lcfg: dict[str, Any]) -> frozenset[str]:
    """Every source_type these kinds can write (for ingest.MALFORMED_AS_UNPARSEABLE)."""
    out = set(_ls(lcfg))
    for name, d in _ds(lcfg).items():
        out.add(name)
        out.update(str(p["source_type"]) for p in (d.get("paths") or {}).values() if p.get("source_type"))
    return frozenset(out)


# ---------------------------------------------------------------------------------------------------- sniff

def sniff_line_source(lines: list[str] | None, lcfg: dict[str, Any]) -> str | None:
    """First line source (config order) whose detect_regex matches the first non-header sniffed line
    (or the first line if every sniffed line is a header line)."""
    if not lines:
        return None
    for name, s in _ls(lcfg).items():
        hdr = re.compile(s["header_regex"]) if s.get("header_regex") else None
        body = [ln for ln in lines if ln.strip() and not (hdr and hdr.match(ln))]
        cand = body[0] if body else lines[0]
        if re.match(s.get("detect_regex") or s["line_regex"], cand):
            return name
    return None


def sniff_directive_source(lines: list[str] | None, lcfg: dict[str, Any]) -> str | None:
    if not lines:
        return None
    first = lines[0].lstrip("﻿")
    return next((n for n, d in _ds(lcfg).items() if re.match(d["detect_regex"], first)), None)


def sniff(lines: list[str] | None, lcfg: dict[str, Any]) -> dict[str, Any] | None:
    """{'format': 'directive' | 'line', 'source_type': name} or None. Directive headers are checked first."""
    d = sniff_directive_source(lines, lcfg)
    if d:
        return {"format": "directive", "source_type": d}
    s = sniff_line_source(lines, lcfg)
    return {"format": "line", "source_type": s} if s else None


# ---------------------------------------------------------------------------------------------- SQL pieces

def _clean(x: str, nulls: list[str]) -> str:
    return f"nullif(CASE WHEN list_contains({sql_list(nulls)}, trim({x})) THEN '' ELSE trim({x}) END, '')"


def _value(spec: Any, get: Getter, nulls: list[str]) -> str:
    """SQL VARCHAR for a field spec (see config/line_sources.yaml header)."""
    if isinstance(spec, str):
        raw = get(spec)
        return _clean(raw, nulls) if raw is not None else NULL
    if isinstance(spec, list):
        vals = [_value(s, get, nulls) for s in spec]
        return vals[0] if len(vals) == 1 else f"coalesce({', '.join(vals)})"
    if not isinstance(spec, dict):
        raise ValueError(f"bad field spec {spec!r}")
    if "const" in spec:
        return sql_str(str(spec["const"]))
    if "concat" in spec:
        parts = [_value(s, get, nulls) for s in spec["concat"]]
        v = f"nullif(concat_ws({sql_str(str(spec.get('sep', '')))}, {', '.join(parts)}), '')"
    else:
        v = _value(spec["group"], get, nulls)
    if v == NULL:
        return NULL
    if spec.get("replace"):
        pat, rep = spec["replace"]
        v = f"regexp_replace({v}, {sql_str(pat)}, {sql_str(rep)}, 'g')"
    if spec.get("regex"):
        v = f"nullif(regexp_extract({v}, {sql_str(spec['regex'])}, 1), '')"
    if spec.get("trim"):
        v = f"trim({v}, {sql_str(spec['trim'])})"
    if spec.get("lower"):
        v = f"lower({v})"
    return f"nullif({v}, '')"


def _cond(rule: dict[str, Any], get: Getter, nulls: list[str]) -> str:
    """All `when` conditions: RE2 search on the cleaned value; a column the file lacks never matches."""
    parts = []
    for g, rx in (rule.get("when") or {}).items():
        raw = get(str(g))
        parts.append("false" if raw is None else f"regexp_matches(coalesce({_clean(raw, nulls)}, ''), {sql_str(rx)})")
    return " AND ".join(parts) or "true"


def _case(rules: list[dict[str, Any]], attr: str, get: Getter, nulls: list[str]) -> str | None:
    arms = [f"WHEN {_cond(r, get, nulls)} THEN {sql_str(str(r[attr]))}" for r in rules if r.get(attr) is not None]
    return f"CASE {' '.join(arms)} END" if arms else None


def _ts(tcfg: dict[str, Any], get: Getter, nulls: list[str]) -> str:
    """Epoch ms (UTC) from the string value(s); the zone is explicit in the value or in config, never guessed."""
    raws = [get(str(f)) for f in tcfg.get("fields") or []]
    if not raws or any(r is None for r in raws):
        return "CAST(NULL AS BIGINT)"
    x = " || ' ' || ".join(_clean(r, nulls) for r in raws)
    fmt = str(tcfg.get("format", ""))
    if fmt == "epoch":
        return (f"CASE WHEN regexp_full_match({x}, '\\d{{1,12}}(\\.\\d+)?') "
                f"THEN CAST(floor(try_cast({x} AS DECIMAL(24,6)) * 1000) AS BIGINT) END")
    if fmt == "epoch_ms":
        return f"CASE WHEN regexp_full_match({x}, '\\d{{1,15}}') THEN try_cast({x} AS BIGINT) END"
    if "%z" in fmt or "%Z" in fmt:
        return f"epoch_ms(try_strptime({x}, {sql_str(fmt)}))"
    return f"epoch_ms(timezone({sql_str(str(tcfg['zone']))}, try_strptime({x}, {sql_str(fmt)})))"


def _fcols(scfg: dict[str, Any], get: Getter, nulls: list[str]) -> str:
    vals = {str(f): _value(spec, get, nulls) for f, spec in (scfg.get("fields") or {}).items()}
    acts: list[dict[str, Any]] = scfg.get("actions") or []
    vals["event_action"] = _case(acts, "action", get, nulls) or NULL
    oc = [c for c in (_case(acts, "outcome", get, nulls), _case(scfg.get("outcome_rules") or [], "outcome", get,
                                                                  nulls)) if c]
    if oc:
        vals["outcome"] = f"coalesce({', '.join([*oc, vals['outcome']] if 'outcome' in vals else oc)})"
    return ", ".join(f"CASE WHEN ok THEN {vals[f]} END AS f_{f}" if f in vals else f"{NULL} AS f_{f}"
                     for f in FIELDS)


def _wrap(stype: str, inner: str, scfg: dict[str, Any], get: Getter, nulls: list[str]) -> str:
    return (f"SELECT {sql_str(stype)} AS source_type, rel, line, line AS raw_line, NOT ok AS malformed, "
            f"CASE WHEN ok THEN CAST({_ts(scfg.get('ts') or {}, get, nulls)} AS BIGINT) END AS ts_ms, "
            f"{_fcols(scfg, get, nulls)} FROM ({inner})")


def _rel(root: str, rel: str | None) -> str:
    return sql_str(rel) if rel else f"replace(filename, {sql_str(root.replace(chr(92), '/').rstrip('/') + '/')}, '')"


def _group_names(rx: str) -> list[str]:
    """One struct field name per capture group, by group number (unnamed groups get _g<n>)."""
    pat = re.compile(rx)
    names = {i: n for n, i in pat.groupindex.items()}
    return [names.get(i, f"_g{i}") for i in range(1, pat.groups + 1)]


# -------------------------------------------------------------------------------------------- line sources

def _header_pred(kind: str, scfg: dict[str, Any]) -> str | None:
    if kind == "directive":
        return "starts_with(line, '#')"
    return f"regexp_matches(line, {sql_str(scfg['header_regex'])})" if scfg.get("header_regex") else None


def line_select(name: str, files: list[str], root: str, lcfg: dict[str, Any], rel: str | None = None) -> str:
    """Intermediate SELECT for one line source over `files` (header lines excluded, non-matching kept malformed)."""
    s = _ls(lcfg)[name]
    rx = str(s["line_regex"])
    names = _group_names(rx)
    known = set(names)
    nulls = [str(v) for v in s.get("null_values", ["", "-"])]

    def get(g: str) -> str | None:
        if g not in known:
            raise ValueError(f"line_sources.{name}: group {g!r} is not in line_regex")
        return f"struct_extract(g, {sql_str(g)})"

    hp = _header_pred("line", s)
    where = NONEMPTY + (f" AND NOT {hp}" if hp else "")
    inner = (f"SELECT rel, line, ok, CASE WHEN ok THEN regexp_extract(line, {sql_str(rx)}, {sql_list(names)}) END "
             f"AS g FROM (SELECT {_rel(root, rel)} AS rel, line, regexp_matches(line, {sql_str(rx)}) AS ok "
             f"FROM {line_reader(files)} WHERE {where})")
    return _wrap(name, inner, s, get, nulls)


def header_lines(con: duckdb.DuckDBPyConnection, files: list[str], kind: str, name: str,
                 lcfg: dict[str, Any]) -> int:
    """Non-empty header lines in `files` (kind 'line' | 'directive'): counted as header_line, never as rows."""
    scfg = (_ls(lcfg) if kind == "line" else _ds(lcfg))[name]
    hp = _header_pred(kind, scfg)
    if not hp:
        return 0
    return int(con.execute(f"SELECT count(*) FROM {line_reader(files, filename=False)} "
                           f"WHERE {NONEMPTY} AND {hp}").fetchone()[0])


# ---------------------------------------------------------------------------------------- directive sources

def _unescape(v: str) -> str:
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), v)


def _columns(line: str, prefix: str, sep: str) -> list[str]:
    rest = line[len(prefix):]
    return [c for c in (rest.split() if sep == " " else rest.split(sep)) if c.strip()]


def _log_path(path_line: str | None, file: str, paths: dict[str, Any]) -> str:
    if path_line:
        parts = path_line.split(None, 1)
        if len(parts) == 2 and parts[1].strip() in paths:
            return parts[1].strip()
    stem = Path(file).name.split(".")[0].lower()
    return stem if stem in paths else "_default"


def _segment(name: str, d: dict[str, Any], files: list[str], sep_line: str | None, path_line: str | None,
             fields_line: str | None, rel: str | None) -> dict[str, Any]:
    sep = _unescape(sep_line.split(None, 1)[1]) if sep_line and len(sep_line.split(None, 1)) == 2 \
        else str(d.get("separator", "\t"))
    cols = _columns(fields_line, str(d["fields_directive"]), sep) if fields_line else []
    paths = d.get("paths") or {}
    lp = _log_path(path_line, files[0], paths)
    stype = str((paths.get(lp) or {}).get("source_type") or name)
    return {"source_type": stype, "directive_source": name, "log_path": lp, "separator": sep, "columns": cols,
            "files": files, "rel": rel}


def plan_directive(con: duckdb.DuckDBPyConnection, path: str, name: str, lcfg: dict[str, Any],
                   work_dir: str | Path, rel: str | None = None) -> list[dict[str, Any]]:
    """Segments of one directive file: [{source_type, log_path, separator, columns, files, rel}].

    One DuckDB pass reads the distinct schema directives. One schema (the common case, also when IIS repeats an
    identical header after a restart) -> one segment over the file itself. Several -> the file is streamed once
    (bounded memory) into one work file per schema; those segments carry `rel` so source_seq keeps the original
    file name. Data lines before the first '#fields' get columns [] (all malformed, counted).
    """
    d = _ds(lcfg)[name]
    fd, sd, pd = (str(d.get(k) or "") for k in ("fields_directive", "separator_directive", "path_directive"))
    keys = [k for k in (fd, sd, pd) if k]
    rows = con.execute(
        f"SELECT DISTINCT line FROM {line_reader([path], filename=False)} WHERE starts_with(line, '#') AND "
        f"({' OR '.join(f'starts_with(line, {sql_str(k)})' for k in keys)})").fetchall()
    found = [str(r[0]) for r in rows]
    by = {k: [x for x in found if x.startswith(k)] if k else [] for k in (fd, sd, pd)}
    if all(len(v) <= 1 for v in by.values()):
        return [_segment(name, d, [path], (by[sd] or [None])[0], (by[pd] or [None])[0], (by[fd] or [None])[0],
                         None)]
    log.info("%s: %d distinct schema directives; splitting per schema", path, len(found))
    return _split(path, name, d, (fd, sd, pd), Path(work_dir), rel or Path(path).name)


def _split(path: str, name: str, d: dict[str, Any], keys: tuple[str, str, str], work_dir: Path,
           rel: str) -> list[dict[str, Any]]:
    fd, sd, pd = (k.encode("utf-8") if k else b"\x00" for k in keys)  # absent directive: never a line prefix
    out_dir = work_dir / "directive_split"
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(path, "rb") as fh:
        gz = fh.read(2) == b"\x1f\x8b"
    opener = gzip.open if gz else open
    state: dict[str, bytes | None] = {"sep": None, "path": None}
    handles: dict[tuple[bytes | None, ...], Any] = {}
    files: dict[tuple[bytes | None, ...], str] = {}
    key: tuple[bytes | None, ...] = (None, None, None)
    stem = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(path).name)

    def handle(k: tuple[bytes | None, ...]) -> Any:
        if k not in handles:
            f = out_dir / f"{stem}.{len(handles)}.log"
            files[k] = f.as_posix()
            handles[k] = open(f, "wb")
        return handles[k]

    try:
        with opener(path, "rb") as src:
            for raw in src:
                ln = raw.rstrip(b"\r\n")
                if ln.startswith(sd):
                    state["sep"] = ln
                elif ln.startswith(pd):
                    state["path"] = ln
                elif ln.startswith(fd):
                    key = (state["sep"], state["path"], ln)
                handle(key).write(ln + b"\n")
    finally:
        for h in handles.values():
            h.close()

    def s(b: bytes | None) -> str | None:
        return b.decode("utf-8", "replace") if b is not None else None

    return [_segment(name, d, [files[k]], s(k[0]), s(k[1]), s(k[2]), rel) for k in files]


def directive_select(seg: dict[str, Any], root: str, lcfg: dict[str, Any]) -> str:
    """Intermediate SELECT for one segment of plan_directive (one schema). Directive lines are excluded."""
    d = _ds(lcfg)[seg["directive_source"]]
    pcfg = (d.get("paths") or {}).get(seg["log_path"]) or (d.get("paths") or {}).get("_default") or {}
    cols: list[str] = list(seg["columns"])
    idx = {c: i + 1 for i, c in enumerate(cols)}
    nulls = [str(v) for v in d.get("null_values", ["-"])]

    def get(c: str) -> str | None:
        return f"g[{idx[c]}]" if c in idx else None

    sep = str(seg["separator"])
    split = "regexp_split_to_array(trim(line), ' +')" if sep == " " else f"string_split(line, {sql_str(sep)})"
    ok = f"len(g) = {len(cols)}" if cols else "false"
    inner = (f"SELECT rel, line, {ok} AS ok, g FROM (SELECT {_rel(root, seg.get('rel'))} AS rel, line, "
             f"{split} AS g FROM {line_reader(seg['files'])} WHERE {NONEMPTY} AND NOT starts_with(line, '#'))")
    return _wrap(str(seg["source_type"]), inner, pcfg, get, nulls)


# ----------------------------------------------------------------------------------------- validate / helpers

def validate(con: duckdb.DuckDBPyConnection, lcfg: dict[str, Any]) -> None:
    """Fail before ingest, naming the source: regexes compile in Python and RE2, groups / fields / zones exist."""
    known = set(FIELDS)

    def check(where: str, scfg: dict[str, Any], groups: set[str] | None) -> None:
        for f in scfg.get("fields") or {}:
            if f not in known:
                raise ValueError(f"{where}: unknown canonical field {f!r} (known: attacklens.ingest_sql.FIELDS)")
        t = scfg.get("ts") or {}
        fmt = str(t.get("format", ""))
        if fmt not in ("epoch", "epoch_ms") and "%z" not in fmt and "%Z" not in fmt:
            z = t.get("zone")
            if not z:
                raise ValueError(f"{where}: ts format {fmt!r} has no offset; set ts.zone explicitly")
            if not con.execute("SELECT count(*) FROM pg_timezone_names() WHERE name = ?", [str(z)]).fetchone()[0]:
                raise ValueError(f"{where}: unknown time zone {z!r}")
        if groups is not None:
            refs = [str(g) for g in t.get("fields") or []]
            refs += [str(g) for r in [*(scfg.get("actions") or []), *(scfg.get("outcome_rules") or [])]
                     for g in r.get("when") or {}]
            missing = [g for g in refs if g not in groups]
            if missing:
                raise ValueError(f"{where}: groups {missing} are not in line_regex")
        for r in [*(scfg.get("actions") or []), *(scfg.get("outcome_rules") or [])]:
            for rx in (r.get("when") or {}).values():
                _re2(where, str(rx))

    def _re2(where: str, rx: str) -> None:
        try:
            re.compile(rx)
            con.execute(f"SELECT regexp_matches('', {sql_str(rx)})").fetchone()
        except (re.error, duckdb.Error) as exc:
            raise ValueError(f"{where}: regex does not compile in Python and RE2: {rx!r}: {exc}") from exc

    for name, s in _ls(lcfg).items():
        for k in ("detect_regex", "line_regex", "header_regex"):
            if s.get(k):
                _re2(f"line_sources.{name}.{k}", str(s[k]))
        groups = set(_group_names(str(s["line_regex"])))
        check(f"line_sources.{name}", s, groups)
        line_select(name, ["x"], "", lcfg)  # raises on a field spec naming a missing group
    for name, d in _ds(lcfg).items():
        _re2(f"directive_sources.{name}.detect_regex", str(d["detect_regex"]))
        for p, pcfg in (d.get("paths") or {}).items():
            check(f"directive_sources.{name}.paths.{p}", pcfg, None)


def account(con: duckdb.DuckDBPyConnection, units: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per source_type {rows_in, rows_ok, dropped, drop_reasons, header_lines} for units {source_type, kind, name,
    files, select}. rows_in = non-empty non-header lines; rows_in = rows_ok + dropped always holds."""
    per: dict[str, dict[str, Any]] = {}
    for u in units:
        e = per.setdefault(u["source_type"], {"rows_in": 0, "rows_ok": 0, "dropped": 0, "drop_reasons": {},
                                              "header_lines": 0})
        phys = int(con.execute(f"SELECT count(*) FROM {line_reader(u['files'], filename=False)} "
                               f"WHERE {NONEMPTY}").fetchone()[0])
        hdr = header_lines(con, u["files"], u["kind"], u["name"], u["lcfg"])
        n, bad, nots = con.execute(f"SELECT count(*), count(*) FILTER (WHERE malformed), count(*) FILTER "
                                   f"(WHERE NOT malformed AND ts_ms IS NULL) FROM ({u['select']})").fetchone()
        reasons = {"unparseable_line (kept in ts_ok=false, action=malformed)": int(bad),
                   "missing_or_unparseable_timestamp (kept in ts_ok=false)": int(nots),
                   "reader_skipped": phys - hdr - int(n)}
        e["rows_in"] += phys - hdr
        e["rows_ok"] += int(n) - int(bad) - int(nots)
        e["header_lines"] += hdr
        for k, v in reasons.items():
            if v:
                e["drop_reasons"][k] = e["drop_reasons"].get(k, 0) + v
    for e in per.values():
        e["dropped"] = e["rows_in"] - e["rows_ok"]
    return per


def file_units(con: duckdb.DuckDBPyConnection, path: str, root: str, lcfg: dict[str, Any], work_dir: str | Path,
               first: list[str] | None, rel: str | None = None) -> list[dict[str, Any]]:
    """Sniff one file and build its reader units [{source_type, kind, name, files, select, lcfg}] ([] = not ours)."""
    info = sniff(first, lcfg)
    if not info:
        return []
    name = info["source_type"]
    if info["format"] == "line":
        return [{"source_type": name, "kind": "line", "name": name, "files": [path], "lcfg": lcfg,
                 "select": line_select(name, [path], root, lcfg, rel)}]
    return [{"source_type": s["source_type"], "kind": "directive", "name": name, "files": s["files"], "lcfg": lcfg,
             "segment": s, "select": directive_select(s, root, lcfg)}
            for s in plan_directive(con, path, name, lcfg, work_dir, rel)]
