"""Syslog ingest (Stage 1): ordered header grammar, message pack, auditd payloads. All from config/sources.yaml
`syslog` (headers, pre_unwrap, normalise_process, messages, auditd).

profile.py sniffs with the same header list (`sniff_syslog`), so sniff and parse cannot disagree. A line that
matches no header is malformed (accounted, kept in ts_ok=false), never a row with a silent NULL timestamp.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from attacklens.db import line_reader, sql_list, sql_str

log = logging.getLogger(__name__)

GROUPS = ("ts_bsd", "ts_bsd_year", "ts_iso", "host", "proc", "pid", "msgid", "sd", "msg")
NONEMPTY = "line IS NOT NULL AND trim(line) <> ''"


@lru_cache(maxsize=32)
def _compile(rx: str) -> re.Pattern[str]:
    return re.compile(rx)


def headers(scfg: dict[str, Any]) -> list[dict[str, Any]]:
    """[{name, regex, sniff, groups: {group: 1-based index}}] in config order."""
    out = []
    for h in scfg.get("headers") or []:
        pat = _compile(str(h["regex"]))
        out.append({"name": str(h.get("name", "")), "regex": str(h["regex"]), "sniff": bool(h.get("sniff", True)),
                    "groups": {g: i for g, i in pat.groupindex.items() if g in GROUPS}})
    return out


def sniff_syslog(line: str, scfg: dict[str, Any]) -> dict[str, Any] | None:
    """Profile sniff for one line: first sniffable header that matches -> {format: syslog, source_type, header}.
    A payload that is an audit record makes the file source_type auditd (raw or via audisp-syslog)."""
    for h in headers(scfg):
        if not h["sniff"]:
            continue
        m = _compile(h["regex"]).match(line)
        if m is None:
            continue
        msg = m.groupdict().get("msg") or ""
        acfg = scfg.get("auditd") or {}
        if acfg.get("detect_regex") and re.match(str(acfg["detect_regex"]), msg):
            return {"format": "syslog", "source_type": str(acfg.get("source_type", "auditd")), "header": h["name"]}
        return {"format": "syslog", "source_type": "syslog", "header": h["name"], "msg": msg}
    return None


def strip_header_sql(x: str, scfg: dict[str, Any]) -> str:
    """SQL: the payload of a syslog-wrapped line (header removed), or the line itself when no header matches.
    Lines that already start with a key= token skip the regexes (cheap guard for bulk kv)."""
    arms = " ".join(f"WHEN regexp_matches({x}, {sql_str(h['regex'])}) THEN "
                    f"regexp_extract({x}, {sql_str(h['regex'])}, {h['groups']['msg']})"
                    for h in headers(scfg) if "msg" in h["groups"] and h["name"] != "auditd_raw")
    return (f"CASE WHEN regexp_matches({x}, '^[A-Za-z_0-9]+=') THEN {x} "
            f"WHEN regexp_matches({x}, '^<\\d{{1,3}}>[A-Za-z_0-9]+=') THEN regexp_replace({x}, '^<\\d{{1,3}}>', '') "
            f"{arms} ELSE {x} END")


def _unit_stype(files: list[str], scfg: dict[str, Any]) -> str:
    """Source type of a unit when the caller does not pass it: re-sniff the first file with the same function
    profile.py uses (ingest groups units by (format, source_type), so every file in the unit agrees)."""
    for f in files[:1]:
        try:
            with Path(f).open("rb") as fh:
                text = fh.read(65536).decode("utf-8", errors="replace").lstrip("﻿")
        except OSError:
            break
        for ln in text.splitlines()[:10]:
            info = sniff_syslog(ln.rstrip("\r").lstrip(), scfg) if ln.strip() else None
            if info:
                return str(info["source_type"])
    return "syslog"


def _header_cols(scfg: dict[str, Any]) -> tuple[str, str]:
    """(header index CASE, per-group extraction columns) over `line`."""
    hs = headers(scfg)
    idx = "CASE " + " ".join(f"WHEN regexp_matches(line, {sql_str(h['regex'])}) THEN {i}"
                             for i, h in enumerate(hs)) + " END"
    nil = sql_str(str(scfg.get("nil_value", "-")))
    cols = []
    for g in GROUPS:
        arms = " ".join(f"WHEN {i} THEN regexp_extract(line, {sql_str(h['regex'])}, {h['groups'][g]})"
                        for i, h in enumerate(hs) if g in h["groups"])
        e = f"CASE h {arms} END" if arms else "CAST(NULL AS VARCHAR)"
        cols.append(f"nullif(nullif({e}, ''), {nil}) AS h_{g}" if g != "msg" else f"{e} AS h_{g}")
    return idx if hs else "CAST(NULL AS INTEGER)", ", ".join(cols)


def _proc_expr(scfg: dict[str, Any]) -> str:
    arms = " ".join(f"WHEN regexp_matches(lower(h_proc), {sql_str(str(n['regex']))}) THEN {sql_str(str(n['name']))}"
                    for n in scfg.get("normalise_process") or [])
    return f"CASE {arms} ELSE nullif(lower(h_proc), '') END" if arms else "nullif(lower(h_proc), '')"


def _msg_values(scfg: dict[str, Any], fields: tuple[str, ...]) -> dict[str, str]:
    """Message pack: first matching entry (process / process_regex + regex) sets action, outcome and fields."""
    msgs: list[dict[str, Any]] = scfg.get("messages") or []
    conds = []
    for m in msgs:
        c = f"regexp_matches(msg, {sql_str(m['regex'])})"
        if m.get("process"):
            c = f"proc = {sql_str(str(m['process']).lower())} AND {c}"
        if m.get("process_regex"):
            c = f"regexp_matches(coalesce(proc, ''), {sql_str(str(m['process_regex']))}) AND {c}"
        conds.append(c)

    def per_msg(getter: Any) -> str | None:
        arms = [f"WHEN {c} THEN {getter(m)}" for c, m in zip(conds, msgs) if getter(m) is not None]
        return f"CASE {' '.join(arms)} END" if arms else None

    vals: dict[str, str] = {}
    for key in ("action", "outcome"):
        e = per_msg(lambda m, k=key: sql_str(m[k]) if m.get(k) else None)
        if e:
            vals["event_action" if key == "action" else "outcome"] = e
    for f in fields:
        def g(m: dict[str, Any], f: str = f) -> str | None:
            if f in (m.get("fields") or {}):
                return f"nullif(regexp_extract(msg, {sql_str(m['regex'])}, {int(m['fields'][f])}), '')"
            if f in (m.get("const") or {}):
                return sql_str(str(m["const"][f]))
            return None
        e = per_msg(g)
        if e and f not in ("event_action", "outcome"):
            vals[f] = e
    return vals


def _audit_values(acfg: dict[str, Any]) -> dict[str, str]:
    """auditd record fields from msg (kv tokens separated by space, quote or the ENRICHED \\x1d)."""
    nulls = sql_list([str(x) for x in acfg.get("null_values") or []])

    def key(k: str) -> str:
        rx = "(?:^|[ '\\x1d])" + re.escape(k) + "=(\"[^\"]*\"|[^ '\\x1d]*)"
        v = f"trim(regexp_extract(msg, {sql_str(rx)}, 1), '\"')"
        return f"CASE WHEN list_contains({nulls}, {v}) THEN NULL ELSE nullif({v}, '') END"

    vals = {f: "coalesce(" + ", ".join(key(k) for k in keys) + ")"
            for f, keys in (acfg.get("fields") or {}).items() if keys}
    if acfg.get("argv_regex"):
        argv = (f"nullif(array_to_string(list_transform(regexp_extract_all(msg, {sql_str(acfg['argv_regex'])}, 1), "
                f"lambda x: trim(x, '\"')), ' '), '')")
        types = [str(x) for x in acfg.get("argv_types") or []]
        if types:
            argv = (f"CASE WHEN regexp_extract(msg, 'type=([A-Z_]+) ', 1) IN ({', '.join(sql_str(x) for x in types)}) "
                    f"THEN {argv} END")
        hexes = [f"CASE WHEN regexp_full_match({key(h)}, '([0-9A-Fa-f]{{2}})+') THEN "
                 f"try(replace(decode(unhex({key(h)})), chr(0), ' ')) ELSE {key(h)} END"
                 for h in acfg.get("hex_fields") or []]
        vals["command_line"] = "coalesce(" + ", ".join([argv] + hexes) + ")"
    rules: list[dict[str, Any]] = acfg.get("actions") or []

    def cond(r: dict[str, Any]) -> str:
        return " AND ".join(f"lower(coalesce({key(k)}, '')) IN ({', '.join(sql_str(str(x).lower()) for x in v)})"
                            for k, v in (r.get("when") or {}).items()) or "true"

    for attr, out in (("action", "event_action"), ("outcome", "outcome")):
        arms = " ".join(f"WHEN {cond(r)} THEN {sql_str(str(r[attr]))}" for r in rules if attr in r)
        if arms:
            vals[out] = f"CASE {arms} END"
    return vals


def syslog_select(files: list[str], root: str, scfg: dict[str, Any], year: int, syslog_fmt: str,
                  formats: list[str], rejects: str | None, fields: tuple[str, ...], ts_expr: Any,
                  stype: str | None = None) -> str:
    """Intermediate SELECT for syslog / auditd units. ts: audit(epoch) > ISO > BSD with year > BSD (+baseline year)."""
    stype = stype or _unit_stype(files, scfg)
    acfg = scfg.get("auditd") or {}
    hidx, hcols = _header_cols(scfg)
    unwrap = scfg.get("pre_unwrap")
    msg = (f"CASE WHEN regexp_matches(h_msg, {sql_str(unwrap)}) THEN regexp_extract(h_msg, {sql_str(unwrap)}, 2) "
           f"ELSE h_msg END" if unwrap else "h_msg")
    is_audit = (f"regexp_matches(coalesce(msg, ''), {sql_str(acfg['detect_regex'])})"
                if acfg.get("detect_regex") else "false")
    sv, av = _msg_values(scfg, fields), _audit_values(acfg) if acfg else {}
    vals: dict[str, str] = {}
    for f in fields:
        a, s = av.get(f), sv.get(f)
        if f == "host":
            s = "h_host"
        elif f == "process_name":
            s = "proc"
        if a and s:
            vals[f] = f"CASE WHEN is_audit THEN {a if f not in ('host',) else f'coalesce({a}, {s})'} ELSE {s} END"
        elif a:
            vals[f] = f"CASE WHEN is_audit THEN {a} END"
        elif s:
            vals[f] = f"CASE WHEN NOT is_audit THEN {s} END" if f not in ("host",) else s
    fcols = ", ".join(f"{vals.get(f, 'CAST(NULL AS VARCHAR)')} AS f_{f}" for f in fields)
    bsd = (f"epoch_ms(try_strptime({sql_str(str(year))} || ' ' || regexp_replace(h_ts_bsd, '\\s+', ' ', 'g'), "
           f"{sql_str(syslog_fmt)})::TIMESTAMPTZ)")
    bsd_y = (f"epoch_ms(try_strptime(regexp_replace(h_ts_bsd_year, '\\s+', ' ', 'g'), "
             f"{sql_str(str(scfg.get('ts_bsd_year_format', '%b %d %Y %H:%M:%S')))})::TIMESTAMPTZ)")
    trx = sql_str(str(acfg.get("ts_regex", "msg=audit\\((\\d+)\\.(\\d+):")))
    audit_ts = (f"CASE WHEN is_audit THEN try_cast(regexp_extract(msg, {trx}, 1) AS BIGINT) * 1000 + "
                f"try_cast(rpad(substr(regexp_extract(msg, {trx}, 2), 1, 3), 3, '0') AS BIGINT) END")
    ts = (f"coalesce({audit_ts}, CASE WHEN h_ts_iso IS NOT NULL THEN {ts_expr('h_ts_iso', formats)} "
          f"WHEN h_ts_bsd_year IS NOT NULL THEN {bsd_y} WHEN h_ts_bsd IS NOT NULL THEN {bsd} END)")
    rel = f"replace(filename, {sql_str(root.rstrip('/') + '/')}, '')"
    return (f"SELECT {sql_str(stype)} AS source_type, rel, line, line AS raw_line, h IS NULL AS malformed, "
            f"CASE WHEN h IS NOT NULL THEN {ts} END AS ts_ms, {fcols} FROM ("
            f"SELECT *, {is_audit} AS is_audit FROM ("
            f"SELECT *, {_proc_expr(scfg)} AS proc, {msg} AS msg FROM ("
            f"SELECT rel, line, h, {hcols} FROM ("
            f"SELECT {rel} AS rel, line, {hidx} AS h FROM {line_reader(files, rejects=rejects)} WHERE {NONEMPTY}))))")
