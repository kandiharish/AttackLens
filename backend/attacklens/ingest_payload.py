"""Vendor firewall payload parsers (Stage 1, sweep item 15): PAN-OS CSV, Cisco ASA message ids, pfSense filterlog,
Check Point Log Exporter and LEEF 1.0/2.0, all from config/payloads.yaml.

The syslog header grammar (ingest_syslog.py) yields `msg`; `payload_select` wraps any SELECT that has that column
and adds `p_type`, `p_variant`, `p_ts_ms`, `p_ts_zoned`, `p_unparsed` and one `p_<field>` VARCHAR per PFIELDS.
`detect()` (Python sniff) and the SQL CASE come from the same ordered `types` list, so routing and parsing cannot
disagree. A row whose payload type is detected but cannot be parsed keeps NULL fields and gets a reason in
`p_unparsed` (`unmapped_id`, `regex_miss`, `no_layout`, `missing_required`, `detect_miss`), so it can be counted.
"""

from __future__ import annotations

import logging
import re
from functools import lru_cache
from typing import Any

from attacklens.db import sql_list, sql_str

log = logging.getLogger(__name__)

PFIELDS: tuple[str, ...] = (
    "event_action", "outcome", "host", "host_ip", "user", "group", "src_ip", "src_port", "dst_ip", "dst_port",
    "proto", "fw_rule", "bytes", "bytes_in", "app", "signature", "vendor_severity", "src_zone", "dst_zone",
    "direction",
)
OUT_COLUMNS: tuple[str, ...] = ("p_type", "p_variant", "p_ts_ms", "p_ts_zoned", "p_unparsed",
                                *(f"p_{f}" for f in PFIELDS))
NULL = "CAST(NULL AS VARCHAR)"


def section(cfg: dict[str, Any]) -> dict[str, Any]:
    """Accept the full load_config() dict or the payloads section itself."""
    return cfg.get("payloads", cfg) if "types" not in cfg else cfg


@lru_cache(maxsize=256)
def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def types(cfg: dict[str, Any], force: str | None = None) -> list[dict[str, Any]]:
    """Ordered payload types; `force` selects exactly that type (also `sniff: false` ones)."""
    ts = section(cfg).get("types") or []
    if force:
        out = [t for t in ts if t.get("name") == force]
        if not out:
            raise ValueError(f"unknown payload type {force!r}")
        return out
    return [t for t in ts if t.get("sniff", True)]


def _variants(t: dict[str, Any]) -> list[dict[str, Any]]:
    """Messages (msgid) or layouts (csv); kv / leef have one implicit variant = the type itself."""
    if t["kind"] == "msgid":
        return list(t.get("messages") or [])
    if t["kind"] == "csv":
        return list(t.get("layouts") or [])
    return [{"name": t["name"]}]


def _inherit(t: dict[str, Any], v: dict[str, Any], key: str) -> Any:
    return v[key] if key in v else t.get(key)


# ---------------------------------------------------------------- input shaping + sniff (Python and SQL twins)

def payload_text(cfg: dict[str, Any], msg: str | None, proc: str | None = None, sd: str | None = None,
                 line: str | None = None) -> str | None:
    """Python twin of input_sql(): the text the payload parsers see."""
    inp = section(cfg).get("input") or {}
    if sd and inp.get("sd_payload_regex") and _rx(str(inp["sd_payload_regex"])).search(sd):
        return sd
    for r in inp.get("tag_rejoin") or []:
        if proc and _rx(str(r["proc_regex"])).search(proc):
            return proc + str(r.get("sep", ": ")) + (msg or "")
    if msg is None and sd is None and line is not None:
        return _rx(str(inp.get("pri_strip_regex", r"^<\d{1,3}>"))).sub("", line, count=1)
    return msg


def input_sql(cfg: dict[str, Any], msg: str, proc: str | None = None, sd: str | None = None,
              line: str | None = None) -> str:
    """SQL expression of the payload text from syslog_select's columns (h_msg/msg, h_proc, h_sd, line)."""
    inp = section(cfg).get("input") or {}
    arms = []
    if sd and inp.get("sd_payload_regex"):
        arms.append(f"WHEN {sd} IS NOT NULL AND regexp_matches({sd}, {sql_str(str(inp['sd_payload_regex']))}) "
                    f"THEN {sd}")
    for r in (inp.get("tag_rejoin") or []) if proc else []:
        arms.append(f"WHEN regexp_matches(coalesce({proc}, ''), {sql_str(str(r['proc_regex']))}) "
                    f"THEN {proc} || {sql_str(str(r.get('sep', ': ')))} || coalesce({msg}, '')")
    if line:
        sd_null = f" AND {sd} IS NULL" if sd else ""
        arms.append(f"WHEN {msg} IS NULL{sd_null} THEN regexp_replace({line}, "
                    f"{sql_str(str(inp.get('pri_strip_regex', '^<[0-9]{1,3}>')))}, '')")
    return f"CASE {' '.join(arms)} ELSE {msg} END" if arms else msg


def detect(text: str | None, cfg: dict[str, Any], force: str | None = None) -> str | None:
    """Payload type of one payload text (first `detect` regex in config order), or None."""
    if not text:
        return None
    for t in types(cfg, force):
        if _rx(str(t["detect"])).search(text):
            return str(t["name"])
    return None


def detect_sql(x: str, cfg: dict[str, Any], force: str | None = None) -> str:
    arms = " ".join(f"WHEN regexp_matches({x}, {sql_str(str(t['detect']))}) THEN {sql_str(str(t['name']))}"
                    for t in types(cfg, force))
    return f"CASE {arms} END" if arms else NULL


# ---------------------------------------------------------------- source values per kind

def _nulls(cfg: dict[str, Any]) -> str:
    return sql_list([str(v) for v in section(cfg).get("null_values") or ["", "-"]])


def _clean(e: str, cfg: dict[str, Any]) -> str:
    v = f"trim({e})"
    return f"CASE WHEN {v} IS NULL OR list_contains({_nulls(cfg)}, {v}) THEN NULL ELSE {v} END"


def _csv_col(i: int, cfg: dict[str, Any]) -> str:
    raw = f"p_parts[{int(i)}]"
    unq = (f"CASE WHEN {raw} LIKE '\"%\"' AND length({raw}) >= 2 THEN replace(substr({raw}, 2, length({raw}) - 2), "
           f"'\"\"', '\"') ELSE {raw} END")
    return _clean(unq, cfg)


def _src(t: dict[str, Any], v: dict[str, Any], key: Any, cfg: dict[str, Any]) -> str:
    """SQL value of one source key in the context of type t / variant v."""
    kind = t["kind"]
    if key == "_id":
        return _clean("p_id", cfg)
    if kind == "csv":
        return _csv_col(int(key), cfg)
    if kind == "msgid":
        gi = _rx(str(v["regex"])).groupindex
        if str(key) not in gi:
            raise ValueError(f"payload {t['name']}/{v.get('name')}: no group {key!r} in regex")
        return _clean(f"regexp_extract(p_body, {sql_str(str(v['regex']))}, {gi[str(key)]})", cfg)
    if kind == "kv":
        rx = str(t["pair_regex"]).replace("{key}", re.escape(str(key)))
        return _clean(f"replace(regexp_extract(p_body, {sql_str(rx)}, 1), '\\\"', '\"')", cfg)
    if kind == "leef":
        rx = "(?:^|\\t)" + re.escape(str(key)) + "=([^\\t]*)"
        return _clean(f"regexp_extract(p_body, {sql_str(rx)}, 1)", cfg)
    raise ValueError(f"payload {t['name']}: unknown kind {kind!r}")


def _keys_value(t: dict[str, Any], v: dict[str, Any], spec: Any, cfg: dict[str, Any]) -> str:
    keys = spec if isinstance(spec, list) else [spec]
    vals = [_src(t, v, k, cfg) for k in keys]
    return vals[0] if len(vals) == 1 else f"coalesce({', '.join(vals)})"


def _rule_cond(t: dict[str, Any], v: dict[str, Any], r: dict[str, Any], cfg: dict[str, Any]) -> str:
    conds = []
    for k, vals in (r.get("when") or {}).items():
        e = _src(t, v, k, cfg)
        vl = [str(x).lower() for x in (vals if isinstance(vals, list) else [vals])]
        conds.append(f"{e} IS NOT NULL" if vl == ["*"] else f"lower({e}) IN ({', '.join(sql_str(x) for x in vl)})")
    for k, rx in (r.get("when_regex") or {}).items():
        conds.append(f"regexp_matches(coalesce({_src(t, v, k, cfg)}, ''), {sql_str(str(rx))})")
    return " AND ".join(conds) or "true"


def _field_expr(t: dict[str, Any], v: dict[str, Any], f: str, cfg: dict[str, Any]) -> str | None:
    """Expression of canonical field f for variant v (None when the variant does not set it)."""
    if f in ("event_action", "outcome"):
        attr = "action" if f == "event_action" else "outcome"
        rules = _inherit(t, v, "actions") or []
        arms = [f"WHEN {_rule_cond(t, v, r, cfg)} THEN {sql_str(str(r[attr]))}" for r in rules if attr in r]
        const = _inherit(t, v, attr)
        if arms:
            return f"CASE {' '.join(arms)}{' ELSE ' + sql_str(str(const)) if const else ''} END"
        return sql_str(str(const)) if const else None
    const = (_inherit(t, v, "const") or {}).get(f)
    spec = (_inherit(t, v, "fields") or {}).get(f)
    if spec is not None:
        e = _keys_value(t, v, spec, cfg)
        return f"coalesce({e}, {sql_str(str(const))})" if const is not None else e
    return sql_str(str(const)) if const is not None else None


# ---------------------------------------------------------------- timestamps

def _epoch(e: str) -> str:
    """Epoch digits s / ms / us / ns -> ms."""
    return (f"CASE WHEN regexp_full_match({e}, '\\d{{9,10}}(\\.\\d+)?') THEN CAST(try_cast({e} AS DOUBLE) * 1000 AS BIGINT) "
            f"WHEN regexp_full_match({e}, '\\d{{12,13}}') THEN try_cast({e} AS BIGINT) "
            f"WHEN regexp_full_match({e}, '\\d{{16}}') THEN try_cast({e} AS BIGINT) // 1000 "
            f"WHEN regexp_full_match({e}, '\\d{{19}}') THEN try_cast({e} AS BIGINT) // 1000000 END")


def _strp(e: str, fmt: str) -> str:
    return f"epoch_ms(try_strptime({e}, {sql_str(fmt)})::TIMESTAMPTZ)"


def _ts_exprs(t: dict[str, Any], cfg: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(zoned candidates, naive candidates) for type t, in config order."""
    zoned: list[str] = []
    naive: list[str] = []
    v0 = _variants(t)[0] if t["kind"] == "msgid" and _variants(t) else {"name": t["name"]}
    for c in t.get("ts") or []:
        if "regex" in c:
            e = f"nullif(regexp_extract(p_text, {sql_str(str(c['regex']))}, 1), '')"
            zoned.append(f"epoch_ms(try_cast({e} AS TIMESTAMPTZ))")
            continue
        e = _src(t, v0, c["key"], cfg)
        if c.get("epoch"):
            zoned.append(_epoch(e))
        elif "format" in c:
            (zoned if re.search("%[zZ]", str(c["format"])) else naive).append(_strp(e, str(c["format"])))
        elif "format_key" in c:
            fk = _src(t, v0, c["format_key"], cfg)
            fmts = t.get("devtime_formats") or {}
            z_arms = [f"WHEN {fk} = {sql_str(str(j))} THEN {_strp(e, str(p))}"
                      for j, p in fmts.items() if re.search("%[zZ]", str(p))]
            n_arms = [f"WHEN {fk} = {sql_str(str(j))} THEN {_strp(e, str(p))}"
                      for j, p in fmts.items() if not re.search("%[zZ]", str(p))]
            zoned.append(f"CASE WHEN {fk} IS NULL OR lower({fk}) = 'epoch' THEN {_epoch(e)} "
                         f"{' '.join(z_arms)} END")
            naive.append(f"CASE {' '.join(n_arms)} ELSE epoch_ms(try_cast({e} AS TIMESTAMPTZ)) END"
                         if n_arms else f"epoch_ms(try_cast({e} AS TIMESTAMPTZ))")
    return zoned, naive


# ---------------------------------------------------------------- the SELECT

def _leef_body(t: dict[str, Any]) -> tuple[str, str]:
    hdr, drx = sql_str(str(t["header_regex"])), sql_str(str(t["delim_regex"]))
    rest = f"regexp_extract(p_text, {hdr}, 6)"
    d = f"regexp_extract({rest}, {drx}, 1)"
    dch = (f"CASE WHEN length({d}) > 1 THEN chr(try_cast('0x' || regexp_replace({d}, '^0?[xX]', '') AS INTEGER)) "
           f"ELSE {d} END")
    body = (f"CASE WHEN regexp_extract(p_text, {hdr}, 1) = '2.0' AND regexp_matches({rest}, {drx}) "
            f"THEN replace(regexp_extract({rest}, {drx}, 2), {dch}, chr(9)) ELSE {rest} END")
    return f"regexp_extract(p_text, {hdr}, 5)", body


def _cond_k(t: dict[str, Any], i: int, v: dict[str, Any], cfg: dict[str, Any]) -> str:
    if t["kind"] == "msgid":
        ids = ", ".join(sql_str(str(x)) for x in v.get("ids") or [])
        return f"p_id IN ({ids}) AND regexp_matches(p_body, {sql_str(str(v['regex']))})"
    if t["kind"] == "csv":
        return _rule_cond(t, v, {"when": v.get("when") or {}}, cfg)
    return "true"


def _miss_reason(t: dict[str, Any]) -> str:
    if t["kind"] == "msgid":
        ids = sorted({str(x) for v in _variants(t) for x in v.get("ids") or []})
        return f"CASE WHEN p_id IN ({', '.join(sql_str(x) for x in ids) or 'NULL'}) THEN 'regex_miss' ELSE 'unmapped_id' END"
    return "'no_layout'"


def payload_select(src: str, cfg: dict[str, Any], msg_col: str = "msg", force: str | None = None) -> str:
    """Wrap `src` (any SELECT with column `msg_col`) and add OUT_COLUMNS. Pure: builds SQL text only.
    `force` parses every row as that type (rows its detect regex rejects get p_unparsed = 'detect_miss')."""
    ts_ = types(cfg, force)
    csv_names = [str(t["name"]) for t in ts_ if t["kind"] == "csv"]
    split = sql_str(str(section(cfg).get("csv_split_regex", ',("(?:[^"]|"")*"|[^,]*)')))
    id_arms, body_arms, k_arms, miss_arms, ts_arms = [], [], [], [], []
    farms: dict[str, list[str]] = {f: [] for f in (*PFIELDS, "p_variant")}
    req_arms: list[str] = []
    for t in ts_:
        n = sql_str(str(t["name"]))
        if t["kind"] == "msgid":
            idr = sql_str(str(t["id_regex"]))
            id_arms.append(f"WHEN {n} THEN regexp_extract(p_text, {idr}, 2)")
            body_arms.append(f"WHEN {n} THEN regexp_extract(p_text, {idr}, 3)")
        elif t["kind"] == "leef":
            pid, body = _leef_body(t)
            id_arms.append(f"WHEN {n} THEN {pid}")
            body_arms.append(f"WHEN {n} THEN {body}")
        elif t["kind"] == "kv":
            body_arms.append(f"WHEN {n} THEN p_text")
        vs = _variants(t)
        k_arms.append(f"WHEN {n} THEN CASE " + " ".join(f"WHEN {_cond_k(t, i, v, cfg)} THEN {i}"
                                                         for i, v in enumerate(vs)) + " END")
        miss_arms.append(f"WHEN {n} THEN {_miss_reason(t)}")
        for i, v in enumerate(vs):
            sel = f"p_type = {n} AND p_k = {i}"
            farms["p_variant"].append(f"WHEN {sel} THEN {sql_str(str(v.get('name', i)))}")
            for f in PFIELDS:
                e = _field_expr(t, v, f, cfg)
                if e is not None:
                    farms[f].append(f"WHEN {sel} THEN {e}")
            req = _inherit(t, v, "require_any") or []
            if req:
                req_arms.append(f"WHEN {sel} AND " + " AND ".join(f"p_{r} IS NULL" for r in req)
                                + " THEN 'missing_required'")
        zoned, naive = _ts_exprs(t, cfg)
        z = f"coalesce({', '.join(zoned)})" if zoned else "CAST(NULL AS BIGINT)"
        nv = f"coalesce({', '.join(naive)})" if naive else "CAST(NULL AS BIGINT)"
        ts_arms.append((n, z, nv))
    pmap = (section(cfg).get("value_maps") or {}).get("proto") or {}
    farms_sql = {f: (f"CASE {' '.join(a)} END" if a else NULL) for f, a in farms.items()}
    if pmap:
        pm = " ".join(f"WHEN {sql_str(str(k))} THEN {sql_str(str(v))}" for k, v in pmap.items())
        farms_sql["proto"] = f"CASE lower({farms_sql['proto']}) {pm} ELSE lower({farms_sql['proto']}) END"
    fcols = ", ".join([f"{farms_sql['p_variant']} AS p_variant"] + [f"{farms_sql[f]} AS p_{f}" for f in PFIELDS])
    zcase = "CASE p_type " + " ".join(f"WHEN {n} THEN {z}" for n, z, _ in ts_arms) + " END"
    ncase = "CASE p_type " + " ".join(f"WHEN {n} THEN {nv}" for n, _, nv in ts_arms) + " END"
    detect_miss = f"WHEN p_text IS NOT NULL AND p_type IS NULL THEN 'detect_miss' " if force else ""
    unparsed = (f"CASE {detect_miss}WHEN p_type IS NULL THEN NULL WHEN p_k IS NULL THEN CASE p_type "
                f"{' '.join(miss_arms)} END {' '.join(req_arms)} END")
    case = lambda arms: f"CASE p_type {' '.join(arms)} END" if arms else NULL  # noqa: E731
    parts = (f"CASE WHEN p_type IN ({', '.join(sql_str(x) for x in csv_names)}) THEN "
             f"regexp_extract_all(',' || p_text, {split}, 1) END" if csv_names else "CAST(NULL AS VARCHAR[])")
    return (f"SELECT * EXCLUDE (p_text, p_id, p_body, p_parts, p_k, p_zts, p_nts), "
            f"coalesce(p_zts, p_nts) AS p_ts_ms, CASE WHEN p_type IS NOT NULL THEN p_zts IS NOT NULL END AS p_ts_zoned, "
            f"{unparsed} AS p_unparsed FROM ("
            f"SELECT *, {fcols}, {zcase} AS p_zts, {ncase} AS p_nts FROM ("
            f"SELECT *, CASE p_type {' '.join(k_arms)} END AS p_k FROM ("
            f"SELECT *, {case(id_arms)} AS p_id, {case(body_arms)} AS p_body, {parts} AS p_parts FROM ("
            f"SELECT *, {detect_sql('p_text', cfg, force)} AS p_type FROM ("
            f"SELECT *, {msg_col} AS p_text FROM ({src}))))))")


def unparsed_counts_sql(rel: str) -> str:
    """Per (payload type, reason) counts of rows that were detected but not (fully) parsed."""
    return (f"SELECT p_type, p_unparsed AS reason, count(*) AS n FROM {rel} WHERE p_unparsed IS NOT NULL "
            f"GROUP BY ALL")
