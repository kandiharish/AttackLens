"""SQL builders for Stage 1 ingest. Each source format becomes one SELECT that yields the same intermediate
columns (f_* VARCHAR + source_type, rel, line, raw_line, malformed, ts_ms); normalize_sql() maps them to the
canonical schema. Everything is generated from config/sources.yaml and config/pipeline.yaml.
"""

from __future__ import annotations

import json
from typing import Any

from attacklens.db import line_reader, sql_list, sql_str

FIELDS: tuple[str, ...] = (
    "ts", "event_id", "event_action", "outcome", "logon_id", "logon_type", "host", "host_ip", "user",
    "subject_user", "target_name", "member_name", "group", "src_ip", "src_port", "dst_ip", "dst_port",
    "dst_domain", "process_name", "process_path", "parent_process", "command_line", "file_path", "file_ext",
    "registry_path", "bytes", "direction", "service_name",
)
CANONICAL_ACTIONS = ("login_failed", "login_success", "priv_assigned", "user_created", "group_member_added",
                     "proc_start", "conn_out", "conn_allowed", "conn_denied", "dns_query", "file_write",
                     "file_rename", "reg_set", "service_installed", "scheduled_task", "log_cleared", "other")
LOGON_ACTIONS = "('login_success', 'login_failed')"
NONEMPTY = "line IS NOT NULL AND trim(line) <> ''"


def _clean(expr: str) -> str:
    """'' and '-' -> NULL."""
    return f"nullif(nullif(trim({expr}), ''), '-')"


def _rel(root: str) -> str:
    return f"replace(filename, {sql_str(root.rstrip('/') + '/')}, '')"


def ts_expr(x: str, formats: list[str]) -> str:
    """Epoch ms from a timestamp STRING: TIMESTAMPTZ cast, then epoch digits, then strptime formats (UTC)."""
    fmts = f", try_strptime({x}, {sql_list(formats)})::TIMESTAMPTZ" if formats else ""
    return (f"coalesce(epoch_ms(try_cast({x} AS TIMESTAMPTZ)), "
            f"CASE WHEN regexp_full_match({x}, '\\d{{12,13}}') THEN try_cast({x} AS BIGINT) "
            f"WHEN regexp_full_match({x}, '\\d{{9,10}}(\\.\\d+)?') THEN CAST(try_cast({x} AS DOUBLE) * 1000 AS BIGINT) END"
            f"{', epoch_ms(' + fmts[2:] + ')' if fmts else ''})")


def _fcols(values: dict[str, str]) -> str:
    return ", ".join(f"{values.get(f, 'CAST(NULL AS VARCHAR)')} AS f_{f}" for f in FIELDS)


def json_select(stype: str, files: list[str], root: str, scfg: dict[str, Any], sources: dict[str, Any],
                formats: list[str]) -> str:
    fields: dict[str, list[str]] = scfg.get("fields") or {}
    paths: list[str] = []
    index: dict[str, list[int]] = {}
    for f in FIELDS:
        for p in fields.get(f) or []:
            paths.append(p)
            index.setdefault(f, []).append(len(paths))
    vals = {f: "coalesce(" + ", ".join(_clean(f"v[{i}]") for i in idx) + ")" for f, idx in index.items()}
    top = {k: None for k in sources.get("label_keys") or []}
    nested = {k: {s: None for s in subs} for k, subs in (sources.get("label_nested_keys") or {}).items()}
    raw = json_raw_line(top, nested)
    return (f"SELECT {sql_str(stype)} AS source_type, rel, line, {raw} AS raw_line, v IS NULL AS malformed, "
            f"{ts_expr('f_ts0', formats)} AS ts_ms, * EXCLUDE (v, line, rel, f_ts0) FROM ("
            f"SELECT rel, line, v, {vals.get('ts', 'CAST(NULL AS VARCHAR)')} AS f_ts0, {_fcols(vals)} FROM ("
            f"SELECT {_rel(root)} AS rel, line, try(json_extract_string(line, {sql_list(paths)})) AS v "
            f"FROM {line_reader(files)} WHERE {NONEMPTY}))")


def json_raw_line(top: dict[str, None], nested: dict[str, dict[str, None]]) -> str:
    """raw_line without label fields. Valid JSON with a top-level label key: json_merge_patch (rare rows only).
    Nested hints (event.kind, event.severity, ...) with scalar values: regex removal (cheap, every row).
    Malformed JSON keeps its original text, cut at the first label key if one appears."""
    if not top and not nested:
        return "line"
    p_top, p_full = sql_str(json.dumps(top)), sql_str(json.dumps({**top, **nested}))
    top_rx = sql_str('"(' + "|".join(top) + ')"\\s*:') if top else None
    has_top = f"regexp_matches(line, {top_rx})" if top_rx else "false"
    nested_test = " AND ".join(f"json_type(line, {sql_str('$.' + k)}) = 'OBJECT'" for k in nested) or "false"
    cut = (f"regexp_replace(line, {sql_str('[,{]?\\s*\"(' + '|'.join(top) + ')\"\\s*:.*$')}, '')"
           if top else "line")
    expr = (f"CASE WHEN v IS NULL THEN CASE WHEN {has_top} THEN {cut} ELSE line END "
            f"WHEN {has_top} THEN CAST(json_merge_patch(line, CASE WHEN {nested_test} THEN {p_full} "
            f"ELSE {p_top} END) AS VARCHAR) ELSE line END")
    subs = [s for v in nested.values() for s in v]
    if subs:
        kv = '"(?:' + "|".join(subs) + ')"\\s*:\\s*(?:"[^"\\\\]*"|-?[0-9.]+)'
        expr = f"regexp_replace({expr}, {sql_str(',\\s*' + kv + '|' + kv + '\\s*,?')}, '', 'g')"
    return expr


def _cef_key(key: str) -> str:
    rx = f"(?:^|\\s){key}=((?:\\\\.|[^\\\\])*?)(?:\\s+[A-Za-z0-9_.]+=|$)"
    v = f"nullif(regexp_extract(ext, {sql_str(rx)}, 1), '')"
    return f"replace(replace({v}, '\\=', '='), '\\\\', '\\')"


def cef_select(files: list[str], root: str, ccfg: dict[str, Any], formats: list[str]) -> str:
    fields: dict[str, list[str]] = ccfg.get("fields") or {}
    vals = {f: "coalesce(" + ", ".join(_clean(_cef_key(k)) for k in keys) + ")"
            for f, keys in fields.items() if keys}
    pfx_host = ("nullif(regexp_extract(line, '^(?:<\\d+>)?(?:[A-Z][a-z]{2}\\s+\\d+\\s+\\d\\d:\\d\\d:\\d\\d|"
                "\\d{4}-\\d\\d-\\d\\dT\\S+)\\s+(\\S+)\\s+.*?CEF:\\d+\\|', 1), '')")
    vals["host"] = f"coalesce({vals['host']}, {pfx_host})" if "host" in vals else pfx_host
    raw = "regexp_replace(line, '\\s*cs\\d+Label=mitre\\s+cs\\d+=\\S*', '', 'g')"
    return (f"SELECT 'cef' AS source_type, rel, line, {raw} AS raw_line, "
            f"ext IS NULL AS malformed, {ts_expr('f_ts', formats)} AS ts_ms, * EXCLUDE (ext, line, rel) FROM ("
            f"SELECT rel, line, ext, {_fcols(vals)} FROM ("
            f"SELECT {_rel(root)} AS rel, line, "
            f"nullif(regexp_extract(line, 'CEF:\\d+\\|(?:[^|]*\\|){{6}}(.*)$', 1), '') AS ext "
            f"FROM {line_reader(files)} WHERE {NONEMPTY}))")


def syslog_select(files: list[str], root: str, scfg: dict[str, Any], year: int, syslog_fmt: str,
                  formats: list[str]) -> str:
    msgs: list[dict[str, Any]] = scfg.get("messages") or []
    conds = []
    for m in msgs:
        c = f"regexp_matches(msg, {sql_str(m['regex'])})"
        if m.get("process"):
            c = f"proc = {sql_str(str(m['process']).lower())} AND {c}"
        conds.append(c)

    def per_msg(getter: Any) -> str | None:
        arms = [f"WHEN {c} THEN {getter(m)}" for c, m in zip(conds, msgs) if getter(m) is not None]
        return f"CASE {' '.join(arms)} END" if arms else None

    vals: dict[str, str] = {"host": "nullif(p.host, '')", "process_name": "proc"}
    a = per_msg(lambda m: sql_str(m["action"]) if m.get("action") else None)
    if a:
        vals["event_action"] = a
    o = per_msg(lambda m: sql_str(m["outcome"]) if m.get("outcome") else None)
    if o:
        vals["outcome"] = o
    for f in FIELDS:
        def g(m: dict[str, Any], f: str = f) -> str | None:
            if f in (m.get("fields") or {}):
                return f"nullif(regexp_extract(msg, {sql_str(m['regex'])}, {int(m['fields'][f])}), '')"
            if f in (m.get("const") or {}):
                return sql_str(str(m["const"][f]))
            return None
        e = per_msg(g)
        if e and f not in ("event_action", "outcome"):
            vals[f] = e
    bsd = (f"epoch_ms(try_strptime({sql_str(str(year))} || ' ' || regexp_replace(p.ts_bsd, '\\s+', ' ', 'g'), "
           f"{sql_str(syslog_fmt)})::TIMESTAMPTZ)")
    ts = f"CASE WHEN p.ts_bsd <> '' THEN {bsd} WHEN p.ts_iso <> '' THEN {ts_expr('p.ts_iso', formats)} END"
    return (f"SELECT 'syslog' AS source_type, rel, line, line AS raw_line, false AS malformed, {ts} AS ts_ms, "
            f"{_fcols(vals)} FROM (SELECT *, nullif(lower(p.proc), '') AS proc, p.msg AS msg FROM ("
            f"SELECT {_rel(root)} AS rel, line, regexp_extract(line, {sql_str(scfg['line_regex'])}, "
            f"['ts_bsd', 'ts_iso', 'host', 'proc', 'pid', 'msg']) AS p FROM {line_reader(files)} WHERE {NONEMPTY}))")


def csv_select(stype: str, files: list[str], root: str, delim: str, columns: list[str],
               ccfg: dict[str, Any], formats: list[str]) -> str:
    by_lower = {c.lower(): c for c in columns}

    def q(c: str) -> str:
        return '"' + c.replace('"', '""') + '"'

    vals: dict[str, str] = {}
    for f, aliases in (ccfg.get("fields") or {}).items():
        hit = [by_lower[a.lower()] for a in aliases or [] if a.lower() in by_lower]
        if hit:
            vals[f] = "coalesce(" + ", ".join(_clean(q(h)) for h in hit) + ")"
    raw = f"concat_ws({sql_str(delim)}, " + ", ".join(f"coalesce({q(c)}, '')" for c in columns) + ")"
    reader = (f"read_csv({sql_list(files)}, header=true, delim={sql_str(delim)}, all_varchar=true, "
              f"filename=true, null_padding=true, ignore_errors=true)")
    return (f"SELECT {sql_str(stype)} AS source_type, rel, raw AS line, raw AS raw_line, false AS malformed, "
            f"{ts_expr('f_ts', formats)} AS ts_ms, * EXCLUDE (rel, raw) FROM ("
            f"SELECT {_rel(root)} AS rel, {raw} AS raw, {_fcols(vals)} FROM {reader})")


def _user(x: str) -> str:
    """NFC, lower, strip DOMAIN\\ and @domain, '' / '-' -> NULL."""
    inner = f"regexp_replace(regexp_replace(lower(nfc_normalize(trim({x}))), '^.*\\\\', ''), '@.*$', '')"
    return _clean(inner)


def _base(x: str) -> str:
    return f"lower(nullif(regexp_extract({x}, '([^\\\\/]+)$', 1), ''))"


def action_case(sources: dict[str, Any]) -> str:
    am = sources.get("action_map") or {}
    arms = [f"WHEN event_id_i = {int(k)} THEN {sql_str(v)}" for k, v in (am.get("event_ids") or {}).items()]
    eva = {str(k).lower(): v for k, v in (am.get("event_actions") or {}).items()}
    for a in CANONICAL_ACTIONS:
        eva.setdefault(a, a)
    for k, v in eva.items():
        if isinstance(v, dict):
            v = (f"CASE outcome_n WHEN 'success' THEN {sql_str(v.get('success', 'other'))} "
                 f"WHEN 'failure' THEN {sql_str(v.get('failure', 'other'))} ELSE {sql_str(v.get('default', 'other'))} END")
        else:
            v = sql_str(v)
        arms.append(f"WHEN ev_act = {sql_str(k)} THEN {v}")
    return "CASE WHEN malformed THEN 'malformed' " + " ".join(arms) + " ELSE 'other' END"


def normalize_sql(union_sql: str, sources: dict[str, Any]) -> str:
    """Canonical columns (schemas.CANONICAL_COLUMNS order) from the unioned intermediate rows."""
    am = sources.get("action_map") or {}
    oc = am.get("outcomes") or {}
    succ = sql_list([str(x).lower() for x in oc.get("success", ["success"])])
    fail = sql_list([str(x).lower() for x in oc.get("failure", ["failure"])])
    lt = sources.get("logon_types") or {}
    lt_arms = " ".join(f"WHEN {sql_str(str(k).lower())} THEN {int(v)}" for k, v in lt.items())
    ssh_lt = int(sources.get("default_logon_type_ssh", 10))
    member = ("CASE WHEN f_member_name ILIKE 'cn=%' THEN nullif(regexp_extract(f_member_name, "
              "'^[Cc][Nn]=((?:\\\\,|[^,])+)', 1), '') ELSE f_member_name END")
    a = (f"SELECT *, try_cast(f_event_id AS INTEGER) AS event_id_i, lower(trim(f_event_action)) AS ev_act, "
         f"CASE WHEN list_contains({succ}, lower(trim(f_outcome))) THEN 'success' "
         f"WHEN list_contains({fail}, lower(trim(f_outcome))) THEN 'failure' END AS outcome_n FROM ({union_sql})")
    b = f"SELECT *, {action_case(sources)} AS action FROM ({a})"
    c = (f"SELECT *, "
         f"CASE WHEN action IN {LOGON_ACTIONS} THEN {_user('f_subject_user')} "
         f"ELSE {_user('coalesce(f_subject_user, f_user)')} END AS src_user, "
         f"CASE WHEN action IN {LOGON_ACTIONS} THEN {_user('coalesce(f_target_name, f_user)')} "
         f"WHEN action IN ('user_created', 'group_member_added') THEN {_user(f'coalesce({member}, f_target_name)')} "
         f"ELSE {_user('f_target_name')} END AS target_user, "
         f"coalesce({_base('f_process_name')}, {_base('f_process_path')}) AS process_name_n FROM ({b})")
    lt_expr = (f"coalesce(CASE lower(replace(f_logon_type, ' ', '')) {lt_arms} "
               f"ELSE try_cast(f_logon_type AS INTEGER) END, "
               f"CASE WHEN action IN {LOGON_ACTIONS} AND process_name_n = 'sshd' THEN {ssh_lt} END)")
    file_ext = (f"lower(coalesce(nullif(ltrim(f_file_ext, '.'), ''), "
                f"nullif(regexp_extract(f_file_path, '\\.([A-Za-z0-9]{{1,10}})$', 1), '')))")
    cols = {
        "ts_ms": "ts_ms",
        "ts_ok": "ts_ms IS NOT NULL",
        "event_day": "CAST(epoch_ms(ts_ms) AS DATE)",
        "source_type": "source_type",
        "source_seq": "hash(rel, line)",
        "action": "action",
        "event_id": "event_id_i",
        "outcome": ("coalesce(outcome_n, CASE action WHEN 'login_failed' THEN 'failure' "
                    "WHEN 'login_success' THEN 'success' END)"),
        "logon_id": "lower(f_logon_id)",
        "logon_type": lt_expr,
        "host": "lower(f_host)",
        "host_ip": "lower(f_host_ip)",
        "src_user": "src_user",
        "target_user": "target_user",
        "is_machine": (f"coalesce(CASE WHEN action IN {LOGON_ACTIONS} THEN coalesce(target_user, src_user) "
                       f"ELSE coalesce(src_user, target_user) END LIKE '%$', false)"),
        "group_name": ("lower(coalesce(f_group, CASE WHEN action = 'group_member_added' "
                       "AND f_member_name IS NOT NULL THEN f_target_name END))"),
        "src_ip": "lower(f_src_ip)",
        "src_port": "try_cast(f_src_port AS INTEGER)",
        "dst_ip": "lower(f_dst_ip)",
        "dst_port": "try_cast(f_dst_port AS INTEGER)",
        "dst_domain": "nullif(rtrim(lower(f_dst_domain), '.'), '')",
        "process_name": "process_name_n",
        "process_path": "f_process_path",
        "parent_process": _base("f_parent_process"),
        "command_line": "f_command_line",
        "file_path": "f_file_path",
        "file_ext": file_ext,
        "registry_path": "f_registry_path",
        "bytes_out": ("CASE WHEN f_direction IS NULL OR lower(f_direction) IN ('outbound', 'egress', 'outgoing', "
                      "'out', 'external') THEN try_cast(try_cast(f_bytes AS DOUBLE) AS BIGINT) END"),
        "raw_line": "raw_line",
    }
    return "SELECT " + ", ".join(f"{e} AS {k}" for k, e in cols.items()) + f" FROM ({c})"
