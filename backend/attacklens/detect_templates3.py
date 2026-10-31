"""Stage 2 detection templates, firewall pack (DEVELOPMENT.md §15.9). Same contract as detect_templates:
(con, rule, thresholds) -> one SQL SELECT producing exactly the raw_alerts columns. Registered into
detect_templates.TEMPLATES.
"""

from __future__ import annotations

from typing import Any

import duckdb

from attacklens.detect_sql import (OK, ev_keys, ev_lines, finish, q, rule_filter, sql_list, subject_host_expr,
                                   window_bursts)

CONN = "('conn_allowed', 'conn_denied')"


def _conn_rows(th: dict[str, Any], extra: str = "") -> str:
    """Firewall connection rows with src/dst/port, plus the row's subject (host_ip_map, else internal IP)."""
    return f"""SELECT e.ts_ms, e.source_seq, e.host, e.src_ip, e.dst_ip, e.dst_port, e.raw_line,
                      {subject_host_expr('e', 'm', th)} AS sh
               FROM events e LEFT JOIN al_ip_host m ON m.ip = e.src_ip
               WHERE {OK} AND e.action IN {CONN} AND e.src_ip IS NOT NULL AND e.dst_ip IS NOT NULL
                 AND e.dst_port IS NOT NULL {extra}"""


def port_scan(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1046: within scan_window_ms, one src_ip reaches >= scan_min_ports distinct dst_port on one dst_ip, or
    >= scan_min_hosts distinct dst_ip on one dst_port (internal dst_ip only if scan_horizontal_internal_only)."""
    n_ports, n_hosts, win = int(th["scan_min_ports"]), int(th["scan_min_hosts"]), int(th["scan_window_ms"])
    internal = "AND al_is_internal_ip(e.dst_ip)" if th.get("scan_horizontal_internal_only", True) else ""

    def variant(part: str, key: str, n: int, extra: str, dst: str) -> str:
        return f"""(
    WITH c AS ({_conn_rows(th, extra)}),
    cand AS (SELECT {part} FROM c GROUP BY ALL HAVING count(DISTINCT {key}) >= {n}),
    r AS (SELECT c.* FROM c SEMI JOIN cand USING ({part})),
    {window_bursts(part, win, f'count(DISTINCT {key})', f'wv >= {n}')},
    b AS (SELECT {part}, bid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                 count(*) AS n, al_mode(list(host)) AS host, al_mode(list(sh)) AS sh,
                 {ev_lines(th)} AS ev, {ev_keys(th)} AS keys
          FROM mb GROUP BY {part}, bid HAVING count(DISTINCT {key}) >= {n})
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, sh AS subject_host,
           NULL AS src_user, NULL AS target_user, src_ip, {dst} AS dst_ip, n AS raw_alert_count,
           ev AS evidence_lines, keys AS source_keys FROM b)"""

    core = (f"SELECT * FROM {variant('src_ip, dst_ip', 'dst_port', n_ports, '', 'dst_ip')}\n"
            f"    UNION ALL\n    SELECT * FROM {variant('src_ip, dst_port', 'dst_ip', n_hosts, internal, 'NULL')}")
    return finish(rule, core)


def internal_lateral(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1021.x: conn_allowed on a lateral_ports port to an internal dst_ip, for a (src_ip, dst_ip, dst_port)
    triple seen <= lateral_max_triple_seen times in the data set. lateral_direction: internal (default; internal
    src only) or inbound (external src only). Sub-technique from lateral_ports. Subject = the source's host, else
    the internal endpoint IP (inbound: the internal destination)."""
    mx = int(th["lateral_max_triple_seen"])
    ports = {int(k): str(v) for k, v in (th.get("lateral_ports") or {}).items()}
    if not ports:
        ports = {0: "T1021"}
    sub = "CASE dst_port " + " ".join(f"WHEN {p} THEN {q(t)}" for p, t in ports.items()) + " END"
    mc = int(th.get("evidence_max_chars", 300))
    direction = str(th.get("lateral_direction", "internal"))
    if direction not in ("internal", "inbound"):
        raise ValueError(f"lateral_direction {direction!r}: expected internal or inbound")
    src_ok = "NOT al_is_internal_ip(e.src_ip)" if direction == "inbound" else "al_is_internal_ip(e.src_ip)"
    core = f"""
    WITH c AS ({_conn_rows(th, f"AND e.action = 'conn_allowed' AND e.dst_port IN ({', '.join(map(str, ports))}) "
                               f"AND {src_ok} AND al_is_internal_ip(e.dst_ip)")}),
    t AS (SELECT src_ip, dst_ip, dst_port FROM c GROUP BY ALL HAVING count(*) <= {mx})
    SELECT 'primary' AS label, {sub} AS sub_technique_id, ts_ms, ts_ms AS last_ts_ms, source_seq, host,
           sh AS subject_host, NULL AS src_user, NULL AS target_user, src_ip, dst_ip, 1 AS raw_alert_count,
           [left(raw_line, {mc})] AS evidence_lines, [source_seq] AS source_keys
    FROM c SEMI JOIN t USING (src_ip, dst_ip, dst_port)
    """
    return finish(rule, core)


def _severity_sql(th: dict[str, Any]) -> str:
    """Row severity from the vendor's own severity field, lowered when the device blocked the event."""
    smap = th.get("vendor_severity_map") or {}
    cases = " ".join(f"WHEN {q(str(k).lower())} THEN {int(v)}" for k, v in smap.items())
    base = f"(CASE lower(e.vendor_severity) {cases} ELSE {int(th.get('vendor_severity_default', 40))} END)"
    blocked = sql_list([str(o).lower() for o in th.get("blocked_outcomes") or []])
    pen, floor = int(th.get("blocked_penalty", 20)), int(th.get("blocked_floor", 30))
    return f"CASE WHEN lower(e.outcome) IN {blocked} THEN greatest({base} - {pen}, {floor}) ELSE {base} END"


def signature_map(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """Rows of rule `action` (default ips_alert) whose `signature` matches a pattern of rule `signatures`
    (first match wins, case-insensitive RE2); each entry carries its own technique and tactic. Severity per row
    from vendor_severity (vendor_severity_map) minus blocked_penalty when outcome is in blocked_outcomes."""
    sigs = rule.get("signatures") or []
    action = str(rule.get("action", "ips_alert"))
    mc = int(th.get("evidence_max_chars", 300))
    label = "CASE " + " ".join(f"WHEN regexp_matches(e.signature, {q('(?i)' + str(s['pattern']))}) THEN 'sig{i}'"
                               for i, s in enumerate(sigs)) + " END" if sigs else "NULL"
    core = f"""
    WITH e AS (SELECT * FROM events WHERE {OK} AND action = {q(action)} AND signature IS NOT NULL{rule_filter(rule)}),
    s AS (SELECT e.*, {label} AS lbl, {_severity_sql(th)} AS sev FROM e)
    SELECT s.lbl AS label, NULL AS sub_technique_id, s.ts_ms, s.ts_ms AS last_ts_ms, s.source_seq, s.host,
           {subject_host_expr('s', 'm', th)} AS subject_host, s.src_user, s.target_user, s.src_ip, s.dst_ip,
           1 AS raw_alert_count, [left(s.raw_line, {mc})] AS evidence_lines, [s.source_seq] AS source_keys,
           s.sev AS severity_override
    FROM s LEFT JOIN al_ip_host m ON m.ip = s.src_ip
    WHERE s.lbl IS NOT NULL
    """
    return finish(rule, core, row_severity=True)


def config_change_after_login(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1562.004: config_change by a user within cfg_after_login_window_ms after that user's latest
    login_success from an external src_ip on the same device."""
    win = int(th["cfg_after_login_window_ms"])
    mc = int(th.get("evidence_max_chars", 300))
    core = f"""
    WITH c AS (SELECT ts_ms, source_seq, host, coalesce(src_user, target_user) AS u, raw_line FROM events
               WHERE {OK} AND action = 'config_change' AND coalesce(src_user, target_user) IS NOT NULL),
    l AS (SELECT e.ts_ms, e.source_seq, e.host, coalesce(e.target_user, e.src_user) AS u, e.src_ip, e.raw_line
          FROM events e SEMI JOIN c ON e.host = c.host AND coalesce(e.target_user, e.src_user) = c.u
          WHERE {OK} AND e.action = 'login_success' AND e.src_ip IS NOT NULL AND NOT al_is_internal_ip(e.src_ip)),
    j AS (SELECT c.*, l.ts_ms AS l_ts, l.source_seq AS l_seq, l.src_ip, l.raw_line AS l_line
          FROM c ASOF JOIN l ON c.host = l.host AND c.u = l.u AND c.ts_ms >= l.ts_ms)
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, ts_ms AS last_ts_ms, source_seq, host,
           host AS subject_host, u AS src_user, NULL AS target_user, src_ip, NULL AS dst_ip, 1 AS raw_alert_count,
           [left(raw_line, {mc}), left(l_line, {mc})] AS evidence_lines, [source_seq, l_seq] AS source_keys
    FROM j WHERE ts_ms - l_ts <= {win}
    """
    return finish(rule, core)


def blocked_daily(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """Prevented detections (rule `actions`, outcome in blocked_outcomes) as ONE low-severity alert per
    (subject, UTC day), so blocked noise stays visible but bounded (never one episode per hit)."""
    acts = sql_list([str(a) for a in rule.get("actions") or []])
    blocked = sql_list([str(o).lower() for o in th.get("blocked_outcomes") or []])
    core = f"""
    WITH e AS (SELECT * FROM events WHERE {OK} AND action IN {acts} AND lower(outcome) IN {blocked}),
    r AS (SELECT e.*, {subject_host_expr('e', 'm', th)} AS sh FROM e LEFT JOIN al_ip_host m ON m.ip = e.src_ip),
    b AS (SELECT sh, ts_ms // 86400000 AS d, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms,
                 min(source_seq) AS source_seq, count(*) AS n, al_mode(list(host)) AS host,
                 al_mode(list(src_ip)) AS src_ip, al_mode(list(dst_ip)) AS dst_ip,
                 {ev_lines(th)} AS ev, {ev_keys(th)} AS keys
          FROM r GROUP BY sh, d)
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, sh AS subject_host,
           NULL AS src_user, NULL AS target_user, src_ip, dst_ip, n AS raw_alert_count, ev AS evidence_lines,
           keys AS source_keys FROM b
    """
    return finish(rule, core)


TEMPLATES3 = {
    "blocked_daily": blocked_daily,
    "config_change_after_login": config_change_after_login,
    "signature_map": signature_map,
    "port_scan": port_scan,
    "internal_lateral": internal_lateral,
}
