"""Stage 2 detection templates, firewall pack (DEVELOPMENT.md §15.9). Same contract as detect_templates:
(con, rule, thresholds) -> one SQL SELECT producing exactly the raw_alerts columns. Registered into
detect_templates.TEMPLATES.
"""

from __future__ import annotations

from typing import Any

import duckdb

from attacklens.detect_sql import evidence_chars
from attacklens.detect_sql import (OK, ev_keys, ev_lines, finish, q, rule_filter, sql_list, subject_host_expr,
                                   window_bursts)

CONN = "('conn_allowed', 'conn_denied')"


def _conn_rows(th: dict[str, Any], extra: str = "") -> str:
    """Firewall connection rows with src/dst/port, plus the row's subject (host_ip_map, else internal IP)."""
    return f"""SELECT e.ts_ms, e.source_seq, e.host, e.src_ip, e.dst_ip, e.dst_port, e.bytes_out, e.bytes_in,
                      e.raw_line,
                      {subject_host_expr('e', 'm', th)} AS sh
               FROM events e LEFT JOIN al_ip_host m ON m.ip = e.src_ip LEFT JOIN al_ip_host md ON md.ip = e.dst_ip
               WHERE {OK} AND e.action IN {CONN} AND e.src_ip IS NOT NULL AND e.dst_ip IS NOT NULL
                 AND e.dst_port IS NOT NULL {extra}"""


def internal_lateral(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1021.x: conn_allowed on a lateral_ports port to an internal dst_ip, for a (src_ip, dst_ip, dst_port)
    triple seen <= lateral_max_triple_seen times in the data set, AND the service (dst_ip, dst_port) is either
    used routinely by other sources (median per-source sightings >= lateral_peer_median_min) or used by
    <= lateral_sole_user_max_srcs sources at all. The service gate fails OPEN when its baseline is thin (fewer than
    lateral_gate_min_service_sightings sightings of the service): then the rare triple alone fires.
    Connections below lateral_min_bytes sent + received (scan probes) are ignored; unknown byte counts pass.
    lateral_direction: internal (default; internal src only) or inbound (external src only).
    Sub-technique from lateral_ports. Subject = the source's host, else
    the internal endpoint IP (inbound: the internal destination)."""
    mx = int(th["lateral_max_triple_seen"])
    peer_med = float(th.get("lateral_peer_median_min", 0))
    sole = int(th.get("lateral_sole_user_max_srcs", 0))
    min_svc = int(th.get("lateral_gate_min_service_sightings", 0))
    min_bytes = int(th.get("lateral_min_bytes", 0))
    ports = {int(k): str(v) for k, v in (th.get("lateral_ports") or {}).items()}
    if not ports:
        ports = {0: "T1021"}
    sub = "CASE dst_port " + " ".join(f"WHEN {p} THEN {q(t)}" for p, t in ports.items()) + " END"
    mc = evidence_chars(th)
    direction = str(th.get("lateral_direction", "internal"))
    if direction not in ("internal", "inbound"):
        raise ValueError(f"lateral_direction {direction!r}: expected internal or inbound")
    src_ok = "NOT al_is_internal_ip(e.src_ip)" if direction == "inbound" else "al_is_internal_ip(e.src_ip)"
    core = f"""
    WITH c AS ({_conn_rows(th, f"AND e.action = 'conn_allowed' AND e.dst_port IN ({', '.join(map(str, ports))}) "
                               f"AND {src_ok} AND al_is_internal_ip(e.dst_ip) "
                               f"AND ((e.bytes_out IS NULL AND e.bytes_in IS NULL) "
                               f"OR coalesce(e.bytes_out, 0) + coalesce(e.bytes_in, 0) >= {min_bytes})")}),
    t0 AS (SELECT src_ip, dst_ip, dst_port, count(*) AS n FROM c GROUP BY ALL),
    svc AS (SELECT dst_ip, dst_port, count(*) AS nsrc, median(n) AS med, sum(n) AS total FROM t0 GROUP BY ALL),
    t AS (SELECT t0.src_ip, t0.dst_ip, t0.dst_port FROM t0 JOIN svc USING (dst_ip, dst_port)
          WHERE t0.n <= {mx} AND (svc.total < {min_svc} OR svc.med >= {peer_med} OR svc.nsrc <= {sole}))
    SELECT 'primary' AS label, {sub} AS sub_technique_id, ts_ms, ts_ms AS last_ts_ms, source_seq, host,
           sh AS subject_host, NULL AS src_user, NULL AS target_user, src_ip, dst_ip, 1 AS raw_alert_count,
           [left(raw_line, {mc})] AS evidence_lines, [source_seq] AS source_keys
    FROM c SEMI JOIN t USING (src_ip, dst_ip, dst_port)
    """
    return finish(rule, core)


def _severity_sql(th: dict[str, Any]) -> str:
    """Row severity from the vendor's own severity field (NULL when absent/unknown, so the rule's or the
    signature entry's severity applies), lowered when the device blocked the event."""
    smap = th.get("vendor_severity_map") or {}
    cases = " ".join(f"WHEN {q(str(k).lower())} THEN {int(v)}" for k, v in smap.items())
    base = f"(CASE lower(e.vendor_severity) {cases} ELSE NULL END)"   # NULL -> the label's own severity
    blocked = sql_list([str(o).lower() for o in th.get("blocked_outcomes") or []])
    pen, floor = int(th.get("blocked_penalty", 20)), int(th.get("blocked_floor", 30))
    return f"CASE WHEN lower(e.outcome) IN {blocked} THEN greatest({base} - {pen}, {floor}) ELSE {base} END"


def _direction_sql(direction: str | None, th: dict[str, Any]) -> str:
    """Optional signature-entry direction: inbound (external src), outbound (internal src -> external dst),
    internal (internal -> internal). Internal = RFC1918 or zone in entity_internal_zones."""
    if not direction:
        return ""
    zones = sql_list([str(z).lower() for z in th.get("entity_internal_zones", ["lan", "dmz"])])
    src = f"(e.src_ip IS NOT NULL AND (al_is_internal_ip(e.src_ip) OR lower(e.src_zone) IN {zones}))"
    dst = f"(e.dst_ip IS NOT NULL AND (al_is_internal_ip(e.dst_ip) OR lower(e.dst_zone) IN {zones}))"
    cond = {"inbound": f"NOT {src}", "outbound": f"{src} AND NOT {dst}", "internal": f"{src} AND {dst}"}
    if direction not in cond:
        raise ValueError(f"signature direction {direction!r}: expected inbound, outbound or internal")
    return f" AND ({cond[direction]})"


def _sig_label(sigs: list[dict[str, Any]], th: dict[str, Any], default: str) -> str:
    """CASE over rule `signatures` (first match wins, case-insensitive RE2, optional direction) -> 'sig<i>'."""
    if not sigs:
        return default
    return "CASE " + " ".join(f"WHEN regexp_matches(e.signature, {q('(?i)' + str(s['pattern']))})"
                              f"{_direction_sql(s.get('direction'), th)} THEN 'sig{i}'"
                              for i, s in enumerate(sigs)) + f" ELSE {default} END"


def signature_map(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """Rows of rule `action` (default ips_alert) whose `signature` matches a pattern of rule `signatures`
    (first match wins, case-insensitive RE2); each entry carries its own technique and tactic. Severity per row
    from vendor_severity (vendor_severity_map) minus blocked_penalty when outcome is in blocked_outcomes."""
    sigs = rule.get("signatures") or []
    action = str(rule.get("action", "ips_alert"))
    mc = evidence_chars(th)
    label = _sig_label(sigs, th, "NULL")
    core = f"""
    WITH e AS (SELECT * FROM events WHERE {OK} AND action = {q(action)} AND signature IS NOT NULL{rule_filter(rule)}),
    s AS (SELECT e.*, {label} AS lbl, {_severity_sql(th)} AS sev FROM e)
    SELECT s.lbl AS label, NULL AS sub_technique_id, s.ts_ms, s.ts_ms AS last_ts_ms, s.source_seq, s.host,
           {subject_host_expr('s', 'm', th)} AS subject_host, s.src_user, s.target_user, s.src_ip, s.dst_ip,
           1 AS raw_alert_count, [left(s.raw_line, {mc})] AS evidence_lines, [s.source_seq] AS source_keys,
           s.sev AS severity_override
    FROM s LEFT JOIN al_ip_host m ON m.ip = s.src_ip LEFT JOIN al_ip_host md ON md.ip = s.dst_ip
    WHERE s.lbl IS NOT NULL
    """
    return finish(rule, core, row_severity=True)


def config_change_after_login(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1562.004: config_change by a user within cfg_after_login_window_ms after that user's latest
    login_success from an external src_ip on the same device."""
    win = int(th["cfg_after_login_window_ms"])
    mc = evidence_chars(th)
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
    """Prevented detections (rule `actions`, outcome in blocked_outcomes) as ONE alert per (subject, UTC day,
    label), so blocked noise stays visible but bounded (never one episode per hit). With rule `signatures` (same
    shape as signature_map; reuse it with a YAML anchor) each row is labelled by the first matching entry, else the
    rule's own technique. Severity: blocked_severity (low; the device prevented it)."""
    acts = sql_list([str(a) for a in rule.get("actions") or []])
    blocked = sql_list([str(o).lower() for o in th.get("blocked_outcomes") or []])
    core = f"""
    WITH e AS (SELECT * FROM events WHERE {OK} AND action IN {acts} AND lower(outcome) IN {blocked}),
    r AS (SELECT e.*, {subject_host_expr('e', 'm', th)} AS sh,
                 {_sig_label(rule.get('signatures') or [], th, "'primary'")} AS lbl
          FROM e
          LEFT JOIN al_ip_host m ON m.ip = e.src_ip LEFT JOIN al_ip_host md ON md.ip = e.dst_ip),
    b AS (SELECT sh, lbl, ts_ms // 86400000 AS d, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms,
                 min(source_seq) AS source_seq, count(*) AS n, al_mode(list(host)) AS host,
                 al_mode(list(src_ip)) AS src_ip, al_mode(list(dst_ip)) AS dst_ip,
                 {ev_lines(th)} AS ev, {ev_keys(th)} AS keys
          FROM r GROUP BY sh, lbl, d)
    SELECT lbl AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, sh AS subject_host,
           NULL AS src_user, NULL AS target_user, src_ip, dst_ip, n AS raw_alert_count, ev AS evidence_lines,
           keys AS source_keys, {int(th.get('blocked_severity', 30))} AS severity_override FROM b
    """
    return finish(rule, core, row_severity=True)


def vpn_login_context(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1133: VPN login_success (logon_type vpn_logon_type) from an external src_ip where, within
    vpn_context_window_ms before it, the same src_ip had an allowed ips_alert, or >= vpn_min_failures VPN
    login_failed, or (vpn_first_seen_pair) the (user, src_ip) pair had no earlier VPN login_success.
    dst_ip = the login row's dst_ip (FortiGate: the assigned tunnel IP), so the session links to its traffic."""
    win, nf = int(th["vpn_context_window_ms"]), int(th["vpn_min_failures"])
    lt = int(th.get("vpn_logon_type", 10))
    blocked = sql_list([str(o).lower() for o in th.get("blocked_outcomes") or []])
    first_seen = "OR NOT EXISTS (SELECT 1 FROM v v2 WHERE v2.target_user = v.target_user AND v2.src_ip = v.src_ip " \
                 "AND v2.ts_ms < v.ts_ms)" if th.get("vpn_first_seen_pair") else ""
    mc = evidence_chars(th)
    core = f"""
    WITH v AS (SELECT ts_ms, source_seq, host, target_user, src_ip, dst_ip, raw_line FROM events
               WHERE {OK} AND action = 'login_success' AND logon_type = {lt} AND src_ip IS NOT NULL
                 AND NOT al_is_internal_ip(src_ip)),
    ips AS (SELECT e.src_ip, e.ts_ms FROM events e SEMI JOIN (SELECT DISTINCT src_ip FROM v) x ON e.src_ip = x.src_ip
            WHERE {OK} AND e.action = 'ips_alert' AND coalesce(lower(e.outcome), '') NOT IN {blocked}),
    fl AS (SELECT e.src_ip, e.ts_ms FROM events e SEMI JOIN (SELECT DISTINCT src_ip FROM v) x ON e.src_ip = x.src_ip
           WHERE {OK} AND e.action = 'login_failed' AND e.logon_type = {lt})
    SELECT 'primary' AS label, NULL AS sub_technique_id, v.ts_ms, v.ts_ms AS last_ts_ms, v.source_seq, v.host,
           v.host AS subject_host, NULL AS src_user, v.target_user, v.src_ip, v.dst_ip, 1 AS raw_alert_count,
           [left(v.raw_line, {mc})] AS evidence_lines, [v.source_seq] AS source_keys
    FROM v
    WHERE EXISTS (SELECT 1 FROM ips WHERE ips.src_ip = v.src_ip AND ips.ts_ms <= v.ts_ms
                    AND ips.ts_ms >= v.ts_ms - {win})
       OR (SELECT count(*) FROM fl WHERE fl.src_ip = v.src_ip AND fl.ts_ms <= v.ts_ms
             AND fl.ts_ms >= v.ts_ms - {win}) >= {nf}
       {first_seen}
    """
    return finish(rule, core)


TEMPLATES3 = {
    "vpn_login_context": vpn_login_context,
    "blocked_daily": blocked_daily,
    "config_change_after_login": config_change_after_login,
    "signature_map": signature_map,
    "internal_lateral": internal_lateral,
}
