"""Stage 2 detection templates, coverage round (DEVELOPMENT.md §15.8). Same contract as detect_templates:
(con, rule, thresholds) -> one SQL SELECT producing exactly the raw_alerts columns. Registered into
detect_templates.TEMPLATES.
"""

from __future__ import annotations

from typing import Any

import duckdb

from attacklens.detect_sql import OK, ev_keys, ev_lines, finish, window_bursts


def sudo_escalation(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1548.003: sudo process starts for a (user, host) pair seen <= sudo_max_pair_seen times in the data set."""
    mx = int(th["sudo_max_pair_seen"])
    mc = int(th.get("evidence_max_chars", 300))
    core = f"""
    WITH s AS (SELECT ts_ms, source_seq, host, coalesce(src_user, target_user) AS u, src_ip, raw_line FROM events
               WHERE {OK} AND action = 'proc_start' AND lower(process_name) = 'sudo' AND host IS NOT NULL
                 AND coalesce(src_user, target_user) IS NOT NULL),
    pairs AS (SELECT host, u FROM s GROUP BY ALL HAVING count(*) <= {mx})
    SELECT 'primary' AS label, NULL AS sub_technique_id, s.ts_ms, s.ts_ms AS last_ts_ms, s.source_seq, s.host,
           s.host AS subject_host, s.u AS src_user, NULL AS target_user, s.src_ip, NULL AS dst_ip,
           1 AS raw_alert_count, [left(s.raw_line, {mc})] AS evidence_lines, [s.source_seq] AS source_keys
    FROM s SEMI JOIN pairs USING (host, u)
    """
    return finish(rule, core)


def kerberoasting(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1558.003: >= kerberoast_min_services distinct service_name in kerberos_tgs rows with ticket_encryption in
    kerberoast_encryption, by one account, within kerberoast_window_ms."""
    n, win = int(th["kerberoast_min_services"]), int(th["kerberoast_window_ms"])
    enc = ", ".join("'" + str(e).lower().replace("'", "''") + "'" for e in th.get("kerberoast_encryption", ["0x17"]))
    core = f"""
    WITH f AS (SELECT ts_ms, source_seq, host, coalesce(src_user, target_user) AS u, src_ip, service_name, raw_line
               FROM events WHERE {OK} AND action = 'kerberos_tgs' AND lower(ticket_encryption) IN ({enc})
                 AND service_name IS NOT NULL AND coalesce(src_user, target_user) IS NOT NULL),
    cand AS (SELECT u FROM f GROUP BY u HAVING count(DISTINCT lower(service_name)) >= {n}),
    r AS (SELECT f.* FROM f SEMI JOIN cand USING (u)),
    {window_bursts('u', win, 'count(DISTINCT lower(service_name))', f'wv >= {n}')},
    b AS (SELECT u, bid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                 count(*) AS n, al_mode(list(host)) AS host, al_mode(list(src_ip)) AS src_ip,
                 {ev_lines(th)} AS ev, {ev_keys(th)} AS keys
          FROM mb GROUP BY u, bid HAVING count(DISTINCT lower(service_name)) >= {n})
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, host AS subject_host,
           u AS src_user, NULL AS target_user, src_ip, NULL AS dst_ip, n AS raw_alert_count, ev AS evidence_lines,
           keys AS source_keys
    FROM b
    """
    return finish(rule, core)


def pass_the_hash(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1550.002: login_success with logon_type in pth_logon_types and auth_package in pth_auth_packages, on a
    (user, host) pair with <= pth_max_pair_seen such logons in the data set."""
    mx = int(th["pth_max_pair_seen"])
    types = ", ".join(str(int(t)) for t in th.get("pth_logon_types", [9]))
    pk = ", ".join("'" + str(a).lower().replace("'", "''") + "'" for a in th.get("pth_auth_packages", ["ntlm"]))
    mc = int(th.get("evidence_max_chars", 300))
    core = f"""
    WITH s AS (SELECT ts_ms, source_seq, host, target_user, src_ip, raw_line FROM events
               WHERE {OK} AND action = 'login_success' AND logon_type IN ({types})
                 AND lower(auth_package) IN ({pk}) AND host IS NOT NULL AND target_user IS NOT NULL
                 AND NOT coalesce(is_machine, FALSE) AND NOT ends_with(target_user, '$')),
    pairs AS (SELECT host, target_user FROM s GROUP BY ALL HAVING count(*) <= {mx})
    SELECT 'primary' AS label, NULL AS sub_technique_id, s.ts_ms, s.ts_ms AS last_ts_ms, s.source_seq, s.host,
           s.host AS subject_host, NULL AS src_user, s.target_user, s.src_ip, NULL AS dst_ip, 1 AS raw_alert_count,
           [left(s.raw_line, {mc})] AS evidence_lines, [s.source_seq] AS source_keys
    FROM s SEMI JOIN pairs USING (host, target_user)
    """
    return finish(rule, core)


TEMPLATES2 = {
    "sudo_escalation": sudo_escalation,
    "kerberoasting": kerberoasting,
    "pass_the_hash": pass_the_hash,
}
