"""Stage 2 detection templates, coverage round (DEVELOPMENT.md §15.8). Same contract as detect_templates:
(con, rule, thresholds) -> one SQL SELECT producing exactly the raw_alerts columns. Registered into
detect_templates.TEMPLATES.
"""

from __future__ import annotations

from typing import Any

import duckdb

from attacklens.detect_sql import evidence_chars
from attacklens.detect_sql import OK, ev_keys, ev_lines, finish, q, rule_filter, sql_list, window_bursts


def sudo_escalation(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1548.003: sudo process starts for a (user, host) pair seen <= sudo_max_pair_seen times in the data set."""
    mx = int(th["sudo_max_pair_seen"])
    mc = evidence_chars(th)
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
    mc = evidence_chars(th)
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


def _any_regex(col: str, patterns: list[Any]) -> str:
    """OR of RE2 patterns (as written in config; case-insensitive via (?i)) over one column; FALSE if none."""
    arms = [f"regexp_matches({col}, {q(str(p))})" for p in patterns or []]
    return "(" + " OR ".join(arms) + ")" if arms else "FALSE"


def remote_service_exec(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1569.002 (PsExec-style remote service execution), two row kinds:
    - service_installed (7045 / 4697) whose service_name is in remote_svc_names, or whose image (process_path:
      7045 ImagePath) matches a remote_svc_image_patterns regex (binary in the ADMIN$ root, UNC admin share,
      shell one-liner as the service binary);
    - proc_start whose parent is services.exe and whose image is in remote_svc_binaries / remote_svc_shells or
      whose process_path matches remote_svc_child_path_patterns (a binary in the Windows directory root = ADMIN$).
    Each row gives one primary alert. When a network logon (login_success, logon_type in remote_svc_logon_types,
    remote src_ip, non-machine account not in remote_svc_ignore_users) to the same host precedes it by at most
    remote_svc_logon_window_ms, the primary carries that account as target_user and the logon src_ip, and a
    secondary T1021.002 Lateral Movement alert is emitted for the same row (the remote session that created it).
    Evidence: the row and the logon line (<= 2)."""
    win = int(th["remote_svc_logon_window_ms"])
    names = sql_list([str(x).lower() for x in th.get("remote_svc_names") or []])
    bins = sql_list([str(x).lower() for x in th.get("remote_svc_binaries") or []])
    shells = sql_list([str(x).lower() for x in th.get("remote_svc_shells") or []])
    lts = ", ".join(str(int(t)) for t in th.get("remote_svc_logon_types") or [3])
    ign = sql_list([str(x).lower() for x in th.get("remote_svc_ignore_users") or []])
    loop = sql_list([str(x) for x in th.get("remote_svc_loopback_ips") or ["127.0.0.1", "::1"]])
    img = _any_regex("process_path", th.get("remote_svc_image_patterns") or [])
    child = _any_regex("process_path", th.get("remote_svc_child_path_patterns") or [])
    mc = evidence_chars(th)
    core = f"""
    WITH c AS (SELECT ts_ms, source_seq, host, src_user, target_user, src_ip, raw_line FROM events
               WHERE {OK} AND host IS NOT NULL
                 AND ((action = 'service_installed'
                       AND (lower(service_name) IN {names} OR (process_path IS NOT NULL AND {img})))
                   OR (action = 'proc_start' AND lower(parent_process) = 'services.exe'
                       AND (lower(process_name) IN {bins} OR lower(process_name) IN {shells}
                            OR (process_path IS NOT NULL AND {child}))))
                 {rule_filter(rule)}),
    l AS (SELECT e.ts_ms AS l_ts, e.source_seq AS l_seq, e.host, e.target_user AS l_user, e.src_ip AS l_ip,
                 e.raw_line AS l_line
          FROM events e SEMI JOIN (SELECT DISTINCT host FROM c) h ON e.host = h.host
          WHERE {OK} AND e.action = 'login_success' AND e.logon_type IN ({lts}) AND e.src_ip IS NOT NULL
            AND e.src_ip NOT IN {loop} AND e.target_user IS NOT NULL AND NOT coalesce(e.is_machine, FALSE)
            AND NOT ends_with(e.target_user, '$') AND lower(e.target_user) NOT IN {ign}),
    j AS (SELECT c.*, l.l_ts, l.l_seq, l.l_user, l.l_ip, l.l_line
          FROM c ASOF LEFT JOIN l ON c.host = l.host AND c.ts_ms >= l.l_ts),
    k AS (SELECT *, l_ts IS NOT NULL AND ts_ms - l_ts <= {win} AS remote FROM j)
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, ts_ms AS last_ts_ms, source_seq, host,
           host AS subject_host, src_user, CASE WHEN remote THEN l_user ELSE target_user END AS target_user,
           CASE WHEN remote THEN l_ip ELSE src_ip END AS src_ip, NULL AS dst_ip, 1 AS raw_alert_count,
           CASE WHEN remote THEN [left(raw_line, {mc}), left(l_line, {mc})] ELSE [left(raw_line, {mc})] END
               AS evidence_lines,
           CASE WHEN remote THEN [source_seq, l_seq] ELSE [source_seq] END AS source_keys
    FROM k
    UNION ALL
    SELECT 'secondary', NULL, ts_ms, ts_ms, source_seq, host, host, NULL, l_user, l_ip, NULL, 1,
           [left(l_line, {mc}), left(raw_line, {mc})], [l_seq, source_seq]
    FROM k WHERE remote
    """
    return finish(rule, core)


TEMPLATES2 = {
    "sudo_escalation": sudo_escalation,
    "kerberoasting": kerberoasting,
    "pass_the_hash": pass_the_hash,
    "remote_service_exec": remote_service_exec,
}
