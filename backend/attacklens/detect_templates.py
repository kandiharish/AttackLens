"""Stage 2 detection templates (DEVELOPMENT.md §5.2). Each function takes (con, rule, thresholds) and returns one SQL
SELECT producing exactly the raw_alerts columns (§15.4).

Preconditions on `con`: an `events` view and the helpers from detect_sql.prepare() (al_is_internal_ip, al_attack,
al_ip_host). Every template first selects only its candidate action rows (and pre-aggregates candidate keys)
before any window function, so windows never run over the whole input.
"""

from __future__ import annotations

from typing import Any, Callable

import duckdb

from attacklens.detect_sql import OK, ev_keys, ev_lines, finish, sql_list, subject_host_expr

Template = Callable[[duckdb.DuckDBPyConnection, dict[str, Any], dict[str, Any]], str]


def _window_bursts(part: str, win: int, agg: str, cond: str) -> str:
    """CTEs over CTE `r` (ts_ms, source_seq, <part cols>, ...): rows inside any [t, t+win) window whose `agg`
    satisfies `cond` (on column wv), grouped into bursts `bid` (a gap > win starts a new burst). Ends in CTE `mb`."""
    return f"""
    w AS (SELECT *, {agg} OVER (PARTITION BY {part} ORDER BY ts_ms
                               RANGE BETWEEN CURRENT ROW AND {win - 1} FOLLOWING) AS wv FROM r),
    s AS (SELECT *, max(CASE WHEN {cond} THEN ts_ms END) OVER (PARTITION BY {part} ORDER BY ts_ms, source_seq
                                                               ROWS UNBOUNDED PRECEDING) AS ls FROM w),
    m AS (SELECT * FROM s WHERE ls IS NOT NULL AND ts_ms - ls < {win}),
    g AS (SELECT *, CASE WHEN ts_ms - lag(ts_ms) OVER (PARTITION BY {part} ORDER BY ts_ms, source_seq) <= {win}
                         THEN 0 ELSE 1 END AS nb FROM m),
    mb AS (SELECT *, sum(nb) OVER (PARTITION BY {part} ORDER BY ts_ms, source_seq ROWS UNBOUNDED PRECEDING) AS bid
           FROM g)"""


def _gap_sessions(src: str, part: str, gap: int) -> str:
    """CTEs over CTE `{src}`: session id `sid` per partition, new session when the gap > `gap` ms; `dt` = gap to
    the previous row inside the session (NULL for the session's first row). Ends in CTE `ss`."""
    return f"""
    gl AS (SELECT *, ts_ms - lag(ts_ms) OVER (PARTITION BY {part} ORDER BY ts_ms, source_seq) AS gap0 FROM {src}),
    gn AS (SELECT *, CASE WHEN gap0 IS NULL OR gap0 > {gap} THEN 1 ELSE 0 END AS nb FROM gl),
    ss AS (SELECT *, sum(nb) OVER (PARTITION BY {part} ORDER BY ts_ms, source_seq ROWS UNBOUNDED PRECEDING) AS sid,
                  CASE WHEN nb = 0 THEN gap0 END AS dt FROM gn)"""


def brute_force_then_success(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1110: >= bf_min_failures login_failed per (target_user, host) in a burst (gaps > bf_gap_ms split bursts).
    T1078 (secondary): the first login_success for the same pair within bf_success_window_ms after the burst."""
    n, gap, sw = int(th["bf_min_failures"]), int(th["bf_gap_ms"]), int(th["bf_success_window_ms"])
    need_success = bool(th.get("bf_require_success", False))
    emit2 = bool(th.get("emit_t1078_on_bruteforce", True))
    core = f"""
    WITH f AS (SELECT ts_ms, source_seq, host, target_user, src_ip, raw_line FROM events
               WHERE {OK} AND action = 'login_failed' AND target_user IS NOT NULL AND host IS NOT NULL),
    cand AS (SELECT host, target_user FROM f GROUP BY host, target_user HAVING count(*) >= {n}),
    fc AS (SELECT f.* FROM f SEMI JOIN cand USING (host, target_user)),
    {_gap_sessions('fc', 'host, target_user', gap)},
    b AS (SELECT host, target_user, sid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms,
                 min(source_seq) AS source_seq, count(*) AS n, mode(src_ip) AS src_ip,
                 {ev_lines(th)} AS ev, {ev_keys(th)} AS keys
          FROM ss GROUP BY host, target_user, sid HAVING count(*) >= {n}),
    sc AS (SELECT e.ts_ms, e.source_seq, e.host, e.target_user, e.src_ip, e.raw_line FROM events e
           SEMI JOIN cand c ON e.host = c.host AND e.target_user = c.target_user
           WHERE {OK} AND e.action = 'login_success'),
    bs AS (SELECT b.*, sc.ts_ms AS s_ts, sc.source_seq AS s_seq, sc.src_ip AS s_ip, sc.raw_line AS s_line
           FROM b ASOF LEFT JOIN sc ON b.host = sc.host AND b.target_user = sc.target_user
                                    AND sc.ts_ms >= b.last_ts_ms),
    ok AS (SELECT *, (s_ts IS NOT NULL AND s_ts - last_ts_ms <= {sw}) AS has_success FROM bs)
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, host AS subject_host,
           NULL AS src_user, target_user, src_ip, NULL AS dst_ip, n AS raw_alert_count, ev AS evidence_lines,
           keys AS source_keys
    FROM ok WHERE {'has_success' if need_success else 'TRUE'}
    UNION ALL
    SELECT 'secondary', NULL, s_ts, s_ts, s_seq, host, host, NULL, target_user, s_ip, NULL, 1,
           [left(s_line, {int(th.get('evidence_max_chars', 300))})], [s_seq]
    FROM ok WHERE has_success AND {'TRUE' if emit2 else 'FALSE'}
    """
    return finish(rule, core)


def password_spray(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1110.003: one src_ip with >= spray_min_users distinct target users failing within spray_window_ms.
    T1078 (secondary): first login_success from that src_ip within bf_success_window_ms after the spray.
    The spray alert's target_user = the account that then logged on (NULL when no success followed)."""
    n, win, sw = int(th["spray_min_users"]), int(th["spray_window_ms"]), int(th["bf_success_window_ms"])
    emit2 = bool(th.get("emit_t1078_on_bruteforce", True))
    core = f"""
    WITH f AS (SELECT ts_ms, source_seq, host, target_user, src_ip, raw_line FROM events
               WHERE {OK} AND action = 'login_failed' AND src_ip IS NOT NULL AND target_user IS NOT NULL),
    cand AS (SELECT src_ip FROM f GROUP BY src_ip HAVING count(DISTINCT target_user) >= {n}),
    r AS (SELECT f.* FROM f SEMI JOIN cand USING (src_ip)),
    {_window_bursts('src_ip', win, 'count(DISTINCT target_user)', f'wv >= {n}')},
    b AS (SELECT src_ip, bid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                 count(*) AS n, mode(host) AS host, {ev_lines(th)} AS ev, {ev_keys(th)} AS keys
          FROM mb GROUP BY src_ip, bid HAVING count(DISTINCT target_user) >= {n}),
    sc AS (SELECT e.ts_ms, e.source_seq, e.host, e.target_user, e.src_ip, e.raw_line FROM events e
           SEMI JOIN cand c ON e.src_ip = c.src_ip WHERE {OK} AND e.action = 'login_success'),
    bs AS (SELECT b.*, sc.ts_ms AS s_ts, sc.source_seq AS s_seq, sc.host AS s_host, sc.target_user AS s_user,
                  sc.raw_line AS s_line
           FROM b ASOF LEFT JOIN sc ON b.src_ip = sc.src_ip AND sc.ts_ms >= b.last_ts_ms)
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, host AS subject_host,
           NULL AS src_user, CASE WHEN s_ts - last_ts_ms <= {sw} THEN s_user END AS target_user, src_ip,
           NULL AS dst_ip, n AS raw_alert_count, ev AS evidence_lines, keys AS source_keys
    FROM bs
    UNION ALL
    SELECT 'secondary', NULL, s_ts, s_ts, s_seq, s_host, s_host, NULL, s_user, src_ip, NULL, 1,
           [left(s_line, {int(th.get('evidence_max_chars', 300))})], [s_seq]
    FROM bs WHERE s_ts IS NOT NULL AND s_ts - last_ts_ms <= {sw} AND {'TRUE' if emit2 else 'FALSE'}
    """
    return finish(rule, core)


def account_created_then_elevated(con: duckdb.DuckDBPyConnection, rule: dict[str, Any],
                                  th: dict[str, Any]) -> str:
    """T1136 (primary, at the creation) + T1098 (secondary, at the group add): user_created then the first
    group_member_added for the same target_user within create_elevate_window_ms. Neither fires alone."""
    win = int(th["create_elevate_window_ms"])
    mc = int(th.get("evidence_max_chars", 300))
    core = f"""
    WITH c AS (SELECT ts_ms, source_seq, host, src_user, target_user, raw_line FROM events
               WHERE {OK} AND action = 'user_created' AND target_user IS NOT NULL),
    ga AS (SELECT e.ts_ms, e.source_seq, e.host, e.src_user, e.target_user, e.raw_line FROM events e
           SEMI JOIN c ON e.target_user = c.target_user
           WHERE {OK} AND e.action = 'group_member_added'),
    j AS (SELECT c.*, ga.ts_ms AS g_ts, ga.source_seq AS g_seq, ga.host AS g_host, ga.src_user AS g_src,
                 ga.raw_line AS g_line
          FROM c ASOF JOIN ga ON c.target_user = ga.target_user AND ga.ts_ms >= c.ts_ms),
    k AS (SELECT * FROM j WHERE g_ts - ts_ms <= {win})
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, ts_ms AS last_ts_ms, source_seq, host,
           host AS subject_host, src_user, target_user, NULL AS src_ip, NULL AS dst_ip, 1 AS raw_alert_count,
           [left(raw_line, {mc})] AS evidence_lines, [source_seq] AS source_keys
    FROM k
    UNION ALL
    SELECT 'secondary', NULL, g_ts, g_ts, g_seq, g_host, g_host, g_src, target_user, NULL, NULL, 1,
           [left(g_line, {mc})], [g_seq]
    FROM k
    """
    return finish(rule, core)


def beaconing(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1071.001: same (subject_host, destination) with >= beacon_min_conns connections in one session (gaps
    > beacon_session_gap_ms split sessions) and inter-arrival coefficient of variation < beacon_max_cv."""
    n, cv, gap = int(th["beacon_min_conns"]), float(th["beacon_max_cv"]), int(th["beacon_session_gap_ms"])
    core = f"""
    WITH c0 AS (SELECT host, src_ip, coalesce(dst_ip, lower(dst_domain)) AS dk FROM events
                WHERE {OK} AND action IN ('conn_out', 'conn_allowed') AND coalesce(dst_ip, dst_domain) IS NOT NULL),
    cand AS (SELECT host, src_ip, dk FROM c0 GROUP BY ALL HAVING count(*) >= {n}),
    c AS (SELECT e.ts_ms, e.source_seq, e.action, e.host, e.src_ip, e.dst_ip, e.src_user, e.target_user,
                 e.raw_line, coalesce(e.dst_ip, lower(e.dst_domain)) AS dk
          FROM events e WHERE {OK} AND e.action IN ('conn_out', 'conn_allowed')
                         AND coalesce(e.dst_ip, e.dst_domain) IS NOT NULL),
    cc AS (SELECT c.*, {subject_host_expr('c', 'm')} AS sh FROM c
           SEMI JOIN cand ON c.host = cand.host AND c.src_ip IS NOT DISTINCT FROM cand.src_ip AND c.dk = cand.dk
           LEFT JOIN al_ip_host m ON m.ip = c.src_ip),
    {_gap_sessions('cc', 'sh, dk', gap)},
    a AS (SELECT sh, dk, sid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                 count(*) AS n, avg(dt) AS mu, stddev_pop(dt) AS sd, mode(host) AS host, mode(src_ip) AS src_ip,
                 mode(dst_ip) AS dst_ip, mode(coalesce(src_user, target_user)) AS u,
                 {ev_lines(th)} AS ev, {ev_keys(th)} AS keys
          FROM ss GROUP BY sh, dk, sid HAVING count(*) >= {n})
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, sh AS subject_host,
           u AS src_user, NULL AS target_user, src_ip, dst_ip, n AS raw_alert_count, ev AS evidence_lines,
           keys AS source_keys
    FROM a WHERE mu > 0 AND sd / mu < {cv}
    """
    return finish(rule, core)


def ransom_rename(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1486: >= mass_rename_min file_rename events on one host within mass_rename_window_ms."""
    n, win = int(th["mass_rename_min"]), int(th["mass_rename_window_ms"])
    core = f"""
    WITH f AS (SELECT ts_ms, source_seq, host, src_user, target_user, raw_line FROM events
               WHERE {OK} AND action = 'file_rename' AND host IS NOT NULL),
    cand AS (SELECT host FROM f GROUP BY host HAVING count(*) >= {n}),
    r AS (SELECT f.* FROM f SEMI JOIN cand USING (host)),
    {_window_bursts('host', win, 'count(*)', f'wv >= {n}')},
    b AS (SELECT host, bid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                 count(*) AS n, mode(coalesce(src_user, target_user)) AS u, {ev_lines(th)} AS ev,
                 {ev_keys(th)} AS keys
          FROM mb GROUP BY host, bid HAVING count(*) >= {n})
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, host AS subject_host,
           u AS src_user, NULL AS target_user, NULL AS src_ip, NULL AS dst_ip, n AS raw_alert_count,
           ev AS evidence_lines, keys AS source_keys
    FROM b
    """
    return finish(rule, core)


def exfil_volume(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1048: sum(bytes_out) per (subject_host, dst_ip) to an external dst within exfil_window_ms exceeds
    max(exfil_min_bytes, exfil_baseline_mult x host baseline); baseline = median over days of the host's daily
    external bytes per distinct external destination."""
    mn, win, mult = int(th["exfil_min_bytes"]), int(th["exfil_window_ms"]), float(th["exfil_baseline_mult"])
    core = f"""
    WITH c0 AS (SELECT host, src_ip, dst_ip, bytes_out FROM events
                WHERE {OK} AND action IN ('conn_out', 'conn_allowed') AND bytes_out > 0 AND dst_ip IS NOT NULL
                  AND NOT al_is_internal_ip(dst_ip)),
    cand AS (SELECT host, src_ip, dst_ip FROM c0 GROUP BY ALL HAVING sum(bytes_out) > {mn}),
    c AS (SELECT e.ts_ms, e.source_seq, e.action, e.host, e.src_ip, e.dst_ip, e.bytes_out, e.src_user,
                 e.target_user, e.raw_line
          FROM events e SEMI JOIN cand ON e.host = cand.host AND e.src_ip IS NOT DISTINCT FROM cand.src_ip
                                       AND e.dst_ip = cand.dst_ip
          WHERE {OK} AND e.action IN ('conn_out', 'conn_allowed') AND e.bytes_out > 0),
    cs AS (SELECT c.*, {subject_host_expr('c', 'm')} AS sh FROM c LEFT JOIN al_ip_host m ON m.ip = c.src_ip),
    daily AS (SELECT e.host, e.ts_ms // 86400000 AS d,
                     sum(e.bytes_out)::DOUBLE / greatest(approx_count_distinct(e.dst_ip), 1) AS per_dst
              FROM events e SEMI JOIN (SELECT DISTINCT host FROM cand) h ON e.host = h.host
              WHERE {OK} AND e.action IN ('conn_out', 'conn_allowed') AND e.bytes_out > 0 AND e.dst_ip IS NOT NULL
                AND NOT al_is_internal_ip(e.dst_ip)
              GROUP BY ALL),
    base AS (SELECT host, median(per_dst) AS base FROM daily GROUP BY host),
    r AS (SELECT cs.*, greatest({mn}::DOUBLE, {mult} * coalesce(base.base, 0)) AS thr
          FROM cs LEFT JOIN base ON base.host = cs.host),
    {_window_bursts('sh, dst_ip', win, 'sum(bytes_out)', 'wv > thr')},
    b AS (SELECT sh, dst_ip, bid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                 count(*) AS n, mode(host) AS host, mode(src_ip) AS src_ip,
                 mode(coalesce(src_user, target_user)) AS u, {ev_lines(th)} AS ev, {ev_keys(th)} AS keys
          FROM mb GROUP BY sh, dst_ip, bid)
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, sh AS subject_host,
           u AS src_user, NULL AS target_user, src_ip, dst_ip, n AS raw_alert_count, ev AS evidence_lines,
           keys AS source_keys
    FROM b
    """
    return finish(rule, core)


def new_admin_logon(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """Privileged remote logon on a rare (user, host) pair. Admin logon = login_success (type 3/10) + priv_assigned
    with the same (host, logon_id), excluding system logon ids and machine accounts; SSH logon = login_success by
    sshd. Pair is rare if it has <= new_admin_max_pair_seen such logons in the data set.
    Suppressed: pairs with >= new_admin_routine_min_logons non-privileged login_success on the host when the logon
    hour (UTC) is inside new_admin_business_hours_utc [start, end) - routine admin work.
    Internal source -> T1021 (.002 network, .001 RDP, .004 SSH); external source -> secondary T1078."""
    mx = int(th["new_admin_max_pair_seen"])
    rmin = int(th.get("new_admin_routine_min_logons", 10**9))
    bh0, bh1 = (int(v) for v in th.get("new_admin_business_hours_utc", [0, 0]))
    excl = sql_list([str(x).lower() for x in th.get("new_admin_excluded_logon_ids", [])])
    core = f"""
    WITH ls AS (SELECT ts_ms, source_seq, host, target_user, lower(logon_id) AS lid, logon_type, src_ip,
                       lower(process_name) = 'sshd' AS is_ssh, raw_line FROM events
                WHERE {OK} AND action = 'login_success' AND host IS NOT NULL AND target_user IS NOT NULL
                  AND NOT coalesce(is_machine, FALSE) AND NOT ends_with(target_user, '$')
                  AND (logon_type IN (3, 10) OR lower(process_name) = 'sshd')),
    pa AS (SELECT host, lower(logon_id) AS lid, min(source_seq) AS p_seq, min_by(raw_line, ts_ms) AS p_line
           FROM events WHERE {OK} AND action = 'priv_assigned' AND logon_id IS NOT NULL
                         AND lower(logon_id) NOT IN {excl}
           GROUP BY ALL),
    adm AS (SELECT ls.*, pa.p_seq, pa.p_line FROM ls JOIN pa ON ls.host = pa.host AND ls.lid = pa.lid
            WHERE ls.lid NOT IN {excl}),
    x AS (SELECT * FROM adm
          UNION ALL BY NAME
          SELECT ls.* FROM ls ANTI JOIN adm ON ls.source_seq = adm.source_seq WHERE ls.is_ssh),
    pairs AS (SELECT host, target_user FROM x GROUP BY ALL HAVING count(*) <= {mx}),
    k0 AS (SELECT x.* FROM x SEMI JOIN pairs USING (host, target_user)),
    routine AS (SELECT e.host, e.target_user FROM events e SEMI JOIN pairs p
                    ON e.host = p.host AND e.target_user = p.target_user
                WHERE {OK} AND e.action = 'login_success'
                  AND e.source_seq NOT IN (SELECT source_seq FROM x)
                GROUP BY ALL HAVING count(*) >= {rmin}),
    k AS (SELECT k0.* FROM k0 LEFT JOIN routine r USING (host, target_user)
          WHERE NOT (r.host IS NOT NULL
                     AND ((k0.ts_ms // 3600000) % 24) >= {bh0}
                     AND ((k0.ts_ms // 3600000) % 24) < {bh1}))
    SELECT CASE WHEN src_ip IS NOT NULL AND NOT al_is_internal_ip(src_ip) THEN 'secondary' ELSE 'primary' END
               AS label,
           CASE WHEN src_ip IS NOT NULL AND NOT al_is_internal_ip(src_ip) THEN NULL
                WHEN is_ssh THEN 'T1021.004' WHEN logon_type = 10 THEN 'T1021.001' ELSE 'T1021.002' END
               AS sub_technique_id,
           ts_ms, ts_ms AS last_ts_ms, least(source_seq, coalesce(p_seq, source_seq)) AS source_seq, host,
           host AS subject_host, NULL AS src_user, target_user, src_ip, NULL AS dst_ip, 1 AS raw_alert_count,
           list_filter([left(raw_line, {int(th.get('evidence_max_chars', 300))}),
                        left(p_line, {int(th.get('evidence_max_chars', 300))})], lambda v: v IS NOT NULL)
               AS evidence_lines,
           list_filter([source_seq, p_seq], lambda v: v IS NOT NULL) AS source_keys
    FROM k
    """
    return finish(rule, core)


TEMPLATES: dict[str, Template] = {
    "brute_force_then_success": brute_force_then_success,
    "password_spray": password_spray,
    "account_created_then_elevated": account_created_then_elevated,
    "beaconing": beaconing,
    "ransom_rename": ransom_rename,
    "exfil_volume": exfil_volume,
    "new_admin_logon": new_admin_logon,
}
