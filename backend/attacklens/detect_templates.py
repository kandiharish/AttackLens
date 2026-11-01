"""Stage 2 detection templates (DEVELOPMENT.md §5.2). Each function takes (con, rule, thresholds) and returns one SQL
SELECT producing exactly the raw_alerts columns (§15.4).

Preconditions on `con`: an `events` view and the helpers from detect_sql.prepare() (al_is_internal_ip, al_attack,
al_ip_host). Every template first selects only its candidate action rows (and pre-aggregates candidate keys)
before any window function, so windows never run over the whole input.
"""

from __future__ import annotations

from typing import Any, Callable

import duckdb

from attacklens.detect_sql import evidence_chars
from attacklens.detect_sql import OK, TIE_ORDER, ev_keys, ev_lines, finish, rule_filter, sql_list, subject_host_expr
from attacklens.detect_sql import window_bursts as _window_bursts

Template = Callable[[duckdb.DuckDBPyConnection, dict[str, Any], dict[str, Any]], str]


def _gap_sessions(src: str, part: str, gap: int) -> str:
    """CTEs over CTE `{src}`: session id `sid` per partition, new session when the gap between consecutive rows
    (time order) > `gap` ms. Ends in CTE `ss` (= `{src}` rows + sid).
    Scale: rows sharing one ts_ms always share a session (gap 0), so the windows run over the distinct
    (part, ts_ms) points only and rows get their sid by an equi-join - a timestamp pile-up (millions of rows in
    one second) costs one point per key instead of a million-row sort partition."""
    if gap < 0:
        raise ValueError(f"gap {gap} ms: must be >= 0")
    return f"""
    gp AS (SELECT {part}, ts_ms FROM {src} GROUP BY ALL),
    gl AS (SELECT *, ts_ms - lag(ts_ms) OVER (PARTITION BY {part} ORDER BY ts_ms) AS gap0 FROM gp),
    gs AS (SELECT {part}, ts_ms, sum(CASE WHEN gap0 IS NULL OR gap0 > {gap} THEN 1 ELSE 0 END)
                      OVER (PARTITION BY {part} ORDER BY ts_ms ROWS UNBOUNDED PRECEDING) AS sid FROM gl),
    ss AS (SELECT {src}.*, gs.sid FROM {src} JOIN gs USING ({part}, ts_ms))"""


def _distinct_bursts(part: str, dcol: str, win: int, n: int) -> str:
    """Same rows/bursts as detect_sql.window_bursts(part, win, 'count(DISTINCT dcol)', 'wv >= n') over CTE `r`,
    without a DISTINCT RANGE window over the rows. Ends in CTE `mb` (= `r` rows + bid).
    wv(t) = distinct dcol values with a row in [t, t + win). A row of value v at x (previous row of v at pv) covers
    the points [max(x - win + 1, pv + 1), x]; these spans are disjoint per value and their union is exactly the
    points where v counts, so +1/-1 at the span edges summed in time order gives wv at every distinct
    (part, ts_ms) point (ASOF join). Bursts are then built over points only: all rows of one ts_ms share wv, ls
    and burst, so the result equals the row-level windows, and a timestamp pile-up is one point."""
    if win < 1:
        raise ValueError(f"window {win} ms: must be >= 1")
    on = " AND ".join(f"pt.{k} = uc.{k}" for k in _cols(part))
    return f"""
    uo AS (SELECT {part}, {dcol} AS dv, ts_ms FROM r GROUP BY ALL),
    ul AS (SELECT {part}, ts_ms, lag(ts_ms) OVER (PARTITION BY {part}, dv ORDER BY ts_ms) AS pv FROM uo),
    ue AS (SELECT {part}, p, sum(d) AS d
           FROM (SELECT {part}, greatest(ts_ms - {win - 1}, coalesce(pv + 1, ts_ms - {win - 1})) AS p, 1 AS d FROM ul
                 UNION ALL SELECT {part}, ts_ms + 1 AS p, -1 AS d FROM ul) GROUP BY ALL),
    uc AS (SELECT {part}, p, sum(d) OVER (PARTITION BY {part} ORDER BY p ROWS UNBOUNDED PRECEDING) AS c FROM ue),
    pt AS (SELECT {part}, ts_ms FROM uo GROUP BY ALL),
    pw AS (SELECT pt.*, uc.c AS wv FROM pt ASOF JOIN uc ON {on} AND pt.ts_ms >= uc.p),
    ps AS (SELECT *, max(CASE WHEN wv >= {n} THEN ts_ms END) OVER (PARTITION BY {part} ORDER BY ts_ms
                                                                    ROWS UNBOUNDED PRECEDING) AS ls FROM pw),
    pm AS (SELECT * FROM ps WHERE ls IS NOT NULL AND ts_ms - ls < {win}),
    pg AS (SELECT *, CASE WHEN ts_ms - lag(ts_ms) OVER (PARTITION BY {part} ORDER BY ts_ms) <= {win}
                          THEN 0 ELSE 1 END AS nb FROM pm),
    pb AS (SELECT {part}, ts_ms, sum(nb) OVER (PARTITION BY {part} ORDER BY ts_ms ROWS UNBOUNDED PRECEDING) AS bid
           FROM pg),
    mb AS (SELECT r.*, pb.bid FROM r JOIN pb USING ({part}, ts_ms))"""


def _cols(part: str) -> list[str]:
    return [c.strip() for c in part.split(",") if c.strip()]


def _mode_cte(name: str, src: str, keys: str, col: str) -> str:
    """CTE `{name}`({keys}, mode): al_mode(list({col})) per {keys} group of `{src}` (highest count, then smallest
    value, NULLs ignored) from per-value counts, so no group ever holds a list of all its rows. Groups whose
    values are all NULL are absent (LEFT JOIN -> NULL, as al_mode)."""
    return f"""
    {name}_c AS (SELECT {keys}, {col} AS v, count(*) AS c FROM {src} WHERE {col} IS NOT NULL GROUP BY ALL),
    {name} AS (SELECT {keys}, arg_min(v, {{'c': -c, 'k': v}}) AS mode FROM {name}_c GROUP BY ALL)"""


def _line_keys(th: dict[str, Any]) -> str:
    """Aggregate: the source_seq of the evidence_max_lines first rows by (ts_ms, source_seq) - the rows
    ev_lines(th) takes its lines from (copies of one line share source_seq and appear once per copy)."""
    return f"min_by(source_seq, {TIE_ORDER}, {int(th.get('evidence_max_lines', 3))})"


def _evidence(name: str, src: str, keys: str, where: str, th: dict[str, Any]) -> str:
    """CTE `{name}`({keys}, ev): evidence_lines = left(raw_line) for the source_seq list `lk` of each `{src}` group,
    in list order. source_seq = hash(file, line), so one seq names one line: raw_line is read only for those rows
    (one scan of events `where`, probed by a small seq set) instead of being carried through every window."""
    mc = evidence_chars(th)
    return f"""
    {name}_k AS (SELECT {keys}, unnest(lk) AS seq, generate_subscripts(lk, 1) AS pos FROM {src}),
    {name}_l AS (SELECT source_seq, any_value(left(raw_line, {mc})) AS line FROM events
                 WHERE {where} AND source_seq IN (SELECT seq FROM {name}_k) GROUP BY source_seq),
    {name} AS (SELECT {name}_k.{keys.replace(', ', f', {name}_k.')}, list(l.line ORDER BY {name}_k.pos) AS ev
               FROM {name}_k JOIN {name}_l l ON l.source_seq = {name}_k.seq GROUP BY ALL)"""


BF_KEY_COLUMNS = ("host", "target_user", "src_ip")


def _bf_key(th: dict[str, Any]) -> list[str]:
    """thresholds/params bf_key: burst key columns, a subset of BF_KEY_COLUMNS (default target_user, host)."""
    key = [str(k) for k in (th.get("bf_key") or ["target_user", "host"])]
    bad = [k for k in key if k not in BF_KEY_COLUMNS]
    if bad or not {"host", "target_user"} <= set(key):
        raise ValueError(f"bf_key {key}: must contain host and target_user, columns from {BF_KEY_COLUMNS}")
    return key


def brute_force_then_success(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1110: >= bf_min_failures login_failed per bf_key (default (target_user, host)) in a burst (gaps > bf_gap_ms
    split bursts). T1078 (secondary): a login_success for the same key within bf_success_window_ms after the
    burst, preferring one from the burst's own source IPs (then earliest); any source only if none exists.
    Scale: sessions over distinct (key, ts_ms) points (_gap_sessions); the success is found by ASOF joins over
    successes pre-reduced to one row per (key[, src_ip], ts_ms) (lowest source_seq), never burst x success pairs;
    raw_line read only for the evidence rows (_evidence)."""
    n, gap, sw = int(th["bf_min_failures"]), int(th["bf_gap_ms"]), int(th["bf_success_window_ms"])
    need_success = bool(th.get("bf_require_success", False))
    flt = rule_filter(rule)
    emit2 = bool(th.get("emit_t1078_on_bruteforce", True))
    key = _bf_key(th)
    kc = ", ".join(key)
    nonnull = " AND ".join(f"{k} IS NOT NULL" for k in key)
    on_c = " AND ".join(f"e.{k} = c.{k}" for k in key)
    on_1 = " AND ".join(f"b.{k} = s1.{k}" for k in key)
    on_2 = " AND ".join(f"bi.{k} = s2.{k}" for k in key)
    has_ip = "src_ip" in key
    ip_mode = "" if has_ip else _mode_cte("bm", "ss", f"{kc}, sid", "src_ip") + ","
    ip_col = "b0.src_ip" if has_ip else "bm.mode AS src_ip"
    ip_join = "" if has_ip else f"LEFT JOIN bm USING ({kc}, sid)"
    w = "{'s_ts': ts_ms, 's_seq': source_seq, 's_ip': src_ip, 's_line': raw_line}"
    core = f"""
    WITH f AS (SELECT ts_ms, source_seq, host, target_user, src_ip FROM events
               WHERE {OK} AND action = 'login_failed' AND {nonnull}{flt}),
    cand AS (SELECT {kc} FROM f GROUP BY {kc} HAVING count(*) >= {n}),
    fc AS (SELECT f.* FROM f SEMI JOIN cand USING ({kc})),
    {_gap_sessions('fc', kc, gap)},
    b0 AS (SELECT {kc}, sid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms,
                  min(source_seq) AS source_seq, count(*) AS n, list(DISTINCT src_ip) AS ips,
                  {_line_keys(th)} AS lk, {ev_keys(th)} AS keys
           FROM ss GROUP BY {kc}, sid HAVING count(*) >= {n}),
    {ip_mode}
    {_evidence('be', 'b0', f'{kc}, sid', f"{OK} AND action = 'login_failed'", th)},
    b AS (SELECT b0.{kc.replace(', ', ', b0.')}, b0.sid, b0.ts_ms, b0.last_ts_ms, b0.source_seq, b0.n,
                 {ip_col}, b0.ips, be.ev, b0.keys
          FROM b0 {ip_join} LEFT JOIN be USING ({kc}, sid)),
    sc AS (SELECT e.ts_ms, e.source_seq, e.host, e.target_user, e.src_ip, e.raw_line
           FROM (SELECT * FROM events WHERE {OK} AND action = 'login_success'{flt}) e
           SEMI JOIN cand c ON {on_c}),
    s1 AS (SELECT {kc}, ts_ms, arg_min({w}, source_seq) AS w FROM sc GROUP BY {kc}, ts_ms),
    s2 AS (SELECT {kc}, src_ip AS mip, ts_ms, arg_min({w}, source_seq) AS w FROM sc WHERE src_ip IS NOT NULL
           GROUP BY {kc}, src_ip, ts_ms),
    p1 AS (SELECT b.{kc.replace(', ', ', b.')}, b.sid, s1.w FROM b ASOF JOIN s1 ON {on_1} AND s1.ts_ms >= b.last_ts_ms
           WHERE s1.ts_ms - b.last_ts_ms <= {sw}),
    bi AS (SELECT {kc}, sid, last_ts_ms, unnest(ips) AS ip FROM b),
    p2 AS (SELECT bi.{kc.replace(', ', ', bi.')}, bi.sid, arg_min(s2.w, {{'t': s2.w.s_ts, 'q': s2.w.s_seq}}) AS w
           FROM bi ASOF JOIN s2 ON {on_2} AND bi.ip = s2.mip AND s2.ts_ms >= bi.last_ts_ms
           WHERE s2.ts_ms - bi.last_ts_ms <= {sw} GROUP BY ALL),
    pick AS (SELECT {kc}, sid, coalesce(p2.w, p1.w) AS w FROM p1 LEFT JOIN p2 USING ({kc}, sid)),
    ok AS (SELECT b.*, pk.w.s_ts AS s_ts, pk.w.s_seq AS s_seq, pk.w.s_ip AS s_ip, pk.w.s_line AS s_line,
                  pk.w IS NOT NULL AS has_success
           FROM b LEFT JOIN pick pk USING ({kc}, sid))
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, host AS subject_host,
           NULL AS src_user, target_user, src_ip, NULL AS dst_ip, n AS raw_alert_count, ev AS evidence_lines,
           keys AS source_keys
    FROM ok WHERE {'has_success' if need_success else 'TRUE'}
    UNION ALL
    SELECT 'secondary', NULL, s_ts, s_ts, s_seq, host, host, NULL, target_user, s_ip, NULL, 1,
           [left(s_line, {evidence_chars(th)})], [s_seq]
    FROM ok WHERE has_success AND {'TRUE' if emit2 else 'FALSE'}
    """
    return finish(rule, core)


def password_spray(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1110.003: one src_ip with >= spray_min_users distinct target users failing within spray_window_ms.
    T1078 (secondary): first login_success from that src_ip within bf_success_window_ms after the spray.
    The spray alert's target_user = the account that then logged on (NULL when no success followed).
    Scale: bursts via _distinct_bursts (point-level windows, no DISTINCT RANGE window over rows); host mode from
    per-host counts; raw_line read only for the evidence rows (_evidence)."""
    n, win, sw = int(th["spray_min_users"]), int(th["spray_window_ms"]), int(th["bf_success_window_ms"])
    flt = rule_filter(rule)
    emit2 = bool(th.get("emit_t1078_on_bruteforce", True))
    core = f"""
    WITH f AS (SELECT ts_ms, source_seq, host, target_user, src_ip FROM events
               WHERE {OK} AND action = 'login_failed' AND src_ip IS NOT NULL AND target_user IS NOT NULL{flt}),
    cand AS (SELECT src_ip FROM f GROUP BY src_ip HAVING count(DISTINCT target_user) >= {n}),
    r AS (SELECT f.* FROM f SEMI JOIN cand USING (src_ip)),
    {_distinct_bursts('src_ip', 'target_user', win, n)},
    b0 AS (SELECT src_ip, bid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                  count(*) AS n, {_line_keys(th)} AS lk, {ev_keys(th)} AS keys
           FROM mb GROUP BY src_ip, bid HAVING count(DISTINCT target_user) >= {n}),
    {_mode_cte('hm', 'mb', 'src_ip, bid', 'host')},
    {_evidence('be', 'b0', 'src_ip, bid', f"{OK} AND action = 'login_failed'", th)},
    b AS (SELECT b0.src_ip, b0.bid, b0.ts_ms, b0.last_ts_ms, b0.source_seq, b0.n, hm.mode AS host, be.ev, b0.keys
          FROM b0 LEFT JOIN hm USING (src_ip, bid) LEFT JOIN be USING (src_ip, bid)),
    sc AS (SELECT e.ts_ms, e.source_seq, e.host, e.target_user, e.src_ip, e.raw_line
           FROM (SELECT * FROM events WHERE {OK} AND action = 'login_success'{flt}) e
           SEMI JOIN cand c ON e.src_ip = c.src_ip),
    bs AS (SELECT b.*, sc.ts_ms AS s_ts, sc.source_seq AS s_seq, sc.host AS s_host, sc.target_user AS s_user,
                  sc.raw_line AS s_line
           FROM b ASOF LEFT JOIN sc ON b.src_ip = sc.src_ip AND sc.ts_ms >= b.last_ts_ms)
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, host AS subject_host,
           NULL AS src_user, CASE WHEN s_ts - last_ts_ms <= {sw} THEN s_user END AS target_user, src_ip,
           NULL AS dst_ip, n AS raw_alert_count, ev AS evidence_lines, keys AS source_keys
    FROM bs
    UNION ALL
    SELECT 'secondary', NULL, s_ts, s_ts, s_seq, s_host, s_host, NULL, s_user, src_ip, NULL, 1,
           [left(s_line, {evidence_chars(th)})], [s_seq]
    FROM bs WHERE s_ts IS NOT NULL AND s_ts - last_ts_ms <= {sw} AND {'TRUE' if emit2 else 'FALSE'}
    """
    return finish(rule, core)


def account_created_then_elevated(con: duckdb.DuckDBPyConnection, rule: dict[str, Any],
                                  th: dict[str, Any]) -> str:
    """T1136 (primary, at the creation) + T1098 (secondary, at the group add): user_created then the first
    group_member_added for the same target_user within create_elevate_window_ms. Neither fires alone."""
    win = int(th["create_elevate_window_ms"])
    mc = evidence_chars(th)
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
                 count(*) AS n, al_mode(list(coalesce(src_user, target_user))) AS u, {ev_lines(th)} AS ev,
                 {ev_keys(th)} AS keys
          FROM mb GROUP BY host, bid HAVING count(*) >= {n})
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, host AS subject_host,
           u AS src_user, NULL AS target_user, NULL AS src_ip, NULL AS dst_ip, n AS raw_alert_count,
           ev AS evidence_lines, keys AS source_keys
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
    pa AS (SELECT host, lower(logon_id) AS lid, min(source_seq) AS p_seq,
                  min_by(raw_line, {{'t': ts_ms, 's': source_seq}}) AS p_line
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
           list_filter([left(raw_line, {evidence_chars(th)}),
                        left(p_line, {evidence_chars(th)})], lambda v: v IS NOT NULL)
               AS evidence_lines,
           list_filter([source_seq, p_seq], lambda v: v IS NOT NULL) AS source_keys
    FROM k
    """
    return finish(rule, core)


TEMPLATES: dict[str, Template] = {
    "brute_force_then_success": brute_force_then_success,
    "password_spray": password_spray,
    "account_created_then_elevated": account_created_then_elevated,
    "ransom_rename": ransom_rename,
    "new_admin_logon": new_admin_logon,
}

from attacklens.detect_templates2 import TEMPLATES2  # noqa: E402  (coverage-round templates)

TEMPLATES.update(TEMPLATES2)

from attacklens.detect_templates3 import TEMPLATES3  # noqa: E402  (firewall pack)

TEMPLATES.update(TEMPLATES3)

from attacklens.detect_templates_net import TEMPLATES_NET  # noqa: E402  (scale-safe network templates)

TEMPLATES.update(TEMPLATES_NET)
