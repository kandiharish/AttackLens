"""Stage 2 network-volume templates built for 40-60 M connection rows (DEVELOPMENT.md §4, §11).

Stage order in every template (measured: the first stage decides whether the template scales):
  1. one aggregation on raw narrow columns (host, src_ip, dst_ip / dst_port) with no joins - the most selective
     necessary condition (e.g. the pair's total bytes, connection count, distinct ports);
  2. bucketing / baselines / window functions only on the rows of those candidate keys;
  3. subject_host (host_ip_map joins, entity fallback) only on candidate rows; evidence lines are fetched at the
     end by source_seq (with_evidence), so raw_line never passes through a window.
Same contract as detect_templates: (con, rule, thresholds) -> SQL producing the raw_alerts columns.
"""

from __future__ import annotations

from typing import Any

import duckdb

from attacklens.detect_sql import evidence_chars
from attacklens.detect_sql import OK, TIE_ORDER, ev_keys, finish, ip_host_joins, rule_filter, subject_host_expr


def with_evidence(core: str, th: dict[str, Any]) -> str:
    """`core` yields CORE_COLUMNS with `ev_keys` (source_seq list) instead of evidence_lines; add the lines."""
    mc, ml = evidence_chars(th), int(th.get("evidence_max_lines", 3))
    return f"""
    WITH a AS (SELECT row_number() OVER () AS rid, * FROM ({core})),
    k AS (SELECT rid, unnest(ev_keys) AS s, generate_subscripts(ev_keys, 1) AS o FROM a),
    l AS (SELECT source_seq AS s, any_value(left(raw_line, {mc})) AS line FROM events
          WHERE {OK} AND source_seq IN (SELECT s FROM k) GROUP BY source_seq),
    ev AS (SELECT k.rid, list_slice(list(l.line ORDER BY k.o), 1, {ml}) AS evidence_lines
           FROM k JOIN l USING (s) GROUP BY k.rid)
    SELECT a.* EXCLUDE (rid, ev_keys), coalesce(ev.evidence_lines, []::VARCHAR[]) AS evidence_lines
    FROM a LEFT JOIN ev USING (rid)"""


def _ev(th: dict[str, Any]) -> str:
    """Earliest evidence_max_lines source_seq of a group (lines are fetched later by with_evidence)."""
    return f"min_by(source_seq, {TIE_ORDER}, {int(th.get('evidence_max_lines', 3))})"


def _raw(actions: str, extra: str, flt: str = "") -> str:
    """Stage-1 source: narrow raw columns, no joins."""
    return (f"(SELECT ts_ms, source_seq, source_type, action, host, src_ip, dst_ip, dst_port, bytes_out, src_zone, "
            f"dst_zone, coalesce(src_user, target_user) AS u, coalesce(dst_ip, lower(dst_domain)) AS dk FROM events "
            f"WHERE {OK} AND action IN {actions} {extra}{flt})")


def _subject(th: dict[str, Any], rows: str) -> str:
    """Stage 3: add subject `sh` and `m_host` (host of src_ip) to candidate rows."""
    return f"""SELECT e.*, m.host AS m_host, {subject_host_expr('e', 'm', th)} AS sh FROM {rows} e
               {ip_host_joins('e', 'm')}"""


def _on(cols: str, a: str, b: str, nullable: tuple[str, ...] = ()) -> str:
    """Equi-join predicate on comma-separated `cols`; `nullable` columns use IS NOT DISTINCT FROM."""
    return " AND ".join(f"{a}.{c} IS NOT DISTINCT FROM {b}.{c}" if c in nullable else f"{a}.{c} = {b}.{c}"
                        for c in (x.strip() for x in cols.split(",")))


def point_bursts(part: str, win: int, cond: str) -> str:
    """detect_sql.window_bursts evaluated on (part, ts_ms) points instead of rows. In its RANGE frame every row of
    one ts_ms shares wv, so cond, the latest satisfying ts (ls), the burst start and bid depend only on the point;
    rows sharing a timestamp (pile-up seconds) therefore cost one window row, not one each. Needs CTE `pw`
    (part cols, ts_ms unique per part, wv [, cond inputs]); defines q1..q3 and ends in CTE `pb` (part, ts_ms, bid)."""
    return f"""
    q1 AS (SELECT *, max(CASE WHEN {cond} THEN ts_ms END) OVER (PARTITION BY {part} ORDER BY ts_ms
                                                                ROWS UNBOUNDED PRECEDING) AS ls FROM pw),
    q2 AS (SELECT * FROM q1 WHERE ls IS NOT NULL AND ts_ms - ls < {win}),
    q3 AS (SELECT *, CASE WHEN ts_ms - lag(ts_ms) OVER (PARTITION BY {part} ORDER BY ts_ms) <= {win}
                          THEN 0 ELSE 1 END AS nb FROM q2),
    pb AS (SELECT {part}, ts_ms, sum(nb) OVER (PARTITION BY {part} ORDER BY ts_ms ROWS UNBOUNDED PRECEDING) AS bid
           FROM q3)"""


def window_distinct(part: str, key: str, win: int, rows: str) -> str:
    """CTEs pd, pl, pe, pw: per (part, ts_ms) point of `rows`, wv = count(DISTINCT key) over rows with ts in
    [ts, ts + win) (the RANGE CURRENT ROW .. win-1 FOLLOWING frame) without a DISTINCT window, which is
    superlinear when one second holds a whole partition (measured: 1 M peers 13.7 s vs 250 k 1.2 s). Each distinct
    (key, s) covers the window starts t in (lo, s], lo = max(previous s of the key, s - win); these intervals are
    disjoint per key, so wv(t) = #{lo < t} - #{s < t}: one running sum over the sorted events."""
    return f"""
    pd AS (SELECT DISTINCT {part}, {key}, ts_ms FROM {rows}),
    pl AS (SELECT {part}, ts_ms AS s, greatest(coalesce(lag(ts_ms) OVER (PARTITION BY {part}, {key} ORDER BY ts_ms),
                                                         ts_ms - {win}), ts_ms - {win}) AS lo FROM pd),
    pe AS (SELECT {part}, t, o, sum(d) AS d FROM (
               SELECT {part}, lo AS t, 1 AS o, 1 AS d FROM pl UNION ALL SELECT {part}, s, 1, -1 FROM pl
               UNION ALL SELECT DISTINCT {part}, ts_ms, 0, 0 FROM pd) GROUP BY ALL),
    pw AS (SELECT * EXCLUDE (o, d) FROM (
               SELECT {part}, t AS ts_ms, o, d, sum(d) OVER (PARTITION BY {part} ORDER BY t, o
                                                             ROWS UNBOUNDED PRECEDING) AS wv FROM pe) WHERE o = 0)"""


def beaconing(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1071.001: same (source, destination) with >= beacon_min_conns connections in one session (gaps
    > beacon_session_gap_ms split sessions) and inter-arrival coefficient of variation < beacon_max_cv.
    Candidates: (host, src_ip, dst) with >= beacon_min_conns connections, then (pair, UTC day) groups with
    beacon_min_conns..beacon_max_conns_per_day connections."""
    n, cv, gap = int(th["beacon_min_conns"]), float(th["beacon_max_cv"]), int(th["beacon_session_gap_ms"])
    mx = int(th.get("beacon_max_conns_per_day", 10**12))
    src = _raw("('conn_out', 'conn_allowed')", "AND coalesce(dst_ip, dst_domain) IS NOT NULL", rule_filter(rule))
    key = "host, src_ip, dk"
    on = "c.host = p.host AND c.src_ip IS NOT DISTINCT FROM p.src_ip AND c.dk = p.dk"
    pon = _on(key, "r", "p", ("src_ip",))
    # sessions are computed on (pair, ts_ms) points: rows sharing a timestamp add c - 1 zero gaps, so each session's
    # gap multiset (fed to the same avg / stddev_pop) equals the row-level one; rows are only aggregated per session
    core = f"""
    WITH c0 AS (SELECT * FROM {src}),
    cand AS (SELECT {key} FROM c0 GROUP BY ALL HAVING count(*) >= {n}),
    c AS (SELECT c.* FROM c0 c SEMI JOIN cand p ON {on}),
    pd AS (SELECT {key}, ts_ms // 86400000 AS d FROM c GROUP BY ALL HAVING count(*) BETWEEN {n} AND {mx}),
    r0 AS (SELECT c.* FROM c SEMI JOIN pd p ON {on} AND c.ts_ms // 86400000 = p.d),
    pt AS (SELECT {key}, ts_ms, count(*) AS c FROM r0 GROUP BY ALL),
    gl AS (SELECT *, ts_ms - lag(ts_ms) OVER (PARTITION BY {key} ORDER BY ts_ms) AS gap0 FROM pt),
    gn AS (SELECT *, CASE WHEN gap0 IS NULL OR gap0 > {gap} THEN 1 ELSE 0 END AS nb FROM gl),
    ss AS (SELECT *, sum(nb) OVER (PARTITION BY {key} ORDER BY ts_ms ROWS UNBOUNDED PRECEDING) AS sid FROM gn),
    sv AS (SELECT {key}, sid, unnest(CASE WHEN nb = 0 THEN [gap0] ELSE []::BIGINT[] END
                                     || list_resize([]::BIGINT[], (c - 1)::BIGINT, 0::BIGINT)) AS dt FROM ss),
    st AS (SELECT {key}, sid FROM sv GROUP BY {key}, sid
           HAVING count(*) + 1 >= {n} AND avg(dt) > 0 AND stddev_pop(dt) / avg(dt) < {cv}),
    sp AS (SELECT * FROM ss s SEMI JOIN st p ON {_on(key, "s", "p", ("src_ip",))} AND s.sid = p.sid),
    rs AS (SELECT r.*, p.sid FROM r0 r JOIN sp p ON {pon} AND r.ts_ms = p.ts_ms),
    r AS ({_subject(th, 'rs')}),
    a AS (SELECT {key}, sid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                 count(*) AS n, al_mode(list(sh)) AS sh,
                 al_mode(list(dst_ip)) AS dst_ip, al_mode(list(u)) AS u, {_ev(th)} AS ev_keys, {ev_keys(th)} AS keys
          FROM r GROUP BY {key}, sid HAVING count(*) >= {n})
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, sh AS subject_host,
           u AS src_user, NULL AS target_user, src_ip, dst_ip, n AS raw_alert_count, ev_keys, keys AS source_keys
    FROM a
    """
    return finish(rule, with_evidence(core, th))


def exfil_volume(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1048: sum(bytes_out) per (host, src_ip, dst_ip) to an external dst within exfil_window_ms exceeds
    max(exfil_min_bytes, exfil_baseline_mult x baseline). Baseline = median over the source's days of daily
    external bytes per distinct destination, excluding the days the pair itself has traffic. Candidates: pairs
    whose total > exfil_min_bytes, then tumbling exfil_window_ms buckets where two adjacent buckets sum above it.
    Routine transfers are suppressed: a pair with traffic on >= exfil_routine_min_days days whose alert-day volume
    is <= exfil_routine_max_ratio x the pair's median daily volume."""
    mn, win, mult = int(th["exfil_min_bytes"]), int(th["exfil_window_ms"]), float(th["exfil_baseline_mult"])
    rdays, rratio = int(th.get("exfil_routine_min_days", 10**6)), float(th.get("exfil_routine_max_ratio", 0))
    src = _raw("('conn_out', 'conn_allowed')",
               "AND bytes_out > 0 AND dst_ip IS NOT NULL AND NOT al_is_internal_ip(dst_ip)")
    key = "host, src_ip, dst_ip"
    on = "x.host = y.host AND x.src_ip IS NOT DISTINCT FROM y.src_ip AND x.dst_ip = y.dst_ip"
    hs = "x.host = y.host AND x.src_ip IS NOT DISTINCT FROM y.src_ip"
    core = f"""
    WITH c0 AS (SELECT * FROM {src}),
    cand AS (SELECT {key} FROM c0 GROUP BY ALL HAVING sum(bytes_out) > {mn}),
    c AS (SELECT x.* FROM c0 x SEMI JOIN cand y ON {on}),
    bk AS (SELECT {key}, ts_ms // {win} AS k, sum(bytes_out) AS s FROM c GROUP BY ALL),
    ck AS (SELECT x.host, x.src_ip, x.dst_ip, x.k FROM bk x LEFT JOIN bk y ON {on} AND y.k = x.k + 1
           WHERE x.s + coalesce(y.s, 0) > {mn}),
    kk AS (SELECT DISTINCT * FROM (SELECT * FROM ck UNION ALL SELECT host, src_ip, dst_ip, k + 1 FROM ck)),
    pairs AS (SELECT DISTINCT host, src_ip, dst_ip FROM ck),
    pdaily AS (SELECT x.host, x.src_ip, x.dst_ip, x.ts_ms // 86400000 AS d, sum(x.bytes_out) AS vol
               FROM c x SEMI JOIN pairs y ON {on} GROUP BY ALL),
    pstat AS (SELECT host, src_ip, dst_ip, count(*) AS ndays, median(vol) AS med FROM pdaily GROUP BY ALL),
    daily AS (SELECT x.host, x.src_ip, x.ts_ms // 86400000 AS d,
                     sum(x.bytes_out)::DOUBLE / greatest(approx_count_distinct(x.dst_ip), 1) AS per_dst
              FROM c0 x SEMI JOIN (SELECT DISTINCT host, src_ip FROM pairs) y ON {hs} GROUP BY ALL),
    base AS (SELECT p.host, p.src_ip, p.dst_ip, median(dl.per_dst) AS base
             FROM pairs p JOIN daily dl ON dl.host = p.host AND dl.src_ip IS NOT DISTINCT FROM p.src_ip
             WHERE NOT EXISTS (SELECT 1 FROM pdaily q WHERE q.host = p.host AND q.src_ip IS NOT DISTINCT FROM p.src_ip
                               AND q.dst_ip = p.dst_ip AND q.d = dl.d)
             GROUP BY ALL),
    r0 AS (SELECT x.*, greatest({mn}::DOUBLE, {mult} * coalesce(b.base, 0)) AS thr
           FROM c x SEMI JOIN kk y ON {on} AND x.ts_ms // {win} = y.k
           LEFT JOIN base b ON b.host = x.host AND b.src_ip IS NOT DISTINCT FROM x.src_ip AND b.dst_ip = x.dst_ip),
    pw AS (SELECT *, sum(v) OVER (PARTITION BY {key} ORDER BY ts_ms RANGE BETWEEN CURRENT ROW AND {win - 1} FOLLOWING)
                  AS wv FROM (SELECT {key}, ts_ms, sum(bytes_out) AS v, max(thr) AS thr FROM r0 GROUP BY ALL)),
    {point_bursts(key, win, 'wv > thr')},
    mb AS (SELECT x.*, p.bid FROM r0 x JOIN pb p ON {_on(key, "x", "p", ("src_ip",))} AND x.ts_ms = p.ts_ms),
    r AS ({_subject(th, 'mb')}),
    b AS (SELECT {key}, bid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                 count(*) AS n, al_mode(list(sh)) AS sh, al_mode(list(u)) AS u, {_ev(th)} AS ev_keys,
                 {ev_keys(th)} AS keys
          FROM r GROUP BY {key}, bid),
    f AS (SELECT b.* FROM b
          LEFT JOIN pstat ps ON ps.host = b.host AND ps.src_ip IS NOT DISTINCT FROM b.src_ip AND ps.dst_ip = b.dst_ip
          LEFT JOIN pdaily pd ON pd.host = b.host AND pd.src_ip IS NOT DISTINCT FROM b.src_ip AND pd.dst_ip = b.dst_ip
                             AND pd.d = b.ts_ms // 86400000
          WHERE NOT (coalesce(ps.ndays, 0) >= {rdays} AND coalesce(pd.vol, 0) <= {rratio} * ps.med))
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, sh AS subject_host,
           u AS src_user, NULL AS target_user, src_ip, dst_ip, n AS raw_alert_count, ev_keys, keys AS source_keys
    FROM f
    """
    return finish(rule, with_evidence(core, th))


def port_scan(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """T1046: within scan_window_ms, one src_ip reaches >= scan_min_ports distinct dst_port on one dst_ip
    (vertical; subject = internal endpoint), or >= scan_min_hosts distinct dst_ip on one dst_port (horizontal;
    internal dst only if scan_horizontal_internal_only; subject = the scanner, dst_ip NULL). Candidates: keys
    reaching the distinct count over the whole set, then tumbling-bucket pairs that could reach it in a window.
    An external scanner gets the rule's secondary label (T1595 Active Scanning, Reconnaissance, low severity)."""
    n_ports, n_hosts, win = int(th["scan_min_ports"]), int(th["scan_min_hosts"]), int(th["scan_window_ms"])
    internal = "AND al_is_internal_ip(dst_ip)" if th.get("scan_horizontal_internal_only", True) else ""
    acts = "('conn_allowed', 'conn_denied')"
    # an internal scanner is Discovery (primary, T1046); an internet scanner is Reconnaissance (secondary label)
    internal_src = "al_is_internal_ip(src_ip)" if rule.get("secondary") else "TRUE"

    def variant(a: str, b: str, key: str, n: int, extra: str, subject: str, dst: str) -> str:
        part = f"{a}, {b}"
        on = f"x.{a} = y.{a} AND x.{b} = y.{b}"
        src = _raw(acts, "AND src_ip IS NOT NULL AND dst_ip IS NOT NULL AND dst_port IS NOT NULL " + extra)
        return f"""(
    WITH c0 AS (SELECT * FROM {src}),
    cand AS (SELECT {part} FROM c0 GROUP BY ALL HAVING count(DISTINCT {key}) >= {n}),
    c AS (SELECT x.* FROM c0 x SEMI JOIN cand y ON {on}),
    bk AS (SELECT {part}, ts_ms // {win} AS k, count(DISTINCT {key}) AS cd FROM c GROUP BY ALL),
    ck AS (SELECT x.{a}, x.{b}, x.k FROM bk x LEFT JOIN bk y ON {on} AND y.k = x.k + 1
           WHERE x.cd + coalesce(y.cd, 0) >= {n}),
    kk AS (SELECT DISTINCT * FROM (SELECT * FROM ck UNION ALL SELECT {part}, k + 1 FROM ck)),
    r0 AS (SELECT x.* FROM c x SEMI JOIN kk y ON {on} AND x.ts_ms // {win} = y.k),
    {window_distinct(part, key, win, 'r0')},
    {point_bursts(part, win, f'wv >= {n}')},
    mb AS (SELECT x.*, p.bid FROM r0 x JOIN pb p ON {on.replace('y.', 'p.')} AND x.ts_ms = p.ts_ms),
    r AS ({_subject(th, 'mb')}),
    b AS (SELECT {part}, bid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                 count(*) AS n, al_mode(list(host)) AS host, al_mode(list({subject})) AS sh,
                 {_ev(th)} AS ev_keys, {ev_keys(th)} AS keys
          FROM r GROUP BY {part}, bid HAVING count(DISTINCT {key}) >= {n})
    SELECT CASE WHEN {internal_src} THEN 'primary' ELSE 'secondary' END AS label, NULL AS sub_technique_id,
           ts_ms, last_ts_ms, source_seq, host, sh AS subject_host, NULL AS src_user, NULL AS target_user, src_ip,
           {dst} AS dst_ip, n AS raw_alert_count, ev_keys, keys AS source_keys FROM b)"""

    # horizontal: the scanner is the subject (its host name if known, else its IP as the entity)
    vertical = variant("src_ip", "dst_ip", "dst_port", n_ports, "", "sh", "dst_ip")
    horizontal = variant("src_ip", "dst_port", "dst_ip", n_hosts, internal, "coalesce(m_host, src_ip)", "NULL")
    return finish(rule, with_evidence(f"SELECT * FROM {vertical}\n    UNION ALL\n    SELECT * FROM {horizontal}", th))


TEMPLATES_NET = {
    "beaconing": beaconing,
    "exfil_volume": exfil_volume,
    "port_scan": port_scan,
}
