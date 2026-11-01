"""Behavioural cloud templates (catalog §5): first_seen (new / rare / dormant keys), geo_velocity (impossible
travel) and new_source_burst (bulk reads by a source new to a data store). Same contract as detect_cloud_templates: Spec -> one SELECT of HIT_COLUMNS over cloud_ev.

Cold start (catalog §5 "baseline rules", §7.7): a hit whose history key (actor_key by default, `hist_key`) has less
than cold_start.min_history_days of history, or fewer than min_actor_events events on earlier days, gets
baseline_ok=false; detect_cloud.wrap() then caps its severity at cold_start.severity and the evidence says why.
"""

from __future__ import annotations

from attacklens.detect_cloud_ev import DAY_MS, baseline_ok_sql
from attacklens.detect_cloud_templates import HIT_COLUMNS, TIE, Spec, _int, _key_cte, _keys, agg_cols, projection
from attacklens.detect_sql import window_bursts


def first_seen(spec: Spec) -> str:
    """The first row per (key, day) whose key had <= max_prior_count rows (by <= max_prior_actors actors) in the
    baseline_days before that day. require_older_history: the key must also have rows before the baseline window
    (dormant identity reactivated). exclude_machine (default true): machine identities never take part.
    max_per_actor_day: more hits for one actor_key on one day collapse into one summary hit (summary_severity)."""
    p = spec.p
    keys = _keys(spec)
    bd = _int(p.get("baseline_days", 14))
    ks = ", ".join(f"({k}) AS _k{i}" for i, k in enumerate(keys))
    part = ", ".join(f"_k{i}" for i in range(len(keys)))
    nn = " AND ".join(f"_k{i} IS NOT NULL" for i in range(len(keys)))
    on = " AND ".join(f"x._k{i} = y._k{i}" for i in range(len(keys)))
    on_f = " AND ".join(f"f._k{i} = c._k{i}" for i in range(len(keys)))
    mach = " AND NOT coalesce(machine, false)" if p.get("exclude_machine", True) else ""
    maxa = p.get("max_prior_actors")
    older = ""
    if p.get("require_older_history"):
        older = f" AND EXISTS (SELECT 1 FROM kd z WHERE {on.replace('x.', 'z.').replace('y.', 'kd.')} " \
                f"AND z.day < kd.day - {bd})"
    hk = str(p.get("hist_key", "actor_key"))
    mdays = float(p.get("min_history_days", spec.cold.get("min_history_days", 3)))
    mev = _int(p.get("min_actor_events", spec.cold.get("min_actor_events", 50)))
    bok = baseline_ok_sql("r", "r.ts_ms", hk, spec.hist(hk), mdays, mev) if spec.hist and (mdays or mev) else "true"
    cap = _int(p.get("max_per_actor_day", 0))
    keytxt = " || '|' || ".join(f"CAST(_k{i} AS VARCHAR)" for i in range(len(keys)))
    cold_note = (f"'baseline_ok=false: history < {mdays:g} d or < {mev} earlier events for ' || coalesce({hk}, '?')")
    cols = [c for c in HIT_COLUMNS if c not in ("sev", "lbl", "baseline_ok", "ev", "keys", "n", "last_ts_ms",
                                                 "target_user")]
    sql = f"""WITH f AS (SELECT * FROM (SELECT *, {ks} FROM cloud_ev WHERE ({spec.filter}){mach}) WHERE {nn}),
    kd AS (SELECT {part}, day, count(*) AS n, list(DISTINCT actor_key) AS acts,
                  arg_min(source_seq, {TIE}) AS seq0 FROM f GROUP BY ALL),
    pr AS (SELECT x.{part.replace(', ', ', x.')}, x.day, sum(y.n) AS pn,
                  len(list_distinct(flatten(list(y.acts)))) AS pa
           FROM kd x JOIN kd y ON {on} AND y.day < x.day AND y.day >= x.day - {bd} GROUP BY ALL),
    c AS (SELECT kd.*, coalesce(pr.pn, 0) AS pn FROM kd LEFT JOIN pr USING ({part}, day)
          WHERE coalesce(pr.pn, 0) <= {_int(p.get('max_prior_count', 0))}
                {f'AND coalesce(pr.pa, 0) <= {_int(maxa)}' if maxa is not None else ''}{older}),
    r AS (SELECT f.*, c.pn FROM c JOIN f ON f.source_seq = c.seq0 AND f.day = c.day AND {on_f}),
    s AS (SELECT r.*, CAST(coalesce({spec.sev or 'NULL'}, {spec.base}) AS INTEGER) AS _s, {bok} AS _bok,
                 'first_seen key=' || {keytxt} || ' prior=' || r.pn || ' in {bd} d' AS _note FROM r),
    rk AS (SELECT *, row_number() OVER (PARTITION BY coalesce(actor_key, ''), day
                                        ORDER BY _bok DESC, _s DESC, ts_ms, source_seq) AS _rn FROM s)
    SELECT {', '.join(cols)}, ts_ms AS last_ts_ms, lower(CAST({spec.target or 'target_user'} AS VARCHAR)) AS target_user,
           1 AS n, CASE WHEN _bok THEN [_note, evl] ELSE [{cold_note}, _note, evl] END AS ev, [source_seq] AS keys,
           _s AS sev, CAST({spec.label or 'NULL'} AS VARCHAR) AS lbl, _bok AS baseline_ok
    FROM rk {f'WHERE _rn <= {cap}' if cap else ''}"""
    if not cap:
        return sql
    return sql + f"""
    UNION ALL BY NAME
    SELECT min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq, al_mode(list(host)) AS host,
           al_mode(list(acct)) AS acct, al_mode(list(actor)) AS actor, any_value(actor_key) AS actor_key,
           al_mode(list(src_user)) AS src_user, NULL::VARCHAR AS target_user, al_mode(list(src_ip)) AS src_ip,
           count(*) AS n, list_prepend('first_seen summary: ' || count(*) || ' more new keys for '
                                       || coalesce(any_value(actor_key), '?') || ' this day',
                                       min_by(evl, {TIE}, {max(1, spec.lines - 1)})) AS ev,
           min_by(source_seq, {TIE}, {spec.keys}) AS keys, {_int(p.get('summary_severity', 35))} AS sev,
           NULL::VARCHAR AS lbl, al_mode(list(api)) AS api, bool_and(coalesce(machine, false)) AS machine,
           bool_and(_bok) AS baseline_ok
    FROM rk WHERE _rn > {cap} GROUP BY coalesce(actor_key, ''), day"""


def geo_velocity(spec: Spec) -> str:
    """Consecutive rows of one actor_key with coordinates (SigninLogs geo, or a country centroid when
    geo.country_centroids_path is set): distance >= min_km and speed > max_kmh (time floor 1 min). Pairs in the same
    ASN (ignore_same_asn), from corporate egress, or from cloud-provider ranges are ignored."""
    p = spec.p
    mach = " AND NOT coalesce(machine, false)" if p.get("exclude_machine", True) else ""
    same_asn = " AND NOT coalesce(asn = p_asn, false)" if p.get("ignore_same_asn", True) else ""
    km = ("2 * 6371 * asin(sqrt(pow(sin(radians(lat - p_lat) / 2), 2) + cos(radians(p_lat)) * cos(radians(lat)) "
          "* pow(sin(radians(lon - p_lon) / 2), 2)))")
    return f"""WITH f AS (SELECT ts_ms, source_seq, host, acct, actor, actor_key, src_user, target_user, src_ip, api,
                         machine, evl, asn, cc, lat, lon, corp_ip, provider, day
               FROM cloud_ev WHERE ({spec.filter}) AND lat IS NOT NULL AND lon IS NOT NULL
                 AND actor_key IS NOT NULL{mach}),
    w AS (SELECT *, lag(ts_ms) OVER o AS p_ts, lag(source_seq) OVER o AS p_seq, lag(lat) OVER o AS p_lat,
                 lag(lon) OVER o AS p_lon, lag(asn) OVER o AS p_asn, lag(evl) OVER o AS p_evl,
                 lag(corp_ip) OVER o AS p_corp, lag(provider) OVER o AS p_prov, lag(cc) OVER o AS p_cc
          FROM f WINDOW o AS (PARTITION BY actor_key ORDER BY ts_ms, source_seq)),
    d AS (SELECT *, {km} AS km FROM w WHERE p_ts IS NOT NULL)
    SELECT p_ts AS ts_ms, ts_ms AS last_ts_ms, p_seq AS source_seq, host, acct, actor, actor_key, src_user,
           target_user, src_ip, 2 AS n,
           ['impossible_travel ' || round(km) || ' km in ' || round((ts_ms - p_ts) / 60000.0) || ' min '
            || coalesce(p_cc, '?') || ' -> ' || coalesce(cc, '?'), p_evl, evl] AS ev, [p_seq, source_seq] AS keys,
           CAST({spec.sev or 'NULL'} AS INTEGER) AS sev, CAST({spec.label or 'NULL'} AS VARCHAR) AS lbl, api,
           machine, NULL::BOOLEAN AS baseline_ok
    FROM d WHERE km >= {float(p.get('min_km', 500))}
      AND km / greatest((ts_ms - p_ts) / 3600000.0, 1.0 / 60) > {float(p.get('max_kmh', 900))}
      AND NOT coalesce(corp_ip OR p_corp, false) AND p_prov IS NULL AND provider IS NULL{same_asn}"""


def new_source_burst(spec: Spec) -> str:
    """Bulk data reads by a source new to a store: per (store, source), >= min_distinct distinct objects (`distinct`)
    inside any window_ms window, where the source had <= max_prior reads of that store (rows of the branch filter) in
    the novel_days before the burst. Cold start is judged on the STORE: it needs store_history_days of reads before
    the burst (baseline_ok); a source without history is the point of the rule, not a reason to stay quiet.
    params: store, source (SQL over cloud_ev), distinct, window_ms, min_distinct, novel_days, store_history_days,
    max_prior (default 0)."""
    p = spec.p
    win, nmin = _int(p["window_ms"]), _int(p.get("min_distinct", 1))
    nd = int(float(p.get("novel_days", 14)) * DAY_MS)
    mh = int(float(p.get("store_history_days", spec.cold.get("min_history_days", 3))) * DAY_MS)
    f, part, _ = _key_cte(spec, [str(p["store"]), str(p["source"])], f", ({p.get('distinct', 'source_seq')}) AS _d")
    hit = ", ".join("b." + c for c in HIT_COLUMNS if c != "baseline_ok")
    return f"""WITH {f},
    cand AS (SELECT {part} FROM f WHERE _d IS NOT NULL GROUP BY ALL HAVING count(DISTINCT _d) >= {nmin}),
    r AS (SELECT {projection(spec, ('_k0', '_k1', '_d'), spec.sev, spec.label, spec.target)}
          FROM f SEMI JOIN cand USING ({part}) WHERE _d IS NOT NULL),
    {window_bursts(part, win, 'count(DISTINCT _d)', f'wv >= {nmin}')},
    b AS (SELECT {part}, bid, {agg_cols(spec)} FROM mb GROUP BY {part}, bid HAVING count(DISTINCT _d) >= {nmin}),
    st AS (SELECT _k0, min(ts_ms) AS first_ts FROM f GROUP BY _k0),
    pr AS (SELECT b._k0, b._k1, b.bid, count(x.ts_ms) AS pn FROM b LEFT JOIN f x ON x._k0 = b._k0 AND x._k1 = b._k1
           AND x.ts_ms < b.ts_ms AND x.ts_ms >= b.ts_ms - {nd} GROUP BY ALL)
    SELECT {hit}, b.ts_ms - st.first_ts >= {mh} AS baseline_ok
    FROM b JOIN pr USING ({part}, bid) JOIN st USING (_k0) WHERE pr.pn <= {_int(p.get('max_prior', 0))}"""


BEHAVIOUR_TEMPLATES = {"first_seen": first_seen, "geo_velocity": geo_velocity, "new_source_burst": new_source_burst}
