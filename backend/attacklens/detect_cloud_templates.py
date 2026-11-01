"""Cloud rule templates (catalog §5 table): match, distinct_burst, rate_spike, sequence, multi_network_session.
first_seen and geo_velocity live in detect_cloud_behaviour.py.

Every template returns ONE SELECT over `cloud_ev` (or the alert view `cl_alerts_ev` for sequence sides) producing the
hit columns HIT_COLUMNS. detect_cloud.wrap() turns hits into raw_alerts rows (labels, severity controls, bounds).
Every template filters candidate rows first; window functions only run over candidate keys.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from attacklens.detect_sql import window_bursts

HIT_COLUMNS = ("ts_ms", "last_ts_ms", "source_seq", "host", "acct", "actor", "actor_key", "src_user", "target_user",
               "src_ip", "n", "ev", "keys", "sev", "lbl", "api", "machine", "baseline_ok")
TIE = "{'t': ts_ms, 's': source_seq}"


@dataclass
class Spec:
    """One rule branch, every SQL fragment already expanded ({cfg.x} replaced)."""
    rule_id: str
    filter: str                      # SQL over cloud_ev incl. the outcome gate
    p: dict[str, Any]                # template params (values resolved)
    base: int                        # branch severity when the template gives none
    sev: str | None = None           # match: row SQL; burst / spike: aggregate SQL; sequence: pair SQL (a., b.)
    target: str | None = None        # target_user SQL (row / pair level)
    label: str | None = None         # SQL -> 'primary' | 'secondary' (row / aggregate / pair level)
    lines: int = 3
    keys: int = 50
    cold: dict[str, Any] = field(default_factory=dict)
    hist: Callable[[str], str] | None = None   # column -> cl_hist_<column> table name
    cols: tuple[str, ...] = ()                 # cloud_ev columns (empty = carry every column through windows)


AGG_BASE = ("ts_ms", "source_seq", "host", "acct", "actor", "actor_key", "src_user", "target_user", "src_ip", "evl",
            "api", "machine")


def projection(spec: Spec, extra: tuple[str, ...], *sqls: str | None) -> str:
    """Columns carried into window layers: the hit columns, `extra` (keys, distinct) and every cloud_ev column
    named in the given SQL fragments. Fewer columns per window layer = much cheaper planning and execution."""
    if not spec.cols:
        return "*"
    words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", " ".join(x for x in sqls if x)))
    keep = [c for c in spec.cols if c in AGG_BASE or c in words]
    return ", ".join(keep + list(extra))


def _int(v: Any) -> int:
    return int(float(v))


def _keys(spec: Spec, name: str = "key", default: tuple[str, ...] = ("actor_key",)) -> list[str]:
    k = spec.p.get(name, list(default))
    return [str(x) for x in ([k] if isinstance(k, str) else k)]


def agg_cols(spec: Spec, target: str = "target_user") -> str:
    """Hit columns aggregated over a group of cloud_ev-shaped rows (bursts, spikes)."""
    return (f"min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq, "
            f"al_mode(list(host)) AS host, al_mode(list(acct)) AS acct, al_mode(list(actor)) AS actor, "
            f"al_mode(list(actor_key)) AS actor_key, al_mode(list(src_user)) AS src_user, "
            f"al_mode(list({target})) AS target_user, al_mode(list(src_ip)) AS src_ip, count(*) AS n, "
            f"min_by(evl, {TIE}, {spec.lines}) AS ev, min_by(source_seq, {TIE}, {spec.keys}) AS keys, "
            f"CAST({spec.sev or 'NULL'} AS INTEGER) AS sev, CAST({spec.label or 'NULL'} AS VARCHAR) AS lbl, "
            f"al_mode(list(api)) AS api, bool_and(coalesce(machine, false)) AS machine")


def match(spec: Spec) -> str:
    return (f"SELECT ts_ms, ts_ms AS last_ts_ms, source_seq, host, acct, actor, actor_key, src_user, "
            f"CAST(lower(CAST({spec.target or 'target_user'} AS VARCHAR)) AS VARCHAR) AS target_user, src_ip, 1 AS n, "
            f"[evl] AS ev, [source_seq] AS keys, CAST({spec.sev or 'NULL'} AS INTEGER) AS sev, "
            f"CAST({spec.label or 'NULL'} AS VARCHAR) AS lbl, api, machine, NULL::BOOLEAN AS baseline_ok "
            f"FROM cloud_ev e WHERE ({spec.filter})")


def _key_cte(spec: Spec, keys: list[str], extra: str = "") -> tuple[str, str, str]:
    """(CTE f over candidate rows with _k0.. columns, partition list, non-null predicate)."""
    ks = ", ".join(f"({k}) AS _k{i}" for i, k in enumerate(keys))
    part = ", ".join(f"_k{i}" for i in range(len(keys)))
    nn = " AND ".join(f"_k{i} IS NOT NULL" for i in range(len(keys)))
    sel = projection(spec, (), spec.sev, spec.label, spec.target, *keys, *(str(v) for v in spec.p.values()))
    return (f"f0 AS (SELECT {sel}, {ks}{extra} FROM cloud_ev WHERE ({spec.filter})), "
            f"f AS (SELECT * FROM f0 WHERE {nn})"), part, nn


def distinct_burst(spec: Spec) -> str:
    """>= min_distinct distinct `distinct` values (and >= min_count rows, and the aggregate `having` SQL) per key inside
    any window_ms window.
    baseline_mult: the burst's distinct count must also be >= mult x the key's p95 per window_ms bucket over
    baseline_days before it; a key with less history than cold_start.min_history_days -> baseline_ok=false, or, with
    require_history: true, no hit at all (a branch whose new keys another branch judges, e.g. new_source_burst)."""
    p = spec.p
    keys = _keys(spec)
    win, nmin, cmin = _int(p["window_ms"]), _int(p.get("min_distinct", 1)), _int(p.get("min_count", 0))
    f, part, _ = _key_cte(spec, keys, f", ({p.get('distinct', 'source_seq')}) AS _d")
    using = ", ".join(f"_k{i}" for i in range(len(keys)))
    mult = float(p.get("baseline_mult") or 0)
    sql = f"""WITH {f},
    cand AS (SELECT {part}, min(ts_ms) AS first_ts FROM f WHERE _d IS NOT NULL GROUP BY ALL
             HAVING count(DISTINCT _d) >= {nmin} AND count(*) >= {cmin}),
    r AS (SELECT {projection(spec, tuple(f'_k{i}' for i in range(len(keys))) + ('_d',), spec.sev, spec.label,
                             spec.target, p.get('having'))}
          FROM f SEMI JOIN cand USING ({using}) WHERE _d IS NOT NULL),
    {window_bursts(part, win, 'count(DISTINCT _d)', f'wv >= {nmin}')},
    b AS (SELECT {part}, bid, {agg_cols(spec)}, count(DISTINCT _d) AS nd FROM mb GROUP BY {part}, bid
          HAVING count(DISTINCT _d) >= {nmin} AND count(*) >= {cmin} AND ({p.get('having') or 'true'}))"""
    if not mult:
        return sql + f"""
    SELECT {', '.join(c for c in HIT_COLUMNS if c != 'baseline_ok')}, NULL::BOOLEAN AS baseline_ok FROM b"""
    bms = int(float(p.get("baseline_days", 14)) * 86_400_000)
    mh = int(float(spec.cold.get("min_history_days", 3)) * 86_400_000)
    on = " AND ".join(f"h._k{i} = b._k{i}" for i in range(len(keys)))
    return sql + f""",
    hb AS (SELECT {part}, ts_ms // {win} AS bk, count(DISTINCT _d) AS c FROM f SEMI JOIN cand USING ({using})
           WHERE _d IS NOT NULL GROUP BY ALL),
    bl AS (SELECT b.{part.replace(', ', ', b.')}, b.bid, quantile_cont(h.c, 0.95) AS p95 FROM b JOIN hb h ON {on}
           AND h.bk * {win} < b.ts_ms - {win} AND h.bk * {win} >= b.ts_ms - {bms} GROUP BY ALL)
    SELECT {', '.join('b.' + c for c in HIT_COLUMNS if c != 'baseline_ok')},
           b.ts_ms - c.first_ts >= {mh} AS baseline_ok
    FROM b LEFT JOIN bl USING ({using}, bid) JOIN cand c USING ({using})
    WHERE b.nd >= {mult} * coalesce(bl.p95, 0){f' AND b.ts_ms - c.first_ts >= {mh}' if p.get('require_history') else ''}"""


def multi_network_session(spec: Spec) -> str:
    """One session key seen from >= min_networks networks (ASN, else /16 or /48 prefix) within window_ms.
    Rows from corporate egress ranges, and (ignore_provider) from cloud-provider ranges, are not counted."""
    p = dict(spec.p)
    flt = f"({spec.filter}) AND ({p.get('network', 'net')}) IS NOT NULL AND NOT corp_ip"
    if p.get("ignore_provider", True):
        flt += " AND provider IS NULL"
    p.update(key=[p.get("session", "session")], distinct=p.get("network", "net"),
             min_distinct=p.get("min_networks", 2))
    return distinct_burst(Spec(**{**spec.__dict__, "filter": flt, "p": p}))


def rate_spike(spec: Spec) -> str:
    """Per key and fixed window_ms bucket: num rows (num SQL) >= min_num, num/all >= min_ratio, distinct `distinct`
    among num rows >= min_distinct, and num > mean + z * max(sigma, sigma_floor) of the key's zero-padded bucket
    counts over baseline_days before it."""
    p = spec.p
    keys = _keys(spec)
    win, nmin = _int(p["window_ms"]), _int(p["min_num"])
    f, part, _ = _key_cte(spec, keys, f", coalesce(({p['num']}), false) AS _num, ({p.get('distinct', 'source_seq')}) AS _d")
    using = ", ".join(f"_k{i}" for i in range(len(keys)))
    nb = max(1, int(float(p.get("baseline_days", 14)) * 86_400_000 // win))
    z, floor = float(p.get("z", 3.0)), float(p.get("sigma_floor", 1.0))
    mh = int(float(spec.cold.get("min_history_days", 3)) * 86_400_000)
    on = " AND ".join(f"a._k{i} = h._k{i}" for i in range(len(keys)))
    return f"""WITH {f},
    cand AS (SELECT {part}, min(ts_ms) AS first_ts FROM f GROUP BY ALL HAVING count(*) FILTER (WHERE _num) >= {nmin}),
    fb AS (SELECT {projection(spec, tuple(f'_k{i}' for i in range(len(keys))) + ('_d', '_num'), spec.sev, spec.label,
                              spec.target)}, ts_ms // {win} AS bk FROM f SEMI JOIN cand USING ({using})),
    cnt AS (SELECT {part}, bk, count(*) FILTER (WHERE _num) AS num, count(*) AS den,
                   count(DISTINCT _d) FILTER (WHERE _num) AS nd FROM fb GROUP BY ALL),
    hit AS (SELECT * FROM cnt WHERE num >= {nmin} AND num >= {float(p.get('min_ratio', 0))} * den
            AND nd >= {_int(p.get('min_distinct', 0))}),
    st AS (SELECT h.{part.replace(', ', ', h.')}, h.bk, coalesce(sum(a.num), 0) AS s1,
                  coalesce(sum(a.num * a.num), 0) AS s2
           FROM hit h LEFT JOIN cnt a ON {on} AND a.bk < h.bk AND a.bk >= h.bk - {nb} GROUP BY ALL),
    zt AS (SELECT st.*, hit.num, greatest(1, least({nb}, hit.bk - c.first_ts // {win})) AS nbk, c.first_ts
           FROM st JOIN hit USING ({using}, bk) JOIN cand c USING ({using})),
    ok AS (SELECT *, s1 / nbk AS mu, greatest(sqrt(greatest(s2 / nbk - (s1 / nbk) * (s1 / nbk), 0)), {floor}) AS sd
           FROM zt),
    sel AS (SELECT {part}, bk, first_ts FROM ok WHERE num > mu + {z} * sd),
    g AS (SELECT {part}, bk, {agg_cols(spec)} FROM fb SEMI JOIN sel USING ({using}, bk) WHERE _num GROUP BY ALL)
    SELECT {', '.join('g.' + c for c in HIT_COLUMNS if c != 'baseline_ok')}, g.ts_ms - sel.first_ts >= {mh} AS baseline_ok
    FROM g JOIN sel USING ({using}, bk)"""


SIDE_ALERTS = "cl_alerts_ev"


def _side(name: str, p: dict[str, Any], joins: list[tuple[str, str]], idx: int) -> str:
    rules = p.get(f"{name}_rules")
    if rules:
        src = SIDE_ALERTS
        flt = "rule_id IN (" + ", ".join("'" + str(r).replace("'", "''") + "'" for r in rules) + ")"
        if p.get(f"{name}_min_severity") is not None:
            flt += f" AND severity >= {_int(p[f'{name}_min_severity'])}"
        if p.get(f"{name}_filter"):
            flt += f" AND ({p[f'{name}_filter']})"
    else:
        src, flt = "cloud_ev", str(p[f"{name}_filter"])
    js = ", ".join(f"({j[idx]}) AS _j{i}" for i, j in enumerate(joins))
    nn = " AND ".join(f"_j{i} IS NOT NULL" for i in range(len(joins)))
    return f"{name} AS (SELECT * FROM (SELECT *, {js} FROM {src} WHERE ({flt})) WHERE {nn})"


def sequence(spec: Spec) -> str:
    """A then B within window_ms, joined on `join` pairs [[a_expr, b_expr], ...] (+ optional pair_where on a./b.).
    A / B are cloud_ev rows (a_filter / b_filter) or earlier cloud alerts (a_rules / b_rules, cl_alerts_ev). One hit
    per (A event, B actor): ts = first B, evidence = A line then B lines, severity = max of the pair SQL."""
    p = spec.p
    joins = [(str(a), str(b)) for a, b in p.get("join") or [("acct", "acct")]]
    win = _int(p["window_ms"])
    on = " AND ".join(f"a._j{i} = b._j{i}" for i in range(len(joins)))
    pw = f" AND ({p['pair_where']})" if p.get("pair_where") else ""
    order = "b.ts_ms >= a.ts_ms" if p.get("order", "a_before_b") == "a_before_b" else "true"
    lines = max(1, spec.lines - 1)
    return f"""WITH {_side('a', p, joins, 0)}, {_side('b', p, joins, 1)},
    pr AS (SELECT b.ts_ms, b.source_seq, b.host, b.acct, b.actor, b.actor_key, b.src_user, b.src_ip, b.api,
                  b.machine, b.evl, a.ts_ms AS a_ts, a.source_seq AS a_seq, a.evl AS a_evl,
                  CAST({spec.target or 'b.target_user'} AS VARCHAR) AS _tgt, CAST({spec.sev or 'NULL'} AS INTEGER) AS _ps,
                  CAST({spec.label or 'NULL'} AS VARCHAR) AS _pl
           FROM a JOIN b ON {on} AND {order} AND abs(b.ts_ms - a.ts_ms) <= {win} AND b.source_seq <> a.source_seq{pw}),
    g AS (SELECT a_seq, coalesce(actor_key, '') AS _ak, any_value(a_evl) AS a_evl, min(ts_ms) AS ts_ms,
                 max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq, al_mode(list(host)) AS host,
                 al_mode(list(acct)) AS acct, al_mode(list(actor)) AS actor, al_mode(list(actor_key)) AS actor_key,
                 al_mode(list(src_user)) AS src_user, al_mode(list(lower(_tgt))) AS target_user,
                 al_mode(list(src_ip)) AS src_ip, count(*) AS n, min_by(evl, {TIE}, {lines}) AS bev,
                 min_by(source_seq, {TIE}, {max(1, spec.keys - 1)}) AS bkeys, max(_ps) AS sev, max(_pl) AS lbl,
                 al_mode(list(api)) AS api, bool_and(coalesce(machine, false)) AS machine
          FROM pr GROUP BY a_seq, coalesce(actor_key, ''))
    SELECT ts_ms, last_ts_ms, source_seq, host, acct, actor, actor_key, src_user, target_user, src_ip,
           n + 1 AS n, list_concat([a_evl], bev) AS ev, list_concat([a_seq], bkeys) AS keys, sev, lbl, api, machine,
           NULL::BOOLEAN AS baseline_ok FROM g"""


TEMPLATES: dict[str, Callable[[Spec], str]] = {
    "match": match,
    "distinct_burst": distinct_burst,
    "multi_network_session": multi_network_session,
    "rate_spike": rate_spike,
    "sequence": sequence,
}
