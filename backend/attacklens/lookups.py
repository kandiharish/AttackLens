"""Stage 1b — lookups (DEVELOPMENT.md §4): host_ip_map and background_hubs.

host_ip_map(ip, host, first_ms, last_ms): each host's own reporting IP (host_ip) over time. Loopback, '::1', '-'
and empty values are excluded. (Logon source IPs carry no host name in the canonical schema, so they cannot
name a host; they are resolved against this map instead.)

background_hubs(entity): entities whose median daily distinct peers (over every event day, zero-padded) exceeds
thresholds.hub_min_median_daily_peers. Peers come from logon actions (user = coalesce(target_user, src_user)):
  user:<u> -> distinct hosts, host:<h> -> distinct users, ip:<src_ip> -> distinct hosts;
and from network actions: ip:<dst_ip> -> distinct sources (src_ip or reporting host).
"""

from __future__ import annotations

import logging
from typing import Any

from attacklens.context import RunContext
from attacklens.detect_sql import LOGON_ACTIONS, NET_ACTIONS, OK, ensure_events, register_macros, sql_list

log = logging.getLogger(__name__)


def host_ip_map_sql() -> str:
    return f"""
    SELECT host_ip AS ip, host, min(ts_ms) AS first_ms, max(ts_ms) AS last_ms
    FROM events
    WHERE {OK} AND host IS NOT NULL AND ts_ms IS NOT NULL AND NOT al_is_loopback(host_ip)
    GROUP BY host_ip, host
    """


def background_hubs_sql(min_peers: float) -> str:
    logon = sql_list(list(LOGON_ACTIONS))
    net = sql_list(list(NET_ACTIONS))
    return f"""
    WITH lg AS (
        SELECT ts_ms // 86400000 AS d, host, coalesce(target_user, src_user) AS u, src_ip
        FROM events WHERE {OK} AND action IN {logon} AND host IS NOT NULL
    ),
    nt AS (
        SELECT ts_ms // 86400000 AS d, dst_ip, coalesce(src_ip, host) AS peer
        FROM events WHERE {OK} AND action IN {net} AND dst_ip IS NOT NULL AND NOT al_is_loopback(dst_ip)
    ),
    daily AS (
        SELECT 'user:' || u AS entity, d, count(DISTINCT host) AS peers FROM lg WHERE u IS NOT NULL GROUP BY ALL
        UNION ALL
        SELECT 'host:' || host, d, count(DISTINCT u) FROM lg WHERE u IS NOT NULL GROUP BY ALL
        UNION ALL
        SELECT 'ip:' || src_ip, d, count(DISTINCT host) FROM lg WHERE NOT al_is_loopback(src_ip) GROUP BY ALL
        UNION ALL
        SELECT 'ip:' || dst_ip, d, count(DISTINCT peer) FROM nt GROUP BY ALL
    ),
    nd AS (SELECT greatest(count(DISTINCT ts_ms // 86400000), 1) AS n FROM events WHERE {OK} AND ts_ms IS NOT NULL),
    med AS (
        SELECT entity,
               list_aggregate(list_concat(list(peers::DOUBLE),
                                          list_resize([]::DOUBLE[], greatest(any_value(nd.n) - count(*), 0), 0.0)),
                              'median') AS median_peers
        FROM daily, nd GROUP BY entity
    )
    SELECT entity, median_peers FROM med WHERE median_peers > {float(min_peers)}
    """


def run(ctx: RunContext) -> dict[str, Any]:
    con = ctx.con
    ensure_events(con, ctx.events_glob)
    register_macros(con)
    th = (ctx.cfg.get("rules") or {}).get("thresholds") or {}
    min_peers = float(th.get("hub_min_median_daily_peers", 20))
    work = ctx.work_dir
    hip = (work / "host_ip_map.parquet").as_posix()
    hubs = (work / "background_hubs.parquet").as_posix()
    con.execute(f"COPY ({host_ip_map_sql()}) TO '{hip}' (FORMAT PARQUET)")
    con.execute(f"COPY ({background_hubs_sql(min_peers)}) TO '{hubs}' (FORMAT PARQUET)")
    n_map = con.execute(f"SELECT count(*) FROM read_parquet('{hip}')").fetchone()[0]
    n_hubs = con.execute(f"SELECT count(*) FROM read_parquet('{hubs}')").fetchone()[0]
    log.info("lookups: host_ip_map=%d rows, background_hubs=%d (min median daily peers > %s)",
             n_map, n_hubs, min_peers)
    return {"host_ip_map": int(n_map), "background_hubs": int(n_hubs)}
