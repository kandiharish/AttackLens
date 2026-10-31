"""Reach-next (FR-6, DEVELOPMENT.md §6.7): small AdminTo / MemberOf / CanReach tables built once in DuckDB,
then a BFS of at most `max_hops` in Python from an incident's frontier."""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

from attacklens.context import RunContext
from attacklens.db import register_events
from attacklens.link import sql_path
from attacklens.models import ReachNext
from attacklens.schemas import CANONICAL_COLUMNS

log = logging.getLogger(__name__)

DEFAULT_REACH: dict[str, Any] = {
    "max_hops": 3, "max_results": 20, "ports": [22, 445, 3389, 5985], "admin_logon_types": [3, 10],
    "excluded_logon_ids": ["0x3e7", "0x3e4", "0x3e5"], "ssh_process_names": ["sshd"],
    "admin_groups": ["administrators", "domain admins", "enterprise admins"],
    "domain_admin_groups": ["domain admins", "enterprise admins"], "elevated_tactics": ["Privilege Escalation"],
    "crown_jewels": [{"contains": "dc", "tag": "dc"}, {"contains": "file", "tag": "file"},
                     {"contains": "db", "tag": "db"}, {"contains": "web", "tag": "web"}],
}
FILES = {"admin": "reach_admin.parquet", "flows": "reach_flows.parquet"}


def reach_params(cfg: dict[str, Any]) -> dict[str, Any]:
    return {**DEFAULT_REACH, **((cfg.get("linking") or {}).get("reach") or {})}


@dataclass
class Frontier:
    users: list[str]
    hosts: list[str]
    touched: set[str] = field(default_factory=set)  # every host the incident already touched


@dataclass
class ReachGraph:
    admin: dict[str, list[tuple[str, str]]]          # user -> [(host, evidence)]
    flows: dict[str, list[tuple[str, int, str]]]     # src host -> [(dst host, port, evidence)]


def crown_jewel(host: str, rules: list[dict[str, str]]) -> str | None:
    h = host.lower()
    return next((r["tag"] for r in rules if r.get("contains") and r["contains"] in h), None)


def _lit(values: list[Any]) -> str:
    out = [str(int(v)) if isinstance(v, int) else "'" + str(v).lower().replace("'", "''") + "'" for v in values]
    return ", ".join(out) or "NULL"


def _iso(ms_expr: str) -> str:
    return f"strftime(epoch_ms(CAST({ms_expr} AS BIGINT)), '%Y-%m-%dT%H:%M:%SZ')"


def _events_view(ctx: RunContext) -> str | None:
    """Return a canonical-column SELECT over `events`, or None when no events exist."""
    con = ctx.con
    has_view = con.execute("SELECT count(*) FROM duckdb_views() WHERE view_name = 'events'").fetchone()[0]
    if not has_view:
        if not any(Path(ctx.parquet_dir, "events").rglob("*.parquet")):
            return None
        register_events(con, ctx.events_glob)
    have = {r[0] for r in con.execute("DESCRIBE SELECT * FROM events").fetchall()}
    cols = [f'"{c}"' if c in have else f'NULL::{t} AS "{c}"' for c, t in CANONICAL_COLUMNS.items()
            if c != "raw_line"]
    return f"SELECT {', '.join(cols)} FROM events"


def _ip_map_sql(work: Path) -> str:
    p = work / "host_ip_map.parquet"
    if not p.exists():
        return "SELECT NULL::VARCHAR AS ip, NULL::VARCHAR AS host WHERE FALSE"
    return (f"SELECT ip, arg_max(lower(host), coalesce(last_ms, 0) - coalesce(first_ms, 0)) AS host "
            f"FROM read_parquet('{sql_path(p)}') WHERE ip IS NOT NULL AND host IS NOT NULL GROUP BY ip")


def prepare(ctx: RunContext) -> dict[str, int]:
    """Build work/reach_admin.parquet (user, host, ts_ms, evidence) and work/reach_flows.parquet
    (src_host, dst_host, port, ts_ms, evidence). Filters candidate actions before every join."""
    p, con, work = reach_params(ctx.cfg), ctx.con, ctx.work_dir
    ev = _events_view(ctx)
    admin_out, flows_out = work / FILES["admin"], work / FILES["flows"]
    if ev is None:
        con.execute(f"COPY (SELECT NULL::VARCHAR AS \"user\", NULL::VARCHAR AS host, NULL::BIGINT AS ts_ms, "
                    f"NULL::VARCHAR AS evidence WHERE FALSE) TO '{sql_path(admin_out)}' (FORMAT PARQUET)")
        con.execute(f"COPY (SELECT NULL::VARCHAR AS src_host, NULL::VARCHAR AS dst_host, NULL::INTEGER AS port, "
                    f"NULL::BIGINT AS ts_ms, NULL::VARCHAR AS evidence WHERE FALSE) TO '{sql_path(flows_out)}' "
                    "(FORMAT PARQUET)")
        return {"admin_edges": 0, "flow_edges": 0}
    excl, ltypes = _lit(p["excluded_logon_ids"]), _lit([int(x) for x in p["admin_logon_types"]])
    sshp, groups = _lit(p["ssh_process_names"]), _lit(p["admin_groups"])
    ports = _lit([int(x) for x in p["ports"]])
    not_machine = "NOT coalesce(is_machine, FALSE) AND NOT ends_with(u, '$')"
    con.execute(f"""COPY (
        WITH ev AS ({ev}),
        logons AS (SELECT lower(host) AS host, lower(logon_id) AS lid, logon_type, ts_ms, event_id, is_machine,
                          lower(coalesce(target_user, src_user)) AS u, process_name, dst_port
                   FROM ev WHERE ts_ok AND action = 'login_success' AND host IS NOT NULL),
        privs AS (SELECT DISTINCT lower(host) AS host, lower(logon_id) AS lid FROM ev
                  WHERE ts_ok AND action = 'priv_assigned' AND logon_id IS NOT NULL
                    AND lower(logon_id) NOT IN ({excl})),
        win AS (SELECT l.u, l.host, l.ts_ms, coalesce(l.event_id, 4624)::VARCHAR || ' type '
                       || l.logon_type::VARCHAR || ' + 4672 at ' || {_iso('l.ts_ms')} AS evidence
                FROM logons l JOIN privs p ON l.host = p.host AND l.lid = p.lid
                WHERE l.logon_type IN ({ltypes}) AND l.lid NOT IN ({excl}) AND {not_machine}
                  AND l.u IS NOT NULL),
        ssh AS (SELECT u, host, ts_ms, 'ssh logon at ' || {_iso('ts_ms')} AS evidence FROM logons
                WHERE (lower(process_name) IN ({sshp}) OR dst_port = 22) AND u IS NOT NULL AND {not_machine}),
        grp AS (SELECT lower(target_user) AS u, lower(host) AS host, ts_ms, is_machine,
                       coalesce(event_id, 4732)::VARCHAR || ' added to ' || group_name || ' at '
                       || {_iso('ts_ms')} AS evidence
                FROM ev WHERE ts_ok AND action = 'group_member_added' AND lower(group_name) IN ({groups})
                  AND target_user IS NOT NULL AND host IS NOT NULL),
        grp_ok AS (SELECT u, host, ts_ms, evidence FROM grp WHERE {not_machine}),
        allrows AS (SELECT * FROM win UNION ALL SELECT * FROM ssh UNION ALL SELECT * FROM grp_ok)
        SELECT u AS "user", host, min(ts_ms) AS ts_ms, arg_min(evidence, ts_ms) AS evidence
        FROM allrows GROUP BY u, host ORDER BY u, host) TO '{sql_path(admin_out)}' (FORMAT PARQUET)""")
    con.execute(f"""COPY (
        WITH ev AS ({ev}), ipmap AS ({_ip_map_sql(work)}),
        f AS (SELECT host, src_ip, dst_ip, dst_port, ts_ms, action FROM ev
              WHERE ts_ok AND action IN ('conn_allowed', 'conn_out') AND dst_port IN ({ports}) AND dst_ip IS NOT NULL),
        r AS (SELECT CASE WHEN f.action = 'conn_out' THEN lower(f.host) ELSE coalesce(s.host, lower(f.host)) END
                     AS src_host, d.host AS dst_host, f.dst_ip, f.dst_port AS port, f.ts_ms
              FROM f LEFT JOIN ipmap s ON f.src_ip = s.ip JOIN ipmap d ON f.dst_ip = d.ip)
        SELECT src_host, dst_host, port, min(ts_ms) AS ts_ms,
               arg_min('allowed flow ' || src_host || ' -> ' || dst_ip || ':' || port::VARCHAR || ' at '
                       || {_iso('ts_ms')}, ts_ms) AS evidence
        FROM r WHERE src_host IS NOT NULL AND dst_host IS NOT NULL AND src_host <> dst_host
        GROUP BY src_host, dst_host, port ORDER BY src_host, dst_host, port) TO '{sql_path(flows_out)}'
        (FORMAT PARQUET)""")
    n_a = con.execute(f"SELECT count(*) FROM read_parquet('{sql_path(admin_out)}')").fetchone()[0]
    n_f = con.execute(f"SELECT count(*) FROM read_parquet('{sql_path(flows_out)}')").fetchone()[0]
    return {"admin_edges": int(n_a), "flow_edges": int(n_f)}


def load_graph(ctx: RunContext) -> ReachGraph:
    work = ctx.work_dir
    if not all((work / f).exists() for f in FILES.values()):
        prepare(ctx)
    p = reach_params(ctx.cfg)
    admin: dict[str, list[tuple[str, str]]] = {}
    for u, h, ev in ctx.con.execute(f"SELECT \"user\", host, evidence FROM read_parquet("
                                    f"'{sql_path(work / FILES['admin'])}') ORDER BY 1, 2").fetchall():
        admin.setdefault(u, []).append((h, ev))
    flows: dict[str, list[tuple[str, int, str]]] = {}
    for s, d, port, ev in ctx.con.execute(f"SELECT src_host, dst_host, port, evidence FROM read_parquet("
                                          f"'{sql_path(work / FILES['flows'])}') ORDER BY 1, 2, 3").fetchall():
        flows.setdefault(s, []).append((d, int(port), ev))
    # Domain-admin group membership grants AdminTo on every domain controller seen in the reach tables.
    known = {h for lst in admin.values() for h, _ in lst} | set(flows) | {d for l in flows.values() for d, _, _ in l}
    dcs = sorted(h for h in known if crown_jewel(h, p["crown_jewels"]) == "dc")
    da = [f"added to {g.lower()} at" for g in p.get("domain_admin_groups", [])]
    for lst in admin.values():
        grants = [ev for _, ev in lst if any(m in ev.lower() for m in da)]
        if grants:
            have = {h for h, _ in lst}
            lst.extend((dc, grants[0]) for dc in dcs if dc not in have)
    return ReachGraph(admin=admin, flows=flows)


def compute(ctx: RunContext, frontier: Frontier, graph: ReachGraph | None = None) -> list[ReachNext]:
    """BFS <= max_hops from the frontier. Untouched hosts first, then crown jewels, then hop count."""
    g = graph or load_graph(ctx)
    p = reach_params(ctx.cfg)
    max_hops, start_hosts = int(p["max_hops"]), {h.lower() for h in frontier.hosts if h}
    best: dict[str, tuple[int, str | None, str]] = {}
    q: deque[tuple[str, int, str | None]] = deque((h, 0, None) for h in sorted(start_hosts))
    seen = set(start_hosts)
    for u in sorted({u.lower() for u in frontier.users if u and not u.endswith("$")}):
        for h, ev in g.admin.get(u, []):
            if h not in seen:
                seen.add(h)
                best[h] = (1, u, ev)
                q.append((h, 1, u))
    while q:
        host, hops, via = q.popleft()
        if hops >= max_hops:
            continue
        for d, _port, ev in g.flows.get(host, []):
            if d not in seen:
                seen.add(d)
                best[d] = (hops + 1, via, ev)
                q.append((d, hops + 1, via))
    touched = {t.lower() for t in frontier.touched}
    out = [ReachNext(host=h, hops=hp, via_user=via, evidence=ev[:300], crown_jewel=crown_jewel(h, p["crown_jewels"]),
                     touched=h in touched) for h, (hp, via, ev) in best.items()]
    out.sort(key=lambda r: (r.touched, r.crown_jewel is None, r.hops, r.host))
    return out[: int(p["max_results"])]


def iso_ms(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
