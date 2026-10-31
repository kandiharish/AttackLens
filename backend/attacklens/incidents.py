"""Stage 4: components -> gate -> risk -> path DP -> gaps -> reach-next -> work/incidents.json (DEVELOPMENT.md §4, §6)."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import networkx as nx

from attacklens import reach
from attacklens.context import RunContext
from attacklens.incident_gate import (_params, _round, allowlist_entities, burst, entities, gate,  # noqa: F401
                                      risk_score, tactic_idx)
from attacklens.link import episode_select, sql_path
from attacklens.models import (EntryPoint, Graph, GraphEdge, GraphNode, Incident, Narrative, PathEdge, Step,
                               dump)
from attacklens.paths import Edge, Node, best_path
from attacklens.schemas import TACTIC_IDX, TACTICS_V20

log = logging.getLogger(__name__)

LIGHT_COLS = ["episode_id", "rule_id", "technique_id", "sub_technique_id", "technique_name", "tactic", "tactic_idx",
              "severity", "ts_ms", "last_ts_ms", "source_seq", "host", "subject_host", "src_host", "dst_host",
              "src_user", "target_user", "src_ip", "dst_ip", "merged_alert_count", "user", "confidence"]


@dataclass
class Comp:
    ids: list[str]
    backbone: list[str]
    branches: list[list[str]]
    back: dict[str, str | None]


def iso(ms: int | None) -> str:
    return reach.iso_ms(int(ms or 0))


def _load(ctx: RunContext) -> tuple[dict[str, dict[str, Any]], list[tuple[str, str, str, float, int, str]]]:
    work, con = ctx.work_dir, ctx.con
    ep_path, ed_path = work / "episodes.parquet", work / "edges.parquet"
    if not ep_path.exists():
        return {}, []
    cols = ", ".join(f'"{c}"' for c in LIGHT_COLS)
    rows = con.execute(f"SELECT {cols} FROM ({episode_select(con, ep_path)}) WHERE episode_id IS NOT NULL "
                       "AND ts_ms IS NOT NULL ORDER BY episode_id").fetchall()
    eps = {r[0]: dict(zip(LIGHT_COLS, r)) for r in rows}
    edges = []
    if ed_path.exists():
        edges = con.execute(f"SELECT i, j, rule, weight, dt_ms, why_linked FROM read_parquet('{sql_path(ed_path)}') "
                            "ORDER BY i, j").fetchall()
    return eps, edges


def _evidence(ctx: RunContext, ids: set[str], p: dict[str, Any]) -> dict[str, list[str]]:
    if not ids:
        return {}
    ctx.con.execute("CREATE OR REPLACE TEMP TABLE _ev_ids (id VARCHAR)")
    ctx.con.executemany("INSERT INTO _ev_ids VALUES (?)", [(i,) for i in sorted(ids)])
    src = episode_select(ctx.con, ctx.work_dir / "episodes.parquet")
    rows = ctx.con.execute(f"SELECT e.episode_id, e.evidence_lines FROM ({src}) e "
                           "JOIN _ev_ids x ON e.episode_id = x.id").fetchall()
    ctx.con.execute("DROP TABLE IF EXISTS _ev_ids")
    return {i: [clip(str(x), p["ev_chars"]) for x in (lines or [])[: p["ev_lines"]]] for i, lines in rows}


def clip(text: str, n: int) -> str:
    """At most n characters; a cut line ends with an ellipsis so the reader knows it was truncated."""
    return text if len(text) <= n else text[: max(0, n - 1)] + "…"


def _tech_name(cfg: dict[str, Any], e: dict[str, Any]) -> str | None:
    if e.get("technique_name"):
        return str(e["technique_name"])
    att = cfg.get("attack") or {}
    techs = att.get("techniques", att) if isinstance(att, dict) else {}
    t = techs.get(e.get("sub_technique_id") or "") or techs.get(e.get("technique_id") or "")
    return str(t.get("name")) if isinstance(t, dict) and t.get("name") else None


def _step(k: int, e: dict[str, Any], ev: list[str], cfg: dict[str, Any]) -> Step:
    return Step(step=k, episode_id=e["episode_id"], ts=iso(e["ts_ms"]),
                technique_id=e.get("technique_id") or e.get("rule_id") or "unknown",
                sub_technique_id=e.get("sub_technique_id"), technique_name=_tech_name(cfg, e),
                tactic=e.get("tactic") or "unknown", rule_id=e.get("rule_id"),
                host=e.get("subject_host") or e.get("host"), user=e.get("user"), src_ip=e.get("src_ip"),
                dst_ip=e.get("dst_ip"), severity=int(e.get("severity") or 0),
                confidence=_round(float(e.get("confidence") or 0)),
                merged_alert_count=int(e.get("merged_alert_count") or 0), evidence=ev)


def entry_summary(s: Step) -> str:
    out = s.technique_name or s.technique_id
    out += f" on user:{s.user}" if s.user else ""
    out += f" from ip:{s.src_ip}" if s.src_ip else ""
    return out + (f" against host:{s.host}" if s.host else "")


def build_graph(steps: list[Step], eps: dict[str, dict[str, Any]], compromised: set[str],
                reach_hosts: list[str]) -> Graph:
    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str], GraphEdge] = {}

    def node(typ: str, val: str | None) -> str | None:
        if not val:
            return None
        nid = f"{typ}:{str(val).lower()}"
        if nid not in nodes:
            label = str(val).upper() if typ == "host" else str(val)
            nodes[nid] = GraphNode(id=nid, type=typ, label=label, compromised=nid in compromised)  # type: ignore[arg-type]
        return nid

    for s in steps:
        e = eps[s.episode_id]
        h = node("host", s.host)
        u = node("user", s.user)
        src = node("host", e.get("src_host")) if e.get("src_host") else node("ip", e.get("src_ip"))
        dst = node("host", e.get("dst_host")) if e.get("dst_host") else node("ip", e.get("dst_ip"))
        pair = ((h, dst) if dst and dst != h else (src, h) if src and src != h else (u, h))
        if pair[0] and pair[1] and pair not in edges:
            edges[pair] = GraphEdge(source=pair[0], target=pair[1], label=s.technique_id, step=s.step)
    for rh in reach_hosts:
        node("host", rh)
    return Graph(nodes=sorted(nodes.values(), key=lambda n: n.id), edges=list(edges.values()))


def _frontier(bb: list[dict[str, Any]], comp_eps: list[dict[str, Any]], p: dict[str, Any]) -> reach.Frontier:
    last = bb[-2:]
    users = {e.get("user") for e in last} | {e.get("target_user") for e in bb if e.get("tactic") in p["elevated"]}
    hosts = {e.get("subject_host") or e.get("host") for e in last}
    touched = {str(e[c]).lower() for e in comp_eps for c in ("subject_host", "src_host", "dst_host", "host")
               if e.get(c)}
    return reach.Frontier(users=sorted(u for u in users if u), hosts=sorted(h for h in hosts if h), touched=touched)


def _path_edge(edge_map: dict[tuple[str, str], tuple], i: str, j: str, label: dict[str, int]) -> PathEdge | None:
    rec = edge_map.get((i, j))
    if rec is None:
        return None
    rule, w, why = rec[2], float(rec[3]), str(rec[5])
    if rule == "R3" and i in label and j in label:
        # User-facing step numbers are 1-based (Step.step stays 0-based per the contract).
        why = why.replace(f"step {i}", f"step {label[i] + 1}").replace(f"step {j}", f"step {label[j] + 1}")
    return PathEdge(**{"from": i, "to": j, "rule": rule, "weight": round(w, 3), "why_linked": why})


def build_incident(ctx: RunContext, c: Comp, eps: dict[str, dict[str, Any]], edge_map: dict[tuple[str, str], tuple],
                   ev: dict[str, list[str]], p: dict[str, Any], rg: reach.ReachGraph) -> tuple[Incident, float]:
    bb = [eps[x] for x in c.backbone]
    br = [[eps[x] for x in b] for b in c.branches]
    path_eps = bb + [e for b in br for e in b]
    comp_eps = [eps[x] for x in c.ids]
    steps = [_step(k, e, ev.get(e["episode_id"], []), ctx.cfg) for k, e in enumerate(bb)]
    nxt, branches = len(steps), []
    for b in br:
        branches.append([_step(nxt + k, e, ev.get(e["episode_id"], []), ctx.cfg) for k, e in enumerate(b)])
        nxt += len(b)
    label = {s.episode_id: s.step for s in steps + [x for b in branches for x in b]}
    back: list[tuple[str, str]] = list(zip(c.backbone, c.backbone[1:]))
    for b in c.branches:
        # A branch hangs off the DP predecessor of its first node (on the backbone or an earlier branch).
        first_pred = c.back.get(b[0])
        back += ([(first_pred, b[0])] if first_pred else []) + list(zip(b, b[1:]))
    pedges = [pe for i, j in back if (pe := _path_edge(edge_map, i, j, label)) is not None]
    risk, raw = risk_score(path_eps, p)
    path_tactics = sorted({e.get("tactic") for e in path_eps if e.get("tactic")}, key=lambda t: TACTIC_IDX.get(t, 99))
    comp_tactics = {e.get("tactic") for e in comp_eps}
    idxs = [tactic_idx(e) for e in bb if tactic_idx(e) > 0]
    gaps = [t for t in TACTICS_V20 if idxs and min(idxs) < TACTIC_IDX[t] < max(idxs) and t not in comp_tactics]
    reach_next = reach.compute(ctx, _frontier(bb, comp_eps, p), rg)
    compromised = {f"host:{str(s.host).lower()}" for s in steps if s.host} | \
                  {f"user:{str(s.user).lower()}" for s in steps if s.user}
    graph = build_graph(steps + [s for b in branches for s in b], eps, compromised, [r.host for r in reach_next])
    inc = Incident(
        id="inc-" + hashlib.sha1(",".join(sorted(c.ids)).encode("utf-8")).hexdigest()[:8], risk=risk,
        first_ts=iso(min(e["ts_ms"] for e in path_eps)),
        last_ts=iso(max(int(e.get("last_ts_ms") or e["ts_ms"]) for e in path_eps)),
        merged_alert_count=sum(int(e.get("merged_alert_count") or 0) for e in comp_eps), episode_count=len(c.ids),
        entry_point=EntryPoint(step=0, summary=entry_summary(steps[0])), tactics=path_tactics, gaps=gaps,
        backbone=steps, branches=branches, edges=pedges, graph=graph, reach_next=reach_next,
        narrative=Narrative(text="", source="template"))
    return Incident.model_validate(dump(inc)), raw


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(obj, ensure_ascii=False, indent=1))


def _gate_ids(ids: list[str], eps: dict[str, dict[str, Any]], allow: set[str],
              p: dict[str, Any]) -> tuple[str | None, set[str], float]:
    ce = [eps[x] for x in ids]
    # Tactic diversity counts only episodes with at least min_tactic_confidence (0 = literal §6.3 gate).
    tactics = {e["tactic"] for e in ce if e.get("tactic") and float(e.get("confidence") or 0) >= p["tactic_conf"]}
    top = max(ce, key=lambda e: (float(e.get("confidence") or 0), int(e.get("merged_alert_count") or 0)))
    max_conf = float(top.get("confidence") or 0)
    allowlisted = bool(allow) and all(entities(e) <= allow for e in ce)
    reason = gate(tactics, max_conf, allowlisted, p, int(top.get("merged_alert_count") or 0), burst(ce, p))
    return reason, tactics, max_conf


def _extract(ids: list[str], eps: dict[str, dict[str, Any]], by_j: dict[str, list[Edge]], g: nx.Graph,
             p: dict[str, Any]) -> tuple[Comp, set[str]]:
    """Path DP on one (sub)component. Members = path + non-seed episodes directly linked to it; returns
    (comp, remainder). A seed is either shown (backbone / branch) or left in the remainder to be re-gated."""
    sid = set(ids)
    val = "confidence" if p["node_score"] == "confidence" else "severity"
    nodes = [Node(x, int(eps[x]["ts_ms"]), int(eps[x].get("source_seq") or 0), float(eps[x].get(val) or 0),
                  eps[x].get("tactic") or "", tactic_idx(eps[x])) for x in ids]
    seeds = {x for x in ids if float(eps[x].get("confidence") or 0) >= p["seed"]}
    cedges = [e for x in ids for e in by_j.get(x, []) if e.i in sid]
    standalone = None
    if p["peel_tails"]:
        def standalone(tail: list[str]) -> bool:  # multi-tactic tail that passes the gate by itself
            reason, tactics, _ = _gate_ids(tail, eps, set(), p)
            return reason is None and len(tactics) >= p["min_tactics"]
    res = best_path(nodes, cedges, p["exempt"], p["branch_ratio"], p["max_branches"], standalone, seeds)
    path = set(res.backbone) | {x for b in res.branches for x in b}
    members = path | {n for x in path for n in g.neighbors(x) if n in sid and n not in seeds}
    return Comp(ids=sorted(members), backbone=res.backbone, branches=res.branches, back=res.back), sid - members


def episode_accounting(eps: dict[str, Any], kept: list[list[str]], suppressed: list[list[str]]) -> dict[str, Any]:
    """Invariant: every episode is in exactly one kept incident or one suppressed entry (no silent loss)."""
    n_kept, n_sup = sum(map(len, kept)), sum(map(len, suppressed))
    seen = [x for ids in kept + suppressed for x in ids]
    out = {"episodes": len(eps), "in_incidents": n_kept, "in_suppressed": n_sup,
           "missing": len(set(eps) - set(seen)), "duplicated": len(seen) - len(set(seen))}
    out["ok"] = out["missing"] == 0 and out["duplicated"] == 0 and n_kept + n_sup == len(eps)
    if not out["ok"]:
        log.error("incidents: episode accounting invariant violated: %s", out)
    return out


def run(ctx: RunContext) -> dict[str, Any]:
    t0 = time.perf_counter()
    p = _params(ctx.cfg)
    eps, edges = _load(ctx)
    g = nx.Graph()
    g.add_nodes_from(sorted(eps))
    g.add_edges_from((i, j) for i, j, *_ in edges if i in eps and j in eps)
    comps = sorted((sorted(cc) for cc in nx.connected_components(g)), key=lambda cc: cc[0])
    allow = allowlist_entities(ctx.cfg)
    edge_map = {(r[0], r[1]): r for r in edges}
    by_j: dict[str, list[Edge]] = {}
    for i, j, rule, w, *_ in edges:
        by_j.setdefault(j, []).append(Edge(i, j, rule, float(w)))
    kept: list[Comp] = []
    sup_all: list[list[str]] = []  # full id lists of suppressed entries (suppressed.json keeps only sup_ids)
    suppressed: list[dict[str, Any]] = []
    reasons: dict[str, int] = {}
    peeled = 0
    for comp in comps:
        queue, n_out = [comp], 0
        while queue:
            ids = queue.pop(0)
            reason, tactics, max_conf = _gate_ids(ids, eps, allow, p)
            if reason is None and n_out >= p["max_per_comp"]:
                reason = f"more than {p['max_per_comp']} incidents peeled from one component"
            if reason is not None:
                named = reason.startswith(("allow", "fewer", "more", "critical"))
                key = reason.split(" and ")[0].split(":")[0] if named else "low confidence"
                reasons[key] = reasons.get(key, 0) + 1
                sup_all.append(ids)
                suppressed.append({"episode_ids": ids[: p["sup_ids"]], "episode_count": len(ids),
                                   "tactics": sorted(tactics, key=lambda t: TACTIC_IDX.get(t, 99)),
                                   "max_confidence": round(max_conf, 1), "reason": reason})
                continue
            c, rest = _extract(ids, eps, by_j, g, p)
            # Re-gate the extracted incident (path + direct neighbours): it can fail even when its component passed.
            c_reason, c_tactics, c_conf = _gate_ids(c.ids, eps, allow, p)
            if c_reason is None:
                kept.append(c)
                n_out += 1
            else:
                reasons["extracted path fails gate"] = reasons.get("extracted path fails gate", 0) + 1
                sup_all.append(c.ids)
                suppressed.append({"episode_ids": c.ids[: p["sup_ids"]], "episode_count": len(c.ids),
                                   "tactics": sorted(c_tactics, key=lambda t: TACTIC_IDX.get(t, 99)),
                                   "max_confidence": round(c_conf, 1),
                                   "reason": f"extracted path fails gate: {c_reason}"})
            if rest:
                # Peel: the remainder may hold another attack that a noise chain had merged in. Re-split, re-gate.
                subs = sorted((sorted(cc) for cc in nx.connected_components(g.subgraph(rest))), key=lambda cc: cc[0])
                peeled += len(subs)
                queue.extend(subs)
    accounting = episode_accounting(eps, [c.ids for c in kept], sup_all)
    no_burst = {**p, "burst_techniques": 0}
    via_burst = sum(_gate_ids(c.ids, eps, allow, no_burst)[0] is not None for c in kept)
    ev = _evidence(ctx, {x for c in kept for x in c.backbone + [y for b in c.branches for y in b]}, p)
    reach_stats = reach.prepare(ctx)
    rg = reach.load_graph(ctx)
    incidents, raws = [], {}
    for c in kept:
        inc, raw = build_incident(ctx, c, eps, edge_map, ev, p, rg)
        incidents.append(inc)
        raws[inc.id] = round(raw, 3)
    incidents.sort(key=lambda x: (-x.risk, x.first_ts, x.id))
    _write_json(ctx.work_dir / "incidents.json", [dump(i) for i in incidents])
    suppressed.sort(key=lambda s: (-s["max_confidence"], s["episode_ids"][0]))
    _write_json(ctx.out_dir / "suppressed.json", {"total": len(suppressed), "by_reason": dict(sorted(reasons.items())),
                                                  "components": suppressed[: p["sup_max"]]})
    stats = {"episode_accounting": accounting, "kept_via_burst": via_burst, "components": len(comps),
             "peeled_subcomponents": peeled, "kept": len(kept), "suppressed": len(suppressed),
             "incidents": len(incidents), "suppressed_by_reason": dict(sorted(reasons.items())),
             "largest_component": max(map(len, comps), default=0), "raw_risk": raws, "reach": reach_stats,
             "seconds": round(time.perf_counter() - t0, 3)}
    log.info("incidents: %s", {k: v for k, v in stats.items() if k != "raw_risk"})
    return stats
