"""Host-monotonic path DP over one component (DEVELOPMENT.md §6 "Path DP (FR-5)"). Pure Python, no I/O.

S(j) = sev_j + max(0, max_{i in Pred(j), ok(i,j)} S(i) + w_ij)
ok(i,j) <=> rule(i,j) = R1  or  tactic_idx(j) >= tactic_idx(i)  or  tactic(i) in floor_exempt
Nodes are processed in (ts_ms, source_seq, episode_id) order, so every edge points forward (the graph is a DAG).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable


@dataclass(frozen=True)
class Node:
    id: str
    ts_ms: int
    seq: int
    severity: float
    tactic: str
    tactic_idx: int

    @property
    def key(self) -> tuple[int, int, str]:
        return (self.ts_ms, self.seq, self.id)


@dataclass(frozen=True)
class Edge:
    i: str
    j: str
    rule: str
    weight: float


@dataclass
class PathResult:
    backbone: list[str]
    branches: list[list[str]] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    back: dict[str, str | None] = field(default_factory=dict)  # DP predecessor of each node
    lead_in: list[str] = field(default_factory=list)  # lead-in seed branches (shown, but never gate donors)


def ok(i: Node, j: Node, rule: str, exempt: frozenset[str]) -> bool:
    return rule == "R1" or j.tactic_idx >= i.tactic_idx or i.tactic in exempt


def best_path(nodes: Iterable[Node], edges: Iterable[Edge], exempt: Iterable[str] = (),
              branch_min_ratio: float = 0.5, max_branches: int = 5,
              standalone: Callable[[list[str]], bool] | None = None, seeds: Iterable[str] = (),
              weak: Iterable[str] = (), lead_in_rules: Iterable[str] = ()) -> PathResult:
    """Node.severity is the node value of the DP (incidents.py passes confidence or severity per config).

    standalone(tail) -> True means the tail is an incident on its own: it is not attached as a branch
    (incidents.py then peels it if it is not directly linked to the path).
    seeds: high-confidence episodes that must never be hidden. Every seed not on the backbone joins as a branch
    (ignoring max_branches / branch_min_ratio / standalone) if its DP chain shares a prefix with what is shown, or
    if it has a link from (else, by a lead_in_rules rule, to) a shown episode. Seeds with none are left for
    incidents.py to peel and re-gate.
    weak: low-confidence episodes that may bridge two backbone steps but never start or end the backbone. Leading /
    trailing weak runs of the backbone move to branches (head run first, then tail run), so they stay shown and
    accounted; a backbone made only of weak steps is left as is."""
    by_id = {n.id: n for n in nodes}
    if not by_id:
        return PathResult(backbone=[])
    ex = frozenset(exempt)
    seed_set = frozenset(seeds)
    preds: dict[str, list[Edge]] = {}
    lead_rules = frozenset(lead_in_rules)
    succs: dict[str, set[str]] = {}  # successors by a lead_in_rules link
    for e in edges:
        if e.i in by_id and e.j in by_id and by_id[e.i].key < by_id[e.j].key:
            preds.setdefault(e.j, []).append(e)
            if e.rule in lead_rules:
                succs.setdefault(e.i, set()).add(e.j)
    order = sorted(by_id.values(), key=lambda n: n.key)
    score: dict[str, float] = {}
    back: dict[str, str | None] = {}
    for n in order:
        # Tie-break on equal value: the later predecessor (closest in time); keys are unique, so deterministic.
        cands = [(score[e.i] + e.weight, by_id[e.i].key, e.i) for e in preds.get(n.id, ())
                 if ok(by_id[e.i], n, e.rule, ex)]
        best = max(cands) if cands else None
        if best is not None and best[0] > 0.0:
            score[n.id], back[n.id] = n.severity + best[0], best[2]
        else:
            score[n.id], back[n.id] = n.severity, None

    def trace(end: str) -> list[str]:
        out: list[str] = []
        cur: str | None = end
        while cur is not None:
            out.append(cur)
            cur = back[cur]
        return out[::-1]

    end = max(order, key=lambda n: (score[n.id], n.key)).id
    backbone = trace(end)
    covered = set(backbone)
    used_as_pred = {p for p in back.values() if p is not None}
    top = score[end]
    branches: list[list[str]] = []
    for n in sorted(order, key=lambda n: (-score[n.id], n.key)):
        if len(branches) >= max_branches or score[n.id] < branch_min_ratio * top:
            break
        if n.id in covered or n.id in used_as_pred:
            continue
        path = trace(n.id)
        tail = [x for x in path if x not in covered]
        # A branch must diverge from the backbone (or an earlier branch): it shares a prefix with what is shown.
        # Disjoint chains are not branches; incidents.py peels them into their own sub-component.
        if not tail or len(tail) == len(path):
            continue
        # Strength = the tail's own gain past the divergence point, not the shared prefix: a noise singleton
        # hanging off a strong backbone step would otherwise always qualify. Seed ends are handled below.
        s_div = score[path[len(path) - len(tail) - 1]]
        if score[n.id] - s_div < branch_min_ratio * (top - s_div) and n.id not in seed_set:
            continue
        if not (standalone and standalone(tail)):
            branches.append(tail)
            covered.update(tail)
    lead_in: list[str] = []
    for s in sorted((x for x in seed_set if x in by_id), key=lambda x: by_id[x].key):
        if s in covered:
            continue
        path = trace(s)
        tail = [x for x in path if x not in covered]
        if len(tail) == len(path):  # own chain: hang the seed off its best shown predecessor, if any
            shown = [(score[e.i] + e.weight, by_id[e.i].key, e.i) for e in preds.get(s, ()) if e.i in covered]
            if not shown:
                lead_in.append(s)
                continue
            back[s], tail = max(shown)[2], [s]
        if standalone and standalone(tail):
            continue  # an incident on its own: left for incidents.py to peel and re-gate (still accounted)
        branches.append(tail)
        covered.update(tail)
    # Lead-in seeds: no shown predecessor, but a link INTO a step shown above, whose DP slot a heavier (weak) chain
    # took (cloud_small A5). Shown alone, DP predecessor dropped (incidents.py draws the link out). Checked against
    # the set shown before this pass, so a lead-in never becomes the shown predecessor that pulls in another seed.
    shown_before = frozenset(covered)
    joined = [s for s in lead_in if succs.get(s, set()) & shown_before and not (standalone and standalone([s]))]
    for s in joined:
        back[s] = None
        branches.append([s])
    backbone, ends = trim_weak(backbone, frozenset(weak))
    return PathResult(backbone=backbone, branches=branches + ends, scores=score, back=back, lead_in=joined)


def trim_weak(backbone: list[str], weak: frozenset[str]) -> tuple[list[str], list[list[str]]]:
    """Split leading / trailing weak runs off the backbone: (core, [head run, tail run] without empties)."""
    lo, hi = 0, len(backbone)
    while lo < hi and backbone[lo] in weak:
        lo += 1
    while hi > lo and backbone[hi - 1] in weak:
        hi -= 1
    if lo == hi:
        return backbone, []
    return backbone[lo:hi], [run for run in (backbone[:lo], backbone[hi:]) if run]
