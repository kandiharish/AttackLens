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


def ok(i: Node, j: Node, rule: str, exempt: frozenset[str]) -> bool:
    return rule == "R1" or j.tactic_idx >= i.tactic_idx or i.tactic in exempt


def best_path(nodes: Iterable[Node], edges: Iterable[Edge], exempt: Iterable[str] = (),
              branch_min_ratio: float = 0.5, max_branches: int = 5,
              standalone: Callable[[list[str]], bool] | None = None, seeds: Iterable[str] = ()) -> PathResult:
    """Node.severity is the node value of the DP (incidents.py passes confidence or severity per config).

    standalone(tail) -> True means the tail is an incident on its own: it is not attached as a branch
    (incidents.py then peels it if it is not directly linked to the path).
    seeds: high-confidence episodes that must never be hidden. Every seed not on the backbone joins as a branch
    (ignoring max_branches / branch_min_ratio / standalone) if its DP chain shares a prefix with what is shown, or
    if it has a link from a shown episode. Seeds with neither are left for incidents.py to peel and re-gate."""
    by_id = {n.id: n for n in nodes}
    if not by_id:
        return PathResult(backbone=[])
    ex = frozenset(exempt)
    preds: dict[str, list[Edge]] = {}
    for e in edges:
        if e.i in by_id and e.j in by_id and by_id[e.i].key < by_id[e.j].key:
            preds.setdefault(e.j, []).append(e)
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
        if tail and len(tail) < len(path) and not (standalone and standalone(tail)):
            branches.append(tail)
            covered.update(tail)
    for s in sorted((x for x in set(seeds) if x in by_id), key=lambda x: by_id[x].key):
        if s in covered:
            continue
        path = trace(s)
        tail = [x for x in path if x not in covered]
        if len(tail) == len(path):  # own chain: hang the seed off its best shown predecessor, if any
            shown = [(score[e.i] + e.weight, by_id[e.i].key, e.i) for e in preds.get(s, ()) if e.i in covered]
            if not shown:
                continue
            back[s], tail = max(shown)[2], [s]
        branches.append(tail)
        covered.update(tail)
    return PathResult(backbone=backbone, branches=branches, scores=score, back=back)
