"""QA unit / white-box tests for attacklens.paths.best_path (track qa_coverage_unit).

Baseline coverage showed three branches never ran: a seed with its own chain hung off a shown predecessor whose
edge fails the tactic-order check (paths.py ~l.126), a seed skipped because standalone(tail) is True (~l.128) and a
regular branch rejected by standalone (~l.114). Exact backbone / branches / back pointers, positive + near miss.
"""

from __future__ import annotations

from attacklens.paths import Edge, Node, PathResult, best_path, trim_weak
from attacklens.schemas import TACTIC_IDX


def n(i: str, ts: int, sev: float, tactic: str) -> Node:
    return Node(i, ts, ts, sev, tactic, TACTIC_IDX[tactic])


A = n("A", 1, 10, "Execution")
B = n("B", 2, 10, "Exfiltration")
S = n("S", 3, 5, "Discovery")        # Discovery (10) after Exfiltration (14): tactic order regresses


def test_seed_with_failing_order_edge_hangs_off_shown_pred() -> None:
    edges = [Edge("A", "B", "R2", 1.0), Edge("B", "S", "R2", 1.0)]   # B -> S fails ok(): not R1, not exempt
    r = best_path([A, B, S], edges, exempt=(), seeds=["S"])
    assert r.backbone == ["A", "B"]
    assert r.branches == [["S"]]
    assert r.back["S"] == "B"                                        # rewired to the shown predecessor
    assert r.scores == {"A": 10.0, "B": 21.0, "S": 5.0}              # the DP itself never used B -> S


def test_seed_near_miss_not_a_seed_is_left_out() -> None:
    edges = [Edge("A", "B", "R2", 1.0), Edge("B", "S", "R2", 1.0)]
    r = best_path([A, B, S], edges, exempt=(), seeds=[])
    assert (r.backbone, r.branches, r.back["S"]) == (["A", "B"], [], None)


def test_seed_without_any_shown_link_is_left_out() -> None:
    r = best_path([A, B, S], [Edge("A", "B", "R2", 1.0)], exempt=(), seeds=["S"])
    assert (r.backbone, r.branches) == (["A", "B"], [])               # incidents.py peels and re-gates it


def test_seed_standalone_tail_is_not_attached() -> None:
    edges = [Edge("A", "B", "R2", 1.0), Edge("B", "S", "R2", 1.0)]
    r = best_path([A, B, S], edges, exempt=(), seeds=["S"], standalone=lambda tail: tail == ["S"])
    assert (r.backbone, r.branches) == (["A", "B"], [])


def test_exempt_tactic_makes_regressing_edge_ok() -> None:
    # near miss of the first test: with Exfiltration floor-exempt the DP uses B -> S, S joins the backbone
    edges = [Edge("A", "B", "R2", 1.0), Edge("B", "S", "R2", 1.0)]
    r = best_path([A, B, S], edges, exempt=("Exfiltration",), seeds=["S"])
    assert r.backbone == ["A", "B", "S"] and r.scores["S"] == 27.0


def test_r1_edge_ignores_tactic_order() -> None:
    edges = [Edge("A", "B", "R2", 1.0), Edge("B", "S", "R1", 1.0)]
    assert best_path([A, B, S], edges).backbone == ["A", "B", "S"]


C = n("C", 4, 9, "Exfiltration")


def test_regular_branch_and_standalone_rejection() -> None:
    edges = [Edge("A", "B", "R2", 1.0), Edge("A", "C", "R2", 1.0)]   # scores A 10, B 21, C 20
    r = best_path([A, B, C], edges)
    assert (r.backbone, r.branches) == (["A", "B"], [["C"]])
    r2 = best_path([A, B, C], edges, standalone=lambda tail: True)  # an incident on its own: not a branch
    assert (r2.backbone, r2.branches) == (["A", "B"], [])


def test_branch_ratio_boundary() -> None:
    edges = [Edge("A", "B", "R2", 1.0), Edge("A", "C", "R2", 1.0)]
    # C's own gain past A = 10; backbone gain past A = 11 -> ratio 10/11 = 0.909
    assert best_path([A, B, C], edges, branch_min_ratio=0.9).branches == [["C"]]
    assert best_path([A, B, C], edges, branch_min_ratio=0.95).branches == []


def test_max_branches_zero() -> None:
    edges = [Edge("A", "B", "R2", 1.0), Edge("A", "C", "R2", 1.0)]
    assert best_path([A, B, C], edges, max_branches=0).branches == []


def test_empty_and_dangling_edges() -> None:
    assert best_path([], []) == PathResult(backbone=[])
    r = best_path([A], [Edge("X", "A", "R2", 5.0), Edge("A", "Y", "R2", 5.0)])   # unknown endpoints ignored
    assert (r.backbone, r.scores) == (["A"], {"A": 10.0})


def test_backward_edge_ignored_by_dp() -> None:
    r = best_path([A, B], [Edge("B", "A", "R2", 100.0)])             # j earlier than i: not a predecessor
    assert r.scores == {"A": 10.0, "B": 10.0} and r.back == {"A": None, "B": None}
    assert r.backbone == ["B"]                                       # equal score: the later key wins


def test_trim_weak_runs() -> None:
    assert trim_weak(["w1", "a", "w2", "b", "w3"], frozenset({"w1", "w2", "w3"})) == (["a", "w2", "b"],
                                                                                     [["w1"], ["w3"]])
    assert trim_weak(["w1", "w2"], frozenset({"w1", "w2"})) == (["w1", "w2"], [])   # only weak: unchanged
    assert trim_weak([], frozenset()) == ([], [])
