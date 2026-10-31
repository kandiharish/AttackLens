"""Path DP tests (TESTING.md §4.4, DEVELOPMENT.md §6 Path DP + §15.7 floor_exempt_tactics). Pure Python."""

from __future__ import annotations

import pytest

from attacklens import config
from attacklens.paths import Edge, Node, best_path, ok
from attacklens.schemas import TACTIC_IDX

T0 = 1792807200000
MIN = 60_000
EXEMPT = tuple((config.load_config().get("linking") or {}).get("path", {}).get("floor_exempt_tactics", []))


def n(i: str, k: int, tactic: str, sev: float = 80, seq: int | None = None, ts: int | None = None) -> Node:
    return Node(i, T0 + k * MIN if ts is None else ts, k if seq is None else seq, sev, tactic, TACTIC_IDX[tactic])


def test_config_exempt_tactics_pinned() -> None:
    assert set(EXEMPT) == {"Initial Access", "Credential Access", "Lateral Movement"}  # §15.7


@pytest.mark.parametrize("ti,tj,rule,exempt,expected", [
    ("Execution", "Discovery", "R2", (), True),             # forward tactic
    ("Execution", "Execution", "R2", (), True),             # equal is ok
    ("Discovery", "Execution", "R2", (), False),            # backwards on same host
    ("Discovery", "Execution", "R1", (), True),             # R1 handoff resets the floor
    ("Credential Access", "Initial Access", "R2", (), False),  # literal rule
    ("Credential Access", "Initial Access", "R2", EXEMPT, True),  # §15.7 exempt
    ("Lateral Movement", "Execution", "R3", EXEMPT, True),
    ("Exfiltration", "Execution", "R3", EXEMPT, False),
])
def test_ok(ti: str, tj: str, rule: str, exempt: tuple, expected: bool) -> None:
    assert ok(n("i", 0, ti), n("j", 1, tj), rule, frozenset(exempt)) is expected


def test_linear_chain_score_and_backbone() -> None:
    nodes = [n("a", 0, "Execution", 80), n("b", 1, "Discovery", 50), n("c", 2, "Exfiltration", 85)]
    edges = [Edge("a", "b", "R2", 1.0), Edge("b", "c", "R2", 0.5)]
    r = best_path(nodes, edges)
    assert r.backbone == ["a", "b", "c"]
    assert r.scores == {"a": 80, "b": 50 + 80 + 1.0, "c": 85 + 131.0 + 0.5}
    assert r.back == {"a": None, "b": "a", "c": "b"} and r.branches == []


def test_backwards_tactic_breaks_chain_without_r1() -> None:
    nodes = [n("a", 0, "Discovery", 80), n("b", 1, "Execution", 70)]
    assert best_path(nodes, [Edge("a", "b", "R2", 1.0)]).backbone == ["a"]
    assert best_path(nodes, [Edge("a", "b", "R1", 1.0)]).backbone == ["a", "b"]


def test_s1_like_order_needs_exempt_tactics() -> None:
    nodes = [n("bf", 0, "Credential Access", 75), n("ok", 5, "Initial Access", 85),
             n("lm", 20, "Lateral Movement", 75), n("ex", 24, "Execution", 75), n("out", 65, "Exfiltration", 85)]
    edges = [Edge("bf", "ok", "R2", 1.0), Edge("ok", "lm", "R3", 1.0), Edge("lm", "ex", "R2", 1.0),
             Edge("ex", "out", "R2", 1.0)]
    assert best_path(nodes, edges, EXEMPT).backbone == ["bf", "ok", "lm", "ex", "out"]
    assert best_path(nodes, edges, ()).backbone != ["bf", "ok", "lm", "ex", "out"]  # literal rule cannot


def test_edges_pointing_backwards_in_time_ignored() -> None:
    nodes = [n("a", 0, "Execution"), n("b", 1, "Execution")]
    assert best_path(nodes, [Edge("b", "a", "R2", 5.0)]).back == {"a": None, "b": None}


def test_equal_timestamps_ordered_by_source_seq() -> None:
    a = n("zz", 0, "Execution", seq=1, ts=T0)
    b = n("aa", 0, "Execution", seq=2, ts=T0)
    r = best_path([a, b], [Edge("zz", "aa", "R2", 1.0), Edge("aa", "zz", "R2", 1.0)])
    assert r.backbone == ["zz", "aa"]  # seq 1 precedes seq 2 even though "aa" < "zz"


def test_branch_shares_prefix_and_meets_ratio() -> None:
    nodes = [n("a", 0, "Execution", 80), n("b", 1, "Discovery", 80), n("c", 2, "Collection", 80),
             n("d", 3, "Discovery", 60), n("e", 4, "Discovery", 1)]
    edges = [Edge("a", "b", "R2", 1.0), Edge("b", "c", "R2", 1.0), Edge("a", "d", "R2", 1.0)]
    r = best_path(nodes, edges, branch_min_ratio=0.5)
    top = r.scores["c"]
    assert r.backbone == ["a", "b", "c"] and r.scores["d"] == 141.0 >= 0.5 * top
    assert r.branches == [["d"]]  # e (score 1) is neither linked nor >= 0.5 x max


def test_branch_below_ratio_dropped() -> None:
    nodes = [n("a", 0, "Execution", 80), n("b", 1, "Discovery", 80), n("c", 2, "Collection", 80),
             n("d", 3, "Discovery", 10)]
    edges = [Edge("a", "b", "R2", 1.0), Edge("b", "c", "R2", 1.0), Edge("a", "d", "R2", 1.0)]
    r = best_path(nodes, edges, branch_min_ratio=0.5)
    assert r.scores["d"] == 91.0 < 0.5 * r.scores["c"] and r.branches == []


def test_disjoint_chain_is_not_a_branch() -> None:
    nodes = [n("a", 0, "Execution", 80), n("b", 1, "Discovery", 80), n("x", 2, "Execution", 79),
             n("y", 3, "Discovery", 79)]
    r = best_path(nodes, [Edge("a", "b", "R2", 1.0), Edge("x", "y", "R2", 1.0)])
    assert r.backbone == ["a", "b"] and r.branches == []


def test_max_branches() -> None:
    nodes = [n("a", 0, "Execution", 80)] + [n(f"d{k}", k + 1, "Discovery", 80) for k in range(6)] + \
            [n("z", 9, "Exfiltration", 85)]
    edges = [Edge("a", f"d{k}", "R2", 1.0) for k in range(6)] + [Edge("d0", "z", "R2", 1.0)]
    r = best_path(nodes, edges, branch_min_ratio=0.0, max_branches=2)
    assert r.backbone == ["a", "d0", "z"] and len(r.branches) == 2


def test_empty_component() -> None:
    assert best_path([], []).backbone == []
