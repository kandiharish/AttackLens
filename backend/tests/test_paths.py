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


def _branch_case(d_sev: float) -> tuple[list[Node], list[Edge]]:
    nodes = [n("a", 0, "Execution", 80), n("b", 1, "Discovery", 80), n("c", 2, "Collection", 80),
             n("d", 3, "Discovery", d_sev), n("e", 4, "Discovery", 1)]
    return nodes, [Edge("a", "b", "R2", 1.0), Edge("b", "c", "R2", 1.0), Edge("a", "d", "R2", 1.0)]


def test_branch_gain_is_measured_past_the_divergence() -> None:
    # S(a)=80, top S(c)=242. d=60: S(d)=141, own gain 141-80=61 < 0.5*(242-80)=81 -> no branch, although
    # S(d) >= 0.5*top (the old rule): its score comes from the shared prefix a.
    nodes, edges = _branch_case(60)
    r = best_path(nodes, edges, branch_min_ratio=0.5)
    assert r.backbone == ["a", "b", "c"] and r.scores["d"] == 141.0 and r.scores["d"] >= 0.5 * r.scores["c"]
    assert r.branches == []


def test_branch_with_enough_own_gain_qualifies() -> None:
    nodes, edges = _branch_case(100)  # gain 181-80 = 101 >= 81
    assert best_path(nodes, edges, branch_min_ratio=0.5).branches == [["d"]]


def test_seed_branch_exempt_from_gain_rule() -> None:
    nodes, edges = _branch_case(60)
    r = best_path(nodes, edges, branch_min_ratio=0.5, seeds={"d"})
    assert r.branches == [["d"]]  # seed ends are always shown; e (unlinked, score 1) never is


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



# ================================================================ seeds are never hidden (best_path seeds=)
def test_seed_off_backbone_with_link_from_shown_becomes_branch() -> None:
    # backbone a->b->c; seed s has its own (weaker) chain from x but a link from shown b -> it hangs off b
    nodes = [n("a", 0, "Execution", 80), n("b", 1, "Discovery", 80), n("c", 2, "Collection", 80),
             n("x", 3, "Execution", 5), n("s", 4, "Persistence", 70)]
    edges = [Edge("a", "b", "R2", 1.0), Edge("b", "c", "R2", 1.0), Edge("x", "s", "R2", 1.0), Edge("b", "s", "R1", 0.1)]
    r = best_path(nodes, edges, EXEMPT, branch_min_ratio=0.99, max_branches=0, seeds={"s"})
    assert r.backbone == ["a", "b", "c"]
    assert ["s"] in r.branches  # shown despite branch_min_ratio / max_branches


def test_seed_without_any_link_to_shown_is_left_for_peeling() -> None:
    nodes = [n("a", 0, "Execution", 80), n("b", 1, "Discovery", 80), n("s", 2, "Persistence", 70)]
    r = best_path(nodes, [Edge("a", "b", "R2", 1.0)], EXEMPT, seeds={"s"})
    assert r.backbone == ["a", "b"] and r.branches == []


def test_lead_in_seed_linking_into_shown_becomes_branch() -> None:
    # cloud_small A5: a weak floor-exempt Initial Access chain (w1..w4) out-scores the seed s (Persistence 80) as b's
    # DP predecessor; s's own chain (x -> s) has no shown step, but s links INTO shown b -> s is still shown.
    nodes = [n("x", 0, "Persistence", 60), n("s", 1, "Persistence", 80), n("w1", 2, "Initial Access", 51),
             n("w2", 3, "Initial Access", 30), n("w3", 4, "Initial Access", 51), n("w4", 5, "Initial Access", 26),
             n("b", 6, "Privilege Escalation", 75), n("c", 7, "Defense Impairment", 85)]
    edges = [Edge("x", "s", "R3", 1.07), Edge("s", "w1", "R2", 0.86), Edge("w1", "w2", "R2", 1.0),
             Edge("w2", "w3", "R2", 0.81), Edge("w3", "w4", "R2", 0.86), Edge("w4", "b", "R2", 1.0),
             Edge("s", "b", "R3", 1.3), Edge("b", "c", "R3", 1.3)]
    lead = ("R1", "R2", "R3")
    r = best_path(nodes, edges, EXEMPT, seeds={"s", "b", "c"}, weak={"w2", "w4"}, lead_in_rules=lead)
    assert r.backbone == ["w1", "w2", "w3", "w4", "b", "c"]
    assert ["s"] in r.branches and r.back["s"] is None  # its DP predecessor x is not shown: no hidden link drawn
    assert r.lead_in == ["s"]
    assert ["s"] not in best_path(nodes, edges, EXEMPT, seeds={"s", "b", "c"}, weak={"w2", "w4"}).branches  # off
    # host-only R4 links (Collection -> Exfiltration on one cloud account id) do not pull a seed in
    r4 = [e for e in edges if e.i != "s"] + [Edge("s", "b", "R4", 1.3)]
    assert ["s"] not in best_path(nodes, r4, EXEMPT, seeds={"s", "b", "c"}, weak={"w2", "w4"},
                                  lead_in_rules=lead).branches


def test_lead_in_seed_does_not_pull_in_another_seed() -> None:
    # lead-in seed s joins (links into shown b); seed t's only shown-side predecessor is s: t stays for peeling
    nodes = [n("a", 0, "Execution", 80), n("s", 1, "Persistence", 70), n("b", 2, "Discovery", 80),
             n("t", 3, "Exfiltration", 85)]
    edges = [Edge("a", "b", "R2", 1.0), Edge("s", "b", "R2", 0.1), Edge("s", "t", "R2", 0.1)]
    r = best_path(nodes, edges, EXEMPT, seeds={"s", "t"}, lead_in_rules=("R2",))
    assert r.backbone == ["a", "b"] and r.branches == [["s"]]


def test_non_seed_respects_branch_limits() -> None:
    nodes = [n("a", 0, "Execution", 80), n("b", 1, "Discovery", 80), n("c", 2, "Collection", 80),
             n("d", 3, "Discovery", 60)]
    edges = [Edge("a", "b", "R2", 1.0), Edge("b", "c", "R2", 1.0), Edge("a", "d", "R2", 1.0)]
    assert best_path(nodes, edges, EXEMPT, max_branches=0).branches == []
    assert best_path(nodes, edges, EXEMPT, max_branches=0, seeds={"d"}).branches == [["d"]]
