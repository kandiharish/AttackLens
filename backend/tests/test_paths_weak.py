"""Weak backbone ends (GRAPH fix of 31 Oct: paths.trim_weak, best_path(weak=), incident_gate weak_conf from
linking.yaml path.backbone_end_min_confidence, incidents keeps the edge from a trimmed head run into backbone[0]).

Rule under test: a step below weak_conf may bridge two backbone steps but never starts or ends the backbone.
Leading / trailing weak runs move to branches (head run first, then tail run) so they stay shown and accounted;
a backbone made only of weak steps is left as is. Every expected value below is computed by hand.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from attacklens import config, incidents
from attacklens.paths import Edge, best_path, trim_weak

from .conftest import make_events_parquet, write_episodes
from .test_incidents import MIN, REACH_EVENTS, SEED_EDGES, SEEDS, T0, _write_edges
from .test_paths import n


# ================================================================ trim_weak (pure)
@pytest.mark.parametrize("bb, weak, core, ends", [
    ([], set(), [], []),
    (["a", "b", "c"], set(), ["a", "b", "c"], []),                          # nothing weak
    (["w", "a", "b"], {"w"}, ["a", "b"], [["w"]]),                          # head run
    (["a", "b", "w"], {"w"}, ["a", "b"], [["w"]]),                          # tail run
    (["w1", "w2", "a", "b", "w3"], {"w1", "w2", "w3"}, ["a", "b"], [["w1", "w2"], ["w3"]]),  # head first, then tail
    (["a", "m", "b"], {"m"}, ["a", "m", "b"], []),                          # bridge stays
    (["w", "a", "m", "b", "x"], {"w", "m", "x"}, ["a", "m", "b"], [["w"], ["x"]]),  # bridge stays, ends move
    (["w1", "w2"], {"w1", "w2"}, ["w1", "w2"], []),                         # all weak: left as is
    (["a"], {"z"}, ["a"], []),                                              # weak id not on the backbone
])
def test_trim_weak_exact(bb: list, weak: set, core: list, ends: list) -> None:
    assert trim_weak(bb, frozenset(weak)) == (core, ends)


# ================================================================ best_path(weak=)
CHAIN = [n("w1", 0, "Execution", 20), n("a", 1, "Execution", 80), n("m", 2, "Execution", 20),
         n("b", 3, "Execution", 80), n("w2", 4, "Execution", 20)]
CHAIN_EDGES = [Edge("w1", "a", "R2", 1.0), Edge("a", "m", "R2", 1.0), Edge("m", "b", "R2", 1.0),
               Edge("b", "w2", "R2", 1.0)]


def test_best_path_without_weak_keeps_full_chain() -> None:
    # near miss / control: same graph, no weak set -> literal DP backbone (scores 20, 101, 122, 203, 224)
    r = best_path(CHAIN, CHAIN_EDGES)
    assert r.backbone == ["w1", "a", "m", "b", "w2"] and r.branches == []
    assert r.scores == {"w1": 20, "a": 101, "m": 122, "b": 203, "w2": 224}


def test_best_path_moves_weak_ends_to_branches_keeps_bridge() -> None:
    r = best_path(CHAIN, CHAIN_EDGES, weak={"w1", "m", "w2"})
    assert r.backbone == ["a", "m", "b"]
    assert r.branches == [["w1"], ["w2"]]
    # DP itself is unchanged: scores and predecessors are the literal ones (incidents.py rebuilds edges from back)
    assert r.scores == {"w1": 20, "a": 101, "m": 122, "b": 203, "w2": 224}
    assert r.back == {"w1": None, "a": "w1", "m": "a", "b": "m", "w2": "b"}


def test_best_path_all_weak_left_as_is() -> None:
    r = best_path(CHAIN, CHAIN_EDGES, weak={x.id for x in CHAIN})
    assert r.backbone == ["w1", "a", "m", "b", "w2"] and r.branches == []


# ================================================================ config pin
def test_weak_conf_follows_config() -> None:
    cfg = config.load_config()
    p = incidents._params(cfg)
    assert p["weak_conf"] == cfg["linking"]["path"]["backbone_end_min_confidence"] == 40.0
    assert p["weak_conf"] == cfg["linking"]["gate"]["min_tactic_confidence"]       # documented coupling


# ================================================================ Stage 4: shown, accounted, head edge kept
W0 = {"episode_id": "w0", "ts_ms": T0 - 10 * MIN, "host": "srv-dc-01", "tactic": "Reconnaissance",
      "technique_id": "T1595", "src_ip": "203.0.113.57", "target_user": "svc_backup", "severity": 30,
      "confidence": 20}
W9 = {"episode_id": "w9", "ts_ms": T0 + 70 * MIN, "host": "ws-fin-010", "tactic": "Impact", "technique_id": "T1489",
      "src_user": "svc_backup", "severity": 30, "confidence": 20}
WEAK_EDGES = [("w0", "s1", "R2", 1.0), ("s4", "w9", "R2", 1.0)]


def _run(tmp: Path, weak_conf: float | None) -> tuple[dict, list[dict]]:
    ctx = make_events_parquet(tmp, REACH_EVENTS)
    if weak_conf is not None:
        ctx.cfg["linking"]["path"]["backbone_end_min_confidence"] = weak_conf
    try:
        write_episodes(ctx, SEEDS + [W0, W9])
        _write_edges(ctx, SEED_EDGES + WEAK_EDGES)
        stats = incidents.run(ctx)
        data = json.loads((ctx.work_dir / "incidents.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    return stats, data


def _shape(inc: dict) -> tuple[list[str], list[list[str]], set[tuple[str, str]], dict[str, int]]:
    steps = inc["backbone"] + [s for b in inc["branches"] for s in b]
    return ([s["episode_id"] for s in inc["backbone"]], [[s["episode_id"] for s in b] for b in inc["branches"]],
            {(e["from"], e["to"]) for e in inc["edges"]}, {s["episode_id"]: s["step"] for s in steps})


ALL_EDGES = {("w0", "s1"), ("s1", "s2"), ("s2", "s3"), ("s3", "s4"), ("s4", "w9")}


def test_stage4_weak_ends_become_branches_with_every_edge(tmp_path: Path) -> None:
    stats, data = _run(tmp_path, None)                                 # shipped config: 40
    assert len(data) == 1
    bb, br, edges, step = _shape(data[0])
    assert bb == ["s1", "s2", "s3", "s4"]
    assert br == [["w0"], ["w9"]]
    assert edges == ALL_EDGES                                          # w0 -> s1 is not lost by the trim
    assert step == {"s1": 0, "s2": 1, "s3": 2, "s4": 3, "w0": 4, "w9": 5}
    assert data[0]["entry_point"]["step"] == 0 and data[0]["backbone"][0]["episode_id"] == "s1"
    acc = stats["episode_accounting"]
    assert acc == {"episodes": 6, "in_incidents": 6, "in_suppressed": 0, "missing": 0, "duplicated": 0, "ok": True}


def test_stage4_weak_conf_zero_is_literal_backbone(tmp_path: Path) -> None:
    # near miss: 0 turns the trim off -> the weak ends frame the backbone again, same edges
    _, data = _run(tmp_path, 0)
    bb, br, edges, _ = _shape(data[0])
    assert bb == ["w0", "s1", "s2", "s3", "s4", "w9"] and br == [] and edges == ALL_EDGES


def test_stage4_weak_threshold_is_strict_less_than(tmp_path: Path) -> None:
    # boundary: confidence 20 is weak at 20.1, not weak at 20 (weak = confidence < weak_conf)
    _, at = _run(tmp_path / "at", 20)
    _, above = _run(tmp_path / "above", 20.1)
    assert _shape(at[0])[0] == ["w0", "s1", "s2", "s3", "s4", "w9"]
    assert _shape(above[0])[0] == ["s1", "s2", "s3", "s4"]
