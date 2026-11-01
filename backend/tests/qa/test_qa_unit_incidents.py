"""QA unit / white-box tests for Stage 4 (attacklens.incidents + attacklens.incident_gate), track qa_coverage_unit.

Baseline coverage (data/tmp/qa_cov/before.json) showed these branches never ran in the fast suite:
- incident_gate.entities() (the allowlist check was always short-circuited by an empty allowlist),
- allowlist_entities() list form,
- incidents.run: "more than N incidents peeled from one component" and "extracted path fails gate",
- incidents._path_edge for a pair without an edge.
Every case below is a positive plus a near miss with exact suppressed.json reasons.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from attacklens import incident_gate, incidents

from ..conftest import insert_rows, make_events_parquet, write_episodes

T0 = 1792807200000
MIN = 60_000


# ---- pure helpers ----------------------------------------------------------------------------------------------
def test_entities_exact() -> None:
    e = {"subject_host": "SRV-DC-01", "src_host": "ws-a", "dst_host": None, "src_user": "Bob",
         "target_user": "", "src_ip": "203.0.113.9", "dst_ip": "10.0.0.5", "host": "ignored-reporting-host"}
    assert incident_gate.entities(e) == {"host:srv-dc-01", "host:ws-a", "user:bob", "ip:203.0.113.9",
                                         "ip:10.0.0.5"}
    assert incident_gate.entities({"host": "only-reporter"}) == set()   # `host` is not an entity column here


def test_allowlist_entities_forms() -> None:
    assert incident_gate.allowlist_entities({"allowlist": ["HOST:A", "user:B"]}) == {"host:a", "user:b"}
    cfg = {"allowlist": {"entities": ["ip:10.0.0.1"], "hosts": ["SRV-1"], "users": ["Svc"], "ips": ["1.2.3.4"]}}
    assert incident_gate.allowlist_entities(cfg) == {"ip:10.0.0.1", "host:srv-1", "user:svc", "ip:1.2.3.4"}
    assert incident_gate.allowlist_entities({"allowlist": None}) == set()
    assert incident_gate.allowlist_entities({"allowlist": {"entities": None}}) == set()


def test_burst_skips_episodes_without_subject() -> None:
    p = {**incident_gate._params({}), "burst_techniques": 2, "burst_rules": 1, "burst_conf": 60, "seed": 65}
    no_subject = [{"episode_id": f"x{k}", "ts_ms": T0 + k, "technique_id": f"T10{k}", "rule_id": "r",
                   "confidence": 90} for k in range(3)]
    assert incident_gate.burst(no_subject, p) is False                       # no subject -> never a burst
    with_subject = [{**e, "host": "ws-1"} for e in no_subject]
    assert incident_gate.burst(with_subject, p) is True                      # near miss: same episodes on a host


def test_path_edge_missing_pair_and_r3_relabel() -> None:
    edge_map = {("e1", "e2"): ("e1", "e2", "R3", 1.23456, 0, "account from step e1 used in step e2")}
    assert incidents._path_edge(edge_map, "e2", "e1", {}) is None            # reversed pair: no edge
    pe = incidents._path_edge(edge_map, "e1", "e2", {"e1": 0, "e2": 3})
    assert (pe.from_, pe.to, pe.rule, pe.weight, pe.why_linked) == ("e1", "e2", "R3", 1.235,
                                                                     "account from step 1 used in step 4")
    pe2 = incidents._path_edge(edge_map, "e1", "e2", {"e1": 0})              # one side unlabelled: text unchanged
    assert pe2.why_linked == "account from step e1 used in step e2"


# ---- Stage 4 runs -----------------------------------------------------------------------------------------------
def _edges(ctx, rows: list[tuple[str, str, str, float]]) -> None:
    con = ctx.con
    con.execute("CREATE OR REPLACE TEMP TABLE _ed (i VARCHAR, j VARCHAR, rule VARCHAR, weight DOUBLE, dt_ms BIGINT, "
                "why_linked VARCHAR)")
    insert_rows(con, "_ed", [("i", "VARCHAR"), ("j", "VARCHAR"), ("rule", "VARCHAR"), ("weight", "DOUBLE"),
                             ("dt_ms", "BIGINT"), ("why_linked", "VARCHAR")],
                [[i, j, r, w, 0, f"{r} {i}->{j}"] for i, j, r, w in rows])
    con.execute(f"COPY _ed TO '{(ctx.work_dir / 'edges.parquet').as_posix()}' (FORMAT PARQUET)")


PAIR = [
    {"episode_id": "a1", "ts_ms": T0, "host": "srv-x-01", "tactic": "Credential Access", "technique_id": "T1110",
     "target_user": "bob", "src_ip": "203.0.113.9", "severity": 85, "confidence": 85},
    {"episode_id": "a2", "ts_ms": T0 + 5 * MIN, "host": "srv-x-01", "tactic": "Execution", "technique_id": "T1059",
     "src_user": "bob", "severity": 80, "confidence": 80},
]


def _run(tmp: Path, eps: list[dict], edges: list[tuple[str, str, str, float]], cfg_patch=None) -> tuple:
    ctx = make_events_parquet(tmp, [{"ts_ms": T0 - MIN, "action": "other", "host": "h"}])
    try:
        if cfg_patch:
            cfg_patch(ctx.cfg)
        write_episodes(ctx, eps)
        _edges(ctx, edges)
        stats = incidents.run(ctx)
        data = json.loads((ctx.work_dir / "incidents.json").read_text(encoding="utf-8"))
        sup = json.loads((ctx.out_dir / "suppressed.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    return stats, data, sup


def _allow(entities: list[str]):
    def patch(cfg: dict) -> None:
        cfg["allowlist"] = {"entities": entities}
    return patch


def test_allowlisted_component_suppressed(tmp_path: Path) -> None:
    stats, data, sup = _run(tmp_path, PAIR, [("a1", "a2", "R2", 1.0)],
                            _allow(["host:srv-x-01", "user:bob", "ip:203.0.113.9"]))
    assert data == []
    assert sup["by_reason"] == {"allowlisted": 1}
    assert [(c["episode_ids"], c["reason"]) for c in sup["components"]] == [
        (["a1", "a2"], "allowlisted: every entity is on the allowlist")]
    assert stats["episode_accounting"]["ok"] is True


def test_allowlist_near_miss_one_entity_missing_kept(tmp_path: Path) -> None:
    # the attacker IP is not allowlisted -> not every entity is on the allowlist -> kept
    stats, data, sup = _run(tmp_path, PAIR, [("a1", "a2", "R2", 1.0)], _allow(["host:srv-x-01", "user:bob"]))
    assert [[s["episode_id"] for s in i["backbone"]] for i in data] == [["a1", "a2"]]
    assert sup["by_reason"] == {} and stats["kept"] == 1


def test_allowlist_dict_keys_form_suppresses(tmp_path: Path) -> None:
    def patch(cfg: dict) -> None:
        cfg["allowlist"] = {"hosts": ["SRV-X-01"], "users": ["Bob"], "ips": ["203.0.113.9"]}
    _, data, sup = _run(tmp_path, PAIR, [("a1", "a2", "R2", 1.0)], patch)
    assert data == [] and sup["by_reason"] == {"allowlisted": 1}


def test_max_incidents_per_component_cap(tmp_path: Path) -> None:
    def cap0(cfg: dict) -> None:
        cfg["linking"].setdefault("gate", {})["max_incidents_per_component"] = 0
    stats, data, sup = _run(tmp_path, PAIR, [("a1", "a2", "R2", 1.0)], cap0)
    assert data == []
    assert sup["by_reason"] == {"more than 0 incidents peeled from one component": 1}
    assert stats["episode_accounting"]["ok"] is True

    def cap1(cfg: dict) -> None:                                           # near miss: one incident allowed
        cfg["linking"].setdefault("gate", {})["max_incidents_per_component"] = 1
    _, data1, sup1 = _run(tmp_path / "b", PAIR, [("a1", "a2", "R2", 1.0)], cap1)
    assert len(data1) == 1 and sup1["by_reason"] == {}


def test_extracted_path_fails_gate_then_remainder_regated(tmp_path: Path) -> None:
    """Component {b1, b2} passes (2 tactics, conf 86) but its only edge points backwards in time (b2 -> b1), so
    the DP has no predecessor: backbone = the best single node b2 (higher severity AND confidence, so the result
    does not depend on path.dp_node_score); b1 is a seed with no shown predecessor -> remainder. The extracted
    incident {b2} is single-tactic below critical -> 'extracted path fails gate'; the re-gated remainder {b1}
    fails too. Both entries accounted, nothing kept."""
    eps = [
        {"episode_id": "b1", "ts_ms": T0, "host": "srv-y-01", "tactic": "Credential Access", "technique_id": "T1110",
         "target_user": "eve", "severity": 50, "confidence": 85},
        {"episode_id": "b2", "ts_ms": T0 + 5 * MIN, "host": "srv-y-01", "tactic": "Execution",
         "technique_id": "T1059", "src_user": "eve", "severity": 90, "confidence": 86},
    ]
    stats, data, sup = _run(tmp_path, eps, [("b2", "b1", "R2", 1.0)])
    assert data == []
    assert sup["by_reason"] == {"extracted path fails gate": 1, "fewer than 2 tactics": 1}
    reasons = sorted((c["episode_ids"], c["reason"]) for c in sup["components"])
    assert reasons == [(["b1"], "fewer than 2 tactics and max confidence 85 < 90"),
                       (["b2"], "extracted path fails gate: fewer than 2 tactics and max confidence 86 < 90")]
    assert stats["peeled_subcomponents"] == 1
    assert stats["episode_accounting"] == {"episodes": 2, "in_incidents": 0, "in_suppressed": 2, "missing": 0,
                                           "duplicated": 0, "ok": True}


def test_extracted_path_near_miss_forward_edge_kept(tmp_path: Path) -> None:
    """Same two episodes with the edge forward in time (b1 -> b2): one incident, nothing suppressed."""
    eps = [
        {"episode_id": "b1", "ts_ms": T0, "host": "srv-y-01", "tactic": "Credential Access", "technique_id": "T1110",
         "target_user": "eve", "severity": 50, "confidence": 85},
        {"episode_id": "b2", "ts_ms": T0 + 5 * MIN, "host": "srv-y-01", "tactic": "Execution",
         "technique_id": "T1059", "src_user": "eve", "severity": 90, "confidence": 86},
    ]
    stats, data, sup = _run(tmp_path, eps, [("b1", "b2", "R2", 1.0)])
    assert [[s["episode_id"] for s in i["backbone"]] for i in data] == [["b1", "b2"]]
    assert sup["by_reason"] == {} and stats["peeled_subcomponents"] == 0


def test_no_episodes_file_gives_empty_stage(tmp_path: Path) -> None:
    ctx = make_events_parquet(tmp_path, [{"ts_ms": T0, "action": "other", "host": "h"}])
    try:
        stats = incidents.run(ctx)                                          # no work/episodes.parquet at all
        data = json.loads((ctx.work_dir / "incidents.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    assert data == [] and stats["incidents"] == 0 and stats["components"] == 0
    assert stats["episode_accounting"]["ok"] is True


def test_episode_accounting_detects_loss_and_duplicates() -> None:
    eps = {"a": {}, "b": {}, "c": {}}
    bad = incidents.episode_accounting(eps, [["a", "b"]], [["b"]])
    assert bad == {"episodes": 3, "in_incidents": 2, "in_suppressed": 1, "missing": 1, "duplicated": 1, "ok": False}
    good = incidents.episode_accounting(eps, [["a", "b"]], [["c"]])
    assert good["ok"] is True and (good["missing"], good["duplicated"]) == (0, 0)


@pytest.mark.parametrize("text, n, expected", [("abcdef", 6, "abcdef"), ("abcdefg", 6, "abcde…"), ("ab", 1, "…")])
def test_clip_boundaries(text: str, n: int, expected: str) -> None:
    out = incidents.clip(text, n)
    assert out == expected and len(out) <= max(n, 1)
