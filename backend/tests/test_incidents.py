"""Stage 4 tests (TESTING.md §4.4, DEVELOPMENT.md §6.3/§6.4 + §15.7): gate, risk, components -> incidents."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import pytest

from attacklens import config, incidents, link
from attacklens.models import Incident

from .conftest import insert_rows, make_events_parquet, write_episodes

T0 = 1792807200000
MIN, H = 60_000, 3_600_000


@pytest.fixture(scope="module")
def p() -> dict:
    return incidents._params(config.load_config())


# ---------------------------------------------------------------- gate
def test_gate_params_follow_config(p: dict) -> None:
    cfg = config.load_config()
    th = cfg["rules"]["thresholds"]
    assert (p["seed"], p["critical"]) == (th["seed_confidence"], th["critical_confidence"])
    assert p["critical_min_merged"] == int(cfg["linking"]["gate"].get("critical_min_merged_alerts", 1))


def test_gate_two_tactics_at_seed_kept(p: dict) -> None:
    assert incidents.gate({"Execution", "Persistence"}, p["seed"], False, p, 1) is None


def test_gate_two_tactics_below_seed_suppressed(p: dict) -> None:
    assert incidents.gate({"Execution", "Persistence"}, p["seed"] - 0.1, False, p, 1) is not None


def test_gate_single_tactic_noise_suppressed(p: dict) -> None:
    reason = incidents.gate({"Execution"}, p["critical"] - 0.1, False, p, 100)
    assert reason is not None and reason.startswith("fewer than")


def test_gate_critical_single_tactic_kept_with_enough_alerts(p: dict) -> None:
    need = p["critical_min_merged"]
    assert incidents.gate({"Impact"}, p["critical"], False, p, need) is None   # e.g. S5 ransom_rename (300)
    if need > 1:
        reason = incidents.gate({"Impact"}, p["critical"], False, p, need - 1)  # one stray .locked file
        assert reason is not None and reason.startswith("critical single-tactic")


def test_gate_allowlisted_suppressed(p: dict) -> None:
    assert incidents.gate({"Execution", "Impact"}, 100, True, p, 300).startswith("allowlisted")


# ---------------------------------------------------------------- risk (B-1)
def _ep(tactic: str, sev: int, host: str = "h1", merged: int = 1) -> dict:
    from attacklens.schemas import TACTIC_IDX
    return {"tactic": tactic, "tactic_idx": TACTIC_IDX[tactic], "severity": sev, "subject_host": host,
            "merged_alert_count": merged}


def test_risk_exact_formula(p: dict) -> None:
    path = [_ep("Execution", 80, "h1", 2), _ep("Credential Access", 85, "h2", 10)]
    raw = 1.4 * math.log(8.0) + 1.9 * math.log(8.5)
    bonus = min(p["bonus_cap"], math.floor(2 * math.log(3) + math.log(13) + 0.5))
    risk, got_raw = incidents.risk_score(path, p)
    assert got_raw == pytest.approx(raw)
    assert risk == min(100, math.floor(p["base_points"] * raw / p["raw_ref"] + 0.5) + bonus)


def test_risk_monotonic(p: dict) -> None:
    base = [_ep("Execution", 70), _ep("Persistence", 70)]
    r0 = incidents.risk_score(base, p)[0]
    assert incidents.risk_score(base + [_ep("Exfiltration", 85)], p)[0] > r0     # more tactics
    assert incidents.risk_score([_ep("Execution", 90), _ep("Persistence", 70)], p)[0] > r0  # higher severity
    assert incidents.risk_score(base + [_ep("Execution", 50)], p)[0] >= r0       # never decreases


def test_risk_not_saturated_two_attacks_differ(p: dict) -> None:
    s3 = [_ep("Execution", 80, "ws-hr-012"), _ep("Persistence", 75, "ws-hr-012"),
          _ep("Command and Control", 75, "ws-hr-012", 10)]
    s4 = [_ep("Credential Access", 75, "srv-web-01", 20), _ep("Initial Access", 85, "srv-web-01"),
          _ep("Lateral Movement", 75, "srv-db-01"), _ep("Exfiltration", 85, "srv-db-01", 3)]
    r3, r4 = incidents.risk_score(s3, p)[0], incidents.risk_score(s4, p)[0]
    assert r3 != r4 and r3 < 100 and r4 < 100


# ---------------------------------------------------------------- Stage 4 end to end on a tiny component
S1_EPS = [
    {"episode_id": "e1", "ts_ms": T0, "host": "srv-dc-01", "tactic": "Credential Access", "technique_id": "T1110",
     "sub_technique_id": "T1110.001", "rule_id": "brute_force_then_success", "target_user": "svc_backup",
     "src_ip": "203.0.113.57", "severity": 75, "confidence": 85, "merged_alert_count": 60},
    {"episode_id": "e2", "ts_ms": T0 + 5 * MIN, "host": "srv-dc-01", "tactic": "Initial Access",
     "technique_id": "T1078", "target_user": "svc_backup", "src_ip": "203.0.113.57", "severity": 85},
    {"episode_id": "e3", "ts_ms": T0 + 20 * MIN, "host": "ws-fin-010", "tactic": "Lateral Movement",
     "technique_id": "T1021", "target_user": "svc_backup", "severity": 75, "confidence": 75},
    {"episode_id": "e4", "ts_ms": T0 + 24 * MIN, "host": "ws-fin-010", "tactic": "Execution",
     "technique_id": "T1059", "sub_technique_id": "T1059.001", "src_user": "svc_backup", "severity": 75},
    {"episode_id": "e5", "ts_ms": T0 + 65 * MIN, "host": "ws-fin-010", "tactic": "Exfiltration",
     "technique_id": "T1048", "src_user": "svc_backup", "dst_ip": "198.51.100.23", "severity": 85,
     "merged_alert_count": 4},
    # unrelated low-confidence single-tactic noise -> suppressed
    {"episode_id": "e9", "ts_ms": T0 + 10 * H, "host": "ws-it-003", "tactic": "Discovery", "technique_id": "T1082",
     "src_user": "kiyer", "severity": 45, "confidence": 45},
]
REACH_EVENTS = [
    # svc_backup has admin (4624 type 3 + 4672) on srv-file-01 (untouched) and srv-dc-01 (touched)
    {"ts_ms": T0 - H, "action": "login_success", "host": "srv-file-01", "target_user": "svc_backup",
     "logon_type": 3, "logon_id": "0xa1", "event_id": 4624},
    {"ts_ms": T0 - H, "action": "priv_assigned", "host": "srv-file-01", "target_user": "svc_backup",
     "logon_id": "0xa1", "event_id": 4672},
    {"ts_ms": T0 - 2 * H, "action": "login_success", "host": "srv-dc-01", "target_user": "svc_backup",
     "logon_type": 3, "logon_id": "0xa2", "event_id": 4624},
    {"ts_ms": T0 - 2 * H, "action": "priv_assigned", "host": "srv-dc-01", "target_user": "svc_backup",
     "logon_id": "0xa2", "event_id": 4672},
]


def _stage4(tmp: Path) -> tuple:
    ctx = make_events_parquet(tmp, REACH_EVENTS)
    write_episodes(ctx, S1_EPS)
    link.run(ctx)
    stats = incidents.run(ctx)
    return ctx, stats


def test_stage4_builds_one_incident_exact(tmp_path: Path) -> None:
    ctx, stats = _stage4(tmp_path)
    try:
        data = json.loads((ctx.work_dir / "incidents.json").read_text(encoding="utf-8"))
        sup = json.loads((ctx.out_dir / "suppressed.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    assert (stats["incidents"], stats["suppressed"]) == (1, 1)
    inc = Incident.model_validate(data[0])
    ids = ["e1", "e2", "e3", "e4", "e5"]
    assert inc.id == "inc-" + hashlib.sha1(",".join(ids).encode()).hexdigest()[:8]
    assert [s.episode_id for s in inc.backbone] == ids and [s.step for s in inc.backbone] == list(range(5))
    assert inc.tactics == ["Initial Access", "Execution", "Credential Access", "Lateral Movement", "Exfiltration"]
    assert inc.gaps == ["Persistence", "Privilege Escalation", "Stealth", "Defense Impairment", "Discovery",
                        "Collection", "Command and Control"]
    assert inc.first_ts == "2026-10-24T02:00:00Z" and inc.last_ts == "2026-10-24T03:05:00Z"
    assert inc.episode_count == 5 and inc.merged_alert_count == 60 + 1 + 1 + 1 + 4
    assert inc.entry_point.step == 0 and "203.0.113.57" in inc.entry_point.summary
    assert {(e.from_, e.to) for e in inc.edges} == {("e1", "e2"), ("e2", "e3"), ("e3", "e4"), ("e4", "e5")}
    assert all(e.why_linked for e in inc.edges)
    assert [(r.host, r.hops, r.via_user, r.touched, r.crown_jewel) for r in inc.reach_next] == [
        ("srv-file-01", 1, "svc_backup", False, "file"), ("srv-dc-01", 1, "svc_backup", True, "dc")]
    assert {n.id for n in inc.graph.nodes if n.compromised} >= {"host:srv-dc-01", "host:ws-fin-010",
                                                                 "user:svc_backup"}
    assert sup["total"] == 1 and sup["components"][0]["episode_ids"] == ["e9"]
    assert sup["components"][0]["reason"].startswith("fewer than")


def test_stage4_rerun_byte_identical(tmp_path: Path) -> None:
    outs = []
    for k in range(2):
        ctx, _ = _stage4(tmp_path / f"r{k}")
        try:
            outs.append(((ctx.work_dir / "incidents.json").read_bytes(), (ctx.out_dir / "suppressed.json").read_bytes()))
        finally:
            ctx.con.close()
    assert outs[0] == outs[1]


def test_stage4_two_attacks_two_incidents_sorted_by_risk(tmp_path: Path) -> None:
    other = [  # S3-like on another host/user, no shared entity
        {"episode_id": "f1", "ts_ms": T0 + 3 * H, "host": "ws-hr-012", "tactic": "Execution",
         "technique_id": "T1059", "src_user": "pmehta", "severity": 80},
        {"episode_id": "f2", "ts_ms": T0 + 3 * H + 5 * MIN, "host": "ws-hr-012", "tactic": "Persistence",
         "technique_id": "T1547", "src_user": "pmehta", "severity": 75},
    ]
    ctx = make_events_parquet(tmp_path, REACH_EVENTS)
    try:
        write_episodes(ctx, S1_EPS + other)
        link.run(ctx)
        incidents.run(ctx)
        data = json.loads((ctx.work_dir / "incidents.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    assert [[s["episode_id"] for s in d["backbone"]] for d in data] == [["e1", "e2", "e3", "e4", "e5"],
                                                                         ["f1", "f2"]]
    assert data[0]["risk"] > data[1]["risk"]



# ================================================================ scale invariance: seeds vs a high-severity noise chain
def _write_edges(ctx, rows: list[tuple[str, str, str, float]]) -> None:
    con = ctx.con
    con.execute("CREATE OR REPLACE TEMP TABLE _ed (i VARCHAR, j VARCHAR, rule VARCHAR, weight DOUBLE, dt_ms BIGINT, "
                "why_linked VARCHAR)")
    insert_rows(con, "_ed", [("i", "VARCHAR"), ("j", "VARCHAR"), ("rule", "VARCHAR"), ("weight", "DOUBLE"),
                             ("dt_ms", "BIGINT"), ("why_linked", "VARCHAR")],
                [[i, j, r, w, 0, f"{r} {i}->{j}"] for i, j, r, w in rows])
    con.execute(f"COPY _ed TO '{(ctx.work_dir / 'edges.parquet').as_posix()}' (FORMAT PARQUET)")


SEEDS = [
    {"episode_id": "s1", "ts_ms": T0, "host": "srv-dc-01", "tactic": "Credential Access", "technique_id": "T1110",
     "target_user": "svc_backup", "src_ip": "203.0.113.57", "severity": 75, "confidence": 85},
    {"episode_id": "s2", "ts_ms": T0 + 5 * MIN, "host": "srv-dc-01", "tactic": "Initial Access",
     "technique_id": "T1078", "target_user": "svc_backup", "severity": 85, "confidence": 85},
    {"episode_id": "s3", "ts_ms": T0 + 20 * MIN, "host": "ws-fin-010", "tactic": "Lateral Movement",
     "technique_id": "T1021", "target_user": "svc_backup", "severity": 75, "confidence": 75},
    {"episode_id": "s4", "ts_ms": T0 + 60 * MIN, "host": "ws-fin-010", "tactic": "Exfiltration",
     "technique_id": "T1048", "src_user": "svc_backup", "dst_ip": "198.51.100.23", "severity": 85, "confidence": 85},
]
NOISE_TACTICS = ["Discovery", "Collection", "Command and Control", "Impact", "Execution", "Persistence"]


def _noise(n: int) -> tuple[list[dict], list[tuple[str, str, str, float]]]:
    """An earlier noise Execution n0, then an n-step noise chain (severity 80, confidence 17-52) on another host."""
    eps = [{"episode_id": "n0", "ts_ms": T0 - 30 * MIN, "host": "ws-it-003", "tactic": "Execution",
            "technique_id": "T1059", "src_user": "kiyer", "severity": 80, "confidence": 30}]
    for k in range(1, n + 1):
        eps.append({"episode_id": f"n{k:02d}", "ts_ms": T0 + 6 * MIN + k * 4 * MIN, "host": "ws-it-003",
                    "tactic": NOISE_TACTICS[(k - 1) % len(NOISE_TACTICS)], "technique_id": "T1082",
                    "src_user": "kiyer", "severity": 80, "confidence": 17 + (35 * (k - 1)) // max(1, n - 1)})
    chain = [(f"n{k:02d}", f"n{k + 1:02d}", "R2", 1.0) for k in range(1, n)]
    weak = [("s2", "n01", "R1", 0.3), ("n0", "n01", "R2", 0.1)]
    return eps, chain + weak


def _stage4_with(tmp: Path, eps: list[dict], edge_rows: list[tuple[str, str, str, float]]) -> tuple:
    ctx = make_events_parquet(tmp, REACH_EVENTS)
    write_episodes(ctx, eps)
    _write_edges(ctx, edge_rows)
    try:
        stats = incidents.run(ctx)
        data = json.loads((ctx.work_dir / "incidents.json").read_text(encoding="utf-8"))
        sup = json.loads((ctx.out_dir / "suppressed.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    return stats, data, sup


SEED_EDGES = [("s1", "s2", "R2", 1.0), ("s2", "s3", "R3", 1.0), ("s3", "s4", "R2", 1.0)]


@pytest.mark.parametrize("n_noise", [4, 12])
def test_seed_chain_beats_high_severity_noise_chain(tmp_path: Path, n_noise: int) -> None:
    noise, noise_edges = _noise(n_noise)
    stats, data, sup = _stage4_with(tmp_path, SEEDS + noise, SEED_EDGES + noise_edges)
    acc = stats["episode_accounting"]
    assert acc["ok"] is True and acc["in_incidents"] + acc["in_suppressed"] == acc["episodes"] == 4 + 1 + n_noise
    assert acc["missing"] == 0 and acc["duplicated"] == 0
    s1_inc = [d for d in data if any(s["episode_id"] == "s1" for s in d["backbone"])]
    assert len(s1_inc) == 1
    inc = s1_inc[0]
    assert inc["backbone"][0]["episode_id"] == "s1"                       # backbone starts with the brute force
    assert [s["episode_id"] for s in inc["backbone"]] == ["s1", "s2", "s3", "s4"]
    shown = {s["episode_id"] for d in data for s in d["backbone"] + [x for b in d["branches"] for x in b]}
    sup_ids = {x for c in sup["components"] for x in c["episode_ids"]}
    for seed in ("s1", "s2", "s3", "s4"):
        assert seed in shown or seed in sup_ids, seed                    # a seed is never hidden


def test_backbone_identical_across_noise_sizes(tmp_path: Path) -> None:
    got = []
    for n in (4, 12):
        noise, noise_edges = _noise(n)
        _, data, _ = _stage4_with(tmp_path / f"n{n}", SEEDS + noise, SEED_EDGES + noise_edges)
        got.append(next([s["episode_id"] for s in d["backbone"]] for d in data
                        if d["backbone"][0]["episode_id"] == "s1"))
    assert got[0] == got[1] == ["s1", "s2", "s3", "s4"]


def test_unlinked_seed_is_shown_or_suppressed_never_lost(tmp_path: Path) -> None:
    lone = {"episode_id": "z9", "ts_ms": T0 + 5 * H, "host": "ws-hr-012", "tactic": "Persistence",
            "technique_id": "T1547", "src_user": "pmehta", "severity": 75, "confidence": 70}
    stats, data, sup = _stage4_with(tmp_path, SEEDS + [lone], SEED_EDGES)
    shown = {s["episode_id"] for d in data for s in d["backbone"] + [x for b in d["branches"] for x in b]}
    sup_ids = {x for c in sup["components"] for x in c["episode_ids"]}
    assert "z9" in shown | sup_ids and stats["episode_accounting"]["ok"] is True


def test_lead_in_seed_is_shown_with_its_link(tmp_path: Path) -> None:
    # cloud_small A5 shape: weak Initial Access chain w1..w4 takes b's DP slot from seed s (Persistence 80); s used
    # to be peeled into a one-episode suppressed group. It must be shown, with its edge into the shown path.
    def ep(i: str, k: int, tactic: str, conf: float) -> dict:
        return {"episode_id": i, "ts_ms": T0 + k * MIN, "host": "corp-data-5678", "tactic": tactic,
                "technique_id": "T1098", "src_user": "dsingh", "severity": 80, "confidence": conf}
    eps = [ep("x", 0, "Persistence", 60), ep("s", 1, "Persistence", 80), ep("w1", 2, "Initial Access", 51),
           ep("w2", 3, "Initial Access", 30), ep("w3", 4, "Initial Access", 51), ep("w4", 5, "Initial Access", 26),
           ep("b", 6, "Privilege Escalation", 75), ep("c", 7, "Defense Impairment", 85)]
    edges = [("x", "s", "R3", 1.07), ("s", "w1", "R2", 0.86), ("w1", "w2", "R2", 1.0), ("w2", "w3", "R2", 0.81),
             ("w3", "w4", "R2", 0.86), ("w4", "b", "R2", 1.0), ("s", "b", "R3", 1.3), ("b", "c", "R3", 1.3)]
    stats, data, sup = _stage4_with(tmp_path, eps, edges)
    assert stats["episode_accounting"]["ok"] is True and len(data) == 1
    inc = data[0]
    assert "s" in {x["episode_id"] for b in inc["branches"] for x in b}
    assert ("s", "b") in {(e["from"], e["to"]) for e in inc["edges"]}
    assert all(e["from"] != "x" for e in inc["edges"])  # x is a hidden member, never an edge end
    assert not any("s" in c["episode_ids"] for c in sup["components"])


def test_lead_in_seed_never_donates_a_gate_tactic(tmp_path: Path) -> None:
    # cloud_small CI noise: one-tactic Execution path (conf 43) + a Defense Impairment seed linking into it -> the
    # extracted path still fails the gate (the seed is not a donor); every episode stays accounted
    def ep(i: str, k: int, tactic: str, conf: float) -> dict:
        return {"episode_id": i, "ts_ms": T0 + k * MIN, "host": "111122223333", "tactic": tactic,
                "technique_id": "T1648", "src_user": "gha-1", "severity": 80, "confidence": conf}
    eps = [ep("s", 0, "Defense Impairment", 75)] + [ep(f"x{k}", k, "Execution", 43) for k in (1, 2, 3)]
    edges = [("x1", "x2", "R2", 1.0), ("x2", "x3", "R2", 1.0), ("s", "x2", "R2", 0.5)]
    stats, data, sup = _stage4_with(tmp_path, eps, edges)
    assert data == [] and stats["episode_accounting"]["ok"] is True
    assert any("s" in c["episode_ids"] and c["reason"].startswith("extracted path fails gate")
               for c in sup["components"])


def test_episode_accounting_invariant_on_s1_component(tmp_path: Path) -> None:
    ctx, stats = _stage4(tmp_path)
    ctx.con.close()
    acc = stats["episode_accounting"]
    assert acc == {"episodes": 6, "in_incidents": 5, "in_suppressed": 1, "missing": 0, "duplicated": 0, "ok": True}


# ================================================================ text: 1-based step numbers, evidence clipping
def test_r3_why_linked_uses_one_based_steps(tmp_path: Path) -> None:
    eps = [SEEDS[0], {"episode_id": "x2", "ts_ms": T0 + 30 * MIN, "host": "ws-fin-010", "tactic": "Execution",
                      "technique_id": "T1059", "src_user": "svc_backup", "severity": 80, "confidence": 80}]
    ctx = make_events_parquet(tmp_path, REACH_EVENTS)
    try:
        write_episodes(ctx, eps)
        link.run(ctx)
        incidents.run(ctx)
        data = json.loads((ctx.work_dir / "incidents.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    inc = Incident.model_validate(data[0])
    assert [s.episode_id for s in inc.backbone] == ["s1", "x2"] and [s.step for s in inc.backbone] == [0, 1]
    assert [(e.rule, e.why_linked) for e in inc.edges] == [("R3", "Account svc_backup from step 1 used in step 2")]


def test_clip_evidence_exact() -> None:
    n = int(config.load_config()["linking"]["path"]["max_evidence_chars"])
    assert n == 300
    cut = incidents.clip("x" * 400, n)
    assert len(cut) == 300 and cut.endswith("…") and cut[:-1] == "x" * 299
    assert incidents.clip("y" * 300, n) == "y" * 300 and incidents.clip("", n) == ""


def test_evidence_clipped_in_published_steps(tmp_path: Path) -> None:
    eps = [dict(SEEDS[0], evidence_lines=["a" * 400, "b" * 300]), SEEDS[1]]
    ctx = make_events_parquet(tmp_path, REACH_EVENTS)
    try:
        write_episodes(ctx, eps)
        link.run(ctx)
        incidents.run(ctx)
        data = json.loads((ctx.work_dir / "incidents.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    ev = next(s["evidence"] for d in data for s in d["backbone"] if s["episode_id"] == "s1")
    assert ev == ["a" * 299 + "…", "b" * 300]


def test_branch_hosts_are_marked_compromised(tmp_path: Path) -> None:
    branch = {"episode_id": "b1", "ts_ms": T0 + 30 * MIN, "host": "ws-br-01", "tactic": "Persistence",
              "technique_id": "T1547", "src_user": "pmehta", "severity": 75, "confidence": 70}
    stats, data, _ = _stage4_with(tmp_path, SEEDS + [branch], SEED_EDGES + [("s2", "b1", "R1", 0.5)])
    inc = next(Incident.model_validate(d) for d in data if d["backbone"][0]["episode_id"] == "s1")
    assert [s.episode_id for b in inc.branches for s in b] == ["b1"]
    nodes = {n.id: n.compromised for n in inc.graph.nodes}
    assert nodes["host:ws-br-01"] is True and nodes["user:pmehta"] is True and nodes["host:srv-dc-01"] is True


def _sum(**kw) -> str:
    from attacklens.models import Step
    base = {"step": 0, "episode_id": "e", "ts": "2026-10-24T02:00:00Z", "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "severity": 80,
            "confidence": 80, "merged_alert_count": 1, "user": None, "src_ip": None, "dst_ip": None, "host": None}
    return incidents.entry_summary(Step(**{**base, **kw}))


@pytest.mark.parametrize("kw,expected", [
    ({"host": "10.0.2.37", "src_ip": "10.0.2.37", "dst_ip": "203.0.113.5"},
     "Exfiltration Over Alternative Protocol by host:10.0.2.37 towards ip:203.0.113.5"),
    ({"host": "10.10.20.15", "src_ip": "203.0.113.66", "dst_ip": "10.10.20.15"},
     "Exfiltration Over Alternative Protocol from ip:203.0.113.66 against host:10.10.20.15"),
    ({"host": "ws-fin-010", "dst_ip": "198.51.100.23"},
     "Exfiltration Over Alternative Protocol against host:ws-fin-010 towards ip:198.51.100.23"),
    ({"host": "srv-dc-01", "src_ip": "203.0.113.57", "user": "svc_backup"},
     "Exfiltration Over Alternative Protocol on user:svc_backup from ip:203.0.113.57 against host:srv-dc-01"),
    ({"host": "10.0.2.37", "src_ip": "10.0.2.37"}, "Exfiltration Over Alternative Protocol by host:10.0.2.37"),
])
def test_entry_summary_wording(kw: dict, expected: str) -> None:
    assert _sum(**kw) == expected
