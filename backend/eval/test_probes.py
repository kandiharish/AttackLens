"""Harness probes (TESTING.md §4.5, L2). The harness must never be generous. Frozen table + extra strictness probes.

Every probe builds incidents with models.Incident in a tmp dir and asserts exact metric values.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import pytest

from attacklens.models import EntryPoint, Incident, Narrative, Step, dump
from eval.harness import evaluate, main
from eval.match import norm_user, technique_ok

T0 = 1792807200000  # 2026-10-24T02:00:00Z
MIN = 60_000

# 7-step attack modelled on S1 (TESTING.md §3.2)
S1 = [
    {"step": 1, "ts_ms": T0, "technique_id": "T1110", "tactic": "Credential Access",
     "host": "srv-dc-01", "user": "svc_backup", "src_ip": "203.0.113.57", "dst_ip": None},
    {"step": 2, "ts_ms": T0 + 5 * MIN, "technique_id": "T1078", "tactic": "Initial Access",
     "host": "srv-dc-01", "user": "svc_backup", "src_ip": "203.0.113.57", "dst_ip": None},
    {"step": 3, "ts_ms": T0 + 20 * MIN, "technique_id": "T1021", "tactic": "Lateral Movement",
     "host": "ws-fin-010", "user": "svc_backup", "src_ip": "10.10.0.10", "dst_ip": None},
    {"step": 4, "ts_ms": T0 + 24 * MIN, "technique_id": "T1059.001", "tactic": "Execution",
     "host": "ws-fin-010", "user": "svc_backup", "src_ip": None, "dst_ip": None},
    {"step": 5, "ts_ms": T0 + 40 * MIN, "technique_id": "T1087", "tactic": "Discovery",
     "host": "ws-fin-010", "user": "svc_backup", "src_ip": None, "dst_ip": None},
    {"step": 6, "ts_ms": T0 + 50 * MIN, "technique_id": "T1560.001", "tactic": "Collection",
     "host": "ws-fin-010", "user": "svc_backup", "src_ip": None, "dst_ip": None},
    {"step": 7, "ts_ms": T0 + 65 * MIN, "technique_id": "T1048", "tactic": "Exfiltration",
     "host": "ws-fin-010", "user": "svc_backup", "src_ip": None, "dst_ip": "198.51.100.23"},
]


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z")


def step_from(gt: dict, idx: int, ep: str, **over) -> Step:
    d = {"step": idx, "episode_id": ep, "ts": iso(gt["ts_ms"]), "technique_id": gt["technique_id"].split(".")[0],
         "sub_technique_id": gt["technique_id"] if "." in gt["technique_id"] else None,
         "tactic": gt["tactic"], "host": gt["host"], "user": gt["user"], "src_ip": gt["src_ip"],
         "dst_ip": gt["dst_ip"], "severity": 80, "confidence": 80, "merged_alert_count": 1}
    d.update(over)
    return Step(**d)


def incident(inc_id: str, backbone: list[Step], branches: list[list[Step]] | None = None) -> Incident:
    allsteps = backbone + [s for b in branches or [] for s in b]
    return Incident(
        id=inc_id, risk=50, first_ts=min(s.ts for s in allsteps), last_ts=max(s.ts for s in allsteps),
        merged_alert_count=len(allsteps), episode_count=len(allsteps), entry_point=EntryPoint(step=0, summary="x"),
        tactics=sorted({s.tactic for s in allsteps}), backbone=backbone, branches=branches or [],
        narrative=Narrative(text="t", source="template"))


def write(tmp: Path, incidents: list[Incident], attacks: list[dict] | None = None,
          noise: list[dict] | None = None, attack_version: str = "v20") -> tuple[Path, Path]:
    out, gtdir = tmp / "out", tmp / "gt"
    (out / "incidents").mkdir(parents=True, exist_ok=True)
    gtdir.mkdir(parents=True, exist_ok=True)
    for inc in incidents:
        (out / "incidents" / f"{inc.id}.json").write_text(json.dumps(dump(inc)), encoding="utf-8")
    gt = gtdir / "attacks.json"
    gt.write_text(json.dumps({"attack_version": attack_version,
                              "attacks": attacks if attacks is not None else [{"id": "S1", "steps": S1}]}),
                  encoding="utf-8")
    if noise is not None:
        (gtdir / "noise_alerts.jsonl").write_text("".join(json.dumps(n) + "\n" for n in noise), encoding="utf-8")
    return out, gt


def perfect_steps(prefix: str = "e") -> list[Step]:
    return [step_from(g, i, f"{prefix}{i}") for i, g in enumerate(S1)]


# ================================================================ frozen table (TESTING.md §4.5)
def test_empty_prediction(tmp_path: Path) -> None:
    card = evaluate(*write(tmp_path, []))
    m = card
    assert m["detection_pct"] == 0.0 and m["rebuilt_pct"] == 0.0
    assert m["labels_pct"] is None and m["false_alarms_strict_pct"] is None  # 0/0 -> null (§15.6)
    assert m["false_alarms_lenient_pct"] is None and m["singleton_recall_pct"] is None
    assert card["counts"]["incidents"] == 0 and card["counts"]["steps_matched"] == 0
    assert card["per_attack"][0]["rebuilt"] is False
    # an empty prediction passes nothing, including the false-alarm target
    assert all(not v for lv in card["targets"].values() for v in lv.values())


def test_perfect_prediction(tmp_path: Path) -> None:
    card = evaluate(*write(tmp_path, [incident("inc-perfect1", perfect_steps())]))
    m = card
    assert (m["detection_pct"], m["labels_pct"], m["rebuilt_pct"]) == (100.0, 100.0, 100.0)
    assert m["false_alarms_strict_pct"] == 0.0 and m["false_alarms_lenient_pct"] == 0.0
    assert card["counts"]["steps_matched"] == 7 and card["counts"]["attacks_rebuilt"] == 1
    pa = card["per_attack"][0]
    assert pa["matched_incident"] == "inc-perfect1" and pa["lcs_ratio"] == 1.0 and pa["rebuilt"] is True
    assert all(lv["great"] for lv in card["targets"].values())
    assert card["unmatched_incidents"] == []


def test_one_episode_vs_seven_step_attack(tmp_path: Path) -> None:
    card = evaluate(*write(tmp_path, [incident("inc-one00001", [step_from(S1[0], 0, "e0")])]))
    assert card["counts"]["steps_matched"] == 1
    assert card["detection_pct"] == round(100 / 7, 2) == 14.29
    assert card["rebuilt_pct"] == 0.0
    assert card["per_attack"][0]["rebuilt"] is False
    assert card["per_attack"][0]["lcs_ratio"] == round(1 / 7, 4)
    # the single incident did overlap S1, so it is matched, not a false alarm
    assert card["false_alarms_strict_pct"] == 0.0


def test_two_steps_swapped_in_time(tmp_path: Path) -> None:
    steps = perfect_steps()
    # step 3 (T1021) reported at step 4's time and vice versa (4 min apart, still inside tolerance)
    steps[2] = step_from(S1[2], 2, "e2", ts=iso(S1[3]["ts_ms"]))
    steps[3] = step_from(S1[3], 3, "e3", ts=iso(S1[2]["ts_ms"]))
    card = evaluate(*write(tmp_path, [incident("inc-swap0001", steps)]))
    assert card["counts"]["steps_matched"] == 7 and card["detection_pct"] == 100.0
    assert card["labels_pct"] == 100.0
    pa = card["per_attack"][0]
    assert pa["lcs_ratio"] == round(6 / 7, 4) and pa["rebuilt"] is False
    assert card["rebuilt_pct"] == 0.0


def test_two_steps_swapped_in_backbone_positions(tmp_path: Path) -> None:
    steps = perfect_steps()
    steps[2], steps[3] = step_from(S1[3], 2, "e3"), step_from(S1[2], 3, "e2")  # times right, path order wrong
    card = evaluate(*write(tmp_path, [incident("inc-swap0002", steps)]))
    pa = card["per_attack"][0]
    assert card["detection_pct"] == 100.0
    assert pa["backbone_order_ok"] is False and pa["rebuilt"] is False


@pytest.mark.parametrize("pred_user", ["jdoe", "JDOE", "jdoe@corp.local", "user:jdoe", "CORP\\JDoe"])
def test_domain_user_normalized_matches(tmp_path: Path, pred_user: str) -> None:
    gt = [{**S1[3], "user": "CORP\\jdoe"}]
    pred = step_from(gt[0], 0, "e0", user=pred_user, host="HOST:WS-FIN-010")
    card = evaluate(*write(tmp_path, [incident("inc-jdoe0001", [pred])], [{"id": "A", "steps": gt}]))
    assert card["counts"]["steps_matched"] == 1 and card["detection_pct"] == 100.0


def test_different_user_no_ip_not_matched(tmp_path: Path) -> None:
    gt = [{**S1[3], "user": "CORP\\jdoe"}]  # no IPs on this step
    pred = step_from(gt[0], 0, "e0", user="jdoe2")
    card = evaluate(*write(tmp_path, [incident("inc-jdoe0002", [pred])], [{"id": "A", "steps": gt}]))
    assert card["counts"]["steps_matched"] == 0 and card["false_alarms_strict_pct"] == 100.0
    assert card["detection_pct"] == 0.0 and card["labels_pct"] is None


@pytest.mark.parametrize("offset_ms,matched", [
    (11 * MIN, False), (-11 * MIN, False), (10 * MIN + 1, False), (10 * MIN, True), (-10 * MIN, True)])
def test_time_tolerance(tmp_path: Path, offset_ms: int, matched: bool) -> None:
    gt = [S1[0]]
    pred = step_from(gt[0], 0, "e0", ts=iso(gt[0]["ts_ms"] + offset_ms))
    card = evaluate(*write(tmp_path, [incident("inc-time0001", [pred])], [{"id": "A", "steps": gt}]))
    assert card["counts"]["steps_matched"] == (1 if matched else 0)


def test_same_episode_matching_two_steps_used_once(tmp_path: Path) -> None:
    # steps 1 and 2 are 5 min apart on the same host/user/ip; one episode at +2 min fits both
    ep = step_from(S1[0], 0, "e0", ts=iso(T0 + 2 * MIN))
    card = evaluate(*write(tmp_path, [incident("inc-once0001", [ep])], [{"id": "A", "steps": S1[:2]}]))
    assert card["counts"]["steps_matched"] == 1 and card["detection_pct"] == 50.0
    assert card["per_attack"][0]["rebuilt"] is False


def test_same_episode_in_two_incidents_counted_once(tmp_path: Path) -> None:
    a = incident("inc-dupa0001", [step_from(S1[0], 0, "e0")])
    b = incident("inc-dupb0001", [step_from(S1[1], 0, "e0")])  # same episode id again
    card = evaluate(*write(tmp_path, [a, b], [{"id": "A", "steps": S1[:2]}]))
    assert card["counts"]["predicted_steps"] == 1 and card["counts"]["duplicate_episode_ids"] == 1
    assert card["counts"]["steps_matched"] == 1


def test_extra_incident_is_false_alarm(tmp_path: Path) -> None:
    extra = incident("inc-extra001", [step_from(
        {**S1[0], "host": "ws-hr-012", "user": "pmehta", "src_ip": None}, 0, "x0")])
    card = evaluate(*write(tmp_path, [incident("inc-perfect1", perfect_steps()), extra]))
    m = card
    assert m["detection_pct"] == 100.0 and m["rebuilt_pct"] == 100.0
    assert m["false_alarms_strict_pct"] == 50.0 and m["false_alarms_lenient_pct"] == 50.0  # no noise GT -> nothing excluded
    assert card["counts"]["incidents_unmatched"] == 1
    assert [u["id"] for u in card["unmatched_incidents"]] == ["inc-extra001"]
    assert card["unmatched_incidents"][0]["top_episodes"][0]["episode_id"] == "x0"
    assert card["targets"]["false_alarms_strict_pct"] == {"good": False, "great": False}


# ================================================================ extra strictness probes
def test_duplicate_incident_for_same_attack_is_false_alarm_and_splits_attack(tmp_path: Path) -> None:
    main_inc = incident("inc-aaaa0001", perfect_steps()[1:])  # 6 of 7 steps
    dup = incident("inc-bbbb0001", [step_from(S1[0], 0, "d0")])  # step 1 alone in another incident
    card = evaluate(*write(tmp_path, [main_inc, dup]))
    assert card["detection_pct"] == 100.0
    assert card["per_attack"][0]["matched_incident"] == "inc-aaaa0001"
    assert card["per_attack"][0]["rebuilt"] is False  # split across incidents
    assert card["false_alarms_strict_pct"] == 50.0


def test_host_mismatch_not_matched(tmp_path: Path) -> None:
    pred = step_from(S1[0], 0, "e0", host="srv-dc-02")
    card = evaluate(*write(tmp_path, [incident("inc-host0001", [pred])], [{"id": "A", "steps": [S1[0]]}]))
    assert card["counts"]["steps_matched"] == 0


def test_missing_host_not_matched(tmp_path: Path) -> None:
    pred = step_from(S1[0], 0, "e0", host=None)
    card = evaluate(*write(tmp_path, [incident("inc-host0002", [pred])], [{"id": "A", "steps": [S1[0]]}]))
    assert card["counts"]["steps_matched"] == 0


def test_ip_alone_matches_when_user_differs(tmp_path: Path) -> None:
    pred = step_from(S1[0], 0, "e0", user="someone_else")  # src_ip 203.0.113.57 still shared
    card = evaluate(*write(tmp_path, [incident("inc-ip000001", [pred])], [{"id": "A", "steps": [S1[0]]}]))
    assert card["counts"]["steps_matched"] == 1


def test_wrong_technique_counts_as_detected_but_wrong_label(tmp_path: Path) -> None:
    steps = perfect_steps()
    steps[4] = step_from(S1[4], 4, "e4", technique_id="T1082", sub_technique_id=None)
    card = evaluate(*write(tmp_path, [incident("inc-lab00001", steps)]))
    assert card["detection_pct"] == 100.0
    assert card["labels_pct"] == round(100 * 6 / 7, 2)


def test_right_technique_wrong_tactic_is_wrong_label(tmp_path: Path) -> None:
    steps = perfect_steps()
    steps[1] = step_from(S1[1], 1, "e1", tactic="Persistence")  # T1078 but not Initial Access
    card = evaluate(*write(tmp_path, [incident("inc-lab00002", steps)]))
    assert card["labels_pct"] == round(100 * 6 / 7, 2)
    assert card["labels_technique_only_pct"] == 100.0


def test_greedy_prefers_label_match(tmp_path: Path) -> None:
    # two GT steps same host/user 5 min apart; pred A (T1078) sits closer to GT step 1 (T1110) than pred B (T1110)
    a = step_from(S1[1], 0, "eA", ts=iso(T0 + 1 * MIN))
    b = step_from(S1[0], 1, "eB", ts=iso(T0 + 3 * MIN))
    card = evaluate(*write(tmp_path, [incident("inc-gred0001", [a, b])], [{"id": "A", "steps": S1[:2]}]))
    assert card["counts"]["steps_matched"] == 2 and card["labels_pct"] == 100.0


@pytest.mark.parametrize("gt_t,tech,sub,ok", [
    ("T1110", "T1110", None, True), ("T1110", "T1110", "T1110.001", True),
    ("T1110.003", "T1110", None, True), ("T1110.003", "T1110", "T1110.003", True),
    ("T1110.003", "T1110", "T1110.001", False), ("T1110", "T1078", None, False),
    ("T1059.001", "T1059.001", None, True), ("T1059.001", "T1059.003", None, False)])
def test_technique_rule(gt_t: str, tech: str, sub: str | None, ok: bool) -> None:
    assert technique_ok(gt_t, tech, sub) is ok


@pytest.mark.parametrize("gt_tactic,pred_tactic,ok", [
    ("Defense Evasion", "Stealth", True), ("Defense Evasion", "Defense Impairment", True),
    ("Stealth", "Defense Impairment", False), ("Defense Impairment", "Defense Evasion", False),
    ("Stealth", "Stealth", True)])
def test_defense_evasion_mapping_only_from_gt(tmp_path: Path, gt_tactic: str, pred_tactic: str, ok: bool) -> None:
    gt = [{**S1[3], "technique_id": "T1070.001", "tactic": gt_tactic}]
    pred = step_from(gt[0], 0, "e0", tactic=pred_tactic)
    card = evaluate(*write(tmp_path, [incident("inc-de000001", [pred])], [{"id": "A", "steps": gt}]))
    assert card["counts"]["steps_matched"] == 1
    assert card["labels_pct"] == (100.0 if ok else 0.0)


def test_branch_steps_count_for_detection_and_order(tmp_path: Path) -> None:
    steps = perfect_steps()
    bb, br = steps[:6], [steps[6]]
    card = evaluate(*write(tmp_path, [incident("inc-brch0001", bb, [br])]))
    assert card["detection_pct"] == 100.0 and card["per_attack"][0]["rebuilt"] is True


def test_naive_timestamp_rejected(tmp_path: Path) -> None:
    pred = step_from(S1[0], 0, "e0", ts="2026-10-24T02:00:00")
    with pytest.raises(ValueError, match="time zone"):
        evaluate(*write(tmp_path, [incident("inc-naive001", [pred])]))


def test_normalization_nfc_and_homoglyph() -> None:
    assert norm_user("CORP\\José") == norm_user("josé@corp.local") == "josé"
    assert norm_user("аdmin") != norm_user("admin")  # Cyrillic a stays distinct
    assert norm_user("-") is None and norm_user("") is None


def test_lenient_fa_excludes_noise_only_incidents(tmp_path: Path) -> None:
    noise = [{"ts_ms": T0 + 600 * MIN, "technique_id": "T1547.001", "tactic": "Persistence",
              "host": "WS-HR-012", "user": "pmehta", "src_ip": None, "dst_ip": None, "event_id": "n1"}]
    noise_inc = incident("inc-noise001", [step_from({**noise[0], "step": 0}, 0, "n0")])
    junk = incident("inc-junk0001", [step_from(
        {**S1[0], "host": "ws-it-001", "user": "kiyer", "src_ip": None, "ts_ms": T0 + 900 * MIN}, 0, "j0")])
    card = evaluate(*write(tmp_path, [incident("inc-perfect1", perfect_steps()), noise_inc, junk], noise=noise))
    m = card
    assert m["false_alarms_strict_pct"] == round(100 * 2 / 3, 2)
    assert m["false_alarms_lenient_pct"] == 50.0  # (2 unmatched - 1 noise-only) / (3 - 1)
    assert card["counts"]["incidents_noise_only"] == 1
    # singleton recall from incidents (no raw_alerts.parquet): 1 of 1 detectable
    assert m["singleton_recall_pct"] == 100.0 and card["singleton_recall_source"] == "incidents"


def test_noise_with_wrong_technique_is_not_noise_only(tmp_path: Path) -> None:
    noise = [{"ts_ms": T0 + 600 * MIN, "technique_id": "T1547.001", "tactic": "Persistence",
              "host": "ws-hr-012", "user": "pmehta", "src_ip": None, "dst_ip": None, "event_id": "n1"}]
    wrong = incident("inc-noise002", [step_from({**noise[0], "step": 0, "technique_id": "T1059.001",
                                                 "tactic": "Execution"}, 0, "n0")])
    card = evaluate(*write(tmp_path, [wrong], noise=noise))
    assert card["counts"]["incidents_noise_only"] == 0 and card["false_alarms_lenient_pct"] == 100.0
    assert card["singleton_recall_pct"] == 0.0


def test_singleton_recall_and_rule_counts_from_raw_alerts(tmp_path: Path) -> None:
    noise = [
        {"ts_ms": T0, "technique_id": "T1059.001", "tactic": "Execution", "host": "WS-HR-012",
         "user": "pmehta", "src_ip": None, "dst_ip": None, "event_id": "a"},
        {"ts_ms": T0 + 60 * MIN, "technique_id": "T1486", "tactic": "Impact", "host": "SRV-FILE-01",
         "user": "kiyer", "src_ip": None, "dst_ip": None, "event_id": "b"},
        {"ts_ms": T0 + 120 * MIN, "technique_id": "T1110", "tactic": "Credential Access", "host": "SRV-DC-01",
         "user": "rkumar", "src_ip": "192.0.2.88", "dst_ip": None, "event_id": "c"},  # not detectable
    ]
    out, gt = write(tmp_path, [], noise=noise)
    work = out / "work"
    work.mkdir(parents=True)
    con = duckdb.connect()
    con.execute("""CREATE TABLE ra AS SELECT * FROM (VALUES
        ('office_spawns_script','T1059','T1059.001','Execution', 1792807230000::BIGINT,'ws-hr-012','ws-hr-012',
         'pmehta',NULL,NULL,NULL,1::BIGINT),
        ('office_spawns_script','T1059','T1059.001','Execution', 1792807231000::BIGINT,'ws-hr-012','ws-hr-012',
         'pmehta',NULL,NULL,NULL,1::BIGINT),
        ('ransom_rename','T1486',NULL,'Impact', 1792814400000::BIGINT,'srv-file-01','srv-file-01',
         NULL,'rkumar',NULL,NULL,300::BIGINT))
        t(rule_id, technique_id, sub_technique_id, tactic, ts_ms, host, subject_host, src_user, target_user,
          src_ip, dst_ip, raw_alert_count)""")
    con.execute(f"COPY ra TO '{(work / 'raw_alerts.parquet').as_posix()}' (FORMAT PARQUET)")
    con.close()
    card = evaluate(out, gt)
    # T1059.001 detected (two alerts, one-to-one -> 1); T1486 wrong user -> missed; T1110 not detectable
    assert card["counts"]["noise_detectable"] == 2 and card["counts"]["noise_detected"] == 1
    assert card["singleton_recall_pct"] == 50.0 and card["singleton_recall_source"] == "raw_alerts"
    assert card["per_rule_alerts"] == [
        {"rule_id": "office_spawns_script", "alerts": 2, "raw_alert_count": 2},
        {"rule_id": "ransom_rename", "alerts": 1, "raw_alert_count": 300}]


def test_cli_writes_scorecard(tmp_path: Path) -> None:
    out, gt = write(tmp_path, [incident("inc-perfect1", perfect_steps())])
    assert main(["--out", str(out), "--gt", str(gt)]) == 0
    card = json.loads((out / "eval_scorecard.json").read_text(encoding="utf-8"))
    assert card["rebuilt_pct"] == 100.0


def test_scorecard_top_level_keys_pinned(tmp_path: Path) -> None:
    """DEVELOPMENT.md §15.6: the UI reads exactly these keys."""
    card = evaluate(*write(tmp_path, [incident("inc-perfect1", perfect_steps())]))
    for k in ("detection_pct", "labels_pct", "rebuilt_pct", "false_alarms_strict_pct", "false_alarms_lenient_pct",
              "singleton_recall_pct", "per_attack", "per_rule_alerts", "unmatched_incidents", "targets"):
        assert k in card, k
    for k in ("detection_pct", "labels_pct", "rebuilt_pct", "false_alarms_strict_pct", "false_alarms_lenient_pct"):
        assert isinstance(card[k], float) and 0.0 <= card[k] <= 100.0, k
    assert card["singleton_recall_pct"] is None  # no noise GT given
    assert set(card["targets"]) == {"detection_pct", "labels_pct", "rebuilt_pct", "false_alarms_strict_pct"}
    assert all(set(v) == {"good", "great"} for v in card["targets"].values())
