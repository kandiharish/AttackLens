"""Single-step critical allow-list (config/linking.yaml gate.single_step_critical): an allow-listed critical
technique at confidence >= min_confidence forms a 1-step incident; everything else keeps the literal gate."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from attacklens import config, incidents, link
from attacklens.incident_gate import single_step, single_step_params

from .conftest import make_events_parquet, write_episodes

T0 = 1792807200000


@pytest.fixture(scope="module")
def cfg() -> dict[str, Any]:
    return config.load_config()


@pytest.fixture(scope="module")
def p(cfg: dict[str, Any]) -> dict[str, Any]:
    return incidents._params(cfg)


def _ep(i: str, tech: str, sub: str | None, tactic: str, conf: float, merged: int = 1) -> dict[str, Any]:
    return {"episode_id": i, "ts_ms": T0, "host": "ws-fin-010", "tactic": tactic, "technique_id": tech,
            "sub_technique_id": sub, "rule_id": f"r_{i}", "src_user": "kiyer", "severity": 90, "confidence": conf,
            "merged_alert_count": merged}


def _gate(eps: list[dict[str, Any]], p: dict[str, Any]) -> str | None:
    return incidents._gate_ids([e["episode_id"] for e in eps], {e["episode_id"]: e for e in eps}, set(), p)[0]


def _with(cfg: dict[str, Any], ss: dict[str, Any]) -> dict[str, Any]:
    c = copy.deepcopy(cfg)
    c["linking"]["gate"]["single_step_critical"] = ss
    return incidents._params(c)


# ------------------------------------------------------------------ gate decisions
def test_listed_technique_at_min_confidence_kept(p: dict[str, Any]) -> None:
    assert p["ss_conf"] == 80
    assert _gate([_ep("a", "T1003", "T1003.001", "Credential Access", 80)], p) is None


def test_listed_technique_below_min_confidence_suppressed(p: dict[str, Any]) -> None:
    reason = _gate([_ep("a", "T1003", "T1003.001", "Credential Access", 79)], p)
    assert reason is not None and reason.startswith("fewer than")


def test_unlisted_technique_at_95_still_suppressed(p: dict[str, Any]) -> None:
    # PowerShell (T1059.001) at 95 with one merged alert: still the critical-path rule (merged < 5)
    reason = _gate([_ep("a", "T1059", "T1059.001", "Execution", 95)], p)
    assert reason is not None and reason.startswith("critical single-tactic")
    # ... and below critical: the 2-tactic rule
    reason = _gate([_ep("a", "T1059", "T1059.001", "Execution", 85)], p)
    assert reason is not None and reason.startswith("fewer than")


def test_gate_function_flag_only_bypasses_tactic_rule() -> None:
    p = incidents._params(config.load_config())
    assert incidents.gate({"Credential Access"}, 80, False, p, 1, False, True) is None
    assert incidents.gate({"Credential Access"}, 80, True, p, 1, False, True).startswith("allowlisted")
    assert incidents.gate({"Credential Access"}, 80, False, p, 1, False, False) is not None


def test_sub_technique_prefix_match(p: dict[str, Any]) -> None:
    # parent entry T1003 covers every sub-technique; a sub-technique entry matches only itself
    assert single_step([_ep("a", "T1003", "T1003.006", "Credential Access", 85)], p)
    assert single_step([_ep("a", "T1685", "T1685.002", "Defense Impairment", 85)], p)
    assert not single_step([_ep("a", "T1685", None, "Defense Impairment", 85)], p)          # parent only
    assert not single_step([_ep("a", "T1685", "T1685.003", "Defense Impairment", 85)], p)   # sibling sub
    q = single_step_params({"techniques": ["T100"]}, {})
    assert not single_step([_ep("a", "T1003", "T1003.001", "Credential Access", 99)], {**p, **q})  # no bare prefix


def test_per_entry_min_confidence_raises_bar(p: dict[str, Any]) -> None:
    assert ("T1078.004", 90.0) in p["ss_techniques"]
    assert not single_step([_ep("a", "T1078", "T1078.004", "Initial Access", 89)], p)
    assert single_step([_ep("a", "T1078", "T1078.004", "Initial Access", 90)], p)
    q = single_step_params({"min_confidence": 80, "techniques": [{"id": "T1003", "min_confidence": 50}]}, {})
    assert q["ss_techniques"] == [("T1003", 80.0)]  # an entry can only raise the bar, never lower it


def test_listed_set_comes_only_from_config(cfg: dict[str, Any], p: dict[str, Any]) -> None:
    ss = cfg["linking"]["gate"]["single_step_critical"]
    want = [(str(t["id"] if isinstance(t, dict) else t).upper(),
             max(float(ss["min_confidence"]), float(t.get("min_confidence", 0)) if isinstance(t, dict) else 0))
            for t in ss["techniques"]]
    assert p["ss_techniques"] == want
    assert single_step_params({}, {})["ss_techniques"] == [] and single_step_params({}, {})["ss_tactics"] == set()
    lsass = [_ep("a", "T1003", "T1003.001", "Credential Access", 95)]
    assert _gate(lsass, _with(cfg, {"techniques": []})) is not None
    assert _gate(lsass, _with(cfg, {**ss, "enabled": False})) is not None
    other = _with(cfg, {"min_confidence": 80, "techniques": ["T1059"]})
    assert _gate([_ep("a", "T1059", "T1059.001", "Execution", 80)], other) is None
    assert _gate(lsass, other) is not None


def test_whole_tactic_by_ta_id(cfg: dict[str, Any]) -> None:
    q = _with(cfg, {"min_confidence": 80, "techniques": [], "tactics": ["TA0112"]})
    assert q["ss_tactics"] == {"Defense Impairment"}
    assert _gate([_ep("a", "T1222", None, "Defense Impairment", 80)], q) is None
    assert _gate([_ep("a", "T1222", None, "Defense Impairment", 79)], q) is not None
    assert _gate([_ep("a", "T1059", None, "Execution", 85)], q) is not None


# ------------------------------------------------------------------ Stage 4 end to end
def _stage4(tmp: Path, eps: list[dict[str, Any]]) -> tuple[dict, list, dict]:
    ctx = make_events_parquet(tmp, [{"ts_ms": T0 - 3_600_000, "action": "login_success", "host": "ws-fin-010",
                                     "target_user": "kiyer", "logon_type": 2, "event_id": 4624}])
    write_episodes(ctx, eps)
    try:
        link.run(ctx)
        stats = incidents.run(ctx)
        data = json.loads((ctx.work_dir / "incidents.json").read_text(encoding="utf-8"))
        sup = json.loads((ctx.out_dir / "suppressed.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    return stats, data, sup


def test_stage4_single_step_incident_is_flagged(tmp_path: Path, p: dict[str, Any]) -> None:
    stats, data, sup = _stage4(tmp_path, [_ep("lsass", "T1003", "T1003.001", "Credential Access", 80)])
    assert len(data) == 1 and sup["total"] == 0
    assert stats["kept_via_single_step"] == 1 and stats["kept_via_burst"] == 0
    assert [s["episode_id"] for s in data[0]["backbone"]] == ["lsass"]
    assert data[0]["entry_point"]["summary"].startswith(f"{p['ss_label']}: ")


def test_stage4_below_min_confidence_suppressed(tmp_path: Path) -> None:
    stats, data, sup = _stage4(tmp_path, [_ep("lsass", "T1003", "T1003.001", "Credential Access", 79)])
    assert data == [] and stats["kept_via_single_step"] == 0
    assert sup["components"][0]["reason"].startswith("fewer than")


def test_stage4_two_tactic_incident_not_flagged(tmp_path: Path, p: dict[str, Any]) -> None:
    # passes the literal gate (2 tactics, seed): no single-step label even though it holds an allow-listed step
    eps = [_ep("lsass", "T1003", "T1003.001", "Credential Access", 85),
           {**_ep("ps", "T1059", "T1059.001", "Execution", 70), "ts_ms": T0 + 60_000}]
    stats, data, _ = _stage4(tmp_path, eps)
    assert len(data) == 1 and len(data[0]["tactics"]) == 2 and stats["kept_via_single_step"] == 0
    assert all(not d["entry_point"]["summary"].startswith(p["ss_label"]) for d in data)


# ------------------------------------------------------------------ context-only rules (gate.context_only_rules)
def _ua(conf: float = 75) -> dict[str, Any]:
    return {**_ep("ua", "T1059", "T1059.009", "Execution", conf), "rule_id": "cl_attack_tool_user_agent"}


def test_context_only_rules_come_from_config(cfg: dict[str, Any], p: dict[str, Any]) -> None:
    assert p["context_only"] == set(cfg["linking"]["gate"]["context_only_rules"])
    assert "cl_attack_tool_user_agent" in p["context_only"]
    assert incidents._params({**cfg, "linking": {**cfg["linking"], "gate": {}}})["context_only"] == set()


def test_tool_user_agent_never_donates_the_second_tactic(cfg: dict[str, Any], p: dict[str, Any]) -> None:
    # decisive single cloud action + attack-tool user agent: 2 raw tactics, but only 1 counted
    unlisted = {**_ep("act", "T1098", "T1098.003", "Privilege Escalation", 85), "rule_id": "aws_role_trust_backdoor"}
    reason = _gate([unlisted, _ua()], p)
    assert reason is not None and reason.startswith("fewer than")
    # same pair without the context-only list: the literal 2-tactic rule would have kept it
    assert _gate([unlisted, _ua()], {**p, "context_only": set()}) is None


def test_tool_user_agent_plus_listed_action_passes_only_via_single_step(cfg: dict[str, Any], p: dict[str, Any]) -> None:
    share = {**_ep("act", "T1537", None, "Exfiltration", 85), "rule_id": "cl_snapshot_image_share_external"}
    assert _gate([share, _ua()], p) is None
    assert _gate([share, _ua()], _with(cfg, {"techniques": []})) is not None   # not via the 2-tactic rule


def test_stage4_tool_user_agent_component_flagged_single_step(tmp_path: Path, p: dict[str, Any]) -> None:
    share = {**_ep("act", "T1537", None, "Exfiltration", 85), "rule_id": "cl_snapshot_image_share_external"}
    stats, data, _ = _stage4(tmp_path, [share, {**_ua(), "ts_ms": T0 + 60_000}])
    assert len(data) == 1 and data[0]["episode_count"] == 2 and stats["kept_via_single_step"] == 1
    assert data[0]["entry_point"]["summary"].startswith(f"{p['ss_label']}: ")
