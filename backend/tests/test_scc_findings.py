"""GCP SCC findings -> alert spool (attacklens/scc_findings.py, alert-input mode only; config/scc_map.yaml)."""

from __future__ import annotations

import json
import shutil

from attacklens import scc_findings
from attacklens.config import load_config

from .conftest import FIXTURES


def test_scc_findings_to_alert_rows(tmp_path) -> None:
    src = tmp_path / "in"
    src.mkdir()
    shutil.copy(FIXTURES / "cloud" / "k8s_gcp" / "gcp_scc.jsonl", src / "a.jsonl")
    extra = [
        {"jsonPayload": {"finding": {"name": "organizations/1/sources/2/findings/f3", "category": "Escape to host",
                                     "eventTime": "2026-10-24T02:00:18Z", "severity": "HIGH", "state": "ACTIVE",
                                     "mitreAttack": {"primaryTactic": "DEFENSE_EVASION",
                                                     "primaryTechniques": ["ESCAPE_TO_HOST"]}},
                         "resource": {"projectDisplayName": "corp-prod-1234"}}},              # Cloud Logging copy
        {"finding": {"name": "organizations/1/sources/2/findings/f4", "category": "Old", "state": "INACTIVE",
                     "eventTime": "2026-10-24T02:00:19Z", "mitreAttack": {"primaryTechniques": ["BRUTE_FORCE"]}},
         "resource": {"projectDisplayName": "corp-prod-1234"}},                                # resolved: skipped
        {"finding": {"name": "organizations/1/sources/2/findings/f5", "category": "Weird", "state": "ACTIVE",
                     "eventTime": "2026-10-24T02:00:20Z", "mitreAttack": {"primaryTechniques": ["NOT_AN_ENUM"]}},
         "resource": {"projectDisplayName": "corp-prod-1234"}},                                # unknown enum
        {"protoPayload": {"methodName": "x"}},                                                 # not a finding
    ]
    (src / "b.jsonl").write_text("\n".join(json.dumps(x) for x in extra) + "\nnot json\n", encoding="utf-8")
    out = tmp_path / "spool" / "scc.jsonl"
    st = scc_findings.convert([src], out, load_config())
    assert st["lines"] == 7 and st["written"] == 3
    assert st["dropped"] == {"skipped_state": 1, "no_technique": 1, "not_a_finding": 1, "malformed_json": 1}
    rows = {r["rule_id"]: r for r in map(json.loads, out.read_text(encoding="utf-8").splitlines())}
    grant = rows["siem:gcp_scc:SCC Persistence: IAM Anomalous Grant"]
    assert (grant["technique_id"], grant["tactic"], grant["severity"], grant["host"], grant["src_user"],
            grant["src_ip"]) == ("T1098", "Persistence", 80, "corp-prod-1234", "mallory", "203.0.113.70")
    assert grant["ts_ms"] == 1792807216000
    miner = rows["siem:gcp_scc:SCC Execution: Cryptocurrency Mining Combined Detection"]
    assert (miner["technique_id"], miner["tactic"], miner["severity"]) == ("T1496", "Impact", 95)
    esc = rows["siem:gcp_scc:SCC Escape to host"]       # DEFENSE_EVASION is not v20: the technique's tactic wins
    assert (esc["technique_id"], esc["tactic"]) == ("T1611", "Privilege Escalation")


def test_scc_map_ids_exist_in_attack_v20() -> None:
    cfg = load_config()
    tech = cfg["attack"]["techniques"]
    assert all(t in tech for t in cfg["scc_map"]["techniques"].values())
