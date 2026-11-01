"""AWS findings -> alert-input rows (attacklens/findings_aws.py, config/aws_findings.yaml).

GuardDuty bare / EventBridge / API Findings[] shapes give the same row; repeated deliveries keep the latest update;
Security Hub posture findings are dropped with a reason; OCSF 2004 attacks are read; every finding is accounted for.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from attacklens import findings_aws as fa
from attacklens.config import load_config
from attacklens.detect_sql import RAW_ALERT_COLUMNS

from .conftest import FIXTURES

FX = FIXTURES / "cloud_aws"


@pytest.fixture(scope="module")
def cfg() -> dict:
    return load_config()


def _lines(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_guardduty_shapes_map_to_the_same_row(cfg, tmp_path) -> None:
    bare, eb = _lines(FX / "guardduty.jsonl")
    (tmp_path / "a.jsonl").write_text(json.dumps(eb["detail"]) + "\n", encoding="utf-8")
    (tmp_path / "b.jsonl").write_text(json.dumps(eb) + "\n", encoding="utf-8")
    (tmp_path / "c.json").write_text(json.dumps({"Findings": [eb["detail"]]}, indent=2), encoding="utf-8")
    rows = {}
    for name in ("a.jsonl", "b.jsonl", "c.json"):
        got, st = fa.convert([tmp_path / name], cfg)
        assert st["findings"] == 1 and st["rows"] == 1, st
        rows[name] = got[0]
    assert rows["a.jsonl"] == rows["b.jsonl"] == rows["c.json"]
    r = rows["a.jsonl"]
    assert set(r) == set(RAW_ALERT_COLUMNS)
    assert (r["rule_id"], r["technique_id"], r["sub_technique_id"], r["tactic"], r["severity"]) == \
        ("siem:aws_guardduty:UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", "T1552",
         "T1552.005", "Credential Access", 80)
    assert (r["host"], r["src_user"], r["src_ip"], r["ts_ms"]) == \
        ("111122223333", "web-app-role", "203.0.113.50", 1792807212000)


def test_outbound_portscan_and_latest_update_wins(cfg, tmp_path) -> None:
    bare, _ = _lines(FX / "guardduty.jsonl")
    old = {**bare, "updatedAt": "2026-10-24T02:05:00Z", "severity": 2.0}
    (tmp_path / "f.jsonl").write_text(json.dumps(bare) + "\n" + json.dumps(old) + "\n", encoding="utf-8")
    rows, st = fa.convert([tmp_path], cfg)
    assert st["findings"] == 2 and st["rows"] == 1 and st["dropped"] == {"older_duplicate": 1}
    r = rows[0]
    assert (r["technique_id"], r["tactic"], r["severity"], r["host"], r["src_ip"], r["dst_ip"]) == \
        ("T1046", "Discovery", 50, "i-0abc1234def567890", "10.0.1.12", "10.0.2.21")


def test_securityhub_attack_kept_posture_dropped(cfg, tmp_path) -> None:
    shutil.copy(FX / "securityhub.jsonl", tmp_path / "sh.jsonl")
    rows, st = fa.convert([tmp_path], cfg)
    assert st["findings"] == 2 and st["rows"] == 1 and st["dropped"] == {"posture_finding": 1}
    r = rows[0]
    assert (r["technique_id"], r["sub_technique_id"], r["severity"], r["host"], r["src_ip"]) == \
        ("T1552", "T1552.005", 80, "i-0abc1234def567890", "203.0.113.50")
    assert r["rule_id"].startswith("siem:aws_securityhub:")


def test_attack_sequence_ocsf_and_unknown(cfg, tmp_path) -> None:
    seq = {"schemaVersion": "2.0", "accountId": "111122223333", "id": "gd9", "type": "AttackSequence:S3/CompromisedData",
           "resource": {"accessKeyDetails": {"userName": "svc-media-upload"}},
           "service": {"serviceName": "guardduty", "detectorId": "d1", "eventFirstSeen": "2026-10-24T03:00:00Z",
                       "detection": {"sequence": {"sequenceIndicators": [
                           {"key": "ATTACK_TACTIC", "values": ["Impact"]},
                           {"key": "ATTACK_TECHNIQUE", "values": ["Data Encrypted for Impact"]}]}}},
           "severity": 9.5, "createdAt": "2026-10-24T03:00:00Z", "updatedAt": "2026-10-24T03:00:00Z"}
    ocsf = {"class_uid": 2004, "time": 1792810800000, "severity_id": 4, "cloud": {"account": {"uid": "111122223333"}},
            "finding_info": {"uid": "o1", "title": "Credential access from TOR", "attacks": [
                {"technique": {"uid": "T1078", "name": "Valid Accounts"}, "sub_technique": {"uid": "T1078.004"},
                 "tactic": {"name": "Initial Access"}}]},
            "src_endpoint": {"ip": "203.0.113.9"}, "actor": {"user": {"name": "pmehta@corp.example"}}}
    lines = [json.dumps(seq), json.dumps(ocsf), json.dumps({"hello": "world"}), "{not json"]
    (tmp_path / "x.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    rows, st = fa.convert([tmp_path], cfg)
    assert st["findings"] == 4 and st["rows"] == 2
    assert st["dropped"] == {"not_a_finding": 1, "malformed_json": 1}
    by = {r["rule_id"].split(":")[1]: r for r in rows}
    s = by["aws_guardduty"]
    assert (s["technique_id"], s["tactic"], s["severity"], s["src_user"]) == ("T1486", "Impact", 95, "svc-media-upload")
    o = by["aws_ocsf"]
    assert (o["technique_id"], o["sub_technique_id"], o["tactic"], o["severity"], o["src_user"], o["host"]) == \
        ("T1078", "T1078.004", "Initial Access", 80, "pmehta", "111122223333")


def test_cli_writes_spool(tmp_path) -> None:
    out = tmp_path / "spool" / "aws.jsonl"
    assert fa.main(["--in", str(FX / "guardduty.jsonl"), str(FX / "securityhub.jsonl"), "--out", str(out)]) == 0
    got = [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]
    assert len(got) == 3 and all(r["rule_id"].startswith("siem:aws_") for r in got)
