"""tools/review_findings.py: markdown findings for an output dir without ground truth (DEVELOPMENT.md §15.9).
Exact content on a tiny synthetic out dir; confidentiality (no evidence / raw text); --redact-ips; escaping."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import duckdb
import pytest

from attacklens.models import Incident, IncidentSummary, dump

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import review_findings as rf  # noqa: E402

MOCK = REPO / "frontend" / "src" / "mock" / "incident.json"
SECRET = "SECRET-EVIDENCE-7f3a"
EVIL_USER = "a|b\n<script>x</script>"


def _step(k: int, tactic: str, tech: str, rule: str, host: str, user: str | None, src: str | None,
          dst: str | None, n: int) -> dict:
    return {"step": k, "episode_id": f"e{k}{rule[:3]}", "ts": f"2026-10-24T0{2 + k}:00:00Z", "technique_id": tech,
            "sub_technique_id": None, "technique_name": None, "tactic": tactic, "rule_id": rule, "host": host,
            "user": user, "src_ip": src, "dst_ip": dst, "severity": 80, "confidence": 80, "merged_alert_count": n,
            "evidence": [f"{SECRET} raw line {k}"]}


def _incident(base: dict, inc_id: str, risk: int, backbone: list[dict]) -> dict:
    d = copy.deepcopy(base)
    d.update({"id": inc_id, "risk": risk, "backbone": backbone, "branches": [], "edges": [],
              "first_ts": backbone[0]["ts"], "last_ts": backbone[-1]["ts"], "episode_count": len(backbone),
              "merged_alert_count": sum(s["merged_alert_count"] for s in backbone),
              "tactics": sorted({s["tactic"] for s in backbone}),
              "entry_point": {"step": 0, "summary": f"{SECRET} entry"},
              "narrative": {"text": f"{SECRET} narrative", "source": "template"}})
    return dump(Incident.model_validate(d))


@pytest.fixture
def out(tmp_path: Path) -> Path:
    base = json.loads(MOCK.read_text(encoding="utf-8"))
    a = _incident(base, "inc-aaaa0001", 90, [
        _step(0, "Credential Access", "T1110", "fw_admin_bruteforce", "fgt-01", "admin", "203.0.113.9", None, 60),
        _step(1, "Initial Access", "T1078", "fw_admin_bruteforce", "fgt-01", "admin", "203.0.113.9", None, 1),
        _step(2, "Exfiltration", "T1048", "exfil_volume", "10.0.2.15", None, "10.0.2.15", "198.51.100.150", 3)])
    b = _incident(base, "inc-bbbb0002", 40, [
        _step(0, "Execution", "T1059", "encoded_powershell", "ws-01", EVIL_USER, "10.0.1.5", "203.0.113.9", 1),
        _step(1, "Execution", "T1059", "office_spawns_script", "ws-01", "pmehta", None, None, 1)])
    (tmp_path / "incidents").mkdir()
    for inc in (a, b):
        (tmp_path / "incidents" / f"{inc['id']}.json").write_text(json.dumps(inc), encoding="utf-8")
    index = [dump(IncidentSummary(id=i["id"], risk=i["risk"], first_ts=i["first_ts"], last_ts=i["last_ts"],
                                  merged_alert_count=i["merged_alert_count"], episode_count=i["episode_count"],
                                  tactics=i["tactics"], hosts=[], entry_summary=f"{SECRET} summary"))
             for i in (a, b)]
    (tmp_path / "incidents_index.json").write_text(json.dumps(index), encoding="utf-8")
    (tmp_path / "run_metrics.json").write_text(json.dumps({
        "set": "fx", "total_wall_s": 12.5, "peak_rss_mb": 900.0, "rows_per_s": 1000.0, "episodes": 7,
        "episodes_spilled": 0, "stages": [{"name": "ingest", "wall_s": 3.2, "peak_rss_mb": 800.0}],
        "stage_stats": {"incidents": {"components": 5, "kept": 2, "suppressed": 3}}}), encoding="utf-8")
    (tmp_path / "ingest_accounting.json").write_text(json.dumps([
        {"source_type": "fortigate_kv", "rows_in": 100, "rows_ok": 98, "dropped": 2,
         "drop_reasons": {"malformed_line": 2}}]), encoding="utf-8")
    (tmp_path / "suppressed.json").write_text(json.dumps({
        "total": 3, "by_reason": {"fewer than 2 tactics": 2, "allowlisted": 1},
        "components": [{"episode_ids": ["e9"], "reason": f"{SECRET} reason"}]}), encoding="utf-8")
    (tmp_path / "work").mkdir()
    con = duckdb.connect()
    con.execute(f"""COPY (SELECT * FROM (VALUES ('port_scan', 20::BIGINT, ['{SECRET} ev']),
                                                ('port_scan', 25::BIGINT, ['{SECRET} ev']),
                                                ('av_malware_download', 1::BIGINT, ['{SECRET} ev']))
                    t(rule_id, raw_alert_count, evidence_lines))
                    TO '{(tmp_path / 'work' / 'raw_alerts.parquet').as_posix()}' (FORMAT PARQUET)""")
    con.close()
    return tmp_path


def test_report_sections_exact(out: Path) -> None:
    md = rf.build_report(out)
    assert md.startswith("# Findings — fx\n")
    for line in ("| ingest | 3.2 | 800.0 |",
                 "| fortigate_kv | 100 | 98 | 2 | malformed_line: 2 |",
                 "| port_scan | 2 | 45 |", "| av_malware_download | 1 | 1 |",
                 "- Episodes kept: 7; spilled: 0",
                 "- Components: 5; kept: 2; suppressed: 3; incidents: 2",
                 "| fewer than 2 tactics | 2 |", "| allowlisted | 1 |",
                 "## Top 2 incidents (by risk)",
                 "### 1. inc-aaaa0001 — risk 90", "### 2. inc-bbbb0002 — risk 40",
                 "- Tactic chain: Credential Access → Initial Access → Exfiltration",
                 "- Steps: 3 on the path + 0 on branches; 3 episodes; 64 merged alerts",
                 "- Hosts: 10.0.2.15, fgt-01", "- IPs: 10.0.2.15, 198.51.100.150, 203.0.113.9", "- Users: admin",
                 "- Tactic chain: Execution"):
        assert line in md, line
    assert md.index("inc-aaaa0001") < md.index("inc-bbbb0002")


def test_checklist_hints(out: Path) -> None:
    md = rf.build_report(out)
    a, b = md.split("### 2.")
    assert "- [x] multi-tactic (3 distinct tactics)" in a
    assert "- [x] external-IP entry point (203.0.113.9)" in a
    assert "- [x] dominated by one rule (> 80 % of alerts): top rule `fw_admin_bruteforce` 95 % of 64 alerts" in a
    assert "- [ ] multi-tactic (1 distinct tactics)" in b
    assert "- [ ] external-IP entry point (entry src 10.0.1.5)" in b
    assert "- [ ] dominated by one rule (> 80 % of alerts): top rule `encoded_powershell` 50 % of 2 alerts" in b
    assert "not a score" in md


def test_no_evidence_or_raw_text_anywhere(out: Path) -> None:
    for redact in (False, True):
        md = rf.build_report(out, redact_ips=redact)
        assert SECRET not in md and "raw line" not in md and "narrative" not in md.lower().replace(
            "no evidence or raw log text", "")


def test_redact_ips_stable_placeholders(out: Path) -> None:
    md = rf.build_report(out, redact_ips=True)
    for ip in ("203.0.113.9", "198.51.100.150"):
        assert ip not in md
    assert "- IPs: 10.0.2.15, ext-1, ext-2" in md                  # internal kept; numbered by first appearance
    assert "(ext-1)" in md.split("### 2.")[0]                      # entry point uses the same placeholder
    assert "10.0.1.5 → ext-1" in md.split("### 2.")[1]             # same IP in another incident -> same ext-1
    assert "Public IPs redacted as ext-N." in md


def test_escaping_of_hostile_entity_values(out: Path) -> None:
    md = rf.build_report(out)
    assert "<script>" not in md and "a\\|b&lt;script&gt;x&lt;/script&gt;" in md
    for row in (ln for ln in md.splitlines() if ln.startswith("| 0 | 2026-10-24T02:00:00Z | T1059")):
        assert row.count(" | ") == 8  # the pipe in the username did not add a column


@pytest.mark.parametrize("ip,kind", [("10.1.2.3", "internal"), ("172.20.0.1", "internal"), ("192.168.1.1", "internal"),
                                     ("127.0.0.1", "internal"), ("203.0.113.9", "external"), ("8.8.8.8", "external"),
                                     ("198.51.100.1", "external"), ("srv-dc-01", None), (None, None)])
def test_ip_kind(ip, kind) -> None:
    assert rf.ip_kind(ip) == kind


def test_top_limit_and_missing_raw_alerts(out: Path) -> None:
    (out / "work" / "raw_alerts.parquet").unlink()
    md = rf.build_report(out, top=1)
    assert "## Top 1 incidents (by risk)" in md and "inc-bbbb0002" not in md
    assert "work/raw_alerts.parquet not found." in md


def test_cli_writes_lf_markdown(out: Path, tmp_path: Path) -> None:
    assert rf.main(["--out", str(out), "--redact-ips"]) == 0
    b = (out / "findings.md").read_bytes()
    assert b"\r" not in b and b.endswith(b"\n") and b"203.0.113.9" not in b
    dest = tmp_path / "reports" / "fx_findings.md"
    assert rf.main(["--out", str(out), "--md", str(dest)]) == 0 and dest.exists()
    assert rf.main(["--out", str(tmp_path / "nope")]) == 2
