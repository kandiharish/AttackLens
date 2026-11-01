"""Smoke test of the Azure dataset generator (tools/cloud_attacks/gen_azure.py, azure_feeds.py, azure_stories.py):
deterministic by seed, every bucket routed by Stage 0 to its source type with no row lost, no ground-truth marker in
served records, attacker IPs only in the reserved range, and every ground-truth step anchored on a served record and
labelled with a v20 technique / tactic."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

from attacklens.config import load_config

from .conftest import accounting, run_ingest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

from cloud_attacks import gen_azure  # noqa: E402

SEED, SCALE = 11, 0.05
ROUTE = {"signinlogs": "azure_signin_json", "aadnoninteractiveusersigninlogs": "azure_signin_json",
         "aadserviceprincipalsigninlogs": "azure_signin_json", "aadmanagedidentitysigninlogs": "azure_signin_json",
         "auditlogs": "azure_activity_json", "azureactivity": "azure_activity_json",
         "administrative": "azure_activity_json", "azkvauditlogs": "azure_keyvault_json",
         "keyvault_auditevent": "azure_keyvault_json", "azurediagnostics": "azure_keyvault_json",
         "microsoftgraphactivitylogs": "azure_graph_json", "aaduserriskevents": "azure_risk_json",
         "aadserviceprincipalriskevents": "azure_risk_json", "riskdetections": "azure_risk_json",
         "aadriskyusers": "azure_risk_json"}
LABEL_RX = re.compile(r'"(threat|rule|labels|labels_extra)"\s*:|"event"\s*:\s*\{[^}]*"(kind|severity)"')


@pytest.fixture(scope="module")
def ds(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("gen_azure")
    m = gen_azure.write(tmp / "raw", SEED, SCALE, force=False)
    ctx = run_ingest(tmp / "raw", tmp)
    yield {"tmp": tmp, "raw": tmp / "raw", "manifest": m, "ctx": ctx}
    ctx.con.close()


def _digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*.jsonl")):
        h.update(p.relative_to(root).as_posix().encode() + p.read_bytes())
    return h.hexdigest()


def test_deterministic_by_seed(ds, tmp_path) -> None:
    gen_azure.write(tmp_path / "again", SEED, SCALE, force=False)
    gen_azure.write(tmp_path / "other", SEED + 1, SCALE, force=False)
    assert _digest(tmp_path / "again") == _digest(ds["raw"])
    assert _digest(tmp_path / "other") != _digest(ds["raw"])


def test_every_bucket_routed_and_nothing_dropped(ds) -> None:
    prof = json.loads((ds["ctx"].out_dir / "source_profile.json").read_text(encoding="utf-8"))
    seen: dict[str, set] = {}
    for f in prof["files"]:
        if f["rel"].endswith(".jsonl"):
            seen.setdefault(Path(f["rel"]).parent.name, set()).add(f.get("source_type"))
    assert {b: seen.get(b) for b in ROUTE} == {b: {t} for b, t in ROUTE.items()}
    assert not prof["unrecognized"]
    acc = {k: v for k, v in accounting(ds["ctx"]).items() if v["rows_in"]}
    assert set(acc) == set(ROUTE.values())
    for stype, a in acc.items():
        assert a["rows_in"] == a["rows_ok"] and a["dropped"] == 0, (stype, a)
    assert sum(a["rows_in"] for a in acc.values()) == ds["manifest"]["total_events"]


def test_no_ground_truth_marker_and_reserved_attacker_range(ds) -> None:
    gt = json.loads((ds["raw"] / "ground_truth" / "attacks.json").read_text(encoding="utf-8"))
    attacker = {s["src_ip"] for a in gt["attacks"] for s in a["steps"]}
    assert attacker and all(ip.startswith("203.0.113.") for ip in attacker)
    for p in ds["raw"].rglob("*.jsonl"):
        text = p.read_text(encoding="utf-8")
        assert not LABEL_RX.search(text), p
        assert "AZ1" not in text and "ground_truth" not in text
        for ip in re.findall(r"203\.0\.113\.(\d+)", text):
            assert 140 <= int(ip) <= 189, (p, ip)


def test_ground_truth_steps_anchor_on_served_records(ds) -> None:
    gt = json.loads((ds["raw"] / "ground_truth" / "attacks.json").read_text(encoding="utf-8"))
    attack = load_config()["attack"]["techniques"]
    assert [a["id"] for a in gt["attacks"]] == ["AZ1", "AZ2", "AZ3", "AZ4", "AZ5"]
    served = "".join(p.read_text(encoding="utf-8") for p in ds["raw"].rglob("*.jsonl"))
    for a in gt["attacks"]:
        assert a["clouds"] == ["azure"] and len(a["steps"]) >= 3
        for s in a["steps"]:
            assert s["ts"].endswith("Z") and s["host"] and s["src_ip"]
            assert s["tactic"] in (attack[s["technique_id"]].get("tactics") or [attack[s["technique_id"]]["tactic"]])
            assert s["event_id"] in served, (a["id"], s["step"])
    assert {d["id"] for d in gt["decoys"]} >= {"ZD1", "ZD2", "ZD3", "ZD7"}
