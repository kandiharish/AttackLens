"""Smoke tests for the identity SaaS generator (tools/cloud_attacks/gen_identity_saas.py).

- deterministic by --seed (a different seed changes the bytes)
- every folder routes to its source type in Stage 0; ingest loses no row
- no ground-truth marker in the served records; only RFC 5737 IPs and .example domains
- every ground-truth step is a real served event: same ts, host and user / IP as the ingested row
- the ground truth validates against config/attack_v20.json and the harness loader
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

from attacklens.config import REPO_ROOT

from .conftest import accounting, query, run_ingest

sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from cloud_attacks import gen_identity_saas as gen  # noqa: E402
from eval.harness import load_ground_truth  # noqa: E402
from eval.match import norm_host, norm_user  # noqa: E402

ROUTE = {"okta/system_log": "okta_json", "google_workspace/reports": "gws_reports_json",
         "google_workspace/cloud_logging": "gcp_audit_json", "m365/management_api": "m365_ual_json",
         "m365/officeactivity": "m365_ual_json", "m365/cloudappevents": "m365_ual_json", "auth0/logs": "auth0_json",
         "duo/authentication": "duo_auth_json", "aws_cloudtrail/cloudtrail": "cloudtrail_json"}
IP_RX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


@pytest.fixture(scope="module")
def ds(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("gen_idsaas")
    raw = tmp / "raw"
    gen.write(raw, 7, force=True)
    ctx = run_ingest(raw, tmp)
    yield {"raw": raw, "ctx": ctx, "tmp": tmp}
    ctx.con.close()


def test_deterministic_by_seed(ds, tmp_path: Path) -> None:
    a = tmp_path / "a"
    gen.write(a, 7, force=True)
    for p in sorted(ds["raw"].rglob("*.jsonl")):
        assert (a / p.relative_to(ds["raw"])).read_bytes() == p.read_bytes(), p
    b = tmp_path / "b"
    gen.write(b, 8, force=True)
    assert (b / "okta/system_log/part-0001.jsonl").read_bytes() != (a / "okta/system_log/part-0001.jsonl").read_bytes()


def test_routing_and_no_loss(ds) -> None:
    prof = ds["ctx"].stats["profile"]
    assert not prof["unrecognized"], prof["unrecognized"]
    for f in prof["files"]:
        folder = f["rel"].rsplit("/", 1)[0]
        assert f["source_type"] == ROUTE[folder], (f["rel"], f["source_type"])
    for stype, acc in accounting(ds["ctx"]).items():
        if acc["rows_in"]:
            assert acc["rows_in"] == acc["rows_ok"] and acc["dropped"] == 0, (stype, acc)


def test_no_ground_truth_markers_and_fake_addresses(ds) -> None:
    for p in ds["raw"].rglob("*.jsonl"):
        for line in p.read_text(encoding="utf-8").splitlines():
            d = json.loads(line)
            assert not {"threat", "rule", "labels", "labels_extra"} & set(d), p
            assert "kind" not in (d.get("event") or {}) and "severity" not in (d.get("event") or {}), p
            for ip in IP_RX.findall(line):
                assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "10.")), (p, ip)
            for dom in re.findall(r"@([a-z0-9.-]+\.[a-z]+)", line):
                assert dom.endswith(".example"), (p, dom)


def test_ground_truth_steps_anchor_on_ingested_rows(ds) -> None:
    doc, steps = load_ground_truth(ds["raw"] / "ground_truth" / "attacks.json")
    attack = json.loads((REPO_ROOT / "config" / "attack_v20.json").read_text(encoding="utf-8"))["techniques"]
    assert len(doc["attacks"]) == 5 and len(steps) == sum(len(a["steps"]) for a in doc["attacks"])
    for a in doc["attacks"]:
        for s in a["steps"]:
            t = attack[s["technique_id"]]
            assert s["tactic"] in (t.get("tactics") or [t.get("tactic")]), s
            rows = query(ds["ctx"], "SELECT host, src_user, target_user, src_ip FROM events WHERE ts_ms = ? AND ts_ok",
                         [s["ts_ms"]])
            hit = [r for r in rows if norm_host(r["host"]) == norm_host(s["host"])
                   and ((s["user"] is not None and norm_user(s["user"]) in (r["src_user"], r["target_user"]))
                        or (s["src_ip"] is not None and r["src_ip"] == s["src_ip"]))]
            assert hit, (a["id"], s["step"], s["ts"], rows)


def test_decoys_present(ds) -> None:
    doc = json.loads((ds["raw"] / "ground_truth" / "attacks.json").read_text(encoding="utf-8"))
    assert {d["id"] for d in doc["decoys"]} == {f"ID{i}" for i in range(1, 8)}
    n = query(ds["ctx"], "SELECT count(*) AS n FROM events WHERE source_type = 'okta_json' "
                         "AND signature = 'user.account.privilege.grant'")[0]["n"]
    assert n == 2   # the decoy (help desk role) and the attack (super administrator)
