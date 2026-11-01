"""Smoke test of tools/cloud_attacks/gen_k8s_and_gcp.py (small scale): deterministic, every file routed to the
right source type, no rows lost, no ground-truth marker in the served events, every ground-truth step anchored on a
served event whose ingested entities equal the step's, and techniques / tactics valid in ATT&CK v20."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from attacklens.config import load_config

from .conftest import accounting, query, run_ingest

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))

from cloud_attacks import gen_k8s_and_gcp as g  # noqa: E402

ROUTE = {"k8s_audit/eks": "k8s_audit_json", "azure_monitor/aksaudit": "k8s_audit_json",
         "gcp_logging/gcp_audit": "gcp_audit_json", "gcp_logging/vpc_flows": "gcp_vpcflow_json",
         "gcp_logging/firewall": "gcp_firewall_json", "gcp_logging/dns_queries": "gcp_dns_json",
         "gcp_scc": "gcp_scc_json"}
GT_KEYS = {"threat", "rule", "labels_extra", "technique_id", "attack_id", "story", "ground_truth"}


def _digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*.jsonl")):
        h.update(p.relative_to(root).as_posix().encode() + p.read_bytes())
    return h.hexdigest()


@pytest.fixture(scope="module")
def ds(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("k8sgcpgen")
    raw = tmp / "raw"
    man = g.generate(raw, seed=3, days=7, scale=0.2)
    ctx = run_ingest(raw, tmp)
    yield {"raw": raw, "man": man, "ctx": ctx, "tmp": tmp}
    ctx.con.close()


def test_deterministic(ds) -> None:
    again = ds["tmp"] / "again"
    g.generate(again, seed=3, days=7, scale=0.2)
    assert _digest(again) == _digest(ds["raw"])
    other = ds["tmp"] / "other"
    g.generate(other, seed=4, days=7, scale=0.2)
    assert _digest(other) != _digest(ds["raw"])


def test_routed_and_no_rows_lost(ds) -> None:
    prof = json.loads((ds["ctx"].out_dir / "source_profile.json").read_text(encoding="utf-8"))
    for f in prof["files"]:
        assert f["source_type"] == ROUTE[f["rel"].rsplit("/", 1)[0]], f["rel"]
    acc = accounting(ds["ctx"])
    assert sum(v["rows_in"] for v in acc.values()) == ds["man"]["total_events"]
    for stype, v in acc.items():
        assert v["rows_in"] == v["rows_ok"] and v["dropped"] == 0, (stype, v)


def test_no_ground_truth_marker_served(ds) -> None:
    for p in ds["raw"].rglob("*.jsonl"):
        for line in p.read_text(encoding="utf-8").splitlines():
            doc = json.loads(line)
            assert not GT_KEYS & set(doc), p
            labels = doc.get("labels")
            assert labels is None or set(labels) <= {"authorization.k8s.io/decision",
                                                     "authorization.k8s.io/reason"}, p   # GKE vendor labels only
            assert "K1" not in line.split('"')[1::2] and "attacks.json" not in line


def test_ground_truth_anchored_and_valid(ds) -> None:
    gt = json.loads((ds["raw"] / "ground_truth" / "attacks.json").read_text(encoding="utf-8"))
    tech = load_config()["attack"]["techniques"]
    assert len(gt["attacks"]) == 5 and sum(len(a["steps"]) for a in gt["attacks"]) == 18
    for atk in gt["attacks"]:
        for s in atk["steps"]:
            t = tech[s["technique_id"]]
            assert s["tactic"] in (t.get("tactics") or [t.get("tactic")]), s
            rows = query(ds["ctx"], "SELECT host, coalesce(src_user, target_user) AS u, src_ip FROM events "
                                    "WHERE abs(ts_ms - ?) <= 1 AND (raw_line LIKE ? OR raw_line LIKE ?)",  # ns rounding
                         [s["ts_ms"], f'%"{s["event_id"]}"%', f'%{s["event_id"].split(":")[0][:30]}%'])
            assert rows, (atk["id"], s["step"])
            want = (s["host"], (s["user"] or "").split("@")[0].lower() or None, s["src_ip"])
            assert (rows[0]["host"], rows[0]["u"], rows[0]["src_ip"]) == want, (atk["id"], s["step"], rows[0])
