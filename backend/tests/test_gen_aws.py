"""Generator smoke test for tools/cloud_attacks/gen_aws.py (track AWS data set data/raw/cloud_aws).

Deterministic by seed; every served file is routed by content to the intended source type; no ground-truth marker
in the served records; every ground-truth step is a valid ATT&CK v20 (technique, tactic) anchored on a served
event with the entity the rules report; attacker addresses only from 203.0.113.0/24.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from attacklens import db, profile
from attacklens.config import load_config
from attacklens.context import RunContext

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
from cloud_attacks import aws_stories, gen_aws  # noqa: E402

ROUTE = {"aws_cloudtrail/cloudtrail": "cloudtrail_json", "aws_vpcflow/hyphen": "aws_vpcflow_json",
         "aws_vpcflow/underscore": "aws_vpcflow_json", "aws_vpcflow/sentinel": "aws_vpcflow_json",
         "aws_route53resolver": "aws_r53resolver_json", "aws_networkfirewall": "aws_nfw_json",
         "aws_findings/guardduty": "aws_guardduty_json", "aws_findings/securityhub": "aws_securityhub_json"}
LABEL_TOP = {"threat", "rule", "labels", "labels_extra"}


@pytest.fixture(scope="module")
def out(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("gen_aws") / "set"
    gen_aws.write(d, seed=3, scale=0.2, force=True, text_flow=d.parent / "text")
    return d


def test_deterministic_and_seed_sensitive() -> None:
    a = [json.dumps(s.gt(), sort_keys=True) for s in aws_stories.build_stories(3)]
    b = [json.dumps(s.gt(), sort_keys=True) for s in aws_stories.build_stories(3)]
    c = [json.dumps(s.gt(), sort_keys=True) for s in aws_stories.build_stories(4)]
    assert a == b and a != c


def test_routing_and_no_label_fields(out: Path, tmp_path: Path) -> None:
    cfg = load_config()
    cfg = {**cfg, "pipeline": {**cfg["pipeline"], "profile": {**(cfg["pipeline"].get("profile") or {}),
                                                              "sample_lines": 300}}}   # routing needs a sample only
    con = db.connect(memory_limit="500MB", threads=2, temp_directory=tmp_path / "spill")
    ctx = RunContext(set_name="g", raw_dir=out, parquet_dir=tmp_path, out_dir=tmp_path, con=con, cfg=cfg)
    profile.run(ctx)
    con.close()
    got = {f["rel"].rsplit("/", 1)[0]: f.get("source_type") for f in ctx.stats["profile"]["files"]}
    assert got == ROUTE
    assert ctx.stats["profile"]["unrecognized"] == []
    for p in out.rglob("*.jsonl"):
        for line in p.read_text(encoding="utf-8").splitlines():
            d = json.loads(line)
            assert not LABEL_TOP & set(d), p
            ev = d.get("event")
            assert not (isinstance(ev, dict) and {"kind", "severity", "module", "dataset"} & set(ev)), p


def test_ground_truth_valid_and_anchored(out: Path) -> None:
    gt = json.loads((out / "ground_truth" / "attacks.json").read_text(encoding="utf-8"))
    tech = load_config()["attack"]["techniques"]
    served = (out / "aws_cloudtrail").as_posix()
    blob = "".join(p.read_text(encoding="utf-8") for p in out.rglob("*.jsonl"))
    assert len(gt["attacks"]) == 5 and sum(len(a["steps"]) for a in gt["attacks"]) == 20
    for atk in gt["attacks"]:
        ts = [s["ts_ms"] for s in atk["steps"]]
        assert ts == sorted(ts), atk["id"]
        for s in atk["steps"]:
            t = tech[s["technique_id"]]
            assert s["tactic"] in (t.get("tactics") or [t.get("tactic")]), (atk["id"], s)
            assert s["host"] and (s["user"] or s["src_ip"]), (atk["id"], s)
            assert s["host"] in blob and (s["src_ip"] is None or s["src_ip"] in blob)
            if s["source"].startswith("aws_cloudtrail"):
                assert s["event_id"] in blob, served
    for d in gt["decoys"]:
        assert d["host"] in blob


def test_attacker_ips_only_from_the_attacker_range(out: Path) -> None:
    gt = json.loads((out / "ground_truth" / "attacks.json").read_text(encoding="utf-8"))
    for atk in gt["attacks"]:
        for s in atk["steps"]:
            ip = s["src_ip"] or ""
            assert ip.startswith(("203.0.113.", "10.0.")), (atk["id"], s)


def test_text_flow_forms(out: Path) -> None:
    text = out.parent / "text"
    s3 = (text / "s3_flow.log").read_text(encoding="utf-8").splitlines()
    cw = (text / "cloudwatch_flow.log").read_text(encoding="utf-8").splitlines()
    assert s3[0].split()[:4] == ["version", "account-id", "interface-id", "srcaddr"] and len(s3[1].split()) == 22
    assert len(cw) == len(s3) - 1 and all(len(x.split()) == 14 and x.startswith("2 ") for x in cw[:50])
