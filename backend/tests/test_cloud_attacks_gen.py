"""Tests for the cloud attack dataset generator (tools/cloud_attacks/).

Proves the dataset the generator produces is measurable by the existing strict eval harness (backend/eval):
  - deterministic by --seed; a different seed gives different bytes
  - every record is in the exact shape its connector spools, and Stage 0 routes it to the right source
  - ingest loses no rows (rows_in == rows_ok, 0 dropped)
  - NO ground-truth marker leaks into the served events
  - every ground-truth step is anchored on a real served event AND is matchable by eval.match (host + user/ip + time)
  - the near-miss negatives (decoys) are present in the served data
  - the ground truth validates against config/attack_v20.json and the harness loader
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "tools"
sys.path.insert(0, str(TOOLS))

from cloud_attacks import gen, stories as st  # noqa: E402
from cloud_attacks.common import ALL_STAFF  # noqa: E402
from cloud_attacks.formats import entity  # noqa: E402

from eval.match import (GTStep, PredStep, candidates, make_gt_step, norm_host, norm_ip,  # noqa: E402
                        norm_user, parent_technique)

SEED = 7
EXPECTED_ROUTE = {
    "aws_cloudtrail/cloudtrail": "cloudtrail_json",
    "azure_monitor/azure_signinlogs": "azure_signin_json",
    "azure_monitor/azure_auditlogs": "azure_activity_json",
    "azure_monitor/azure_azureactivity": "azure_activity_json",
    "azure_monitor/azure_storagebloblogs": "azure_storageblob_json",
    "gcp_logging/gcp_audit": "gcp_audit_json",
}
CLOUD_SOURCES = set(EXPECTED_ROUTE.values())
# well-known attack API / operation names; a "novel" story must NOT anchor a step on any of these
FAMOUS = {
    "CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "StopLogging",
    "DeleteTrail", "ModifySnapshotAttribute", "CreateLoginProfile", "UpdateLoginProfile", "DeleteDetector",
    "AuthorizeSecurityGroupIngress", "ScheduleKeyDeletion", "CreateFunction20150331", "RunInstances",
    "google.iam.admin.v1.CreateServiceAccountKey", "SetIamPolicy", "storage.setIamPermissions",
    "storage.setIamPolicy", "google.logging.v2.ConfigServiceV2.DeleteSink",
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION", "Add service principal credentials",
    "Consent to application", "Add OAuth2PermissionGrant",
}


# ---------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory):
    out = tmp_path_factory.mktemp("cloud") / "cloud_small"
    manifest = gen.write(out, seed=SEED, size="small", force=True)
    return out, manifest


@pytest.fixture(scope="module")
def served(built):
    """rid -> (feed, doc) for every served record, plus the flat list of docs per feed."""
    out, _ = built
    by_rid: dict[str, tuple[str, dict]] = {}
    per_feed: dict[str, list[dict]] = defaultdict(list)
    feed_of_dir = {"cloudtrail": "cloudtrail", "azure_signinlogs": "signin", "azure_auditlogs": "audit",
                   "azure_azureactivity": "activity", "azure_storagebloblogs": "blob", "gcp_audit": "gcp"}
    for p in out.rglob("*.jsonl"):
        feed = feed_of_dir[p.parent.name]
        for ln in p.read_text(encoding="utf-8").splitlines():
            doc = json.loads(ln)
            rid = {"cloudtrail": doc.get("eventID"), "gcp": doc.get("insertId")}.get(feed) or doc.get("_ItemId")
            by_rid[rid] = (feed, doc)
            per_feed[feed].append(doc)
    return by_rid, per_feed


@pytest.fixture(scope="module")
def ingested(built):
    from attacklens import config, db, ingest, profile
    from attacklens.context import RunContext
    out, _ = built
    tmp = Path(tempfile.mkdtemp())
    con = db.connect(memory_limit="2GB", threads=4, temp_directory=tmp / "spill")
    ctx = RunContext(set_name="cloud", raw_dir=out, parquet_dir=tmp / "pq", out_dir=tmp / "out", con=con,
                     cfg=config.load_config())
    profile.run(ctx)
    ingest.run(ctx)
    db.register_events(ctx.con, ctx.events_glob)
    yield ctx
    con.close()


@pytest.fixture(scope="module")
def gt(built):
    out, _ = built
    return json.loads((out / "ground_truth" / "attacks.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def attack_catalog():
    doc = json.loads((REPO / "config" / "attack_v20.json").read_text(encoding="utf-8"))
    techniques = doc["techniques"]
    tactics = {t["name"] for t in doc["tactics"]}
    return set(techniques), tactics


# ---------------------------------------------------------------- determinism
def test_determinism_same_seed_same_bytes():
    a = [gen.line(e) for e in gen.generate(SEED, 0.05)]
    b = [gen.line(e) for e in gen.generate(SEED, 0.05)]
    assert a == b and len(a) > 500


def test_different_seed_differs():
    a = [gen.line(e) for e in gen.generate(SEED, 0.05)]
    c = [gen.line(e) for e in gen.generate(SEED + 1, 0.05)]
    assert a != c


def test_manifest_size_small_under_50mb(built):
    _, m = built
    assert 5 * 1024 * 1024 < m["total_bytes"] < 50 * 1024 * 1024
    assert m["baseline_scale"] > 0 and m["total_events"] > 10_000
    assert len(m["attacks"]) == 10 and set(m["feeds"]) == set(EXPECTED_ROUTE)


# ---------------------------------------------------------------- routing + accounting
def test_every_file_routed_to_expected_source(ingested):
    sp = json.loads((ingested.out_dir / "source_profile.json").read_text(encoding="utf-8"))
    seen = set()
    for f in sp["files"]:
        key = "/".join(Path(f["rel"]).parts[:2])
        assert f["source_type"] == EXPECTED_ROUTE[key], (f["rel"], f["source_type"])
        seen.add(key)
    assert seen == set(EXPECTED_ROUTE)


def test_ingest_no_dropped_rows(ingested):
    acc = json.loads((ingested.out_dir / "ingest_accounting.json").read_text(encoding="utf-8"))
    rows = acc if isinstance(acc, list) else acc.get("sources", acc.get("accounting", []))
    tot: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for r in rows:
        t = tot[r["source_type"]]
        t[0] += r["rows_in"]; t[1] += r["rows_ok"]; t[2] += r["dropped"]
    assert set(tot) == CLOUD_SOURCES
    for stype, (rin, rok, drop) in tot.items():
        assert rin == rok and drop == 0 and rin > 0, (stype, rin, rok, drop)


# ---------------------------------------------------------------- vendor schema validity
def test_cloudtrail_schema(served):
    _, per = served
    for d in per["cloudtrail"]:
        assert d["eventVersion"] and d["eventName"] and d["eventSource"] and d["eventTime"].endswith("Z")
        assert d["recipientAccountId"] and d["awsRegion"] and d["eventID"] and "userIdentity" in d
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", d["eventTime"])  # whole seconds, UTC


def test_azure_signin_schema(served):
    _, per = served
    for d in per["signin"]:
        assert d["Type"] == "SigninLogs" and d["UserPrincipalName"].endswith("@corp.example")
        assert "ConditionalAccessStatus" in d and d["IPAddress"] and "AlId" not in d
        assert isinstance(d.get("Status"), dict) and re.search(r"\.\d{7}Z$", d["TimeGenerated"])


def test_azure_activity_and_audit_schema(served):
    _, per = served
    for d in per["activity"]:
        assert d["Type"] == "AzureActivity" and d["OperationNameValue"] and d["CallerIpAddress"]
        assert d["ActivityStatusValue"] in {"Start", "Success", "Failure", "Accept"}
    for d in per["audit"]:
        assert d["Type"] == "AuditLogs" and d["LoggedByService"] and isinstance(d["InitiatedBy"], dict)
        assert isinstance(d["TargetResources"], list)


def test_gcp_schema(served):
    _, per = served
    for d in per["gcp"]:
        pp = d["protoPayload"]
        assert pp["@type"].endswith("audit.AuditLog") and pp["methodName"] and pp["serviceName"]
        assert d["resource"]["labels"]["project_id"] and d["timestamp"].endswith("Z")
        assert d["logName"].startswith("projects/") and "cloudaudit.googleapis.com" in d["logName"]


# ---------------------------------------------------------------- no label leakage
def test_no_ground_truth_marker_in_served(built):
    out, _ = built
    # GT-specific markers only (GCP resource.labels is a legitimate field, not a ground-truth label)
    forbidden = re.compile(r"technique_id|\btactic\b|\bthreat\b|labels_extra|\bmitre\b|ground_truth|"
                           r"attack_version|\bdecoys?\b|T1\d{3}")
    whats = {s.what for a in st.build_stories(SEED) for s in a.steps}
    for p in out.rglob("*.jsonl"):
        text = p.read_text(encoding="utf-8")
        m = forbidden.search(text)
        assert not m, f"{p.name}: leaked marker {m.group(0)!r}"
        for w in whats:
            assert w not in text


# ---------------------------------------------------------------- ground-truth schema
def test_ground_truth_loads_and_is_valid(gt, attack_catalog):
    techniques, tactics = attack_catalog
    assert gt["attack_version"] == "v20"
    ids = [a["id"] for a in gt["attacks"]]
    assert ids == [f"A{i}" for i in range(1, 11)]
    seen = set()
    for a in gt["attacks"]:
        steps = a["steps"]
        assert [s["step"] for s in steps] == list(range(1, len(steps) + 1))
        for s in steps:
            assert s["technique_id"] in techniques, s["technique_id"]
            assert parent_technique(s["technique_id"]) in techniques
            assert s["tactic"] in tactics, s["tactic"]
            assert isinstance(s["ts_ms"], int) and s["src_ip"]
            key = (a["id"], s["step"])
            assert key not in seen
            seen.add(key)


def test_harness_loader_accepts_ground_truth(built):
    from eval.harness import load_ground_truth
    out, _ = built
    doc, steps = load_ground_truth(out / "ground_truth" / "attacks.json")
    assert len(steps) == sum(len(a["steps"]) for a in doc["attacks"]) == 43


# ---------------------------------------------------------------- anchors match the events
def test_each_gt_step_anchored_on_a_real_served_event(gt, served):
    by_rid, _ = served
    for a in gt["attacks"]:
        for s in a["steps"]:
            assert s["event_id"] in by_rid, (a["id"], s["step"])
            feed, doc = by_rid[s["event_id"]]
            ent = entity(_ev(feed, doc))
            assert norm_host(ent["host"]) == norm_host(s["host"])
            assert norm_ip(ent["src_ip"]) == norm_ip(s["src_ip"])
            if s["user"] is not None:
                assert norm_user(ent["user"]) == norm_user(s["user"])


def test_every_gt_step_is_matchable_by_the_strict_harness(gt, ingested):
    """Build predictions from the ingested cloud events and run eval.match.candidates: every ground-truth step
    must have at least one candidate (host equal AND user-or-ip AND |dt|<=10min). This is exactly the harness rule,
    so a detector that emits these episodes can be scored."""
    rows = ingested.con.execute(
        "SELECT ts_ms, host, src_user, target_user, src_ip, dst_ip FROM events "
        "WHERE list_contains(?, source_type) AND ts_ms IS NOT NULL", [sorted(CLOUD_SOURCES)]).fetchall()
    preds = []
    for k, (ts, host, su, tu, sip, dip) in enumerate(rows):
        users = [u for u in (norm_user(su), norm_user(tu)) if u]
        preds.append(PredStep(incident_id="ev", episode_id=f"e{k}", order=k, ts_ms=int(ts), technique=None,
                              sub_technique=None, tactic=None, host=norm_host(host),
                              user=users[0] if users else None, alt_users=frozenset(users[1:]),
                              ips=frozenset(x for x in (norm_ip(sip), norm_ip(dip)) if x)))
    gts: list[GTStep] = []
    for a in gt["attacks"]:
        for s in a["steps"]:
            gts.append(make_gt_step(a["id"], s))
    covered = {c.gt.key for c in candidates(gts, preds)}
    missing = [g.key for g in gts if g.key not in covered]
    assert not missing, f"ground-truth steps the strict harness cannot match: {missing}"


# ---------------------------------------------------------------- novel stories
def test_at_least_two_novel_behavioural_stories():
    novel = [s for s in st.build_stories(SEED) if s.novel]
    assert len(novel) >= 2
    for s in novel:
        anchor_actions = {entity(st_.events[0])["action"] for st_ in s.steps}
        assert not (anchor_actions & FAMOUS), (s.id, anchor_actions & FAMOUS)


# ---------------------------------------------------------------- near-miss decoys present
def test_explicit_decoys_present_in_served(gt, served):
    by_rid, _ = served
    explicit = [d for d in gt["decoys"] if not d.get("recurring")]
    assert {d["id"] for d in explicit} == {"D1", "D5", "D6", "D8"}
    for d in explicit:
        assert d["event_id"] in by_rid, d["id"]


def test_recurring_decoys_present_in_served(served):
    by_rid, per = served
    # D2: CI role re-attaches a scoped user policy (AttachUserPolicy by the ci-deploy-role, scoped, not Admin)
    ci_attach = [d for d in per["cloudtrail"] if d["eventName"] == "AttachUserPolicy"
                 and "ci-deploy-role" in json.dumps(d["userIdentity"])
                 and "AdministratorAccess" not in json.dumps(d.get("requestParameters") or {})]
    assert ci_attach, "D2 missing: CI AttachUserPolicy"
    # D3: the real traveller vreddy signs in from Singapore WITH MFA
    travel = [d for d in per["signin"] if d["UserPrincipalName"].startswith("vreddy@")
              and d.get("Location") == "SG" and d["AuthenticationRequirement"] == "multiFactorAuthentication"]
    assert travel, "D3 missing: vreddy Singapore MFA sign-in"
    # D4: svc-backup bulk S3 GetObject from the internal backup host
    backup = [d for d in per["cloudtrail"] if d["eventName"] == "GetObject"
              and (d["userIdentity"].get("userName") == "svc-backup") and d["sourceIPAddress"].startswith("10.")]
    assert len(backup) >= 100, "D4 missing: svc-backup bulk reads"
    # D7: terraform-admin SetIamPolicy from CI
    tf = [d for d in per["gcp"] if d["protoPayload"]["methodName"] == "SetIamPolicy"
          and "terraform-admin" in d["protoPayload"]["authenticationInfo"]["principalEmail"]]
    assert tf, "D7 missing: terraform SetIamPolicy"


def test_known_staff_count_and_uniqueness():
    ids = [u for u, _, _ in ALL_STAFF]
    assert len(ids) == len(set(ids)) >= 40


# wrap a served (feed, doc) pair back into the Ev shape entity() expects
def _ev(feed: str, doc: dict):
    from cloud_attacks.common import Ev
    return Ev(0, feed, "", doc)
