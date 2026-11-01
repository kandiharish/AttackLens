"""Cloud audit-log ingest (config/sources.yaml json_sources cloudtrail_json / azure_signin_json / azure_activity_json /
gcp_audit_json, per-source maps in attacklens/ingest_maps.py). Fixtures are made up (fixtures/cloud/*.jsonl), one
file per format, routed by content (keys), never by file name."""

from __future__ import annotations

import shutil

import pytest

from .conftest import FIXTURES, accounting, query, run_ingest

FX = FIXTURES / "cloud"
T0 = 1792807200000  # 2026-10-24T02:00:00Z
FILES = {"cloudtrail.jsonl": ("cloudtrail_json", 5), "azure_signin.jsonl": ("azure_signin_json", 3),
         "azure_activity.jsonl": ("azure_activity_json", 3), "gcp_audit.jsonl": ("gcp_audit_json", 3)}


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("cloud")
    raw = tmp / "raw"
    raw.mkdir()
    for i, name in enumerate(FILES):
        shutil.copy(FX / name, raw / f"part-{i}.log")  # neutral names: routing is by content
    c = run_ingest(raw, tmp)
    yield c
    c.con.close()


def rows(ctx, stype: str) -> list[dict]:
    return query(ctx, "SELECT * FROM events WHERE source_type = ? ORDER BY ts_ms", [stype])


def test_every_cloud_file_routed_and_fully_accounted(ctx) -> None:
    acc = {k: v for k, v in accounting(ctx).items() if v["rows_in"]}
    assert set(acc) == {s for s, _ in FILES.values()}
    for stype, n in FILES.values():
        assert acc[stype]["rows_in"] == acc[stype]["rows_ok"] == n, (stype, acc[stype])
        assert acc[stype]["dropped"] == 0
        assert all(r["ts_ok"] for r in rows(ctx, stype))


def test_cloudtrail_mapping(ctx) -> None:
    r = rows(ctx, "cloudtrail_json")
    assert [x["ts_ms"] for x in r] == [T0, T0 + 1000, T0 + 2000, T0 + 3000, T0 + 4000]
    ok, bad, create, attach, add = r
    assert (ok["action"], ok["outcome"], ok["target_user"], ok["src_ip"], ok["host"]) == \
        ("login_success", "success", "alice", "203.0.113.10", "111122223333")
    assert (bad["action"], bad["outcome"], bad["target_user"], bad["src_ip"]) == \
        ("login_failed", "failure", "bob", "203.0.113.66")
    assert (create["action"], create["outcome"], create["src_user"], create["target_user"]) == \
        ("user_created", "success", "alice", "backdoor")
    # errorCode -> failure; API name kept in signature, service in app; AWS service caller is not an IP.
    # AssumedRole: the user is the session name from the ARN (assumed-role/OpsRole/session1), the role is group_name
    assert (attach["action"], attach["outcome"], attach["src_user"], attach["src_ip"], attach["signature"],
            attach["app"]) == ("other", "failure", "session1", None, "AttachUserPolicy", "iam.amazonaws.com")
    assert attach["group_name"] == "opsrole"
    assert (add["action"], add["group_name"], add["target_user"]) == ("group_member_added", "admins", "backdoor")


def test_azure_signin_mapping(ctx) -> None:
    ok, bad, mfa = rows(ctx, "azure_signin_json")
    assert ok["ts_ms"] == T0 + 123                                       # 100 ns precision -> ms
    assert (ok["action"], ok["outcome"], ok["target_user"], ok["src_ip"], ok["host"], ok["app"]) == \
        ("login_success", "success", "alice", "198.51.100.7", "/tenants/aaaa-1111/providers/microsoft.aadiam",
         "azure portal")
    assert (bad["action"], bad["outcome"], bad["target_user"]) == ("login_failed", "failure", "bob")
    assert (mfa["action"], mfa["outcome"]) == ("other", None)            # MFA interrupt: neither outcome


def test_azure_activity_and_audit_mapping(ctx) -> None:
    vm, start, add = rows(ctx, "azure_activity_json")
    assert (vm["action"], vm["outcome"], vm["src_user"], vm["src_ip"], vm["signature"]) == \
        ("other", "success", "alice", "198.51.100.7", "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE")
    assert vm["host"] == "/subscriptions/sub-1/resourcegroups/rg1/providers/microsoft.compute/virtualmachines/vm1"
    assert start["outcome"] is None                                      # "Start" is a progress state
    assert (add["action"], add["outcome"], add["src_user"], add["target_user"], add["src_ip"]) == \
        ("user_created", "success", "alice", "backdoor", "198.51.100.7")


def test_gcp_audit_mapping(ctx) -> None:
    iam, denied, insert = rows(ctx, "gcp_audit_json")
    assert iam["ts_ms"] == T0 + 123                                      # ns precision -> ms
    assert (iam["outcome"], iam["src_user"], iam["src_ip"], iam["host"], iam["signature"], iam["app"]) == \
        ("success", "alice", "192.0.2.10", "acme-prod", "SetIamPolicy", "cloudresourcemanager.googleapis.com")
    assert (denied["outcome"], denied["src_user"], denied["action"]) == ("failure", "mallory", "other")
    assert (insert["outcome"], insert["src_ip"], insert["src_user"]) == ("success", None, "svc-deploy")


def test_cloud_rows_carry_no_label_fields(ctx) -> None:
    for r in query(ctx, "SELECT raw_line FROM events"):
        assert '"threat"' not in r["raw_line"] and '"labels_extra"' not in r["raw_line"]


@pytest.fixture(scope="module")
def ctx2(tmp_path_factory: pytest.TempPathFactory):
    """Org-level GCP entry (no project_id) and Azure Activity progress / timeout states."""
    import json
    tmp = tmp_path_factory.mktemp("cloud2")
    raw = tmp / "raw"
    raw.mkdir()
    gcp = {"insertId": "o-1", "timestamp": "2026-10-24T02:00:00Z", "protoPayload": {
        "methodName": "SetIamPolicy", "serviceName": "cloudresourcemanager.googleapis.com", "status": {},
        "authenticationInfo": {"principalEmail": "root@acme.example"}},
        "resource": {"type": "organization", "labels": {"organization_id": "123456789"}}}
    az = [{"TimeGenerated": f"2026-10-24T02:00:0{i}Z", "OperationNameValue": "MICROSOFT.X/Y/WRITE",
           "ActivityStatusValue": st, "Caller": "alice@contoso.com", "_ItemId": f"x{i}"}
          for i, st in enumerate(["In Progress", "Active", "Resolved", "Timeout"])]
    (raw / "g.log").write_text(json.dumps(gcp) + "\n", encoding="utf-8")
    (raw / "a.log").write_text("\n".join(json.dumps(d) for d in az) + "\n", encoding="utf-8")
    c = run_ingest(raw, tmp)
    yield c
    c.con.close()


def test_gcp_org_level_host_and_azure_states(ctx2) -> None:
    (g,) = rows(ctx2, "gcp_audit_json")
    assert g["host"] == "123456789" and g["outcome"] == "success"
    assert [r["outcome"] for r in rows(ctx2, "azure_activity_json")] == [None, None, None, "failure"]
