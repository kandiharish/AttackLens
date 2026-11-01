"""Native cloud detection (attacklens/detect_cloud*.py, config/rules_cloud.yaml, config/cloud.yaml).

One synthetic data set (CloudTrail, Entra sign-ins, Entra audit, Activity Log, GCP audit) goes through the real
Stage 0 + 1 ingest, then run_cloud. Positive actors are named p_*, near-miss actors n_*: each rule family gets one
positive and one near miss. Ten days of routine history come first so baseline rules are past their cold start.
"""

from __future__ import annotations

import copy
import itertools
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb
import pytest

from attacklens import db
from attacklens.detect_sql import RAW_ALERT_COLUMNS

from .conftest import run_ingest

ACCT = "111122223333"
SUB = "9b0e6a51-0000-4000-8000-0000000000b2"
TENANT = "4d5f1c2e-0000-4000-8000-0000000000a1"
T0 = int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp() * 1000)
DAY, HOUR, MIN = 86_400_000, 3_600_000, 60_000
D10 = T0 + 10 * DAY + 9 * HOUR          # "attack day" 09:00 UTC
_ids = itertools.count(1)


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ct(ts: int, api: str, user: str, *, src: str = "iam.amazonaws.com", ip: str = "192.0.2.10",
       rp: Any = None, re: Any = None, err: str | None = None, utype: str = "IAMUser", akid: str | None = None,
       ua: str = "aws-cli/2.15.0 Python/3.11", role: str | None = None, add: Any = None, region: str = "us-east-1",
       pad: int = 0) -> dict[str, Any]:
    ui: dict[str, Any] = {"type": utype, "accountId": ACCT}
    if utype == "AssumedRole":
        ui["arn"] = f"arn:aws:sts::{ACCT}:assumed-role/{role}/{user}"
        ui["sessionContext"] = {"sessionIssuer": {"type": "Role", "userName": role,
                                                  "arn": f"arn:aws:iam::{ACCT}:role/{role}"}}
    else:
        ui.update(userName=user, arn=f"arn:aws:iam::{ACCT}:user/{user}")
    if akid:
        ui["accessKeyId"] = akid
    d: dict[str, Any] = {"eventVersion": "1.09", "userIdentity": ui, "eventTime": iso(ts), "eventSource": src,
                         "eventName": api, "awsRegion": region, "sourceIPAddress": ip, "userAgent": ua,
                         "requestParameters": rp, "responseElements": re, "eventID": f"ev-{next(_ids)}",
                         "eventType": "AwsApiCall", "recipientAccountId": ACCT}
    if err:
        d.update(errorCode=err, errorMessage="denied")
    if add:
        d["additionalEventData"] = add
    if pad:
        d["requestParameters"] = {**(rp or {}), "padding": "x" * pad}
    return d


def login(ts: int, user: str, ok: bool, mfa: str = "No", ip: str = "192.0.2.10") -> dict[str, Any]:
    return ct(ts, "ConsoleLogin", user, src="signin.amazonaws.com", ip=ip, add={"MFAUsed": mfa},
              re={"ConsoleLogin": "Success" if ok else "Failure"})


def si(ts: int, upn: str, code: str = "0", ip: str = "198.51.100.7", cc: str = "IN", lat: float = 12.97,
       lon: float = 77.59, asn: int = 64500, sess: str | None = None, **extra: Any) -> dict[str, Any]:
    return {"TenantId": TENANT, "TimeGenerated": iso(ts), "OperationName": "Sign-in activity", "Category": "SignInLogs",
            "ResultType": code, "UserPrincipalName": upn, "AppDisplayName": "Azure Portal", "AppId": "c44b4083",
            "IPAddress": ip, "ClientAppUsed": "Browser", "AuthenticationRequirement": "multiFactorAuthentication",
            "ConditionalAccessStatus": "success", "AutonomousSystemNumber": asn, "Id": f"si-{next(_ids)}",
            "LocationDetails": {"countryOrRegion": cc, "geoCoordinates": {"latitude": lat, "longitude": lon}},
            "SessionId": sess or f"s-{next(_ids)}", "Type": "SigninLogs",
            "ResourceId": f"/tenants/{TENANT}/providers/Microsoft.aadiam", **extra}


def aza(ts: int, op: str, caller: str, resource: str = "resourcegroups/rg1/providers/microsoft.storage/storageaccounts/a1",
        ip: str = "198.51.100.7", status: str = "Success", req: Any = None) -> dict[str, Any]:
    props: dict[str, Any] = {"eventCategory": "Administrative"}
    if req is not None:
        props["requestbody"] = json.dumps(req)
    return {"TenantId": TENANT, "TimeGenerated": iso(ts), "CategoryValue": "Administrative", "OperationNameValue": op,
            "OperationName": op.title(), "ActivityStatusValue": status, "Caller": caller, "CallerIpAddress": ip,
            "CorrelationId": f"corr-{next(_ids)}", "SubscriptionId": SUB, "Properties_d": props,
            "_ResourceId": f"/subscriptions/{SUB}/{resource}", "Type": "AzureActivity"}


def aud(ts: int, name: str, by: str, targets: list[dict[str, Any]], cat: str = "RoleManagement") -> dict[str, Any]:
    return {"TenantId": TENANT, "TimeGenerated": iso(ts), "OperationName": name, "ActivityDisplayName": name,
            "Category": cat, "Result": "success", "CorrelationId": f"corr-{next(_ids)}", "Id": f"Dir_{next(_ids)}",
            "InitiatedBy": {"user": {"userPrincipalName": by, "ipAddress": "198.51.100.7"}},
            "LoggedByService": "Core Directory", "TargetResources": targets, "AADTenantId": TENANT, "Type": "AuditLogs",
            "ResourceId": f"/tenants/{TENANT}/providers/Microsoft.aadiam"}


def gcp(ts: int, method: str, principal: str, svc: str = "logging.googleapis.com", ip: str = "192.0.2.30",
        code: int | None = None, req: Any = None, delta: Any = None, res: str | None = None) -> dict[str, Any]:
    pp: dict[str, Any] = {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": svc,
                          "methodName": method, "authenticationInfo": {"principalEmail": principal},
                          "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": "google-cloud-sdk gcloud/470"},
                          "resourceName": res or f"projects/acme-prod/{method}", "status": {"code": code} if code else {}}
    if req is not None:
        pp["request"] = req
    if delta is not None:
        pp["serviceData"] = {"policyDelta": {"bindingDeltas": delta}}
    return {"protoPayload": pp, "insertId": f"g-{next(_ids)}", "resource": {"type": "project", "labels": {
        "project_id": "acme-prod"}}, "timestamp": iso(ts),
        "logName": "projects/acme-prod/logs/cloudaudit.googleapis.com%2Factivity"}


def history() -> dict[str, list[dict[str, Any]]]:
    """Ten quiet days: routine reads by alice / prober / nprober, daily sign-ins, routine GCP and Azure calls."""
    out: dict[str, list[dict[str, Any]]] = {"ct": [], "si": [], "aza": [], "aud": [], "gcp": []}
    for d in range(10):
        for i in range(8):
            t = T0 + d * DAY + 9 * HOUR + i * 20 * MIN
            out["ct"].append(ct(t, "DescribeInstances", "alice", src="ec2.amazonaws.com"))
            for who in ("prober", "nprober"):
                out["ct"].append(ct(t + 1000, "ListBuckets", who, src="s3.amazonaws.com", ip="192.0.2.40"))
                out["ct"].append(ct(t + 2000, "DescribeVolumes", who, src="ec2.amazonaws.com", ip="192.0.2.40"))
            out["gcp"].append(gcp(t, "storage.buckets.list", "carol@acme.example", svc="storage.googleapis.com"))
        out["si"].append(si(T0 + d * DAY + 8 * HOUR, "bob@corp.example"))
        out["aza"].append(aza(T0 + d * DAY + 10 * HOUR, "MICROSOFT.COMPUTE/VIRTUALMACHINES/READ", "dave@corp.example"))
    return out


def attacks() -> dict[str, list[dict[str, Any]]]:
    t = D10
    s3_policy = {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess", "userName": "eve"}
    out: dict[str, list[dict[str, Any]]] = {"ct": [], "si": [], "aza": [], "aud": [], "gcp": []}
    c = out["ct"]
    # match: admin policy attached (near miss: read-only policy)
    c.append(ct(t, "AttachUserPolicy", "p_admin", rp=s3_policy))
    c.append(ct(t, "AttachUserPolicy", "n_admin", rp={**s3_policy, "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}))
    # distinct_burst: 12 distinct secrets in 6 min (near miss: one secret read 12 times)
    for i in range(12):
        c.append(ct(t + i * 30_000, "GetSecretValue", "p_secret", src="secretsmanager.amazonaws.com", rp={"secretId": f"s{i}"}))
        c.append(ct(t + i * 30_000, "GetSecretValue", "n_secret", src="secretsmanager.amazonaws.com", rp={"secretId": "s0"}))
    # sequence: stop -> user data change on the SAME instance (near miss: different instance)
    stop = {"instancesSet": {"items": [{"instanceId": "i-0aaa"}]}}
    c.append(ct(t, "StopInstances", "p_udata", src="ec2.amazonaws.com", rp=stop))
    c.append(ct(t + 10 * MIN, "ModifyInstanceAttribute", "p_udata", src="ec2.amazonaws.com",
                rp={"instanceId": "i-0aaa", "attribute": "userData"}))
    c.append(ct(t, "StopInstances", "n_udata", src="ec2.amazonaws.com", rp={"instancesSet": {"items": [{"instanceId": "i-0bbb"}]}}))
    c.append(ct(t + 10 * MIN, "ModifyInstanceAttribute", "n_udata", src="ec2.amazonaws.com",
                rp={"instanceId": "i-0ccc", "attribute": "userData"}))
    # logging tamper then a write by the same actor (B11); near miss: read-only trail call
    c.append(ct(t + HOUR, "StopLogging", "p_trail", src="cloudtrail.amazonaws.com", rp={"name": "main"}))
    c.append(ct(t + HOUR + 5 * MIN, "CreateUser", "p_trail", rp={"userName": "ghost"}))
    c.append(ct(t + HOUR, "DescribeTrails", "n_trail", src="cloudtrail.amazonaws.com"))
    # firewall open to the world on 22 (near miss: 443)
    for who, port in (("p_fw", 22), ("n_fw", 443)):
        c.append(ct(t, "AuthorizeSecurityGroupIngress", who, src="ec2.amazonaws.com", rp={
            "groupId": "sg-1", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": port, "toPort": port,
                                                            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}))
    # snapshot shared with a foreign account (near miss: own account)
    for who, acc in (("p_snap", "999988887777"), ("n_snap", ACCT)):
        c.append(ct(t, "ModifySnapshotAttribute", who, src="ec2.amazonaws.com", rp={
            "snapshotId": "snap-1", "attributeType": "CREATE_VOLUME_PERMISSION",
            "createVolumePermission": {"add": {"items": [{"userId": acc}]}}}))
    # rate_spike: 15 denied calls over 6 APIs in one hour (near miss: 8 denied)
    apis = ["ListUsers", "ListRoles", "GetAccountAuthorizationDetails", "ListPolicies", "CreateUser", "AttachUserPolicy"]
    for i in range(15):
        c.append(ct(t + i * MIN, apis[i % 6], "prober", ip="192.0.2.40", err="AccessDenied"))
    for i in range(8):
        c.append(ct(t + i * MIN, apis[i % 6], "nprober", ip="192.0.2.40", err="AccessDenied"))
    # first_seen: alice calls a new sensitive API (near miss: a routine API); newbie has no history (cold start)
    c.append(ct(t + 2 * HOUR, "CreateAccessKey", "alice", re={"accessKey": {"accessKeyId": "AKIANEWKEY0000000001"}}))
    c.append(ct(t + 2 * HOUR, "DescribeInstances", "alice", src="ec2.amazonaws.com"))
    c.append(ct(t + 2 * HOUR, "CreateAccessKey", "newbie"))
    # multi_network_session: one temporary key from two /16 networks in 10 min (near miss: same /16)
    for who, ips in (("p_sess", ("203.0.113.5", "198.18.0.5")), ("n_sess", ("203.0.113.5", "203.0.113.77"))):
        for k, ip in enumerate(ips):
            c.append(ct(t + k * 5 * MIN, "ListBuckets", who, src="s3.amazonaws.com", ip=ip, utype="AssumedRole",
                        role="AppRole", akid=f"ASIA{who.upper():0<16}"))
    # evidence bound: a very long request
    c.append(ct(t, "AttachUserPolicy", "p_long", rp=s3_policy, pad=5000))
    # Entra sign-ins: brute force then success (near miss: 5 failures); MFA fatigue then success (near miss: 3)
    s = out["si"]
    for i in range(12):
        s.append(si(t + i * 20_000, "p_bf@corp.example", code="50126", ip="203.0.113.9"))
    s.append(si(t + 5 * MIN, "p_bf@corp.example", ip="203.0.113.9"))
    for i in range(5):
        s.append(si(t + i * 20_000, "n_bf@corp.example", code="50126", ip="203.0.113.9"))
    for i in range(6):
        s.append(si(t + HOUR + i * MIN, "p_mfa@corp.example", code="500121"))
    s.append(si(t + HOUR + 8 * MIN, "p_mfa@corp.example"))
    for i in range(3):
        s.append(si(t + HOUR + i * MIN, "n_mfa@corp.example", code="500121"))
    # geo_velocity: Bengaluru -> London in 30 min (near miss: Bengaluru -> Mumbai in 3 h)
    s.append(si(t + 3 * HOUR, "bob@corp.example"))
    s.append(si(t + 3 * HOUR + 30 * MIN, "bob@corp.example", ip="203.0.113.200", cc="GB", lat=51.5, lon=-0.12, asn=64999))
    s.append(si(t + 3 * HOUR, "n_travel@corp.example"))
    s.append(si(t + 6 * HOUR, "n_travel@corp.example", ip="198.51.100.9", cc="IN", lat=19.07, lon=72.87, asn=64501))
    # Azure activity: elevate access (near miss: a read); key listing on 6 accounts (near miss: 2)
    a = out["aza"]
    a.append(aza(t, "MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION", "p_elev@corp.example", resource="providers/microsoft.authorization"))
    a.append(aza(t, "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/READ", "n_elev@corp.example"))
    for i in range(6):
        a.append(aza(t + i * MIN, "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", "p_keys@corp.example",
                     resource=f"resourcegroups/rg1/providers/microsoft.storage/storageaccounts/acc{i}"))
    for i in range(2):
        a.append(aza(t + i * MIN, "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", "n_keys@corp.example",
                     resource=f"resourcegroups/rg1/providers/microsoft.storage/storageaccounts/acc{i}"))
    a.append(aza(t, "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE", "p_pub@corp.example", req={"properties": {"allowBlobPublicAccess": True}}))
    a.append(aza(t, "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE", "n_pub@corp.example", req={"properties": {"allowBlobPublicAccess": False}}))
    # Entra audit: privileged role (near miss: reader role)
    out["aud"].append(aud(t, "Add member to role", "p_role@corp.example", [
        {"type": "User", "userPrincipalName": "eve@corp.example", "modifiedProperties": [
            {"displayName": "Role.DisplayName", "newValue": "\"Global Administrator\""}]}]))
    out["aud"].append(aud(t, "Add member to role", "n_role@corp.example", [
        {"type": "User", "userPrincipalName": "eve@corp.example", "modifiedProperties": [
            {"displayName": "Role.DisplayName", "newValue": "\"Reports Reader\""}]}]))
    # GCP: sink deleted (near miss: list); owner granted to an external user (near miss: viewer)
    g = out["gcp"]
    g.append(gcp(t, "google.logging.v2.ConfigServiceV2.DeleteSink", "p_sink@acme.example"))
    g.append(gcp(t, "google.logging.v2.ConfigServiceV2.ListSinks", "n_sink@acme.example"))
    for who, role in (("p_grant", "roles/owner"), ("n_grant", "roles/viewer")):
        g.append(gcp(t, "SetIamPolicy", f"{who}@acme.example", svc="cloudresourcemanager.googleapis.com",
                     delta=[{"action": "ADD", "role": role, "member": "user:mallory@evil.example"}]))
    return out


def write_raw(raw: Path, parts: list[dict[str, list[dict[str, Any]]]], dup_first_ct: bool = False) -> None:
    raw.mkdir(parents=True, exist_ok=True)
    for name in ("ct", "si", "aza", "aud", "gcp"):
        rows = [r for p in parts for r in p.get(name, [])]
        if rows:
            (raw / f"{name}.log").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    if dup_first_ct:   # the same CloudTrail record delivered twice (organization trail + account trail)
        (raw / "ct_dup.log").write_text(json.dumps(parts[0]["ct"][0]) + "\n", encoding="utf-8")


class Ctx:
    def __init__(self, work: Path, events_glob: str) -> None:
        self.work_dir, self.events_glob = work, events_glob


def run(con: duckdb.DuckDBPyConnection, cfg: dict[str, Any], work: Path, events_glob: str) -> tuple[dict, list[dict]]:
    from attacklens import detect_cloud
    work.mkdir(parents=True, exist_ok=True)
    st = detect_cloud.run_cloud(con, cfg, Ctx(work, events_glob))
    p = work / detect_cloud.OUT_NAME
    if not p.exists():
        return st, []
    cur = con.execute(f"SELECT * FROM read_parquet('{p.as_posix()}')")
    cols = [d[0] for d in cur.description]
    return st, [dict(zip(cols, r)) for r in cur.fetchall()]


def subset(cfg: dict[str, Any], ids: set[str]) -> dict[str, Any]:
    """Config copy with only these cloud rules (later test runs do not need the whole catalogue)."""
    out = copy.deepcopy(cfg)
    out["rules_cloud"]["rules"] = [r for r in out["rules_cloud"]["rules"] if r["id"] in ids]
    return out


@pytest.fixture(scope="module")
def ds(tmp_path_factory: pytest.TempPathFactory):
    """The whole catalogue runs ONCE, on a connection from db.connect with a small memory_limit."""
    tmp = tmp_path_factory.mktemp("cloud_detect")
    write_raw(tmp / "raw", [history(), attacks()], dup_first_ct=True)
    ctx = run_ingest(tmp / "raw", tmp)
    ctx.con.close()
    con = db.connect(memory_limit="300MB", threads=2, temp_directory=tmp / "spill")
    limit = con.execute("SELECT current_setting('memory_limit')").fetchone()[0]
    db.register_events(con, ctx.events_glob)
    ctx.con = con
    st, alerts = run(con, ctx.cfg, tmp / "work", ctx.events_glob)
    yield {"ctx": ctx, "stats": st, "alerts": alerts, "tmp": tmp, "limit": limit}
    con.close()


def of(ds: dict, rule: str, who: str | None = None) -> list[dict]:
    return [a for a in ds["alerts"] if a["rule_id"] == rule
            and (who is None or who in (a["src_user"], a["target_user"]))]


def test_every_rule_ran_without_error(ds) -> None:
    st = ds["stats"]
    assert st["errors"] == 0, st["error_messages"]
    assert st["rules"] >= 88 and len(st["alerts_per_rule"]) == st["rules"]   # 88 base; source tracks add more
    assert st["dedup_removed"] == 1                     # duplicate eventID delivered twice


@pytest.mark.parametrize("rule, pos, neg", [
    ("aws_admin_policy_attached", "p_admin", "n_admin"),                  # match (AWS)
    ("cl_secrets_mass_read", "p_secret", "n_secret"),                     # distinct_burst
    ("aws_logging_tamper", "p_trail", "n_trail"),
    ("cl_firewall_open_world", "p_fw", "n_fw"),                           # port range vs sensitive ports
    ("cl_snapshot_image_share_external", "p_snap", "n_snap"),             # external account vs own
    ("cl_signin_bruteforce", "p_bf", "n_bf"),                             # Entra sign-in burst
    ("az_mfa_fatigue", "p_mfa", "n_mfa"),
    ("az_elevate_access", "p_elev", "n_elev"),                            # Activity Log
    ("cl_storage_public_or_external", "p_pub", "n_pub"),
    ("az_entra_privileged_role", "p_role", "n_role"),                     # Entra audit
    ("gcp_logging_tamper", "p_sink", "n_sink"),                           # GCP
    ("gcp_sensitive_grant", "p_grant", "n_grant"),
    ("cl_denied_spike", "prober", "nprober"),                             # rate_spike
    ("cl_session_multi_asn", "p_sess", "n_sess"),                         # multi_network_session
    ("cl_impossible_travel", "bob", "n_travel"),                          # geo_velocity
])
def test_positive_and_near_miss(ds, rule: str, pos: str, neg: str) -> None:
    assert of(ds, rule, pos), f"{rule}: no alert for {pos}"
    assert not of(ds, rule, neg), f"{rule}: near miss {neg} alerted: {of(ds, rule, neg)}"


def test_sequence_same_instance_only(ds) -> None:
    assert max(a["severity"] for a in of(ds, "aws_ec2_userdata_modified", "p_udata")) == 85
    assert max(a["severity"] for a in of(ds, "aws_ec2_userdata_modified", "n_udata")) == 75   # match only
    ev = [a for a in of(ds, "aws_ec2_userdata_modified", "p_udata") if a["severity"] == 85][0]["evidence_lines"]
    assert "api=StopInstances" in ev[0] and "api=ModifyInstanceAttribute" in ev[1]


def test_sequence_on_alerts_and_secondary_labels(ds) -> None:
    (b11,) = of(ds, "seq_logging_off_then_write", "p_trail")
    assert b11["severity"] == 90 and b11["tactic"] == "Defense Impairment"
    bf = of(ds, "cl_signin_bruteforce", "p_bf")
    assert {a["technique_id"] for a in bf} == {"T1110", "T1078"}
    assert {a["tactic"] for a in bf} == {"Credential Access", "Initial Access"}
    assert any(a["sub_technique_id"] == "T1078.004" and a["severity"] == 85 for a in bf)
    assert any(a["technique_id"] == "T1078" for a in of(ds, "az_mfa_fatigue", "p_mfa"))


def test_burst_threshold_tiers(ds) -> None:
    assert max(a["severity"] for a in of(ds, "az_key_listing", "p_keys")) == 80
    assert max(a["severity"] for a in of(ds, "az_key_listing", "n_keys")) < 80
    assert max(a["severity"] for a in of(ds, "gcp_sensitive_grant", "p_grant")) == 85   # external member


def test_first_seen_and_cold_start(ds) -> None:
    fs = of(ds, "cl_first_seen_api", "alice")
    new = [a for a in fs if any("api=CreateAccessKey" in e for e in a["evidence_lines"])]
    # sensitive API, baseline ok: the rule is context (rules_cloud.yaml context: true), capped at context_severity
    assert new and new[0]["severity"] == int(ds["ctx"].cfg["cloud"]["context_severity"])
    assert not new[0]["evidence_lines"][0].startswith("baseline_ok=false")
    assert not [a for a in fs if any("api=DescribeInstances" in e for e in a["evidence_lines"])]   # routine
    (cold,) = [a for a in of(ds, "cl_first_seen_api", "newbie")]
    assert cold["severity"] == 30 and cold["evidence_lines"][0].startswith("baseline_ok=false")


def test_entities_follow_conventions(ds) -> None:
    a = of(ds, "aws_admin_policy_attached", "p_admin")[0]
    assert (a["subject_host"], a["host"], a["src_user"], a["target_user"], a["src_ip"]) == \
        (ACCT, ACCT, "p_admin", "eve", "192.0.2.10")
    (sess,) = of(ds, "cl_session_multi_asn", "p_sess")
    assert sess["severity"] == 35                       # prefix-only networks (no ASN data) are context
    s = of(ds, "cl_signin_bruteforce", "p_bf")[0]
    # host = the event's ingest host (resource id, lower-cased), as a Sigma alert on the same event gets
    assert s["subject_host"] == s["host"] == f"/tenants/{TENANT}/providers/microsoft.aadiam" and s["target_user"] == "p_bf"


def test_evidence_and_keys_bounded(ds) -> None:
    th = ds["ctx"].cfg["rules"]["thresholds"]
    n, c, k = int(th["evidence_max_lines"]), int(th["evidence_max_chars"]) + 1, int(th["source_keys_max"])
    assert ds["alerts"]
    for a in ds["alerts"]:
        assert 1 <= len(a["evidence_lines"]) <= n and all(len(x) <= c for x in a["evidence_lines"]), a["rule_id"]
        assert 1 <= len(a["source_keys"]) <= k and a["raw_alert_count"] >= 1
    assert any(len(x) == c for a in of(ds, "aws_admin_policy_attached", "p_long") for x in a["evidence_lines"])


def test_schema_matches_raw_alerts_and_settings_kept(ds) -> None:
    con = ds["ctx"].con
    assert con.execute("SELECT current_setting('memory_limit')").fetchone()[0] == ds["limit"]   # never raised
    assert con.execute("SELECT current_setting('TimeZone')").fetchone()[0] == "UTC"
    got = con.execute(f"DESCRIBE SELECT * FROM read_parquet('{(ds['tmp'] / 'work' / 'raw_alerts_cloud.parquet').as_posix()}')"
                      ).fetchall()
    assert [(r[0], r[1]) for r in got] == list(RAW_ALERT_COLUMNS.items())


SUBSET = {"aws_admin_policy_attached", "cl_secrets_mass_read", "aws_ec2_userdata_modified", "aws_logging_tamper",
          "seq_logging_off_then_write", "cl_first_seen_api", "cl_signin_bruteforce", "cl_impossible_travel",
          "cl_denied_spike"}   # one rule per template kind


def test_evidence_bounds_follow_config(ds) -> None:
    cfg = subset(ds["ctx"].cfg, SUBSET)
    cfg["rules"]["thresholds"].update(evidence_max_lines=1, evidence_max_chars=40, source_keys_max=2)
    _, alerts = run(ds["ctx"].con, cfg, ds["tmp"] / "work_bounds", ds["ctx"].events_glob)
    assert alerts and all(len(a["evidence_lines"]) == 1 and len(a["evidence_lines"][0]) <= 41
                          and len(a["source_keys"]) <= 2 for a in alerts)


def test_allowlist_downgrades_never_drops_and_cap(ds) -> None:
    cfg = subset(ds["ctx"].cfg, {"aws_admin_policy_attached", "cl_first_seen_api"})
    cfg["cloud"]["params"]["iac_principals"] = ["p_admin"]
    cfg["cloud"]["max_alerts_per_rule"] = 2
    st, alerts = run(ds["ctx"].con, cfg, ds["tmp"] / "work_allow", ds["ctx"].events_glob)
    adm = [a for a in alerts if a["rule_id"] == "aws_admin_policy_attached" and a["src_user"] == "p_admin"]
    assert [a["severity"] for a in adm] == [45]
    assert st["capped_by_rule"]["cl_first_seen_api"] > 0
    assert max(st["alerts_per_rule"].values()) <= 2
