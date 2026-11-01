"""Native cloud rule quality (config/rules_cloud.yaml, config/cloud.yaml, attacklens/detect_cloud*.py):

1. CI/CD and IaC identities (cloud.yaml params.automation_identity_patterns): routine writes after someone else's
   logging tamper are downgraded to context, never dropped, unless the automation identity shows a risk signal
   (a network it never used, an attack-tool user agent, a burst of denied calls).
2. Baselining rules (first-seen API / geo, rare API, prefix-only multi-network session) are context: they never
   reach the seed / tactic tiers on their own, but sequences still read their full severity.
3. Storage data access: a source new to a bucket / storage account reading many objects, a known source far above its
   own baseline, and account keys listed then used for blob reads from the same network (AWS S3, GCP GCS, Azure Blob).
"""

from __future__ import annotations

import copy
import itertools
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from .conftest import run_ingest
from .test_detect_cloud import ACCT, DAY, HOUR, MIN, SUB, T0, TENANT, aza, ct, gcp, iso, run, si, subset, write_raw

D10 = T0 + 10 * DAY + 9 * HOUR
_ids = itertools.count(1)
CI_NET, NEW_NET = "198.51.100.44", "203.0.113.250"


def web_identity(ts: int, subject: str, ip: str) -> dict[str, Any]:
    """GitHub Actions OIDC: AssumeRoleWithWebIdentity; the identity is the token subject (repo:<org>/<repo>:ref:...)."""
    return {"eventVersion": "1.09", "eventTime": iso(ts), "eventSource": "sts.amazonaws.com",
            "eventName": "AssumeRoleWithWebIdentity", "awsRegion": "us-east-1", "sourceIPAddress": ip,
            "userAgent": "aws-sdk-nodejs/3.4", "readOnly": False, "eventType": "AwsApiCall", "recipientAccountId": ACCT,
            "eventID": f"wi-{next(_ids)}",
            "userIdentity": {"type": "WebIdentityUser", "userName": subject, "accountId": ACCT,
                             "identityProvider": f"arn:aws:iam::{ACCT}:oidc-provider/token.actions.githubusercontent.com"},
            "requestParameters": {"roleArn": f"arn:aws:iam::{ACCT}:role/ci-deploy-role", "roleSessionName": "gha-1"}}


def ci(ts: int, api: str, session: str, ip: str = CI_NET, role: str = "ci-deploy-role", **kw: Any) -> dict[str, Any]:
    return ct(ts, api, session, src="cloudformation.amazonaws.com", ip=ip, utype="AssumedRole", role=role,
              ua="aws-sdk-nodejs/3.4 github-actions", **kw)


def blob(ts: int, op: str, account: str, key: str, ip: str, auth: str = "OAuth", upn: str | None = None,
         status: str = "200") -> dict[str, Any]:
    d: dict[str, Any] = {"TenantId": TENANT, "TimeGenerated": iso(ts), "AccountName": account, "OperationName": op,
                         "AuthenticationType": auth, "StatusCode": status, "StatusText": "Success",
                         "CallerIpAddress": f"{ip}:50000", "CorrelationId": f"b-{next(_ids)}",
                         "ObjectKey": f"/{account}/{key}", "ResponseBodySize": 1000, "Category": "StorageRead",
                         "_ResourceId": f"/subscriptions/{SUB}/resourcegroups/rg-data/providers/microsoft.storage/"
                                        f"storageaccounts/{account}/blobservices/default", "Type": "StorageBlobLogs"}
    if upn:
        d["RequesterUpn"] = upn
    return d


def write_blob(raw: Path, rows: list[dict[str, Any]]) -> None:
    (raw / "blob.log").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _of(alerts: list[dict], rule: str, who: str | None = None) -> list[dict]:
    return [a for a in alerts if a["rule_id"] == rule and (who is None or who in (a["src_user"], a["target_user"]))]


# ----------------------------------------------------------------------------------------------------------- 1 CI/CD
@pytest.fixture(scope="module")
def auto(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("cloud_auto")
    out: dict[str, list[dict[str, Any]]] = {"ct": []}
    c = out["ct"]
    for d in range(10):                                  # ten days of routine CI deploys from the runner network
        t = T0 + d * DAY + 9 * HOUR
        for i, role in enumerate(("ci-deploy-role", "ci-risky-role", "ci-denied-role")):
            c.append(ci(t + i * MIN, "UpdateStack", f"gha-{d}{i}", role=role))
        c.append(web_identity(t, "repo:corp/app:ref:refs/heads/main", CI_NET))
        c.append(ct(t, "PutObject", "bob", src="s3.amazonaws.com"))
    t = D10
    c.append(ct(t, "StopLogging", "mallory", src="cloudtrail.amazonaws.com", ip="203.0.113.9", rp={"name": "main"}))
    c.append(ci(t + 20 * MIN, "UpdateFunctionCode20150331v2", "gha-501"))                # routine: known network
    c.append(web_identity(t + 21 * MIN, "repo:corp/app:ref:refs/heads/main", CI_NET))     # routine OIDC exchange
    c.append(ci(t + 22 * MIN, "UpdateStack", "gha-502", role="ci-risky-role", ip=NEW_NET))  # risk: new network
    for i in range(6):                                                                    # risk: denied burst
        c.append(ci(t + 23 * MIN + i * 1000, "AttachRolePolicy", "gha-503", role="ci-denied-role", err="AccessDenied"))
    c.append(ci(t + 24 * MIN, "UpdateStack", "gha-503", role="ci-denied-role"))
    c.append(ct(t + 25 * MIN, "PutObject", "bob", src="s3.amazonaws.com"))                # unrelated human write
    c.append(ct(t + 26 * MIN, "CreateUser", "frank", ip="203.0.113.9", rp={"userName": "x"}))  # same IP as the tamper
    write_raw(tmp / "raw", [out])
    ctx = run_ingest(tmp / "raw", tmp)
    st, alerts = run(ctx.con, subset(ctx.cfg, {"aws_logging_tamper", "seq_logging_off_then_write"}), tmp / "work",
                     ctx.events_glob)
    yield {"ctx": ctx, "stats": st, "alerts": alerts}
    ctx.con.close()


def test_automation_patterns_are_config(auto) -> None:
    cc = auto["ctx"].cfg["cloud"]
    pats = cc["params"]["automation_identity_patterns"]
    assert any("repo:" in p for p in pats) and any("gha-" in p for p in pats) and any("project_path" in p for p in pats)
    assert any("cloudbuild" in p for p in pats) and any("sc://" in p for p in pats) and any("terraform" in p for p in pats)
    assert int(cc["automation"]["severity"]) <= int(cc["context_severity"])


def test_ci_write_after_tamper_downgraded_not_dropped(auto) -> None:
    st, alerts = auto["stats"], auto["alerts"]
    assert st["errors"] == 0, st["error_messages"]
    ctx_sev = int(auto["ctx"].cfg["cloud"]["context_severity"])
    for who in ("gha-501", "repo:corp/app:ref:refs/heads/main"):
        hits = _of(alerts, "seq_logging_off_then_write", who)
        assert hits, f"{who}: the automation hit must be kept (downgraded, never dropped)"
        assert max(a["severity"] for a in hits) <= ctx_sev, hits
        assert any("automation" in a["evidence_lines"][0] for a in hits)


@pytest.mark.parametrize("who", ["gha-502", "gha-503"])   # new network / denied burst
def test_ci_with_risk_signal_not_downgraded(auto, who: str) -> None:
    hits = _of(auto["alerts"], "seq_logging_off_then_write", who)
    assert hits and max(a["severity"] for a in hits) > int(auto["ctx"].cfg["cloud"]["automation"]["severity"]), hits
    assert not any("automation identity" in a["evidence_lines"][0] for a in hits)


def test_unrelated_write_after_tamper_is_signal_tier(auto) -> None:
    """Any write in the account inside the blind window used to score 75 (strong). An unrelated identity from an
    unrelated IP is a signal (50); the same actor (90) or the tamper's source IP (85) stay strong."""
    bob = _of(auto["alerts"], "seq_logging_off_then_write", "bob")
    assert bob and max(a["severity"] for a in bob) == 50
    frank = _of(auto["alerts"], "seq_logging_off_then_write", "frank")
    assert frank and max(a["severity"] for a in frank) == 85
    assert max(a["severity"] for a in _of(auto["alerts"], "aws_logging_tamper", "mallory")) >= 85


def test_every_single_source_template_applies_its_filter() -> None:
    """branch_sql only passes a branch's filter to templates in SINGLE_SOURCE (new_source_burst once ran unfiltered)."""
    from attacklens import detect_cloud
    assert set(detect_cloud.TEMPLATES) - {"sequence"} == set(detect_cloud.SINGLE_SOURCE)


# --------------------------------------------------------------------------------------------------- 2 context rules
@pytest.fixture(scope="module")
def baseline(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("cloud_ctx")
    out: dict[str, list[dict[str, Any]]] = {"ct": [], "si": [], "aud": []}
    for d in range(10):
        t = T0 + d * DAY + 9 * HOUR
        for i in range(8):
            out["ct"].append(ct(t + i * 20 * MIN, "DescribeInstances", "alice", src="ec2.amazonaws.com"))
            out["ct"].append(ct(t + i * 20 * MIN, "PutObject", "alice", src="s3.amazonaws.com"))
        for i in range(6):                               # >= cold_start.min_actor_events before the attack day
            out["si"].append(si(t + i * HOUR, "erin@corp.example"))
    t = D10
    out["ct"].append(ct(t, "CreateAccessKey", "alice", re={"accessKey": {"accessKeyId": "AKIANEWKEY0000000009"}}))
    # one temporary key from two /16 prefixes in 10 min (no ASN data: prefix-only networks)
    for k, ip in enumerate(("203.0.113.5", "198.18.0.5")):
        out["ct"].append(ct(t + k * 5 * MIN, "ListBuckets", "p_sess", src="s3.amazonaws.com", ip=ip,
                            utype="AssumedRole", role="AppRole", akid="ASIAPSESS000000001"))
    # Entra sign-in from a first-seen country, then a new authentication method (risky sign-in -> persistence)
    out["si"].append(si(t, "erin@corp.example", ip="203.0.113.60", cc="BR", lat=-23.5, lon=-46.6, asn=64777))
    out["aud"].append({"TenantId": TENANT, "TimeGenerated": iso(t + 10 * MIN), "OperationName": "User registered security info",
                       "ActivityDisplayName": "User registered security info", "Category": "UserManagement",
                       "Result": "success", "CorrelationId": "c-ctx-1", "Id": "Dir_ctx_1", "LoggedByService": "Authentication Methods",
                       "InitiatedBy": {"user": {"userPrincipalName": "erin@corp.example", "ipAddress": "203.0.113.60"}},
                       "TargetResources": [{"type": "User", "userPrincipalName": "erin@corp.example"}],
                       "AADTenantId": TENANT, "Type": "AuditLogs",
                       "ResourceId": f"/tenants/{TENANT}/providers/Microsoft.aadiam"})
    write_raw(tmp / "raw", [out])
    ctx = run_ingest(tmp / "raw", tmp)
    yield {"ctx": ctx, "tmp": tmp}
    ctx.con.close()


CONTEXT_RULES = ("cl_first_seen_api", "cl_rare_api_account", "cl_first_seen_geo")


def test_baselining_rules_are_context(baseline) -> None:
    ctx = baseline["ctx"]
    cc = ctx.cfg["cloud"]
    ids = {r["id"]: r for r in ctx.cfg["rules_cloud"]["rules"]}
    assert all(ids[r].get("context") is True for r in CONTEXT_RULES)
    st, alerts = run(ctx.con, subset(ctx.cfg, set(CONTEXT_RULES) | {"cl_session_multi_asn"}),
                     baseline["tmp"] / "w1", ctx.events_glob)
    assert st["errors"] == 0, st["error_messages"]
    new = [a for a in _of(alerts, "cl_first_seen_api", "alice") if any("api=CreateAccessKey" in e for e in a["evidence_lines"])]
    assert new, "the first-seen hit is kept as context"
    assert all(a["severity"] <= int(cc["context_severity"]) for a in alerts if a["rule_id"] in CONTEXT_RULES)
    assert _of(alerts, "cl_first_seen_geo", "erin")
    (sess,) = _of(alerts, "cl_session_multi_asn", "p_sess")
    assert sess["severity"] <= int(cc["context_severity"])     # prefix-only networks (no ASN data) are context


def test_sequences_read_context_rules_at_full_strength(baseline) -> None:
    """seq_risky_signin_then_persistence starts from cl_first_seen_geo (a_min_severity 45): capping the context rule's
    output must not starve the sequence, which is the combined (real) signal."""
    ctx = baseline["ctx"]
    cfg = subset(ctx.cfg, {"cl_first_seen_geo", "az_auth_method_added", "seq_risky_signin_then_persistence"})
    seq = next(r for r in cfg["rules_cloud"]["rules"] if r["id"] == "seq_risky_signin_then_persistence")
    seq["branches"][0]["params"]["a_rules"] = ["cl_first_seen_geo"]
    st, alerts = run(ctx.con, cfg, baseline["tmp"] / "w2", ctx.events_glob)
    assert st["errors"] == 0, st["error_messages"]
    assert _of(alerts, "az_auth_method_added", "erin"), "fixture: the persistence step must alert"
    assert max(a["severity"] for a in _of(alerts, "cl_first_seen_geo", "erin")) <= int(ctx.cfg["cloud"]["context_severity"])
    assert _of(alerts, "seq_risky_signin_then_persistence", "erin")


# ------------------------------------------------------------------------------------------------- 3 storage reads
STORAGE = "cl_storage_data_access"


@pytest.fixture(scope="module")
def storage(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("cloud_storage")
    out: dict[str, list[dict[str, Any]]] = {"ct": [], "aza": [], "gcp": []}
    blobs: list[dict[str, Any]] = []
    for d in range(10):                                   # routine readers of each store, a few objects a day
        t = T0 + d * DAY + 9 * HOUR
        for i in range(4):
            out["ct"].append(ct(t + i * MIN, "GetObject", "app", src="s3.amazonaws.com",
                                rp={"bucketName": "corp-data", "key": f"k{d}-{i}"}))
            out["ct"].append(ct(t + i * MIN, "GetObject", "kbulk", src="s3.amazonaws.com",
                                rp={"bucketName": "corp-data", "key": f"b{d}-{i}"}))
            out["gcp"].append(gcp(t + i * MIN, "storage.objects.get", "app@acme.example", svc="storage.googleapis.com",
                                  res=f"projects/_/buckets/corp-gcs/objects/k{d}-{i}"))
            blobs.append(blob(t + i * MIN, "GetBlob", "corpfin", f"c/k{d}-{i}", "192.0.2.21", upn="nbose@corp.example"))
            blobs.append(blob(t + i * MIN, "GetBlob", "corpfin", f"c/j{d}-{i}", "192.0.2.23", upn="kiyer@corp.example"))
        # nightly job: 80 objects every day (a big but known, steady reader: never an alert after its cold start)
        for i in range(80):
            out["ct"].append(ct(t + 2 * HOUR + i * 1000, "GetObject", "backup", src="s3.amazonaws.com",
                                rp={"bucketName": "corp-data", "key": f"n{d}-{i}"}))
    t = D10
    for i in range(60):
        # AWS: a principal that never read corp-data pulls 60 objects (near miss: the nightly job, same volume)
        out["ct"].append(ct(t + i * 2000, "GetObject", "p_s3", src="s3.amazonaws.com", ip="203.0.113.11",
                            rp={"bucketName": "corp-data", "key": f"x{i}"}))
        # AWS: a known reader 15x above its own baseline
        out["ct"].append(ct(t + i * 2000, "GetObject", "kbulk", src="s3.amazonaws.com",
                            rp={"bucketName": "corp-data", "key": f"y{i}"}))
        # GCP: anonymous (no principal) reads of a bucket from an external IP
        out["gcp"].append(gcp(t + i * 2000, "storage.objects.get", "", svc="storage.googleapis.com", ip="203.0.113.55",
                              res=f"projects/_/buckets/corp-gcs/objects/x{i}"))
        # Azure: a known user 15x above baseline (OAuth), and account-key reads after listKeys from the same IP
        blobs.append(blob(t + i * 2000, "GetBlob", "corpfin", f"c/f{i}", "203.0.113.77", upn="kiyer@corp.example"))
        blobs.append(blob(t + HOUR + i * 2000, "GetBlob", "corpfin", f"c/a{i}", "203.0.113.33", auth="AccountKey"))
        # near miss: a new principal DELETING 60 objects is not a data read (cl_mass_destruction's job)
        out["ct"].append(ct(t + i * 2000, "DeleteObject", "n_del", src="s3.amazonaws.com", ip="203.0.113.12",
                            rp={"bucketName": "corp-data", "key": f"d{i}"}))
    for i in range(3):                                    # near miss: a few account-key reads, nobody listed keys
        blobs.append(blob(t + i * MIN, "GetBlob", "corpfin", f"c/s{i}", "198.51.100.200", auth="AccountKey"))
    out["aza"].append(aza(t + 40 * MIN, "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", "kiyer@corp.example",
                          resource="resourcegroups/rg-data/providers/microsoft.storage/storageaccounts/corpfin",
                          ip="203.0.113.33"))
    for i in range(80):                                   # the nightly job on attack day: same volume as always
        out["ct"].append(ct(t + 2 * HOUR + i * 1000, "GetObject", "backup", src="s3.amazonaws.com",
                            rp={"bucketName": "corp-data", "key": f"n10-{i}"}))
    write_raw(tmp / "raw", [out])
    write_blob(tmp / "raw", blobs)
    ctx = run_ingest(tmp / "raw", tmp)
    st, alerts = run(ctx.con, subset(ctx.cfg, {STORAGE, "cl_exfil_volume"}), tmp / "work", ctx.events_glob)
    yield {"ctx": ctx, "stats": st, "alerts": alerts}
    ctx.con.close()


def _storage(alerts: list[dict], *, user: str | None = None, ip: str | None = None) -> list[dict]:
    return [a for a in alerts if a["rule_id"] == STORAGE and (user is None or user in (a["src_user"], a["target_user"]))
            and (ip is None or a["src_ip"] == ip)]


def test_storage_rule_labels(storage) -> None:
    st = storage["stats"]
    assert st["errors"] == 0, st["error_messages"]
    rule = next(r for r in storage["ctx"].cfg["rules_cloud"]["rules"] if r["id"] == STORAGE)
    assert rule["technique"] == "T1530" and rule["tactic"] == "Collection" and set(rule["clouds"]) == {"aws", "azure", "gcp"}


def test_new_source_bulk_read_s3(storage) -> None:
    hits = _storage(storage["alerts"], user="p_s3")
    assert hits and max(a["severity"] for a in hits) >= 65, hits
    ctx_sev = int(storage["ctx"].cfg["cloud"]["context_severity"])
    # the steady nightly reader: only its first night (store cold start, baseline_ok=false) may show, as context
    backup = _storage(storage["alerts"], user="backup")
    assert all(a["severity"] <= ctx_sev for a in backup), backup
    assert all(a["ts_ms"] < T0 + DAY for a in backup), backup
    assert not _storage(storage["alerts"], user="app")
    assert not _storage(storage["alerts"], user="n_del"), "the branch filter (object reads only) must apply"


def test_known_source_spike_s3_and_blob(storage) -> None:
    for who in ("kbulk", "kiyer"):
        hits = _storage(storage["alerts"], user=who)
        assert hits and max(a["severity"] for a in hits) >= 65, (who, hits)
    assert not _storage(storage["alerts"], user="nbose")


def test_anonymous_gcs_reads_from_new_ip(storage) -> None:
    hits = _storage(storage["alerts"], ip="203.0.113.55")
    assert hits and max(a["severity"] for a in hits) >= 65, hits


def test_listkeys_then_account_key_reads_same_ip(storage) -> None:
    hits = _storage(storage["alerts"], ip="203.0.113.33")
    assert hits and max(a["severity"] for a in hits) >= 80, hits
    assert any("LISTKEYS" in a["evidence_lines"][0].upper() for a in hits)
    assert all(a["host"].endswith("/storageaccounts/corpfin/blobservices/default") for a in hits)
    assert not _storage(storage["alerts"], ip="198.51.100.200")


def test_exfil_volume_keys_identityless_reads(storage, tmp_path) -> None:
    """cl_exfil_volume (GCS / Blob branch) keyed on actor_key dropped every AccountKey / SAS / anonymous read (NULL
    principal). With the threshold lowered for the test, identity-less reads must reach the burst."""
    ctx = storage["ctx"]
    cfg = subset(ctx.cfg, {"cl_exfil_volume"})
    cfg["cloud"]["params"]["b14_min_objects"] = 50
    st, alerts = run(ctx.con, cfg, tmp_path / "w", ctx.events_glob)
    assert st["errors"] == 0, st["error_messages"]
    assert [a for a in alerts if a["src_ip"] in ("203.0.113.33", "203.0.113.55")]
