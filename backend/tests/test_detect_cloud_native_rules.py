"""Native cloud rule quality, rules track (config/rules_cloud.yaml, config/cloud.yaml).

Each rule family has one positive (p_* style actor or attacker IP) and one near miss. Ten quiet days of history come
first so the baseline rules are past their cold start. Covers:
- ConsoleLogin failures for user names that do not exist ("No username found in supplied account"), T1110
- stolen-key recon fingerprint: first-seen network for an established identity, small discovery burst with recon /
  denied calls (T1580), denied spike judged per identity (not per new IP), and the Initial Access step that ties the
  novel network to the follow-on action (T1078.004)
- GCS / Azure storage object enumeration (T1619) and bulk writes into a bucket the account never used (T1537)
- STS temporary credentials used from a network other than the one they were issued to (T1550.001)
- Lambda created then wired to a trigger (T1648), KMS imported key material then deleted (T1486)
- delegated OAuth grant with risky scopes (T1528), snapshot burst by a human (T1578.001)
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from .conftest import run_ingest
from .test_detect_cloud import ACCT, DAY, HOUR, MIN, T0, aud, ct, iso, run, subset, write_raw

D10 = T0 + 10 * DAY + 9 * HOUR
_ids = itertools.count(1)
RULES = {"aws_console_unknown_user", "cl_first_seen_geo", "cl_discovery_burst", "cl_denied_spike", "cl_secrets_mass_read",
         "cl_storage_enum_burst", "cl_storage_write_new_bucket", "seq_novel_network_then_action",
         "aws_sts_token_new_network", "aws_serverless_code_change", "cl_kms_key_destroy", "cl_storage_ransom_encrypt",
         "az_oauth_consent_privileged", "cl_compute_snapshot_create"}
UNKNOWN = "No username found in supplied account"


def unknown_login(ts: int, ip: str) -> dict[str, Any]:
    d = ct(ts, "ConsoleLogin", "HIDDEN_DUE_TO_SECURITY_REASONS", src="signin.amazonaws.com", ip=ip,
           add={"MFAUsed": "No"}, re={"ConsoleLogin": "Failure"}, ua="Mozilla/5.0 (Macintosh)")
    d.update(errorMessage=UNKNOWN)
    d["userIdentity"].pop("arn", None)
    return d


def gcs(ts: int, method: str, principal: str, bucket: str, obj: str | None = None, ip: str = "198.51.100.30") -> dict:
    res = f"projects/_/buckets/{bucket}" + (f"/objects/{obj}" if obj else "")
    return {"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "status": {},
                             "authenticationInfo": {"principalEmail": principal},
                             "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": "gcloud-python/3.1.0"},
                             "serviceName": "storage.googleapis.com", "methodName": method, "resourceName": res},
            "insertId": f"gs-{next(_ids)}", "timestamp": iso(ts),
            "resource": {"type": "gcs_bucket", "labels": {"project_id": "acme-data", "bucket_name": bucket}},
            "logName": "projects/acme-data/logs/cloudaudit.googleapis.com%2Fdata_access"}


def history() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {"ct": [], "gcp": [], "aud": []}
    for d in range(10):
        for i in range(8):
            t = T0 + d * DAY + 9 * HOUR + i * 20 * MIN
            for who, ip in (("carl", "198.51.100.20"), ("dana", "198.51.100.21")):
                out["ct"].append(ct(t, "PutMetricData", who, src="monitoring.amazonaws.com", ip=ip,
                                    akid=f"AKIA{who.upper():0<16}"))
            for who in ("gina@acme.example", "hank@acme.example"):
                out["gcp"].append(gcs(t, "storage.objects.list", who, "acme-logs", f"day{d}/{i}"))
            out["gcp"].append(gcs(t + 1000, "storage.objects.create", "hank@acme.example", "acme-logs", f"in/{d}-{i}"))
        out["ct"].append(ct(T0 + d * DAY + 10 * HOUR, "DescribeInstances", "dana", src="ec2.amazonaws.com",
                            ip="198.51.100.21", akid="AKIADANA000000000000"))
    return out


def attacks() -> dict[str, list[dict[str, Any]]]:
    t = D10
    out: dict[str, list[dict[str, Any]]] = {"ct": [], "gcp": [], "aud": []}
    c, g = out["ct"], out["gcp"]
    # unknown-user console failures: 4 from one IP in 3 min (near miss: 1 from another IP)
    for i in range(4):
        c.append(unknown_login(t + i * 45_000, "203.0.113.70"))
    c.append(unknown_login(t, "203.0.113.71"))
    # carl's key from a new network: whoami, a small recon burst with denials, then denied secret reads
    kw = {"ip": "203.0.113.66", "akid": "AKIACARL000000000000", "ua": "Boto3/1.34.0 Botocore/1.34.0"}
    c.append(ct(t + HOUR, "GetCallerIdentity", "carl", src="sts.amazonaws.com", **kw))
    recon = [("DescribeInstances", "ec2", None), ("ListBuckets", "s3", None), ("DescribeDBInstances", "rds", None),
             ("ListTables", "dynamodb", None), ("ListRoles", "iam", "AccessDenied"),
             ("GetAccountAuthorizationDetails", "iam", "AccessDenied"), ("ListFunctions20150331", "lambda", None),
             ("DescribeRepositories", "ecr", "AccessDenied"), ("GetDatabases", "glue", "AccessDenied"),
             ("DescribeClusters", "redshift", None)]
    for i, (api, svc, err) in enumerate(recon):
        c.append(ct(t + HOUR + 2 * MIN + i * 9000, api, "carl", src=f"{svc}.amazonaws.com", err=err, **kw))
    for i in range(12):
        c.append(ct(t + HOUR + 6 * MIN + i * 6000, "GetSecretValue", "carl", src="secretsmanager.amazonaws.com",
                    err="AccessDenied", rp={"secretId": f"prod/{i}/db"}, **kw))
    # near miss: dana's ordinary describe sweep from her usual network (no recon-first API, no denial)
    for i, api in enumerate(["DescribeInstances", "DescribeVolumes", "DescribeDBInstances", "DescribeClusters",
                             "DescribeRepositories", "DescribeTable", "DescribeLoadBalancers", "DescribeAlarms",
                             "DescribeStacks", "DescribeKeyPairs"]):
        svc = ["ec2", "ec2", "rds", "redshift", "ecr", "dynamodb", "elasticloadbalancing", "monitoring",
               "cloudformation", "ec2"][i]
        c.append(ct(t + HOUR + i * 9000, api, "dana", src=f"{svc}.amazonaws.com", ip="198.51.100.21",
                    akid="AKIADANA000000000000"))
    # GCS: gina lists 6 buckets from a new network, later writes 30 objects into a bucket the project never used;
    # near miss hank: lists 6 objects of one bucket, creates a bucket in-project then fills it
    g.append(gcs(t + 2 * HOUR, "storage.buckets.list", "gina@acme.example", "acme-logs", ip="203.0.113.99"))
    for r in range(3):
        for b in range(6):
            g.append(gcs(t + 2 * HOUR + 5 * MIN + (r * 6 + b) * 4000, "storage.objects.list", "gina@acme.example",
                         f"acme-bucket-{b}", ip="203.0.113.99"))
    for i in range(30):
        g.append(gcs(t + 3 * HOUR + i * 3000, "storage.objects.create", "gina@acme.example", "drop-990",
                     f"loot/{i:04d}", ip="203.0.113.99"))
        g.append(gcs(t + 3 * HOUR + i * 3000, "storage.objects.create", "gina@acme.example", "acme-logs",
                     f"up/{i:04d}", ip="203.0.113.99"))
    for i in range(6):
        g.append(gcs(t + 2 * HOUR + i * 4000, "storage.objects.list", "hank@acme.example", "acme-logs", f"x/{i}"))
    g.append(gcs(t + 3 * HOUR, "storage.buckets.create", "hank@acme.example", "acme-staging"))
    for i in range(30):
        g.append(gcs(t + 3 * HOUR + MIN + i * 3000, "storage.objects.create", "hank@acme.example", "acme-staging",
                     f"s/{i:04d}"))
    # STS: erin's role session used from another network (near miss: fred, same /16)
    for who, ip_a, ip_b in (("erin", "198.51.100.40", "203.0.113.80"), ("fred", "198.51.100.41", "198.51.100.42")):
        key = f"ASIA{who.upper():0<16}"
        c.append(ct(t + 4 * HOUR, "AssumeRole", who, src="sts.amazonaws.com", ip=ip_a,
                    rp={"roleArn": f"arn:aws:iam::{ACCT}:role/AppRole", "roleSessionName": who},
                    re={"credentials": {"accessKeyId": key}}))
        c.append(ct(t + 4 * HOUR + 10 * MIN, "ListBuckets", who, src="s3.amazonaws.com", ip=ip_b,
                    utype="AssumedRole", role="AppRole", akid=key))
    # Lambda created and wired to a stream trigger (near miss: terraform creates a function, no trigger)
    fn = {"functionName": "orders-sync", "runtime": "python3.12", "role": f"arn:aws:iam::{ACCT}:role/Infra"}
    c.append(ct(t + 5 * HOUR, "CreateFunction20150331", "gus", src="lambda.amazonaws.com", rp=fn))
    c.append(ct(t + 5 * HOUR + 25_000, "CreateEventSourceMapping20150331", "gus", src="lambda.amazonaws.com",
                rp={"functionName": "orders-sync", "eventSourceArn": f"arn:aws:dynamodb:us-east-1:{ACCT}:table/o/stream/1"}))
    c.append(ct(t + 5 * HOUR, "CreateFunction20150331", "ivan", src="lambda.amazonaws.com",
                rp={**fn, "functionName": "tf-fn"}, ua="Terraform/1.7.0 terraform-provider-aws/5.40"))
    # KMS: imported key material then deleted on the same key (near miss: another key)
    k1, k2, k3 = ("1234abcd-12ab-34cd-56ef-1234567890a1", "1234abcd-12ab-34cd-56ef-1234567890a2",
                  "1234abcd-12ab-34cd-56ef-1234567890a3")
    for who, ka, kb in (("kara", k1, k1), ("liam", k2, k3)):
        c.append(ct(t + 6 * HOUR, "ImportKeyMaterial", who, src="kms.amazonaws.com", rp={"keyId": ka}))
        c.append(ct(t + 6 * HOUR + 10 * MIN, "DeleteImportedKeyMaterial", who, src="kms.amazonaws.com",
                    rp={"keyId": f"arn:aws:kms:us-east-1:{ACCT}:key/{kb}"}))
    # snapshots of 3 volumes by a human in 2 min (near miss: one snapshot)
    for i in range(3):
        c.append(ct(t + 7 * HOUR + i * 30_000, "CreateSnapshot", "olga", src="ec2.amazonaws.com", ip="203.0.113.88",
                    rp={"volumeId": f"vol-0{i}", "description": "backup"}))
    c.append(ct(t + 7 * HOUR, "CreateSnapshot", "pete", src="ec2.amazonaws.com", rp={"volumeId": "vol-9"}))
    # delegated OAuth grant with mail scopes (near miss: sign-in scopes only)
    for who, scope in (("mona@corp.example", "Mail.Read Mail.Send offline_access"), ("nora@corp.example", "User.Read openid")):
        out["aud"].append(aud(t + 8 * HOUR, "Add OAuth2PermissionGrant", who, [
            {"id": f"sp-{who}", "displayName": "PDF Merger Pro", "type": "ServicePrincipal",
             "modifiedProperties": [{"displayName": "Scope", "newValue": f"\"{scope}\""}]}], cat="ApplicationManagement"))
    return out


@pytest.fixture(scope="module")
def ds(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("cloud_native_rules")
    write_raw(tmp / "raw", [history(), attacks()])
    ctx = run_ingest(tmp / "raw", tmp)
    st, alerts = run(ctx.con, subset(ctx.cfg, RULES), tmp / "work", ctx.events_glob)
    yield {"ctx": ctx, "stats": st, "alerts": alerts}
    ctx.con.close()


def _of(alerts: list[dict], rule: str, who: str | None = None, ip: str | None = None) -> list[dict]:
    return [a for a in alerts if a["rule_id"] == rule
            and (who is None or who in (str(a["src_user"] or ""), str(a["target_user"] or "")))
            and (ip is None or a["src_ip"] == ip)]


def _max(alerts: list[dict]) -> int:
    return max((int(a["severity"]) for a in alerts), default=0)


def test_rules_load_and_run_clean(ds) -> None:
    from attacklens import detect_cloud
    rules, errs = detect_cloud.load_rules(ds["ctx"].cfg)
    assert errs == []
    assert RULES <= {r["id"] for r in rules}
    assert ds["stats"]["errors"] == 0, ds["stats"].get("error_messages")


def test_unknown_user_console_failures(ds) -> None:
    a = ds["alerts"]
    hit = _of(a, "aws_console_unknown_user", ip="203.0.113.70")
    assert _max(hit) >= 60 and {x["technique_id"] for x in hit} == {"T1110"}, hit
    assert _max(_of(a, "aws_console_unknown_user", ip="203.0.113.71")) <= 35


def test_stolen_key_recon_fingerprint(ds) -> None:
    a = ds["alerts"]
    disc = _of(a, "cl_discovery_burst", ip="203.0.113.66")
    assert _max(disc) >= 45 and disc[0]["technique_id"] == "T1580", disc
    assert not [x for x in _of(a, "cl_discovery_burst") if x["src_ip"] == "198.51.100.21"]   # dana: ordinary sweep
    # the denied spike is judged against the identity's own history, not cold-started by its new IP
    assert _max(_of(a, "cl_denied_spike", ip="203.0.113.66")) > 35
    assert _of(a, "cl_first_seen_geo", ip="203.0.113.66"), "first-seen network on a recon-first read (whoami)"


def test_novel_network_then_action_marks_initial_access(ds) -> None:
    a = ds["alerts"]
    hit = _of(a, "seq_novel_network_then_action", ip="203.0.113.66")
    assert hit and _max(hit) >= 65, hit
    assert min(x["ts_ms"] for x in hit) == D10 + HOUR                      # at the novel-network event (whoami)
    assert {(x["technique_id"], x["tactic"]) for x in hit} == {("T1078", "Initial Access")}
    assert not _of(a, "seq_novel_network_then_action", ip="198.51.100.21")


def test_storage_enumeration_and_new_bucket_writes(ds) -> None:
    a = ds["alerts"]
    enum = _of(a, "cl_storage_enum_burst", ip="203.0.113.99")
    assert _max(enum) >= 45 and enum[0]["technique_id"] == "T1619", enum
    assert not _of(a, "cl_storage_enum_burst", ip="198.51.100.30")         # hank: objects of one bucket
    new = _of(a, "cl_storage_write_new_bucket")
    assert new and _max(new) >= 70 and {x["technique_id"] for x in new} == {"T1537"}, new
    assert {x["src_ip"] for x in new} == {"203.0.113.99"}                  # not hank's in-project bucket
    assert all("acme-logs" not in " ".join(x["evidence_lines"]) for x in new)   # known bucket: no hit
    assert _of(a, "seq_novel_network_then_action", ip="203.0.113.99")


def test_sts_token_used_from_other_network(ds) -> None:
    a = ds["alerts"]
    hit = _of(a, "aws_sts_token_new_network", ip="203.0.113.80")
    assert hit and hit[0]["sub_technique_id"] == "T1550.001" and hit[0]["tactic"] == "Lateral Movement", hit
    assert not _of(a, "aws_sts_token_new_network", ip="198.51.100.42")


def test_lambda_created_then_triggered(ds) -> None:
    a = ds["alerts"]
    assert _max(_of(a, "aws_serverless_code_change", "gus")) >= 70
    assert {x["technique_id"] for x in _of(a, "aws_serverless_code_change", "gus")} == {"T1648"}
    assert _max(_of(a, "aws_serverless_code_change", "ivan")) <= 45


def test_kms_imported_material_deleted_is_ransomware(ds) -> None:
    a = ds["alerts"]
    hit = _of(a, "cl_storage_ransom_encrypt", "kara")
    assert hit and _max(hit) >= 85 and hit[0]["technique_id"] == "T1486", hit
    assert not _of(a, "cl_storage_ransom_encrypt", "liam")
    assert _of(a, "cl_kms_key_destroy", "liam")                            # the deletion itself still alerts (T1485)


def test_delegated_grant_with_mail_scopes(ds) -> None:
    a = ds["alerts"]
    hit = [x for x in _of(a, "az_oauth_consent_privileged") if x["src_user"] and "mona" in x["src_user"]]
    assert hit and hit[0]["technique_id"] == "T1528" and _max(hit) >= 70, _of(a, "az_oauth_consent_privileged")
    assert not [x for x in _of(a, "az_oauth_consent_privileged") if x["src_user"] and "nora" in x["src_user"]]


def test_snapshot_burst_by_human(ds) -> None:
    a = ds["alerts"]
    hit = _of(a, "cl_compute_snapshot_create", "olga")
    assert hit and hit[0]["sub_technique_id"] == "T1578.001" and hit[0]["tactic"] == "Defense Impairment", hit
    assert _max(hit) >= 50
    assert _max(_of(a, "cl_compute_snapshot_create", "pete")) < 50


def test_attack_label_decisions_kept() -> None:
    """ATT&CK v20 decisions (reports/cloud/rule_catalog.md): a bucket opened to AllUsers is T1537 ('creating anonymous
    file sharing links'), access keys for another user are T1098.001 ('CreateAccessKey API ... add access keys')."""
    from attacklens.config import load_config
    rules = {r["id"]: r for r in load_config()["rules_cloud"]["rules"]}
    assert rules["cl_storage_public_or_external"]["technique"] == "T1537"
    assert rules["aws_credential_for_other_user"]["sub_technique"] == "T1098.001"
