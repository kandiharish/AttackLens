"""P1-21: tests for connector claims that had none (reports/cloud/log_coverage.md section 3b).

- azure_monitor: the three AAD*SignInLogs tables are in the default union; their rows (string-typed JSON columns
  like LocationDetails) are decoded, spooled per table and ingest as azure_signin_json with user / src_ip set.
- azure_monitor: the StorageBlobLogs optional table (template, switch forms, invalid names) and its rows ingest as
  azure_storageblob_json with the `ip:port` caller stripped.
- azure_monitor alerts mode: SecurityAlert pulled from tools/mock_siem.py (Entra token, keyset paging) and mapped
  to raw_alerts rows with the vendor technique, every row accounted for.
- aws_cloudtrail: STS role_arn assume (RoleArn, ExternalId, session name, the derived session) and its refresh
  before the 1 h credentials expire; the organization-trail S3 prefix with several member accounts.
No real network: httpc.open_url is faked, or the local mock serves 127.0.0.1; boto3 is a stub module.
"""

from __future__ import annotations

import gzip
import io
import json
import sys
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from attacklens import integrations as ig

from .conftest import query, run_ingest
from .test_cloud_connectors import (T0, FakeHTTP, accounted, azure_cfg, base_cfg, get, http, make_cfg,  # noqa: F401
                                    spool_docs)

REPO = Path(__file__).resolve().parents[2]
TS = "2026-10-24T02:00:01.5000000Z"


# ----------------------------------------------------------------------------- Log Analytics fake (any columns)
class TableServer:
    """Token endpoint + Log Analytics query API serving dict rows (each row its own columns, like a union);
    records every KQL query."""

    def __init__(self, http: FakeHTTP, rows: list[dict[str, Any]]) -> None:
        self.rows, self.queries = rows, []
        http.route("login.microsoftonline.com", lambda *a: (200, {"access_token": "tok-1", "expires_in": 3599}, {}))
        http.route("api.loganalytics", self.query)

    def query(self, method, url, body, headers):
        q = json.loads(body)["query"]
        self.queries.append(q)
        cols: list[str] = []
        for r in self.rows:
            cols += [c for c in r if c not in cols]
        rows = self.rows
        if 'AlId > "' in q:
            last = q.split('AlId > "', 1)[1].split('"', 1)[0]
            rows = [r for r in rows if r["AlId"] > last]
        return 200, {"tables": [{"name": "PrimaryResult", "columns": [{"name": c, "type": "string"} for c in cols],
                                 "rows": [[r.get(c) for c in cols] for r in rows]}]}, {}


def aad_rows() -> list[dict[str, Any]]:
    loc = json.dumps({"city": "Amsterdam", "countryOrRegion": "NL", "geoCoordinates": {"latitude": 52.37}})
    status = json.dumps({"errorCode": 0, "additionalDetails": "MFA requirement satisfied by claim in the token"})
    base = {"TimeGenerated": TS, "OperationName": "Sign-in activity", "ResultType": "0", "LocationDetails": loc,
            "Status": status, "ConditionalAccessStatus": "notApplied", "ResourceDisplayName": "Microsoft Graph"}
    return [
        {**base, "Type": "AADNonInteractiveUserSignInLogs", "_ItemId": "n1", "AlId": "n1",
         "Category": "NonInteractiveUserSignInLogs", "UserPrincipalName": "pmehta@corp.example",
         "IPAddress": "203.0.113.77", "AppDisplayName": "Microsoft Office", "IsInteractive": "false",
         "AuthenticationRequirement": "singleFactorAuthentication", "UniqueTokenIdentifier": "utiAAA",
         "DeviceDetail": json.dumps({"operatingSystem": "Windows10", "browser": "Rich Client 4.0"})},
        {**base, "Type": "AADServicePrincipalSignInLogs", "_ItemId": "s1", "AlId": "s1",
         "Category": "ServicePrincipalSignInLogs", "ServicePrincipalName": "backup-automation",
         "ServicePrincipalId": "7c1e0000-0000-4000-8000-000000000001", "IPAddress": "198.51.100.66",
         "ServicePrincipalCredentialKeyId": "keyid-1", "ResultType": "7000215"},
        {**base, "Type": "AADManagedIdentitySignInLogs", "_ItemId": "m1", "AlId": "m1",
         "Category": "ManagedIdentitySignInLogs", "ServicePrincipalName": "vm-app01",
         "ServicePrincipalId": "7c1e0000-0000-4000-8000-000000000002", "IPAddress": "",
         "ResourceDisplayName": "Azure Key Vault"},
        {"TimeGenerated": "2026-10-24T02:00:02Z", "Type": "StorageBlobLogs", "_ItemId": "b1", "AlId": "b1",
         "OperationName": "GetBlob", "StatusCode": "200", "StatusText": "Success",
         "CallerIpAddress": "203.0.113.77:52344", "AccountName": "corpfinance",
         "ObjectKey": "/corpfinance/exports/payroll.csv", "AuthenticationType": "AccountKey",
         "ResponseBodySize": "4096", "Uri": "https://corpfinance.blob.core.windows.net/exports/payroll.csv"},
    ]


def test_aad_signin_tables_in_default_union_decoded_and_ingested(base_cfg, tmp_path, http, monkeypatch) -> None:
    from attacklens.connectors.azure_monitor import DEFAULT_TABLES
    assert {"AADNonInteractiveUserSignInLogs", "AADServicePrincipalSignInLogs",
            "AADManagedIdentitySignInLogs"} <= set(DEFAULT_TABLES)
    srv = TableServer(http, aad_rows())
    cfg = azure_cfg(base_cfg, tmp_path, monkeypatch)                         # page_size 2: keyset paging
    cfg["integrations"]["connectors"]["azure_monitor"]["events"]["optional_tables"] = {"StorageBlobLogs": True}
    st = get("azure_monitor", cfg).cycle()
    accounted(st)
    assert st["ok"] and st["written"] == 4, st
    head = srv.queries[0].split("|")[0]
    assert head.startswith("union isfuzzy=true AzureActivity, SigninLogs, AuditLogs, AADNonInteractiveUserSignInLogs,"
                           " AADServicePrincipalSignInLogs, AADManagedIdentitySignInLogs, StorageBlobLogs"), head
    docs = dict((d["_ItemId"], (b, d)) for b, d in spool_docs(tmp_path))
    assert docs["n1"][0] == "azure_aadnoninteractiveusersigninlogs"
    assert docs["s1"][0] == "azure_aadserviceprincipalsigninlogs" and docs["b1"][0] == "azure_storagebloblogs"
    assert docs["n1"][1]["LocationDetails"]["city"] == "Amsterdam"            # string-typed JSON column decoded
    assert docs["n1"][1]["Status"]["errorCode"] == 0 and "AlId" not in docs["n1"][1]
    assert "IPAddress" not in docs["m1"][1]                                   # empty column of the union dropped
    ctx = run_ingest(tmp_path / "spool" / "events", tmp_path / "ing")
    rows = query(ctx, "SELECT source_type, coalesce(target_user, src_user) AS who, src_ip, host, outcome FROM events")
    assert sorted(r["source_type"] for r in rows) == ["azure_signin_json"] * 3 + ["azure_storageblob_json"], rows
    sig = {r["who"]: r for r in rows if r["source_type"] == "azure_signin_json"}
    assert set(sig) == {"pmehta", "backup-automation", "vm-app01"}, sig               # UPN normalized to the name
    assert sig["pmehta"]["src_ip"] == "203.0.113.77" and sig["vm-app01"]["src_ip"] is None
    assert sig["backup-automation"]["outcome"] == "failure" and sig["pmehta"]["outcome"] == "success"
    blob = [r for r in rows if r["source_type"] == "azure_storageblob_json"]
    assert len(blob) == 1 and blob[0]["src_ip"] == "203.0.113.77", blob      # ip:port -> ip


def test_storageblob_optional_table_forms_and_validation() -> None:
    from attacklens.connectors.azure_monitor import DEFAULT_TABLES, all_tables, optional_tables
    assert all_tables({}) == list(DEFAULT_TABLES)                              # off by default
    assert all_tables({"optional_tables": {"StorageBlobLogs": False}}) == list(DEFAULT_TABLES)
    on = list(DEFAULT_TABLES) + ["StorageBlobLogs"]
    for form in ({"StorageBlobLogs": True}, ["StorageBlobLogs"], "StorageBlobLogs", " StorageBlobLogs , "):
        assert all_tables({"optional_tables": form}) == on, form
    assert all_tables({"tables": ["SigninLogs", "StorageBlobLogs"], "optional_tables": "StorageBlobLogs"}) == \
        ["SigninLogs", "StorageBlobLogs"]                                     # never twice
    assert optional_tables("") == [] and optional_tables(None) == []          # empty never falls back to defaults
    for bad in ("Storage Blob", "x|take 1", "T;drop"):
        with pytest.raises(ValueError, match="invalid table name"):
            optional_tables(bad)


# ----------------------------------------------------------------------------- alerts mode against the mock SIEM
def test_azure_monitor_alerts_mode_against_the_mock(base_cfg, tmp_path, monkeypatch) -> None:
    sys.path.insert(0, str(REPO / "tools"))
    import mock_cloud_seed as seed
    import mock_siem as ms
    from attacklens.connectors import azure_monitor

    from .test_mock_siem import write_fixture
    monkeypatch.setenv("AL_T_AZ_SECRET", "AZ-SECRET-claims-1")
    cloud = {"azure_tenant": seed.TENANT, "azure_client_id": "cid-claims", "azure_client_secret": "AZ-SECRET-claims-1",
             "sentinel_oauth": True}
    with ms.MockSIEM(write_fixture(tmp_path / "raw"), cloud=cloud) as m:
        cfg = make_cfg(base_cfg, tmp_path, "azure_monitor", base_url=m.url, login_url=m.url, workspace_id="ws1",
                       workspace_id_env=None, tenant_id=seed.TENANT, tenant_id_env=None, client_id="cid-claims",
                       client_id_env=None, client_secret_env="AL_T_AZ_SECRET", token_env=None, page_size=3)
        c = azure_monitor.AzureMonitorConnector(cfg, "alerts", T0 - 3_600_000)
        st = c.cycle()
        again = azure_monitor.AzureMonitorConnector(cfg, "alerts").cycle()
    accounted(st)
    assert st["ok"] and st["pulled"] == 7, st                                  # 7 SecurityAlert rows, 3 pages
    assert st["written"] + st["failed"] == 7 and set(st["failed_reasons"]) <= {"no_technique", "no_entity"}, st
    assert again["ok"] and again["written"] == 0, again                        # checkpoint: nothing twice
    rows = [json.loads(ln) for p in sorted((tmp_path / "spool" / "alerts").rglob("*.jsonl"))
            for ln in p.read_text(encoding="utf-8").splitlines() if ln]
    assert len(rows) == st["written"] and all(r["rule_id"].startswith("siem:azure_monitor:") for r in rows)
    brute = next(r for r in rows if "Brute force" in r["rule_id"])
    assert brute["sub_technique_id"] == "T1110.001" and brute["host"] and brute["src_ip"] == "203.0.113.57", brute
    assert not list((tmp_path / "spool" / "events").rglob("*.jsonl"))         # alerts never reach the events spool


# ----------------------------------------------------------------------------- AWS: STS role + organization trail
class Boto:
    """boto3 stub: Session(**kw).client(service) with sts.assume_role / get_caller_identity, cloudtrail
    lookup_events (empty) and S3 list / get over `objects`."""

    def __init__(self) -> None:
        self.sessions: list[dict[str, Any]] = []
        self.assumed: list[dict[str, Any]] = []
        self.lists: list[str] = []
        self.objects: dict[str, tuple[datetime, bytes]] = {}
        self.expiration = datetime.now(timezone.utc) + timedelta(hours=1)

    def module(self) -> types.ModuleType:
        b = self

        class Client:
            def __init__(self, service: str, sess: dict[str, Any]) -> None:
                self.service, self.sess = service, sess

            def assume_role(self, **kw: Any) -> dict[str, Any]:
                b.assumed.append({**kw, "_caller": self.sess.get("aws_access_key_id")})
                n = len(b.assumed)
                return {"Credentials": {"AccessKeyId": f"ASIATEMP{n}", "SecretAccessKey": f"temp-secret-{n}",
                                        "SessionToken": f"temp-token-{n}", "Expiration": b.expiration}}

            def get_caller_identity(self) -> dict[str, Any]:
                return {"Account": "999988887777"}

            def lookup_events(self, **kw: Any) -> dict[str, Any]:
                return {"Events": []}

            def list_objects_v2(self, **kw: Any) -> dict[str, Any]:
                b.lists.append(kw["Prefix"])
                return {"Contents": [{"Key": k, "LastModified": lm} for k, (lm, _) in b.objects.items()
                                     if k.startswith(kw["Prefix"])], "IsTruncated": False}

            def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:
                return {"Body": io.BytesIO(b.objects[Key][1])}

        class Session:
            def __init__(self, **kw: Any) -> None:
                self.kw = kw
                b.sessions.append(kw)

            def client(self, service: str, config: Any = None, **kw: Any) -> Client:
                return Client(service, self.kw)

        boto3 = types.ModuleType("boto3")
        boto3.session = types.SimpleNamespace(Session=Session)  # type: ignore[attr-defined]
        return boto3


@pytest.fixture
def boto(monkeypatch: pytest.MonkeyPatch) -> Boto:
    from attacklens.connectors import aws_cloudtrail
    fake = Boto()
    bconf = types.ModuleType("botocore.config")
    bconf.Config = lambda **kw: kw  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", fake.module())
    monkeypatch.setitem(sys.modules, "botocore", types.ModuleType("botocore"))
    monkeypatch.setitem(sys.modules, "botocore.config", bconf)
    monkeypatch.setattr(aws_cloudtrail, "_sleep", lambda s: None)
    monkeypatch.setenv("AL_T_AK", "AKIAEXAMPLE")
    monkeypatch.setenv("AL_T_SK", "aws-secret-xyz")
    return fake


def role_cfg(base, tmp, **over):
    return make_cfg(base, tmp, "aws_cloudtrail", access_key_id_env="AL_T_AK", secret_access_key_env="AL_T_SK",
                    session_token_env=None, min_call_interval_s=0,
                    role_arn="arn:aws:iam::111122223333:role/AttackLensRead", external_id="ext-42", **over)


def test_sts_role_arn_assumed_with_external_id_and_refreshed_before_expiry(base_cfg, tmp_path, boto) -> None:
    from attacklens.connectors.aws_cloudtrail import AwsCloudTrailConnector
    c = AwsCloudTrailConnector(role_cfg(base_cfg, tmp_path), "events", T0)
    st = c.cycle()
    assert st["ok"], st
    assert boto.assumed[0] == {"RoleArn": "arn:aws:iam::111122223333:role/AttackLensRead", "RoleSessionName":
                               "attacklens", "ExternalId": "ext-42", "_caller": "AKIAEXAMPLE"}
    assert boto.sessions[0]["aws_access_key_id"] == "AKIAEXAMPLE"              # base keys only call STS
    assert boto.sessions[1] == {"aws_access_key_id": "ASIATEMP1", "aws_secret_access_key": "temp-secret-1",
                                "aws_session_token": "temp-token-1", "region_name": "us-east-1"}
    c.client("cloudtrail")
    assert len(boto.assumed) == 1                                              # cached while valid
    boto.expiration = datetime.now(timezone.utc) + timedelta(minutes=2)
    c._role_exp = time.time() + 120                                            # 2 min left < 5 min skew
    c.client("cloudtrail")
    assert len(boto.assumed) == 2 and boto.sessions[-1]["aws_access_key_id"] == "ASIATEMP2"
    state = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "state").rglob("*.json"))
    assert "temp-secret" not in state and "aws-secret-xyz" not in state


def test_org_trail_prefix_several_member_accounts_and_dedupe(base_cfg, tmp_path, boto) -> None:
    from attacklens.connectors.aws_cloudtrail import AwsCloudTrailConnector
    org = "AWSLogs/o-abc123def4/{account}/CloudTrail/{region}/{yyyy}/{mm}/{dd}/"
    cfg = role_cfg(base_cfg, tmp_path, account_id="111122223333, 444455556666")
    ev = cfg["integrations"]["connectors"]["aws_cloudtrail"]["events"]
    ev.update(source="s3", s3_bucket="org-trail", s3_prefix=org, regions=["us-east-1", "eu-west-1"])
    c = AwsCloudTrailConnector(cfg, "events", T0)
    pre = c._prefixes(T0, T0 + 3_600_000)
    assert pre == [f"AWSLogs/o-abc123def4/{a}/CloudTrail/{r}/2026/10/24/" for a in ("111122223333", "444455556666")
                   for r in ("us-east-1", "eu-west-1")]

    def obj(acct: str, ids: list[str], lm_ms: int) -> tuple[datetime, bytes]:
        recs = [{"eventVersion": "1.09", "eventID": i, "eventTime": "2026-10-24T02:00:00Z", "recipientAccountId": acct,
                 "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey", "sourceIPAddress": "203.0.113.77",
                 "userIdentity": {"type": "IAMUser", "userName": "alice", "accountId": acct}} for i in ids]
        return datetime.fromtimestamp(lm_ms / 1000, tz=timezone.utc), gzip.compress(json.dumps({"Records": recs}).encode())
    k1 = "AWSLogs/o-abc123def4/111122223333/CloudTrail/us-east-1/2026/10/24/111122223333_CloudTrail_us-east-1_a.json.gz"
    k2 = "AWSLogs/o-abc123def4/444455556666/CloudTrail/eu-west-1/2026/10/24/444455556666_CloudTrail_eu-west-1_b.json.gz"
    k3 = "AWSLogs/111122223333/CloudTrail/us-east-1/2026/10/24/111122223333_CloudTrail_us-east-1_c.json.gz"
    k4 = k1.replace("_a.json.gz", "_d.json.gz")
    boto.objects = {k1: obj("111122223333", ["e1", "e2"], T0 + 60_000), k2: obj("444455556666", ["e3"], T0 + 90_000),
                    k3: obj("111122223333", ["e9"], T0 + 120_000),     # account trail: outside the org prefix
                    k4: obj("111122223333", ["e1"], T0 + 150_000)}     # the same event delivered again
    st = c.cycle()
    accounted(st)
    assert st["ok"] and st["written"] == 3 and st["skipped_reasons"] == {"duplicate": 1}, st
    assert all(p.startswith("AWSLogs/o-abc123def4/") for p in boto.lists)    # never the account trail / whole bucket
    assert sorted(d["eventID"] for _, d in spool_docs(tmp_path)) == ["e1", "e2", "e3"]
    cfg2 = role_cfg(base_cfg, tmp_path, account_id="1111-2222")
    with pytest.raises(ValueError, match="12-digit"):
        AwsCloudTrailConnector(cfg2, "events", T0)._accounts()
    assert ig.iso_ms(T0) == "2026-10-24T02:00:00.000Z"
