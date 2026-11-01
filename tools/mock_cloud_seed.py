"""Deterministic seed data for the mock cloud endpoints (tools/mock_cloud.py), stdlib only.

One small cross-source attack story hides in benign cloud activity (all IPs RFC 5737 / private, all names fake):
  C1 step 1  T1078.004 Initial Access        Azure SigninLogs: vreddy@corp.example signs in to the Azure Portal from
                                             a NEW IP 203.0.113.77 (NL); every earlier sign-in is from 192.0.2.10/11
  C1 step 2  T1078.004 Initial Access        AWS CloudTrail ConsoleLogin, IAM user vreddy, same IP, no MFA
  C1 step 3  T1098.001 Persistence           AWS iam CreateAccessKey for vreddy, by vreddy, same IP
  C1 step 4  T1098.003 Privilege Escalation  AWS iam AttachUserPolicy AdministratorAccess on vreddy, same IP
  C1 step 5  T1530 Collection                GCP data_access storage.objects.get x40 on corp-finance-exports by
                                             vreddy@corp.example from the same IP in 10 minutes
Decoys (must not become an incident): asharma's CreateAccessKey for svc-backup from the corp IP in business hours,
asharma resetting pmehta's password (AuditLogs), svc-backup's nightly 30 x storage.objects.get from 10.20.0.5.

The story is marked ONLY in the ground truth (ground_truth()); served records carry no label field.
Write the seed + ground truth to disk:  python tools/mock_cloud_seed.py --out data/raw/cloud_seed [--anchor now]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ANCHOR_MS = 1793404800000          # 2026-10-31T00:00:00Z (fixed anchor; "now" rebases everything by one offset)
MIN = 60_000
SPAN_MS = 6 * 60 * MIN + 10 * MIN  # last seed record is < anchor + 6h10m
ACCOUNT, REGION = "111122223333", "us-east-1"
TENANT = "4d5f1c2e-0000-4000-8000-0000000000a1"
SUBSCRIPTION = "9b0e6a51-0000-4000-8000-0000000000b2"
WORKSPACE = "ws-mock-0001"
PROJECT = "corp-prod-1234"
BUCKET_GCS = "corp-finance-exports"
S3_BUCKET = "attacklens-mock-trail"
ATTACKER_IP = "203.0.113.77"
CORP_IPS = ("192.0.2.10", "192.0.2.11")
BACKUP_IP = "10.20.0.5"
DOMAIN = "corp.example"
USERS = (("asharma", "Aarti Sharma"), ("pmehta", "Priya Mehta"), ("vreddy", "Vikram Reddy"), ("kiyer", "Kavya Iyer"))
LA_TABLES = ("AzureActivity", "SigninLogs", "AuditLogs")
FEEDS = LA_TABLES + ("CloudTrail", "GcpLogging")
TIE_OFFSET_MS = 300 * MIN          # tie_burst rows all share anchor + 5h
LATE_OFFSET_MS = 20 * MIN          # the late row is dated anchor + 20 min
FUTURE_MS = 6 * 3_600_000          # future row = now + 6h


@dataclass
class Item:
    ts_ms: int
    rid: str
    doc: dict[str, Any]            # LA row dict / CloudTrail event record / GCP LogEntry
    visible_after: int = 0         # served only once its feed has been queried this many times (late arrival)
    s3_only: bool = False          # CloudTrail data events: in the S3 trail files, not in LookupEvents


@dataclass
class Seed:
    anchor_ms: int
    feeds: dict[str, list[Item]] = field(default_factory=dict)


def iso(ms: int, frac: bool = False) -> str:
    d = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S") + (f".{d.microsecond // 1000:03d}" if frac else "") + "Z"


class _Ids:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)

    def guid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128), version=4))

    def hexs(self, n: int) -> str:
        return "".join(self.rng.choice("0123456789abcdef") for _ in range(n))

    def akid(self, prefix: str = "AKIA") -> str:
        return prefix + "".join(self.rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16))


# ----------------------------------------------------------------------------- Azure (Log Analytics rows)
def signin(ids: _Ids, ts: int, user: str, name: str, ip: str, ok: bool = True, country: str = "IN",
           city: str = "Bengaluru") -> Item:
    rid = ids.guid()
    row = {"TimeGenerated": iso(ts, True), "Id": rid, "CorrelationId": ids.guid(),
           "OperationName": "Sign-in activity", "Category": "SignInLogs",
           "UserPrincipalName": f"{user}@{DOMAIN}", "UserDisplayName": name, "UserId": ids.guid(),
           "AppDisplayName": "Azure Portal", "AppId": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
           "IPAddress": ip, "ClientAppUsed": "Browser", "IsInteractive": True,
           "ResultType": "0" if ok else "50126",
           "ResultDescription": "" if ok else
           "Invalid username or password or Invalid on-premise username or password.",
           "ConditionalAccessStatus": "notApplied", "AuthenticationRequirement": "singleFactorAuthentication",
           "RiskLevelDuringSignIn": "none", "RiskState": "none",
           "LocationDetails": json.dumps({"city": city, "state": "", "countryOrRegion": country}),
           "DeviceDetail": json.dumps({"operatingSystem": "Windows10", "browser": "Edge 129.0.0"}),
           "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/129.0", "TenantId": TENANT,
           "Type": "SigninLogs", "_ItemId": rid}
    return Item(ts, rid, row)


def activity(ids: _Ids, ts: int, op: str, caller: str, ip: str, rg: str = "rg-prod") -> Item:
    rid = ids.guid()
    provider = op.split("/")[0]
    res = f"/SUBSCRIPTIONS/{SUBSCRIPTION.upper()}/RESOURCEGROUPS/{rg.upper()}/PROVIDERS/{provider}/X/VM-APP-01"
    row = {"TimeGenerated": iso(ts, True), "OperationNameValue": op, "OperationName": op.split("/")[-2].title(),
           "CategoryValue": "Administrative", "Level": "Informational", "ActivityStatusValue": "Success",
           "ActivitySubstatusValue": "OK", "Caller": caller, "CallerIpAddress": ip, "CorrelationId": ids.guid(),
           "EventDataId": rid, "ResourceGroup": rg, "ResourceProviderValue": provider,
           "SubscriptionId": SUBSCRIPTION, "_ResourceId": res.lower(),
           "Properties_d": json.dumps({"eventCategory": "Administrative", "entity": res, "message": op}),
           "Authorization_d": json.dumps({"action": op, "scope": res}), "TenantId": TENANT,
           "Type": "AzureActivity", "_ItemId": rid}
    return Item(ts, rid, row)


def audit(ids: _Ids, ts: int, op: str, actor: str, ip: str, target: str, category: str) -> Item:
    rid = f"Directory_{ids.guid()}"
    row = {"TimeGenerated": iso(ts, True), "Id": rid, "OperationName": op, "ActivityDisplayName": op,
           "ActivityDateTime": iso(ts, True), "Category": category, "Result": "success", "ResultReason": "",
           "LoggedByService": "Core Directory", "CorrelationId": ids.guid(), "AADOperationType": op.split()[0],
           "InitiatedBy": json.dumps({"user": {"userPrincipalName": f"{actor}@{DOMAIN}", "ipAddress": ip}}),
           "TargetResources": json.dumps([{"userPrincipalName": f"{target}@{DOMAIN}", "type": "User"}]),
           "AdditionalDetails": json.dumps([]), "TenantId": TENANT, "Type": "AuditLogs", "_ItemId": rid}
    return Item(ts, rid, row)


# ----------------------------------------------------------------------------- AWS CloudTrail records
def trail(ids: _Ids, ts: int, source: str, name: str, user: str, ip: str, *, read_only: bool = False,
          req: dict[str, Any] | None = None, resp: dict[str, Any] | None = None, etype: str = "AwsApiCall",
          extra: dict[str, Any] | None = None, data_event: bool = False,
          resources: list[dict[str, str]] | None = None) -> Item:
    eid = ids.guid()
    ident: dict[str, Any] = {"type": "IAMUser", "principalId": "AIDA" + ids.akid("")[:17],
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}", "accountId": ACCOUNT, "userName": user}
    if etype == "AwsApiCall":
        ident["accessKeyId"] = ids.akid("ASIA")
    rec: dict[str, Any] = {"eventVersion": "1.09", "userIdentity": ident, "eventTime": iso(ts),
                           "eventSource": source, "eventName": name, "awsRegion": REGION, "sourceIPAddress": ip,
                           "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" if etype != "AwsApiCall"
                           else "aws-cli/2.17.0 Python/3.11 Windows/10",
                           "requestParameters": req, "responseElements": resp, "requestID": ids.guid(),
                           "eventID": eid, "readOnly": read_only, "eventType": etype,
                           "managementEvent": not data_event, "recipientAccountId": ACCOUNT,
                           "eventCategory": "Data" if data_event else "Management"}
    if resources:
        rec["resources"] = resources
    rec.update(extra or {})
    return Item(ts, eid, rec, s3_only=data_event)


def console_login(ids: _Ids, ts: int, user: str, ip: str, mfa: bool) -> Item:
    return trail(ids, ts, "signin.amazonaws.com", "ConsoleLogin", user, ip, etype="AwsConsoleSignIn",
                 resp={"ConsoleLogin": "Success"},
                 extra={"additionalEventData": {"LoginTo": "https://console.aws.amazon.com/console/home",
                                                "MobileVersion": "No", "MFAUsed": "Yes" if mfa else "No"}})


# ----------------------------------------------------------------------------- GCP LogEntry (cloudaudit)
def gcp(ids: _Ids, ts: int, principal: str, ip: str, service: str, method: str, resource_name: str,
        permission: str, *, data_access: bool, resource: dict[str, Any]) -> Item:
    insert = ids.hexs(12)
    log = "data_access" if data_access else "activity"
    entry = {"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "status": {},
                              "authenticationInfo": {"principalEmail": principal},
                              "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent":
                                                  "google-cloud-sdk gcloud/496.0.0,gzip(gfe)",
                                                  "requestAttributes": {"time": iso(ts, True), "auth": {}},
                                                  "destinationAttributes": {}},
                              "serviceName": service, "methodName": method,
                              "authorizationInfo": [{"resource": resource_name, "permission": permission,
                                                     "granted": True, "resourceAttributes": {}}],
                              "resourceName": resource_name, "resourceLocation": {"currentLocations": ["us-east1"]}},
             "insertId": insert, "resource": resource, "timestamp": iso(ts, True),
             "severity": "INFO" if data_access else "NOTICE",
             "logName": f"projects/{PROJECT}/logs/cloudaudit.googleapis.com%2F{log}",
             "receiveTimestamp": iso(ts + 412, True)}
    return Item(ts, insert, entry)


def gcs_get(ids: _Ids, ts: int, principal: str, ip: str, obj: str, bucket: str = BUCKET_GCS) -> Item:
    return gcp(ids, ts, principal, ip, "storage.googleapis.com", "storage.objects.get",
               f"projects/_/buckets/{bucket}/objects/{obj}", "storage.objects.get", data_access=True,
               resource={"type": "gcs_bucket", "labels": {"project_id": PROJECT, "bucket_name": bucket,
                                                          "location": "us-east1"}})


# ----------------------------------------------------------------------------- build
def build(anchor_ms: int = ANCHOR_MS, *, tie_burst: int = 0, late_after: int = 0,
          future_now_ms: int | None = None, late_ts_ms: int | None = None) -> Seed:
    """Same anchor -> same bytes. tie_burst: N extra rows sharing one timestamp per tie feed; late_after: one old row
    per feed (dated late_ts_ms, default anchor + 20 min) that appears only after that many queries of the feed;
    future_now_ms: one row per feed at now + 6h."""
    A, ids = anchor_ms, _Ids(20261031)
    f: dict[str, list[Item]] = {k: [] for k in FEEDS}
    for i in range(24):                                     # benign sign-ins, corp IPs only
        u, n = USERS[i % 4]
        f["SigninLogs"].append(signin(ids, A + (10 + 15 * i) * MIN, u, n, CORP_IPS[i % 2], ok=i != 7))
    f["SigninLogs"].append(signin(ids, A + 180 * MIN, "vreddy", "Vikram Reddy", ATTACKER_IP,
                                  country="NL", city="Amsterdam"))            # C1 step 1
    ops = ("MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION", "MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE/ACTION",
           "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE", "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION")
    for i in range(12):
        f["AzureActivity"].append(activity(ids, A + (5 + 30 * i) * MIN, ops[i % 4], f"asharma@{DOMAIN}",
                                           CORP_IPS[0]))
    for i, (op, cat, tgt) in enumerate((("Update user", "UserManagement", "kiyer"),
                                        ("Add member to group", "GroupManagement", "pmehta"),
                                        ("Reset user password", "UserManagement", "pmehta"),     # decoy
                                        ("Update user", "UserManagement", "vreddy"),
                                        ("Add member to group", "GroupManagement", "kiyer"),
                                        ("Update user", "UserManagement", "pmehta"),
                                        ("Update user", "UserManagement", "asharma"),
                                        ("Add member to group", "GroupManagement", "vreddy"))):
        f["AuditLogs"].append(audit(ids, A + (15 + 45 * i) * MIN, op, "asharma", CORP_IPS[1], tgt, cat))

    ct = f["CloudTrail"]
    benign = (("ec2.amazonaws.com", "DescribeInstances", True, {"maxResults": 100}),
              ("sts.amazonaws.com", "GetCallerIdentity", True, None),
              ("s3.amazonaws.com", "GetBucketPolicy", True, {"bucketName": "corp-app-assets"}),
              ("iam.amazonaws.com", "ListUsers", True, None),
              ("ec2.amazonaws.com", "StartInstances", False, {"instancesSet": {"items": [{"instanceId":
                                                                                         "i-0abc1234def567890"}]}}))
    for i in range(30):
        src, name, ro, req = benign[i % 5]
        ct.append(trail(ids, A + (3 + 12 * i) * MIN, src, name, "asharma", CORP_IPS[i % 2], read_only=ro, req=req))
    ct.append(console_login(ids, A + 60 * MIN, "asharma", CORP_IPS[0], mfa=True))
    ct.append(trail(ids, A + 120 * MIN, "iam.amazonaws.com", "CreateAccessKey", "asharma", CORP_IPS[0],   # decoy
                    req={"userName": "svc-backup"},
                    resp={"accessKey": {"accessKeyId": ids.akid(), "status": "Active", "userName": "svc-backup"}}))
    ct.append(console_login(ids, A + 185 * MIN, "vreddy", ATTACKER_IP, mfa=False))                      # step 2
    ct.append(trail(ids, A + 192 * MIN, "iam.amazonaws.com", "CreateAccessKey", "vreddy", ATTACKER_IP,  # step 3
                    req={"userName": "vreddy"},
                    resp={"accessKey": {"accessKeyId": ids.akid(), "status": "Active", "userName": "vreddy"}}))
    ct.append(trail(ids, A + 194 * MIN, "iam.amazonaws.com", "AttachUserPolicy", "vreddy", ATTACKER_IP,  # step 4
                    req={"userName": "vreddy", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    for i in range(10):                                     # S3 data events (trail files only)
        key = f"backups/2026-10-30/part-{i:03d}.tar"
        ct.append(trail(ids, A + (40 + i) * MIN, "s3.amazonaws.com", "GetObject", "svc-backup", BACKUP_IP,
                        read_only=True, data_event=True, req={"bucketName": "corp-backups", "key": key},
                        resources=[{"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::corp-backups/{key}"}]))

    g = f["GcpLogging"]
    for i in range(10):
        g.append(gcp(ids, A + (8 + 30 * i) * MIN, f"asharma@{DOMAIN}", CORP_IPS[0], "compute.googleapis.com",
                     "v1.compute.instances.start", f"projects/{PROJECT}/zones/us-east1-b/instances/app-{i % 3}",
                     "compute.instances.start", data_access=False,
                     resource={"type": "gce_instance", "labels": {"project_id": PROJECT, "zone": "us-east1-b",
                                                                 "instance_id": str(4100000000000000 + i)}}))
    svc = f"svc-backup@{PROJECT}.iam.gserviceaccount.com"
    for i in range(30):                                     # decoy: nightly backup job, internal IP
        g.append(gcs_get(ids, A + 50 * MIN + i * 10_000, svc, BACKUP_IP, f"db/dump-{i:03d}.sql.gz", "corp-db-backups"))
    for i in range(40):                                     # step 5: 40 objects in 10 min from the attacker IP
        g.append(gcs_get(ids, A + 210 * MIN + i * 15_000, f"vreddy@{DOMAIN}", ATTACKER_IP, f"q3/ledger-{i:03d}.csv"))

    _switches(f, ids, A, tie_burst, late_after, future_now_ms, late_ts_ms)
    for items in f.values():
        items.sort(key=lambda it: (it.ts_ms, it.rid))
    return Seed(A, f)


def benign_item(feed: str, ids: _Ids, ts: int) -> Item:
    """One ordinary record for a feed (late / future / appended rows)."""
    return {"SigninLogs": lambda: signin(ids, ts, "kiyer", "Kavya Iyer", CORP_IPS[0]),
            "AzureActivity": lambda: activity(ids, ts, "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE", f"asharma@{DOMAIN}",
                                              CORP_IPS[0]),
            "AuditLogs": lambda: audit(ids, ts, "Update user", "asharma", CORP_IPS[1], "kiyer", "UserManagement"),
            "CloudTrail": lambda: trail(ids, ts, "ec2.amazonaws.com", "DescribeInstances", "asharma", CORP_IPS[0],
                                        read_only=True),
            "GcpLogging": lambda: gcs_get(ids, ts, f"asharma@{DOMAIN}", CORP_IPS[0], "late/one.csv",
                                          "corp-app-assets")}[feed]()


def _switches(f: dict[str, list[Item]], ids: _Ids, A: int, tie_burst: int, late_after: int,
              future_now_ms: int | None, late_ts_ms: int | None = None) -> None:
    t = A + TIE_OFFSET_MS
    for i in range(tie_burst):
        f["AzureActivity"].append(activity(ids, t, "MICROSOFT.RESOURCES/TAGS/WRITE", f"automation@{DOMAIN}",
                                           CORP_IPS[1], rg=f"rg-tag-{i % 7}"))
        f["CloudTrail"].append(trail(ids, t, "tagging.amazonaws.com", "TagResources", "automation", CORP_IPS[1],
                                     req={"resourceARNList": [f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-{i:017x}"]}))
        f["GcpLogging"].append(gcs_get(ids, t, f"svc-backup@{PROJECT}.iam.gserviceaccount.com", BACKUP_IP,
                                       f"tie/{i:05d}.bin", "corp-db-backups"))
    extra: list[tuple[int, int]] = []
    if late_after:
        extra.append((late_ts_ms if late_ts_ms is not None else A + LATE_OFFSET_MS, late_after))
    if future_now_ms is not None:
        extra.append((future_now_ms + FUTURE_MS, 0))
    for ts, vis in extra:
        for feed in FEEDS:
            it = benign_item(feed, ids, ts)
            it.visible_after = vis
            f[feed].append(it)


def ground_truth(anchor_ms: int = ANCHOR_MS) -> dict[str, Any]:
    A = anchor_ms
    def step(n: int, off: int, t: str, tac: str, src: str) -> dict[str, Any]:
        return {"step": n, "ts_ms": A + off * MIN, "technique_id": t, "tactic": tac, "host": None, "user": "vreddy",
                "src_ip": ATTACKER_IP, "dst_ip": None, "source": src}
    return {"attack_version": "v20", "anchor_ms": A, "anchor": iso(A), "attacks": [{
        "id": "C1", "name": "cloud console login from a new IP -> IAM change -> data access", "steps": [
            step(1, 180, "T1078.004", "Initial Access", "azure_monitor:SigninLogs"),
            step(2, 185, "T1078.004", "Initial Access", "aws_cloudtrail:ConsoleLogin"),
            step(3, 192, "T1098.001", "Persistence", "aws_cloudtrail:CreateAccessKey"),
            step(4, 194, "T1098.003", "Privilege Escalation", "aws_cloudtrail:AttachUserPolicy"),
            step(5, 210, "T1530", "Collection", "gcp_logging:storage.objects.get")]}],
        "decoys": [
            {"ts_ms": A + 120 * MIN, "source": "aws_cloudtrail:CreateAccessKey", "user": "asharma",
             "why": "admin creates a key for svc-backup from the corp IP in business hours"},
            {"ts_ms": A + 105 * MIN, "source": "azure_monitor:AuditLogs", "user": "asharma",
             "why": "helpdesk password reset for pmehta"},
            {"ts_ms": A + 50 * MIN, "source": "gcp_logging:storage.objects.get", "user": "svc-backup",
             "why": "nightly backup job reads 30 objects from an internal IP"}]}


def now_anchor(now_ms: int) -> int:
    """Anchor so the seed ends ~50 min before now (inside a 24h default_since); minute-aligned."""
    return (now_ms - 7 * 3_600_000) // MIN * MIN


def write(out: Path, anchor_ms: int = ANCHOR_MS) -> Path:
    """Seed files per feed + ground_truth/attacks.json next to them (the served files have no labels)."""
    seed = build(anchor_ms)
    out.mkdir(parents=True, exist_ok=True)
    for feed, items in seed.feeds.items():
        (out / f"{feed}.jsonl").write_text("".join(json.dumps(it.doc, sort_keys=True) + "\n" for it in items),
                                           encoding="utf-8")
    (out / "ground_truth").mkdir(exist_ok=True)
    (out / "ground_truth" / "attacks.json").write_text(json.dumps(ground_truth(anchor_ms), indent=1),
                                                       encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="write the mock cloud seed + ground truth")
    ap.add_argument("--out", required=True)
    ap.add_argument("--anchor", default="fixed", help="fixed (2026-10-31T00:00Z) | now")
    a = ap.parse_args(argv)
    import time
    anchor = ANCHOR_MS if a.anchor == "fixed" else now_anchor(int(time.time() * 1000))
    write(Path(a.out), anchor)
    return 0


if __name__ == "__main__":
    sys.exit(main())
