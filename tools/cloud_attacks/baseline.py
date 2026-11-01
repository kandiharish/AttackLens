"""Scaled benign baseline: employees + workloads across AWS, Entra ID / Azure and GCP, one hour at a time.

Volume = RATE[feed] events per weekday at scale 1, shaped by a Bengaluru-office diurnal curve (weekends x0.15 for
human traffic). Every (feed, day, hour) has its own RNG stream, so the bytes never depend on chunking.
Realism knobs: 3 % wrong passwords, 6 % MFA interrupts then success, rare benign 500121, AccessDenied from apps,
the real traveller vreddy (Singapore, days 5-7, MFA), VPN exits, admins doing IAM reads.
"""

from __future__ import annotations

from cloud_attacks.common import (ACCT_PROD, ALL_STAFF, AWS_HUMANS, CORP_IPS, DAY, DOMAIN, GCP_HUMANS, HOUR, MIN,
                                  PROJ_DATA, PROJ_PROD, REGIONS, SEC, START_MS, TRAVEL_IP, VPN_IPS, Ev, Rand,
                                  home_ip, staff_index, sub_rng)
from cloud_attacks import formats as F
from cloud_attacks.baseline_fixed import AUTOMATION_SP, CI_SP, UA_JAVA

W = (0.05, 0.05, 0.2, 0.6, 1, 1, 1, 1, 0.8, 1, 1, 1, 0.9, 0.6, 0.3, 0.2, 0.15, 0.1, 0.08, 0.05, 0.05, 0.05, 0.05,
     0.05)
WSUM = sum(W)
# events per weekday at scale 1: (human diurnal, workload flat)
RATE = {"cloudtrail": (1200, 800), "signin": (300, 0), "audit": (25, 0), "activity": (60, 40), "blob": (60, 90),
        "gcp": (300, 300)}
TRAVEL_DAYS = (5, 6, 7)

AWS_READS = (("ec2.amazonaws.com", "DescribeInstances"), ("ec2.amazonaws.com", "DescribeSecurityGroups"),
             ("ec2.amazonaws.com", "DescribeVolumes"), ("s3.amazonaws.com", "ListBuckets"),
             ("s3.amazonaws.com", "GetBucketPolicy"), ("iam.amazonaws.com", "ListRoles"),
             ("iam.amazonaws.com", "GetRole"), ("lambda.amazonaws.com", "ListFunctions20150331"),
             ("lambda.amazonaws.com", "GetFunction20150331v2"), ("logs.amazonaws.com", "FilterLogEvents"),
             ("logs.amazonaws.com", "DescribeLogGroups"), ("monitoring.amazonaws.com", "GetMetricData"),
             ("rds.amazonaws.com", "DescribeDBInstances"), ("ecs.amazonaws.com", "DescribeServices"),
             ("sts.amazonaws.com", "GetCallerIdentity"), ("cloudformation.amazonaws.com", "DescribeStacks"),
             ("ssm.amazonaws.com", "DescribeInstanceInformation"), ("glue.amazonaws.com", "GetTables"),
             ("kms.amazonaws.com", "ListKeys"), ("secretsmanager.amazonaws.com", "ListSecrets"))
AWS_WRITES = (("ec2.amazonaws.com", "StartInstances"), ("ec2.amazonaws.com", "StopInstances"),
              ("ec2.amazonaws.com", "CreateTags"), ("lambda.amazonaws.com", "UpdateFunctionConfiguration20150331v2"),
              ("ssm.amazonaws.com", "StartSession"), ("athena.amazonaws.com", "StartQueryExecution"))
APPS = ("Office 365 Exchange Online", "Microsoft Teams", "Office 365 SharePoint Online", "Azure Portal")
GCP_HUMAN_CALLS = (("compute.googleapis.com", "v1.compute.instances.list", "compute.instances.list", False),
                   ("compute.googleapis.com", "v1.compute.instances.get", "compute.instances.get", False),
                   ("bigquery.googleapis.com", "google.cloud.bigquery.v2.JobService.InsertJob",
                    "bigquery.jobs.create", True),
                   ("logging.googleapis.com", "google.logging.v2.LoggingServiceV2.ListLogEntries",
                    "logging.logEntries.list", True),
                   ("storage.googleapis.com", "storage.buckets.list", "storage.buckets.list", True))
AZ_OPS = ("MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION", "MICROSOFT.COMPUTE/VIRTUALMACHINES/DEALLOCATE/ACTION",
          "MICROSOFT.COMPUTE/VIRTUALMACHINES/RESTART/ACTION", "MICROSOFT.WEB/SITES/RESTART/ACTION",
          "MICROSOFT.RESOURCES/TAGS/WRITE", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE")


def _count(r: Rand, rate: float) -> int:
    n = int(rate)
    return n + (1 if r.random() < rate - n else 0)


def human_ip(r: Rand, user: str, day: int) -> str:
    if user == "vreddy" and day in TRAVEL_DAYS:
        return TRAVEL_IP if r.random() < 0.7 else VPN_IPS[3]
    x = r.random()
    if x < 0.6:
        return CORP_IPS[staff_index(user) % 2]
    if x < 0.85:
        return VPN_IPS[staff_index(user) % len(VPN_IPS)]
    return home_ip(staff_index(user))


def _geo(user: str, ip: str) -> tuple[str, str]:
    return ("SG", "Singapore") if ip == TRAVEL_IP else ("IN", ("Bengaluru", "Mumbai", "Pune")[staff_index(user) % 3])


def benign_hour(seed: int, scale: float, day: int, hour: int) -> list[Ev]:
    t0 = START_MS + day * DAY + hour * HOUR
    weekend = day % 7 >= 5
    out: list[Ev] = []
    for feed, (human, flat) in RATE.items():
        r = sub_rng(seed, "b", feed, day, hour)
        nh = _count(r, human * scale * W[hour] / WSUM * (0.15 if weekend else 1.0))
        nf = _count(r, flat * scale / 24)
        gen = _GEN[feed]
        for _ in range(nh):
            out += gen(r, t0 + r.randrange(HOUR - 60 * SEC), day, True)
        for _ in range(nf):
            out += gen(r, t0 + r.randrange(HOUR - 60 * SEC), day, False)
    return out


def _cloudtrail(r: Rand, t: int, day: int, human: bool) -> list[Ev]:
    region = REGIONS[0] if r.random() < 0.7 else r.choice(REGIONS[1:])
    if human:
        u = r.choice(AWS_HUMANS)
        ident, ip = F.iam_user(r, ACCT_PROD, u), human_ip(r, u, day)
        x = r.random()
        if x < 0.8:
            src, name = r.choice(AWS_READS)
            return [F.ct(r, t, ACCT_PROD, region, src, name, ident, ip, ro=True)]
        if x < 0.9:
            src, name = r.choice(AWS_WRITES)
            return [F.ct(r, t, ACCT_PROD, region, src, name, ident, ip)]
        bucket = "corp-customer-data" if u in ("lfernandes", "dsingh") else "corp-app-assets"
        return [F.s3_data(r, t, ACCT_PROD, ident, ip, r.choice(("GetObject", "ListObjects", "PutObject")), bucket,
                          f"tables/{r.randint(1, 400):04d}.parquet")]
    x = r.random()
    if x < 0.35:
        svc = r.choice(("ec2.amazonaws.com", "lambda.amazonaws.com", "ecs-tasks.amazonaws.com"))
        role = {"ec2.amazonaws.com": "app-server-role", "lambda.amazonaws.com": "lambda-etl-role",
                "ecs-tasks.amazonaws.com": "orders-task-role"}[svc]
        return [F.ct(r, t, ACCT_PROD, region, "sts.amazonaws.com", "AssumeRole", F.aws_service(svc), svc, ro=True,
                     ua=svc, req={"roleArn": f"arn:aws:iam::{ACCT_PROD}:role/{role}",
                                  "roleSessionName": r.hexs(16)})]
    if x < 0.6:
        return [F.ct(r, t, ACCT_PROD, region, "kms.amazonaws.com", r.choice(("Decrypt", "GenerateDataKey")),
                     F.aws_service("s3.amazonaws.com"), "s3.amazonaws.com", ro=True, ua="s3.amazonaws.com")]
    who = F.assumed(r, ACCT_PROD, "lambda-etl-role", "etl-nightly")
    if x < 0.85:
        return [F.s3_data(r, t, ACCT_PROD, who, f"10.0.6.{r.randint(10, 40)}", r.choice(("GetObject", "PutObject")),
                          "corp-analytics", f"etl/{day:02d}/{r.hexs(8)}.json", ua=UA_JAVA)]
    who = F.assumed(r, ACCT_PROD, "app-server-role", "i-0a1b2c3d4e5f60789")
    return [F.ct(r, t, ACCT_PROD, "ap-south-1", "ssm.amazonaws.com", "GetParameter", who, "10.0.5.21", ro=True,
                 ua=UA_JAVA, req={"name": "/prod/app/feature-flags"})]


def _signin(r: Rand, t: int, day: int, human: bool) -> list[Ev]:
    u, name, _ = r.choice(ALL_STAFF)
    ip = human_ip(r, u, day)
    country, city = _geo(u, ip)
    app = r.choice(APPS)
    kw = {"country": country, "city": city, "app": app}
    x = r.random()
    if x < 0.03:   # typo, then success
        return [F.signin(r, t, u, name, ip, result="50126", **kw),
                F.signin(r, t + r.randint(15, 60) * SEC, u, name, ip, mfa="Mobile app notification", ca="success",
                         **kw)]
    if x < 0.09:   # MFA interrupt, then success
        return [F.signin(r, t, u, name, ip, result="50074", **kw),
                F.signin(r, t + r.randint(10, 40) * SEC, u, name, ip, mfa="Mobile app notification", ca="success",
                         **kw)]
    if x < 0.092:  # benign single MFA denial (pressed deny by mistake), then success
        return [F.signin(r, t, u, name, ip, result="500121", **kw),
                F.signin(r, t + r.randint(30, 90) * SEC, u, name, ip, mfa="OATH verification code", ca="success",
                         **kw)]
    mfa = "Previously satisfied" if r.random() < 0.7 else "Mobile app notification"
    return [F.signin(r, t, u, name, ip, mfa=mfa, ca="success", **kw)]


def _audit(r: Rand, t: int, day: int, human: bool) -> list[Ev]:
    actor = r.choice(("asharma", "akumar", "akumar"))
    tgt = r.choice(ALL_STAFF)[0]
    op, cat = r.choice((("Update user", "UserManagement"), ("Add member to group", "GroupManagement"),
                        ("Reset user password", "UserManagement"), ("Change user license", "UserManagement"),
                        ("Update group", "GroupManagement")))
    if r.random() < 0.3:
        return [F.audit(r, t, "Update user", "UserManagement", "", [F.user_target(tgt)],
                        app="Microsoft Substrate Management")]
    return [F.audit(r, t, op, cat, CORP_IPS[0], [F.user_target(tgt)], actor=actor)]


def _activity(r: Rand, t: int, day: int, human: bool) -> list[Ev]:
    op = r.choice(AZ_OPS)
    rg = r.choice(("rg-prod", "rg-web", "rg-data"))
    kind = "virtualmachines" if "COMPUTE" in op else ("sites" if "WEB" in op else "networksecuritygroups")
    prov = op.split("/")[0].lower()
    res = F.res_id(f"resourcegroups/{rg}/providers/{prov}/{kind}/{rg[3:]}-{r.randint(1, 6)}")
    if human:
        u = r.choice(("asharma", "rnair", "akumar", "pmehta"))
        return F.activity(r, t, op, f"{u}@{DOMAIN}", human_ip(r, u, day), res)
    return F.activity(r, t, op, r.choice((AUTOMATION_SP, CI_SP)), "198.51.100.60", res)


def _blob(r: Rand, t: int, day: int, human: bool) -> list[Ev]:
    if human:
        u = r.choice(("kiyer", "nbose", "asharma", "lfernandes"))
        return [F.blob(r, t, "corpfinancedata", "rg-data", r.choice(("GetBlob", "ListBlobs", "GetBlobProperties")),
                       f"ledgers/2026/q{r.randint(1, 3)}-{r.randint(1, 900):04d}.csv", human_ip(r, u, day),
                       r.randint(49152, 65535), auth="OAuth", upn=f"{u}@{DOMAIN}",
                       ua="Mozilla/5.0 (Windows NT 10.0) Azure Portal")]
    return [F.blob(r, t, "corpappassets", "rg-web", "GetBlob", f"static/{r.hexs(10)}.js",
                   f"10.1.0.{r.randint(4, 30)}", r.randint(49152, 65535), auth="OAuth", oid=AUTOMATION_SP,
                   ua="azsdk-net-Storage.Blobs/12.21.0 (.NET 8.0.8; Linux)")]


def _gcp(r: Rand, t: int, day: int, human: bool) -> list[Ev]:
    if human:
        u = r.choice(GCP_HUMANS)
        ip, proj = human_ip(r, u, day), PROJ_DATA if u in ("mjoshi", "lfernandes", "dsingh") else PROJ_PROD
        if r.random() < 0.3:
            return [F.gcs(r, t, proj, f"{u}@{DOMAIN}", ip, r.choice(("storage.objects.get", "storage.objects.list")),
                          f"{proj}-analytics", f"exports/{r.randint(1, 500):04d}.csv")]
        svc, method, perm, da = r.choice(GCP_HUMAN_CALLS)
        rname = f"projects/{proj}" + ("/zones/asia-south1-a/instances/app-1" if "instances.get" in method else "")
        return [F.gcp(r, t, proj, f"{u}@{DOMAIN}", ip, svc, method, rname, perm, data_access=da,
                      resource={"type": "gce_instance" if "compute" in svc else "project", "labels": {}})]
    x = r.random()
    if x < 0.6:
        return [F.gcs(r, t, PROJ_PROD, f"gke-nodes@{PROJ_PROD}.iam.gserviceaccount.com", f"10.30.0.{r.randint(2, 60)}",
                      "storage.objects.get", "corp-artifacts", f"images/layer-{r.hexs(12)}")]
    sa = f"inventory-sync@{PROJ_PROD}.iam.gserviceaccount.com"
    deny = r.random() < 0.05
    return [F.gcp(r, t, PROJ_PROD, sa, "10.30.1.9", "compute.googleapis.com",
                  "v1.compute.disks.list" if deny else "v1.compute.instances.list",
                  f"projects/{PROJ_PROD}", "compute.disks.list" if deny else "compute.instances.list", denied=deny,
                  ua="google-api-go-client/0.5", resource={"type": "gce_instance", "labels": {}})]


_GEN = {"cloudtrail": _cloudtrail, "signin": _signin, "audit": _audit, "activity": _activity, "blob": _blob,
        "gcp": _gcp}
