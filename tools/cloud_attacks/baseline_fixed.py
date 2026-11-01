"""Fixed-volume recurring benign automation (independent of --size, so near-miss patterns are identical in every
set). Each helper takes (seed, day) and is deterministic; baseline.py places its events by hour.

Recurring near-misses (must NOT become incidents):
- backup_aws / backup_gcp: svc-backup bulk reads every night from 10.20.0.5 (looks like T1530 collection)
- ci_run: ci-deploy-role attaches / puts role policies on every workday, AttachUserPolicy on Tuesdays
- inventory: app-inventory gets AccessDenied every 15 min (steady error rate from a misconfigured app)
- app_server_boot: app-server-role reads SSM parameters + secrets 3x a day (A7 / A10 use the same API names)
"""

from __future__ import annotations

from cloud_attacks.common import (ACCT_DEV, ACCT_PROD, AWS_HUMANS, AZ_AUTOMATION_IP, BACKUP_IP, CI_IPS, CORP_IPS,
                                  DAY, DOMAIN, HOUR, MIN, PROJ_PROD, SEC, START_MS, Ev, sub_rng)
from cloud_attacks import formats as F

CI_SP = "7d2c0b4e-0000-4000-8000-00000000c1c1"         # Azure DevOps service principal object id
AUTOMATION_SP = "3a9e11f0-0000-4000-8000-00000000a7a7"
UA_GO = "aws-sdk-go/1.50.0 (go1.21.6; linux; amd64)"
UA_JAVA = "aws-sdk-java/2.25.10 Linux/5.10.215 OpenJDK_64-Bit_Server_VM/17.0.10 Java/17.0.10"
UA_GHA = "aws-sdk-js/3.540.0 ua/2.0 os/linux#6.5.0 lang/js md/nodejs#20.11.1 api/github-actions"
GHA_SUB = "repo:corp/orders-api:ref:refs/heads/main"


def is_workday(day: int) -> bool:
    return day % 7 < 5


def day0(day: int) -> int:
    return START_MS + day * DAY


def backup_aws(seed: int, day: int) -> list[Ev]:
    r = sub_rng(seed, "backup_aws", day)
    ident = F.iam_user(r, ACCT_PROD, "svc-backup")
    t = day0(day) + 30 * MIN
    out = []
    for i in range(400):
        out.append(F.s3_data(r, t + i * 3 * SEC, ACCT_PROD, ident, BACKUP_IP, "GetObject", "corp-backups",
                             f"rds/{day:02d}/chunk-{i:04d}.bak", ua=UA_GO))
    return out


def backup_gcp(seed: int, day: int) -> list[Ev]:
    r = sub_rng(seed, "backup_gcp", day)
    sa = f"svc-backup@{PROJ_PROD}.iam.gserviceaccount.com"
    t = day0(day) + HOUR
    return [F.gcs(r, t + i * 4 * SEC, PROJ_PROD, sa, BACKUP_IP, "storage.objects.get", "corp-db-backups",
                  f"pg/{day:02d}/dump-{i:03d}.sql.gz") for i in range(300)]


def ci_run(seed: int, day: int, run: int, acct: str = ACCT_PROD) -> list[Ev]:
    r = sub_rng(seed, "ci", acct, day, run)
    t = day0(day) + (5 + run * 1.4) * HOUR + r.randint(0, 20) * MIN
    ip = CI_IPS[r.randrange(len(CI_IPS))]
    reg = "ap-south-1"
    web = {"type": "WebIdentityUser", "principalId": f"arn:aws:iam::{acct}:oidc-provider/token.actions."
           f"githubusercontent.com:sts.amazonaws.com:{GHA_SUB}", "userName": GHA_SUB,
           "identityProvider": f"arn:aws:iam::{acct}:oidc-provider/token.actions.githubusercontent.com"}
    out = [F.ct(r, int(t), acct, reg, "sts.amazonaws.com", "AssumeRoleWithWebIdentity", web, ip, ua=UA_GHA,
                req={"roleArn": f"arn:aws:iam::{acct}:role/ci-deploy-role", "roleSessionName": f"gha-{r.randint(10**8, 10**9)}"},
                resp={"credentials": {"accessKeyId": r.akid("ASIA"), "expiration": "Oct 19, 2026, 6:00:00 AM"}})]
    who = F.assumed(r, acct, "ci-deploy-role", f"gha-{r.randint(10**8, 10**9)}")
    steps = [("ecr.amazonaws.com", "GetAuthorizationToken", True, None),
             ("cloudformation.amazonaws.com", "UpdateStack", False, {"stackName": "orders-api"}),
             ("lambda.amazonaws.com", "UpdateFunctionCode20150331v2", False, {"functionName": "orders-api"}),
             ("iam.amazonaws.com", "AttachRolePolicy", False,
              {"roleName": "app-orders-role", "policyArn": f"arn:aws:iam::{acct}:policy/orders-dynamodb-rw"}),
             ("iam.amazonaws.com", "PutRolePolicy", False,
              {"roleName": "app-orders-role", "policyName": "orders-sqs-inline"})]
    if day % 7 == 1 and run == 0 and acct == ACCT_PROD:   # Tuesday: CI re-applies the reporting user's policy
        steps.append(("iam.amazonaws.com", "AttachUserPolicy", False,
                      {"userName": "app-reporting", "policyArn": f"arn:aws:iam::{acct}:policy/reporting-s3-read"}))
    for k, (src, name, ro, req) in enumerate(steps):
        out.append(F.ct(r, int(t) + (k + 1) * 20 * SEC, acct, reg, src, name, who, ip, ua=UA_GHA, ro=ro, req=req))
    return out


def inventory(seed: int, day: int, hour: int) -> list[Ev]:
    r = sub_rng(seed, "inventory", day, hour)
    ident = F.iam_user(r, ACCT_PROD, "app-inventory")
    out = []
    for q in range(4):
        t = day0(day) + hour * HOUR + q * 15 * MIN + r.randint(0, 30) * SEC
        out.append(F.ct(r, t, ACCT_PROD, "ap-south-1", "ec2.amazonaws.com", "DescribeInstances", ident, "10.0.12.34",
                        ua=UA_JAVA, ro=True))
        out.append(F.ct(r, t + 2 * SEC, ACCT_PROD, "ap-south-1", "s3.amazonaws.com", "GetBucketTagging", ident,
                        "10.0.12.34", ua=UA_JAVA, ro=True, req={"bucketName": "corp-app-assets", "tagging": ""},
                        err=F.denied(ACCT_PROD, ident["arn"], "s3:GetBucketTagging")))
    return out


def metrics(seed: int, day: int, hour: int) -> list[Ev]:
    r = sub_rng(seed, "metrics", day, hour)
    ident = F.iam_user(r, ACCT_PROD, "svc-metrics")
    return [F.ct(r, day0(day) + hour * HOUR + k * 10 * MIN + r.randint(0, 20) * SEC, ACCT_PROD, "ap-south-1",
                 "monitoring.amazonaws.com", "PutMetricData", ident, "10.0.40.8", ua=UA_GO,
                 req={"namespace": "Corp/Orders"}) for k in range(6)]


def reporting(seed: int, day: int, hour: int) -> list[Ev]:
    r = sub_rng(seed, "reporting", day, hour)
    ident = F.iam_user(r, ACCT_PROD, "app-reporting")
    t = day0(day) + hour * HOUR + 7 * MIN
    out = [F.s3_data(r, t, ACCT_PROD, ident, "10.0.30.15", "ListObjects", "corp-reports", None, ua=UA_JAVA)]
    for k in range(3):
        out.append(F.s3_data(r, t + (k + 1) * 5 * SEC, ACCT_PROD, ident, "10.0.30.15", "GetObject", "corp-reports",
                             f"daily/{day:02d}/{hour:02d}-{k}.parquet", ua=UA_JAVA))
    return out


def app_server_boot(seed: int, day: int, hour: int) -> list[Ev]:
    if hour not in (2, 10, 18):
        return []
    r = sub_rng(seed, "boot", day, hour)
    who = F.assumed(r, ACCT_PROD, "app-server-role", "i-0a1b2c3d4e5f60789")
    t = day0(day) + hour * HOUR + r.randint(1, 50) * MIN
    return [F.ct(r, t, ACCT_PROD, "ap-south-1", "ssm.amazonaws.com", "GetParametersByPath", who, "10.0.5.21",
                 ua=UA_JAVA, ro=True, req={"path": "/prod/app/", "recursive": True, "withDecryption": True}),
            F.ct(r, t + 2 * SEC, ACCT_PROD, "ap-south-1", "secretsmanager.amazonaws.com", "GetSecretValue", who,
                 "10.0.5.21", ua=UA_JAVA, ro=True, req={"secretId": "prod/orders/db"})]


def human_morning(seed: int, day: int) -> list[Ev]:
    """Workday console logins with MFA, tgupta's routine AssumeRole, asharma's Monday IAM review."""
    if not is_workday(day):
        return []
    r = sub_rng(seed, "morning", day)
    out = []
    for i, u in enumerate(AWS_HUMANS):
        if r.random() < 0.75:
            ip = CORP_IPS[i % 2] if not (u == "vreddy" and day in (5, 6, 7)) else "192.0.2.25"
            out.append(F.console_login(r, day0(day) + int(3.7 * HOUR) + r.randint(0, 110) * MIN, ACCT_PROD, u, ip,
                                       mfa=True))
    t = day0(day) + int(4.2 * HOUR) + r.randint(0, 20) * MIN
    out.append(F.ct(r, t, ACCT_PROD, "ap-south-1", "sts.amazonaws.com", "AssumeRole",
                    F.iam_user(r, ACCT_PROD, "tgupta"), CORP_IPS[1], ro=True,
                    req={"roleArn": f"arn:aws:iam::{ACCT_PROD}:role/DevReadOnly", "roleSessionName": "tgupta"}))
    if day % 7 == 0:
        who = F.iam_user(r, ACCT_PROD, "asharma")
        t = day0(day) + 5 * HOUR
        for k, name in enumerate(("GetAccountAuthorizationDetails", "ListUsers", "ListAccessKeys", "ListRoles",
                                  "GenerateCredentialReport", "GetCredentialReport")):
            out.append(F.ct(r, t + k * 30 * SEC, ACCT_PROD, "us-east-1", "iam.amazonaws.com", name, who, CORP_IPS[0],
                            ro=True))
    return out


def azure_automation(seed: int, day: int) -> list[Ev]:
    r = sub_rng(seed, "az_auto", day)
    out = F.activity(r, day0(day) + 2 * HOUR + r.randint(0, 9) * MIN,
                     "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", AUTOMATION_SP, AZ_AUTOMATION_IP,
                     F.res_id("resourcegroups/rg-web/providers/microsoft.storage/storageaccounts/corpappassets"),
                     pair=False)
    if is_workday(day):
        for k in range(3):
            out += F.activity(r, day0(day) + (6 + 2 * k) * HOUR + r.randint(0, 50) * MIN,
                              "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE", CI_SP, CI_IPS[k],
                              F.res_id(f"resourcegroups/rg-web/providers/microsoft.resources/deployments/web-{day}-{k}"))
    return out


def gcp_admin(seed: int, day: int) -> list[Ev]:
    r = sub_rng(seed, "gcp_admin", day)
    out: list[Ev] = []
    tf = f"terraform-admin@{PROJ_PROD}.iam.gserviceaccount.com"
    if day % 7 == 1:   # weekly terraform apply from CI (near-miss for A6 step 2)
        t = day0(day) + 6 * HOUR + r.randint(0, 30) * MIN
        out.append(F.gcp(r, t, PROJ_PROD, tf, CI_IPS[2], "cloudresourcemanager.googleapis.com", "SetIamPolicy",
                         f"projects/{PROJ_PROD}", "resourcemanager.projects.setIamPolicy",
                         resource={"type": "project", "labels": {}}, ua="Terraform/1.9.5 terraform-provider-google/6.4",
                         service_data=F.policy_delta("roles/viewer", f"group:analysts@{DOMAIN}")))
    if day % 7 == 2:   # asharma updates a startup script (setMetadata is not rare globally; A8 uses it)
        t = day0(day) + 7 * HOUR + r.randint(0, 30) * MIN
        out.append(F.gcp(r, t, PROJ_PROD, f"asharma@{DOMAIN}", CORP_IPS[0], "compute.googleapis.com",
                         "v1.compute.instances.setMetadata",
                         f"projects/{PROJ_PROD}/zones/asia-south1-a/instances/app-1", "compute.instances.setMetadata",
                         resource={"type": "gce_instance", "labels": {"zone": "asia-south1-a",
                                                                       "instance_id": "4100000000000001"}}))
    return out


def fixed_daily(seed: int, day: int) -> list[Ev]:
    """Everything above that is placed once per day (bucketed into hours by the caller)."""
    out = backup_aws(seed, day) + backup_gcp(seed, day) + human_morning(seed, day) + azure_automation(seed, day)
    out += gcp_admin(seed, day)
    if is_workday(day):
        for run in range(6):
            out += ci_run(seed, day, run)
        out += ci_run(seed, day, 0, ACCT_DEV)
    return out


def fixed_hourly(seed: int, day: int, hour: int) -> list[Ev]:
    return (inventory(seed, day, hour) + metrics(seed, day, hour) + reporting(seed, day, hour)
            + app_server_boot(seed, day, hour))
