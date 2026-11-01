"""The planted multi-step attack stories and the near-miss decoys.

Placement is fixed relative to START_MS and independent of --size, so the same attacks appear in cloud_small and
cloud1 (TESTING.md §3.1 rule 7). Modelled on Datadog Stratus Red Team (Apache-2.0,
https://github.com/DataDog/stratus-red-team) and public cloud-incident write-ups; all IPs are RFC 5737 / RFC 1918
and all identities fake. Attacker infrastructure uses 203.0.113.0/24 ONLY.

Technique / tactic labels use ATT&CK v20 (config/attack_v20.json): note Defense Evasion is split into Stealth and
Defense Impairment; "Disable or Modify Cloud Log" is T1685.002.
"""

from __future__ import annotations

from cloud_attacks.common import (ACCT_DEV, ACCT_EXTERNAL, ACCT_PROD, DOMAIN, MIN, OWNER_ROLE, PROJ_DATA, PROJ_PROD,
                                  SEC, SUB, Rand, sub_rng)
from cloud_attacks import formats as F
from cloud_attacks.story import Decoy, Step, Story, at

STRATUS = "https://github.com/DataDog/stratus-red-team"
AIP = {"A1": "203.0.113.11", "A2": "203.0.113.22", "A3": "203.0.113.33", "A4": "203.0.113.44", "A5": "203.0.113.55",
       "A6": "203.0.113.66", "A7": "203.0.113.77", "A8": "203.0.113.88", "A9": "203.0.113.99", "A10": "203.0.113.120"}


def _ct(r, t, name, ident, ip, src="iam.amazonaws.com", region="us-east-1", **kw):
    return F.ct(r, t, ACCT_PROD, region, src, name, ident, ip, **kw)


# ============================================================================ A1 — leaked AWS access key, full chain
def a1(seed: int) -> Story:
    r = sub_rng(seed, "A1")
    ip = AIP["A1"]
    who = F.iam_user(r, ACCT_PROD, "pmehta")       # pmehta's long-term key leaked in a public git repo
    t = at(2, 11, 5)
    s1 = [_ct(r, t, "GetCallerIdentity", who, ip, src="sts.amazonaws.com", ro=True, ua=F.UA_BOTO)]
    disc, td = [], t + 2 * MIN
    for k, (src, name, req) in enumerate((
            ("iam.amazonaws.com", "GetAccountAuthorizationDetails", None), ("iam.amazonaws.com", "ListUsers", None),
            ("iam.amazonaws.com", "ListRoles", None), ("iam.amazonaws.com", "ListAccessKeys", None),
            ("s3.amazonaws.com", "ListBuckets", None), ("ec2.amazonaws.com", "DescribeInstances", None),
            ("ec2.amazonaws.com", "DescribeSecurityGroups", None), ("rds.amazonaws.com", "DescribeDBInstances", None),
            ("kms.amazonaws.com", "ListKeys", None), ("organizations.amazonaws.com", "DescribeOrganization", None))):
        disc.append(_ct(r, td + k * 12 * SEC, name, who, ip, src=src, ro=True, ua=F.UA_BOTO, req=req))
    t3 = t + 9 * MIN
    s3 = [_ct(r, t3, "CreateUser", who, ip, ua=F.UA_BOTO, req={"userName": "support-ops"},
              resp={"user": {"userName": "support-ops", "userId": "AIDA" + r.b32(17),
                             "arn": f"arn:aws:iam::{ACCT_PROD}:user/support-ops"}}),
          _ct(r, t3 + 20 * SEC, "CreateAccessKey", who, ip, ua=F.UA_BOTO, req={"userName": "support-ops"},
              resp={"accessKey": {"accessKeyId": r.akid("AKIA"), "status": "Active", "userName": "support-ops"}})]
    s4 = [_ct(r, t + 11 * MIN, "AttachUserPolicy", who, ip, ua=F.UA_BOTO,
              req={"userName": "support-ops", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})]
    attacker = F.iam_user(r, ACCT_PROD, "support-ops")     # now acting as the new admin user
    t5 = t + 16 * MIN
    s5 = [_ct(r, t5, "StopLogging", attacker, ip, src="cloudtrail.amazonaws.com", ua=F.UA_BOTO,
              req={"name": f"arn:aws:cloudtrail:us-east-1:{ACCT_PROD}:trail/corp-org-trail"}),
          _ct(r, t5 + 30 * SEC, "DeleteTrail", attacker, ip, src="cloudtrail.amazonaws.com", ua=F.UA_BOTO,
              req={"name": f"arn:aws:cloudtrail:us-east-1:{ACCT_PROD}:trail/corp-org-trail"})]
    t6 = t + 20 * MIN
    s6 = [F.s3_data(r, t6 + k * 4 * SEC, ACCT_PROD, attacker, ip, "GetObject", "corp-customer-data",
                    f"pii/export-{k:04d}.csv.gz", ua=F.UA_BOTO) for k in range(60)]
    s7 = [_ct(r, t + 27 * MIN, "ModifySnapshotAttribute", attacker, ip, src="ec2.amazonaws.com", region="ap-south-1",
              req={"snapshotId": "snap-0abc1234def567890", "attributeType": "createVolumePermission",
                   "createVolumePermission": {"add": [{"userId": ACCT_EXTERNAL}]}})]
    return Story("A1", "leaked AWS key: discovery -> new admin -> trail off -> S3 exfil -> snapshot shared out",
                 ("aws",), (STRATUS + " (aws.credential-access, aws.exfiltration.ec2-share-ebs-snapshot)",), [
        Step("T1078.004", "Initial Access", s1, "GetCallerIdentity with the leaked key from a new ASN"),
        Step("T1580", "Discovery", disc, "IAM / EC2 / S3 enumeration burst"),
        Step("T1136.003", "Persistence", s3, "CreateUser support-ops + CreateAccessKey"),
        Step("T1098.003", "Privilege Escalation", s4, "AttachUserPolicy AdministratorAccess"),
        Step("T1685.002", "Defense Impairment", s5, "StopLogging then DeleteTrail"),
        Step("T1530", "Collection", s6, "60x S3 GetObject from corp-customer-data"),
        Step("T1537", "Exfiltration", s7, "share EBS snapshot to external account")])


# ============================================================================ A2 — role chaining -> cloud ransomware
def a2(seed: int) -> Story:
    r = sub_rng(seed, "A2")
    ip = AIP["A2"]
    t = at(3, 20, 0)
    dev = F.iam_user(r, ACCT_PROD, "tgupta")   # compromised dev, out-of-hours console login (20:00 UTC = 01:30 IST)
    s1 = [F.console_login(r, t, ACCT_PROD, "tgupta", ip, mfa=False)]
    r1 = F.assumed(r, ACCT_PROD, "DevReadOnly", "tgupta")
    r2 = F.assumed(r, ACCT_PROD, "InfraDeploy", "chain")
    s2 = [_ct(r, t + 3 * MIN, "AssumeRole", dev, ip, src="sts.amazonaws.com", ua=F.UA_BOTO,
              req={"roleArn": f"arn:aws:iam::{ACCT_PROD}:role/DevReadOnly", "roleSessionName": "tgupta"}),
          _ct(r, t + 4 * MIN, "AssumeRole", r1, ip, src="sts.amazonaws.com", ua=F.UA_BOTO,
              req={"roleArn": f"arn:aws:iam::{ACCT_PROD}:role/InfraDeploy", "roleSessionName": "chain"})]
    t3 = t + 12 * MIN
    s3 = [_ct(r, t3, "CreateFunction20150331", r2, ip, src="lambda.amazonaws.com", region="ap-south-1", ua=F.UA_BOTO,
              req={"functionName": "orders-metrics-sync", "runtime": "python3.12",
                   "role": f"arn:aws:iam::{ACCT_PROD}:role/InfraDeploy", "handler": "index.handler"}),
          _ct(r, t3 + 25 * SEC, "CreateEventSourceMapping", r2, ip, src="lambda.amazonaws.com", region="ap-south-1",
              ua=F.UA_BOTO, req={"functionName": "orders-metrics-sync", "eventSourceArn":
                                 f"arn:aws:dynamodb:ap-south-1:{ACCT_PROD}:table/orders/stream/2026"})]
    s4 = [_ct(r, t + 20 * MIN, "AuthorizeSecurityGroupIngress", r2, ip, src="ec2.amazonaws.com", region="ap-south-1",
              ua=F.UA_BOTO, req={"groupId": "sg-0aa11bb22cc33dd44", "ipPermissions": {"items": [
                  {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
                   "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}})]
    t5 = t + 40 * MIN
    s5 = [_ct(r, t5 + k * 15 * SEC, "ScheduleKeyDeletion", r2, ip, src="kms.amazonaws.com", region="ap-south-1",
              ua=F.UA_BOTO, req={"keyId": f"arn:aws:kms:ap-south-1:{ACCT_PROD}:key/{r.guid()}",
                                 "pendingWindowInDays": 7}) for k in range(4)]
    t6 = t + 50 * MIN
    s6 = [F.s3_data(r, t6 + k * 3 * SEC, ACCT_PROD, r2, ip, "DeleteObject", "corp-customer-data",
                    f"pii/export-{k:04d}.csv.gz", ua=F.UA_BOTO) for k in range(80)]
    return Story("A2", "AWS role chaining -> Lambda backdoor -> SG 0.0.0.0/0 -> KMS key deletion + mass S3 delete",
                 ("aws",), (STRATUS + " (aws.defense-evasion.cloudtrail-stop, aws.impact.s3-ransomware)",), [
        Step("T1078.004", "Initial Access", s1, "out-of-hours console login without MFA"),
        Step("T1550.001", "Lateral Movement", s2, "AssumeRole chaining DevReadOnly -> InfraDeploy"),
        Step("T1648", "Execution", s3, "Lambda backdoor with a DynamoDB stream trigger"),
        Step("T1686.001", "Defense Impairment", s4, "open security group 0.0.0.0/0 on port 22"),
        Step("T1486", "Impact", s5, "KMS ScheduleKeyDeletion on 4 data keys"),
        Step("T1485", "Impact", s6, "80x S3 DeleteObject")])


# ============================================================================ A3 — Azure spray -> Owner -> blob exfil
def a3(seed: int) -> Story:
    r = sub_rng(seed, "A3")
    ip = AIP["A3"]
    victims = ("kiyer", "nbose", "mjoshi", "skapoor", "rnair", "lfernandes", "dsingh", "akumar", "tgupta", "vreddy")
    t = at(4, 21, 0)
    spray = []
    for k in range(60):
        u = victims[k % len(victims)]
        spray.append(F.signin(r, t + k * 8 * SEC, u, u.title(), ip, result="50126", country="RU", city="Moscow",
                              app="Azure Portal", client="Browser"))
    hit = "kiyer"
    s2 = [F.signin(r, t + 11 * MIN, hit, "Kavya Iyer", ip, country="RU", city="Moscow", app="Azure Portal",
                   ca="notApplied")]   # success, single factor, no MFA
    t3 = at(4, 21, 30)
    appoid = r.guid()
    s3 = [F.audit(r, t3, "Add application", "ApplicationManagement", ip,
                  [F.obj_target("Application", "corp-reporting-sync", appoid)], actor=hit),
          F.audit(r, t3 + 90 * SEC, "Add service principal", "ApplicationManagement", ip,
                  [F.obj_target("ServicePrincipal", "corp-reporting-sync", r.guid())], actor=hit),
          F.audit(r, t3 + 150 * SEC, "Add service principal credentials", "ApplicationManagement", ip,
                  [F.obj_target("ServicePrincipal", "corp-reporting-sync", appoid,
                                [{"displayName": "KeyDescription", "newValue": '["[Password]"]'}])], actor=hit)]
    s4 = F.activity(r, at(5, 8, 0), "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", f"{hit}@{DOMAIN}", ip,
                    F.res_id(f"providers/microsoft.authorization/roleassignments/{r.guid()}"),
                    props={"roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/"
                           f"roleDefinitions/{OWNER_ROLE}", "principalId": r.guid(), "principalType": "User"})
    s5 = F.activity(r, at(5, 8, 20), "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE", f"{hit}@{DOMAIN}", ip,
                    F.res_id("resourcegroups/rg-data/providers/microsoft.storage/storageaccounts/corpfinancedata/"
                             "providers/microsoft.insights/diagnosticsettings/to-sentinel"))
    s6 = F.activity(r, at(5, 8, 40), "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION", f"{hit}@{DOMAIN}", ip,
                    F.res_id("resourcegroups/rg-data/providers/microsoft.storage/storageaccounts/corpfinancedata"))
    s6 += F.activity(r, at(5, 8, 42), "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION", f"{hit}@{DOMAIN}", ip,
                     F.res_id("resourcegroups/rg-data/providers/microsoft.storage/storageaccounts/corpfinancedata"))
    t7 = at(5, 9, 0)
    s7 = [F.blob(r, t7 + k * 2 * SEC, "corpfinancedata", "rg-data", "GetBlob", f"ledgers/2026/q3-{k:04d}.csv", ip,
                 r.randint(49152, 65535), auth="AccountKey") for k in range(120)]
    return Story("A3", "Entra ID password spray -> no-MFA sign-in -> app credential -> Owner -> diag off -> blob exfil",
                 ("azure",), (STRATUS + " (azure.initial-access, azure.persistence.create-service-principal)",), [
        Step("T1110.003", "Credential Access", spray, "60 failed sign-ins across 10 users from one IP", user=None),
        Step("T1078.004", "Initial Access", s2, "successful single-factor sign-in from a new country"),
        Step("T1098.001", "Persistence", s3, "new app registration + service principal credential"),
        Step("T1098.003", "Privilege Escalation", s4, "Owner role assignment at subscription scope"),
        Step("T1685.002", "Defense Impairment", s5, "delete the storage diagnostic setting"),
        Step("T1555.006", "Credential Access", s6, "list then regenerate storage account keys"),
        Step("T1530", "Collection", s7, "120x blob download with the account key")])


# ============================================================================ A4 — MFA fatigue + OAuth consent
def a4(seed: int) -> Story:
    r = sub_rng(seed, "A4")
    ip = AIP["A4"]
    u, name = "rnair", "Rohan Nair"
    t = at(5, 19, 0)
    fatigue = [F.signin(r, t + k * 40 * SEC, u, name, ip, result="500121", country="DE", city="Frankfurt",
                        app="Microsoft Teams", mfa="Mobile app notification") for k in range(9)]
    s2 = [F.signin(r, t + 7 * MIN, u, name, ip, country="DE", city="Frankfurt", app="Microsoft Teams",
                   mfa="Mobile app notification", ca="success")]   # user finally approves
    t3 = t + 15 * MIN
    appoid = r.guid()
    s3 = [F.audit(r, t3, "Consent to application", "ApplicationManagement", ip,
                  [F.obj_target("ServicePrincipal", "PDF Merger Pro", appoid,
                                [{"displayName": "ConsentContext.IsAdminConsent", "newValue": '"False"'}])], actor=u),
          F.audit(r, t3 + 20 * SEC, "Add OAuth2PermissionGrant", "ApplicationManagement", ip,
                  [F.obj_target("ServicePrincipal", "PDF Merger Pro", appoid,
                                [{"displayName": "Scope", "newValue": '"Mail.Read Mail.Send offline_access"'}])],
                  actor=u)]
    s4 = [F.audit(r, t3 + 4 * MIN, "Add service principal credentials", "ApplicationManagement", ip,
                  [F.obj_target("ServicePrincipal", "PDF Merger Pro", appoid)], actor=u)]
    return Story("A4", "Entra ID MFA fatigue -> approval -> illicit OAuth consent (Mail.Read) -> SP credential",
                 ("azure",), (STRATUS + " (azure.credential-access, entra.oauth-consent-grant)",), [
        Step("T1621", "Credential Access", fatigue, "9 MFA push prompts in 6 minutes"),
        Step("T1078.004", "Initial Access", s2, "sign-in after the user approves a prompt"),
        Step("T1528", "Credential Access", s3, "illicit OAuth consent for Mail.Read / Mail.Send"),
        Step("T1098.001", "Persistence", s4, "add a credential to the consented service principal")])


# ============================================================================ A5 — GCP SA key -> owner -> public bucket
def a5(seed: int) -> Story:
    r = sub_rng(seed, "A5")
    ip = AIP["A5"]
    actor = f"dsingh@{DOMAIN}"       # a data engineer who has never touched IAM
    sa = f"ingest-runner@{PROJ_DATA}.iam.gserviceaccount.com"
    t = at(6, 20, 0)
    s1 = [F.gcp(r, t, PROJ_DATA, actor, ip, "iam.googleapis.com",
                "google.iam.admin.v1.CreateServiceAccountKey",
                f"projects/{PROJ_DATA}/serviceAccounts/{sa}", "iam.serviceAccountKeys.create",
                resource={"type": "service_account", "labels": {"email_id": sa}},
                response={"name": f"projects/{PROJ_DATA}/serviceAccounts/{sa}/keys/{r.hexs(40)}"})]
    s2 = [F.gcp(r, t + 6 * MIN, PROJ_DATA, actor, ip, "cloudresourcemanager.googleapis.com", "SetIamPolicy",
                f"projects/{PROJ_DATA}", "resourcemanager.projects.setIamPolicy",
                resource={"type": "project", "labels": {}},
                service_data=F.policy_delta("roles/owner", f"serviceAccount:{sa}"))]
    s3 = [F.gcp(r, t + 12 * MIN, PROJ_DATA, sa, ip, "logging.googleapis.com",
                "google.logging.v2.ConfigServiceV2.DeleteSink",
                f"projects/{PROJ_DATA}/sinks/to-siem", "logging.sinks.delete",
                resource={"type": "logging_sink", "labels": {"name": "to-siem"}}, sa_key="//iam.googleapis.com/"
                f"projects/{PROJ_DATA}/serviceAccounts/{sa}/keys/{r.hexs(40)}")]
    t4 = t + 18 * MIN
    bucket = "corp-data-exports"
    s4 = [F.gcp(r, t4, PROJ_DATA, sa, ip, "storage.googleapis.com", "storage.setIamPermissions",
                f"projects/_/buckets/{bucket}", "storage.buckets.setIamPolicy",
                resource={"type": "gcs_bucket", "labels": {"bucket_name": bucket}},
                service_data=F.policy_delta("roles/storage.objectViewer", "allUsers"))]
    s4 += [F.gcs(r, t4 + 30 * SEC + k * 3 * SEC, PROJ_DATA, sa, ip, "storage.objects.get", bucket,
                 f"warehouse/customers-{k:04d}.parquet") for k in range(80)]
    return Story("A5", "GCP SA key by unusual principal -> project Owner -> logging sink delete -> public bucket read",
                 ("gcp",), (STRATUS + " (gcp.persistence.sa-key, gcp.exfiltration.gcs-make-public)",), [
        Step("T1098.001", "Persistence", s1, "CreateServiceAccountKey by a user who never uses IAM"),
        Step("T1098.003", "Privilege Escalation", s2, "SetIamPolicy grants roles/owner to the SA"),
        Step("T1685.002", "Defense Impairment", s3, "delete the logging sink to the SIEM"),
        Step("T1530", "Collection", s4, "make the bucket public (allUsers) then 80x objects.get")])


# ============================================================================ A6 — NOVEL AWS: behaviour only
def a6(seed: int) -> Story:
    r = sub_rng(seed, "A6")
    ip = AIP["A6"]
    # svc-metrics normally only PutMetricData from 10.0.40.8. No famous attack API is used; the signal is:
    # first-seen external geo + APIs this principal never calls + an AccessDenied rate spike.
    who = F.iam_user(r, ACCT_PROD, "svc-metrics")
    arn = who["arn"]
    t = at(7, 23, 0)
    s1 = [_ct(r, t, "GetCallerIdentity", who, ip, src="sts.amazonaws.com", ro=True, ua=F.UA_BOTO)]
    t2 = t + 2 * MIN
    rare = (("ec2.amazonaws.com", "DescribeInstances", False), ("s3.amazonaws.com", "ListBuckets", False),
            ("rds.amazonaws.com", "DescribeDBInstances", False), ("dynamodb.amazonaws.com", "ListTables", False),
            ("iam.amazonaws.com", "ListRoles", True), ("iam.amazonaws.com", "GetAccountAuthorizationDetails", True),
            ("lambda.amazonaws.com", "ListFunctions20150331", False), ("ecr.amazonaws.com", "DescribeRepositories",
             True), ("glue.amazonaws.com", "GetDatabases", True), ("redshift.amazonaws.com", "DescribeClusters",
             False))
    s2 = []
    for k, (src, name, deny) in enumerate(rare):
        s2.append(_ct(r, t2 + k * 9 * SEC, name, who, ip, src=src, ro=True, ua=F.UA_BOTO,
                      err=F.denied(ACCT_PROD, arn, f"{src.split('.')[0]}:{name}") if deny else None))
    t3 = t + 6 * MIN
    s3 = []
    for k in range(12):   # reads secrets it has no access to: steady 403 spike, generic API names
        s3.append(_ct(r, t3 + k * 6 * SEC, "GetSecretValue", who, ip, src="secretsmanager.amazonaws.com",
                      region="ap-south-1", ro=True, ua=F.UA_BOTO, req={"secretId": f"prod/{k}/db"},
                      err=F.denied(ACCT_PROD, arn, "secretsmanager:GetSecretValue")))
    return Story("A6", "NOVEL AWS: dormant service identity used from a new ASN, rare-for-it API sweep, 403 spike",
                 ("aws",), ("behavioural (no signature API); cf. " + STRATUS + " discovery techniques",), [
        Step("T1078.004", "Initial Access", s1, "dormant key used from a first-seen external IP"),
        Step("T1580", "Discovery", s2, "APIs this principal has never called, several AccessDenied"),
        Step("T1552", "Credential Access", s3, "Secrets Manager reads with a sustained AccessDenied rate")],
        novel=True)


# ============================================================================ A7 — NOVEL Azure/GCP: behaviour only
def a7(seed: int) -> Story:
    r = sub_rng(seed, "A7")
    ip = AIP["A7"]
    # kiyer (finance) normally reads finance blobs over OAuth from India. No no-MFA / famous signal: she signs in
    # WITH MFA, but from a first-seen country, then does activity she never does and a read-volume spike.
    u, name = "kiyer", "Kavya Iyer"
    t = at(8, 22, 0)
    s1 = [F.signin(r, t, u, name, ip, country="BR", city="Sao Paulo", app="Azure Portal",
                   mfa="Mobile app notification", ca="success")]
    t2 = t + 5 * MIN
    rare_ops = ("MICROSOFT.COMPUTE/VIRTUALMACHINES/READ", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/READ",
                "MICROSOFT.KEYVAULT/VAULTS/READ", "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/READ",
                "MICROSOFT.SQL/SERVERS/DATABASES/READ", "MICROSOFT.WEB/SITES/CONFIG/READ")
    s2 = []
    for k, op in enumerate(rare_ops):
        prov = op.split("/")[0].lower()
        res = F.res_id(f"resourcegroups/rg-prod/providers/{prov}/x/probe-{k}")
        s2 += F.activity(r, t2 + k * 20 * SEC, op, f"{u}@{DOMAIN}", ip, res, pair=False,
                         fail=k % 2 == 1, category="Administrative")
    t3 = t + 20 * MIN
    s3 = [F.blob(r, t3 + k * 2 * SEC, "corpfinancedata", "rg-data", "GetBlob", f"ledgers/2026/q2-{k:04d}.csv", ip,
                 r.randint(49152, 65535), auth="OAuth", upn=f"{u}@{DOMAIN}") for k in range(90)]
    return Story("A7", "NOVEL Azure: MFA-satisfied sign-in from a first-seen country, rare resource reads, blob spike",
                 ("azure",), ("behavioural (first-seen geo + rarity + error spike, no signature API)",), [
        Step("T1078.004", "Initial Access", s1, "sign-in from a country this user has never used (MFA satisfied)"),
        Step("T1619", "Discovery", s2, "resource reads outside this user's normal scope, some 403"),
        Step("T1530", "Collection", s3, "90x finance blob download in 4 minutes")], novel=True)


# ============================================================================ A8 — AWS EBS snapshot exfil
def a8(seed: int) -> Story:
    r = sub_rng(seed, "A8")
    ip = AIP["A8"]
    t = at(9, 18, 0)
    who = F.iam_user(r, ACCT_PROD, "vreddy")
    s1 = [F.console_login(r, t, ACCT_PROD, "vreddy", ip, mfa=False)]
    t2 = t + 20 * MIN
    s2 = [_ct(r, t2 + k * 30 * SEC, "CreateSnapshot", who, ip, src="ec2.amazonaws.com", region="ap-south-1",
              ua=F.UA_BOTO, req={"volumeId": f"vol-0{r.hexs(16)}", "description": "backup"},
              resp={"snapshotId": f"snap-0{r.hexs(16)}"}) for k in range(3)]
    s3 = [_ct(r, t + 110 * MIN, "ModifySnapshotAttribute", who, ip, src="ec2.amazonaws.com", region="ap-south-1",
              ua=F.UA_BOTO, req={"snapshotId": f"snap-0{r.hexs(16)}", "attributeType": "createVolumePermission",
                                 "createVolumePermission": {"add": [{"userId": ACCT_EXTERNAL}]}})]
    return Story("A8", "AWS: compromised user snapshots data volumes and shares them to an external account",
                 ("aws",), (STRATUS + " (aws.exfiltration.ec2-share-ebs-snapshot)",), [
        Step("T1078.004", "Initial Access", s1, "console login without MFA from a new IP"),
        Step("T1578.001", "Defense Impairment", s2, "CreateSnapshot of 3 data volumes"),
        Step("T1537", "Exfiltration", s3, "share the snapshot to an external AWS account")])


# ============================================================================ A9 — GCP bucket discovery + exfil
def a9(seed: int) -> Story:
    r = sub_rng(seed, "A9")
    ip = AIP["A9"]
    actor = f"lfernandes@{DOMAIN}"
    s1 = [F.gcs(r, at(10, 21, 0), PROJ_DATA, actor, ip, "storage.buckets.list", "corp-data-5678-analytics", None)]
    t2 = at(10, 21, 5)
    s2 = [F.gcs(r, t2 + k * 4 * SEC, PROJ_DATA, actor, ip, "storage.objects.list", f"corp-data-bucket-{k % 6}", None)
          for k in range(24)]
    t3 = at(11, 2, 0)      # exfil the next night: copy objects into an attacker bucket in another project
    s3 = [F.gcs(r, t3 + k * 3 * SEC, PROJ_DATA, actor, ip, "storage.objects.create", "exfil-dropbox-990", f"loot/{k:04d}")
          for k in range(70)]
    return Story("A9", "GCP: enumerate buckets, then copy objects to an attacker-owned bucket a day later",
                 ("gcp",), (STRATUS + " (gcp.exfiltration.gcs-object-read)",), [
        Step("T1619", "Discovery", s1, "list buckets the principal rarely lists"),
        Step("T1619", "Discovery", s2, "list objects across 6 buckets"),
        Step("T1537", "Exfiltration", s3, "copy 70 objects to an external bucket")])


# ============================================================================ A10 — AWS backdoor login profile
def a10(seed: int) -> Story:
    r = sub_rng(seed, "A10")
    ip = AIP["A10"]
    t = at(11, 20, 30)
    who = F.iam_user(r, ACCT_PROD, "akumar")
    s1 = [F.console_login(r, t, ACCT_PROD, "akumar", ip, mfa=False)]
    t2 = t + 8 * MIN
    s2 = [_ct(r, t2, "CreateLoginProfile", who, ip, ua=F.UA_BOTO,
              req={"userName": "svc-backup", "passwordResetRequired": False}),
          _ct(r, t2 + 20 * SEC, "CreateAccessKey", who, ip, ua=F.UA_BOTO, req={"userName": "svc-backup"},
              resp={"accessKey": {"accessKeyId": r.akid("AKIA"), "status": "Active", "userName": "svc-backup"}})]
    s3 = [_ct(r, t + 15 * MIN, "DeleteDetector", who, ip, src="guardduty.amazonaws.com", region="ap-south-1",
              ua=F.UA_BOTO, req={"detectorId": r.hexs(32)})]
    return Story("A10", "AWS: backdoor an existing service account with a console password + key, then kill GuardDuty",
                 ("aws",), (STRATUS + " (aws.persistence.iam-create-user-login-profile)",), [
        Step("T1078.004", "Initial Access", s1, "console login without MFA from a new IP"),
        Step("T1098.001", "Persistence", s2, "CreateLoginProfile + CreateAccessKey on svc-backup"),
        Step("T1685.007", "Defense Impairment", s3, "delete the GuardDuty detector")])


STORY_FNS = (a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)


def build_stories(seed: int) -> list[Story]:
    return [fn(seed) for fn in STORY_FNS]


# ============================================================================ decoys (near-miss negatives)
def build_decoys(seed: int) -> list[Decoy]:
    r = sub_rng(seed, "decoys")
    out: list[Decoy] = []

    # D1: admin legitimately onboards a new hire from the corp IP in business hours (scoped policy, not Admin)
    adm = F.iam_user(r, ACCT_PROD, "asharma")
    t = at(2, 5, 0)
    d1 = [_ct(r, t, "CreateUser", adm, "192.0.2.10", ua=F.UA_CONSOLE, req={"userName": "jrao"},
              resp={"user": {"userName": "jrao", "arn": f"arn:aws:iam::{ACCT_PROD}:user/jrao"}}),
          _ct(r, t + 30 * SEC, "CreateAccessKey", adm, "192.0.2.10", ua=F.UA_CONSOLE, req={"userName": "jrao"},
              resp={"accessKey": {"accessKeyId": r.akid("AKIA"), "status": "Active", "userName": "jrao"}}),
          _ct(r, t + 60 * SEC, "AttachUserPolicy", adm, "192.0.2.10", ua=F.UA_CONSOLE,
              req={"userName": "jrao", "policyArn": f"arn:aws:iam::{ACCT_PROD}:policy/developer-baseline"})]
    out.append(Decoy("D1", "admin onboards a new hire from the corp IP in business hours (scoped policy)", d1))

    # D5: planned Owner role assignment by asharma from the corp IP (change window) — near-miss for A3 step 4
    d5 = F.activity(r, at(4, 7, 0), "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", f"asharma@{DOMAIN}", "192.0.2.10",
                    F.res_id(f"providers/microsoft.authorization/roleassignments/{r.guid()}"),
                    props={"roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/"
                           f"roleDefinitions/{OWNER_ROLE}", "principalId": r.guid(), "principalType": "Group"})
    out.append(Decoy("D5", "planned Owner assignment to an admin group by asharma from the corp IP", d5))

    # D6: legitimate diagnostic-setting UPDATE (not delete) by ops — near-miss for A3/A5 defense-impairment
    d6 = F.activity(r, at(6, 7, 30), "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE", f"rnair@{DOMAIN}", "192.0.2.11",
                    F.res_id("resourcegroups/rg-data/providers/microsoft.storage/storageaccounts/corpfinancedata/"
                             "providers/microsoft.insights/diagnosticsettings/to-sentinel"))
    out.append(Decoy("D6", "ops updates (not deletes) a diagnostic setting from the VPN", d6))

    # D8: SA key creation by the terraform admin (the expected principal) from CI — near-miss for A5 step 1
    sa = f"ingest-runner@{PROJ_DATA}.iam.gserviceaccount.com"
    d8 = [F.gcp(r, at(6, 6, 0), PROJ_DATA, f"terraform-admin@{PROJ_DATA}.iam.gserviceaccount.com", "198.51.100.42",
                "iam.googleapis.com", "google.iam.admin.v1.CreateServiceAccountKey",
                f"projects/{PROJ_DATA}/serviceAccounts/{sa}", "iam.serviceAccountKeys.create",
                resource={"type": "service_account", "labels": {"email_id": sa}},
                ua="Terraform/1.9.5 terraform-provider-google/6.4")]
    out.append(Decoy("D8", "expected terraform SA creates an SA key from CI", d8))

    return out


# recurring baseline patterns that also serve as near-misses (one representative instance is described here)
RECURRING_DECOYS = [
    {"id": "D2", "source": "aws_cloudtrail:AttachUserPolicy", "recurring": True,
     "why": "CI ci-deploy-role re-attaches app-reporting's scoped S3 policy every Tuesday"},
    {"id": "D3", "source": "azure_monitor:SigninLogs", "recurring": True,
     "why": "vreddy is a real traveller: Singapore sign-ins with MFA on days 5-7"},
    {"id": "D4", "source": "aws_cloudtrail:GetObject", "recurring": True,
     "why": "svc-backup reads 400 S3 objects from the internal backup host every night"},
    {"id": "D7", "source": "gcp_logging:SetIamPolicy", "recurring": True,
     "why": "terraform-admin runs SetIamPolicy from CI every Tuesday"},
]
