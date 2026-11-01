"""Record builders in the exact shape each connector writes to the spool.

- CloudTrail: the event record dict (connectors/aws_cloudtrail.py writes the LookupEvents CloudTrailEvent / S3
  Records[] item unchanged). eventTime has whole seconds, so Ev.ts is floored to the second.
- Azure: Log Analytics rows with their column names; `dynamic` columns are decoded to objects and empty / null
  columns dropped, exactly like connectors/azure_monitor.py event_line(). `AlId` (keyset column) is never present.
- GCP: Cloud Logging LogEntry with a protoPayload AuditLog (connectors/gcp_logging.py writes the entry unchanged).
"""

from __future__ import annotations

import re

from typing import Any

from cloud_attacks.common import (AAD_RESOURCE, DOMAIN, SUB, TENANT, Ev, Rand, iso_7, iso_9, iso_s)

UA_CLI = "aws-cli/2.17.0 md/awscrt#0.20.11 ua/2.0 os/windows#10 md/arch#amd64 lang/python#3.11.8 md/pyimpl#CPython"
UA_CONSOLE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
UA_BOTO = "Boto3/1.34.0 md/Botocore#1.34.0 ua/2.0 os/linux#6.5.0 md/arch#x86_64 lang/python#3.11.6 Botocore/1.34.0"


# ============================================================================ AWS CloudTrail
def stable(prefix: str, name: str, n: int) -> str:
    """Deterministic id per principal (a user's long-term access key never changes between calls)."""
    h, out = 0, []
    for ch in (prefix + name).encode():
        h = (h * 1_000_003 + ch) % (1 << 80)
    for _ in range(n):
        out.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[h % 32])
        h = h // 32 or (h * 7919 + 17)
    return prefix + "".join(out)


def iam_user(r: Rand, acct: str, user: str, key: bool = True) -> dict[str, Any]:
    d: dict[str, Any] = {"type": "IAMUser", "principalId": stable("AIDA", acct + user, 17),
                         "arn": f"arn:aws:iam::{acct}:user/{user}", "accountId": acct, "userName": user}
    if key:
        d["accessKeyId"] = stable("AKIA", acct + user, 16)
    return d


def assumed(r: Rand, acct: str, role: str, session: str, mfa: bool = False) -> dict[str, Any]:
    rid = stable("AROA", acct + role, 17)
    return {"type": "AssumedRole", "principalId": f"{rid}:{session}",
            "arn": f"arn:aws:sts::{acct}:assumed-role/{role}/{session}", "accountId": acct,
            "accessKeyId": r.akid("ASIA"),
            "sessionContext": {"sessionIssuer": {"type": "Role", "principalId": rid,
                                                 "arn": f"arn:aws:iam::{acct}:role/{role}", "accountId": acct,
                                                 "userName": role},
                               "attributes": {"creationDate": "2026-10-19T00:00:00Z",
                                              "mfaAuthenticated": "true" if mfa else "false"}}}


def aws_service(svc: str) -> dict[str, Any]:
    return {"type": "AWSService", "invokedBy": svc}


def ct(r: Rand, ts: int, acct: str, region: str, source: str, name: str, ident: dict[str, Any], ip: str, *,
       ua: str = UA_CLI, ro: bool = False, req: dict[str, Any] | None = None, resp: dict[str, Any] | None = None,
       err: tuple[str, str] | None = None, etype: str = "AwsApiCall", data: bool = False,
       resources: list[dict[str, str]] | None = None, extra: dict[str, Any] | None = None) -> Ev:
    ts = ts // 1000 * 1000
    eid = r.guid()
    rec: dict[str, Any] = {"eventVersion": "1.09", "userIdentity": ident, "eventTime": iso_s(ts),
                           "eventSource": source, "eventName": name, "awsRegion": region, "sourceIPAddress": ip,
                           "userAgent": ua}
    if err:
        rec["errorCode"], rec["errorMessage"] = err
    rec.update({"requestParameters": req, "responseElements": resp, "requestID": r.guid(), "eventID": eid,
                "readOnly": ro, "eventType": etype, "managementEvent": not data, "recipientAccountId": acct,
                "eventCategory": "Data" if data else "Management"})
    if resources:
        rec["resources"] = resources
    if etype == "AwsApiCall" and not ip.endswith("amazonaws.com"):
        rec["tlsDetails"] = {"tlsVersion": "TLSv1.3", "cipherSuite": "TLS_AES_128_GCM_SHA256",
                             "clientProvidedHostHeader": f"{source.split('.')[0]}.{region}.amazonaws.com"}
    rec.update(extra or {})
    return Ev(ts, "cloudtrail", eid, rec)


def denied(acct: str, arn: str, action: str) -> tuple[str, str]:
    return ("AccessDenied", f"User: {arn} is not authorized to perform: {action} because no identity-based policy "
                            f"allows the {action} action")


def console_login(r: Rand, ts: int, acct: str, user: str, ip: str, mfa: bool, ok: bool = True) -> Ev:
    ident = iam_user(r, acct, user, key=False)
    extra: dict[str, Any] = {"additionalEventData": {"LoginTo": "https://console.aws.amazon.com/console/home",
                                                     "MobileVersion": "No", "MFAUsed": "Yes" if mfa else "No"}}
    if not ok:
        extra["errorMessage"] = "Failed authentication"
    return ct(r, ts, acct, "us-east-1", "signin.amazonaws.com", "ConsoleLogin", ident, ip, ua=UA_CONSOLE,
              etype="AwsConsoleSignIn", resp={"ConsoleLogin": "Success" if ok else "Failure"}, extra=extra)


def s3_data(r: Rand, ts: int, acct: str, ident: dict[str, Any], ip: str, name: str, bucket: str, key: str | None,
            ua: str = UA_CLI, region: str = "ap-south-1", err: tuple[str, str] | None = None) -> Ev:
    req: dict[str, Any] = {"bucketName": bucket, "Host": f"{bucket}.s3.{region}.amazonaws.com"}
    res = [{"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{bucket}", "accountId": acct}]
    if key is not None:
        req["key"] = key
        res.insert(0, {"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::{bucket}/{key}"})
    return ct(r, ts, acct, region, "s3.amazonaws.com", name, ident, ip, ua=ua, ro=name.startswith(("Get", "List",
              "Head")), req=req, data=True, resources=res, err=err,
              extra={"additionalEventData": {"bytesTransferredIn": 0, "bytesTransferredOut":
                                             r.randint(20_000, 4_000_000) if name == "GetObject" else 0}})


# ============================================================================ Azure (Log Analytics rows)
def _clean(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if v is not None and v != ""}


def signin(r: Rand, ts: int, user: str, name: str, ip: str, *, result: str = "0", country: str = "IN",
           city: str = "Bengaluru", app: str = "Office 365 Exchange Online", mfa: str | None = None,
           client: str = "Browser", ua: str = UA_CONSOLE, ca: str = "notApplied", interactive: bool = True) -> Ev:
    rid = r.guid()
    reasons = {"0": "", "50126": "Invalid username or password or Invalid on-premise username or password.",
               "50074": "Strong Authentication is required.", "50053": "Account is locked.",
               "500121": "Authentication failed during strong authentication request.",
               "50140": "This error occurred due to 'Keep me signed in' interrupt when the user was signing in."}
    status: dict[str, Any] = {"errorCode": int(result)}
    if result != "0":
        status["failureReason"] = reasons.get(result, "Other")
    elif mfa:
        status["additionalDetails"] = "MFA completed in Azure AD"
    row = {"TenantId": TENANT, "SourceSystem": "Azure AD", "TimeGenerated": iso_7(ts), "ResourceId": AAD_RESOURCE,
           "OperationName": "Sign-in activity", "OperationVersion": "1.0", "Category": "SignInLogs",
           "ResultType": result, "ResultDescription": reasons.get(result, ""), "CorrelationId": r.guid(),
           "Resource": "Microsoft.aadiam", "ResourceGroup": "Microsoft.aadiam", "Identity": name, "Level": "4",
           "Location": country, "AppDisplayName": app, "AppId": r.guid() if app not in _APP_IDS else _APP_IDS[app],
           "AuthenticationRequirement": "multiFactorAuthentication" if mfa else "singleFactorAuthentication",
           "ClientAppUsed": client, "ConditionalAccessStatus": ca,
           "DeviceDetail": {"operatingSystem": "Windows10", "browser": "Edge 129.0.0"} if client == "Browser"
           else {"operatingSystem": "Linux"},
           "IsInteractive": interactive, "IPAddress": ip,
           "LocationDetails": {"city": city, "state": "", "countryOrRegion": country},
           "MfaDetail": {"authMethod": mfa} if mfa else None, "RiskDetail": "none", "RiskLevelAggregated": "none",
           "RiskLevelDuringSignIn": "none", "RiskState": "none", "Status": status, "UserAgent": ua,
           "UserDisplayName": name, "UserId": _uid(user), "UserPrincipalName": f"{user}@{DOMAIN}",
           "UserType": "Member", "Id": rid, "Type": "SigninLogs", "_ItemId": rid}
    return Ev(ts, "signin", rid, _clean(row))


_APP_IDS = {"Azure Portal": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
            "Office 365 Exchange Online": "00000002-0000-0ff1-ce00-000000000000",
            "Microsoft Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
            "Azure Active Directory PowerShell": "1b730954-1685-4b74-9bfd-dac224a7b894",
            "Office 365 SharePoint Online": "00000003-0000-0ff1-ce00-000000000000"}


def _uid(user: str) -> str:
    h = 0
    for ch in user.encode():
        h = (h * 131 + ch) % (1 << 48)
    return f"5e1a{h % 0xffff:04x}-0000-4000-8000-{h:012x}"


def audit(r: Rand, ts: int, op: str, category: str, ip: str, targets: list[dict[str, Any]], *,
          actor: str | None = None, app: str | None = None, result: str = "success",
          details: list[dict[str, str]] | None = None) -> Ev:
    rid = f"Directory_{r.guid()}"
    by = ({"user": {"userPrincipalName": f"{actor}@{DOMAIN}", "ipAddress": ip, "id": _uid(actor)}} if actor else
          {"app": {"displayName": app, "servicePrincipalId": r.guid()}})
    row = {"TenantId": TENANT, "SourceSystem": "Azure AD", "TimeGenerated": iso_7(ts), "ResourceId": AAD_RESOURCE,
           "OperationName": op, "OperationVersion": "1.0", "Category": category, "Result": result,
           "CorrelationId": r.guid(), "Resource": "Microsoft.aadiam", "ResourceGroup": "Microsoft.aadiam",
           "Identity": actor or app, "Level": "4", "AdditionalDetails": details or [], "Id": rid,
           "InitiatedBy": by, "LoggedByService": "Core Directory", "TargetResources": targets,
           "AADTenantId": TENANT, "ActivityDisplayName": op, "ActivityDateTime": iso_7(ts),
           "AADOperationType": op.split()[0].rstrip(":"), "Type": "AuditLogs", "_ItemId": rid}
    return Ev(ts, "audit", rid, _clean(row))


def user_target(user: str) -> dict[str, Any]:
    return {"id": _uid(user), "type": "User", "userPrincipalName": f"{user}@{DOMAIN}", "modifiedProperties": []}


def obj_target(kind: str, name: str, oid: str, props: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {"id": oid, "displayName": name, "type": kind, "modifiedProperties": props or []}


def res_id(path: str) -> str:
    return f"/subscriptions/{SUB}/{path}".lower()


_OP_NAMES = {"MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE": "Create role assignment",
             "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE": "Delete diagnostic setting",
             "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION": "List Storage Account Keys",
             "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION": "Regenerate Storage Account Keys",
             "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE": "Create Deployment"}


def activity(r: Rand, ts: int, op: str, caller: str, ip: str, resource: str, *, props: dict[str, Any] | None = None,
             category: str = "Administrative", pair: bool = True, fail: bool = False) -> list[Ev]:
    """One Activity Log operation: a Start row then (1-4 s later) its Success / Failure row (same CorrelationId)."""
    corr, provider = r.guid(), op.split("/")[0]
    rg = resource.split("/resourcegroups/")[1].split("/")[0] if "/resourcegroups/" in resource else ""
    out = []
    states = (("Start", "Started"), ("Failure" if fail else "Success", "Forbidden" if fail else "OK"))
    for k, (st, sub) in enumerate(states if pair else states[1:]):
        t = ts + (r.randint(1000, 4000) if k else 0)
        rid = r.guid()
        row = {"TenantId": TENANT, "SourceSystem": "Azure", "TimeGenerated": iso_7(t), "CategoryValue": category,
               "Level": "Error" if st == "Failure" else "Informational", "OperationNameValue": op,
               "OperationName": _OP_NAMES.get(op, op.split("/")[-2].title()),
               "ActivityStatusValue": st, "ActivitySubstatusValue": sub, "Caller": caller, "CallerIpAddress": ip,
               "CorrelationId": corr, "EventDataId": rid, "EventSubmissionTimestamp": iso_7(t + 9000),
               "ResourceGroup": rg, "ResourceProviderValue": provider, "SubscriptionId": SUB,
               "Authorization_d": {"action": op, "scope": resource},
               "Properties_d": {"eventCategory": category, "entity": resource, "message": op, **(props or {})},
               "Claims_d": {"ipaddr": ip, "name": caller},
               "HTTPRequest": {"clientRequestId": r.guid(), "clientIpAddress": ip, "method": "POST"},
               "Hierarchy": f"{TENANT}/{SUB}", "_ResourceId": resource, "Type": "AzureActivity", "_ItemId": rid}
        out.append(Ev(t, "activity", rid, _clean(row)))
    return out


def blob(r: Rand, ts: int, account: str, rg: str, op: str, key: str, ip: str, port: int, *, auth: str = "AccountKey",
         upn: str | None = None, oid: str | None = None, ua: str = "AzCopy/10.26.0 (windows; amd64)") -> Ev:
    # NOTE: real StorageBlobLogs write CallerIpAddress as "ip:port". Stage 0 routes these rows to the dedicated
    # azure_storageblob_json source, whose value_regex strips the port; we still emit the bare IP (dataset bytes
    # unchanged, entity() needs no port handling).
    rid = r.guid()
    row = {"TenantId": TENANT, "TimeGenerated": iso_7(ts), "AccountName": account, "Location": "centralindia",
           "Protocol": "HTTPS", "OperationName": op, "AuthenticationType": auth, "StatusCode": "200",
           "StatusText": "Success", "DurationMs": r.randint(3, 90), "ServerLatencyMs": r.randint(2, 40),
           "Uri": f"https://{account}.blob.core.windows.net/{key}", "CallerIpAddress": ip, "CallerPort": port,
           "CorrelationId": r.guid(), "RequesterUpn": upn, "RequesterObjectId": oid, "UserAgentHeader": ua,
           "ResponseBodySize": r.randint(10_000, 3_000_000) if op == "GetBlob" else r.randint(200, 900),
           "ObjectKey": f"/{account}/{key}", "Category": "StorageRead" if op.startswith(("Get", "List"))
           else "StorageWrite", "_ResourceId": res_id(f"resourcegroups/{rg}/providers/microsoft.storage/"
                                                      f"storageaccounts/{account}/blobservices/default"),
           "Type": "StorageBlobLogs", "_ItemId": rid}
    return Ev(ts, "blob", rid, _clean(row))


# ============================================================================ GCP LogEntry
UA_GCLOUD = "google-cloud-sdk gcloud/496.0.0 command/gcloud.compute.instances.list,gzip(gfe)"


def gcp(r: Rand, ts: int, project: str, principal: str, ip: str, service: str, method: str, resource_name: str,
        permission: str, *, resource: dict[str, Any], data_access: bool = False, denied: bool = False,
        ua: str = UA_GCLOUD, request: dict[str, Any] | None = None, response: dict[str, Any] | None = None,
        service_data: dict[str, Any] | None = None, sa_key: str | None = None) -> Ev:
    insert = r.hexs(14)
    auth: dict[str, Any] = {"principalEmail": principal}
    if sa_key:
        auth["serviceAccountKeyName"] = sa_key
    pp: dict[str, Any] = {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                          "status": {"code": 7, "message": "PERMISSION_DENIED"} if denied else {},
                          "authenticationInfo": auth,
                          "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": ua,
                                              "requestAttributes": {"time": iso_9(ts, r.randint(0, 999_999)),
                                                                    "auth": {}},
                                              "destinationAttributes": {}},
                          "serviceName": service, "methodName": method,
                          "authorizationInfo": [{"resource": resource_name, "permission": permission,
                                                 "granted": not denied, "resourceAttributes": {}}],
                          "resourceName": resource_name}
    for k, v in (("request", request), ("response", response), ("serviceData", service_data)):
        if v is not None:
            pp[k] = v
    log = "data_access" if data_access else "activity"
    entry = {"protoPayload": pp, "insertId": insert, "resource": {"type": resource["type"],
                                                                  "labels": {"project_id": project,
                                                                             **resource.get("labels", {})}},
             "timestamp": iso_9(ts, r.randint(0, 999_999)),
             "severity": "ERROR" if denied else ("INFO" if data_access else "NOTICE"),
             "logName": f"projects/{project}/logs/cloudaudit.googleapis.com%2F{log}",
             "receiveTimestamp": iso_9(ts + r.randint(200, 1500), r.randint(0, 999_999))}
    return Ev(ts, "gcp", insert, entry)


def gcs(r: Rand, ts: int, project: str, principal: str, ip: str, method: str, bucket: str, obj: str | None, *,
        denied: bool = False, ua: str = "gcloud-python/3.1.0 gl-python/3.11", sa_key: str | None = None) -> Ev:
    name = f"projects/_/buckets/{bucket}" + (f"/objects/{obj}" if obj else "")
    return gcp(r, ts, project, principal, ip, "storage.googleapis.com", method, name, method, data_access=True,
               denied=denied, ua=ua, sa_key=sa_key,
               resource={"type": "gcs_bucket", "labels": {"bucket_name": bucket, "location": "asia-south1"}})


def policy_delta(role: str, member: str, action: str = "ADD") -> dict[str, Any]:
    return {"@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
            "policyDelta": {"bindingDeltas": [{"action": action, "role": role, "member": member}]}}


# ============================================================================ entities (generator side)
# config/sources.yaml cloudtrail_json value_regex (user): the first matching ARN pattern keeps group 1, else the ARN
_ARN_USER = (re.compile(r"^arn:aws[a-z-]*:sts::[0-9]*:assumed-role/[^/]+/([^/]+)$"),
             re.compile(r"^arn:aws[a-z-]*:sts::[0-9]*:federated-user/([^/]+)$"),
             re.compile(r"^arn:aws[a-z-]*:iam::[0-9]*:user/(?:.*/)?([^/]+)$"))


def _arn_user(arn: str | None) -> str | None:
    if not arn:
        return None
    arn = arn.strip()
    for rx in _ARN_USER:
        m = rx.match(arn)
        if m and m.group(1):
            return m.group(1)
    return arn


def entity(ev: Ev) -> dict[str, Any]:
    """host / user / src_ip / action of a record, following the alias precedence of config/sources.yaml."""
    d = ev.doc
    if ev.feed == "cloudtrail":
        ui = d.get("userIdentity") or {}
        user = (ui.get("userName") or _arn_user(ui.get("arn"))
                or ((ui.get("sessionContext") or {}).get("sessionIssuer") or {}).get("userName") or ui.get("principalId"))
        return {"host": d.get("recipientAccountId"), "user": user, "src_ip": d.get("sourceIPAddress"),
                "action": d.get("eventName")}
    if ev.feed == "gcp":
        pp = d["protoPayload"]
        return {"host": d["resource"]["labels"]["project_id"], "user": pp["authenticationInfo"].get("principalEmail"),
                "src_ip": pp["requestMetadata"].get("callerIp"), "action": pp["methodName"]}
    if ev.feed == "signin":
        return {"host": d.get("_ResourceId") or d.get("ResourceId"), "user": d.get("UserPrincipalName"),
                "src_ip": d.get("IPAddress"), "action": d.get("OperationName")}
    if ev.feed == "audit":
        by = d.get("InitiatedBy") or {}
        u = (by.get("user") or {})
        return {"host": d.get("_ResourceId") or d.get("ResourceId"),
                "user": u.get("userPrincipalName") or (by.get("app") or {}).get("displayName"),
                "src_ip": u.get("ipAddress"), "action": d.get("OperationName")}
    if ev.feed == "activity":
        return {"host": d.get("_ResourceId"), "user": d.get("Caller"), "src_ip": d.get("CallerIpAddress"),
                "action": d.get("OperationNameValue")}
    if ev.feed == "blob":   # azure_storageblob_json: user = UPN, else object id; AccountKey / SAS rows -> None
        return {"host": d.get("_ResourceId") or d.get("AccountName"),
                "user": d.get("RequesterUpn") or d.get("RequesterObjectId"),
                "src_ip": d.get("CallerIpAddress"), "action": d.get("OperationName")}
    raise ValueError(ev.feed)
