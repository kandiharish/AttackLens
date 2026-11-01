"""Azure record builders for gen_azure.py (Key Vault, Microsoft Graph activity, Entra ID Protection, AAD* sign-in
tables, diagnostic-settings export shapes) and their ground-truth entity() view.

Shapes (one per spool bucket, routed by content exactly as config/sources.yaml does):
    kv        AZKVAuditLogs (Log Analytics resource-specific)       kv_x      Key Vault AuditEvent diagnostic export
    kv_diag   AzureDiagnostics (legacy, *_s / *_g / *_d columns)   graph     MicrosoftGraphActivityLogs
    graph_x   Graph activity diagnostic export (properties.*)       risk      AADUserRiskEvents
    risk_sp   AADServicePrincipalRiskEvents                         risk_api  Graph riskDetection (API JSON)
    riskyusers AADRiskyUsers                                        signin_ni AADNonInteractiveUserSignInLogs (strings)
    signin_sp AADServicePrincipalSignInLogs                         signin_mi AADManagedIdentitySignInLogs
    signin_x / audit_x / activity_x  diagnostic export of SigninLogs / AuditLogs / Activity Log (from formats.py rows)
Records carry NO ground-truth field; entity() mirrors the sources.yaml alias precedence (first non-empty wins).
"""

from __future__ import annotations

import json
from typing import Any

from cloud_attacks import formats as F
from cloud_attacks.common import AAD_RESOURCE, DOMAIN, SUB, TENANT, Ev, Rand, iso_7

UPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
OID = "http://schemas.microsoft.com/identity/claims/objectidentifier"
_STATUS = {200: "OK", 201: "Created", 204: "NoContent", 401: "Unauthorized", 403: "Forbidden", 404: "NotFound"}
UA_KV_PY = "azsdk-python-keyvault-secrets/4.8.0 Python/3.11.6 (Linux-6.5.0-x86_64)"
UA_KV_NET = "azsdk-net-Security.KeyVault.Secrets/4.6.0 (.NET 8.0.8; Microsoft Windows 10.0.20348)"
UA_PS = "AzurePowerShell/Az.KeyVault 5.2.0 PSVersion/v7.4.5"


def vault_id(vault: str, rg: str = "rg-sec") -> str:
    return f"/subscriptions/{SUB}/resourcegroups/{rg}/providers/microsoft.keyvault/vaults/{vault}"


def kv(r: Rand, ts: int, shape: str, vault: str, op: str, who: str, ip: str, obj: str = "", *, status: int = 200,
       ua: str = UA_KV_PY) -> Ev:
    """Key Vault data-plane request. who = UPN (user), else an app id (service principal / managed identity).
    obj = "secrets/<name>" / "keys/<name>" / "deletedsecrets/<name>" ... ('' = the collection, e.g. SecretList)."""
    uri = f"https://{vault}.vault.azure.net/{obj or 'secrets'}"
    claim = {UPN: who, "appid": "04b07795-8ddb-461a-bbee-02f9e1bf7b46"} if "@" in who else {"appid": who, OID: who}
    rid, corr, res = r.guid(), r.guid(), vault_id(vault)
    sig = _STATUS.get(status, str(status))
    if shape == "kv":
        doc = {"TenantId": TENANT, "TimeGenerated": iso_7(ts), "OperationName": op, "OperationVersion": "7.4",
               "ResultType": "Success" if status < 400 else "Failure", "ResultSignature": sig,
               "DurationMs": r.randint(4, 60), "CallerIpAddress": ip, "CorrelationId": corr,
               "Identity": {"claim": claim}, "Id": uri, "ClientInfo": ua, "HttpStatusCode": status,
               "RequestUri": f"{uri}?api-version=7.4", "IsAccessPolicyMatch": status < 400, "IsRbacAuthorized": False,
               "_ResourceId": res, "Type": "AZKVAuditLogs", "_ItemId": rid}
    elif shape == "kv_x":
        doc = {"time": iso_7(ts), "category": "AuditEvent", "operationName": op, "operationVersion": "7.4",
               "resultType": "Success" if status < 400 else "Failure", "resultSignature": sig,
               "resultDescription": "" if status < 400 else "Caller is not authorized to perform action on resource.",
               "durationMs": str(r.randint(4, 60)), "callerIpAddress": ip, "correlationId": rid,
               "identity": {"claim": claim}, "properties": {"id": uri, "clientInfo": ua, "httpStatusCode": status,
                                                            "requestUri": f"{uri}?api-version=7.4",
                                                            "isAccessPolicyMatch": status < 400, "tlsVersion": "TLS1.2"},
               "resourceId": res.upper()}
    else:   # kv_diag: AzureDiagnostics
        doc = {"TenantId": TENANT, "TimeGenerated": iso_7(ts), "ResourceId": res.upper(), "Category": "AuditEvent",
               "ResourceGroup": "RG-SEC", "SubscriptionId": SUB, "ResourceProvider": "MICROSOFT.KEYVAULT",
               "Resource": vault.upper(), "ResourceType": "VAULTS", "OperationName": op,
               "ResultType": "Success" if status < 400 else "Failure", "ResultSignature": sig, "CorrelationId": corr,
               "id_s": uri, "CallerIPAddress": ip, "clientInfo_s": ua, "httpStatusCode_d": status,
               "requestUri_s": f"{uri}?api-version=7.4", "isAccessPolicyMatch_b": status < 400,
               "DurationMs": r.randint(4, 60), "Type": "AzureDiagnostics", "_ResourceId": res, "_ItemId": rid}
        if "@" in who:
            doc["identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s"] = who
        else:
            doc["identity_claim_appid_g"] = who
    return Ev(ts, shape, rid, doc)


def graph(r: Rand, ts: int, shape: str, who: str, path: str, ip: str, tok: str, *, method: str = "GET",
          status: int = 200, ua: str = "Microsoft Office/16.0", app: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
          sp: bool = False, roles: str = "", scopes: str = "User.Read Mail.Read") -> Ev:
    """One Graph request. who = the user's object id (delegated) or the service principal id (app-only, sp=True)."""
    rid = r.guid()
    cols = {"RequestId": rid, "OperationId": r.hexs(16), "ClientRequestId": r.guid(), "ApiVersion": "v1.0",
            "RequestMethod": method, "ResponseStatusCode": status, "AadTenantId": TENANT, "IPAddress": ip,
            "UserAgent": ua, "RequestUri": f"https://graph.microsoft.com/v1.0{path}", "DurationMs": r.randint(20, 900),
            "ResponseSizeBytes": r.randint(300, 90_000) if status < 400 else 220, "SignInActivityId": tok,
            "Roles": roles, "TokenIssuedAt": iso_7(ts - r.randint(60, 1800) * 1000), "AppId": app,
            "UserId": "" if sp else who, "ServicePrincipalId": who if sp else "", "Scopes": "" if sp else scopes,
            "IdentityProvider": f"https://sts.windows.net/{TENANT}/", "ClientAuthMethod": 2 if sp else 0}
    if shape == "graph":
        doc = {"TenantId": TENANT, "TimeGenerated": iso_7(ts), "Location": "Central India", **cols,
               "_ResourceId": AAD_RESOURCE.lower(), "Type": "MicrosoftGraphActivityLogs", "_ItemId": rid}
    else:
        props = {k[0].lower() + k[1:]: v for k, v in cols.items()}
        props["ipAddress"], props["tenantId"] = props.pop("iPAddress"), props.pop("aadTenantId")
        doc = {"time": iso_7(ts), "resourceId": AAD_RESOURCE.upper(), "operationName": "Microsoft Graph Activity",
               "operationVersion": "v1.0", "category": "MicrosoftGraphActivityLogs", "resultSignature": str(status),
               "durationMs": str(cols["DurationMs"]), "callerIpAddress": ip, "correlationId": r.guid(),
               "level": "Informational", "location": "Central India", "properties": {"timeGenerated": iso_7(ts), **props}}
    return Ev(ts, shape, rid, doc)


def risk(r: Rand, ts: int, shape: str, who: str, rtype: str, ip: str, *, level: str = "medium",
         state: str = "atRisk", detail: str = "none", source: str = "IdentityProtection", timing: str = "realtime",
         delay_ms: int = 0, cc: str = "IN") -> Ev:
    """Risk detection (user, or service principal for shape risk_sp). ts = the risky ACTIVITY time."""
    rid = r.guid()
    loc = {"city": "", "state": "", "countryOrRegion": cc}
    if shape == "risk_api":
        doc = {"id": rid, "requestId": r.guid(), "correlationId": r.guid(), "riskType": rtype, "riskEventType": rtype,
               "riskState": state, "riskLevel": level, "riskDetail": detail, "source": source,
               "detectionTimingType": timing, "activity": "signin", "tokenIssuerType": "AzureAD", "ipAddress": ip,
               "location": loc, "activityDateTime": iso_7(ts), "detectedDateTime": iso_7(ts + delay_ms),
               "lastUpdatedDateTime": iso_7(ts + delay_ms), "userId": F._uid(who), "userDisplayName": who,
               "userPrincipalName": f"{who}@{DOMAIN}", "additionalInfo": "[]"}
        return Ev(ts, shape, rid, doc)
    doc = {"TenantId": TENANT, "TimeGenerated": iso_7(ts + delay_ms + 60_000), "Id": rid, "RequestId": r.guid(),
           "CorrelationId": r.guid(), "RiskEventType": rtype, "RiskState": state, "RiskLevel": level,
           "RiskDetail": detail, "Source": source, "DetectionTimingType": timing, "IpAddress": ip,
           "Location": loc, "ActivityDateTime": iso_7(ts), "DetectedDateTime": iso_7(ts + delay_ms),
           "LastUpdatedDateTime": iso_7(ts + delay_ms), "ResourceId": AAD_RESOURCE, "_ItemId": rid}
    if shape == "risk_sp":
        doc.update(Activity="servicePrincipal", ServicePrincipalId=f"spid-{who}", ServicePrincipalDisplayName=who,
                   AppId=r.guid(), OperationName="Service principal risk detection",
                   Category="ServicePrincipalRiskEvents", Type="AADServicePrincipalRiskEvents")
    else:
        doc.update(Activity="signin", TokenIssuerType="AzureAD", UserId=F._uid(who), UserDisplayName=who,
                   UserPrincipalName=f"{who}@{DOMAIN}", AdditionalInfo=[], OperationName="User Risk Detection",
                   Category="UserRiskEvents", Type="AADUserRiskEvents")
    return Ev(ts, shape, rid, doc)


def risky_user(r: Rand, ts: int, who: str, level: str, state: str, detail: str) -> Ev:
    rid = r.guid()
    doc = {"TenantId": TENANT, "TimeGenerated": iso_7(ts), "Id": F._uid(who), "IsDeleted": False,
           "IsProcessing": False, "RiskDetail": detail, "RiskLastUpdatedDateTime": iso_7(ts - 3_600_000),
           "RiskLevel": level, "RiskState": state, "UserDisplayName": who, "UserPrincipalName": f"{who}@{DOMAIN}",
           "OperationName": "Risky user", "Category": "RiskyUsers", "ResourceId": AAD_RESOURCE,
           "Type": "AADRiskyUsers", "_ItemId": rid}
    return Ev(ts, "riskyusers", rid, doc)


def signin_ni(r: Rand, ts: int, user: str, ip: str, tok: str, *, app: str = "Microsoft Office", cc: str = "IN",
              code: str = "0", asn: int = 64500) -> Ev:
    """AADNonInteractiveUserSignInLogs: Status / LocationDetails / DeviceDetail are JSON STRINGS in this table."""
    rid = r.guid()
    doc = {"TenantId": TENANT, "TimeGenerated": iso_7(ts), "OperationName": "Sign-in activity",
           "Category": "NonInteractiveUserSignInLogs", "ResultType": code, "UserPrincipalName": f"{user}@{DOMAIN}",
           "UserId": F._uid(user), "UserDisplayName": user, "AppDisplayName": app,
           "AppId": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "IPAddress": ip,
           "ClientAppUsed": "Mobile Apps and Desktop clients", "ConditionalAccessStatus": "success",
           "AuthenticationRequirement": "singleFactorAuthentication", "IsInteractive": False,
           "Status": json.dumps({"errorCode": int(code)}),
           "LocationDetails": json.dumps({"city": "Bengaluru" if cc == "IN" else "", "countryOrRegion": cc}),
           "DeviceDetail": json.dumps({"operatingSystem": "Windows 10", "browser": "Rich Client 4.61"}),
           "UniqueTokenIdentifier": tok, "SessionId": r.guid(), "AutonomousSystemNumber": asn,
           "ResourceId": AAD_RESOURCE, "Type": "AADNonInteractiveUserSignInLogs", "Id": rid, "_ItemId": rid}
    return Ev(ts, "signin_ni", rid, doc)


def signin_sp(r: Rand, ts: int, name: str, ip: str, tok: str, *, managed: bool = False, code: str = "0",
              resource: str = "Azure Key Vault") -> Ev:
    rid = r.guid()
    doc = {"TenantId": TENANT, "TimeGenerated": iso_7(ts), "OperationName": "Sign-in activity",
           "Category": "ManagedIdentitySignInLogs" if managed else "ServicePrincipalSignInLogs", "ResultType": code,
           "ServicePrincipalName": name, "ServicePrincipalId": f"spid-{name}", "AppId": F.stable("app", name, 12),
           "IPAddress": "" if managed else ip, "ResourceDisplayName": resource, "ConditionalAccessStatus": "notApplied",
           "LocationDetails": json.dumps({} if managed else {"countryOrRegion": "IN"}),
           "Status": json.dumps({"errorCode": int(code)}), "UniqueTokenIdentifier": tok, "ResourceId": AAD_RESOURCE,
           "Type": "AADManagedIdentitySignInLogs" if managed else "AADServicePrincipalSignInLogs", "Id": rid,
           "_ItemId": rid}
    return Ev(ts, "signin_mi" if managed else "signin_sp", rid, doc)


def signin_export(ev: Ev, tok: str | None = None) -> Ev:
    """SigninLogs row (formats.signin) -> its diagnostic-settings export record."""
    d = ev.doc
    props = {"id": d["Id"], "createdDateTime": d["TimeGenerated"], "userDisplayName": d.get("UserDisplayName"),
             "userPrincipalName": d.get("UserPrincipalName"), "userId": d.get("UserId"), "appId": d.get("AppId"),
             "appDisplayName": d.get("AppDisplayName"), "ipAddress": d.get("IPAddress"), "status": d.get("Status"),
             "clientAppUsed": d.get("ClientAppUsed"), "userAgent": d.get("UserAgent"),
             "deviceDetail": d.get("DeviceDetail"), "location": d.get("LocationDetails"), "mfaDetail": d.get("MfaDetail"),
             "conditionalAccessStatus": d.get("ConditionalAccessStatus"),
             "authenticationRequirement": d.get("AuthenticationRequirement"),
             "riskLevelDuringSignIn": d.get("RiskLevelDuringSignIn"), "riskState": d.get("RiskState"),
             "isInteractive": d.get("IsInteractive"), "uniqueTokenIdentifier": tok or d.get("Id")}
    doc = {"time": d["TimeGenerated"], "resourceId": AAD_RESOURCE, "operationName": "Sign-in activity",
           "operationVersion": "1.0", "category": "SignInLogs", "tenantId": TENANT, "resultType": d["ResultType"],
           "resultSignature": "None", "resultDescription": d.get("ResultDescription", ""), "durationMs": 0,
           "callerIpAddress": d.get("IPAddress"), "correlationId": d.get("CorrelationId"),
           "identity": d.get("UserDisplayName"), "Level": 4, "location": d.get("Location"),
           "properties": {k: v for k, v in props.items() if v is not None}}
    return Ev(ev.ts, "signin_x", ev.rid, doc)


def audit_export(ev: Ev) -> Ev:
    d = ev.doc
    doc = {"time": d["TimeGenerated"], "resourceId": AAD_RESOURCE, "operationName": d["OperationName"],
           "operationVersion": "1.0", "category": "AuditLogs", "tenantId": TENANT, "resultSignature": "None",
           "durationMs": 0, "correlationId": d["CorrelationId"], "level": "Informational",
           "properties": {"id": d["Id"], "category": d["Category"], "correlationId": d["CorrelationId"],
                          "result": d.get("Result", "success"), "resultReason": "",
                          "activityDisplayName": d["ActivityDisplayName"], "activityDateTime": d["ActivityDateTime"],
                          "loggedByService": d.get("LoggedByService"), "operationType": d.get("AADOperationType"),
                          "initiatedBy": d["InitiatedBy"], "targetResources": d.get("TargetResources", []),
                          "additionalDetails": d.get("AdditionalDetails", [])}}
    return Ev(ev.ts, "audit_x", ev.rid, doc)


def activity_export(ev: Ev, display: str = "") -> Ev:
    d = ev.doc
    caller = d.get("Caller", "")
    claims = {"name": display or caller, "ipaddr": d.get("CallerIpAddress")}
    claims.update({UPN: caller} if "@" in caller else {"appid": caller})
    props = dict(d.get("Properties_d") or {})
    props["statusCode"] = "OK" if d["ActivityStatusValue"] == "Success" else d.get("ActivitySubstatusValue", "")
    props["eventDataId"] = d.get("EventDataId", ev.rid)
    doc = {"time": d["TimeGenerated"], "resourceId": d["_ResourceId"].upper(), "operationName": d["OperationNameValue"],
           "category": d.get("CategoryValue", "Administrative"), "resultType": d["ActivityStatusValue"],
           "resultSignature": f"{d['ActivityStatusValue']}.", "durationMs": "0", "callerIpAddress": d["CallerIpAddress"],
           "correlationId": d["CorrelationId"], "level": d.get("Level", "Information"), "location": "global",
           "identity": {"authorization": d.get("Authorization_d"), "claims": claims}, "properties": props}
    return Ev(ev.ts, "activity_x", ev.rid, doc)


def entity(ev: Ev) -> dict[str, Any]:
    """host / user / src_ip / action as ingest maps them (config/sources.yaml alias order)."""
    d, f = ev.doc, ev.feed
    if f in ("signin", "audit", "activity"):
        return F.entity(ev)
    p = d.get("properties") or {}
    if f in ("kv", "kv_x", "kv_diag"):
        c = (d.get("identity") or d.get("Identity") or {}).get("claim") or {}
        user = (c.get(UPN) or d.get("identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s")
                or c.get("appid") or d.get("identity_claim_appid_g"))
        return {"host": d.get("resourceId") or d.get("_ResourceId"), "user": user,
                "src_ip": d.get("callerIpAddress") or d.get("CallerIpAddress") or d.get("CallerIPAddress"),
                "action": d.get("operationName") or d.get("OperationName")}
    if f in ("graph", "graph_x"):
        src = d if f == "graph" else {k[0].upper() + k[1:]: v for k, v in p.items()}
        return {"host": d.get("_ResourceId") or d.get("resourceId"),
                "user": src.get("UserId") or src.get("ServicePrincipalId") or src.get("AppId"),
                "src_ip": d.get("IPAddress") or p.get("ipAddress"), "action": src.get("RequestMethod")}
    if f in ("risk", "risk_sp", "risk_api", "riskyusers"):
        return {"host": d.get("ResourceId"),
                "user": d.get("UserPrincipalName") or d.get("userPrincipalName") or d.get("ServicePrincipalDisplayName"),
                "src_ip": d.get("IpAddress") or d.get("ipAddress"),
                "action": d.get("RiskEventType") or d.get("riskEventType") or d.get("OperationName")}
    if f in ("signin_ni", "signin_sp", "signin_mi"):
        return {"host": d.get("ResourceId"), "user": d.get("UserPrincipalName") or d.get("ServicePrincipalName"),
                "src_ip": d.get("IPAddress") or None, "action": d.get("OperationName")}
    if f == "signin_x":
        return {"host": d["resourceId"], "user": p.get("userPrincipalName"), "src_ip": p.get("ipAddress"),
                "action": d["operationName"]}
    if f == "audit_x":
        by = p.get("initiatedBy") or {}
        return {"host": d["resourceId"], "user": (by.get("user") or {}).get("userPrincipalName")
                or (by.get("app") or {}).get("displayName"),
                "src_ip": (by.get("user") or {}).get("ipAddress"), "action": d["operationName"]}
    if f == "activity_x":
        c = d["identity"]["claims"]
        return {"host": d["resourceId"], "user": c.get(UPN) or c.get("appid"), "src_ip": d.get("callerIpAddress"),
                "action": d["operationName"]}
    raise ValueError(f)
