"""Record builders for the identity SaaS feeds (tools/cloud_attacks/gen_identity_saas.py).

Each builder returns an Ev in the exact shape the vendor API / export delivers (field names from the vendor docs,
values made up). entity() mirrors config/sources.yaml (host / user / src_ip) so ground truth is derived from the
served record, never typed by hand. All IPs are RFC 5737; all domains are .example.
"""

from __future__ import annotations

import json
import zlib
from typing import Any

from cloud_attacks.common import TENANT, Ev, Rand, iso_s

DOMAIN = "corp.example"
GWS_CUSTOMER = "C03corp01"
GWS_ORG = "731840215569"            # Cloud Logging copy: organizations/<id>/logs/...
AUTH0_HOST = "corp-portal.us.auth0.com"
UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
UA_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15"
UA_ATTACK = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
UA_PY = "python-requests/2.32.3"

# feed -> (served folder, file stem)
FEED_DEST = {"okta": ("okta", "system_log"), "gws": ("google_workspace", "reports"),
             "gws_cl": ("google_workspace", "cloud_logging"), "ual": ("m365", "management_api"),
             "ual_la": ("m365", "officeactivity"), "cae": ("m365", "cloudappevents"), "auth0": ("auth0", "logs"),
             "duo": ("duo", "authentication"), "cloudtrail": ("aws_cloudtrail", "cloudtrail")}
SOURCE_TYPE = {"okta": "okta_json", "gws": "gws_reports_json", "gws_cl": "gcp_audit_json", "ual": "m365_ual_json",
               "ual_la": "m365_ual_json", "cae": "m365_ual_json", "auth0": "auth0_json", "duo": "duo_auth_json",
               "cloudtrail": "cloudtrail_json"}


def _h(s: str) -> int:
    """Stable (process-independent) hash: same seed -> same bytes."""
    return zlib.crc32(s.encode("utf-8"))


def _geo(country: str) -> dict[str, Any]:
    pts = {"India": (12.97, 77.59, "Bengaluru"), "Netherlands": (52.37, 4.9, "Amsterdam"),
           "United States": (40.71, -74.0, "New York"), "Singapore": (1.29, 103.85, "Singapore")}
    lat, lon, city = pts.get(country, (12.97, 77.59, "Bengaluru"))
    return {"city": city, "state": None, "country": country, "postalCode": None,
            "geolocation": {"lat": lat, "lon": lon}}


def okta(r: Rand, ts: int, et: str, user: str, ip: str, *, result: str = "SUCCESS", reason: str | None = None,
         sess: str | None = None, asn: int = 64500, as_org: str = "example broadband", ua: str = UA_CHROME,
         country: str = "India", target: list[dict[str, Any]] | None = None,
         debug: dict[str, Any] | None = None, cred: str | None = "PASSWORD") -> Ev:
    uid = r.guid()
    alt = user if "@" in user else f"{user}@{DOMAIN}"
    doc = {"actor": {"id": "00u" + r.hexs(17), "type": "User", "alternateId": alt, "displayName": user.split("@")[0],
                     "detailEntry": None},
           "client": {"userAgent": {"rawUserAgent": ua, "os": "Windows" if "Windows" in ua else "Other",
                                    "browser": "CHROME" if "Chrome" in ua else "UNKNOWN"},
                      "zone": "null", "device": "Computer", "id": None, "ipAddress": ip,
                      "geographicalContext": _geo(country)},
           "device": None,
           "authenticationContext": {"authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
                                     "credentialProvider": None, "credentialType": cred, "issuer": None,
                                     "interface": None, "authenticationStep": 0,
                                     "externalSessionId": sess or ("102" + r.b32(22))},
           "displayMessage": et, "eventType": et, "outcome": {"result": result, "reason": reason},
           "published": iso_ms(ts),
           "securityContext": {"asNumber": asn, "asOrg": as_org, "isp": as_org, "domain": "example.net",
                               "isProxy": False},
           "severity": "INFO" if result in ("SUCCESS", "ALLOW") else "WARN",
           "debugContext": {"debugData": {"requestId": r.b32(20), "requestUri": "/idp/idx/identify",
                                          "threatSuspected": "false", **(debug or {})}},
           "legacyEventType": "core." + et, "transaction": {"type": "WEB", "id": r.b32(20), "detail": {}},
           "uuid": uid, "version": "0",
           "request": {"ipChain": [{"ip": ip, "geographicalContext": _geo(country), "version": "V4", "source": None}]},
           "target": target}
    return Ev(ts, "okta", uid, doc)


def okta_user_target(user: str) -> list[dict[str, Any]]:
    return [{"id": "00u" + str(_h(user) % 10 ** 9), "type": "User", "alternateId": f"{user}@{DOMAIN}",
             "displayName": user, "detailEntry": None}]


def okta_app_target(app: str) -> list[dict[str, Any]]:
    return [{"id": "0oa" + str(_h(app) % 10 ** 9), "type": "AppInstance", "alternateId": app,
             "displayName": app, "detailEntry": None}]


def gws(r: Rand, ts: int, app: str, name: str, user: str, ip: str, params: dict[str, Any] | None = None,
        etype: str | None = None) -> Ev:
    ps = []
    for k, v in (params or {}).items():
        if isinstance(v, bool):
            ps.append({"name": k, "boolValue": v})
        elif isinstance(v, list):
            ps.append({"name": k, "multiValue": v})
        else:
            ps.append({"name": k, "value": str(v)})
    uq = str(-r.randint(10 ** 17, 10 ** 18))
    doc = {"kind": "admin#reports#activity",
           "id": {"time": iso_ms(ts), "uniqueQualifier": uq, "applicationName": app, "customerId": GWS_CUSTOMER},
           "etag": "\"" + r.b32(27) + "\"",
           "actor": {"callerType": "USER", "email": f"{user}@{DOMAIN}", "profileId": str(r.randint(10 ** 20, 10 ** 21))},
           "ipAddress": ip, "events": [{"type": etype or app, "name": name, "parameters": ps}]}
    return Ev(ts, "gws", f"{ts}-{uq}", doc)


def gws_cl(r: Rand, ts: int, svc: str, method: str, ev: str, user: str, ip: str, params: dict[str, str]) -> Ev:
    iid = r.b32(12).lower()
    log = "activity" if svc == "admin.googleapis.com" else "data_access"
    doc = {"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                            "authenticationInfo": {"principalEmail": f"{user}@{DOMAIN}"},
                            "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": UA_CHROME},
                            "serviceName": svc, "methodName": method, "resourceName": f"organizations/{GWS_ORG}",
                            "metadata": {"@type": "type.googleapis.com/ccc_hosted_reporting.ActivityProto",
                                         "activityId": {"timeUsec": str(ts * 1000), "uniqQualifier": str(r.randint(1, 10 ** 12))},
                                         "event": [{"eventType": "DELEGATED_ADMIN_SETTINGS", "eventName": ev,
                                                    "parameter": [{"type": "TYPE_STRING", "name": k, "value": v}
                                                                  for k, v in params.items()]}]}},
           "insertId": iid, "resource": {"type": "audited_resource", "labels": {"service": svc, "method": method}},
           "timestamp": iso_ms(ts), "severity": "NOTICE",
           "logName": f"organizations/{GWS_ORG}/logs/cloudaudit.googleapis.com%2F{log}", "receiveTimestamp": iso_ms(ts + 900)}
    return Ev(ts, "gws_cl", iid, doc)


_RT = {"Exchange": 1, "SharePoint": 6, "OneDrive": 6, "AzureActiveDirectory": 15}


def ual(r: Rand, ts: int, op: str, user: str, ip: str, workload: str, *, params: dict[str, str] | None = None,
        shape: str = "ual", status: str | None = "True", **extra: Any) -> Ev:
    """M365 UAL record: shape ual (Management API), ual_la (OfficeActivity) or cae (CloudAppEvents RawEventData)."""
    rid = r.guid()
    rec: dict[str, Any] = {"CreationTime": iso_s(ts)[:-1], "Id": rid, "Operation": op, "OrganizationId": TENANT,
                           "RecordType": _RT.get(workload, 1), "UserKey": r.hexs(16), "UserType": 0, "Version": 1,
                           "Workload": workload, "ClientIP": ip, "UserId": f"{user}@{DOMAIN}"}
    if status is not None:
        rec["ResultStatus"] = status
    if params is not None:
        rec["Parameters"] = [{"Name": k, "Value": v} for k, v in params.items()]
    rec.update(extra)
    ts = ts // 1000 * 1000
    if shape == "ual_la":
        la = {"TenantId": "0b1d0000-0000-4000-8000-000000000a01", "TimeGenerated": iso_ms(ts), "Operation": op,
              "OfficeWorkload": workload, "RecordType": "ExchangeAdmin" if workload == "Exchange" else workload,
              "UserId": rec["UserId"], "UserType": "Regular", "ClientIP": ip, "OfficeId": rid,
              "OrganizationId": TENANT, "ResultStatus": status, "OfficeObjectId": extra.get("ObjectId"),
              "Type": "OfficeActivity", "SourceSystem": "OfficeActivityManager"}
        if params is not None:
            la["Parameters"] = json.dumps(rec["Parameters"])
        return Ev(ts, "ual_la", rid, {k: v for k, v in la.items() if v is not None})
    if shape == "cae":
        doc = {"Timestamp": iso_ms(ts), "ActionType": op, "Application": "Microsoft SharePoint Online",
               "ApplicationId": 20892, "AccountObjectId": r.guid(), "AccountDisplayName": user, "IsAdminOperation": False,
               "IPAddress": ip.split(":")[0] if ip.count(":") == 1 else ip, "IsAnonymousProxy": False,
               "CountryCode": "NL", "ObjectName": extra.get("SourceFileName"), "ObjectType": "File",
               "ReportId": r.hexs(24), "RawEventData": rec}
        return Ev(ts, "cae", rid, doc)
    return Ev(ts, "ual", rid, rec)


def auth0(r: Rand, ts: int, typ: str, user: str, ip: str, *, client: str = "Customer Portal",
          ua: str = UA_CHROME, desc: str = "") -> Ev:
    lid = "900" + str(r.randint(10 ** 40, 10 ** 41))
    doc = {"date": iso_ms(ts), "type": typ, "description": desc, "connection": "Username-Password-Authentication",
           "connection_id": "con_" + r.b32(16), "client_id": "cl" + r.b32(30).lower(), "client_name": client,
           "ip": ip, "user_agent": ua, "details": {}, "hostname": AUTH0_HOST, "user_id": "auth0|" + r.hexs(24),
           "user_name": user, "strategy": "auth0", "strategy_type": "database", "log_id": lid,
           "tenant_name": "corp-portal"}
    return Ev(ts, "auth0", lid, doc)


def duo(r: Rand, ts: int, user: str, result: str, reason: str, ip: str, *, app: str = "Cisco VPN",
        factor: str = "duo_push", country: str = "India") -> Ev:
    tx = r.guid()
    doc = {"access_device": {"browser": "Chrome", "hostname": None, "ip": ip,
                             "location": {"city": _geo(country)["city"], "country": country, "state": None},
                             "os": "Windows"},
           "alias": "", "application": {"key": "DI" + r.b32(18), "name": app},
           "auth_device": {"ip": "198.51.100." + str(150 + _h(user) % 40), "name": "+91 98xxxx" + r.hexs(4),
                           "location": {"city": "Bengaluru", "country": "India", "state": "Karnataka"}},
           "email": f"{user}@{DOMAIN}", "event_type": "authentication", "factor": factor,
           "isotimestamp": iso_s(ts)[:-1] + f".{ts % 1000:03d}000+00:00", "ood_software": None, "reason": reason,
           "result": result, "timestamp": ts // 1000, "trusted_endpoint_status": "not trusted", "txid": tx,
           "user": {"groups": [], "key": "DU" + r.b32(18), "name": user}}
    return Ev(ts, "duo", tx, doc)


def iso_ms(ms: int) -> str:
    return iso_s(ms)[:-1] + f".{ms % 1000:03d}Z"


def entity(ev: Ev) -> dict[str, Any]:
    """host / user / src_ip as config/sources.yaml maps them (lower-case host, user before @ stripping)."""
    d = ev.doc
    if ev.feed == "okta":
        alt = d["actor"]["alternateId"]
        return {"host": alt.split("@", 1)[1].lower(), "user": alt, "src_ip": d["client"]["ipAddress"],
                "action": d["eventType"]}
    if ev.feed == "gws":
        return {"host": d["id"]["customerId"].lower(), "user": d["actor"]["email"], "src_ip": d["ipAddress"],
                "action": d["events"][0]["name"]}
    if ev.feed == "gws_cl":
        pp = d["protoPayload"]
        return {"host": d["logName"].split("/")[1], "user": pp["authenticationInfo"]["principalEmail"],
                "src_ip": pp["requestMetadata"]["callerIp"], "action": pp["methodName"]}
    if ev.feed in ("ual", "ual_la", "cae"):
        rec = d.get("RawEventData", d)
        ip = rec["ClientIP"]
        ip = ip.rsplit(":", 1)[0] if ip.count(":") == 1 else ip
        return {"host": rec["OrganizationId"].lower(), "user": rec["UserId"], "src_ip": ip, "action": rec["Operation"]}
    if ev.feed == "auth0":
        return {"host": d["hostname"], "user": d["user_name"], "src_ip": d["ip"], "action": d["type"]}
    if ev.feed == "duo":
        return {"host": d["application"]["name"].lower(), "user": d["user"]["name"], "src_ip": d["access_device"]["ip"],
                "action": d["reason"]}
    if ev.feed == "cloudtrail":
        from cloud_attacks.formats import entity as ct_entity
        return ct_entity(ev)
    raise ValueError(ev.feed)
