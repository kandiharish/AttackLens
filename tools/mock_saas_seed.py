"""Seed data for tools/mock_saas.py: Okta System Log events, Office 365 Management Activity API records (grouped
into content blobs) and Google Workspace Reports API activities, in each vendor's native JSON shape.

Synthetic only (RFC 5737 / 2606 addresses and domains). One identity attack story runs through all three feeds:
password spray from ATTACKER_IP -> MFA push fatigue -> success -> admin grant / API token (Okta); inbox forwarding
rule, mass download and an anonymous link (M365); spray -> suspicious login -> OAuth mail scope -> super-admin grant
-> Drive downloads (Workspace). The labels live only in ground_truth(): records never carry a label field.
Deterministic: every value derives from the anchor and a counter.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

MIN = 60_000
ATTACKER_IP = "203.0.113.77"
CORP_IPS = ("192.0.2.10", "192.0.2.11", "198.51.100.20")
DOMAIN = "corp.example"
TENANT = "6f1c2e4d-0000-4000-8000-0000000000c3"
GWS_CUSTOMER = "C03mock01"
USERS = ("asharma", "pmehta", "vreddy", "kiyer", "rnair", "sbose")
VICTIM, ADMIN = "pmehta", "kiyer"
CONTENT_TYPES = ("Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
ATT_UA = "python-requests/2.32.3"


def now_anchor(now_ms: int) -> int:
    """Anchor so the seed ends ~25 min before now (inside a 24h first pull, outside every ingest lag)."""
    return (now_ms - 6 * 3_600_000) // MIN * MIN


def iso(ms: int, frac: bool = True, z: bool = True) -> str:
    d = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    s = d.strftime("%Y-%m-%dT%H:%M:%S") + (f".{ms % 1000:03d}" if frac else "")
    return s + ("Z" if z else "")


class _Ids:
    def __init__(self, seed: str) -> None:
        self.seed, self.n = seed, 0

    def hexs(self, k: int = 32) -> str:
        self.n += 1
        return hashlib.sha256(f"{self.seed}:{self.n}".encode()).hexdigest()[:k]

    def guid(self) -> str:
        h = self.hexs(32)
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


@dataclass
class Seed:
    okta: list[dict[str, Any]] = field(default_factory=list)
    m365: dict[str, list[dict[str, Any]]] = field(default_factory=dict)   # content type -> blobs
    gws: dict[str, list[dict[str, Any]]] = field(default_factory=dict)    # application -> activities
    truth: list[dict[str, Any]] = field(default_factory=list)


def _geo(ip: str) -> dict[str, Any]:
    if ip == ATTACKER_IP:
        return {"city": "Amsterdam", "state": "North Holland", "country": "Netherlands", "postalCode": None,
                "geolocation": {"lat": 52.37, "lon": 4.89}}
    return {"city": "Bengaluru", "state": "Karnataka", "country": "India", "postalCode": "560001",
            "geolocation": {"lat": 12.97, "lon": 77.59}}


def okta_event(ids: _Ids, ts: int, etype: str, user: str, ip: str, result: str = "SUCCESS",
               reason: str | None = None, msg: str = "", target: list[dict[str, Any]] | None = None,
               session: str | None = None) -> dict[str, Any]:
    att = ip == ATTACKER_IP
    return {
        "actor": {"id": "00u" + hashlib.md5(user.encode()).hexdigest()[:17], "type": "User",
                  "alternateId": f"{user}@{DOMAIN}", "displayName": user.title(), "detailEntry": None},
        "client": {"userAgent": {"rawUserAgent": ATT_UA if att else UA, "os": "Unknown" if att else "Windows 10",
                                 "browser": "UNKNOWN" if att else "CHROME"},
                   "zone": "null", "device": "Unknown" if att else "Computer", "id": None, "ipAddress": ip,
                   "geographicalContext": _geo(ip)},
        "device": None,
        "authenticationContext": {"authenticationProvider": None, "credentialProvider": None,
                                  "credentialType": None, "issuer": None, "interface": None,
                                  "authenticationStep": 0, "rootSessionId": session or ids.hexs(25),
                                  "externalSessionId": session or ids.hexs(25)},
        "displayMessage": msg or etype, "eventType": etype, "outcome": {"result": result, "reason": reason},
        "published": iso(ts), "securityContext": {"asNumber": 64496 if att else 64500,
                                                  "asOrg": "example hosting" if att else "corp isp",
                                                  "isp": "example hosting" if att else "corp isp",
                                                  "domain": "example.net" if att else DOMAIN, "isProxy": att},
        "severity": "WARN" if result == "FAILURE" else "INFO",
        "debugContext": {"debugData": {"requestId": ids.hexs(27), "requestUri": "/api/v1/authn",
                                       "url": "/api/v1/authn?"}},
        "legacyEventType": None,
        "transaction": {"type": "WEB", "id": ids.hexs(27), "detail": {}},
        "uuid": ids.guid(), "version": "0",
        "request": {"ipChain": [{"ip": ip, "geographicalContext": _geo(ip), "version": "V4", "source": None}]},
        "target": target or [],
    }


def build_okta(A: int, truth: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ids, out = _Ids(f"okta{A}"), []

    def add(ts: int, *a: Any, tech: str | None = None, **kw: Any) -> None:
        e = okta_event(ids, ts, *a, **kw)
        out.append(e)
        if tech:
            truth.append({"feed": "okta", "id": e["uuid"], "technique": tech})
    for i in range(24):                                          # benign sign-ins and SSO, every ~12 min
        u = USERS[i % len(USERS)]
        add(A + i * 12 * MIN + 30_000, "user.session.start", u, CORP_IPS[i % 3], msg="User login to Okta")
        add(A + i * 12 * MIN + 95_000, "user.authentication.sso", u, CORP_IPS[i % 3],
            msg="User single sign on to app", target=[{"id": "0oa1", "type": "AppInstance",
                                                       "alternateId": "AWS Account Federation",
                                                       "displayName": "AWS Account Federation"}])
    t = A + 3 * 3_600_000
    for k, u in enumerate(USERS):                                # spray: one password per user from one IP
        add(t + k * 20_000, "user.session.start", u, ATTACKER_IP, "FAILURE", "INVALID_CREDENTIALS",
            "User login to Okta", tech="T1110.003")
    s = "102" + ids.hexs(22)
    add(t + 4 * MIN, "user.session.start", VICTIM, ATTACKER_IP, msg="User login to Okta", session=s,
        tech="T1078.004")
    for k in range(6):                                           # MFA fatigue, then the user accepts
        add(t + 5 * MIN + k * 30_000, "user.mfa.okta_verify.deny_push", VICTIM, ATTACKER_IP, "FAILURE",
            "User rejected Okta push verify", "User rejected Okta push verify", session=s, tech="T1621")
    add(t + 9 * MIN, "user.authentication.auth_via_mfa", VICTIM, ATTACKER_IP, msg="Authentication of user via MFA",
        session=s, tech="T1621")
    usr = {"id": "00u" + hashlib.md5(VICTIM.encode()).hexdigest()[:17], "type": "User",
           "alternateId": f"{VICTIM}@{DOMAIN}", "displayName": VICTIM.title()}
    add(t + 15 * MIN, "user.account.privilege.grant", VICTIM, ATTACKER_IP, msg="Grant user privilege",
        target=[usr, {"id": "SUPER_ADMIN", "type": "ROLE", "alternateId": "unknown", "displayName": "Super admin"}],
        session=s, tech="T1098.003")
    add(t + 17 * MIN, "system.api_token.create", VICTIM, ATTACKER_IP, msg="Create API token",
        target=[{"id": "00T1", "type": "Token", "alternateId": "unknown", "displayName": "sync-tool"}],
        session=s, tech="T1098.001")
    out.sort(key=lambda e: (e["published"], e["uuid"]))
    return out


# ---- Office 365 Management Activity API ---------------------------------------------------------------------------
def ual(ids: _Ids, ts: int, op: str, workload: str, record_type: int, user: str, ip: str,
        **extra: Any) -> dict[str, Any]:
    r = {"CreationTime": iso(ts, frac=False, z=False), "Id": ids.guid(), "Operation": op, "OrganizationId": TENANT,
         "RecordType": record_type, "ResultStatus": extra.pop("ResultStatus", "Succeeded"),
         "UserKey": "1003" + ids.hexs(12).upper(), "UserType": 0, "Version": 1, "Workload": workload,
         "UserId": f"{user}@{DOMAIN}", "ClientIP": ip}
    r.update(extra)
    return r


def build_m365(A: int, truth: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    ids = _Ids(f"m365{A}")
    recs: dict[str, list[tuple[int, dict[str, Any]]]] = {c: [] for c in CONTENT_TYPES}

    def add(ct: str, ts: int, *a: Any, tech: str | None = None, **kw: Any) -> None:
        r = ual(ids, ts, *a, **kw)
        recs[ct].append((ts, r))
        if tech:
            truth.append({"feed": "m365_ual", "id": r["Id"], "technique": tech})
    for i in range(12):
        u = USERS[i % len(USERS)]
        ip = CORP_IPS[i % 3]
        add("Audit.AzureActiveDirectory", A + i * 20 * MIN, "UserLoggedIn", "AzureActiveDirectory", 15, u, ip,
            ActorIpAddress=ip, AzureActiveDirectoryEventType=1, ObjectId="00000003-0000-0ff1-ce00-000000000000",
            ExtendedProperties=[{"Name": "UserAgent", "Value": UA}, {"Name": "RequestType",
                                                                     "Value": "OAuth2:Authorize"}])
        add("Audit.SharePoint", A + i * 20 * MIN + 4 * MIN, "FileAccessed", "SharePoint", 6, u, ip,
            ObjectId=f"https://corp.sharepoint.example/sites/fin/Shared Documents/q{i}.xlsx",
            SourceFileName=f"q{i}.xlsx", SiteUrl="https://corp.sharepoint.example/sites/fin/", UserAgent=UA)
        add("Audit.Exchange", A + i * 20 * MIN + 7 * MIN, "MailItemsAccessed", "Exchange", 50, u, ip,
            ClientIPAddress=ip, MailboxOwnerUPN=f"{u}@{DOMAIN}", LogonType=0)
        if i % 3 == 0:
            add("Audit.General", A + i * 20 * MIN + 9 * MIN, "MemberAdded", "MicrosoftTeams", 25, u, ip,
                TeamName="Finance", Members=[{"UPN": f"{USERS[(i + 1) % 6]}@{DOMAIN}", "Role": 1}])
    t, v = A + 3 * 3_600_000 + 20 * MIN, VICTIM
    add("Audit.AzureActiveDirectory", t, "UserLoggedIn", "AzureActiveDirectory", 15, v, ATTACKER_IP,
        ActorIpAddress=ATTACKER_IP, ExtendedProperties=[{"Name": "UserAgent", "Value": ATT_UA}], tech="T1078.004")
    add("Audit.Exchange", t + 3 * MIN, "New-InboxRule", "Exchange", 1, v, f"[::ffff:{ATTACKER_IP}]:51234",
        ObjectId=f"{v}@{DOMAIN}\\.", Parameters=[{"Name": "Name", "Value": "."},
                                                {"Name": "ForwardTo", "Value": "drop@exfil.example"},
                                                {"Name": "MoveToFolder", "Value": "RSS Feeds"},
                                                {"Name": "StopProcessingRules", "Value": "True"}],
        ResultStatus="True", tech="T1114.003")
    for k in range(8):
        add("Audit.SharePoint", t + 6 * MIN + k * 15_000, "FileDownloaded", "SharePoint", 6, v, ATTACKER_IP,
            ObjectId=f"https://corp.sharepoint.example/sites/fin/Shared Documents/payroll{k}.xlsx",
            SourceFileName=f"payroll{k}.xlsx", UserAgent=ATT_UA, tech="T1213.002")
    add("Audit.SharePoint", t + 9 * MIN, "AnonymousLinkCreated", "SharePoint", 14, v, ATTACKER_IP,
        ObjectId="https://corp.sharepoint.example/sites/fin/Shared Documents/payroll0.xlsx", tech="T1567")
    out: dict[str, list[dict[str, Any]]] = {}
    for ct, items in recs.items():
        items.sort(key=lambda x: (x[0], x[1]["Id"]))
        blobs = []
        for j in range(0, len(items), 5):                         # 5 records per blob
            chunk = items[j:j + 5]
            created = chunk[-1][0] + 3 * MIN
            cid = f"{iso(chunk[0][0], z=False).replace('-', '').replace(':', '').replace('.', '')}$" \
                  f"{iso(created, z=False).replace('-', '').replace(':', '').replace('.', '')}$" \
                  f"{ct.lower().replace('.', '_')}${ct.replace('.', '_')}$emea0001"
            blobs.append({"contentType": ct, "contentId": cid, "created_ms": created,
                          "contentCreated": iso(created), "contentExpiration": iso(created + 7 * 86_400_000),
                          "records": [r for _, r in chunk]})
        out[ct] = blobs
    return out


# ---- Google Workspace Reports API ---------------------------------------------------------------------------------
def gws_activity(ids: _Ids, ts: int, app: str, user: str, ip: str | None, etype: str, name: str,
                 params: list[dict[str, Any]]) -> dict[str, Any]:
    uq = str(-(int(ids.hexs(15), 16) % 9_000_000_000_000_000_000))
    a: dict[str, Any] = {"kind": "admin#reports#activity",
                         "id": {"time": iso(ts), "uniqueQualifier": uq, "applicationName": app,
                                "customerId": GWS_CUSTOMER},
                         "etag": f"\"{ids.hexs(20)}/{ids.hexs(12)}\"",
                         "actor": {"callerType": "USER", "email": f"{user}@{DOMAIN}",
                                   "profileId": str(100000000000000000000 + int(ids.hexs(8), 16))},
                         "events": [{"type": etype, "name": name, "parameters": params}]}
    if ip:
        a["ipAddress"] = ip
    return a


def build_gws(A: int, truth: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    ids = _Ids(f"gws{A}")
    out: dict[str, list[dict[str, Any]]] = {"login": [], "admin": [], "token": [], "drive": []}

    def add(ts: int, app: str, *a: Any, tech: str | None = None) -> None:
        act = gws_activity(ids, ts, app, *a)
        out[app].append(act)
        if tech:
            truth.append({"feed": "gws_reports", "id": f"{app}|{act['id']['uniqueQualifier']}|{act['id']['time']}",
                          "technique": tech})
    pw = [{"name": "login_type", "value": "google_password"}, {"name": "login_challenge_method",
                                                                 "multiValue": ["password"]}]
    for i in range(16):
        u = USERS[i % len(USERS)]
        add(A + i * 15 * MIN + 10_000, "login", u, CORP_IPS[i % 3], "login", "login_success",
            pw + [{"name": "is_suspicious", "boolValue": False}])
        add(A + i * 15 * MIN + 5 * MIN, "drive", u, CORP_IPS[i % 3], "access", "view",
            [{"name": "doc_id", "value": f"1doc{i}"}, {"name": "doc_title", "value": f"notes{i}"},
             {"name": "doc_type", "value": "document"}, {"name": "owner", "value": f"{u}@{DOMAIN}"},
             {"name": "visibility", "value": "private"}])
    for i in range(4):
        add(A + i * 50 * MIN + 2 * MIN, "token", USERS[i], CORP_IPS[0], "auth", "authorize",
            [{"name": "client_id", "value": "1234567890.apps.googleusercontent.com"},
             {"name": "app_name", "value": "Calendar Sync"}, {"name": "client_type", "value": "WEB"},
             {"name": "scope", "multiValue": ["https://www.googleapis.com/auth/calendar.readonly"]}])
    t, v = A + 3 * 3_600_000 + 40 * MIN, VICTIM
    for k, u in enumerate(USERS):
        add(t + k * 15_000, "login", u, ATTACKER_IP, "login", "login_failure",
            pw + [{"name": "login_failure_type", "value": "login_failure_invalid_password"}], tech="T1110.003")
    add(t + 3 * MIN, "login", v, ATTACKER_IP, "login", "login_success",
        pw + [{"name": "is_suspicious", "boolValue": True}], tech="T1078.004")
    add(t + 6 * MIN, "token", v, ATTACKER_IP, "auth", "authorize",
        [{"name": "client_id", "value": "9876543210.apps.googleusercontent.com"},
         {"name": "app_name", "value": "Mail Helper"}, {"name": "client_type", "value": "NATIVE_DESKTOP"},
         {"name": "scope", "multiValue": ["https://mail.google.com/"]}], tech="T1528")
    add(t + 9 * MIN, "admin", v, ATTACKER_IP, "DELEGATED_ADMIN_SETTINGS", "ASSIGN_ROLE",
        [{"name": "ROLE_NAME", "value": "_SEED_ADMIN_ROLE"}, {"name": "USER_EMAIL", "value": f"{v}@{DOMAIN}"}],
        tech="T1098.003")
    for k in range(6):
        add(t + 12 * MIN + k * 10_000, "drive", v, ATTACKER_IP, "access", "download",
            [{"name": "doc_id", "value": f"1fin{k}"}, {"name": "doc_title", "value": f"payroll{k}"},
             {"name": "doc_type", "value": "spreadsheet"}, {"name": "owner", "value": f"{ADMIN}@{DOMAIN}"},
             {"name": "visibility", "value": "shared_internally"}], tech="T1530")
    for app in out:
        out[app].sort(key=lambda a: (a["id"]["time"], a["id"]["uniqueQualifier"]), reverse=True)  # newest first
    return out


def build(anchor_ms: int) -> Seed:
    s = Seed()
    s.okta = build_okta(anchor_ms, s.truth)
    s.m365 = build_m365(anchor_ms, s.truth)
    s.gws = build_gws(anchor_ms, s.truth)
    return s


def counts(s: Seed) -> dict[str, int]:
    return {"okta": len(s.okta), "m365_ual": sum(len(b["records"]) for bl in s.m365.values() for b in bl),
            "m365_blobs": sum(len(bl) for bl in s.m365.values()),
            "gws_reports": sum(len(v) for v in s.gws.values())}
