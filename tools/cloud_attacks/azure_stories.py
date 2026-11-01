"""Planted Azure attacks (AZ1-AZ5) and decoys for gen_azure.py. Ground truth comes from each step's FIRST event as
written (ts + entities via azure_feeds.entity), so it can never drift from the data (TESTING.md §3.3).

AZ1 infostealer token replay -> AzureHound -> Key Vault sweep -> app secret (Graph, Key Vault, Identity Protection)
AZ2 leaked service-principal secret -> new-network sign-in -> Key Vault 403 probing -> dump -> purge -> CMK delete
AZ3 password spray -> MFA fatigue / fraud report -> sign-in -> inbox forwarding (Identity Protection detections)
AZ4 illicit consent -> app-only Graph mail collection -> credential added to the service principal (Graph export)
AZ5 export-only tenant (P0-3): risky sign-in -> Global Administrator to a new account -> diagnostic setting deleted
Attacker infrastructure is 203.0.113.140-189 only (RFC 5737); every other address is benign.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_attacks import azure_feeds as A
from cloud_attacks import formats as F
from cloud_attacks.common import (ALL_STAFF, DAY, DOMAIN, HOUR, MIN, SEC, START_MS, TRAVEL_IP, Ev, home_ip, iso_s,
                                  staff_index, sub_rng)

CONNECTOR = {"signin": "azure_monitor:SigninLogs", "audit": "azure_monitor:AuditLogs",
             "activity": "azure_monitor:AzureActivity", "signin_x": "azure_export:SignInLogs",
             "audit_x": "azure_export:AuditLogs", "activity_x": "azure_export:Administrative",
             "signin_ni": "azure_monitor:AADNonInteractiveUserSignInLogs",
             "signin_sp": "azure_monitor:AADServicePrincipalSignInLogs",
             "signin_mi": "azure_monitor:AADManagedIdentitySignInLogs", "kv": "azure_monitor:AZKVAuditLogs",
             "kv_x": "azure_export:AuditEvent", "kv_diag": "azure_monitor:AzureDiagnostics",
             "graph": "azure_monitor:MicrosoftGraphActivityLogs", "graph_x": "azure_export:MicrosoftGraphActivityLogs",
             "risk": "azure_monitor:AADUserRiskEvents", "risk_sp": "azure_monitor:AADServicePrincipalRiskEvents",
             "risk_api": "graph_api:riskDetections", "riskyusers": "azure_monitor:AADRiskyUsers"}
AIP = {"AZ1": "203.0.113.141", "AZ2": "203.0.113.150", "AZ3": "203.0.113.160", "AZ4": "203.0.113.170",
       "AZ5": "203.0.113.180"}
UA_PYREQ = "python-requests/2.31.0"
UA_HOUND = "azurehound/v2.1.7"
CI_SP = "ci-deployer"
PDF_APP = "pdf-converter-pro"
_KEEP = object()


def at(day: int, hour: int, minute: int = 0) -> int:
    return START_MS + day * DAY + hour * HOUR + minute * MIN


def first(events: list[Ev]) -> Ev:
    return min(events, key=lambda e: (e.ts, e.rid))


def source_of(ev: Ev) -> str:
    return f"{CONNECTOR[ev.feed]}:{A.entity(ev)['action']}"


@dataclass
class Step:
    technique_id: str
    tactic: str
    events: list[Ev]
    what: str
    user: Any = _KEEP

    def gt(self, n: int) -> dict[str, Any]:
        a = first(self.events)
        ent = A.entity(a)
        return {"step": n, "ts_ms": a.ts, "ts": iso_s(a.ts), "technique_id": self.technique_id, "tactic": self.tactic,
                "host": ent["host"], "user": ent["user"] if self.user is _KEEP else self.user,
                "src_ip": ent["src_ip"], "dst_ip": None, "source": source_of(a), "event_id": a.rid,
                "events": len(self.events), "what": self.what}


@dataclass
class Story:
    id: str
    name: str
    steps: list[Step]
    extra: list[Ev] = field(default_factory=list)
    refs: tuple[str, ...] = ()
    novel: bool = False

    def events(self) -> list[Ev]:
        return [e for s in self.steps for e in s.events] + self.extra

    def gt(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "clouds": ["azure"], "novel": self.novel, "refs": list(self.refs),
                "steps": [s.gt(i + 1) for i, s in enumerate(self.steps)]}


def sp_app(name: str) -> str:
    """The app id a service principal presents in Key Vault / Graph tokens (same as azure_feeds.signin_sp AppId)."""
    return F.stable("app", name, 12)


ENUM_PATHS = ("/users", "/groups", "/servicePrincipals", "/applications", "/directoryRoles", "/devices",
              "/roleManagement/directory/roleAssignments", "/oauth2PermissionGrants")


def az1(seed: int) -> Story:
    r, u, ip, t = sub_rng(seed, "AZ1"), "mjoshi", AIP["AZ1"], at(9, 10)
    uid, tok = F._uid(u), "tok-" + sub_rng(seed, "AZ1tok").guid()
    stolen = A.signin_ni(r, t - 9 * MIN, u, home_ip(staff_index(u)), tok)    # the victim's own sign-in (benign)
    s1 = [A.graph(r, t, "graph", uid, "/me", ip, tok, ua=UA_PYREQ),
          A.graph(r, t + 20 * SEC, "graph", uid, "/me/memberOf", ip, tok, ua=UA_PYREQ),
          A.risk(r, t + SEC, "risk", u, "anomalousToken", ip, level="medium", timing="offline", delay_ms=40 * MIN)]
    s2 = [A.graph(r, t + 5 * MIN + i * 2500, "graph", uid, f"{ENUM_PATHS[i % 8]}?$top=999&$skiptoken={r.hexs(8)}", ip,
                  tok, ua=UA_HOUND) for i in range(220)]
    t3 = t + 20 * MIN
    s3 = [A.kv(r, t3, "kv", "kv-prod-app", "SecretList", f"{u}@{DOMAIN}", ip)]
    s3 += [A.kv(r, t3 + 30 * SEC + i * 7 * SEC, "kv", "kv-prod-app", "SecretGet", f"{u}@{DOMAIN}", ip,
                f"secrets/{name}/{r.hexs(32)}") for i, name in enumerate(SECRETS_PROD)]
    t4, app = t + 40 * MIN, r.guid()
    s4 = [A.graph(r, t4, "graph", uid, f"/applications/{app}/addPassword", ip, tok, method="POST", ua=UA_PYREQ),
          F.audit(r, t4 + 2 * SEC, "Update application – Certificates and secrets management ", "ApplicationManagement",
                  ip, [F.obj_target("Application", "payroll-api", app,
                                    [{"displayName": "KeyDescription", "newValue": '"[\\"KeyType=Password\\"]"'}])],
                  actor=u)]
    return Story("AZ1", "infostealer token replay -> AzureHound Graph enumeration -> Key Vault sweep -> app secret added",
                 [Step("T1550.001", "Lateral Movement", s1, "Graph calls with mjoshi's token from attacker infra"),
                  Step("T1087.004", "Discovery", s2, "AzureHound enumerates users / groups / SPs / roles via Graph"),
                  Step("T1555.006", "Credential Access", s3, "lists then reads 12 secrets of kv-prod-app"),
                  Step("T1098.001", "Persistence", s4, "adds a password to the payroll-api application")],
                 extra=[stolen], refs=("https://github.com/SpecterOps/AzureHound",))


def az2(seed: int) -> Story:
    r, ip, t = sub_rng(seed, "AZ2"), AIP["AZ2"], at(10, 15)
    app, tok = sp_app(CI_SP), "tok-" + r.guid()
    s1 = [A.signin_sp(r, t, CI_SP, ip, tok, resource="Azure Key Vault"),
          A.risk(r, t + SEC, "risk_sp", CI_SP, "investigationsThreatIntelligence", ip, level="high", timing="offline",
                 delay_ms=2 * HOUR)]
    s2 = [A.kv(r, t + 5 * MIN + i * 20 * SEC, "kv_x", "kv-finance", "SecretGet", app, ip, f"secrets/{name}",
               status=403, ua=UA_PYREQ) for i, name in enumerate(SECRETS_FIN[:6])]
    t3 = t + 15 * MIN
    s3 = [A.kv(r, t3, "kv", "kv-prod-app", "SecretList", app, ip, ua=UA_PYREQ)]
    s3 += [A.kv(r, t3 + 20 * SEC + i * 5 * SEC, "kv", "kv-prod-app", "SecretGet", app, ip, f"secrets/{name}",
                ua=UA_PYREQ) for i, name in enumerate(SECRETS_PROD[:10])]
    t4 = t + 30 * MIN
    s4 = []
    for i, name in enumerate(SECRETS_PROD[6:10]):
        s4.append(A.kv(r, t4 + i * 20 * SEC, "kv", "kv-prod-app", "SecretDelete", app, ip, f"secrets/{name}",
                       ua=UA_PYREQ))
        s4.append(A.kv(r, t4 + i * 20 * SEC + 8 * SEC, "kv", "kv-prod-app", "SecretPurge", app, ip,
                       f"deletedsecrets/{name}", status=204, ua=UA_PYREQ))
    t5 = t + 45 * MIN
    s5 = [A.kv(r, t5, "kv", "kv-prod-app", "KeyDelete", app, ip, "keys/cmk-storage", ua=UA_PYREQ),
          A.kv(r, t5 + MIN, "kv", "kv-prod-app", "KeyPurge", app, ip, "deletedkeys/cmk-storage", status=204, ua=UA_PYREQ)]
    return Story("AZ2", "leaked SP secret -> new-network sign-in -> Key Vault 403 probing -> dump -> purge -> CMK delete",
                 [Step("T1078.004", "Initial Access", s1, "ci-deployer client-credential sign-in from attacker infra"),
                  Step("T1555.006", "Credential Access", s2, "403 on six kv-finance secrets (probing)"),
                  Step("T1555.006", "Credential Access", s3, "lists and reads 10 kv-prod-app secrets"),
                  Step("T1485", "Impact", s4, "deletes and purges four secrets (soft delete defeated)"),
                  Step("T1486", "Impact", s5, "deletes and purges the storage customer-managed key")],
                 refs=("https://learn.microsoft.com/azure/key-vault/general/logging",))


def az3(seed: int) -> Story:
    r, ip, t, u = sub_rng(seed, "AZ3"), AIP["AZ3"], at(11, 6), "nbose"
    victims = [x for x, _, _ in ALL_STAFF[12:26]]
    s1 = [F.signin(r, t + i * 25 * SEC, v, v, ip, result="50126", country="NL", city="Amsterdam", client="Browser",
                   ua=UA_PYREQ) for i, v in enumerate(victims)]
    s1.append(A.risk(r, t + 2 * MIN, "risk", u, "passwordSpray", ip, level="medium", timing="offline",
                     delay_ms=3 * HOUR, cc="NL"))
    s1.append(F.signin(r, t + 2 * MIN, u, "Nikhil Bose", ip, result="50074", country="NL", city="Amsterdam"))
    s2 = [F.signin(r, t + 12 * MIN + i * 50 * SEC, u, "Nikhil Bose", ip, result="500121", country="NL",
                   city="Amsterdam") for i in range(6)]
    s2.append(A.risk(r, t + 14 * MIN, "risk_api", u, "mfaFraud", ip, level="high", cc="NL"))
    s3 = [F.signin(r, t + 20 * MIN, u, "Nikhil Bose", ip, country="NL", city="Amsterdam",
                   mfa="Mobile app notification", ca="success"),
          A.risk(r, t + 20 * MIN + SEC, "risk", u, "unfamiliarFeatures", ip, level="high", cc="NL")]
    s4 = [A.risk(r, t + 40 * MIN, "risk", u, "suspiciousInboxForwarding", ip, level="medium",
                 source="MicrosoftCloudAppSecurity", timing="offline", delay_ms=HOUR, cc="NL")]
    return Story("AZ3", "password spray -> MFA fatigue (fraud reported) -> sign-in -> inbox forwarding rule",
                 [Step("T1110.003", "Credential Access", s1, "50126 for 14 users in 6 minutes, nbose's password works",
                       user=None),
                  Step("T1621", "Credential Access", s2, "six MFA prompts, one reported as fraud"),
                  Step("T1078.004", "Initial Access", s3, "nbose approves a prompt: sign-in from the spray IP"),
                  Step("T1114.003", "Collection", s4, "inbox forwarding rule (Defender for Cloud Apps detection)")],
                 refs=("https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks",))


def az4(seed: int) -> Story:
    r, ip, t, u = sub_rng(seed, "AZ4"), AIP["AZ4"], at(12, 2), "skapoor"
    oid, spid, tok = r.guid(), f"spid-{PDF_APP}", "tok-" + r.guid()
    s1 = [F.audit(r, t, "Consent to application", "ApplicationManagement", ip,
                  [F.obj_target("ServicePrincipal", "PDF Converter Pro", oid,
                                [{"displayName": "ConsentContext.IsAdminConsent", "newValue": '"False"'},
                                 {"displayName": "ConsentAction.Permissions",
                                  "newValue": f'"[[Id: {r.hexs(20)}, ClientId: {oid}, ConsentType: Principal, '
                                              f'Scope:  Mail.Read Mail.ReadWrite offline_access]]"'}])], actor=u),
          F.audit(r, t + 20 * SEC, "Add OAuth2PermissionGrant", "ApplicationManagement", ip,
                  [F.obj_target("ServicePrincipal", "PDF Converter Pro", oid,
                                [{"displayName": "Scope", "newValue": '"Mail.Read Mail.ReadWrite offline_access"'}])],
                  actor=u)]
    t2 = t + 30 * MIN
    boxes = [x for x, _, _ in ALL_STAFF[:12] if x != u]
    s2 = [A.graph(r, t2 + 40 * SEC + i * 45 * SEC, "graph_x", spid, f"/users/{b}@{DOMAIN}/messages?$top=100", ip, tok,
                  sp=True, ua=UA_PYREQ, roles="Mail.Read", app=sp_app(PDF_APP)) for i, b in enumerate(boxes)]
    extra = [A.signin_sp(r, t2, PDF_APP, ip, tok, resource="Microsoft Graph")]
    t3 = t + 50 * MIN
    s3 = [A.graph(r, t3, "graph", F._uid(u), f"/servicePrincipals/{oid}/addPassword", ip, "tok-" + r.guid(),
                  method="POST", ua=UA_PYREQ)]
    return Story("AZ4", "illicit OAuth consent -> app-only Graph mail collection -> password added to the app",
                 [Step("T1528", "Credential Access", s1, "consent + Mail.Read grant to PDF Converter Pro"),
                  Step("T1114.002", "Collection", s2, "the app reads 11 mailboxes through Graph (export shape)"),
                  Step("T1098.001", "Persistence", s3, "password added to the consented service principal")],
                 extra=extra, refs=("https://learn.microsoft.com/graph/microsoft-graph-activity-logs-overview",))


def az5(seed: int) -> Story:
    r, ip, t, u = sub_rng(seed, "AZ5"), AIP["AZ5"], at(13, 3), "dsingh"
    si = F.signin(r, t, u, "Deepak Singh", ip, country="BR", city="Sao Paulo", app="Azure Portal")
    si.doc.update(RiskLevelDuringSignIn="high", RiskState="atRisk", RiskLevelAggregated="high")
    s1 = [A.signin_export(si, tok="tok-" + r.guid())]
    tgt = F.user_target("helpdesk.temp")
    tgt["modifiedProperties"] = [{"displayName": "Role.DisplayName", "oldValue": None,
                                  "newValue": '"Global Administrator"'}]
    s2 = [A.audit_export(F.audit(r, t + 8 * MIN, "Add member to role", "RoleManagement", ip, [tgt], actor=u))]
    diag = F.res_id("resourcegroups/rg-data/providers/microsoft.storage/storageaccounts/corpfinancedata/providers/"
                    "microsoft.insights/diagnosticsettings/to-sentinel")
    s3 = [A.activity_export(e, "Deepak Singh") for e in
          F.activity(r, t + 15 * MIN, "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE", f"{u}@{DOMAIN}", ip, diag)]
    return Story("AZ5", "export-only tenant: risky sign-in -> Global Administrator to a new account -> diag setting off",
                 [Step("T1078.004", "Initial Access", s1, "high-risk sign-in (diagnostic export shape)"),
                  Step("T1098.003", "Privilege Escalation", s2, "Global Administrator granted (AuditLogs export)"),
                  Step("T1685.002", "Defense Impairment", s3, "diagnostic setting deleted (Activity Log export)")])


SECRETS_PROD = ("db-password", "api-key", "storage-conn", "redis-key", "sendgrid-key", "jwt-signing", "payroll-db",
                "sftp-password", "github-pat", "datadog-key", "stripe-secret", "smtp-password")
SECRETS_FIN = ("swift-api-key", "ledger-db", "treasury-sso", "bank-sftp", "erp-admin", "tax-portal", "fx-feed")


def build_stories(seed: int) -> list[Story]:
    return [az1(seed), az2(seed), az3(seed), az4(seed), az5(seed)]


def build_decoys(seed: int) -> list[dict[str, Any]]:
    """Explicit one-off decoys (planted here); the recurring ones are generated by gen_azure's baseline."""
    r = sub_rng(seed, "AZdecoy")
    t = at(6, 7)
    travel = [A.risk(r, t, "risk", "vreddy", "unlikelyTravel", TRAVEL_IP, level="medium", state="dismissed",
                     detail="userPassedMFADrivenByRiskBasedPolicy", cc="SG")]
    t2 = at(8, 6)
    purge = [A.kv(r, t2, "kv_diag", "kv-legacy", "SecretDelete", "asharma@corp.example", "192.0.2.10",
                  "secrets/temp-migration-token", ua=A.UA_PS),
             A.kv(r, t2 + MIN, "kv_diag", "kv-legacy", "SecretPurge", "asharma@corp.example", "192.0.2.10",
                  "deletedsecrets/temp-migration-token", status=204, ua=A.UA_PS)]
    out = []
    for did, why, evs in (("ZD1", "traveller vreddy: unlikelyTravel, dismissed after MFA (Singapore trip)", travel),
                          ("ZD2", "admin deletes + purges ONE temporary migration secret from the corp IP", purge)):
        a = first(evs)
        ent = A.entity(a)
        out.append({"id": did, "ts_ms": a.ts, "ts": iso_s(a.ts), "source": source_of(a), "host": ent["host"],
                    "user": ent["user"], "src_ip": ent["src_ip"], "event_id": a.rid, "events": len(evs),
                    "recurring": False, "why": why, "_events": evs})
    return out


RECURRING_DECOYS = [
    {"id": "ZD3", "source": "azure_monitor:MicrosoftGraphActivityLogs", "recurring": True,
     "why": "secinventory app enumerates users / groups / SPs / roles / apps / devices every night at 01:00 UTC"},
    {"id": "ZD4", "source": "azure_export:MicrosoftGraphActivityLogs", "recurring": True,
     "why": "mailbackup app reads every staff mailbox nightly (app-only Mail.Read)"},
    {"id": "ZD5", "source": "azure_monitor:AZKVAuditLogs", "recurring": True,
     "why": "kv-rotator sets 12 secrets every Monday (SecretSet, not reads)"},
    {"id": "ZD6", "source": "azure_export:AuditEvent", "recurring": True,
     "why": "mi-func-billing gets 403 on one kv-finance secret twice a day (stale access policy)"},
    {"id": "ZD7", "source": "azure_monitor:MicrosoftGraphActivityLogs", "recurring": True,
     "why": "asharma browses users / groups / devices / apps in the Entra admin center every weekday"},
]
