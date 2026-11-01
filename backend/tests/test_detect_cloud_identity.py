"""Identity SaaS native rules (config/rules_cloud.yaml okta_* / gws_* / m365_* / auth0_* / duo_*).

Made-up Okta, Workspace (Reports API + Cloud Logging copy), M365 UAL (Management API + OfficeActivity), Auth0 and Duo
records go through the real Stage 0 + 1 ingest, then run_cloud with only the identity rules. Positive actors are p_*,
near misses n_*; ten quiet days come first so baseline rules (mass download) are past their cold start.
"""

from __future__ import annotations

import itertools
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from attacklens import db

from .conftest import run_ingest
from .test_detect_cloud import run, subset

ORG = "4d5f1c2e-0000-4000-8000-0000000000a1"
T0 = int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp() * 1000)
DAY, HOUR, MIN = 86_400_000, 3_600_000, 60_000
D10 = T0 + 10 * DAY + 9 * HOUR
CHROME, PY = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0", "python-requests/2.31"
_ids = itertools.count(1)


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def okta(ts: int, et: str, who: str, res: str = "SUCCESS", ip: str = "198.51.100.7", sess: str | None = None,
         asn: int = 64500, ua: str = CHROME, target: list | None = None, debug: dict | None = None) -> dict:
    return {"uuid": f"ok-{next(_ids)}", "published": iso(ts), "eventType": et, "legacyEventType": et,
            "actor": {"id": "00u1", "type": "User", "alternateId": f"{who}@corp.example", "displayName": who},
            "client": {"userAgent": {"rawUserAgent": ua}, "ipAddress": ip,
                       "geographicalContext": {"country": "India", "geolocation": {"lat": 12.97, "lon": 77.59}}},
            "authenticationContext": {"externalSessionId": sess or f"s-{next(_ids)}", "credentialType": "PASSWORD"},
            "securityContext": {"asNumber": asn, "isProxy": False}, "outcome": {"result": res, "reason": None},
            "debugContext": {"debugData": debug or {}}, "target": target, "severity": "INFO", "version": "0"}


def gws(ts: int, app: str, name: str, who: str, ip: str = "198.51.100.7", **params: Any) -> dict:
    ps = [{"name": k, "boolValue": v} if isinstance(v, bool) else {"name": k, "multiValue": v} if isinstance(v, list)
          else {"name": k, "value": v} for k, v in params.items()]
    return {"kind": "admin#reports#activity", "id": {"time": iso(ts), "uniqueQualifier": str(next(_ids)),
            "applicationName": app, "customerId": "C03abc123"}, "actor": {"email": f"{who}@corp.example"},
            "ipAddress": ip, "events": [{"type": app, "name": name, "parameters": ps}]}


def gcl(ts: int, svc: str, method: str, ev: str, who: str, ip: str = "198.51.100.7", **params: str) -> dict:
    return {"protoPayload": {"serviceName": svc, "methodName": method, "authenticationInfo": {"principalEmail": f"{who}@corp.example"},
            "requestMetadata": {"callerIp": ip}, "resourceName": "organizations/123",
            "metadata": {"event": [{"eventName": ev, "parameter": [{"name": k, "value": v} for k, v in params.items()]}]}},
            "insertId": f"i-{next(_ids)}", "resource": {"type": "audited_resource", "labels": {"service": svc}},
            "timestamp": iso(ts), "logName": "organizations/123/logs/cloudaudit.googleapis.com%2Factivity"}


def ual(ts: int, op: str, who: str, wl: str = "Exchange", ip: str = "203.0.113.5:1000", la: bool = False,
        params: dict | None = None, **extra: Any) -> dict:
    d: dict[str, Any] = {"Id": f"m-{next(_ids)}", "Operation": op, "OrganizationId": ORG, "RecordType": 1, "UserType": 0,
                         "UserId": f"{who}@corp.example", "ClientIP": ip, "ResultStatus": "True", **extra}
    if params is not None:
        p = [{"Name": k, "Value": v} for k, v in params.items()]
        d["Parameters"] = json.dumps(p) if la else p
    if la:   # Log Analytics OfficeActivity
        d.update(TimeGenerated=iso(ts), OfficeWorkload=wl, Type="OfficeActivity")
    else:
        d.update(CreationTime=iso(ts)[:19], Workload=wl)
    return d


def a0(ts: int, typ: str, who: str, ip: str = "198.51.100.7") -> dict:
    return {"log_id": f"a0-{next(_ids)}", "date": iso(ts), "type": typ, "client_name": "Corp Portal", "client_id": "c1",
            "connection_id": "con_1", "strategy_type": "database", "hostname": "corp.us.auth0.com", "ip": ip,
            "user_name": f"{who}@corp.example"}


def duo(ts: int, who: str, res: str, reason: str, ip: str = "198.51.100.7") -> dict:
    return {"txid": f"tx-{next(_ids)}", "isotimestamp": iso(ts), "timestamp": ts // 1000, "event_type": "authentication",
            "result": res, "reason": reason, "factor": "duo_push", "user": {"name": who},
            "application": {"name": "Okta SSO"}, "access_device": {"ip": ip}, "auth_device": {"ip": "198.51.100.20"},
            "ood_software": None}


def history() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {"okta": [], "gws": [], "ual": [], "a0": [], "duo": []}
    for d in range(10):
        t = T0 + d * DAY + 8 * HOUR
        for who in ("alice", "bob", "p_dl", "n_dl"):
            out["okta"].append(okta(t, "user.session.start", who))
            out["gws"].append(gws(t, "login", "login_success", who))
            out["a0"].append(a0(t, "s", who))
            out["duo"].append(duo(t, who, "success", "user_approved"))
        for who in ("p_dl", "n_dl"):
            for i in range(5):
                out["ual"].append(ual(t + i * MIN, "FileDownloaded", who, wl="SharePoint", ip="198.51.100.9",
                                      ObjectId=f"https://corp.sharepoint.com/sites/x/f{d}-{i}.docx"))
        for i in range(60):   # n_sync: OneDrive sync client pulls 60 files every morning (its own baseline)
            out["ual"].append(ual(t + i * 20_000, "FileSyncDownloadedFull", "n_sync", wl="OneDrive", ip="198.51.100.9",
                                  ObjectId=f"https://corp-my.sharepoint.com/personal/n_sync/d/{i}.parquet"))
    return out


def attacks() -> dict[str, list[dict]]:   # noqa: PLR0915 - one flat list of scenarios is the readable form
    t = D10
    o: list[dict] = []
    users = [f"u{i}" for i in range(10)]
    for i, u in enumerate(users):                                   # spray 10 users -> success from the same IP
        o.append(okta(t + i * MIN, "user.session.start", u, "FAILURE", ip="203.0.113.9"))
        if i < 5:
            o.append(okta(t + i * MIN, "user.session.start", u, "FAILURE", ip="203.0.113.10"))   # near: 5 users
    o.append(okta(t + 12 * MIN, "user.session.start", "u3", ip="203.0.113.9"))
    o += [okta(t + i * MIN, "user.session.start", "n_brute", "FAILURE", ip="203.0.113.11") for i in range(15)]
    for i in range(6):                                              # push fatigue -> approve -> new factor
        o.append(okta(t + HOUR + i * MIN, "system.push.send_factor_verify_push", "p_push"))
        if i % 2:
            o.append(okta(t + HOUR + i * MIN + 30_000, "user.mfa.okta_verify.deny_push", "p_push", "DENY"))
    o.append(okta(t + HOUR + 8 * MIN, "user.authentication.auth_via_mfa", "p_push"))
    o.append(okta(t + HOUR + 20 * MIN, "user.mfa.factor.activate", "p_push"))
    for i in range(3):
        o.append(okta(t + HOUR + i * MIN, "system.push.send_factor_verify_push", "n_push"))
    o.append(okta(t + HOUR + 2 * MIN, "user.mfa.okta_verify.deny_push", "n_push", "DENY"))
    o.append(okta(t, "user.session.start", "p_hij", ip="198.51.100.20", sess="S1", asn=64500))     # cookie replay
    o.append(okta(t + 20 * MIN, "user.authentication.sso", "p_hij", ip="203.0.113.50", sess="S1", asn=64999, ua=PY))
    o.append(okta(t, "user.session.start", "n_roam", ip="198.51.100.21", sess="S2", asn=64501))     # roaming laptop
    o.append(okta(t + 20 * MIN, "user.authentication.sso", "n_roam", ip="198.51.100.150", sess="S2", asn=64502))
    eve = [{"type": "User", "alternateId": "eve@corp.example"}]
    o.append(okta(t, "user.account.privilege.grant", "p_grant", target=eve, debug={"privilegeGranted": "Super administrator"}))
    o.append(okta(t, "user.account.privilege.grant", "n_grant", target=eve, debug={"privilegeGranted": "Help Desk administrator"}))
    o += [okta(t, "system.idp.lifecycle.create", "p_idp"), okta(t, "system.idp.lifecycle.read", "n_idp"),
          okta(t, "policy.lifecycle.deactivate", "p_pol"), okta(t, "policy.lifecycle.update", "n_pol"),
          okta(t, "system.api_token.create", "p_tok"), okta(t, "system.api_token.revoke", "n_tok")]
    g: list[dict] = []
    for i, u in enumerate(users):
        g.append(gws(t + i * MIN, "login", "login_failure", u, ip="203.0.113.20"))
    g.append(gws(t + 12 * MIN, "login", "login_success", "u5", ip="203.0.113.20"))
    g += [gws(t, "login", "login_success", "p_susp", is_suspicious=True),
          gws(t, "login", "login_success", "n_susp", is_suspicious=False),
          gcl(t, "admin.googleapis.com", "google.admin.AdminService.assignRole", "ASSIGN_ROLE", "p_gadm",
              ROLE_NAME="_SEED_ADMIN_ROLE", USER_EMAIL="eve@corp.example"),
          gws(t, "admin", "ASSIGN_ROLE", "n_gadm", ROLE_NAME="Groups Admin", USER_EMAIL="eve@corp.example"),
          gws(t, "login", "2sv_disable", "p_2sv"), gws(t, "login", "2sv_enroll", "n_2sv"),
          gws(t, "token", "authorize", "p_oauth", client_id="9999.apps", app_name="Mail Helper",
              scope=["https://mail.google.com/", "openid"]),
          gws(t, "token", "authorize", "n_oauth", client_id="1111.apps", app_name="Calendar Sync",
              scope=["https://www.googleapis.com/auth/calendar.readonly"]),
          gws(t, "admin", "AUTHORIZE_API_CLIENT_ACCESS", "p_dwd", API_CLIENT_NAME="1234"),
          gws(t, "admin", "REMOVE_API_CLIENT_ACCESS", "n_dwd", API_CLIENT_NAME="1234")]
    m: list[dict] = [
        ual(t, "New-InboxRule", "p_fwd", params={"Name": "x", "ForwardTo": "drop@evil.example"}),
        ual(t, "New-InboxRule", "n_fwd", params={"Name": "x", "ForwardTo": "colleague@corp.example"}),
        ual(t, "Set-Mailbox", "n_fwd0", params={"Identity": "n_fwd0", "ForwardingSmtpAddress": ""}),
        ual(t, "Set-Mailbox", "p_fwd2", la=True, params={"Identity": "p_fwd2", "ForwardingSmtpAddress": "smtp:x@evil.example"}),
        ual(t, "New-InboxRule", "p_hide", params={"MoveToFolder": "RSS Feeds", "SubjectContainsWords": "invoice;payment"}),
        ual(t, "New-InboxRule", "n_hide", params={"MoveToFolder": "Newsletters", "FromAddressContainsWords": "news"}),
        ual(t, "Add-MailboxPermission", "p_deleg", params={"Identity": "ceo", "User": "p_deleg", "AccessRights": "FullAccess"}),
        ual(t, "Add-MailboxFolderPermission", "n_deleg", params={"Identity": "ceo:\\Calendar", "AccessRights": "Reviewer"}),
        ual(t, "Add member to role.", "p_m3role", wl="AzureActiveDirectory", ObjectId="eve@corp.example",
            ModifiedProperties=[{"Name": "Role.DisplayName", "NewValue": "Global Administrator"}]),
        ual(t, "Add member to role.", "n_m3role", wl="AzureActiveDirectory", ObjectId="eve@corp.example",
            ModifiedProperties=[{"Name": "Role.DisplayName", "NewValue": "Reports Reader"}]),
        ual(t, "Consent to application.", "p_consent", wl="AzureActiveDirectory",
            ModifiedProperties=[{"Name": "ConsentAction.Permissions", "NewValue": "Scope: Mail.Read offline_access"}]),
        ual(t, "Consent to application.", "n_consent", wl="AzureActiveDirectory",
            ModifiedProperties=[{"Name": "ConsentAction.Permissions", "NewValue": "Scope: User.Read"}]),
        ual(t, "Set-AdminAuditLogConfig", "p_audit", params={"UnifiedAuditLogIngestionEnabled": "False"}),
        ual(t, "Set-AdminAuditLogConfig", "n_audit", params={"UnifiedAuditLogIngestionEnabled": "True"}),
        ual(t, "SharingInvitationCreated", "n_share", wl="SharePoint", TargetUserOrGroupName="colleague@corp.example",
            TargetUserOrGroupType="Member", ObjectId="https://corp.sharepoint.com/sites/x/a.docx")]
    m += [ual(t + i * 20_000, "FileDownloaded", "p_dl", wl="SharePoint", ObjectId=f"https://corp.sharepoint.com/s/{i}.xlsx")
          for i in range(80)]
    m += [ual(t + i * 20_000, "FileDownloaded", "n_dl", wl="SharePoint", ObjectId=f"https://corp.sharepoint.com/s/n{i}.xlsx")
          for i in range(30)]
    m += [ual(t + i * 20_000, "FileSyncDownloadedFull", "n_sync", wl="OneDrive", ip="198.51.100.9",
              ObjectId=f"https://corp-my.sharepoint.com/personal/n_sync/d/{i}.parquet") for i in range(60)]
    m += [ual(t + i * MIN, "AnonymousLinkCreated", "p_share", wl="SharePoint", ObjectId=f"https://corp.sharepoint.com/s/q{i}.pdf")
          for i in range(6)]
    a: list[dict] = [a0(t + i * MIN, "fp", u, ip="203.0.113.30") for i, u in enumerate(users)]
    a += [a0(t + i * MIN, "fp", u, ip="203.0.113.31") for i, u in enumerate(users[:4])]
    a += [a0(t + 12 * MIN, "s", "u7", ip="203.0.113.30"), a0(t, "limit_mu", "u1", ip="203.0.113.30")]
    a += [a0(t + HOUR + i * MIN, "gd_send_pn", "p_a0push") for i in range(5)]
    a += [a0(t + HOUR + i * MIN + 1000, "gd_auth_rejected", "p_a0push") for i in range(3)]
    a += [a0(t + HOUR + 9 * MIN, "gd_auth_succeed", "p_a0push")]
    a += [a0(t + HOUR, "gd_send_pn", "n_a0push"), a0(t + HOUR + MIN, "gd_send_pn", "n_a0push"),
          a0(t + HOUR + MIN, "gd_auth_rejected", "n_a0push")]
    u: list[dict] = [duo(t + i * MIN, "p_duo", "denied", ("no_response", "user_cancelled")[i % 2]) for i in range(6)]
    u += [duo(t + 8 * MIN, "p_duo", "success", "user_approved")]
    u += [duo(t + i * MIN, "n_duo", "denied", "no_response") for i in range(3)]
    u += [duo(t, "p_fraud", "fraud", "user_marked_fraud"), duo(t, "n_fraud", "success", "user_approved")]
    return {"okta": o, "gws": g, "ual": m, "a0": a, "duo": u}


IDS = {"okta_password_spray", "okta_mfa_push_fatigue", "okta_session_hijack", "okta_admin_grant", "okta_new_idp",
       "okta_policy_weakened", "okta_api_token_created", "okta_mfa_factor_change", "gws_password_spray",
       "gws_suspicious_login", "gws_admin_role_grant", "gws_2sv_disabled", "gws_oauth_broad_scope",
       "gws_domain_wide_delegation", "m365_inbox_forward_rule", "m365_inbox_hiding_rule", "m365_mailbox_delegation",
       "m365_admin_role_grant", "m365_oauth_consent", "m365_mass_download", "m365_external_sharing",
       "m365_audit_disabled", "auth0_credential_stuffing", "auth0_mfa_push_fatigue", "duo_push_fatigue",
       "duo_user_marked_fraud"}


@pytest.fixture(scope="module")
def ds(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("cloud_identity")
    raw = tmp / "raw"
    raw.mkdir()
    h, at = history(), attacks()
    for name in h:
        rows = h[name] + at[name]
        # one export per file (Stage 0 routes a file by its keys): the Cloud Logging copy goes to its own file
        for suffix, part in (("", [r for r in rows if "protoPayload" not in r]),
                             ("_cl", [r for r in rows if "protoPayload" in r])):
            if part:
                (raw / f"{name}{suffix}.log").write_text("\n".join(json.dumps(r) for r in part) + "\n",
                                                          encoding="utf-8")
    # Purview audit search CSV: AuditData is the UAL record as a JSON string (doubled quotes)
    ad = json.dumps({"CreationTime": iso(D10)[:19], "Id": "csv-1", "Operation": "New-InboxRule", "OrganizationId": ORG,
                     "RecordType": 1, "ResultStatus": "True", "UserId": "p_csvfwd@corp.example", "Workload": "Exchange",
                     "ClientIP": "203.0.113.5:4000", "Parameters": [{"Name": "ForwardTo", "Value": "x@evil.example"}]})
    (raw / "purview.csv").write_text(
        "RecordId,CreationDate,RecordType,Operation,UserId,AuditData,AssociatedAdminUnits\r\n"
        f"csv-1,{iso(D10)},ExchangeAdmin,New-InboxRule,p_csvfwd@corp.example,\"{ad.replace(chr(34), chr(34) * 2)}\",\r\n",
        encoding="utf-8")
    ctx = run_ingest(raw, tmp)
    ctx.con.close()
    con = db.connect(memory_limit="400MB", threads=2, temp_directory=tmp / "spill")
    db.register_events(con, ctx.events_glob)
    st, alerts = run(con, subset(ctx.cfg, IDS), tmp / "work", ctx.events_glob)
    yield {"stats": st, "alerts": alerts, "ctx": ctx}
    con.close()


def of(ds: dict, rule: str, who: str | None = None) -> list[dict]:
    return [a for a in ds["alerts"] if a["rule_id"] == rule
            and (who is None or who in (a["src_user"], a["target_user"]) or who == a["src_ip"])]


def test_rules_valid_and_ran(ds) -> None:
    st = ds["stats"]
    assert st["errors"] == 0, st["error_messages"]
    assert st["rules"] == len(IDS)
    assert ds["ctx"].stats["profile"]["files_per_source"].keys() >= {
        "okta_json", "gws_reports_json", "gcp_audit_json", "m365_ual_json", "auth0_json", "duo_auth_json"}


@pytest.mark.parametrize("rule, pos, neg", [
    ("okta_password_spray", "203.0.113.9", "203.0.113.10"),          # 10 users vs 5 users from one IP
    ("okta_mfa_push_fatigue", "p_push", "n_push"),                    # 6 prompts / 3 denies vs 3 prompts
    ("okta_new_idp", "p_idp", "n_idp"),
    ("okta_policy_weakened", "p_pol", "n_pol"),
    ("okta_api_token_created", "p_tok", "n_tok"),
    ("gws_password_spray", "203.0.113.20", "n_none"),
    ("gws_suspicious_login", "p_susp", "n_susp"),
    ("gws_2sv_disabled", "p_2sv", "n_2sv"),
    ("gws_oauth_broad_scope", "p_oauth", "n_oauth"),
    ("gws_domain_wide_delegation", "p_dwd", "n_dwd"),
    ("m365_inbox_hiding_rule", "p_hide", "n_hide"),
    ("m365_audit_disabled", "p_audit", "n_audit"),
    ("m365_mass_download", "p_dl", "n_dl"),                           # 80 files vs 30 (history 5 / day)
    ("m365_external_sharing", "p_share", "n_share"),                  # anonymous links vs an internal invite
    ("auth0_credential_stuffing", "203.0.113.30", "203.0.113.31"),
    ("auth0_mfa_push_fatigue", "p_a0push", "n_a0push"),
    ("duo_push_fatigue", "p_duo", "n_duo"),
    ("duo_user_marked_fraud", "p_fraud", "n_fraud"),
])
def test_positive_and_near_miss(ds, rule: str, pos: str, neg: str) -> None:
    assert of(ds, rule, pos), f"{rule}: no alert for {pos}"
    assert not of(ds, rule, neg), f"{rule}: near miss {neg} alerted: {of(ds, rule, neg)}"


def test_no_spray_from_single_user_brute_force(ds) -> None:
    assert not of(ds, "okta_password_spray", "203.0.113.11")


@pytest.mark.parametrize("rule, pos, neg, hi, lo", [
    ("okta_session_hijack", "p_hij", "n_roam", 85, 35),               # other UA vs same browser roaming
    ("okta_admin_grant", "p_grant", "n_grant", 85, 60),               # super admin vs help desk
    ("gws_admin_role_grant", "p_gadm", "n_gadm", 85, 60),             # Cloud Logging shape vs Reports shape
    ("m365_inbox_forward_rule", "p_fwd", "n_fwd", 85, 45),            # external vs internal forwarding
    ("m365_inbox_forward_rule", "p_fwd2", "n_fwd", 85, 45),           # OfficeActivity Parameters string
    ("m365_inbox_forward_rule", "p_csvfwd", "n_fwd", 85, 45),         # Purview CSV AuditData
    ("m365_mailbox_delegation", "p_deleg", "n_deleg", 70, 55),
    ("m365_admin_role_grant", "p_m3role", "n_m3role", 85, 55),
    ("m365_oauth_consent", "p_consent", "n_consent", 75, 50),
])
def test_severity_tiers(ds, rule: str, pos: str, neg: str, hi: int, lo: int) -> None:
    assert max(a["severity"] for a in of(ds, rule, pos)) == hi
    assert max(a["severity"] for a in of(ds, rule, neg)) == lo


def test_secondary_valid_account_and_followups(ds) -> None:
    spray = of(ds, "okta_password_spray", "u3")
    assert any(a["technique_id"] == "T1078" and a["tactic"] == "Initial Access" and a["severity"] == 85 for a in spray)
    assert any(a["technique_id"] == "T1078" for a in of(ds, "gws_password_spray", "u5"))
    assert any(a["technique_id"] == "T1078" for a in of(ds, "auth0_credential_stuffing", "u7"))
    assert any(a["technique_id"] == "T1078" for a in of(ds, "okta_mfa_push_fatigue", "p_push"))
    assert any(a["technique_id"] == "T1078" for a in of(ds, "duo_push_fatigue", "p_duo"))
    assert max(a["severity"] for a in of(ds, "okta_mfa_factor_change", "p_push")) == 80
    assert not of(ds, "m365_inbox_forward_rule", "n_fwd0")            # clearing a forward is not a forward
    # the daily sync client volume is the user's own baseline: only the cold-start days may alert (capped at 30)
    assert all(a["severity"] <= 30 for a in of(ds, "m365_mass_download", "n_sync"))
    late = [a for a in of(ds, "m365_mass_download", "n_sync") if a["ts_ms"] >= T0 + 3 * DAY]
    assert not late, late
    assert max(a["severity"] for a in of(ds, "auth0_credential_stuffing", "u1")) >= 60   # limit_mu


def test_users_normalised_like_cloud_users(ds) -> None:
    """alice@corp.example in every IdP is user `alice`, the same entity Entra / AWS SSO / GCP rows get."""
    for a in ds["alerts"]:
        for u in (a["src_user"],):
            assert u is None or "@" not in u, a
