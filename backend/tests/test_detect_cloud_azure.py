"""Azure track rules (config/rules_cloud.yaml az_kv_* / az_graph_* / az_idp_* / az_sp_*) and the P0-3 export shapes
through the real ingest + cloud_ev: Key Vault data plane, Microsoft Graph activity, Entra ID Protection, service-
principal sign-ins, the AAD* string-encoded columns, and the Activity / AuditLogs diagnostic export reaching the
existing Azure rules. Ten quiet days first (baselines past cold start), attack day = day 10. Positive actors p_*,
near-miss actors n_* (one each per rule)."""

from __future__ import annotations

import itertools
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from .conftest import run_ingest
from .test_detect_cloud import run, subset

TENANT = "4d5f1c2e-0000-4000-8000-0000000000a1"
SUB = "9b0e6a51-0000-4000-8000-0000000000b2"
AAD = f"/tenants/{TENANT}/providers/Microsoft.aadiam"
T0 = int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp() * 1000)
DAY, HOUR, MIN = 86_400_000, 3_600_000, 60_000
D10 = T0 + 10 * DAY + 9 * HOUR
UPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
_ids = itertools.count(1)
RULES = {"az_kv_secret_sweep", "az_kv_forbidden_then_get", "az_kv_purge", "az_kv_key_destroy", "az_kv_backup_export",
         "az_graph_enum_burst", "az_graph_mail_read", "az_graph_app_credential", "az_graph_token_replay",
         "az_idp_risky_signin", "az_idp_password_spray", "az_idp_token_anomaly", "az_idp_mfa_fraud", "az_idp_inbox_rule",
         "az_sp_signin_new_network", "az_entra_privileged_role", "az_diag_or_defender_off"}


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def kv(ts: int, op: str, who: str, obj: str = "", vault: str = "kv-prod-app", ip: str = "198.51.100.7",
       status: int = 200) -> dict[str, Any]:
    """Key Vault diagnostic export row; who = UPN (user) or a GUID-like app id."""
    claim = {UPN: who} if "@" in who else {"appid": who}
    uri = f"https://{vault}.vault.azure.net/{obj}" if obj else f"https://{vault}.vault.azure.net/secrets"
    return {"time": iso(ts), "category": "AuditEvent", "operationName": op, "resultType": "Success",
            "resultSignature": {200: "OK", 204: "NoContent", 403: "Forbidden"}[status], "callerIpAddress": ip,
            "correlationId": f"kv-{next(_ids)}", "identity": {"claim": claim},
            "properties": {"id": uri, "clientInfo": "azsdk-python-keyvault-secrets/4.8.0", "httpStatusCode": status,
                           "requestUri": uri + "?api-version=7.4", "isAccessPolicyMatch": status == 200},
            "resourceId": f"/SUBSCRIPTIONS/{SUB}/RESOURCEGROUPS/RG-SEC/PROVIDERS/MICROSOFT.KEYVAULT/VAULTS/{vault.upper()}"}


def gr(ts: int, who: str, path: str, method: str = "GET", ip: str = "198.51.100.7", code: int = 200,
       ua: str = "Mozilla/5.0", tok: str | None = None, sp: bool = False) -> dict[str, Any]:
    return {"TenantId": TENANT, "TimeGenerated": iso(ts), "RequestId": f"r-{next(_ids)}", "ApiVersion": "v1.0",
            "RequestMethod": method, "ResponseStatusCode": code, "IPAddress": ip, "UserAgent": ua,
            "RequestUri": f"https://graph.microsoft.com/v1.0{path}", "SignInActivityId": tok or f"t-{next(_ids)}",
            "AppId": "app-1", "UserId": "" if sp else who, "ServicePrincipalId": who if sp else "",
            "TokenIssuedAt": iso(ts - MIN), "_ResourceId": AAD, "Type": "MicrosoftGraphActivityLogs"}


def risk(ts: int, upn: str, rtype: str, level: str = "high", state: str = "atRisk",
         ip: str = "203.0.113.160") -> dict[str, Any]:
    return {"TenantId": TENANT, "TimeGenerated": iso(ts + 30 * MIN), "Id": f"rd-{next(_ids)}", "RiskEventType": rtype,
            "RiskState": state, "RiskLevel": level, "RiskDetail": "none", "Source": "IdentityProtection",
            "DetectionTimingType": "offline", "IpAddress": ip, "ActivityDateTime": iso(ts), "UserPrincipalName": upn,
            "OperationName": "User Risk Detection", "Category": "UserRiskEvents", "ResourceId": AAD,
            "Type": "AADUserRiskEvents"}


def si(ts: int, who: str, ip: str, *, tok: str | None = None, sp: bool = False, code: str = "0",
       loc: str | None = None) -> dict[str, Any]:
    """Sign-in row; sp=True -> AADServicePrincipalSignInLogs, loc -> LocationDetails as a JSON string (AAD* tables)."""
    d: dict[str, Any] = {"TenantId": TENANT, "TimeGenerated": iso(ts), "OperationName": "Sign-in activity",
                         "ResultType": code, "IPAddress": ip, "ConditionalAccessStatus": "notApplied",
                         "UniqueTokenIdentifier": tok or f"tk-{next(_ids)}", "ResourceId": AAD}
    if sp:
        d.update(ServicePrincipalName=who, ServicePrincipalId=f"spid-{who}", Category="ServicePrincipalSignInLogs")
    else:
        d.update(UserPrincipalName=who, Category="NonInteractiveUserSignInLogs", AppDisplayName="Microsoft Office")
    if loc:
        d["LocationDetails"] = loc
    return d


def export_rows(ts: int) -> list[dict[str, Any]]:
    """P0-3: AuditLogs export (role add) and Activity Log export (diagnostic setting deleted, claims UPN)."""
    role = {"time": iso(ts), "resourceId": AAD, "operationName": "Add member to role", "category": "AuditLogs",
            "tenantId": TENANT, "resultSignature": "None", "correlationId": f"c-{next(_ids)}",
            "properties": {"id": f"Dir_{next(_ids)}", "category": "RoleManagement", "result": "success",
                           "activityDisplayName": "Add member to role", "loggedByService": "Core Directory",
                           "initiatedBy": {"user": {"userPrincipalName": "p_export@corp.example",
                                                    "ipAddress": "203.0.113.180"}},
                           "targetResources": [{"id": "u-9", "type": "User", "userPrincipalName": "p_newadmin@corp.example",
                                                "modifiedProperties": [{"displayName": "Role.DisplayName",
                                                                        "newValue": "\"Global Administrator\""}]}]}}
    diag = f"/SUBSCRIPTIONS/{SUB}/RESOURCEGROUPS/RG-DATA/PROVIDERS/MICROSOFT.STORAGE/STORAGEACCOUNTS/FIN/PROVIDERS/" \
           "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/TO-SENTINEL"
    off = {"time": iso(ts + 5 * MIN), "resourceId": diag, "operationName": "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
           "category": "Administrative", "resultType": "Success", "callerIpAddress": "203.0.113.180",
           "correlationId": f"c-{next(_ids)}", "identity": {"claims": {"name": "P Export", UPN: "p_export@corp.example"}},
           "properties": {"statusCode": "OK"}}
    return [role, off]


def history() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {"kv": [], "gr": [], "risk": [], "si": [], "aud": []}
    enum = ["/users", "/groups", "/servicePrincipals", "/applications", "/directoryRoles", "/devices"]
    for d in range(10):
        base = T0 + d * DAY
        for h in range(0, 24, 3):
            for s in ("db-password", "api-key"):
                out["kv"].append(kv(base + h * HOUR, "SecretGet", "mi-web-app", f"secrets/{s}", ip="10.20.1.4"))
            for who, ip in (("ci-deployer", "198.51.100.41"), ("n_sp", "198.51.100.42")):
                for k in range(3):
                    out["si"].append(si(base + h * HOUR + k * MIN, who, ip, sp=True))
        out["kv"].append(kv(base + 4 * HOUR, "SecretList", "asharma@corp.example", vault="kv-finance", ip="192.0.2.10"))
        for i in range(60):                          # daily inventory app: 6 object types, 60 pages
            out["gr"].append(gr(base + 2 * HOUR + i * 5000, "inv-1", f"{enum[i % 6]}?$skiptoken={i}", sp=True,
                                ua="inventory/2.0"))
        for i in range(8):                           # nightly mail backup app
            out["gr"].append(gr(base + 1 * HOUR + i * MIN, "mb-1", f"/users/user{i}@corp.example/messages", sp=True,
                                ua="mailbackup/1.4"))
        out["gr"].append(gr(base + 9 * HOUR, "u-alice", "/me"))
    return out


def attacks() -> dict[str, list[dict[str, Any]]]:
    t = D10
    out: dict[str, list[dict[str, Any]]] = {"kv": [], "gr": [], "risk": [], "si": [], "aud": []}
    k, g, r, s = out["kv"], out["gr"], out["risk"], out["si"]
    k += [kv(t + i * 10_000, "SecretGet", "p_kv@corp.example", f"secrets/s{i}", ip="203.0.113.141") for i in range(10)]
    k += [kv(t + i * 10_000, "SecretGet", "n_kv@corp.example", f"secrets/s{i}") for i in range(5)]
    k += [kv(t + HOUR + i * 10_000, "SecretGet", "p_kvf-app", f"secrets/f{i}", vault="kv-finance", status=403)
          for i in range(5)]
    k.append(kv(t + HOUR + 10 * MIN, "SecretGet", "p_kvf-app", "secrets/db-password"))
    k += [kv(t + HOUR + i * 10_000, "SecretGet", "n_kvf-app", f"secrets/f{i}", vault="kv-finance", status=403)
          for i in range(2)]
    k.append(kv(t + HOUR + 10 * MIN, "SecretGet", "n_kvf-app", "secrets/db-password"))
    for i in range(3):
        k.append(kv(t + 2 * HOUR + i * MIN, "SecretDelete", "p_purge@corp.example", f"secrets/x{i}", status=200))
        k.append(kv(t + 2 * HOUR + i * MIN + 5000, "SecretPurge", "p_purge@corp.example", f"deletedsecrets/x{i}",
                    status=204))
        k.append(kv(t + 2 * HOUR + i * MIN, "SecretDelete", "n_purge@corp.example", f"secrets/y{i}"))
    k.append(kv(t + 3 * HOUR, "KeyDelete", "p_key@corp.example", "keys/cmk-storage"))
    k.append(kv(t + 3 * HOUR, "KeyGet", "n_key@corp.example", "keys/cmk-storage"))
    k += [kv(t + 4 * HOUR + i * MIN, "SecretBackup", "p_bak@corp.example", f"secrets/b{i}") for i in range(4)]
    k += [kv(t + 4 * HOUR + i * MIN, "SecretBackup", "n_bak@corp.example", f"secrets/b{i}") for i in range(2)]
    types = ["/users", "/groups", "/servicePrincipals", "/applications", "/directoryRoles"]
    g += [gr(t + i * 3000, "p-enum", f"{types[i % 5]}?page={i}", ip="203.0.113.141", ua="azurehound/v2.1.7")
          for i in range(50)]
    g += [gr(t + 2 * HOUR + i * 5000, "inv-1", f"/users?$skiptoken={i}", sp=True, ua="inventory/2.0")
          for i in range(60)]                        # usual inventory day (near miss: known source)
    g += [gr(t + i * 3000, "n-enum", f"{types[i % 3]}?page={i}") for i in range(30)]
    g += [gr(t + HOUR + i * MIN, "p-mail", f"/users/v{i}@corp.example/messages", sp=True, ip="203.0.113.170",
             ua="python-requests/2.31.0") for i in range(6)]
    g += [gr(t + HOUR + i * MIN, "mb-1", f"/users/user{i}@corp.example/messages", sp=True, ua="mailbackup/1.4")
          for i in range(8)]
    g += [gr(t + HOUR + i * MIN, "n-mail", "/users/n-mail/messages") for i in range(6)]
    g.append(gr(t + 2 * HOUR, "p-cred", "/applications/app-9/addPassword", method="POST", sp=True))
    g.append(gr(t + 2 * HOUR, "n-cred", "/applications/app-9/addPassword", method="POST", sp=True, code=403))
    s.append(si(t + 3 * HOUR, "p_tok@corp.example", "198.51.100.7", tok="TOK-P"))
    g.append(gr(t + 3 * HOUR + 5 * MIN, "p-tok", "/me/messages", ip="203.0.113.141", tok="TOK-P"))
    s.append(si(t + 3 * HOUR, "n_tok@corp.example", "198.51.100.8", tok="TOK-N"))
    g.append(gr(t + 3 * HOUR + 5 * MIN, "n-tok", "/me/messages", ip="198.51.100.9", tok="TOK-N"))
    s.append(si(t + 5 * HOUR, "ci-deployer", "203.0.113.150", sp=True))
    s.append(si(t + 5 * HOUR, "n_sp", "198.51.100.43", sp=True))
    s.append(si(t + 6 * HOUR, "p_loc@corp.example", "198.51.100.7",
                loc=json.dumps({"countryOrRegion": "NL", "geoCoordinates": {"latitude": 52.37, "longitude": 4.9}})))
    r += [risk(t, "p_idp@corp.example", "unfamiliarFeatures"),
          risk(t, "n_idp@corp.example", "unfamiliarFeatures", level="low", state="dismissed"),
          risk(t, "p_spray@corp.example", "passwordSpray", level="medium"),
          risk(t, "p_tokan@corp.example", "anomalousToken"),
          risk(t, "p_mfa@corp.example", "mfaFraud"), risk(t, "n_mfa@corp.example", "mfaFraud", state="dismissed"),
          risk(t, "p_inbox@corp.example", "suspiciousInboxForwarding", level="medium")]
    r.append({"TenantId": TENANT, "TimeGenerated": iso(t), "Id": "u-c", "RiskDetail": "adminConfirmedUserCompromised",
              "RiskLastUpdatedDateTime": iso(t), "RiskLevel": "high", "RiskState": "confirmedCompromised",
              "UserPrincipalName": "p_conf@corp.example", "OperationName": "Risky user", "Category": "RiskyUsers",
              "ResourceId": AAD, "Type": "AADRiskyUsers"})
    out["aud"] = export_rows(t + 7 * HOUR)
    return out


def write(raw: Path, parts: list[dict[str, list[dict[str, Any]]]]) -> None:
    raw.mkdir(parents=True, exist_ok=True)
    for name in ("kv", "gr", "risk", "si", "aud"):
        rows = [x for p in parts for x in p.get(name, [])]
        (raw / f"{name}.log").write_text("\n".join(json.dumps(x) for x in rows) + "\n", encoding="utf-8")


@pytest.fixture(scope="module")
def az(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("cloud_azure")
    write(tmp / "raw", [history(), attacks()])
    ctx = run_ingest(tmp / "raw", tmp)
    st, alerts = run(ctx.con, subset(ctx.cfg, RULES), tmp / "work", ctx.events_glob)
    yield {"ctx": ctx, "stats": st, "alerts": alerts}
    ctx.con.close()


def of(az: dict, rule: str, who: str) -> list[dict]:
    """Attack-day alerts of one rule for one identity (day-0 cold-start first-seen hits are capped context)."""
    return [a for a in az["alerts"] if a["rule_id"] == rule and who in (a["src_user"], a["target_user"])
            and a["ts_ms"] >= T0 + 10 * DAY]


def test_rules_ran_without_error(az) -> None:
    assert az["stats"]["errors"] == 0, az["stats"]["error_messages"]
    assert az["stats"]["rules"] == len(RULES)


@pytest.mark.parametrize("rule, pos, neg", [
    ("az_kv_secret_sweep", "p_kv", "n_kv"),
    ("az_kv_forbidden_then_get", "p_kvf-app", "n_kvf-app"),
    ("az_kv_purge", "p_purge", "n_purge"),
    ("az_kv_key_destroy", "p_key", "n_key"),
    ("az_kv_backup_export", "p_bak", "n_bak"),
    ("az_graph_enum_burst", "p-enum", "n-enum"),
    ("az_graph_mail_read", "p-mail", "n-mail"),
    ("az_graph_app_credential", "p-cred", "n-cred"),
    ("az_graph_token_replay", "p-tok", "n-tok"),
    ("az_sp_signin_new_network", "ci-deployer", "n_sp"),
    ("az_entra_privileged_role", "p_export", "nobody"),        # AuditLogs diagnostic export (P0-3)
    ("az_diag_or_defender_off", "p_export", "nobody"),         # Activity Log export, claims UPN (P0-3)
])
def test_positive_and_near_miss(az, rule: str, pos: str, neg: str) -> None:
    assert of(az, rule, pos), f"{rule}: no alert for {pos}"
    assert not of(az, rule, neg), f"{rule}: near miss {neg} alerted: {of(az, rule, neg)}"


def test_known_enumerator_and_mail_backup_stay_quiet(az) -> None:
    assert not of(az, "az_graph_enum_burst", "inv-1")
    assert not of(az, "az_graph_mail_read", "mb-1")
    (hit,) = [a for a in of(az, "az_graph_enum_burst", "p-enum") if a["severity"] >= 80]   # attack-tool user agent
    assert hit["src_ip"] == "203.0.113.141" and hit["technique_id"] == "T1087"


@pytest.mark.parametrize("rule, pos, neg, sev", [
    ("az_idp_risky_signin", "p_idp", "n_idp", 65), ("az_idp_password_spray", "p_spray", None, 60),
    ("az_idp_token_anomaly", "p_tokan", None, 75), ("az_idp_mfa_fraud", "p_mfa", "n_mfa", 75),
    ("az_idp_inbox_rule", "p_inbox", None, 65), ("az_idp_risky_signin", "p_conf", None, 80)])
def test_identity_protection_tiers(az, rule: str, pos: str, neg: str | None, sev: int) -> None:
    hits = of(az, rule, pos)
    assert hits and max(a["severity"] for a in hits) == sev, hits
    assert all(a["ts_ms"] == D10 for a in hits if pos != "p_conf")      # activity time, not detection time
    if neg:   # closed (dismissed / low) detections stay context: never seed, never add a tactic alone
        assert of(az, rule, neg) and max(a["severity"] for a in of(az, rule, neg)) <= 35


def test_kv_purge_burst_and_sequence_tiers(az) -> None:
    assert max(a["severity"] for a in of(az, "az_kv_purge", "p_purge")) == 80
    assert max(a["severity"] for a in of(az, "az_kv_forbidden_then_get", "p_kvf-app")) == 75
    assert max(a["severity"] for a in of(az, "az_kv_secret_sweep", "p_kv")) == 70


def test_aad_string_location_and_token_columns(az) -> None:
    con = az["ctx"].con
    cc, lat, tok = con.execute("SELECT cc, lat, si_tokid FROM cloud_ev WHERE actor = 'p_loc'").fetchone()
    assert (cc, round(lat, 2), tok is not None) == ("NL", 52.37, True)
    vault, kind, obj = con.execute("SELECT kv_vault, kv_kind, kv_obj FROM cloud_ev WHERE is_kv AND actor = 'p_kv' "
                                   "ORDER BY ts_ms LIMIT 1").fetchone()
    assert (vault, kind, obj) == ("kv-prod-app", "secrets", "s0")
    assert con.execute("SELECT count(*) FROM cloud_ev WHERE is_idp AND cloud = 'azure'").fetchone()[0] == 8
