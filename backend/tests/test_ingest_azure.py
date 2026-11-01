"""Azure ingest shapes (gaps P0-3, P0-9, P0-13, P1-12 of reports/cloud/log_coverage.md): diagnostic-settings export
rows of the Activity Log / Entra AuditLogs / sign-ins, the AAD* sign-in tables (string-encoded JSON columns), Key
Vault AuditEvent (export, AZKVAuditLogs, AzureDiagnostics), Microsoft Graph activity logs (Log Analytics, export) and
Entra ID Protection risk detections / risky users (Log Analytics, Graph API, export). Fixtures are made up
(fixtures/cloud/azure/*.jsonl), one shape per file, routed by content (keys), never by file name."""

from __future__ import annotations

import shutil

import pytest

from .conftest import FIXTURES, accounting, query, run_ingest

FX = FIXTURES / "cloud" / "azure"
T0 = 1792807200000  # 2026-10-24T02:00:00Z
AAD = "/tenants/4d5f1c2e-0000-4000-8000-0000000000a1/providers/microsoft.aadiam"
SUB = "/subscriptions/9b0e6a51-0000-4000-8000-0000000000b2"
KV_PROD = f"{SUB}/resourcegroups/rg-sec/providers/microsoft.keyvault/vaults/kv-prod-app"
KV_FIN = f"{SUB}/resourcegroups/rg-sec/providers/microsoft.keyvault/vaults/kv-finance"
SP_APP = "11111111-2222-4333-8444-555555555555"
FILES = {"activity_export.jsonl": "azure_activity_json", "audit_export.jsonl": "azure_activity_json",
         "signin_export.jsonl": "azure_signin_json",
         "signin_aad.jsonl": "azure_signin_json", "keyvault_export.jsonl": "azure_keyvault_json",
         "keyvault_azkv.jsonl": "azure_keyvault_json", "keyvault_diag.jsonl": "azure_keyvault_json",
         "graph_la.jsonl": "azure_graph_json", "graph_export.jsonl": "azure_graph_json",
         "risk_la.jsonl": "azure_risk_json", "risk_api.jsonl": "azure_risk_json", "risk_export.jsonl": "azure_risk_json",
         "riskyusers_la.jsonl": "azure_risk_json"}


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("azure")
    raw = tmp / "raw"
    raw.mkdir()
    for name in FILES:
        shutil.copy(FX / name, raw / f"{name.split('.')[0]}.log")
    c = run_ingest(raw, tmp)
    yield c
    c.con.close()


def _rows_of(ctx, name: str) -> list[dict]:
    """Rows of one fixture, in file order (matched by the raw line text)."""
    lines = [ln for ln in (FX / name).read_text(encoding="utf-8").splitlines() if ln.strip()]
    rows = query(ctx, "SELECT * FROM events")
    out = []
    for ln in lines:
        hit = [r for r in rows if r["raw_line"] == ln]
        assert len(hit) == 1, (name, ln[:80])
        out.append(hit[0])
    return out


def test_every_file_routed_and_fully_accounted(ctx) -> None:
    acc = {k: v for k, v in accounting(ctx).items() if v["rows_in"]}
    want: dict[str, int] = {}
    for name, stype in FILES.items():
        want[stype] = want.get(stype, 0) + sum(1 for ln in (FX / name).read_text(encoding="utf-8").splitlines()
                                               if ln.strip())
    assert set(acc) == set(want), acc
    for stype, n in want.items():
        assert acc[stype]["rows_in"] == acc[stype]["rows_ok"] == n, (stype, acc[stype])
        assert acc[stype]["dropped"] == 0
    for name, stype in FILES.items():
        assert {r["source_type"] for r in _rows_of(ctx, name)} == {stype}, name
        assert all(r["ts_ok"] for r in _rows_of(ctx, name)), name


def test_activity_and_auditlogs_export_keep_user_target_outcome(ctx) -> None:
    ra, add, upd, sp = _rows_of(ctx, "activity_export.jsonl")
    assert ra["ts_ms"] == T0 + 123
    # the claims UPN wins over claims.name (the display name)
    assert (ra["src_user"], ra["src_ip"], ra["outcome"], ra["signature"], ra["host"]) == \
        ("dsingh", "203.0.113.180", "success", "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
         f"{SUB}/providers/microsoft.authorization/roleassignments/ra-1")
    assert (add["action"], add["outcome"], add["src_user"], add["target_user"], add["src_ip"], add["host"]) == \
        ("group_member_added", "success", "dsingh", "backdoor.admin", "203.0.113.180", AAD)
    assert (upd["outcome"], upd["src_user"], upd["signature"]) == \
        ("failure", "ci-deployer", "Update application - Certificates and secrets management")
    assert (sp["src_user"], sp["outcome"], sp["src_ip"]) == (SP_APP, None, "198.51.100.41")   # appid claim, Start
    # an AuditLogs-only export file has no top-level callerIpAddress: routed by its properties.* keys
    (role,) = _rows_of(ctx, "audit_export.jsonl")
    assert (role["outcome"], role["src_user"], role["target_user"], role["src_ip"], role["signature"], role["host"]) == \
        ("success", "dsingh", "helpdesk.temp", "203.0.113.180", "Add member to role", AAD)


def test_signin_export_and_aad_tables(ctx) -> None:
    usr, spx = _rows_of(ctx, "signin_export.jsonl")
    assert (usr["ts_ms"], usr["action"], usr["outcome"], usr["target_user"], usr["src_ip"], usr["host"], usr["app"]) == \
        (T0 + 123, "login_success", "success", "dsingh", "203.0.113.180", AAD, "azure portal")
    assert (spx["action"], spx["outcome"], spx["target_user"], spx["src_ip"]) == \
        ("login_failed", "failure", "ci-deployer", "203.0.113.150")
    ni, sp, mi = _rows_of(ctx, "signin_aad.jsonl")
    assert (ni["action"], ni["target_user"], ni["src_ip"], ni["host"]) == \
        ("login_success", "mjoshi", "198.51.100.106", AAD)
    assert (sp["action"], sp["target_user"], sp["src_ip"]) == ("login_success", "ci-deployer", "198.51.100.41")
    assert (mi["action"], mi["target_user"], mi["src_ip"]) == ("login_success", "mi-payroll-web", None)


def test_keyvault_three_shapes(ctx) -> None:
    get_ok, get_denied = _rows_of(ctx, "keyvault_export.jsonl")
    assert (get_ok["ts_ms"], get_ok["action"], get_ok["outcome"], get_ok["src_user"], get_ok["src_ip"],
            get_ok["signature"], get_ok["host"], get_ok["file_path"]) == \
        (T0 + 123, "other", "success", "mjoshi", "203.0.113.141", "SecretGet", KV_PROD,
         "https://kv-prod-app.vault.azure.net/secrets/db-password/0123abcd")
    assert (get_denied["outcome"], get_denied["src_user"], get_denied["host"]) == ("failure", SP_APP, KV_FIN)
    purge, key = _rows_of(ctx, "keyvault_azkv.jsonl")
    assert (purge["signature"], purge["outcome"], purge["src_user"], purge["host"], purge["file_path"]) == \
        ("SecretPurge", "success", SP_APP, KV_PROD, "https://kv-prod-app.vault.azure.net/deletedsecrets/db-password")
    assert (key["signature"], key["src_user"], key["src_ip"]) == \
        ("KeyGet", "22222222-3333-4444-8555-666666666666", "10.20.1.4")
    lst, kdel = _rows_of(ctx, "keyvault_diag.jsonl")
    assert (lst["signature"], lst["outcome"], lst["src_user"], lst["src_ip"], lst["host"], lst["file_path"]) == \
        ("SecretList", "success", "asharma", "192.0.2.10", KV_FIN, "https://kv-finance.vault.azure.net/secrets")
    assert (kdel["signature"], kdel["outcome"], kdel["src_user"], kdel["src_ip"]) == \
        ("KeyDelete", "success", SP_APP, "203.0.113.150")


def test_graph_activity_two_shapes(ctx) -> None:
    enum, addpw = _rows_of(ctx, "graph_la.jsonl")
    assert (enum["ts_ms"], enum["outcome"], enum["src_user"], enum["src_ip"], enum["signature"], enum["host"]) == \
        (T0 + 250, "success", "5e1a0001-0000-4000-8000-0000000000u3", "203.0.113.141", "GET", AAD)
    assert enum["file_path"].startswith("https://graph.microsoft.com/v1.0/users?")
    assert (addpw["outcome"], addpw["src_user"], addpw["signature"]) == ("failure", "sp-9", "POST")
    (mail,) = _rows_of(ctx, "graph_export.jsonl")
    assert (mail["ts_ms"], mail["outcome"], mail["src_user"], mail["src_ip"], mail["signature"], mail["host"]) == \
        (T0, "success", "sp-9", "203.0.113.170", "GET", AAD)


def test_risk_detections_and_risky_users(ctx) -> None:
    spray, safe, sp = _rows_of(ctx, "risk_la.jsonl")
    # the risky ACTIVITY time (not the offline detection / ingestion time) places the event on the attack path
    assert (spray["ts_ms"], spray["signature"], spray["src_user"], spray["src_ip"], spray["host"], spray["app"],
            spray["vendor_severity"]) == \
        (T0, "passwordSpray", "nbose", "203.0.113.160", AAD, "identityprotection", "high")
    assert (safe["signature"], safe["src_user"], safe["vendor_severity"]) == ("unfamiliarFeatures", "vreddy", "low")
    assert (sp["signature"], sp["src_user"]) == ("investigationsThreatIntelligence", "ci-deployer")
    (fraud,) = _rows_of(ctx, "risk_api.jsonl")
    assert (fraud["ts_ms"], fraud["signature"], fraud["src_user"], fraud["src_ip"]) == \
        (T0, "mfaFraud", "nbose", "203.0.113.160")
    (tok,) = _rows_of(ctx, "risk_export.jsonl")
    assert (tok["ts_ms"], tok["signature"], tok["src_user"], tok["host"]) == (T0, "anomalousToken", "mjoshi", AAD)
    conf, rem = _rows_of(ctx, "riskyusers_la.jsonl")
    assert (conf["ts_ms"], conf["signature"], conf["src_user"], conf["vendor_severity"]) == \
        (T0, "Risky user", "nbose", "high")
    assert rem["src_user"] == "rnair"


def test_no_label_keys_leak(ctx) -> None:
    for r in query(ctx, "SELECT raw_line FROM events"):
        assert '"threat"' not in r["raw_line"] and '"labels_extra"' not in r["raw_line"]
