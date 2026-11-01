"""Identity SaaS ingest (config/sources.yaml okta_json, gws_reports_json, m365_ual_json, auth0_json, duo_auth_json,
m365_purview_csv; Workspace Cloud Logging copy -> gcp_audit_json). Fixtures are made up (fixtures/cloud/identity),
one file per shape variant, copied under neutral names: routing is by content, never by file name."""

from __future__ import annotations

import shutil

import pytest

from .conftest import FIXTURES, accounting, query, run_ingest

FX = FIXTURES / "cloud" / "identity"
T0 = 1792807200000  # 2026-10-24T02:00:00Z
ORG = "4d5f1c2e-0000-4000-8000-0000000000a1"
# file -> (source_type, rows)
FILES = {"okta_bare.jsonl": ("okta_json", 4), "okta_eventbridge.jsonl": ("okta_json", 1),
         "gws_reports.jsonl": ("gws_reports_json", 3), "gws_cloudlogging.jsonl": ("gcp_audit_json", 2),
         "m365_mgmt.jsonl": ("m365_ual_json", 3), "m365_officeactivity.jsonl": ("m365_ual_json", 1),
         "m365_cloudappevents.jsonl": ("m365_ual_json", 1), "m365_purview.csv": ("m365_purview_csv", 2),
         "auth0.jsonl": ("auth0_json", 3), "auth0_stream.jsonl": ("auth0_json", 1), "duo.jsonl": ("duo_auth_json", 3),
         "gws_admin.csv": ("gws_admin_csv", 1)}


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("idsaas")
    raw = tmp / "raw"
    raw.mkdir()
    for i, name in enumerate(FILES):
        shutil.copy(FX / name, raw / f"part-{i}.log")
    c = run_ingest(raw, tmp)
    yield c
    c.con.close()


def rows(ctx, stype: str) -> list[dict]:
    return query(ctx, "SELECT * FROM events WHERE source_type = ? ORDER BY ts_ms, source_seq", [stype])


def by_sig(ctx, stype: str) -> dict[str, dict]:
    return {r["signature"]: r for r in rows(ctx, stype)}


def test_every_file_routed_and_fully_accounted(ctx) -> None:
    # an envelope file is unpacked in Stage 0 (cloud_unpack): its records are profiled as "<file>!/<part>"
    prof = {f["rel"].split("!/")[0]: f.get("source_type") for f in ctx.stats["profile"]["files"]}
    for i, (name, (stype, _)) in enumerate(FILES.items()):
        assert prof[f"part-{i}.log"] == stype, (name, prof[f"part-{i}.log"])
    want: dict[str, int] = {}
    for stype, n in FILES.values():
        want[stype] = want.get(stype, 0) + n
    acc = {k: v for k, v in accounting(ctx).items() if v["rows_in"]}
    assert set(acc) == set(want)
    for stype, n in want.items():
        assert acc[stype]["rows_in"] == acc[stype]["rows_ok"] == n, (stype, acc[stype])
        assert acc[stype]["dropped"] == 0
        assert all(r["ts_ok"] for r in rows(ctx, stype))


def test_okta_bare_and_eventbridge(ctx) -> None:
    ok, bad, grant, push, eb = rows(ctx, "okta_json")
    assert [r["ts_ms"] for r in (ok, bad, grant, push, eb)] == [T0, T0 + 1000, T0 + 2000, T0 + 3000, T0 + 4000]
    assert (ok["action"], ok["outcome"], ok["target_user"], ok["src_ip"], ok["host"], ok["signature"]) == \
        ("login_success", "success", "alice", "198.51.100.7", "corp.example", "user.session.start")
    assert (bad["action"], bad["outcome"], bad["target_user"], bad["src_ip"]) == \
        ("login_failed", "failure", "bob", "203.0.113.66")                 # Bob@Corp.Example -> bob
    assert (grant["action"], grant["outcome"], grant["src_user"], grant["signature"]) == \
        ("other", "success", "alice", "user.account.privilege.grant")
    assert (push["outcome"], push["src_user"]) == (None, "carol")           # CHALLENGE is no outcome
    # EventBridge envelope (detail lifted by Stage 0, or read through the detail.* aliases): DENY -> failure
    assert (eb["action"], eb["outcome"], eb["target_user"], eb["src_ip"]) == \
        ("login_failed", "failure", "dave", "203.0.113.70")
    assert eb["host"] in ("corp.example", "corp-dev-123")
    assert "mozilla" in ok["app"]


def test_gws_reports_and_cloud_logging(ctx) -> None:
    fail, ok, role = rows(ctx, "gws_reports_json")
    assert (fail["ts_ms"], fail["action"], fail["outcome"], fail["target_user"], fail["src_ip"], fail["host"],
            fail["app"]) == (T0, "login_failed", "failure", "bob", "203.0.113.66", "c03abc123", "login")
    assert (ok["action"], ok["outcome"], ok["target_user"]) == ("login_success", "success", "alice")
    assert (role["action"], role["outcome"], role["src_user"], role["signature"], role["app"]) == \
        ("other", None, "alice", "ASSIGN_ROLE", "admin")
    g = by_sig(ctx, "gcp_audit_json")
    lf, ar = g["google.login.LoginService.loginFailure"], g["google.admin.AdminService.assignRole"]
    assert (lf["host"], lf["src_user"], lf["src_ip"], lf["app"]) == \
        ("123456789", "bob", "203.0.113.66", "login.googleapis.com")      # logName fallback -> org id
    assert (ar["host"], ar["src_user"]) == ("123456789", "alice")
    (csv,) = rows(ctx, "gws_admin_csv")                                       # Admin console export
    assert (csv["ts_ms"], csv["src_user"], csv["src_ip"], csv["signature"]) == \
        (T0 + 7000, "alice", "203.0.113.5", "Assign role")


def test_m365_three_json_shapes(ctx) -> None:
    s = by_sig(ctx, "m365_ual_json")
    rule, dl, lf = s["New-InboxRule"], s["FileDownloaded"], s["UserLoginFailed"]
    assert (rule["ts_ms"], rule["src_user"], rule["src_ip"], rule["host"], rule["outcome"], rule["app"]) == \
        (T0, "alice", "203.0.113.5", ORG, "success", "exchange")            # naive CreationTime = UTC; ip:port
    assert rule["file_path"] == "corp.example/alice/fwd"
    assert (dl["src_ip"], dl["app"], dl["outcome"]) == ("2001:db8::5", "sharepoint", None)   # [v6]:port
    assert dl["file_path"].endswith("q3.xlsx")
    assert (lf["action"], lf["outcome"], lf["target_user"], lf["src_ip"]) == \
        ("login_failed", "failure", "bob", "203.0.113.66")                 # ::ffff: mapped v4
    mb = s["Set-Mailbox"]                                                     # OfficeActivity (Log Analytics)
    assert (mb["ts_ms"], mb["src_user"], mb["src_ip"], mb["host"], mb["app"], mb["outcome"]) == \
        (T0 + 3123, "alice", "203.0.113.5", ORG, "exchange", "success")
    an = s["AnonymousLinkCreated"]                                            # CloudAppEvents RawEventData
    assert (an["ts_ms"], an["src_user"], an["src_ip"], an["host"], an["app"]) == \
        (T0 + 4000, "alice", "203.0.113.5", ORG, "sharepoint")


def test_m365_purview_csv(ctx) -> None:
    r = rows(ctx, "m365_purview_csv")
    assert [(x["ts_ms"], x["src_user"], x["signature"]) for x in r] == \
        [(T0 + 5000, "alice", "New-InboxRule"), (T0 + 6000, "alice", "FileDownloaded")]
    # AuditData decoded (sources.yaml json_columns): tenant, client IP without its port, object
    assert [(x["host"], x["src_ip"]) for x in r] == [(ORG, "203.0.113.5"), (ORG, "203.0.113.5")]
    assert r[0]["outcome"] == "success" and r[1]["file_path"].endswith("a, b.xlsx")


def test_m365_purview_csv_auditdata_intact(ctx) -> None:
    r = rows(ctx, "m365_purview_csv")
    assert '"ForwardTo"' in r[0]["raw_line"]                                  # AuditData kept for the cloud rules
    assert "a, b.xlsx" in r[1]["raw_line"]                                    # quoted comma inside the JSON


def test_auth0_and_stream_shape(ctx) -> None:
    fp, s, rej, stream = rows(ctx, "auth0_json")
    assert (fp["action"], fp["outcome"], fp["target_user"], fp["src_ip"], fp["host"], fp["app"], fp["signature"]) == \
        ("login_failed", "failure", "bob", "203.0.113.66", "corp.us.auth0.com", "corp portal", "fp")
    assert (s["action"], s["outcome"], s["target_user"]) == ("login_success", "success", "alice")
    assert (rej["action"], rej["outcome"], rej["src_user"]) == ("other", "failure", "carol")
    assert (stream["ts_ms"], stream["action"], stream["target_user"], stream["host"]) == \
        (T0 + 3000, "login_failed", "dave", "corp.us.auth0.com")


def test_duo_auth(ctx) -> None:
    ok, fraud, timeout = rows(ctx, "duo_auth_json")
    assert (ok["ts_ms"], ok["action"], ok["outcome"], ok["target_user"], ok["src_ip"], ok["host"], ok["app"],
            ok["signature"]) == (T0, "login_success", "success", "alice", "198.51.100.7", "okta sso", "duo_push",
                                 "user_approved")
    assert (fraud["ts_ms"], fraud["action"], fraud["outcome"], fraud["signature"]) == \
        (T0 + 1000, "login_failed", "failure", "user_marked_fraud")        # epoch seconds only
    assert (timeout["outcome"], timeout["signature"]) == ("failure", "no_response")
