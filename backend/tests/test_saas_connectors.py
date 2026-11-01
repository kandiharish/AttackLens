"""P0-16 pull connectors okta, m365_ual and gws_reports against tools/mock_saas.py on a free 127.0.0.1 port (no real
network). Each test checks exact accounting (pulled = written + skipped + failed), every seeded record spooled once
in the vendor's native JSON, the checkpoint (a second cycle writes nothing), the vendor paging / auth / rate-limit
rules the mock enforces, and that no secret value reaches the spool, state or error text.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from attacklens import config, httpc
from attacklens import integrations as ig

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
import mock_saas as msaas  # noqa: E402
import mock_saas_seed as sseed  # noqa: E402

OKTA_TOKEN = "00Okta-SSWS-token-7f3c1a"
M365_SECRET = "M365-client-secret-2b9d"
M365_CLIENT = "m365-app-0001"
GWS_ADMIN = f"{sseed.ADMIN}@{sseed.DOMAIN}"
GWS_EMAIL = "attacklens-gws@corp-prod-1234.iam.gserviceaccount.com"
DAY = 86_400_000


@pytest.fixture(scope="module")
def base_cfg() -> dict[str, Any]:
    return config.load_config()


def make_cfg(base: dict[str, Any], tmp: Path, source: str, **over: Any) -> dict[str, Any]:
    cfg = copy.deepcopy(base)
    ic = cfg["integrations"]
    ic["spool"].update(events_dir=str(tmp / "spool" / "events"), alerts_dir=str(tmp / "spool" / "alerts"),
                       state_dir=str(tmp / "state"), status_file=str(tmp / "state" / "status.json"))
    ic["connectors"][source].update(enabled=True, **over)
    return cfg


def spooled(tmp: Path, folder: str) -> list[dict[str, Any]]:
    root = tmp / "spool" / "events"
    out = []
    for p in sorted(root.rglob("*")) if root.exists() else []:
        if p.is_file() and not p.name.startswith("."):
            assert p.parent.name == folder, p
            out += [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln]
    return out


def accounted(st: dict[str, Any]) -> None:
    assert st["pulled"] == st["written"] + st["skipped"] + st["failed"], st
    assert st["skipped"] == sum(st["skipped_reasons"].values()) and st["failed"] == sum(st["failed_reasons"].values())


def no_leak(tmp: Path, *secrets: str) -> None:
    text = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in tmp.rglob("*") if p.is_file())
    assert not [s for s in secrets if s in text], "secret value written to spool / state"


def connector(source: str, cfg: dict[str, Any], since_ms: int | None = None):
    from attacklens import connectors
    return connectors.get(source, cfg, "events", since_ms)


def rsa_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


# ============================================================================= Okta
def okta_cfg(base, tmp, m, monkeypatch, **over):
    monkeypatch.setenv("AL_T_OKTA", OKTA_TOKEN)
    over = {"page_size": 7, "retries": 2, **over}
    return make_cfg(base, tmp, "okta", base_url=m.url, token_env="AL_T_OKTA", **over)


def test_okta_ssws_link_next_paging_and_checkpoint(base_cfg, tmp_path, monkeypatch) -> None:
    with msaas.MockSaaS(okta_token=OKTA_TOKEN) as m:
        cfg = okta_cfg(base_cfg, tmp_path, m, monkeypatch)
        st = connector("okta", cfg).cycle()
        again = connector("okta", cfg).cycle()
        stats = dict(m.stats)
    accounted(st)
    n = len(m.seed.okta)
    assert st["ok"] and st["written"] == n and st["pulled"] == n, st
    assert stats["okta_pages"] >= -(-n // 7) and stats["okta_rows"] == n + again["pulled"]
    docs = spooled(tmp_path, "okta")
    assert sorted(d["uuid"] for d in docs) == sorted(e["uuid"] for e in m.seed.okta)
    assert docs == sorted(docs, key=lambda d: d["published"])                 # sortOrder=ASCENDING
    assert all(d["severity"] in ("INFO", "WARN") and "eventType" in d for d in docs)   # native LogEvent kept
    assert again["ok"] and again["written"] == 0, again                        # checkpoint (+ overlap dedupe)
    no_leak(tmp_path, OKTA_TOKEN)


def test_okta_429_waits_for_reset_and_low_remaining_waits_first(base_cfg, tmp_path, monkeypatch) -> None:
    for min_remaining, want_429 in ((-1, True), (0, False)):                    # -1: never wait before a call
        tmp = tmp_path / f"r{min_remaining}"
        with msaas.MockSaaS(okta_token=OKTA_TOKEN, okta_rate_limit=2, okta_rate_window_s=1.0) as m:
            cfg = okta_cfg(base_cfg, tmp, m, monkeypatch, page_size=20, rate_limit_min_remaining=min_remaining,
                           max_rate_wait_s=3)
            c = connector("okta", cfg)
            st = c.cycle()
            got_429 = m.stats["okta_429"]
        accounted(st)
        assert st["ok"] and st["written"] == len(m.seed.okta), (min_remaining, st)
        assert (got_429 > 0) == want_429 and c.gate.waits, (min_remaining, got_429, c.gate.waits)
        assert all(w <= 3 for w in c.gate.waits)


def test_okta_oauth_private_key_jwt_with_one_line_pem(base_cfg, tmp_path, monkeypatch) -> None:
    pytest.importorskip("cryptography")
    pem = rsa_pem().strip().replace("\n", "\\n")                                # how the UI secret store keeps it
    monkeypatch.setenv("AL_T_OKTA_KEY", pem)
    with msaas.MockSaaS(okta_token=OKTA_TOKEN, okta_client_id="0oaMockService1") as m:
        cfg = make_cfg(base_cfg, tmp_path, "okta", base_url=m.url, token_env=None, client_id="0oaMockService1",
                       private_key_env="AL_T_OKTA_KEY")
        st = connector("okta", cfg).cycle()
        tokens = m.stats["token_okta"]
    assert st["ok"] and st["written"] == len(m.seed.okta), st
    assert tokens == 1
    no_leak(tmp_path, pem[40:80])


def test_okta_bad_token_and_foreign_next_link(base_cfg, tmp_path, monkeypatch) -> None:
    from attacklens.connectors import saas_http
    with msaas.MockSaaS(okta_token="the-real-one") as m:
        st = connector("okta", okta_cfg(base_cfg, tmp_path, m, monkeypatch)).cycle()
    assert not st["ok"] and "okta: HTTP 401" in st["error"] and "E0000011" in st["error"], st
    assert OKTA_TOKEN not in st["error"]
    sent: list[tuple[str, dict[str, str]]] = []

    def fake(method, url, headers, *a, **k):
        sent.append((url, headers))
        return [], {"link": '<https://evil.example/api/v1/logs?after=x>; rel="next"'}
    monkeypatch.setattr(saas_http, "get_json", fake)
    cfg = make_cfg(base_cfg, tmp_path / "b", "okta", base_url="https://corp.okta.example", token_env="AL_T_OKTA")
    st = connector("okta", cfg).cycle()
    assert st["ok"] and len(sent) == 1                                         # empty page: stop, never follow
    monkeypatch.setattr(saas_http, "get_json", lambda *a, **k: ([{"uuid": "u1", "published": ig.iso_ms(
        ig.now_ms() - 3_600_000)}], {"link": '<https://evil.example/api/v1/logs?after=x>; rel="next"'}))
    st = connector("okta", make_cfg(base_cfg, tmp_path / "c", "okta", base_url="https://corp.okta.example",
                                    token_env="AL_T_OKTA")).cycle()
    assert not st["ok"] and "another host" in st["error"], st


# ============================================================================= Microsoft 365
def m365_cfg(base, tmp, m, monkeypatch, **over):
    monkeypatch.setenv("AL_T_M365", M365_SECRET)
    return make_cfg(base, tmp, "m365_ual", base_url=m.url, login_url=m.url, tenant_id=sseed.TENANT,
                    tenant_id_env=None, client_id=M365_CLIENT, client_id_env=None, client_secret_env="AL_T_M365",
                    **over)


def test_m365_starts_subscriptions_pages_next_page_uri_blobs_in_created_order(base_cfg, tmp_path, monkeypatch) -> None:
    with msaas.MockSaaS(m365_client_id=M365_CLIENT, m365_secret=M365_SECRET, m365_page_size=2) as m:
        m.subscriptions["Audit.Exchange"] = "enabled"                         # one already on: not started again
        cfg = m365_cfg(base_cfg, tmp_path, m, monkeypatch)
        st = connector("m365_ual", cfg).cycle()
        again = connector("m365_ual", cfg).cycle()
        stats, subs, pubs = dict(m.stats), dict(m.subscriptions), set(m.publishers)
    accounted(st)
    n = sseed.counts(m.seed)["m365_ual"]
    assert st["ok"] and st["written"] == n and st["pulled"] == n, st
    assert stats["m365_start"] == 3 and set(subs) == set(sseed.CONTENT_TYPES), stats
    assert stats["m365_list"] > len(sseed.CONTENT_TYPES)                       # NextPageUri followed
    assert pubs == {sseed.TENANT}                                              # PublisherIdentifier = tenant
    docs = spooled(tmp_path, "m365_ual")
    assert sorted(d["Id"] for d in docs) == sorted(r["Id"] for bl in m.seed.m365.values() for b in bl
                                                   for r in b["records"])
    rule = next(d for d in docs if d["Operation"] == "New-InboxRule")
    assert rule["Workload"] == "Exchange" and rule["Parameters"][1]["Value"] == "drop@exfil.example"
    assert again["ok"] and again["written"] == 0 and stats["m365_start"] == 3, again
    no_leak(tmp_path, M365_SECRET)


def test_m365_window_sliced_24h_and_clamped_to_7_days(base_cfg, tmp_path, monkeypatch) -> None:
    with msaas.MockSaaS(m365_secret=M365_SECRET) as m:                        # the mock refuses > 24 h / > 7 days
        cfg = m365_cfg(base_cfg, tmp_path, m, monkeypatch)
        st = connector("m365_ual", cfg, ig.now_ms() - 10 * DAY).cycle()
        lists = m.stats["m365_list"]
    assert st["ok"] and st["written"] == sseed.counts(m.seed)["m365_ual"], st
    assert lists >= 7 * len(sseed.CONTENT_TYPES)                               # 7 day slices x 4 content types


def test_m365_auto_start_off_names_the_type_and_af20024_is_fine(base_cfg, tmp_path, monkeypatch) -> None:
    from attacklens.connectors import m365_ual
    with msaas.MockSaaS(m365_secret=M365_SECRET) as m:
        cfg = m365_cfg(base_cfg, tmp_path, m, monkeypatch, auto_start_subscriptions=False)
        st = connector("m365_ual", cfg).cycle()
        assert not st["ok"] and "no enabled subscription for Audit.AzureActiveDirectory" in st["error"], st
        c = connector("m365_ual", m365_cfg(base_cfg, tmp_path / "b", m, monkeypatch))
        real = c._call

        def stale_list(method: str, url: str):                                # the list says off, start says on
            if "subscriptions/list" in url:
                return [], {}
            if "subscriptions/start" in url:
                m.subscriptions.update({t: "enabled" for t in sseed.CONTENT_TYPES})
            return real(method, url)
        c._call = stale_list
        m.subscriptions["Audit.General"] = "enabled"
        c.ensure_subscriptions(list(sseed.CONTENT_TYPES))                       # AF20024 swallowed
    with pytest.raises(ValueError, match="unknown content type"):
        m365_ual.content_types("Audit.Bogus")
    with pytest.raises(httpc.HttpError, match="another host"):
        c._call("GET", "https://evil.example/api/v1.0/x/activity/feed/audit/1")


# ============================================================================= Google Workspace
def gws_cfg(base, tmp, m, monkeypatch, admin: str = GWS_ADMIN, **over):
    key = json.dumps({"type": "service_account", "project_id": "corp-prod-1234", "private_key_id": "k1",
                      "private_key": rsa_pem(), "client_email": GWS_EMAIL, "client_id": "1",
                      "token_uri": f"{m.url}/token"})
    monkeypatch.setenv("AL_T_GWS", key)
    return make_cfg(base, tmp, "gws_reports", base_url=m.url, service_account_json_env="AL_T_GWS",
                    delegated_admin=admin, page_size=5, **over), key


def test_gws_dwd_subject_slices_and_page_tokens(base_cfg, tmp_path, monkeypatch) -> None:
    pytest.importorskip("cryptography")
    with msaas.MockSaaS(gws_client_email=GWS_EMAIL, gws_admins=(GWS_ADMIN,)) as m:
        cfg, key = gws_cfg(base_cfg, tmp_path, m, monkeypatch)
        cfg["integrations"]["connectors"]["gws_reports"]["events"]["window"] = "6h"
        st = connector("gws_reports", cfg).cycle()
        again = connector("gws_reports", cfg).cycle()
        stats = dict(m.stats)
    accounted(st)
    n = sseed.counts(m.seed)["gws_reports"]
    assert st["ok"] and st["written"] == n, st
    assert stats["token_gws"] == 2 and stats["gws_pages"] > 4 * 4              # 6h slices x 4 apps + pageToken
    docs = spooled(tmp_path, "gws_reports")
    assert {d["id"]["applicationName"] for d in docs} == {"login", "admin", "token", "drive"}
    assert len({(d["id"]["applicationName"], d["id"]["uniqueQualifier"]) for d in docs}) == n
    assert any(d["events"][0]["name"] == "ASSIGN_ROLE" for d in docs)
    assert again["ok"] and again["written"] == 0, again
    no_leak(tmp_path, json.loads(key)["private_key"][40:90])


def test_gws_not_delegated_admin_and_missing_subject(base_cfg, tmp_path, monkeypatch) -> None:
    pytest.importorskip("cryptography")
    with msaas.MockSaaS(gws_admins=(GWS_ADMIN,)) as m:
        cfg, _ = gws_cfg(base_cfg, tmp_path, m, monkeypatch, admin="intern@corp.example")
        st = connector("gws_reports", cfg).cycle()
        assert not st["ok"] and "sign-in rejected" in st["error"] and "unauthorized_client" in st["error"], st
        assert "intern@corp.example" in st["error"] and "PRIVATE KEY" not in st["error"]
        cfg, _ = gws_cfg(base_cfg, tmp_path / "b", m, monkeypatch, admin=None)
        st = connector("gws_reports", cfg).cycle()
        assert not st["ok"] and "set delegated_admin" in st["error"], st


# ============================================================================= catalog
def test_identity_catalog_entries() -> None:
    from attacklens import connectors
    from attacklens.integrations_status import catalog
    by_id = {e["id"]: e for e in catalog()}
    for sid in connectors.IDENTITY_SOURCES:
        e = by_id[sid]
        assert e["kind"] == "identity" and e["modes"] == ["events"] and e["docs_url"].startswith("https://")
        assert e["help"].startswith("Minimum permission")
        for f in e["fields"]:
            if any(w in f["key"] for w in ("secret", "token", "private_key", "json")) and not f["key"].endswith("_uri"):
                assert f["type"] == "secret", (sid, f)
            if f["key"] in ("login_url", "token_uri") or (f["key"] == "base_url" and sid != "okta"):
                assert f.get("advanced") and not f.get("required") and not f.get("default"), (sid, f)
    assert [f["key"] for f in by_id["okta"]["fields"] if f.get("required")] == ["base_url"]
    assert [f["key"] for f in by_id["m365_ual"]["fields"] if f.get("required")] == \
        ["tenant_id", "client_id", "client_secret"]
    assert [f["key"] for f in by_id["gws_reports"]["fields"] if f.get("required")] == \
        ["service_account_json", "delegated_admin"]
    ic = config.load_config()["integrations"]["connectors"]
    assert all(ic[s]["enabled"] is False for s in connectors.IDENTITY_SOURCES)  # disabled by default


# ============================================================================= API e2e (like the Connections page)
@pytest.mark.parametrize("source", ["okta", "m365_ual", "gws_reports"])
def test_api_put_test_start_spool_stop_identity(source: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """PUT /api/integrations/{id} -> POST test -> POST start (a real `python -m attacklens.connect` child) -> every
    seeded record in the spool -> POST stop; no secret value in spool / state / logs / API answers."""
    from . import test_e2e_integrations as e2e
    reason = e2e.skip_reason(source)
    if reason:
        pytest.skip(reason)
    if source == "gws_reports":
        pytest.importorskip("cryptography")
    from fastapi.testclient import TestClient

    from attacklens import api, api_integrations

    from .test_integrations import cfg_dir
    monkeypatch.setenv("ATTACKLENS_INTEGRATIONS_DIR", str(tmp_path / "integ"))
    monkeypatch.setenv("ATTACKLENS_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.delenv("ATTACKLENS_INTEGRATIONS_OVERLAY", raising=False)
    (tmp_path / "out").mkdir()
    monkeypatch.setenv("ATTACKLENS_OUT", str(tmp_path / "out"))
    with msaas.MockSaaS(okta_token=OKTA_TOKEN, m365_client_id=M365_CLIENT, m365_secret=M365_SECRET,
                        gws_client_email=GWS_EMAIL, gws_admins=(GWS_ADMIN,)) as m:
        cdir = cfg_dir(tmp_path, e2e.integrations_yaml(m.url, tmp_path))
        if source == "okta":
            body = {"settings": {"base_url": m.url, "verify_tls": False}, "secrets": {"token": OKTA_TOKEN}}
            want, key = len(m.seed.okta), "uuid"
        elif source == "m365_ual":
            body = {"settings": {"base_url": m.url, "login_url": m.url, "tenant_id": sseed.TENANT,
                                 "client_id": M365_CLIENT, "verify_tls": False}, "secrets": {"client_secret": M365_SECRET}}
            want, key = sseed.counts(m.seed)["m365_ual"], "Id"
        else:
            sa = json.dumps({"type": "service_account", "private_key_id": "k1", "private_key": rsa_pem(),
                             "client_email": GWS_EMAIL, "token_uri": f"{m.url}/token"})
            body = {"settings": {"base_url": m.url, "token_uri": f"{m.url}/token", "delegated_admin": GWS_ADMIN,
                                 "verify_tls": False}, "secrets": {"service_account_json": sa}}
            want, key = sseed.counts(m.seed)["gws_reports"], "id"

        def spawn(cmd: list[str], child_env: dict[str, str], log_path: Path) -> Any:
            return e2e._FakeLive() if "attacklens.live" in cmd else api_integrations._spawn(cmd, child_env, log_path)

        svc = api_integrations.IntegrationsService(config_dir=cdir, spawn=spawn)
        state = api.AppState()
        state.integrations = svc  # type: ignore[attr-defined]
        log_file = tmp_path / "integ" / "logs" / f"connect_{source}.log"
        with TestClient(api.create_app(state)) as c:
            try:
                r = c.put(f"/api/integrations/{source}", json=body)
                assert r.status_code == 200 and r.json()["configured"] is True, r.text
                r = c.post(f"/api/integrations/{source}/test")
                assert r.status_code == 200 and r.json()["ok"] is True, r.text
                assert [s["name"] for s in r.json()["steps"] if s["ok"]] == list(("config", "dns", "connect", "auth",
                                                                                  "permission", "data"))
                r = c.post(f"/api/integrations/{source}/start", json={"mode": "events", "since": "2d"})
                assert r.status_code == 200 and r.json()["running"] is True, r.text
                e2e.wait_until(lambda: len(e2e.spool_docs(tmp_path, source)) >= want, e2e.WAIT_S, f"{source} spool",
                               lambda: log_file.read_text(encoding="utf-8", errors="replace")
                               if log_file.exists() else "")
                r = c.post(f"/api/integrations/{source}/stop")
                assert r.status_code == 200 and r.json()["running"] is False, r.text
                listing = c.get(f"/api/integrations/{source}").text + c.get("/api/integrations/status").text
            finally:
                svc.stop_all()
    docs = [json.loads(ln) for ln in e2e.spool_docs(tmp_path, source)]
    ids = [json.dumps(d[key], sort_keys=True) for d in docs]
    assert len(docs) == want and len(set(ids)) == want, (len(docs), want)
    assert sseed.ATTACKER_IP in json.dumps(docs), "the attack story's records were pulled"
    text = e2e.all_text(tmp_path / "spool", tmp_path / "conn_state", tmp_path / "integ") + listing
    secrets_ = [OKTA_TOKEN, M365_SECRET] + ([json.loads(body["secrets"]["service_account_json"])["private_key"][40:90]]
                                            if source == "gws_reports" else [])
    assert not [s for s in secrets_ if s in text], "secret value written to spool / state / logs / API"


# ============================================================================= spool -> Stage 0/1 (identity sources)
def test_spool_ingests_as_the_identity_source_types(base_cfg, tmp_path, monkeypatch) -> None:
    """The three connectors' spool routes to okta_json / m365_ual_json / gws_reports_json with nothing dropped."""
    pytest.importorskip("cryptography")
    want = {"okta_json", "m365_ual_json", "gws_reports_json"}
    missing = want - set(base_cfg["sources"].get("json_sources") or {})
    if missing:
        pytest.skip(f"identity source types not in config/sources.yaml yet: {sorted(missing)}")
    from .conftest import accounting, query, run_ingest
    with msaas.MockSaaS(okta_token=OKTA_TOKEN, m365_secret=M365_SECRET, gws_admins=(GWS_ADMIN,)) as m:
        written = {}
        for src, cfg in (("okta", okta_cfg(base_cfg, tmp_path, m, monkeypatch)),
                         ("m365_ual", m365_cfg(base_cfg, tmp_path, m, monkeypatch)),
                         ("gws_reports", gws_cfg(base_cfg, tmp_path, m, monkeypatch)[0])):
            st = connector(src, cfg).cycle()
            assert st["ok"], st
            written[src] = st["written"]
    ctx = run_ingest(tmp_path / "spool" / "events", tmp_path / "ing")
    acc = accounting(ctx)
    assert {k: v["rows_in"] for k, v in acc.items()} == {"okta_json": written["okta"],
                                                          "m365_ual_json": written["m365_ual"],
                                                          "gws_reports_json": written["gws_reports"]}, acc
    assert all(v["dropped"] == 0 for v in acc.values()), acc
    att = query(ctx, "SELECT source_type, count(*) AS n FROM events WHERE src_ip = ? GROUP BY 1 ORDER BY 1",
                [sseed.ATTACKER_IP])
    assert {r["source_type"] for r in att} == want, att
