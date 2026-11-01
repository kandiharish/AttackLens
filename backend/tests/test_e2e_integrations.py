"""End to end, offline: tools/mock_siem.py (SIEM + Azure / AWS / GCP mocks) on a free 127.0.0.1 port, driven through
the HTTP API like the Integrations page does:
    PUT /api/integrations/{id} {"settings": {...}, "secrets": {...}} -> POST {id}/test -> POST {id}/start
    -> spool files appear (a real `python -m attacklens.connect` child) -> POST {id}/stop
for aws_cloudtrail, azure_monitor, gcp_logging, splunk, sentinel and elastic. Plus the audit cases (token expiry,
429 on page N, late row, future row, > 5000 rows at one timestamp, octet-counted TCP syslog, HEC indexer ack) driven
on the connector / sink directly.

Everything (config copy, overlay settings, DPAPI secrets, spool, state, status, logs) lives under tmp_path; live mode
is not started (its spawn is faked): this file tests connectors and spool, not the pipeline.
Each test skips (with the reason) when what it needs is missing: the API route, the connector in connectors.SOURCES,
an optional dependency (boto3 for AWS, cryptography for the GCP JWT), an endpoint override, or the product fix an
audit case waits for. They switch on by themselves when that lands.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml

from attacklens import config

from .test_integrations import _items, cfg_dir
from .test_mock_siem import ALL, REPO, T0, marker, write_fixture

sys.path.insert(0, str(REPO / "tools"))
import mock_cloud_seed as seed  # noqa: E402
import mock_siem as ms  # noqa: E402

PKG = REPO / "backend" / "attacklens"
ATT = seed.ATTACKER_IP
SIEM_SOURCES = ("splunk", "sentinel", "elastic")
CLOUD_SOURCES = ("aws_cloudtrail", "azure_monitor", "gcp_logging")
SECRET = {"elastic": "E2E-ES-KEY-5b1d", "splunk": "E2E-SPLUNK-TOK-77c2", "sentinel": "E2E-SENTINEL-TOK-a90e",
          "azure": "E2E-AZURE-SECRET-3f6e", "aws_ak": "AKIDE2EMOCK00000001", "aws_sk": "E2E-AWS-SK-c4d1",
          "hec": "E2E-HEC-TOK-19ab"}
AZ_CLIENT = "e2e-client-id"
GCP_EMAIL = f"attacklens-e2e@{seed.PROJECT}.iam.gserviceaccount.com"
# rows the seed serves per source (events mode, management events only for LookupEvents)
EXPECTED_ROWS = {"azure_monitor": 12 + 25 + 8, "aws_cloudtrail": 35, "gcp_logging": 80}
ID_KEY = {"azure_monitor": "_ItemId", "aws_cloudtrail": "eventID", "gcp_logging": "insertId"}
WAIT_S = 90


# ----------------------------------------------------------------------------- availability (skip reasons)
def _src(rel: str) -> str:
    p = PKG / rel
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def _has(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


def _sources() -> tuple[str, ...]:
    try:
        return tuple(importlib.import_module("attacklens.connectors").SOURCES)
    except Exception:  # noqa: BLE001
        return ()


def _api_routes() -> set[tuple[str, str]]:
    try:
        api_int = importlib.import_module("attacklens.api_integrations")
        r = api_int.create_router(api_int.IntegrationsService(spawn=lambda *a, **k: None))
    except Exception:  # noqa: BLE001
        return set()
    return {(m, route.path) for route in r.routes for m in getattr(route, "methods", ())}


ROUTES = {("PUT", "/api/integrations/{iid}"), ("POST", "/api/integrations/{iid}/test"),
          ("POST", "/api/integrations/{iid}/start"), ("POST", "/api/integrations/{iid}/stop")}


def skip_reason(source: str) -> str | None:
    if not ROUTES <= _api_routes():
        return "integrations API (PUT /api/integrations/{id}, test/start/stop) not present"
    if source not in _sources():
        return f"connector {source} not in attacklens.connectors.SOURCES"
    if source == "aws_cloudtrail":
        if not _has("boto3"):
            return "boto3 not installed (pip extra [cloud]); the aws_cloudtrail connector needs it"
        if "endpoint_url" not in _src("connectors/aws_cloudtrail.py"):
            return "aws_cloudtrail has no endpoint_url override (cannot point boto3 at the mock)"
    if source == "gcp_logging":
        if not _has("cryptography"):
            return "cryptography not installed (pip extra [cloud]); needed to sign the GCP service-account JWT"
        if "token_uri" not in _src("connectors/gcp_logging.py"):
            return "gcp_logging has no token_uri override"
    try:
        if not importlib.import_module("attacklens.secrets_store").available():
            return "secret storage (DPAPI) unavailable on this platform"
    except Exception:  # noqa: BLE001
        return "attacklens.secrets_store missing"
    return None


# ----------------------------------------------------------------------------- RSA key + service-account JSON
def _rsa_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def service_account_json(token_uri: str) -> str:
    """Single-line JSON key (the secret store refuses newlines; JSON escapes the PEM's)."""
    return json.dumps({"type": "service_account", "project_id": seed.PROJECT, "private_key_id": "e2e0001",
                       "private_key": _rsa_pem(), "client_email": GCP_EMAIL, "client_id": "1",
                       "token_uri": token_uri})


# ----------------------------------------------------------------------------- environment
class _FakeLive:
    """Stands in for the `attacklens.live` child: running, terminable, never touches data/."""
    pid = 0

    def __init__(self) -> None:
        self.rc: int | None = None

    def poll(self) -> int | None:
        return self.rc

    def terminate(self) -> None:
        self.rc = 0

    def wait(self, timeout: float | None = None) -> int:
        self.rc = 0
        return 0

    def kill(self) -> None:
        self.rc = -9


def integrations_yaml(url: str, tmp: Path) -> dict[str, Any]:
    """config/integrations.yaml, spool/state under tmp, every *_env renamed to an unset AL_E2E_* name (so a
    developer's AZURE_* / SPLUNK_* variables can't win over the UI secrets), endpoints at the mock."""
    ic = yaml.safe_load((config.CONFIG_DIR / "integrations.yaml").read_text(encoding="utf-8"))
    ic["spool"].update(events_dir=str(tmp / "spool" / "events"), alerts_dir=str(tmp / "spool" / "alerts"),
                       state_dir=str(tmp / "conn_state"), status_file=str(tmp / "conn_state" / "status.json"))
    for name, c in ic["connectors"].items():
        if not isinstance(c, dict):
            continue
        for k in list(c):
            if k.endswith("_env") and c[k]:
                c[k] = f"AL_E2E_UNSET_{name}_{k}".upper()
        c.update(enabled=False, poll_interval_s=1, timeout_s=5, retries=1, verify_tls=False)
    c = ic["connectors"]
    c["syslog"].pop("poll_interval_s", None)
    if "aws_cloudtrail" in c:
        c["aws_cloudtrail"].update(endpoint_url=url, region=seed.REGION, min_call_interval_s=0, window="6h")
    if "gcp_logging" in c:
        c["gcp_logging"].update(base_url=f"{url}/v2/entries:list", token_uri=f"{url}/token", min_page_interval_s=0)
    for s in ic["sinks"].values():
        s["enabled"] = False
    return ic


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """(mock, cfg dir, tmp); env points the overlay, secrets and API output at tmp_path."""
    monkeypatch.setenv("ATTACKLENS_INTEGRATIONS_DIR", str(tmp_path / "integ"))
    monkeypatch.setenv("ATTACKLENS_SECRETS_DIR", str(tmp_path / "secrets"))
    monkeypatch.delenv("ATTACKLENS_INTEGRATIONS_OVERLAY", raising=False)
    (tmp_path / "out").mkdir()
    monkeypatch.setenv("ATTACKLENS_OUT", str(tmp_path / "out"))
    now = int(time.time() * 1000)
    cloud = {"anchor_ms": seed.now_anchor(now), "azure_tenant": seed.TENANT, "azure_client_id": AZ_CLIENT,
             "azure_client_secret": SECRET["azure"], "aws_access_key_id": SECRET["aws_ak"],
             "gcp_client_email": GCP_EMAIL, "sentinel_oauth": True}   # Sentinel tables need an Entra token
    with ms.MockSIEM(write_fixture(tmp_path / "raw"), elastic_api_key=SECRET["elastic"],
                     splunk_token=SECRET["splunk"], sentinel_token=SECRET["sentinel"], hec_token=SECRET["hec"],
                     cloud=cloud) as m:
        d = cfg_dir(tmp_path, integrations_yaml(m.url, tmp_path))
        lv = yaml.safe_load((d / "live.yaml").read_text(encoding="utf-8")) or {}
        lv.update(watch_dir=str(tmp_path / "live_watch"), out_dir=str(tmp_path / "live_out"))
        (d / "live.yaml").write_text(yaml.safe_dump(lv, sort_keys=False), encoding="utf-8")
        yield m, d, tmp_path


def body_for(source: str, url: str) -> tuple[dict[str, Any], str]:
    """(PUT body, start `since`) for one source, using only fields the connector's CATALOG declares."""
    if source == "elastic":
        return {"settings": {"base_url": url, "verify_tls": False},
                "secrets": {"api_key": SECRET["elastic"]}}, "30d"
    if source == "splunk":
        return {"settings": {"base_url": url, "verify_tls": False}, "secrets": {"token": SECRET["splunk"]}}, "30d"
    if source == "sentinel":
        return {"settings": {"base_url": url, "login_url": url, "workspace_id": "ws1", "tenant_id": seed.TENANT,
                             "client_id": AZ_CLIENT, "verify_tls": False},
                "secrets": {"client_secret": SECRET["azure"]}}, "30d"
    if source == "azure_monitor":
        return {"settings": {"base_url": url, "login_url": url, "workspace_id": seed.WORKSPACE,
                             "tenant_id": seed.TENANT, "client_id": AZ_CLIENT, "verify_tls": False},
                "secrets": {"client_secret": SECRET["azure"]}}, "2d"
    if source == "aws_cloudtrail":
        return {"settings": {"region": seed.REGION},
                "secrets": {"access_key_id": SECRET["aws_ak"], "secret_access_key": SECRET["aws_sk"]}}, "2d"
    if source == "gcp_logging":
        return {"settings": {"project_ids": seed.PROJECT, "verify_tls": False},
                "secrets": {"service_account_json": service_account_json(f"{url}/token")}}, "2d"
    raise ValueError(source)


def spool_docs(tmp: Path, source: str) -> list[str]:
    root = tmp / "spool" / "events" / source
    if not root.exists():
        return []
    return [ln for p in sorted(root.rglob("*")) if p.is_file() and not p.name.startswith(".")
            for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]


def done(source: str, lines: list[str]) -> bool:
    if source in SIEM_SOURCES:
        return {marker(ln) for ln in lines if "marker evt-" in ln} >= ALL
    return len(lines) >= EXPECTED_ROWS[source]


def wait_until(fn: Callable[[], bool], timeout: float, what: str, log: Callable[[], str] = lambda: "") -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if fn():
            return
        time.sleep(0.25)
    raise AssertionError(f"timed out after {timeout:g}s waiting for {what}\n{log()[-3000:]}")


def all_text(*roots: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="replace") for r in roots if r.exists()
                     for p in r.rglob("*") if p.is_file() and p.suffix not in (".bin", ".dat"))


# ============================================================================= API e2e per source
@pytest.mark.parametrize("source", CLOUD_SOURCES + SIEM_SOURCES)
def test_api_put_test_start_spool_stop(source: str, env) -> None:
    reason = skip_reason(source)
    if reason:
        pytest.skip(reason)
    from fastapi.testclient import TestClient

    from attacklens import api, api_integrations

    m, cdir, tmp = env

    def spawn(cmd: list[str], child_env: dict[str, str], log_path: Path) -> Any:
        if "attacklens.live" in cmd:
            return _FakeLive()
        return api_integrations._spawn(cmd, child_env, log_path)

    svc = api_integrations.IntegrationsService(config_dir=cdir, spawn=spawn)
    state = api.AppState()
    state.integrations = svc  # type: ignore[attr-defined]
    body, since = body_for(source, m.url)
    log_file = tmp / "integ" / "logs" / f"connect_{source}.log"
    with TestClient(api.create_app(state)) as c:
        try:
            r = c.put(f"/api/integrations/{source}", json=body)
            assert r.status_code == 200, r.text
            view = r.json()
            assert view["configured"] is True and all(view["secrets_set"][k] for k in body["secrets"])
            r = c.post(f"/api/integrations/{source}/test")
            assert r.status_code == 200 and r.json()["ok"] is True, r.text
            r = c.post(f"/api/integrations/{source}/start", json={"mode": "events", "since": since})
            assert r.status_code == 200 and r.json()["running"] is True, r.text
            wait_until(lambda: done(source, spool_docs(tmp, source)), WAIT_S, f"{source} spool",
                       lambda: log_file.read_text(encoding="utf-8", errors="replace") if log_file.exists() else "")
            r = c.post(f"/api/integrations/{source}/stop")
            assert r.status_code == 200 and r.json()["running"] is False, r.text
            listing = c.get(f"/api/integrations/{source}").text + c.get("/api/integrations/status").text
        finally:
            svc.stop_all()
    lines = spool_docs(tmp, source)
    if source in SIEM_SOURCES:
        got = [marker(ln) for ln in lines if "marker evt-" in ln]
        assert sorted(got) == sorted(ALL), "each fixture event exactly once"
        assert '"threat"' not in "\n".join(lines) and '"labels_extra"' not in "\n".join(lines)
    else:
        docs = [json.loads(ln) for ln in lines]
        ids = [d.get(ID_KEY[source]) for d in docs]
        assert len(docs) == EXPECTED_ROWS[source] and len(set(ids)) == len(ids) and None not in ids
        assert ATT in "\n".join(lines), "the attack story's records were pulled"
    text = all_text(tmp / "spool", tmp / "conn_state", tmp / "integ") + listing
    leaked = [k for k, v in SECRET.items() if v in text]
    assert not leaked, f"secret values written to spool/state/logs/API: {leaked}"


# ============================================================================= audit cases (connector / sink level)
def load_cfg(cdir: Path, ic_edit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    ic = yaml.safe_load((cdir / "integrations.yaml").read_text(encoding="utf-8"))
    ic_edit(ic)
    (cdir / "integrations.yaml").write_text(yaml.safe_dump(ic, sort_keys=False), encoding="utf-8")
    return config.load_config(cdir)


def azure_cfg(m: Any, monkeypatch: pytest.MonkeyPatch, cdir: Path, page_size: int = 1000) -> dict[str, Any]:
    monkeypatch.setenv("AL_E2E_AZ_SECRET", SECRET["azure"])

    def edit(ic: dict[str, Any]) -> None:
        ic["connectors"]["azure_monitor"].update(
            enabled=True, base_url=m.url, login_url=m.url, workspace_id=seed.WORKSPACE, workspace_id_env=None,
            tenant_id=seed.TENANT, tenant_id_env=None, client_id=AZ_CLIENT, client_id_env=None,
            client_secret_env="AL_E2E_AZ_SECRET", token_env=None, page_size=page_size, overlap="10m")
    return load_cfg(cdir, edit)


def need(source: str, feature: str | None = None, rel: str | None = None) -> None:
    if source not in _sources():
        pytest.skip(f"connector {source} not present")
    if feature and feature.lower() not in _src(rel or f"connectors/{source}.py").lower():
        pytest.skip(f"waiting for the product fix: '{feature}' not handled in {rel or source}")


def spooled_ids(tmp: Path, source: str, key: str) -> list[str]:
    return [json.loads(ln).get(key) for ln in spool_docs(tmp, source)]


def first_ts_ms() -> int:
    return seed.now_anchor(int(time.time() * 1000)) - 3_600_000


def test_audit_azure_token_expiry_401_then_refresh(env, monkeypatch: pytest.MonkeyPatch) -> None:
    need("azure_monitor", "call_with_token", "connectors/loganalytics.py")
    m, cdir, tmp = env
    conn = importlib.import_module("attacklens.connectors").get("azure_monitor", azure_cfg(m, monkeypatch, cdir),
                                                                "events", first_ts_ms())
    st = conn.cycle()
    assert st["ok"] and st["written"] == EXPECTED_ROWS["azure_monitor"], st
    m.cloud.expire_tokens("azure")
    new = m.cloud.add_rows(int(time.time() * 1000) - 20 * 60_000, feeds=("SigninLogs",))   # settled (lag 5m)
    st = conn.cycle()                                         # same instance: cached token is now expired
    assert st["ok"], st
    assert new["SigninLogs"] in spooled_ids(tmp, "azure_monitor", "_ItemId")
    la = [r["status"] for r in m.requests if r["path"].endswith("/query")]
    assert 401 in la and la[-1] == 200 and m.cloud.token_requests["azure"] == 2


def test_audit_429_retry_after_on_page_n_loses_nothing(env, monkeypatch: pytest.MonkeyPatch) -> None:
    need("azure_monitor", "retry_after", "httpc.py")
    m, cdir, tmp = env
    m.fail("loganalytics", status=429, after=2, retry_after=1)          # page 3 of 5 is throttled once
    st = importlib.import_module("attacklens.connectors").get(
        "azure_monitor", azure_cfg(m, monkeypatch, cdir, page_size=10), "events", first_ts_ms()).cycle()
    ids = spooled_ids(tmp, "azure_monitor", "_ItemId")
    assert 429 in [r["status"] for r in m.requests]
    assert st["ok"] and len(ids) == EXPECTED_ROWS["azure_monitor"] == len(set(ids)), st


def test_audit_late_row_inside_overlap_is_pulled_next_cycle(env, monkeypatch: pytest.MonkeyPatch) -> None:
    need("azure_monitor", "overlap", "connectors/base.py")
    m, cdir, tmp = env
    newest = max(it.ts_ms for f in seed.LA_TABLES for it in m.cloud.seed.feeds[f])
    m.cloud.configure(late_after=1, late_ts_ms=newest - 5 * 60_000)      # 5 min before the checkpoint
    conn = importlib.import_module("attacklens.connectors").get("azure_monitor", azure_cfg(m, monkeypatch, cdir),
                                                                "events", first_ts_ms())
    late = {it.rid for f in seed.LA_TABLES for it in m.cloud.seed.feeds[f] if it.visible_after}
    assert conn.cycle()["ok"]
    assert not late & set(spooled_ids(tmp, "azure_monitor", "_ItemId")), "late rows invisible in cycle 1"
    assert conn.cycle()["ok"]
    ids = spooled_ids(tmp, "azure_monitor", "_ItemId")
    assert late <= set(ids) and len(ids) == len(set(ids)) == EXPECTED_ROWS["azure_monitor"] + 3


def test_audit_future_row_does_not_block_later_rows(env, monkeypatch: pytest.MonkeyPatch) -> None:
    need("azure_monitor", "future_ts", "connectors/base.py")
    m, cdir, tmp = env
    m.cloud.configure(future_row=True)
    conn = importlib.import_module("attacklens.connectors").get("azure_monitor", azure_cfg(m, monkeypatch, cdir),
                                                                "events", first_ts_ms())
    future = {it.rid for f in seed.LA_TABLES for it in m.cloud.seed.feeds[f] if it.ts_ms > time.time() * 1000}
    st = conn.cycle()
    assert st["ok"] and len(future) == 3, st
    assert not future & set(spooled_ids(tmp, "azure_monitor", "_ItemId"))   # not yet: dated now + 6h
    new = m.cloud.add_rows(int(time.time() * 1000) - 20 * 60_000, feeds=("AuditLogs",))
    assert conn.cycle()["ok"]
    ids = spooled_ids(tmp, "azure_monitor", "_ItemId")
    assert new["AuditLogs"] in ids and len(ids) == len(set(ids)) == EXPECTED_ROWS["azure_monitor"] + 1


def test_audit_more_than_5000_rows_at_one_timegenerated(env, monkeypatch: pytest.MonkeyPatch) -> None:
    need("azure_monitor", "{after}", "connectors/loganalytics.py")
    m, cdir, tmp = env
    m.cloud.configure(tie_burst=5001)
    st = importlib.import_module("attacklens.connectors").get(
        "azure_monitor", azure_cfg(m, monkeypatch, cdir, page_size=5000), "events", first_ts_ms()).cycle()
    ids = spooled_ids(tmp, "azure_monitor", "_ItemId")
    assert st["ok"] and len(ids) == len(set(ids)) == EXPECTED_ROWS["azure_monitor"] + 5001, st


def _free_tcp_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_audit_syslog_tcp_octet_counted_frames(env) -> None:
    need("syslog", "octet")
    m, cdir, tmp = env
    port = _free_tcp_port()

    def edit(ic: dict[str, Any]) -> None:
        ic["connectors"]["syslog"].update(enabled=True, bind="127.0.0.1", udp_port=None, tcp_port=port,
                                          once_seconds=3, flush_interval_s=1)
    cfg = load_cfg(cdir, edit)
    box: dict[str, Any] = {}
    t = threading.Thread(target=lambda: box.update(st=importlib.import_module("attacklens.connect").pull(
        "syslog", "events", cfg)), daemon=True)
    t.start()
    wait_until(lambda: _listening(port), 10, "syslog TCP listener")
    msgs = ["<134>CEF:0|Vendor|Prod|1|100|first|5|src=192.0.2.1 msg=two\nlines",
            "<134>Oct 31 03:00:00 fw01 sshd[1]: Accepted password for vreddy from 203.0.113.77"]
    ms.send_syslog(("127.0.0.1", port), msgs, framing="octet")         # `<len> <msg>`, no trailing newline
    t.join(timeout=20)
    lines = spool_docs(tmp, "syslog")
    assert box["st"]["written"] == 2 and len(lines) == 2, (box, lines)
    assert "first" in lines[0] + lines[1] and "Accepted password for vreddy" in "\n".join(lines)


def _listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def test_audit_hec_indexer_ack_channel_and_413(env, monkeypatch: pytest.MonkeyPatch) -> None:
    need("splunk", "X-Splunk-Request-Channel", "sinks/splunk_hec.py")
    m, cdir, tmp = env
    m.hec_ack, m.hec_max_bytes = True, 6000
    monkeypatch.setenv("AL_E2E_HEC", SECRET["hec"])

    def edit(ic: dict[str, Any]) -> None:
        ic["sinks"]["splunk_hec"].update(enabled=True, base_url=m.url, token_env="AL_E2E_HEC", verify_tls=False,
                                         batch_size=50, only_changed=False)
    cfg = load_cfg(cdir, edit)
    items = _items(3)
    res = importlib.import_module("attacklens.sinks").publish_all(items, cfg)
    assert res["splunk_hec"]["failed"] == 0 and res["splunk_hec"]["sent"] == 3, res
    hec = [r for r in m.requests if r["path"].startswith("/services/collector")]
    assert all(r["status"] in (200, 413) for r in hec) and len(m.received["hec"]) >= 3


def test_e2e_module_reports_why_it_skips() -> None:
    """Pins the skip logic itself: a missing route or connector must skip with a reason, never pass silently."""
    assert skip_reason("no_such_connector") is not None
    if ROUTES <= _api_routes():
        assert "SOURCES" in skip_reason("no_such_connector")
