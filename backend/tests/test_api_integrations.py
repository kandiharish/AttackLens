"""UI-driven integrations API (/api/integrations/*): catalog, settings + secrets, connection test, start/stop.

No real network: connection tests talk to a tiny local HTTP server; pull loops use a fake subprocess.
Settings / secrets / spool / state all live under tmp_path (ATTACKLENS_INTEGRATIONS_DIR, ATTACKLENS_SECRETS_DIR).
"""

from __future__ import annotations

import json
import shutil
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from attacklens import api_integrations as ai
from attacklens import config, connectors, secrets_store
from attacklens import integrations as ig

SECRET = "S3CRET-al-test-9d2f"
DPAPI = pytest.mark.skipif(not secrets_store.available(), reason="secret storage needs Windows DPAPI")


# ----------------------------------------------------------------------------- fixtures
def cfg_dir(tmp: Path) -> Path:
    """The config files the integrations API reads (integrations, live, sources), spool / state / live under tmp.
    (Not the whole config/: sigma/ exceeds Windows MAX_PATH under tmp, and the rest is not read here.)"""
    d = tmp / "config"
    d.mkdir()
    for name in ("integrations.yaml", "live.yaml", "sources.yaml"):
        shutil.copy2(config.CONFIG_DIR / name, d / name)
    ic = yaml.safe_load((d / "integrations.yaml").read_text(encoding="utf-8"))
    ic["spool"].update(events_dir=str(tmp / "spool" / "events"), alerts_dir=str(tmp / "spool" / "alerts"),
                       state_dir=str(tmp / "conn_state"), status_file=str(tmp / "conn_state" / "status.json"))
    (d / "integrations.yaml").write_text(yaml.safe_dump(ic, sort_keys=False), encoding="utf-8")
    lv = yaml.safe_load((d / "live.yaml").read_text(encoding="utf-8")) or {}
    lv.update(state_dir=str(tmp / "live_state"), out_dir=str(tmp / "live_out"), watch_dir=str(tmp / "watch"))
    (d / "live.yaml").write_text(yaml.safe_dump(lv, sort_keys=False), encoding="utf-8")
    return d


class FakeProc:
    _pid = 4000

    def __init__(self, cmd: list[str], env: dict[str, str]) -> None:
        FakeProc._pid += 1
        self.cmd, self.env, self.pid, self.rc = cmd, env, FakeProc._pid, None

    def poll(self) -> int | None:
        return self.rc

    def terminate(self) -> None:
        self.rc = 1

    kill = terminate

    def wait(self, timeout: float | None = None) -> int | None:
        return self.rc


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv(ig.SETTINGS_DIR_ENV, str(tmp_path / "integrations"))
    monkeypatch.setenv(secrets_store.DIR_ENV, str(tmp_path / "secrets"))
    monkeypatch.delenv(ig.OVERLAY_ENV, raising=False)
    for v in ("ELASTIC_API_KEY", "ELASTIC_USER", "ELASTIC_PASSWORD", "SPLUNK_TOKEN", "SPLUNK_HEC_TOKEN",
              "SENTINEL_TOKEN", "SENTINEL_WORKSPACE_ID"):
        monkeypatch.delenv(v, raising=False)
    from attacklens import live
    monkeypatch.setattr(live, "status", lambda *a, **k: {"enabled": False})
    spawned: list[FakeProc] = []

    def spawn(cmd: list[str], env_: dict[str, str], log_path: Path) -> FakeProc:
        p = FakeProc(cmd, env_)
        spawned.append(p)
        return p

    svc = ai.IntegrationsService(cfg_dir(tmp_path), spawn=spawn)
    app = FastAPI()
    app.include_router(ai.create_router(svc))
    with TestClient(app) as c:
        yield {"c": c, "svc": svc, "spawned": spawned, "tmp": tmp_path, "app": app}
    svc.stop_all()


def tree_text(root: Path) -> str:
    return "".join(p.read_text(encoding="utf-8", errors="replace") for p in root.rglob("*") if p.is_file()) \
        if root.exists() else ""


# ----------------------------------------------------------------------------- local mock HTTP server
class _H(BaseHTTPRequestHandler):
    mode: dict[str, Any] = {}

    def log_message(self, *a: Any) -> None:
        pass

    def _go(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        m = self.server.mode  # type: ignore[attr-defined]
        if m.get("delay"):
            time.sleep(m["delay"])
        status, body = m.get("status", 200), m.get("body")
        if m.get("hec_ack"):  # Splunk HEC with indexer acknowledgement on: every request needs a channel
            m.setdefault("channels", []).append(self.headers.get("X-Splunk-Request-Channel"))
            if not self.headers.get("X-Splunk-Request-Channel"):
                status, body = 400, {"text": "Data channel is missing", "code": 10}
        if body is None:
            now = datetime.now(timezone.utc).isoformat()
            body = {"hits": {"hits": [{"_id": "1", "_source": {"@timestamp": now, "message": "x"},
                                       "sort": [now, "1"]}]}}
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.server.seen.append((self.command, self.path, self.headers.get("Authorization")))  # type: ignore

    do_GET = do_POST = _go


@pytest.fixture
def http() -> Iterator[ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    srv.mode, srv.seen = {}, []  # type: ignore[attr-defined]
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def url(srv: ThreadingHTTPServer, scheme: str = "http") -> str:
    return f"{scheme}://127.0.0.1:{srv.server_address[1]}"


def closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ----------------------------------------------------------------------------- catalog
def test_catalog_shape(env) -> None:
    r = env["c"].get("/api/integrations/catalog")
    assert r.status_code == 200
    cat = r.json()
    ids = {e["id"] for e in cat}
    assert {"elastic", "splunk", "sentinel", "syslog", "splunk_hec", "elastic_bulk", "webhook", "syslog_cef"} <= ids
    assert ids >= set(connectors.SOURCES)
    for e in cat:
        assert e["kind"] in ("siem", "cloud", "identity", "sink") and e["name"] and isinstance(e["fields"], list)
        assert ("modes" in e) == (e["kind"] != "sink")
        if "modes" in e:
            assert set(e["modes"]) <= {"events", "alerts"} and e["modes"]
        for f in e["fields"]:
            assert {"key", "label", "type", "required"} <= set(f)
            assert f["type"] in ("text", "url", "secret", "number", "bool", "select")
            if f["type"] == "select":
                assert f["options"]


def test_catalog_module_entry_wins(env, monkeypatch) -> None:
    from attacklens.connectors import elastic
    monkeypatch.setattr(elastic, "CATALOG", {"kind": "siem", "name": "Elastic (module)", "modes": ["alerts"],
                                             "fields": [{"key": "base_url", "label": "URL", "type": "url",
                                                         "required": True}, {"key": "bad key", "type": "text"}]},
                        raising=False)
    e = next(x for x in env["c"].get("/api/integrations/catalog").json() if x["id"] == "elastic")
    assert e["name"] == "Elastic (module)" and e["modes"] == ["alerts"] and [f["key"] for f in e["fields"]] == ["base_url"]


def test_unknown_id_and_path_tricks_are_404(env) -> None:
    c = env["c"]
    for bad in ("nope", "..%2f..%2fconfig", "ELASTIC", "elastic.x", "a" * 80):
        assert c.get(f"/api/integrations/{bad}").status_code == 404
    r = c.put("/api/integrations/nope", json={"settings": {}})
    assert r.status_code == 404 and r.json()["field"] == "id"


# ----------------------------------------------------------------------------- PUT validation
@pytest.mark.parametrize("body,field", [
    ({"settings": {"base_url": "ftp://x.example"}}, "base_url"),
    ({"settings": {"base_url": "not a url"}}, "base_url"),
    ({"settings": {"base_url": "http://admin:pw@es.example:9200"}}, "base_url"),
    ({"settings": {"poll_interval_s": "abc"}}, "poll_interval_s"),
    ({"settings": {"verify_tls": "maybe"}}, "verify_tls"),
    ({"settings": {"flavor": "solr"}}, "flavor"),
    ({"settings": {"no_such": 1}}, "no_such"),
    ({"settings": {"api_key": "x"}}, "api_key"),
    ({"secrets": {"base_url": "x"}}, "base_url"),
    ({"secrets": {"api_key": "a\nb"}}, "api_key"),
])
def test_put_validation(env, body, field) -> None:
    r = env["c"].put("/api/integrations/elastic", json=body)
    assert r.status_code == 422, r.text
    assert r.json()["field"] == field and r.json()["error"]
    assert not ig.settings_path().exists()                                   # nothing saved


def test_put_number_range(env, monkeypatch) -> None:
    from attacklens.sinks import syslog_cef
    monkeypatch.setattr(syslog_cef, "CATALOG", {"kind": "sink", "name": "CEF", "fields": [
        {"key": "host", "label": "Host", "type": "text", "required": True},
        {"key": "port", "label": "Port", "type": "number", "required": True, "min": 1, "max": 65535}]},
        raising=False)                                                       # pin the spec under test
    r = env["c"].put("/api/integrations/syslog_cef", json={"settings": {"host": "siem.example", "port": 70000}})
    assert r.status_code == 422 and r.json()["field"] == "port"
    r = env["c"].put("/api/integrations/syslog_cef", json={"settings": {"host": "", "port": 5515}})
    assert r.status_code == 422 and r.json()["field"] == "host"            # explicit empty required value


def test_put_required_field(env) -> None:
    r = env["c"].put("/api/integrations/sentinel", json={"settings": {"base_url": "https://api.example"}})
    assert r.status_code == 422 and r.json()["field"] == "workspace_id"


def test_put_bad_json_and_body_cap(env) -> None:
    c = env["c"]
    r = c.put("/api/integrations/elastic", content=b"{nope", headers={"Content-Type": "application/json"})
    assert r.status_code == 422
    r = c.put("/api/integrations/elastic", content=b"{" + b" " * (ai.MAX_BODY + 10) + b"}",
              headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_put_saves_overlay_under_same_keys(env) -> None:
    c = env["c"]
    r = c.put("/api/integrations/elastic", json={"settings": {"base_url": "http://es.example:9200",
                                                              "poll_interval_s": "15", "events.index": "fw-*"}})
    assert r.status_code == 200, r.text
    v = r.json()
    assert v["configured"] and v["enabled"] and not v["running"]
    assert v["settings"]["base_url"] == "http://es.example:9200" and v["settings"]["poll_interval_s"] == 15
    assert v["settings"]["events.index"] == "fw-*" and v["settings"]["flavor"] == "elastic"   # yaml default shown
    cfg = ig.apply_overlay(env["svc"].cfg(overlay=False))
    ic = ig.icfg(cfg)
    assert set(ic) >= {"spool", "alert_input", "connectors", "sinks", "pivots"}
    el = ic["connectors"]["elastic"]
    assert el["enabled"] is True and el["events"]["index"] == "fw-*" and el["events"]["ts_field"] == "@timestamp"
    assert ic["connectors"]["splunk"]["enabled"] is False                   # others untouched


# ----------------------------------------------------------------------------- secrets
@DPAPI
def test_secrets_never_returned_and_resolved(env, monkeypatch) -> None:
    c, tmp = env["c"], env["tmp"]
    r = c.put("/api/integrations/elastic", json={"settings": {"base_url": "http://es.example:9200"},
                                                 "secrets": {"api_key": SECRET}})
    assert r.status_code == 200 and SECRET not in r.text
    v = c.get("/api/integrations/elastic").json()
    assert v["secrets_set"] == {"api_key": True, "user": False, "password": False}
    assert v["secrets_source"]["api_key"] == "stored"
    assert SECRET not in json.dumps(v) and SECRET not in tree_text(tmp / "integrations")
    assert SECRET not in tree_text(tmp / "secrets") and (tmp / "secrets" / "integrations.json").exists()
    # the one resolver: stored value reaches the connector's auth header without connector changes
    cfg = ig.apply_overlay(env["svc"].cfg(overlay=False))
    conn = connectors.get("elastic", cfg, "events", ig.now_ms())
    assert conn.headers() == {"Authorization": f"ApiKey {SECRET}"}
    # env var named in api_key_env wins over the stored value
    monkeypatch.setenv("ELASTIC_API_KEY", "from-env")
    cfg = ig.apply_overlay(env["svc"].cfg(overlay=False))
    assert connectors.get("elastic", cfg, "events", ig.now_ms()).headers() == {"Authorization": "ApiKey from-env"}
    assert c.get("/api/integrations/elastic").json()["secrets_source"]["api_key"] == "env"
    # omitted secret = keep; null = delete
    c.put("/api/integrations/elastic", json={"settings": {"poll_interval_s": 20}})
    assert "elastic.api_key" in secrets_store.refs()
    c.put("/api/integrations/elastic", json={"secrets": {"api_key": None}})
    assert "elastic.api_key" not in secrets_store.refs()


@DPAPI
def test_delete_removes_settings_and_secrets(env) -> None:
    c = env["c"]
    c.put("/api/integrations/splunk", json={"settings": {"base_url": "https://s.example:8089"},
                                            "secrets": {"token": SECRET}})
    assert "splunk.token" in secrets_store.refs()
    r = c.delete("/api/integrations/splunk")
    assert r.status_code == 200
    v = r.json()
    assert not v["configured"] and not v["enabled"] and v["secrets_set"] == {"token": False}
    assert "splunk.token" not in secrets_store.refs()
    assert "splunk" not in ig.read_overlay()["items"]


def test_secret_storage_unavailable_is_501(env, monkeypatch) -> None:
    monkeypatch.setattr(secrets_store, "available", lambda: False)
    r = env["c"].put("/api/integrations/splunk", json={"settings": {"base_url": "https://s.example:8089"},
                                                       "secrets": {"token": SECRET}})
    assert r.status_code == 501 and SECRET not in r.text
    assert not ig.settings_path().exists() and not (env["tmp"] / "secrets" / "integrations.json").exists()


# ----------------------------------------------------------------------------- start / stop
def test_start_stop_fake_connector(env) -> None:
    c, spawned = env["c"], env["spawned"]
    assert c.post("/api/integrations/elastic/start", json={"mode": "events"}).status_code == 409   # not saved yet
    c.put("/api/integrations/elastic", json={"settings": {"base_url": "http://es.example:9200"}})
    r = c.post("/api/integrations/elastic/start", json={"mode": "events", "since": "24h"})
    assert r.status_code == 200 and r.json()["running"] is True and r.json()["mode"] == "events"
    cmds = [p.cmd for p in spawned]
    conn = next(cm for cm in cmds if "attacklens.connect" in cm)
    assert conn[conn.index("--source") + 1] == "elastic" and conn[conn.index("--mode") + 1] == "events"
    assert "--once" not in conn and conn[conn.index("--since") + 1] == "24h"
    assert any("attacklens.live" in cm for cm in cmds)                       # live mode started too
    assert all(p.env[ig.OVERLAY_ENV] == "1" for p in spawned)
    assert all(SECRET not in " ".join(p.cmd) for p in spawned)
    n = len(spawned)
    assert c.post("/api/integrations/elastic/start", json={"mode": "events"}).json()["running"]
    assert len(spawned) == n                                                  # idempotent
    r = c.post("/api/integrations/elastic/stop")
    assert r.status_code == 200 and r.json()["running"] is False
    assert next(p for p in spawned if "attacklens.connect" in p.cmd).rc is not None


def test_start_validation_and_alerts_mode(env, monkeypatch) -> None:
    c = env["c"]
    monkeypatch.setenv("SPLUNK_TOKEN", "from-env")                         # a required secret may come from env
    assert c.put("/api/integrations/splunk", json={"settings": {"base_url": "https://s.example:8089"}}).status_code == 200
    assert c.post("/api/integrations/splunk/start", json={"mode": "bogus"}).json()["field"] == "mode"
    assert c.post("/api/integrations/splunk/start", json={"mode": "events", "since": "yesterday"}).status_code == 422
    r = c.post("/api/integrations/splunk/start", json={"mode": "alerts"})
    assert r.status_code == 200 and r.json()["mode"] == "alerts"
    assert ig.read_overlay()["alert_input"]["enabled"] is True


def test_sink_start_stop_toggles_enabled(env) -> None:
    c = env["c"]
    assert c.post("/api/integrations/webhook/start").status_code == 409
    c.put("/api/integrations/webhook", json={"settings": {"url": "http://127.0.0.1:9/hook", "payload": "summary"}})
    assert c.get("/api/integrations/webhook").json()["enabled"] is True
    assert c.post("/api/integrations/webhook/stop").json()["enabled"] is False
    assert c.post("/api/integrations/webhook/start").json()["running"] is True


# ----------------------------------------------------------------------------- security
def test_non_loopback_client_and_foreign_origin_refused(env) -> None:
    with TestClient(env["app"], client=("10.1.2.3", 5000)) as remote:
        assert remote.get("/api/integrations/catalog").status_code == 403
    c = env["c"]
    assert c.get("/api/integrations/catalog", headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.get("/api/integrations/catalog", headers={"Origin": "null"}).status_code == 403
    assert c.get("/api/integrations/catalog", headers={"Origin": "http://localhost:5173"}).status_code == 200
    with TestClient(env["app"], client=("127.0.0.1", 5000)) as local:
        assert local.get("/api/integrations/catalog").status_code == 200


def test_router_wired_into_app(env, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ATTACKLENS_OUT", str(tmp_path / "out"))
    (tmp_path / "out").mkdir()
    from attacklens import api
    with TestClient(api.create_app()) as c:
        assert c.get("/api/integrations/catalog").status_code == 200
        assert c.get("/api/integrations/elastic").json()["id"] == "elastic"
        assert c.get("/api/integrations/status").status_code == 200        # existing route still first
        assert c.put("/api/integrations/webhook", json={"settings": {"url": "http://127.0.0.1:9/h"}}).status_code == 200
        st = c.get("/api/integrations/status").json()                       # header pill and tile agree
        assert st["sinks"]["webhook"]["enabled"] is c.get("/api/integrations/webhook").json()["enabled"] is True


# ----------------------------------------------------------------------------- connection test
def _save_elastic(c: TestClient, base: str, secret: bool = False) -> None:
    body: dict[str, Any] = {"settings": {"base_url": base, "verify_tls": True}}
    if secret:
        body["secrets"] = {"api_key": SECRET}
    assert c.put("/api/integrations/elastic", json=body).status_code == 200


def test_connection_ok(env, http) -> None:
    _save_elastic(env["c"], url(http))
    r = env["c"].post("/api/integrations/elastic/test").json()
    assert r["ok"] is True and r["sample_count"] == 1 and r["latency_ms"] >= 0 and "error_code" not in r
    assert any("_search" in p for _, p, _ in http.seen)
    assert not (env["tmp"] / "spool").exists()                               # a test never writes the spool


@DPAPI
def test_connection_auth_failed_never_echoes_secret(env, http) -> None:
    http.mode.update(status=401, body={"error": f"bad key {SECRET}"})
    _save_elastic(env["c"], url(http), secret=True)
    resp = env["c"].post("/api/integrations/elastic/test")
    r = resp.json()
    assert r["ok"] is False and r["error_code"] == "auth_failed" and SECRET not in resp.text
    assert http.seen[-1][2] == f"ApiKey {SECRET}"                            # the stored secret was used


@pytest.mark.parametrize("case,code", [("refused", "not_reachable"), ("dns", "not_reachable"),
                                       ("tls", "tls_error"), ("timeout", "timeout"), ("notjson", "bad_response"),
                                       ("500", "bad_response")])
def test_connection_error_mapping(env, http, monkeypatch, case, code) -> None:
    from attacklens import connect
    if case == "timeout":
        monkeypatch.setattr(connect, "TEST_TIMEOUT_S", 0.5)
    base = {"refused": f"http://127.0.0.1:{closed_port()}", "dns": "http://no-such-host.invalid:9200",
            "tls": url(http, "https")}.get(case, url(http))
    if case == "timeout":
        http.mode.update(delay=2.0)
    if case == "notjson":
        http.mode.update(body=b"<html>login</html>")
    if case == "500":
        http.mode.update(status=500, body={"error": "boom"})
    _save_elastic(env["c"], base)
    r = env["c"].post("/api/integrations/elastic/test").json()
    assert r["ok"] is False and r["error_code"] == code, r
    assert r["message"] and r["sample_count"] == 0


def test_sink_connection_test_hec(env, http, monkeypatch) -> None:
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "hec-from-env")                  # required secret via env
    http.mode.update(status=400, body={"text": "No data", "code": 5})
    assert env["c"].put("/api/integrations/splunk_hec", json={"settings": {"base_url": url(http)}}).status_code == 200
    r = env["c"].post("/api/integrations/splunk_hec/test").json()
    assert r["ok"] is True, r
    http.mode.update(status=403, body={"text": "Invalid token", "code": 4})
    assert env["c"].post("/api/integrations/splunk_hec/test").json()["error_code"] == "auth_failed"


def test_sink_connection_test_hec_indexer_ack_channel(env, http, monkeypatch) -> None:
    """Indexer ack on: the probe sends the sink's stable channel (same uuid each test) and gets "No data" (code 5);
    a HEC that still answers code 10 "Data channel is missing" also counts as credentials OK; other 400s fail."""
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "hec-from-env")
    http.mode.update(hec_ack=True, status=400, body={"text": "No data", "code": 5})
    assert env["c"].put("/api/integrations/splunk_hec", json={"settings": {"base_url": url(http)}}).status_code == 200
    for _ in range(2):
        r = env["c"].post("/api/integrations/splunk_hec/test").json()
        assert r["ok"] is True, r
    chans = http.mode["channels"]
    assert len(chans) == 2 and chans[0] == chans[1] and str(uuid.UUID(chans[0])) == chans[0], chans
    http.mode.update(hec_ack=False, body={"text": "Data channel is missing", "code": 10})
    assert env["c"].post("/api/integrations/splunk_hec/test").json()["ok"] is True
    http.mode.update(body={"text": "Invalid data format", "code": 6})
    assert env["c"].post("/api/integrations/splunk_hec/test").json()["ok"] is False
    assert not list((env["tmp"] / "conn_state").glob("sink_splunk_hec_channel*")), "the probe persisted a channel"


def test_hec_channel_is_written_only_under_a_configured_state_dir(tmp_path) -> None:
    """No spool.state_dir -> the process channel, no file (a bare cfg would hit the repo's data/spool); persist=False
    reads only; the sink (persist=True) keeps one id that the probe then reuses."""
    from attacklens.sinks import splunk_hec as hec
    bare = {"integrations": {"sinks": {"splunk_hec": {}}}}
    assert hec.channel(bare) == hec.channel(bare) == hec.channel({}, persist=False)
    cfg = {"integrations": {"spool": {"state_dir": str(tmp_path / "state")}}}
    f = tmp_path / "state" / "sink_splunk_hec_channel.json"
    hec.channel(cfg, persist=False)
    assert not f.exists()
    kept = hec.channel(cfg)
    assert f.exists() and hec.channel(cfg) == hec.channel(cfg, persist=False) == kept != hec.channel(bare)


@pytest.mark.parametrize("status,body,code,needles", [
    (400, '{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret. s=' + SECRET + '"}',
     "auth_failed", ["AADSTS7000215", "invalid client secret"]),
    (400, '{"__type":"AccessDeniedException","message":"User: arn:aws:iam::1:user/x is not authorized to perform: '
          'cloudtrail:LookupEvents"}', "permission_denied", ["AccessDenied", "cloudtrail:LookupEvents"]),
    (403, "Permission 'logging.logEntries.list' denied on resource", "permission_denied",
     ["logging.logEntries.list"]),
    (429, "", "rate_limited", ["429"]),
])
def test_vendor_error_detail_is_allow_listed(status, body, code, needles) -> None:
    from attacklens import connect, httpc
    got, msg = connect._classify(httpc.HttpError("x", status, body), "api.example", "Vendor")
    assert got == code and all(n in msg for n in needles), msg
    assert SECRET not in msg and "arn:aws" not in msg                       # codes only, never free text


def test_tls_untrusted_message_is_actionable() -> None:
    from attacklens import connect, httpc
    exc = httpc.HttpError("POST https://s:8089/x failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    code, msg = connect._classify(exc, "s:8089", "Splunk")
    assert code == "tls_error" and "CA file" in msg and "Verify TLS" in msg


def test_module_probe_result_passes_through(env, http, monkeypatch) -> None:
    from attacklens.connectors import elastic
    monkeypatch.setattr(elastic, "test_connection", lambda cfg: {"ok": False, "error_code": "auth_failed",
                                                                 "message": "Vendor said no (code 42)."},
                        raising=False)
    _save_elastic(env["c"], url(http))                                     # network pre-checks run first
    r = env["c"].post("/api/integrations/elastic/test").json()
    assert r == {**r, "ok": False, "error_code": "auth_failed", "message": "Vendor said no (code 42)."}
    assert _failed_at(r, "auth")["detail"] == "Vendor said no (code 42)."
    monkeypatch.setattr(elastic, "test_connection", lambda cfg: {"ok": True, "sample_count": 3}, raising=False)
    r = env["c"].post("/api/integrations/elastic/test").json()
    assert r["ok"] is True and r["sample_count"] == 3


def test_catalog_passes_advanced_flag(env, monkeypatch) -> None:
    from attacklens.connectors import splunk
    monkeypatch.setattr(splunk, "CATALOG", {"kind": "siem", "name": "Splunk", "fields": [
        {"key": "base_url", "label": "URL", "type": "url", "required": True},
        {"key": "page_size", "label": "Page size", "type": "number", "advanced": True}]}, raising=False)
    e = next(x for x in env["c"].get("/api/integrations/catalog").json() if x["id"] == "splunk")
    assert [f.get("advanced") for f in e["fields"]] == [None, True]


# ----------------------------------------------------------------------------- /test steps (config ... data)
STEP_NAMES = ["config", "dns", "connect", "auth", "permission", "data"]


def _steps(r: dict[str, Any]) -> dict[str, dict[str, Any]]:
    assert [x["name"] for x in r["steps"]] == STEP_NAMES                     # always all six, in order
    assert all(set(x) == {"name", "ok", "detail"} for x in r["steps"])
    return {x["name"]: x for x in r["steps"]}


def _failed_at(r: dict[str, Any], name: str) -> dict[str, Any]:
    st = _steps(r)
    i = STEP_NAMES.index(name)
    assert all(st[n]["ok"] is True for n in STEP_NAMES[:i]), r["steps"]
    assert st[name]["ok"] is False and st[name]["detail"] == r["message"], r["steps"]
    assert all(st[n]["ok"] is None and st[n]["detail"] is None for n in STEP_NAMES[i + 1:]), r["steps"]
    assert r["ok"] is False
    return st[name]


def test_steps_all_ok_with_newest_row(env, http) -> None:
    _save_elastic(env["c"], url(http))
    r = env["c"].post("/api/integrations/elastic/test").json()
    st = _steps(r)
    assert r["ok"] and all(x["ok"] is True for x in r["steps"])
    assert "1 row(s)" in st["data"]["detail"] and "newest 20" in st["data"]["detail"]


def test_steps_no_rows_is_ok_but_says_so(env, http) -> None:
    http.mode.update(body={"hits": {"hits": []}})
    _save_elastic(env["c"], url(http))
    r = env["c"].post("/api/integrations/elastic/test").json()
    assert r["ok"] and r["sample_count"] == 0 and "no rows" in _steps(r)["data"]["detail"]


def test_step_config_missing_required_secret(env, monkeypatch) -> None:
    monkeypatch.setenv("SPLUNK_TOKEN", "from-env")
    assert env["c"].put("/api/integrations/splunk", json={"settings": {"base_url": "https://s.example:8089"}}
                        ).status_code == 200
    monkeypatch.delenv("SPLUNK_TOKEN")
    r = env["c"].post("/api/integrations/splunk/test").json()
    assert "Missing" in _failed_at(r, "config")["detail"] and r["error_code"] == "bad_config" or \
        r["steps"][0]["ok"] is False


def test_step_dns(env, monkeypatch) -> None:
    from attacklens import integrations_status as ist

    def boom(host: str, port: int) -> None:
        raise socket.gaierror(11001, "getaddrinfo failed")
    monkeypatch.setattr(ist, "resolve", boom)
    _save_elastic(env["c"], "http://es.example:9200")
    r = env["c"].post("/api/integrations/elastic/test").json()
    assert "DNS" in _failed_at(r, "dns")["detail"] and r["error_code"] == "not_reachable"


def test_step_connect_tls(env, monkeypatch) -> None:
    import ssl
    from attacklens import integrations_status as ist
    monkeypatch.setattr(ist, "resolve", lambda h, p: None)

    def bad_tls(*a: Any, **k: Any) -> None:
        raise ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
    monkeypatch.setattr(ist, "handshake", bad_tls)
    _save_elastic(env["c"], "https://es.example:9200")
    r = env["c"].post("/api/integrations/elastic/test").json()
    d = _failed_at(r, "connect")["detail"]
    assert r["error_code"] == "tls_error" and "CA file" in d


def test_step_auth_aadsts(env, http) -> None:
    http.mode.update(status=401, body={"error": "invalid_client", "error_description": "AADSTS7000215: bad secret"})
    _save_elastic(env["c"], url(http))
    r = env["c"].post("/api/integrations/elastic/test").json()
    d = _failed_at(r, "auth")["detail"]
    assert r["error_code"] == "auth_failed" and "AADSTS7000215" in d and "Value" in d


def test_step_permission_names_fix(env, http) -> None:
    http.mode.update(status=403, body={"error": {"type": "security_exception", "reason": "action [read] denied"}})
    _save_elastic(env["c"], url(http))
    r = env["c"].post("/api/integrations/elastic/test").json()
    d = _failed_at(r, "permission")["detail"]
    assert r["error_code"] == "permission_denied" and "view_index_metadata" in d and "403" in d


def test_step_permission_bad_response(env, http) -> None:
    http.mode.update(body=b"<html>login</html>")
    _save_elastic(env["c"], url(http))
    r = env["c"].post("/api/integrations/elastic/test").json()
    assert "JSON" in _failed_at(r, "permission")["detail"] and r["error_code"] == "bad_response"


def test_step_fix_hints_per_vendor() -> None:
    from attacklens import integrations_status as ist
    assert "Log Analytics Reader on workspace ws-42" in ist.fix_hint("azure_monitor", {"workspace_id": "ws-42"},
                                                                    "AuthorizationFailed", True).replace("'", "")
    assert "cloudtrail:LookupEvents" in ist.fix_hint("aws_cloudtrail", {}, "for cloudtrail:LookupEvents", True)
    assert "roles/logging.viewer" in ist.fix_hint("gcp_logging", {"project_ids": "p1"}, "PERMISSION_DENIED", True)
    assert "session token" in ist.fix_hint("aws_cloudtrail", {}, "ExpiredToken", False)


# ----------------------------------------------------------------------------- glue: env keys, help, missing deps
def test_status_auth_covers_every_env_key(env, monkeypatch) -> None:
    from attacklens import integrations_status as ist
    monkeypatch.setenv("AL_T_CLIENT_SECRET", SECRET)
    c = {"client_secret_env": "AL_T_CLIENT_SECRET", "tenant_id_env": "AL_T_TENANT_UNSET",
         "secret_access_key_env": None, "service_account_json_env": "AL_T_SA_UNSET", "base_url": "https://x"}
    monkeypatch.delenv("AL_T_TENANT_UNSET", raising=False)
    monkeypatch.delenv("AL_T_SA_UNSET", raising=False)
    got = ist._auth(c)
    assert got == {"client_secret_env": True, "service_account_json_env": False, "tenant_id_env": False}
    assert SECRET not in json.dumps(got)


def test_catalog_passes_help_and_docs_url(env, monkeypatch) -> None:
    from attacklens.connectors import splunk
    monkeypatch.setattr(splunk, "CATALOG", {"kind": "siem", "name": "Splunk", "help": "Minimum permission: search.",
                                            "docs_url": "https://docs.example/splunk", "fields": []}, raising=False)
    e = next(x for x in env["c"].get("/api/integrations/catalog").json() if x["id"] == "splunk")
    assert e["help"] == "Minimum permission: search." and e["docs_url"] == "https://docs.example/splunk"


def test_missing_dependency_is_mapped(env, http, monkeypatch) -> None:
    from attacklens import connect
    from attacklens.connectors import base, elastic
    code, msg = connect._classify(base.MissingDependency("cryptography is not installed; run: pip install "
                                                         '"attacklens[cloud]"'), "x", "GCP")
    assert code == "missing_dependency" and 'pip install "attacklens[cloud]"' in msg
    code, msg = connect._classify(base.MissingDependency("boom"), "x", "GCP")
    assert code == "missing_dependency" and 'pip install "attacklens[cloud]"' in msg

    def no_lib(cfg: Any) -> None:
        raise base.MissingDependency('cryptography is not installed; run: pip install "attacklens[cloud]"')
    monkeypatch.setattr(elastic, "test_connection", no_lib, raising=False)
    _save_elastic(env["c"], url(http))
    r = env["c"].post("/api/integrations/elastic/test").json()
    assert r["error_code"] == "missing_dependency" and "pip install" in _failed_at(r, "auth")["detail"]
