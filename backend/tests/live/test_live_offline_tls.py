"""Sink connection test vs a private CA, offline (NOT marked live: a local HTTPS server, no Docker, no network).

Found while building the live Splunk / Elastic harness: the splunk_hec and elastic_bulk sinks SEND with
`ca_file` (sinks/*.py pass it to httpc), but POST /api/integrations/{id}/test probes them through
connect._probe_sink, which passes only verify_tls. So a sink that delivers fine over a private CA is reported as
"certificate not trusted" by its own connection test. Expected: the probe uses the same TLS settings as send().
"""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest

from .conftest import LIVE_TOOLS  # noqa: F401  (puts tools/live on sys.path)

import certs  # noqa: E402


class _Vendorish(BaseHTTPRequestHandler):
    """GET / -> Elasticsearch root info; POST /services/collector/event (empty) -> HEC 400 'No data' (code 5)."""

    def _send(self, code: int, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        self._send(200, {"name": "es", "version": {"number": "8.19.0"}, "tagline": "You Know, for Search"})

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self._send(400, {"text": "No data", "code": 5})

    def log_message(self, *a: Any) -> None:
        pass


@pytest.fixture
def https(tmp_path: Path) -> Iterator[tuple[str, str]]:
    paths = certs.make(tmp_path / "tls")
    srv = HTTPServer(("127.0.0.1", 0), _Vendorish)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(paths["cert"], paths["key"])
    srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"https://127.0.0.1:{srv.server_address[1]}", str(paths["ca"])
    finally:
        srv.shutdown()
        srv.server_close()


def _entry(iid: str) -> dict[str, Any]:
    from attacklens import integrations_status as ist

    return next(e for e in ist.catalog() if e["id"] == iid)


def _spool(tmp: Path) -> dict[str, str]:
    """State / status under tmp: a cfg without spool.* would default to the repo's data/spool."""
    return {"state_dir": str(tmp / "state"), "status_file": str(tmp / "state" / "status.json")}


@pytest.mark.parametrize("iid", ["splunk_hec", "elastic_bulk"])
def test_sink_connection_test_honours_ca_file(iid: str, https, monkeypatch: pytest.MonkeyPatch,
                                              tmp_path: Path) -> None:
    from attacklens import connect

    url, ca = https
    monkeypatch.setenv("AL_OFFLINE_SINK_SECRET", "offline-sink-secret-0001")
    monkeypatch.delenv("ATTACKLENS_INTEGRATIONS_OVERLAY", raising=False)
    sink = {"enabled": True, "base_url": url, "verify_tls": True, "ca_file": ca, "timeout_s": 5, "index": "al-x",
            "token_env" if iid == "splunk_hec" else "api_key_env": "AL_OFFLINE_SINK_SECRET"}
    res = connect.test_connection(_entry(iid), {"integrations": {"sinks": {iid: sink}, "spool": _spool(tmp_path)}})
    assert res["ok"] is True, f"{iid} probe ignored ca_file: {res.get('error_code')} {res.get('message')}"


def test_sink_connection_test_without_ca_is_untrusted(https, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Control: the same server without the CA must fail as tls_error (so the test above is not vacuous)."""
    from attacklens import connect

    url, _ = https
    monkeypatch.setenv("AL_OFFLINE_SINK_SECRET", "offline-sink-secret-0001")
    sink = {"enabled": True, "base_url": url, "verify_tls": True, "timeout_s": 5, "index": "al-x",
            "api_key_env": "AL_OFFLINE_SINK_SECRET"}
    res = connect.test_connection(_entry("elastic_bulk"), {"integrations": {"sinks": {"elastic_bulk": sink},
                                                                            "spool": _spool(tmp_path)}})
    assert res["ok"] is False and res["error_code"] == "tls_error", res
