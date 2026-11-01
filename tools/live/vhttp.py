"""Tiny stdlib HTTP client for the live-vendor harness (tools/live, backend/tests/live).

Deliberately independent of attacklens.httpc: the harness seeds and verifies the vendor with its own code, so a bug
in the product client can never make a seed or a count look right. Never logs headers or bodies (they carry tokens).
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class Resp:
    status: int
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body or b"{}")

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def basic(user: str, password: str) -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


def ctx(url: str, ca_file: str | None, verify: bool) -> ssl.SSLContext | None:
    if not url.lower().startswith("https"):
        return None
    if verify:
        return ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def req(method: str, url: str, *, headers: dict[str, str] | None = None, form: dict[str, Any] | None = None,
        body: Any = None, raw: bytes | None = None, content_type: str | None = None, ca_file: str | None = None,
        verify: bool = True, timeout: float = 60.0) -> Resp:
    """One request; any HTTP status is returned (never raised). Transport errors raise."""
    h = dict(headers or {})
    data: bytes | None = None
    if form is not None:
        data = urllib.parse.urlencode(form, doseq=True).encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    elif raw is not None:
        data = raw
        if content_type:
            h.setdefault("Content-Type", content_type)
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout, context=ctx(url, ca_file, verify)) as resp:  # noqa: S310
            return Resp(resp.status, resp.read())
    except urllib.error.HTTPError as exc:
        return Resp(exc.code, exc.read() if exc.fp else b"")


def peer_cert_issuer(host: str, port: int) -> str:
    """Issuer CN of the certificate the server presents (no verification): tells which cert a vendor serves."""
    import socket

    c = ctx("https://x", None, False)
    assert c is not None
    with socket.create_connection((host, port), timeout=10) as s, c.wrap_socket(s, server_hostname=host) as t:
        der = t.getpeercert(binary_form=True)
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    return cert.issuer.rfc4514_string()
