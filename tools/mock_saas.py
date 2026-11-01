"""Mock SaaS audit-log APIs for the okta, m365_ual and gws_reports connectors (stdlib only, loopback only).

    python tools/mock_saas.py --port 9300 [--okta-token T] [--m365-secret S] ...     (offline demo)
    with MockSaaS(okta_token="t") as m: m.url ...                                   (tests: free 127.0.0.1 port)

  Okta    GET  /api/v1/logs?since&until&limit(1..1000)&sortOrder&filter&after   JSON array; Link rel="self" / rel="next"
               (next while rows remain; always for a polling request without until); X-Rate-Limit-Limit / -Remaining
               / -Reset on every answer, 429 E0000047 past the limit of the window; auth `SSWS <api token>` or
               `Bearer <token>` from POST /oauth2/v1/token (client_credentials + private_key_jwt client assertion:
               RS256 header, iss = sub = client id, aud = the token URL, exp - iat <= 1 h, jti unused; signature NOT
               verified; scope must include okta.logs.read). filter: `eventType eq|sw "x"` only.
  M365    POST /{tenant}/oauth2/v2.0/token   client_credentials -> bearer for the requested /.default audience
          GET  /api/v1.0/{tenant}/activity/feed/subscriptions/list
          POST /api/v1.0/{tenant}/activity/feed/subscriptions/start?contentType=  (400 AF20024 when already enabled)
          GET  /api/v1.0/{tenant}/activity/feed/subscriptions/content?contentType&startTime&endTime  blob list, by
               contentCreated, `m365_page_size` per page, NextPageUri header; 400 AF20055 for a window > 24 h, older
               than 7 days or with one bound only; 400 AF20022 without an enabled subscription
          GET  /api/v1.0/{tenant}/activity/feed/audit/{contentId}   the blob: JSON array of audit records
          Tokens must have the audience https://manage.office.com/.default and the path tenant.
  Google  POST /token   JWT-bearer grant; `sub` (domain-wide delegation) must be a delegated admin when configured,
               else 401 unauthorized_client; scope must include admin.reports.audit.readonly
          GET  /admin/reports/v1/activity/users/all/applications/{app}?startTime&endTime&maxResults&pageToken
               newest first, nextPageToken bound to the query; a token without `sub` gets 403 (not an admin)
  Control GET /_mock/saas/stats, GET /_mock/saas/ground_truth, POST /_mock/saas {expire_tokens: vendor|null,
          okta_rate_limit, okta_rate_window_s, fail: {path, status, times}}
Seed data (tools/mock_saas_seed.py) is anchored ~6 h before start; labels exist only at /_mock/saas/ground_truth.
"""

from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import json
import logging
import math
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mock_saas_seed as seed  # noqa: E402

log = logging.getLogger("mock_saas")
MANAGE_AUD = "https://manage.office.com/.default"
GWS_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
GWS_APPS = {"login", "admin", "token", "drive", "saml", "user_accounts", "groups", "mobile", "rules", "chat",
            "meet", "calendar", "gcp", "context_aware_access", "access_transparency"}
DAY_MS = 86_400_000


def b64u_json(part: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def parse_ts(v: str | None, strict_z: bool = True) -> int | None:
    """ISO 8601 -> epoch ms; strict_z requires a Z / offset (Okta, Google); M365 takes naive UTC."""
    from datetime import datetime, timezone
    if not v:
        return None
    s = v.strip().replace("Z", "+00:00")
    if strict_z and not re.search(r"[+-]\d\d:\d\d$", s):
        return None
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    return int((d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp() * 1000)


def bound_token(offset: int, query: Any) -> str:
    h = hashlib.sha256(json.dumps(query, sort_keys=True).encode()).hexdigest()[:12]
    return base64.urlsafe_b64encode(json.dumps({"o": offset, "h": h}).encode()).decode().rstrip("=")


def read_bound(tok: str, query: Any) -> int | None:
    try:
        d = b64u_json(tok)
        return d["o"] if d["h"] == b64u_json(bound_token(0, query))["h"] and isinstance(d["o"], int) else None
    except Exception:  # noqa: BLE001 - garbage token
        return None


def jwt_parts(tok: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    p = tok.split(".")
    try:
        if len(p) != 3 or not p[2]:
            return None
        h, c = b64u_json(p[0]), b64u_json(p[1])
    except Exception:  # noqa: BLE001
        return None
    return (h, c) if isinstance(h, dict) and isinstance(c, dict) and h.get("alg") == "RS256" else None


def jwt_times_ok(c: dict[str, Any]) -> bool:
    now, iat, exp = time.time(), c.get("iat"), c.get("exp")
    return isinstance(iat, (int, float)) and isinstance(exp, (int, float)) and 0 < exp - iat <= 3600 \
        and exp > now - 60 and iat < now + 300


class MockSaaS:
    def __init__(self, *, host: str = "127.0.0.1", port: int = 0, anchor_ms: int | None = None,
                 okta_token: str | None = None, okta_client_id: str | None = None,
                 okta_rate_limit: int = 600, okta_rate_window_s: float = 60.0,
                 m365_tenant: str = seed.TENANT, m365_client_id: str | None = None, m365_secret: str | None = None,
                 m365_page_size: int = 3, gws_client_email: str | None = None,
                 gws_admins: tuple[str, ...] | None = None, token_ttl_s: int = 3599) -> None:
        self.host, self.port = host, port
        self.anchor_ms = anchor_ms if anchor_ms is not None else seed.now_anchor(int(time.time() * 1000))
        self.seed = seed.build(self.anchor_ms)
        self.okta_token, self.okta_client_id = okta_token, okta_client_id
        self.okta_rate_limit, self.okta_rate_window_s = okta_rate_limit, okta_rate_window_s
        self.m365_tenant, self.m365_client_id, self.m365_secret = m365_tenant, m365_client_id, m365_secret
        self.m365_page_size, self.token_ttl_s = m365_page_size, token_ttl_s
        self.gws_client_email, self.gws_admins = gws_client_email, gws_admins
        self.subscriptions: dict[str, str] = {}
        self.tokens: dict[str, dict[str, Any]] = {}
        self.jtis: set[str] = set()
        self.stats: collections.Counter[str] = collections.Counter()
        self.publishers: set[str] = set()
        self.rate: list[float] = [0.0, 0]      # [window start (epoch s), calls in window]
        self.faults: list[dict[str, Any]] = []
        self.lock = threading.RLock()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "MockSaaS":
        self._httpd = ThreadingHTTPServer((self.host, self.port), _make_handler(self))
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, args=(0.05,), daemon=True,
                                        name="mock-saas-http")
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "MockSaaS":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # ------------------------------------------------------------------ state helpers
    def issue(self, vendor: str, **info: Any) -> str:
        tok = f"mock-{vendor}-" + secrets.token_hex(16)
        with self.lock:
            self.tokens[tok] = {"vendor": vendor, "exp": time.monotonic() + self.token_ttl_s, **info}
            self.stats[f"token_{vendor}"] += 1
        return tok

    def bearer(self, vendor: str, authz: str) -> dict[str, Any] | None:
        if not authz.startswith("Bearer "):
            return None
        with self.lock:
            t = self.tokens.get(authz[7:].strip())
        return t if t and t["vendor"] == vendor and time.monotonic() < t["exp"] else None

    def expire_tokens(self, vendor: str | None = None) -> int:
        with self.lock:
            hit = [t for t, v in self.tokens.items() if vendor in (None, v["vendor"])]
            for t in hit:
                self.tokens[t]["exp"] = 0.0
        return len(hit)

    def fail(self, path_re: str, status: int, times: int = 1) -> None:
        with self.lock:
            self.faults.append({"path": path_re, "status": status, "times": times})

    def take_fault(self, path: str) -> int | None:
        with self.lock:
            for f in self.faults:
                if f["times"] > 0 and re.search(f["path"], path):
                    f["times"] -= 1
                    return int(f["status"])
        return None

    def okta_rate(self) -> tuple[bool, dict[str, str]]:
        """Count one Okta call; (allowed, X-Rate-Limit headers)."""
        with self.lock:
            now = time.time()
            if now >= self.rate[0] + self.okta_rate_window_s:
                self.rate = [now, 0]
            self.rate[1] += 1
            used, start = int(self.rate[1]), self.rate[0]
        reset = math.ceil(start + self.okta_rate_window_s)
        hdr = {"X-Rate-Limit-Limit": str(self.okta_rate_limit),
               "X-Rate-Limit-Remaining": str(max(0, self.okta_rate_limit - used)), "X-Rate-Limit-Reset": str(reset)}
        return used <= self.okta_rate_limit, hdr

    def ground_truth(self) -> dict[str, Any]:
        return {"anchor_ms": self.anchor_ms, "counts": seed.counts(self.seed), "attack_steps": self.seed.truth}


def _make_handler(m: MockSaaS) -> type[BaseHTTPRequestHandler]:
    import mock_saas_api as api  # vendor handlers (kept apart: module size)

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        disable_nagle_algorithm = True     # headers and body go out in two writes: no 100+ ms Nagle stall
        mock = m

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("%s " + fmt, self.address_string(), *args)

        def send_json(self, status: int, payload: Any, headers: dict[str, str] | None = None) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _do(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            sp = urlsplit(self.path)
            params = dict(parse_qsl(sp.query, keep_blank_values=True))
            with m.lock:
                m.stats["requests"] += 1
            st = m.take_fault(sp.path)
            if st is not None:
                return self.send_json(st, {"error": {"code": "MockFault", "message": f"injected HTTP {st}"}})
            try:
                api.route(self, sp.path, params, body)
            except Exception as exc:  # noqa: BLE001 - a mock bug must answer, not hang the connector
                log.exception("mock_saas: handler error")
                self.send_json(500, {"error": {"code": "MockError", "message": type(exc).__name__}})

        do_GET = do_POST = do_DELETE = _do

    return H


def query_url(base: str, path: str, params: dict[str, str]) -> str:
    return f"{base}{path}?{urlencode(params)}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mock_saas", description=__doc__.split("\n")[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9300)
    ap.add_argument("--okta-token")
    ap.add_argument("--m365-secret")
    ap.add_argument("--gws-admin", action="append")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    m = MockSaaS(host=a.host, port=a.port, okta_token=a.okta_token, m365_secret=a.m365_secret,
                 gws_admins=tuple(a.gws_admin) if a.gws_admin else None).start()
    log.info("mock SaaS listening on %s (Ctrl+C to stop); counts %s", m.url, seed.counts(m.seed))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        m.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
