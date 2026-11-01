"""Browser-attack guards for the local API (config: pipeline.yaml `api:`).

- Host allowlist (Starlette TrustedHostMiddleware): a DNS-rebinding page (evil.example -> 127.0.0.1) sends
  Host: evil.example and is refused, so it cannot reach /api/uploads/local or /api/runs.
- Origin check on state-changing /api requests (POST/PUT/DELETE/PATCH): multipart and text/plain POSTs are CORS
  "simple requests" the browser sends without a preflight, so CORS alone does not stop a foreign page from
  uploading. A request whose Origin header is present and not allowed (or "null") gets 403. No Origin header
  (curl, scripts, the Vite dev proxy forwarding a same-origin fetch) passes; the API's own origin always passes.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from typing import Any

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

log = logging.getLogger(__name__)

DEFAULT_HOSTS = ("localhost", "127.0.0.1", "[::1]",
                 "testserver")  # Starlette TestClient's Host (single label: not a public DNS name to rebind)
DEFAULT_ORIGINS = ("http://localhost:5173", "http://127.0.0.1:5173")
UNSAFE_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})
_DEFAULT_PORT = {"http": "80", "https": "443"}


def norm_origin(origin: str) -> str:
    """scheme://host[:port], lower-case, default port dropped ('http://LOCALHOST:80' -> 'http://localhost')."""
    o = origin.strip().rstrip("/").lower()
    scheme, sep, netloc = o.partition("://")
    if not sep:
        return o
    host, _, port = netloc.rpartition(":") if netloc.rfind(":") > netloc.rfind("]") else (netloc, "", "")
    return f"{scheme}://{host}" if port in ("", _DEFAULT_PORT.get(scheme)) else f"{scheme}://{host}:{port}"


def guard_config(pipe: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(trusted hosts, allowed origins): the defaults plus pipeline.yaml api.trusted_hosts / api.allowed_origins."""
    api = pipe.get("api") if isinstance(pipe.get("api"), dict) else {}
    hosts = [*DEFAULT_HOSTS, *(str(h).lower() for h in api.get("trusted_hosts") or [])]
    origins = [*DEFAULT_ORIGINS, *(str(o) for o in api.get("allowed_origins") or [])]
    return list(dict.fromkeys(hosts)), list(dict.fromkeys(origins))


class OriginGuard:
    """Pure ASGI middleware (does not wrap the body stream: uploads stay streamed)."""

    def __init__(self, app: ASGIApp, allowed_origins: Iterable[str], prefix: str = "/api") -> None:
        self.app = app
        self.allowed = {norm_origin(o) for o in allowed_origins}
        self.prefix = prefix

    def _ok(self, scope: Scope, headers: Headers) -> bool:
        origin = headers.get("origin")
        if origin is None:
            return True
        o = norm_origin(origin)
        own = norm_origin(f"{scope.get('scheme', 'http')}://{headers.get('host', '')}")
        return o != "null" and (o in self.allowed or o == own)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("method", "").upper() in UNSAFE_METHODS:
            path = scope.get("path", "")
            if path == self.prefix or path.startswith(self.prefix + "/"):
                headers = Headers(scope=scope)
                if not self._ok(scope, headers):
                    log.warning("api: refused %s %s from foreign origin", scope.get("method"), path)
                    body = json.dumps({"detail": "cross-origin request refused"}).encode()
                    await send({"type": "http.response.start", "status": 403,
                                "headers": [(b"content-type", b"application/json"),
                                            (b"content-length", str(len(body)).encode())]})
                    await send({"type": "http.response.body", "body": body})
                    return
        await self.app(scope, receive, send)
