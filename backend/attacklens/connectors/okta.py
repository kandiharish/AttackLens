"""Okta System Log connector: GET {org}/api/v1/logs (since / until / limit / sortOrder=ASCENDING [/ filter]), paged by
following the `Link: <...>; rel="next"` header (same host only), stopping at an empty page or when no next link
is returned (requests always carry `until` = now - ingest_lag, so they are bounded).

Auth (first configured wins):
- token_env: an API token, sent as `Authorization: SSWS <token>` (read-only administrator is enough);
- client_id + private_key_env: an OAuth 2.0 API service app granted `okta.logs.read`; client-credentials grant at
  {org}/oauth2/v1/token with a private_key_jwt client assertion (RS256, cloud_auth). The key is a PEM (one-line
  forms with \\n or spaces are accepted). DPoP-bound tokens are not supported: turn "Require DPoP" off for the app.
Rate limits: X-Rate-Limit-Remaining / -Reset are honoured (saas_http.RateGate): the connector waits for the reset
when few calls remain, and a 429 waits for the reset and retries.

Each event is written as the System Log JSON (LogEvent: uuid, published, eventType, actor, client, outcome, target,
...) into the `okta` spool folder. Record id = uuid, ts = published. The System Log keeps 90 days.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Iterator

from attacklens import httpc
from attacklens import integrations as ig
from attacklens.connectors import catalog_fields as cf
from attacklens.connectors import cloud_auth, saas_http
from attacklens.connectors.base import PAGE_END, AuthError, Connector, Record

log = logging.getLogger("attacklens.connect")

RETENTION_MS = 90 * 86_400_000
LOGS_SCOPE = "okta.logs.read"

CATALOG: dict[str, Any] = {
    "id": "okta", "kind": "identity", "name": "Okta System Log", "modes": ["events"],
    "docs_url": "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/SystemLog/",
    "help": "Minimum permission: an API token of a Read-only Administrator, or an API service app granted the "
            "okta.logs.read scope.",
    "fields": [
        cf.field("base_url", "Okta org URL", "url", True, placeholder="https://your-org.okta.com"),
        cf.secret("token", "API token (SSWS)", help="Admin > Security > API > Tokens. Leave empty to use OAuth."),
        cf.advanced("client_id", "OAuth service app client ID (instead of a token)",
                    placeholder="0oa1b2c3d4e5f6g7h8i9"),
        cf.secret("private_key", "OAuth service app private key (PEM)", advanced=True,
                  help="Paste the PEM; line breaks may be written as \\n. The app needs the okta.logs.read scope "
                       "and 'Require DPoP' off."),
        cf.advanced("events.filter", "System Log filter", placeholder='eventType sw "user.session"',
                    help="Okta filter expression; the time window is added automatically."),
        *cf.common(60, cf.SINCE_OPTIONS + ["90d"]),
    ],
}


class OktaConnector(Connector):
    name = "okta"
    AUTH_ENV_KEYS: tuple[str, ...] = ("token_env", "private_key_env")

    def __init__(self, cfg: dict[str, Any], mode: str, since_ms: int | None = None, reset: bool = False) -> None:
        super().__init__(cfg, mode, since_ms, reset)
        if mode != "events":
            raise ValueError("okta supports mode events only")
        self._cache: cloud_auth.TokenCache | None = None
        self.gate = saas_http.RateGate(int(self.ccfg.get("rate_limit_min_remaining", 2)),
                                       float(self.ccfg.get("max_rate_wait_s", 60)), int(self.ccfg.get("retries", 3)),
                                       self.name)

    # ---- auth ----------------------------------------------------------------------------------------------------
    def base(self) -> str:
        b = str(self.ccfg.get("base_url") or "").strip().rstrip("/")
        p = urllib.parse.urlsplit(b)
        if p.scheme not in ("https", "http") or not p.hostname:
            raise ValueError("okta: set base_url to the Okta org URL, e.g. https://your-org.okta.com")
        return f"{p.scheme}://{p.netloc}"

    def _api_token(self) -> str | None:
        return ig.secret(self.ccfg.get("token_env"))

    def _client_id(self) -> str | None:
        v = ig.secret(self.ccfg.get("client_id_env")) or self.ccfg.get("client_id")
        return str(v) if v else None

    def has_credentials(self) -> bool:
        return bool(self._api_token() or (self._client_id() and ig.secret(self.ccfg.get("private_key_env"))))

    def token_cache(self) -> cloud_auth.TokenCache:
        if self._cache is None:
            pem = cloud_auth.normalize_pem(ig.secret(self.ccfg.get("private_key_env")) or "")
            fetch = cloud_auth.private_key_jwt(
                self.base() + "/oauth2/v1/token", self._client_id() or "", pem,
                str(self.ccfg.get("scope") or LOGS_SCOPE), self.ccfg.get("key_id") or None,
                float(self.ccfg.get("timeout_s") or 30), **self.tls(), retries=int(self.ccfg.get("retries", 3)))
            self._cache = cloud_auth.TokenCache(fetch, float(self.ccfg.get("token_refresh_skew_s", 300)))
        return self._cache

    def _get(self, url: str) -> tuple[Any, dict[str, str]]:
        timeout = float(self.ccfg.get("timeout_s") or 30)
        tls = self.tls()

        def once(auth: str) -> tuple[Any, dict[str, str]]:
            return self.gate.call(lambda: saas_http.get_json("GET", url, {"Authorization": auth}, timeout,
                                                             tls["verify_tls"], tls["ca_file"]))
        tok = self._api_token()
        if tok:
            try:
                return once(f"SSWS {tok}")
            except httpc.HttpError as exc:
                if exc.status in (401, 403):
                    raise AuthError(f"okta: HTTP {exc.status} {ig.vendor_detail(exc.body or '') or ''}".strip()
                                    + "; check the API token and that its admin can read the System Log",
                                    exc.status) from None
                raise
        if not self.has_credentials():
            raise PermissionError("okta: no credentials (token_env, or client_id + private_key_env)")
        return cloud_auth.call_with_token(self.token_cache(), lambda t: once(f"Bearer {t}"), self.name)

    # ---- pull ----------------------------------------------------------------------------------------------------
    def first_url(self, since_ms: int) -> str:
        until = self.until_ms if self.until_ms is not None else ig.now_ms()
        since_ms = max(since_ms, ig.now_ms() - RETENTION_MS + 60_000)
        q: dict[str, str] = {"since": str(ig.iso_ms(since_ms)), "until": str(ig.iso_ms(until)),
                             "limit": str(max(1, min(int(self.ccfg.get("page_size", 1000)), 1000))),
                             "sortOrder": "ASCENDING"}
        flt = " ".join(str(self.mcfg.get("filter") or "").split())
        if flt:
            q["filter"] = flt
        return f"{self.base()}/api/v1/logs?{urllib.parse.urlencode(q)}"

    def pull(self, since_ms: int) -> Iterator[Record]:
        base = self.base()
        url: str | None = self.first_url(since_ms)
        for _ in range(int(self.ccfg.get("max_pages_per_cycle", 100))):
            if url is None:
                return
            data, hdrs = self._get(url)
            if not isinstance(data, list):
                raise httpc.HttpError("okta: /api/v1/logs did not return a JSON array")
            for e in data:
                if isinstance(e, dict):
                    rid = e.get("uuid")
                    yield Record(ig.to_ms(e.get("published")), None if rid is None else str(rid), e, "okta")
            yield PAGE_END
            nxt = saas_http.link_next(hdrs.get("link"))
            if not data or not nxt or nxt == url:
                return
            url = saas_http.require_same_origin(nxt, base, "okta")
        log.info("connect okta: max_pages_per_cycle reached; continuing next cycle")
