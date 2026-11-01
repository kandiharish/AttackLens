"""Microsoft 365 unified audit log via the Office 365 Management Activity API (no SDK, plain HTTPS).

Auth: an Entra ID app registration with the Office 365 Management APIs application permission ActivityFeed.Read
(admin consent); client-credentials token for `https://manage.office.com/.default` (cloud_auth; the sovereign hosts
get their own audience), cached, refreshed once on HTTP 401.

Per cycle:
1. subscriptions: GET {base}/api/v1.0/{tenant}/activity/feed/subscriptions/list; every configured content type
   that is not `enabled` is started (POST subscriptions/start?contentType=...) when auto_start_subscriptions is on
   (AF20024 "already enabled" is fine), else the cycle fails naming the content type.
2. content: GET subscriptions/content?contentType=&startTime=&endTime= per content type, in slices of at most 24 h
   (API limit), never older than 7 days (API limit), paged with the `NextPageUri` response header (same host only).
3. blobs of one slice, all content types, in contentCreated order: GET contentUri (same host only) -> JSON array of
   audit records; PAGE_END after each blob (commit point).
The checkpoint walks contentCreated (when the blob became available, like the S3 LastModified of aws_cloudtrail);
each record keeps its own CreationTime. Record id = the record's Id (a re-listed blob is deduped by id).
Records are written as the Management API JSON into the `m365_ual` spool folder.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Iterator

from attacklens import httpc
from attacklens import integrations as ig
from attacklens.connectors import catalog_fields as cf
from attacklens.connectors import cloud_auth, saas_http
from attacklens.connectors.base import PAGE_END, Connector, Record

log = logging.getLogger("attacklens.connect")

MANAGE_URL = "https://manage.office.com"
DEFAULT_CONTENT_TYPES = ("Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General")
CONTENT_TYPES = DEFAULT_CONTENT_TYPES + ("DLP.All",)
# token audience per API host (Microsoft 365 GCC High / DoD use their own); anything else -> manage.office.com
SCOPES = {"manage.office.com": "https://manage.office.com/.default",
          "manage-gcc.office.com": "https://manage-gcc.office.com/.default",
          "manage.office365.us": "https://manage.office365.us/.default",
          "manage.protection.apps.mil": "https://manage.protection.apps.mil/.default"}
MAX_SLICE_MS = 24 * 3_600_000
RETENTION_MS = 7 * 86_400_000
_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$")

CATALOG: dict[str, Any] = {
    "id": "m365_ual", "kind": "identity", "name": "Microsoft 365 audit log (Management Activity API)",
    "modes": ["events"],
    "docs_url": "https://learn.microsoft.com/en-us/office/office-365-management-api/"
                "get-started-with-office-365-management-apis",
    "help": "Minimum permission: an app registration with the Office 365 Management APIs application permission "
            "ActivityFeed.Read (admin consent). Auditing must be on in Microsoft Purview.",
    "fields": [
        cf.field("tenant_id", "Tenant ID", required=True, placeholder="00000000-0000-0000-0000-000000000000"),
        cf.field("client_id", "Client (application) ID", required=True,
                 placeholder="00000000-0000-0000-0000-000000000000"),
        cf.secret("client_secret", "Client secret", required=True),
        cf.advanced("events.content_types", "Content types", default=", ".join(DEFAULT_CONTENT_TYPES),
                    help="Comma-separated: Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint, "
                         "Audit.General, DLP.All."),
        cf.advanced("auto_start_subscriptions", "Start missing subscriptions", "bool", default=True,
                    help="POST subscriptions/start for a content type that is not enabled yet."),
        cf.advanced("base_url", "Management API URL override", "url",
                    help="Empty = https://manage.office.com (GCC: https://manage-gcc.office.com, GCC High: "
                         "https://manage.office365.us)."),
        cf.advanced("login_url", "Entra ID login URL override", "url",
                    help="Empty = https://login.microsoftonline.com."),
        *cf.common(300, ["1h", "24h", "7d"]),
    ],
}


def endpoints(c: dict[str, Any]) -> list[str]:
    return [str(c.get("base_url") or MANAGE_URL), str(c.get("login_url") or cloud_auth.AZURE_LOGIN_URL)]


def test_connection(cfg: dict[str, Any]) -> dict[str, Any]:
    """Connection test: sign in + GET subscriptions/list (read only: a test never starts a subscription)."""
    c = M365UalConnector(cfg, "events")
    c.ccfg["timeout_s"] = min(float(c.ccfg.get("timeout_s") or 10), 10.0)
    content_types(c.mcfg.get("content_types"))
    c._call("GET", c.feed("subscriptions/list"))
    return {"ok": True, "sample_count": 0, "newest": None}


def content_types(v: Any) -> list[str]:
    out = saas_http.as_list(v) or list(DEFAULT_CONTENT_TYPES)
    bad = [t for t in out if t not in CONTENT_TYPES]
    if bad:
        raise ValueError(f"m365_ual: unknown content type(s) {bad[:3]}; one of {', '.join(CONTENT_TYPES)}")
    return list(dict.fromkeys(out))


def api_time(ms: int) -> str:
    """startTime / endTime format of the API (UTC, seconds)."""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


class M365UalConnector(Connector):
    name = "m365_ual"
    AUTH_ENV_KEYS: tuple[str, ...] = ("client_secret_env",)

    def __init__(self, cfg: dict[str, Any], mode: str, since_ms: int | None = None, reset: bool = False) -> None:
        super().__init__(cfg, mode, since_ms, reset)
        if mode != "events":
            raise ValueError("m365_ual supports mode events only")
        self._cache: cloud_auth.TokenCache | None = None
        self.subscribed: set[str] = set()

    # ---- auth ----------------------------------------------------------------------------------------------------
    def _creds(self) -> tuple[str | None, str | None, str | None]:
        c = self.ccfg
        tenant = ig.secret(c.get("tenant_id_env")) or c.get("tenant_id")
        client = ig.secret(c.get("client_id_env")) or c.get("client_id")
        return (str(tenant) if tenant else None, str(client) if client else None,
                ig.secret(c.get("client_secret_env")))

    def has_credentials(self) -> bool:
        return all(self._creds())

    def base(self) -> str:
        return str(self.ccfg.get("base_url") or MANAGE_URL).rstrip("/")

    def tenant(self) -> str:
        t = self._creds()[0]
        if not t or not _TENANT_RE.match(t):
            raise ValueError("m365_ual: set tenant_id (the directory / tenant GUID)")
        return t

    def scope(self) -> str:
        host = (urllib.parse.urlsplit(self.base()).hostname or "").lower()
        return str(self.ccfg.get("scope") or SCOPES.get(host, SCOPES["manage.office.com"]))

    def token_cache(self) -> cloud_auth.TokenCache:
        if self._cache is None:
            tenant, client, sec = self._creds()
            fetch = cloud_auth.azure_client_credentials(
                tenant or "", client or "", sec or "", self.scope(),
                str(self.ccfg.get("login_url") or cloud_auth.AZURE_LOGIN_URL), float(self.ccfg.get("timeout_s") or 60),
                **self.tls(), retries=int(self.ccfg.get("retries", 3)))
            self._cache = cloud_auth.TokenCache(fetch, float(self.ccfg.get("token_refresh_skew_s", 300)))
        return self._cache

    def _call(self, method: str, url: str) -> tuple[Any, dict[str, str]]:
        saas_http.require_same_origin(url, self.base(), self.name)
        timeout, tls = float(self.ccfg.get("timeout_s") or 60), self.tls()
        body = b"" if method == "POST" else None

        def once(tok: str) -> tuple[Any, dict[str, str]]:
            return httpc.with_retries(lambda: saas_http.get_json(
                method, url, {"Authorization": f"Bearer {tok}"}, timeout, tls["verify_tls"], tls["ca_file"], body),
                int(self.ccfg.get("retries", 3)), what=f"{method} {httpc.safe_url(url)}")
        if not self.has_credentials():
            raise PermissionError("m365_ual: no credentials (tenant_id + client_id + client_secret_env)")
        return cloud_auth.call_with_token(self.token_cache(), once, self.name)

    # ---- feed ----------------------------------------------------------------------------------------------------
    def feed(self, path: str, **q: str) -> str:
        pub = str(self.ccfg.get("publisher_id") or self.tenant())
        q = {**q, "PublisherIdentifier": pub}
        return f"{self.base()}/api/v1.0/{self.tenant()}/activity/feed/{path}?{urllib.parse.urlencode(q)}"

    def ensure_subscriptions(self, types: list[str]) -> None:
        if set(types) <= self.subscribed:
            return
        data, _ = self._call("GET", self.feed("subscriptions/list"))
        on = {str(s.get("contentType")) for s in data if isinstance(s, dict)
              and str(s.get("status") or "").lower() == "enabled"} if isinstance(data, list) else set()
        missing = [t for t in types if t not in on]
        if missing and not self.ccfg.get("auto_start_subscriptions", True):
            raise ValueError(f"m365_ual: no enabled subscription for {', '.join(missing)}; start it or set "
                             f"auto_start_subscriptions: true")
        for t in missing:
            try:
                self._call("POST", self.feed("subscriptions/start", contentType=t))
                log.info("connect m365_ual: started the %s subscription", t)
            except httpc.HttpError as exc:
                if exc.status != 400 or "AF20024" not in (exc.body or ""):   # AF20024 = already enabled
                    raise
        self.subscribed |= set(types)

    def list_blobs(self, ctype: str, lo: int, hi: int) -> list[tuple[int, str, str]]:
        """(contentCreated ms, contentId, contentUri) of one content type in [lo, hi], all NextPageUri pages."""
        out: list[tuple[int, str, str]] = []
        url: str | None = self.feed("subscriptions/content", contentType=ctype, startTime=api_time(lo),
                                    endTime=api_time(hi))
        for _ in range(int(self.ccfg.get("max_list_pages", 1000))):
            if not url:
                return out
            data, hdrs = self._call("GET", url)
            for b in data if isinstance(data, list) else []:
                if isinstance(b, dict) and b.get("contentUri"):
                    out.append((ig.to_ms(b.get("contentCreated")) or lo, str(b.get("contentId") or ""),
                                str(b["contentUri"])))
            url = hdrs.get("nextpageuri") or None
        raise httpc.HttpError(f"m365_ual: more than max_list_pages content pages for {ctype}")

    def pull(self, since_ms: int) -> Iterator[Record]:
        types = content_types(self.mcfg.get("content_types"))
        self.ensure_subscriptions(types)
        until = self.until_ms if self.until_ms is not None else ig.now_ms()
        lo = max(since_ms, ig.now_ms() - RETENTION_MS + 120_000)
        if lo > since_ms:
            log.warning("connect m365_ual: window start moved to %s (the API keeps content 7 days)", ig.iso_ms(lo))
        slice_ms = max(60_000, min(MAX_SLICE_MS, ig.parse_duration_ms(self.mcfg.get("window", "24h"))))
        budget = int(self.ccfg.get("max_blobs_per_cycle", 500))
        while lo <= until:
            hi = min(until, lo + slice_ms - 1000)
            blobs = sorted((created, cid, uri) for t in types for created, cid, uri in self.list_blobs(t, lo, hi))
            for created, _cid, uri in blobs:
                if budget <= 0:
                    log.info("connect m365_ual: max_blobs_per_cycle reached; continuing next cycle")
                    return
                budget -= 1
                data, _ = self._call("GET", uri)
                for r in data if isinstance(data, list) else []:
                    if isinstance(r, dict):
                        rid = r.get("Id")
                        yield Record(created, None if rid is None else str(rid), r, "m365_ual")
                yield PAGE_END
            lo = hi + 1000
