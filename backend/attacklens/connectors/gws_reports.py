"""Google Workspace audit via the Admin SDK Reports API: activities.list
(GET {base}/admin/reports/v1/activity/users/all/applications/{application}?startTime=&endTime=&maxResults=&pageToken=)
for login, admin, token and drive by default (configurable).

Auth: a service-account JSON key with domain-wide delegation for
https://www.googleapis.com/auth/admin.reports.audit.readonly, impersonating an administrator (`delegated_admin`, the
JWT `sub`): RS256 JWT -> OAuth token (cloud_auth, `cryptography` from the [cloud] extra), cached, refreshed once on
HTTP 401. A static token (token_env) overrides.

The window [since, until] is cut into `window` slices (default 1 h) walked oldest first; in a slice every
application is paged completely (the API returns newest first) before PAGE_END, so the checkpoint only moves past
whole slices. Record ts = id.time, id = application|uniqueQualifier|time. Each activity is written as the Reports
API JSON (kind admin#reports#activity) into the `gws_reports` spool folder. The Reports API publishes some
applications with a lag of up to hours: raise `overlap` (default 1h) for them.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any, Iterator

from attacklens import httpc
from attacklens import integrations as ig
from attacklens.connectors import catalog_fields as cf
from attacklens.connectors import cloud_auth, saas_http
from attacklens.connectors.base import PAGE_END, Connector, Record

log = logging.getLogger("attacklens.connect")

REPORTS_URL = "https://admin.googleapis.com"
REPORTS_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
DEFAULT_APPLICATIONS = ("login", "admin", "token", "drive")
RETENTION_MS = 180 * 86_400_000
_APP_RE = re.compile(r"^[a-z][a-z_]{1,40}$")
_CUSTOMER_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")

CATALOG: dict[str, Any] = {
    "id": "gws_reports", "kind": "identity", "name": "Google Workspace audit (Reports API)", "modes": ["events"],
    "docs_url": "https://developers.google.com/admin-sdk/reports/v1/guides/delegation",
    "help": "Minimum permission: a service account with domain-wide delegation for "
            "https://www.googleapis.com/auth/admin.reports.audit.readonly, impersonating an admin with the "
            "Reports privilege.",
    "fields": [
        cf.secret("service_account_json", "Service-account JSON key", required=True,
                  help="Paste the whole JSON key file content."),
        cf.field("delegated_admin", "Admin user to impersonate", required=True, placeholder="admin@example.com",
                 help="Domain-wide delegation subject: a Workspace admin allowed to read audit reports."),
        cf.advanced("events.applications", "Applications", default=", ".join(DEFAULT_APPLICATIONS),
                    help="Comma-separated Reports API applications, e.g. login, admin, token, drive, saml."),
        cf.advanced("customer_id", "Customer ID", placeholder="C01234567",
                    help="Empty = the admin's own customer (my_customer)."),
        cf.advanced("base_url", "Reports API URL override", "url",
                    help="Empty = https://admin.googleapis.com."),
        cf.advanced("token_uri", "OAuth token URI override", "url",
                    help="Empty = the key's token_uri (https://oauth2.googleapis.com/token)."),
        *cf.common(300),
    ],
}


def endpoints(c: dict[str, Any]) -> list[str]:
    return [str(c.get("base_url") or REPORTS_URL), str(c.get("token_uri") or cloud_auth.GCP_TOKEN_URI)]


def test_connection(cfg: dict[str, Any]) -> dict[str, Any]:
    """Connection test (POST /api/integrations/gws_reports/test): one activities.list call (maxResults 1, last 5 min)
    with the real sign-in. The generic probe would make no call at all: the window ends before now - ingest_lag."""
    c = GwsReportsConnector(cfg, "events")
    c.ccfg.update(timeout_s=min(float(c.ccfg.get("timeout_s") or 10), 10.0), page_size=1)
    now = ig.now_ms()
    res = c._get(c.url(applications(c.mcfg.get("applications"))[0], now - 300_000, now, None))
    items = (res.get("items") or []) if isinstance(res, dict) else []
    newest = items[0].get("id", {}).get("time") if items and isinstance(items[0], dict) else None
    return {"ok": True, "sample_count": len(items), "newest": newest}


def applications(v: Any) -> list[str]:
    out = saas_http.as_list(v) or list(DEFAULT_APPLICATIONS)
    bad = [a for a in out if not _APP_RE.match(a)]
    if bad:
        raise ValueError(f"gws_reports: invalid application name(s) {bad[:3]}")
    return list(dict.fromkeys(out))


class GwsReportsConnector(Connector):
    name = "gws_reports"
    AUTH_ENV_KEYS: tuple[str, ...] = ("service_account_json_env", "token_env")

    def __init__(self, cfg: dict[str, Any], mode: str, since_ms: int | None = None, reset: bool = False) -> None:
        super().__init__(cfg, mode, since_ms, reset)
        if mode != "events":
            raise ValueError("gws_reports supports mode events only")
        self._cache: cloud_auth.TokenCache | None = None

    def has_credentials(self) -> bool:
        return bool(ig.secret(self.ccfg.get("token_env")) or ig.secret(self.ccfg.get("service_account_json_env")))

    def subject(self) -> str:
        s = ig.secret(self.ccfg.get("delegated_admin_env")) or self.ccfg.get("delegated_admin")
        if not s or "@" not in str(s):
            raise ValueError("gws_reports: set delegated_admin (the admin e-mail the service account impersonates)")
        return str(s).strip()

    def token_cache(self) -> cloud_auth.TokenCache:
        if self._cache is None:
            info = cloud_auth.parse_service_account(ig.secret(self.ccfg.get("service_account_json_env")))
            fetch = cloud_auth.gcp_service_account(
                info, str(self.ccfg.get("scope") or REPORTS_SCOPE), float(self.ccfg.get("timeout_s") or 30),
                **self.tls(), retries=int(self.ccfg.get("retries", 3)), token_uri=self.ccfg.get("token_uri") or None,
                subject=self.subject())
            self._cache = cloud_auth.TokenCache(fetch, float(self.ccfg.get("token_refresh_skew_s", 300)))
        return self._cache

    def _get(self, url: str) -> Any:
        static = ig.secret(self.ccfg.get("token_env"))
        if static:
            return self.http_json("GET", url, None, {"Authorization": f"Bearer {static}"})
        if not ig.secret(self.ccfg.get("service_account_json_env")):
            raise PermissionError("gws_reports: no service-account key (service_account_json_env)")
        return cloud_auth.call_with_token(
            self.token_cache(), lambda t: self.http_json("GET", url, None, {"Authorization": f"Bearer {t}"}),
            self.name)

    def url(self, app: str, lo: int, hi: int, page_token: str | None) -> str:
        q = {"startTime": str(ig.iso_ms(lo)), "endTime": str(ig.iso_ms(hi)),
             "maxResults": str(max(1, min(int(self.ccfg.get("page_size", 1000)), 1000)))}
        cust = self.ccfg.get("customer_id")
        if cust:
            if not _CUSTOMER_RE.match(str(cust)):
                raise ValueError("gws_reports: invalid customer_id")
            q["customerId"] = str(cust)
        if page_token:
            q["pageToken"] = page_token
        base = str(self.ccfg.get("base_url") or REPORTS_URL).rstrip("/")
        return f"{base}/admin/reports/v1/activity/users/all/applications/{app}?{urllib.parse.urlencode(q)}"

    def pull(self, since_ms: int) -> Iterator[Record]:
        apps = applications(self.mcfg.get("applications"))
        self.subject()
        until = self.until_ms if self.until_ms is not None else ig.now_ms()
        lo = max(since_ms, ig.now_ms() - RETENTION_MS + 60_000)
        win = max(60_000, ig.parse_duration_ms(self.mcfg.get("window", "1h")))
        for _ in range(int(self.ccfg.get("max_windows_per_cycle", 48))):
            if lo > until:
                return
            hi = min(until, lo + win)
            for app in apps:
                tok: str | None = None
                for _page in range(int(self.ccfg.get("max_pages_per_window", 1000))):
                    res = self._get(self.url(app, lo, hi, tok))
                    for a in (res.get("items") or []) if isinstance(res, dict) else []:
                        if not isinstance(a, dict):
                            continue
                        aid = a.get("id") if isinstance(a.get("id"), dict) else {}
                        t, uq = aid.get("time"), aid.get("uniqueQualifier")
                        rid = None if t is None and uq is None else f"{aid.get('applicationName') or app}|{uq}|{t}"
                        yield Record(ig.to_ms(t), rid, a, "gws_reports")
                    tok = res.get("nextPageToken") if isinstance(res, dict) else None
                    if not tok:
                        break
                else:
                    raise httpc.HttpError(f"gws_reports: more than max_pages_per_window pages for {app}")
            yield PAGE_END  # slice complete for every application: safe commit point
            lo = hi + 1
        log.info("connect gws_reports: max_windows_per_cycle reached; continuing next cycle")
