"""GCP connector: Cloud Logging `entries.list` (POST https://logging.googleapis.com/v2/entries:list) for Cloud Audit
Logs (filter logName:"cloudaudit.googleapis.com" + a timestamp window), ordered by timestamp asc, paged with
nextPageToken. Auth: a service-account JSON key (the secret's text) -> RS256 JWT -> OAuth access token (cached until
5 min before expiry, refreshed once on HTTP 401). The JWT is signed with `cryptography` (pip extra [cloud]).

Each LogEntry is written as JSON (Stage 0 routes it to `gcp_audit_json`, config/sources.yaml). Record id = insertId.
entries.list allows 60 requests / minute per project: `min_page_interval_s` (default 1.0) spaces the pages.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Iterator

from attacklens import httpc
from attacklens import integrations as ig
from attacklens.connectors import cloud_auth
from attacklens.connectors import catalog_fields as cf
from attacklens.connectors.base import PAGE_END, Connector, Record

log = logging.getLogger("attacklens.connect")

ENTRIES_URL = "https://logging.googleapis.com/v2/entries:list"
DEFAULT_FILTER = 'logName:"cloudaudit.googleapis.com"'
_RES_RE = re.compile(r"^(projects|organizations|folders|billingAccounts)/[A-Za-z0-9_.:-]+"
                     r"(/locations/[A-Za-z0-9_-]+/buckets/[A-Za-z0-9_-]+/views/[A-Za-z0-9_-]+)?$")
MAX_RESOURCE_NAMES = 100  # entries.list limit
_sleep = time.sleep  # tests monkeypatch this

CATALOG: dict[str, Any] = {
    "id": "gcp_logging", "kind": "cloud", "name": "Google Cloud Audit Logs (Cloud Logging)", "modes": ["events"],
    "docs_url": "https://cloud.google.com/iam/docs/keys-create-delete",
    "help": "Minimum permission: roles/logging.viewer (add roles/logging.privateLogViewer for Data Access logs).",
    "fields": [
        cf.field("project_ids", "Project ID(s)", required=True, placeholder="my-project-1, my-project-2"),
        cf.secret("service_account_json", "Service-account JSON key", required=True,
                  help="Paste the whole JSON key file content."),
        cf.advanced("events.filter", "Log filter", default=DEFAULT_FILTER,
                    help="Cloud Logging query; the timestamp window is added automatically."),
        cf.advanced("base_url", "entries:list URL override", "url",
                    help="Empty = https://logging.googleapis.com/v2/entries:list."),
        cf.advanced("token_uri", "OAuth token URI override", "url",
                    help="Empty = the key's token_uri (https://oauth2.googleapis.com/token)."),
        *cf.common(60),
    ],
}


def resource_names(c: dict[str, Any]) -> list[str]:
    raw = c.get("resource_names") or []
    out = [str(r).strip() for r in (raw if isinstance(raw, list) else str(raw).split(",")) if str(r).strip()]
    pids = c.get("project_ids") or []
    for p in pids if isinstance(pids, list) else str(pids).split(","):
        if str(p).strip():
            out.append(f"projects/{str(p).strip()}")
    bad = [r for r in out if not _RES_RE.match(r)]
    if bad:
        raise ValueError(f"gcp_logging: invalid resource name(s) {bad[:3]}")
    if not out:
        raise ValueError("gcp_logging: set project_ids (or resource_names)")
    if len(out) > MAX_RESOURCE_NAMES:
        raise ValueError(f"gcp_logging: at most {MAX_RESOURCE_NAMES} resource names per connector ({len(out)} set)")
    return out


class GcpLoggingConnector(Connector):
    name = "gcp_logging"
    AUTH_ENV_KEYS: tuple[str, ...] = ("service_account_json_env", "token_env")

    def __init__(self, cfg: dict[str, Any], mode: str, since_ms: int | None = None, reset: bool = False) -> None:
        super().__init__(cfg, mode, since_ms, reset)
        if mode != "events":
            raise ValueError("gcp_logging supports mode events only")
        self._cache: cloud_auth.TokenCache | None = None

    def has_credentials(self) -> bool:
        return bool(ig.secret(self.ccfg.get("token_env")) or ig.secret(self.ccfg.get("service_account_json_env")))

    def token_cache(self) -> cloud_auth.TokenCache:
        if self._cache is None:
            info = cloud_auth.parse_service_account(ig.secret(self.ccfg.get("service_account_json_env")))
            fetch = cloud_auth.gcp_service_account(
                info, str(self.ccfg.get("scope") or cloud_auth.GCP_LOGGING_SCOPE), float(self.ccfg.get("timeout_s") or 30),
                **self.tls(), retries=int(self.ccfg.get("retries", 3)), token_uri=self.ccfg.get("token_uri") or None)
            self._cache = cloud_auth.TokenCache(fetch, float(self.ccfg.get("token_refresh_skew_s", 300)))
        return self._cache

    def _list(self, body: dict[str, Any]) -> Any:
        url = str(self.ccfg.get("base_url") or ENTRIES_URL)
        static = ig.secret(self.ccfg.get("token_env"))
        if static:
            return self.http_json("POST", url, body, {"Authorization": f"Bearer {static}"})
        if not ig.secret(self.ccfg.get("service_account_json_env")):
            raise PermissionError("gcp_logging: no service-account key (service_account_json_env)")
        return cloud_auth.call_with_token(
            self.token_cache(), lambda t: self.http_json("POST", url, body, {"Authorization": f"Bearer {t}"}),
            self.name)

    def query_filter(self, since_ms: int) -> str:
        base = " ".join(str(self.mcfg.get("filter") or DEFAULT_FILTER).split())
        until = self.until_ms if self.until_ms is not None else ig.now_ms()
        if re.search(r"\b(OR|NOT)\b|^-", base):  # keep the user's OR / NOT inside its own group
            base = f"({base})"
        return f'{base} AND timestamp>="{ig.iso_ms(since_ms)}" AND timestamp<="{ig.iso_ms(until)}"'

    def pull(self, since_ms: int) -> Iterator[Record]:
        size = max(1, min(int(self.ccfg.get("page_size", 1000)), 1000))
        gap = float(self.ccfg.get("min_page_interval_s", 1.0))
        body: dict[str, Any] = {"resourceNames": resource_names(self.ccfg), "filter": self.query_filter(since_ms),
                                "orderBy": "timestamp asc", "pageSize": size}
        for page in range(int(self.ccfg.get("max_pages_per_cycle", 100))):
            if page and gap > 0:
                _sleep(gap)
            res = self._list(body)
            for e in (res.get("entries") or []) if isinstance(res, dict) else []:
                if not isinstance(e, dict):
                    continue
                rid = e.get("insertId")
                yield Record(ig.to_ms(e.get("timestamp") or e.get("receiveTimestamp")),
                             None if rid is None else f"{e.get('logName', '')}|{rid}", e, "gcp_audit")
            yield PAGE_END
            tok = res.get("nextPageToken") if isinstance(res, dict) else None
            if not tok:
                return
            body["pageToken"] = tok
        log.info("connect gcp_logging: max_pages_per_cycle reached; continuing next cycle")
