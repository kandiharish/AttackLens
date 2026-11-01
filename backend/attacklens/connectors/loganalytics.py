"""Azure Log Analytics query API (`POST {base_url}/v1/workspaces/{id}/query`, KQL), shared by the sentinel and
azure_monitor connectors.

Auth (first that is configured wins):
- token_env: a static bearer token (override; expires after about 1 h, no refresh possible);
- tenant_id(_env) + client_id(_env) + client_secret_env: Entra ID client credentials (cloud_auth), token cached until
  5 min before expiry, refreshed once on HTTP 401.

Paging:
- keyset (query template contains {after}): rows ordered by (TimeGenerated, <keyset_column>); each next page adds
  `| where TimeGenerated > datetime(T) or (TimeGenerated == datetime(T) and <col> > "<id>")` with T = the last row's
  full-precision timestamp, so any number of rows at one timestamp pages correctly.
- legacy template (no {after}): `TimeGenerated >= {since}` per page; fails loudly if a whole page shares one
  timestamp (raise page_size or use a keyset template).
Placeholders: {since} {until} (ISO, ms) {after} {page_size} {tables}.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Iterator

from attacklens import httpc
from attacklens import integrations as ig
from attacklens.connectors import cloud_auth
from attacklens.connectors.base import PAGE_END, Connector, Record

log = logging.getLogger("attacklens.connect")

LA_SCOPE = "https://api.loganalytics.io/.default"   # token audience stays .io for both API hosts
LA_BASE_URL = "https://api.loganalytics.azure.com"
DEFAULT_TIMEOUT_S = 180.0
_COL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def kql_str(v: str) -> str:
    """KQL string literal (double-quoted, backslash-escaped). Values come from the SIEM: never pasted raw."""
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r") + '"'


def kql_dt(v: str) -> str:
    """datetime(...) literal from a vendor timestamp string; only ISO characters are allowed through."""
    s = str(v)
    if not re.fullmatch(r"[0-9T:.\-+Z ]{10,40}", s):
        raise httpc.HttpError(f"log analytics: unexpected timestamp value {s[:40]!r}")
    return f"datetime({s})"


class LogAnalyticsConnector(Connector):
    name = "loganalytics"
    AUTH_ENV_KEYS: tuple[str, ...] = ("token_env", "client_secret_env")

    def __init__(self, cfg: dict[str, Any], mode: str, since_ms: int | None = None, reset: bool = False) -> None:
        super().__init__(cfg, mode, since_ms, reset)
        self._cache: cloud_auth.TokenCache | None = None

    # ---- auth ----------------------------------------------------------------------------------------------------
    def _client_creds(self) -> tuple[str | None, str | None, str | None]:
        c = self.ccfg
        tenant = ig.secret(c.get("tenant_id_env")) or c.get("tenant_id")
        client = ig.secret(c.get("client_id_env")) or c.get("client_id")
        return (str(tenant) if tenant else None, str(client) if client else None,
                ig.secret(c.get("client_secret_env")))

    def static_token(self) -> str | None:
        return ig.secret(self.ccfg.get("token_env"))

    def has_credentials(self) -> bool:
        if self.static_token():
            return True
        return all(self._client_creds())

    def token_cache(self) -> cloud_auth.TokenCache | None:
        if self._cache is None:
            tenant, client, sec = self._client_creds()
            if not (tenant and client and sec):
                return None
            fetch = cloud_auth.azure_client_credentials(
                tenant, client, sec, str(self.ccfg.get("scope") or LA_SCOPE),
                str(self.ccfg.get("login_url") or cloud_auth.AZURE_LOGIN_URL),
                float(self.ccfg.get("timeout_s") or 30), **self.tls(), retries=int(self.ccfg.get("retries", 3)))
            self._cache = cloud_auth.TokenCache(fetch, float(self.ccfg.get("token_refresh_skew_s", 300)))
        return self._cache

    def headers(self) -> dict[str, str]:
        tok = self.static_token()
        if not tok:
            cache = self.token_cache()
            tok = cache.get() if cache else None
        return {"Authorization": f"Bearer {tok}"} if tok else {}

    def _query(self, url: str, q: str) -> Any:
        tok = self.static_token()
        timeout = float(self.ccfg.get("timeout_s") or DEFAULT_TIMEOUT_S)
        # server-side query timeout a little below ours, so the API answers (partial error) before we hang up
        prefer = {"Prefer": f"wait={max(1, int(timeout) - 5)}"}
        if tok:  # static override: no refresh possible, a 401 is reported as is
            return self.http_json("POST", url, {"query": q}, {"Authorization": f"Bearer {tok}", **prefer},
                                  timeout=timeout)
        cache = self.token_cache()
        if cache is None:
            raise PermissionError(f"{self.name}: no credentials (token_env, or tenant_id + client_id + client_secret_env)")
        return cloud_auth.call_with_token(
            cache, lambda t: self.http_json("POST", url, {"query": q}, {"Authorization": f"Bearer {t}", **prefer},
                                            timeout=timeout), self.name)

    # ---- query ---------------------------------------------------------------------------------------------------
    def _workspace(self) -> str:
        ws = ig.secret(self.ccfg.get("workspace_id_env")) or self.ccfg.get("workspace_id")
        if not ws:
            raise httpc.HttpError(f"{self.name}: no workspace id (set workspace_id or the env var named in "
                                  f"workspace_id_env)")
        return str(ws)

    def template(self) -> str:
        return " ".join(str(self.mcfg.get("query") or "").split())

    def render(self, tmpl: str, since: str, size: int, after: str) -> str:
        until = ig.iso_ms(self.until_ms) if self.until_ms is not None else ig.iso_ms(ig.now_ms())
        return (tmpl.replace("{since}", since).replace("{until}", str(until)).replace("{page_size}", str(size))
                .replace("{after}", after))

    def pull(self, since_ms: int) -> Iterator[Record]:
        url = httpc.join(str(self.ccfg.get("base_url") or LA_BASE_URL),
                         f"/v1/workspaces/{self._workspace()}/query")
        size = int(self.ccfg.get("page_size", 5000))
        ts_field = str(self.mcfg.get("ts_field", "TimeGenerated"))
        id_field = str(self.mcfg.get("id_field", "_ItemId"))
        key_col = str(self.mcfg.get("keyset_column", "AlId"))
        if not (_COL_RE.match(ts_field) and _COL_RE.match(key_col)):
            raise ValueError(f"{self.name}: ts_field / keyset_column must be plain column names")
        tmpl = self.template()
        keyset = "{after}" in tmpl
        since_iso = str(ig.iso_ms(since_ms))
        cur_ms, last_ts_raw, last_key = since_ms, None, None
        for _ in range(int(self.ccfg.get("max_pages_per_cycle", 50))):
            after = ""
            if keyset and last_ts_raw is not None:
                t = kql_dt(last_ts_raw)
                after = f"| where {ts_field} > {t} or ({ts_field} == {t} and {key_col} > {kql_str(last_key or '')})"
            q = self.render(tmpl, since_iso if keyset else str(ig.iso_ms(cur_ms)), size, after)
            res = self._query(url, q)
            if res.get("error"):
                err = res["error"]
                raise httpc.HttpError(f"{self.name}: {err.get('code') if isinstance(err, dict) else err}"
                                      f"{': ' + str(err.get('message'))[:200] if isinstance(err, dict) else ''}")
            tables = res.get("tables") or []
            if not tables:
                return
            cols = [c.get("name") for c in tables[0].get("columns") or []]
            rows = tables[0].get("rows") or []
            page_max = None
            for r in rows:
                doc = dict(zip(cols, r))
                ts, rid = ig.to_ms(doc.get(ts_field)), ig.first(doc, id_field)
                if ts is not None and (page_max is None or ts > page_max):
                    page_max = ts
                last_ts_raw, last_key = doc.get(ts_field), doc.get(key_col, rid)
                last_key = None if last_key is None else str(last_key)
                yield Record(ts, None if rid is None else str(rid), doc, self.bucket(doc))
            yield PAGE_END
            if len(rows) < size:
                return
            if keyset:
                if last_ts_raw is None:
                    raise httpc.HttpError(f"{self.name}: rows carry no {ts_field}; cannot page")
                continue
            if page_max is None or page_max <= cur_ms:  # whole page at one timestamp: cannot advance
                raise httpc.HttpError(f"{self.name}: page of {size} rows at one timestamp; raise page_size or "
                                      f"use a keyset query template with {{after}}")
            cur_ms = page_max
        log.info("connect %s: max_pages_per_cycle reached; continuing next cycle", self.name)

    def bucket(self, doc: dict[str, Any]) -> str:
        return ""


def decode_dynamic(v: Any) -> Any:
    """Log Analytics returns `dynamic` columns as JSON text: decode objects / arrays so JSON paths reach inside."""
    if isinstance(v, str) and v[:1] in ("{", "["):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v
