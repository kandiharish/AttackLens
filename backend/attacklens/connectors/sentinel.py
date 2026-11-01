"""Microsoft Sentinel connector: Log Analytics query API (`POST /v1/workspaces/{id}/query`, KQL).

Auth and paging live in connectors/loganalytics.py: a static bearer token (token_env, override) or Entra ID client
credentials (tenant_id + client_id + client_secret_env; token cached, refreshed on 401). Events are written as the
table's raw line (raw_field) when present, else mapped column -> ECS path (event_map) so Stage 0 sees ECS JSON."""

from __future__ import annotations

import logging
from typing import Any

from attacklens.connectors import catalog_fields as cf
from attacklens.connectors.base import Record
from attacklens.connectors.loganalytics import LogAnalyticsConnector

log = logging.getLogger("attacklens.connect")

CATALOG: dict[str, Any] = {
    "id": "sentinel", "kind": "siem", "name": "Microsoft Sentinel", "modes": ["events", "alerts"],
    "docs_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/register-app-for-token",
    "help": "Minimum permission: the app registration needs the Log Analytics Reader role on the Sentinel workspace.",
    "fields": [
        cf.field("workspace_id", "Workspace ID", required=True, placeholder="00000000-0000-0000-0000-000000000000",
                 help="Env var SENTINEL_WORKSPACE_ID wins if set."),
        cf.field("tenant_id", "Tenant ID", required=True, placeholder="00000000-0000-0000-0000-000000000000"),
        cf.field("client_id", "Client (application) ID", required=True,
                 placeholder="00000000-0000-0000-0000-000000000000"),
        cf.secret("client_secret", "Client secret", required=True),
        cf.secret("token", "Static bearer token (override)", advanced=True,
                  help="Expires after about 1 hour; leave empty to sign in with tenant / client / secret."),
        cf.advanced("base_url", "Log Analytics API URL override", "url",
                    help="Empty = https://api.loganalytics.azure.com (Azure public cloud)."),
        cf.advanced("login_url", "Entra ID login URL override", "url",
                    help="Empty = https://login.microsoftonline.com."),
        *cf.common(30),
    ],
}


def _set_path(doc: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur = doc
    for p in parts[:-1]:
        nxt = cur.get(p)
        if not isinstance(nxt, dict):
            nxt = cur[p] = {}
        cur = nxt
    cur[parts[-1]] = value


class SentinelConnector(LogAnalyticsConnector):
    name = "sentinel"

    def event_line(self, rec: Record) -> str | dict[str, Any] | None:
        doc = rec.doc if isinstance(rec.doc, dict) else {}
        raw = doc.get(str(self.mcfg.get("raw_field") or "")) if self.mcfg.get("raw_field") else None
        if isinstance(raw, str) and raw.strip():
            return raw
        emap = self.mcfg.get("event_map") or {}
        out: dict[str, Any] = {}
        for col, path in emap.items():
            v = doc.get(col)
            if v is not None and v != "":
                _set_path(out, str(path), v)
        return out or None
