"""Azure Monitor connector: Log Analytics KQL over AzureActivity, SigninLogs and AuditLogs (table list configurable),
Entra ID client-credentials sign-in (tenant_id + client_id + client_secret), plain HTTPS (no Azure SDK).

Default tables: AzureActivity, SigninLogs, AuditLogs and the three non-interactive / service-principal / managed-identity
sign-in tables (token replay and service-principal abuse show up mostly there). `union isfuzzy=true` tolerates tables
the workspace does not have. Optional tables (`events.optional_tables`, table -> true/false; StorageBlobLogs = blob
data plane, high volume) are appended when switched on.

Events: one union query ordered by (TimeGenerated, _ItemId) with keyset paging (connectors/loganalytics.py). Each row
is written as JSON with its Log Analytics column names (empty columns of the union dropped, `dynamic` columns
decoded), one spool folder per table (`azure_<table>`), so Stage 0 routes SigninLogs to `azure_signin_json` and
AzureActivity / AuditLogs to `azure_activity_json` (config/sources.yaml).
Alerts: SecurityAlert (Defender for Cloud / Sentinel) with the vendor MITRE fields, like the sentinel connector.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from attacklens.connectors import catalog_fields as cf
from attacklens.connectors.base import Record
from attacklens.connectors.loganalytics import LogAnalyticsConnector, decode_dynamic

log = logging.getLogger("attacklens.connect")

_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
DEFAULT_TABLES = ("AzureActivity", "SigninLogs", "AuditLogs", "AADNonInteractiveUserSignInLogs",
                  "AADServicePrincipalSignInLogs", "AADManagedIdentitySignInLogs")
OPTIONAL_TABLES = ("StorageBlobLogs",)
DEFAULT_EVENTS_QUERY = (
    "union isfuzzy=true {tables} | where TimeGenerated >= datetime({since}) and TimeGenerated <= datetime({until}) "
    "| extend AlId = tostring(_ItemId) {after} | order by TimeGenerated asc, AlId asc | take {page_size}")

CATALOG: dict[str, Any] = {
    "id": "azure_monitor", "kind": "cloud", "name": "Azure (Activity Log + Entra ID sign-in / audit)",
    "modes": ["events", "alerts"],
    "docs_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/register-app-for-token",
    "help": "Minimum permission: the app registration needs the Log Analytics Reader role on the workspace.",
    "fields": [
        cf.field("tenant_id", "Tenant ID", required=True, placeholder="00000000-0000-0000-0000-000000000000"),
        cf.field("client_id", "Client (application) ID", required=True,
                 placeholder="00000000-0000-0000-0000-000000000000"),
        cf.secret("client_secret", "Client secret", required=True),
        cf.field("workspace_id", "Log Analytics workspace ID", required=True,
                 placeholder="00000000-0000-0000-0000-000000000000",
                 help="The workspace that receives the Activity Log and Entra ID diagnostic settings."),
        cf.advanced("events.tables", "Tables", default=", ".join(DEFAULT_TABLES),
                    help="Comma-separated Log Analytics tables to pull."),
        cf.advanced("events.optional_tables", "Optional tables", default="",
                    help="Comma-separated extra tables, e.g. StorageBlobLogs (blob data plane: GetBlob / DeleteBlob, "
                         "high volume; needs the storage account diagnostic setting)."),
        cf.advanced("base_url", "Log Analytics API URL override", "url",
                    help="Empty = https://api.loganalytics.azure.com (Azure public cloud)."),
        cf.advanced("login_url", "Entra ID login URL override", "url",
                    help="Empty = https://login.microsoftonline.com (sovereign clouds only)."),
        *cf.common(60),
    ],
}


def tables(v: Any) -> list[str]:
    """Table list from config (list or comma-separated text); names are validated (they go into KQL)."""
    items = list(v) if isinstance(v, (list, tuple)) else str(v or "").split(",")   # a tuple is DEFAULT_TABLES
    out = [str(t).strip() for t in items if str(t).strip()]
    bad = [t for t in out if not _TABLE_RE.match(t)]
    if bad:
        raise ValueError(f"azure_monitor: invalid table name(s) {bad[:3]}")
    return out or list(DEFAULT_TABLES)


def optional_tables(v: Any) -> list[str]:
    """events.optional_tables: {table: true/false}, a list, or comma-separated text (all switched on); validated."""
    items = [t for t, on in v.items() if on] if isinstance(v, dict) else v
    names = [str(t).strip() for t in (items if isinstance(items, list) else str(items or "").split(","))]
    names = [t for t in names if t]
    return tables(names) if names else []   # tables() validates; never falls back to the defaults here


def all_tables(mcfg: dict[str, Any]) -> list[str]:
    base = tables(mcfg.get("tables") or DEFAULT_TABLES)
    return base + [t for t in optional_tables(mcfg.get("optional_tables")) if t not in base]


class AzureMonitorConnector(LogAnalyticsConnector):
    name = "azure_monitor"
    AUTH_ENV_KEYS: tuple[str, ...] = ("token_env", "client_secret_env")

    def template(self) -> str:
        q = " ".join(str(self.mcfg.get("query") or (DEFAULT_EVENTS_QUERY if self.mode == "events" else "")).split())
        # alerts mode has no table list (its mcfg is the `alerts` section): only expand {tables} when present
        return q.replace("{tables}", ", ".join(all_tables(self.mcfg))) if "{tables}" in q else q

    def bucket(self, doc: dict[str, Any]) -> str:
        t = str(doc.get("Type") or "")
        return f"azure_{t.lower()}" if _TABLE_RE.match(t) else "azure"

    def event_line(self, rec: Record) -> str | dict[str, Any] | None:
        doc = rec.doc if isinstance(rec.doc, dict) else {}
        drop = {str(self.mcfg.get("keyset_column", "AlId"))}
        return {k: decode_dynamic(v) for k, v in doc.items() if k not in drop and v is not None and v != ""} or None
