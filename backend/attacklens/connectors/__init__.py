"""Inbound connectors (config/integrations.yaml `connectors`): SIEMs and cloud audit-log sources.
See connectors/base.py for the contract. Each module exposes CATALOG (form fields for the Integrations page)."""

from __future__ import annotations

import importlib
from typing import Any

from attacklens.connectors.base import Connector

# id -> (module, class); module name == id (integrations_status.catalog imports attacklens.connectors.<id>)
_REGISTRY: dict[str, tuple[str, str]] = {
    "elastic": ("elastic", "ElasticConnector"),
    "splunk": ("splunk", "SplunkConnector"),
    "sentinel": ("sentinel", "SentinelConnector"),
    "syslog": ("syslog", "SyslogConnector"),
    "aws_cloudtrail": ("aws_cloudtrail", "AwsCloudTrailConnector"),
    "azure_monitor": ("azure_monitor", "AzureMonitorConnector"),
    "gcp_logging": ("gcp_logging", "GcpLoggingConnector"),
    "okta": ("okta", "OktaConnector"),
    "m365_ual": ("m365_ual", "M365UalConnector"),
    "gws_reports": ("gws_reports", "GwsReportsConnector"),
}
SOURCES = tuple(_REGISTRY)
CLOUD_SOURCES = ("aws_cloudtrail", "azure_monitor", "gcp_logging")
IDENTITY_SOURCES = ("okta", "m365_ual", "gws_reports")   # SaaS identity / productivity audit logs (kind "identity")


def get(source: str, cfg: dict[str, Any], mode: str, since_ms: int | None = None,
        reset: bool = False) -> Connector:
    if source not in _REGISTRY:
        raise ValueError(f"unknown source {source!r}; one of {SOURCES}")
    mod, cls = _REGISTRY[source]
    C = getattr(importlib.import_module(f"attacklens.connectors.{mod}"), cls)
    return C(cfg, mode, since_ms, reset)


def catalog(source: str) -> dict[str, Any]:
    """The CATALOG dict of one connector module (importing it never needs an optional dependency)."""
    if source not in _REGISTRY:
        raise ValueError(f"unknown source {source!r}; one of {SOURCES}")
    return dict(getattr(importlib.import_module(f"attacklens.connectors.{_REGISTRY[source][0]}"), "CATALOG"))
