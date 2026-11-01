"""Form-field helpers for connector CATALOGs (GET /api/integrations/catalog builds the Connect form from them).

Field: {key, label, type: text|url|secret|number|bool|select, required, placeholder?, help?, options?, default?,
advanced?, env_key?}. A secret field K is stored by the API as reference "<id>.K" and resolved through the config key
`env_key` (default K_env) by integrations.secret(). `advanced: true` fields (endpoint overrides, TLS, paging) are
optional, empty by default and hidden behind "Advanced": the defaults target the vendors' public endpoints.
"""

from __future__ import annotations

from typing import Any

SINCE_OPTIONS = ["1h", "24h", "7d", "30d"]


def field(key: str, label: str, type_: str = "text", required: bool = False, **kw: Any) -> dict[str, Any]:
    return {"key": key, "label": label, "type": type_, "required": required, **kw}


def secret(key: str, label: str, required: bool = False, **kw: Any) -> dict[str, Any]:
    return field(key, label, "secret", required, env_key=f"{key}_env", **kw)


def advanced(key: str, label: str, type_: str = "text", **kw: Any) -> dict[str, Any]:
    return field(key, label, type_, False, advanced=True, **kw)


def common(poll_s: int, since_options: list[str] | None = None, tls: bool = True) -> list[dict[str, Any]]:
    """Poll interval + first-pull window (+ TLS options), all advanced."""
    out = [advanced("poll_interval_s", "Poll interval (seconds)", "number", default=poll_s, min=1, max=86400),
           advanced("default_since", "First pull covers", "select", options=since_options or SINCE_OPTIONS,
                    default="24h", help="Used only on the first pull (no checkpoint yet).")]
    return out + (tls_fields() if tls else [])


def tls_fields() -> list[dict[str, Any]]:
    """TLS options (advanced): certificate check on/off + a private CA bundle (connectors and HTTP sinks)."""
    return [advanced("verify_tls", "Verify TLS certificate", "bool", default=True),
            advanced("ca_file", "Extra CA bundle (PEM file path)", placeholder="C:/certs/corp-ca.pem")]
