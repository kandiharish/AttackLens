"""Generic webhook sink (SOAR, Sentinel Logic App, Slack/Teams incoming webhook): one JSON POST per incident.

payload: incident (full Incident JSON) | summary (incidents_index row) | slack ({"text": ...} one-liner)."""

from __future__ import annotations

import json
from typing import Any

from attacklens import httpc
from attacklens import integrations as ig
from attacklens.sinks import PartialSend
from attacklens.connectors import catalog_fields as cf


CATALOG: dict[str, Any] = {
    "id": "webhook", "kind": "sink", "name": "Webhook (SOAR, Logic App, Slack, Teams)",
    "docs_url": "https://api.slack.com/messaging/webhooks",
    "help": "Minimum permission: a webhook URL (and optional bearer token) that accepts JSON POSTs.",
    "fields": [
        cf.field("url", "Webhook URL", "url", True, placeholder="https://soar.example/hooks/attacklens"),
        cf.secret("token", "Bearer token (optional)"),
        cf.field("payload", "Payload", "select", options=["incident", "summary", "slack"], default="incident"),
        *cf.tls_fields(),
    ],
}


def _slack(row: dict[str, Any]) -> dict[str, Any]:
    tactics = " -> ".join(row.get("tactics") or [])
    hosts = ", ".join((row.get("hosts") or [])[:5])
    return {"text": f"AttackLens incident {row.get('id')} risk {row.get('risk')}: {tactics} on {hosts} "
                    f"({row.get('first_ts')} .. {row.get('last_ts')})"}


def send(items: list[tuple[dict[str, Any], dict[str, Any]]], scfg: dict[str, Any], cfg: dict[str, Any]) -> int:
    url = str(scfg["url"])
    headers = {str(k): str(v) for k, v in (scfg.get("headers") or {}).items()}
    tok = ig.secret(scfg.get("token_env"))
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    kind = str(scfg.get("payload", "incident"))
    sent: list[str] = []
    errors: list[str] = []
    for inc, row in items:
        body = inc if kind == "incident" else row if kind == "summary" else _slack(row)
        try:
            data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            with httpc.open_url("POST", url, data, {"Content-Type": "application/json", **headers},
                                float(scfg.get("timeout_s", 10)), bool(scfg.get("verify_tls", True)),
                                scfg.get("ca_file") or None) as resp:
                resp.read(65536)  # any 2xx counts (Slack answers "ok" as text)
            sent.append(str(inc.get("id")))
        except httpc.HttpError as exc:
            errors.append(str(exc))
            if exc.status is None:  # transport down: don't hammer it once per incident
                break
    if len(sent) < len(items):
        raise PartialSend(errors[0] if errors else "not sent", sent)
    return len(sent)
