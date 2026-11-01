"""Elasticsearch / OpenSearch _bulk sink, doc id = incident id.

op_type (config):
- auto (default): create when the target is a data stream (index name matches `data_stream_prefixes`, default
  logs- / metrics- / traces-), else index.
- create: the only bulk op a data stream accepts. A re-send of an incident already stored answers 409
  (version conflict); that counts as delivered (the document exists), it is not an error.
- index: plain index; a re-send overwrites the stored incident (use it to keep updated incidents current; data
  streams reject it).
"""

from __future__ import annotations

import base64
import json
from typing import Any

from attacklens import httpc
from attacklens import integrations as ig
from attacklens.connectors import catalog_fields as cf
from attacklens.connectors.elastic import api_key_header
from attacklens.sinks import PartialSend

DATA_STREAM_PREFIXES = ("logs-", "metrics-", "traces-")

CATALOG: dict[str, Any] = {
    "id": "elastic_bulk", "kind": "sink", "name": "Elasticsearch index / data stream (bulk)",
    "docs_url": "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html",
    "help": "Minimum permission: create_doc (data stream) or index (plain index) on the target, plus "
            "auto_configure if the target does not exist yet.",
    "fields": [
        cf.field("base_url", "Elasticsearch URL", "url", True, placeholder="https://es.example:9200"),
        cf.field("index", "Index or data stream", required=True, default="attacklens-incidents"),
        cf.secret("api_key", "API key", help="Encoded API key, or id:key."),
        cf.secret("user", "Username (basic auth)", advanced=True),
        cf.secret("password", "Password (basic auth)", advanced=True),
        cf.advanced("op_type", "Bulk operation", "select", options=["auto", "create", "index"], default="auto",
                    help="auto: create for data streams (logs-*), index (overwrite updates) for a plain index."),
        *cf.tls_fields(),
    ],
}


def _headers(scfg: dict[str, Any]) -> dict[str, str]:
    key = ig.secret(scfg.get("api_key_env"))
    if key:
        return {"Authorization": api_key_header(key)}
    user, pw = ig.secret(scfg.get("user_env")), ig.secret(scfg.get("password_env"))
    if user and pw:
        return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
    return {}


def op_type(scfg: dict[str, Any], index: str) -> str:
    op = str(scfg.get("op_type") or "auto").lower()
    if op == "auto":
        prefixes = tuple(scfg.get("data_stream_prefixes") or DATA_STREAM_PREFIXES)
        return "create" if index.startswith(prefixes) else "index"
    if op not in ("create", "index"):
        raise ValueError(f"elastic_bulk: op_type must be create, index or auto (got {op!r})")
    return op


def send(items: list[tuple[dict[str, Any], dict[str, Any]]], scfg: dict[str, Any], cfg: dict[str, Any]) -> int:
    index = str(scfg.get("index", "attacklens-incidents"))
    op = op_type(scfg, index)
    url = httpc.join(str(scfg["base_url"]), "/_bulk")
    size = max(1, int(scfg.get("batch_size", 100)))
    sent: list[str] = []
    errors: list[str] = []
    for i in range(0, len(items), size):
        lines = []
        for inc, _ in items[i:i + size]:
            doc = {**inc, "@timestamp": inc.get("first_ts")}
            lines.append(json.dumps({op: {"_index": index, "_id": inc["id"]}}))
            lines.append(json.dumps(doc, ensure_ascii=False, separators=(",", ":")))
        res = httpc.request_json("POST", url, headers=_headers(scfg),
                                 raw_body=("\n".join(lines) + "\n").encode("utf-8"),
                                 content_type="application/x-ndjson", timeout=float(scfg.get("timeout_s", 10)),
                                 verify_tls=bool(scfg.get("verify_tls", True)), ca_file=scfg.get("ca_file") or None,
                                 retries=int(scfg.get("retries", 3)))
        bad: set[str] = set()
        if isinstance(res, dict) and res.get("errors"):
            for it in res.get("items") or []:
                r = next(iter(it.values()), {}) if isinstance(it, dict) else {}
                if not isinstance(r, dict):
                    continue
                status = int(r.get("status", 200))
                if op == "create" and status == 409:
                    continue  # already stored: delivered
                if r.get("error") or status >= 300:
                    bad.add(str(r.get("_id")))
                    errors.append(f"{r.get('_id')}: {str(r.get('error'))[:120]}")
        sent += [str(inc["id"]) for inc, _ in items[i:i + size] if str(inc["id"]) not in bad]
    if errors:
        raise PartialSend(f"bulk: {len(errors)} item error(s), first: {errors[0]}", sent)
    return len(sent)
