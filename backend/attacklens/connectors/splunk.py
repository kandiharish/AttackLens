"""Splunk connector: REST `services/search/jobs/export` (output_mode=json), streamed one result line at a time.

The window [since, until] is split into time chunks (`chunk`, default 15m, widened so a cycle makes at most
`max_chunks_per_cycle` requests), walked oldest first; each chunk is one export request and a PAGE_END, so with
`commit_every_pages: 1` a failure only re-pulls the current chunk. Export returns a chunk newest-first; the checkpoint
only moves after the whole chunk streamed. Dedupe id: splunk_server|index|_cd."""

from __future__ import annotations

import json
import logging
import math
import urllib.parse
from typing import Any, Iterator

from attacklens import httpc
from attacklens import integrations as ig
from attacklens.connectors import catalog_fields as cf
from attacklens.connectors.base import PAGE_END, Connector, Record

log = logging.getLogger("attacklens.connect")


CATALOG: dict[str, Any] = {
    "id": "splunk", "kind": "siem", "name": "Splunk", "modes": ["events", "alerts"],
    "docs_url": "https://docs.splunk.com/Documentation/Splunk/latest/Security/CreateAuthTokens",
    "help": "Minimum permission: a role with the search capability on the index you pull (events and notables).",
    "fields": [
        cf.field("base_url", "Splunk management URL", "url", True, placeholder="https://splunk.example:8089"),
        cf.secret("token", "Auth token", required=True),
        cf.advanced("auth_scheme", "Token scheme", "select", options=["Bearer", "Splunk"], default="Bearer",
                    help="Bearer for authentication tokens, Splunk for session keys."),
        cf.advanced("events.search", "Events search", default="search index=main"),
        cf.advanced("alerts.search", "Alerts (notables) search", default="search index=notable"),
        *cf.common(10),
    ],
}


class SplunkConnector(Connector):
    name = "splunk"

    def headers(self) -> dict[str, str]:
        tok = ig.secret(self.ccfg.get("token_env"))
        scheme = "Splunk" if str(self.ccfg.get("auth_scheme") or "Bearer").lower() == "splunk" else "Bearer"
        return {"Authorization": f"{scheme} {tok}"} if tok else {}

    def chunks(self, since_ms: int, until_ms: int) -> list[tuple[int, int]]:
        """[lo, hi) slices covering [since, until], oldest first, at most max_chunks_per_cycle of them."""
        if until_ms < since_ms:
            return []
        span = until_ms - since_ms + 1
        n_max = max(1, int(self.ccfg.get("max_chunks_per_cycle", 48)))
        size = max(ig.parse_duration_ms(self.ccfg.get("chunk", "15m")), math.ceil(span / n_max))
        return [(lo, min(lo + size, until_ms + 1)) for lo in range(since_ms, until_ms + 1, size)]

    def rid(self, res: dict[str, Any], id_field: str) -> str | None:
        v = ig.first(res, id_field)
        if v is None:
            return None
        if id_field == "_cd":  # _cd is unique per index bucket only: qualify it
            return f"{res.get('splunk_server', '')}|{res.get('index', '')}|{v}"
        return str(v)

    def pull(self, since_ms: int) -> Iterator[Record]:
        until = self.until_ms if self.until_ms is not None else ig.now_ms()
        for lo, hi in self.chunks(since_ms, until):
            yield from self._export(lo, hi)
            yield PAGE_END

    def _export(self, lo: int, hi: int) -> Iterator[Record]:
        search = str(self.mcfg.get("search", "search index=main")).strip()
        if not (search.startswith("search") or search.startswith("|")):
            search = "search " + search
        form = {"search": search, "output_mode": "json", "earliest_time": f"{lo / 1000:.3f}",
                "latest_time": f"{hi / 1000:.3f}"}
        body = urllib.parse.urlencode(form).encode("utf-8")
        url = httpc.join(str(self.ccfg["base_url"]), "/services/search/jobs/export")
        ts_field = str(self.mcfg.get("ts_field", "_time"))
        id_field = str(self.mcfg.get("id_field", "_cd"))
        hdr = {**self.headers(), "Content-Type": "application/x-www-form-urlencoded"}
        tls = self.tls()

        def _open() -> tuple[Any, Any]:  # retried on 429/502/503/504 before any row is read
            cm = httpc.open_url("POST", url, body, hdr, float(self.ccfg.get("timeout_s") or 300), tls["verify_tls"],
                                tls["ca_file"])
            return cm, cm.__enter__()

        cm, resp = httpc.with_retries(_open, int(self.ccfg.get("retries", 3)), what="splunk export")
        try:
            for line in httpc.iter_lines(resp):
                try:
                    obj = json.loads(line)
                except ValueError:
                    raise httpc.HttpError(f"splunk export: non-JSON line {line[:80]!r}") from None
                if not isinstance(obj, dict) or obj.get("preview"):
                    continue
                res = obj.get("result")
                if not isinstance(res, dict):
                    if obj.get("messages"):
                        for m in obj["messages"]:
                            if str(m.get("type", "")).upper() in ("FATAL", "ERROR"):
                                raise httpc.HttpError(f"splunk export: {m.get('text')}")
                    continue
                yield Record(ig.to_ms(res.get(ts_field)), self.rid(res, id_field), res)
        finally:
            cm.__exit__(None, None, None)

    def event_line(self, rec: Record) -> str | dict[str, Any] | None:
        res = rec.doc if isinstance(rec.doc, dict) else {}
        raw = res.get(str(self.mcfg.get("raw_field", "_raw")))
        if isinstance(raw, str) and raw.strip():
            return raw
        return {k: v for k, v in res.items() if not k.startswith("_")} | {"@timestamp": res.get("_time")}
