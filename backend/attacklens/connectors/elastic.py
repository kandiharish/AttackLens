"""Elastic / OpenSearch connector: `_search` with search_after paging, PIT + _shard_doc when available, else a
sort on (ts_field, tiebreak_field). Pages are streamed: only one page of hits is held at a time."""

from __future__ import annotations

import base64
import logging
from typing import Any, Iterator

from attacklens import httpc
from attacklens import integrations as ig
from attacklens.connectors import catalog_fields as cf
from attacklens.connectors.base import PAGE_END, Connector, Record

log = logging.getLogger("attacklens.connect")


CATALOG: dict[str, Any] = {
    "id": "elastic", "kind": "siem", "name": "Elastic / OpenSearch", "modes": ["events", "alerts"],
    "docs_url": "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html",
    "help": "Minimum permission: read on the index patterns (read also allows point-in-time search).",
    "fields": [
        cf.field("base_url", "Elasticsearch URL", "url", placeholder="https://es.example:9200",
                 help="Or Elastic Cloud ID below."),
        cf.field("cloud_id", "Elastic Cloud ID", placeholder="deployment:ZXUtd2VzdC0xLmF3cy5mb3VuZC5pbyRhYmMkZGVm"),
        cf.secret("api_key", "API key", help="Encoded API key, or id:key (encoded for you)."),
        cf.secret("user", "Username (basic auth)", advanced=True),
        cf.secret("password", "Password (basic auth)", advanced=True),
        cf.advanced("flavor", "Flavor", "select", options=["elastic", "opensearch"], default="elastic"),
        cf.advanced("events.index", "Events index pattern", default="logs-*"),
        cf.advanced("alerts.index", "Alerts index pattern", default=".alerts-security.alerts-*"),
        *cf.common(10),
    ],
}


def api_key_header(key: str) -> str:
    """An `id:key` pair is base64-encoded (Elastic expects the encoded form); an encoded key is used as is."""
    k = key.strip()
    if ":" in k:
        k = base64.b64encode(k.encode("utf-8")).decode("ascii")
    return f"ApiKey {k}"


def cloud_id_url(cloud_id: str) -> str:
    """Elastic Cloud ID `name:base64(host$es_id$kibana_id)` -> https://<es_id>.<host>[:port]."""
    try:
        enc = cloud_id.rpartition(":")[2]  # the deployment name may itself contain ':'
        host, es_id = base64.b64decode(enc + "=" * (-len(enc) % 4)).decode("utf-8").split("$")[:2]
    except (ValueError, IndexError, UnicodeDecodeError):
        raise ValueError("elastic: cloud_id is not a valid Elastic Cloud ID") from None
    if not host or not es_id:
        raise ValueError("elastic: cloud_id is not a valid Elastic Cloud ID")
    host, _, port = host.partition(":")
    es_id, _, es_port = es_id.partition(":")  # an es_uuid:port suffix wins over the host port
    port = es_port or port
    return f"https://{es_id}.{host}" + (f":{port}" if port and port != "443" else "")


class ElasticConnector(Connector):
    name = "elastic"

    def base_url(self) -> str:
        if self.ccfg.get("cloud_id"):
            return cloud_id_url(str(self.ccfg["cloud_id"]))
        return str(self.ccfg["base_url"])

    def headers(self) -> dict[str, str]:
        key = ig.secret(self.ccfg.get("api_key_env"))
        if key:
            return {"Authorization": api_key_header(key)}
        user, pw = ig.secret(self.ccfg.get("user_env")), ig.secret(self.ccfg.get("password_env"))
        if user and pw:
            return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
        return {}

    def _post(self, path: str, body: Any, method: str = "POST") -> Any:
        return self.http_json(method, httpc.join(self.base_url(), path), body, self.headers())

    def _open_pit(self, index: str) -> str | None:
        if not self.ccfg.get("use_pit", True):
            return None
        os_flavor = str(self.ccfg.get("flavor", "elastic")).lower() == "opensearch"
        path = f"/{index}/_search/point_in_time?keep_alive=2m" if os_flavor else f"/{index}/_pit?keep_alive=2m"
        try:
            res = self._post(path, None)
        except httpc.HttpError as exc:
            log.warning("connect elastic: PIT unavailable (%s); sorting on tie-break field instead", exc)
            return None
        pit = res.get("pit_id") or res.get("id")
        return str(pit) if pit else None

    def _close_pit(self, pit: str) -> None:
        os_flavor = str(self.ccfg.get("flavor", "elastic")).lower() == "opensearch"
        try:
            if os_flavor:
                self._post("/_search/point_in_time", {"pit_id": [pit]}, "DELETE")
            else:
                self._post("/_pit", {"id": pit}, "DELETE")
        except httpc.HttpError as exc:
            log.debug("connect elastic: PIT close failed: %s", exc)

    def _rid(self, hit: dict[str, Any]) -> str | None:
        f = str(self.mcfg.get("id_field", "_id"))
        v = hit.get(f) if f.startswith("_") else ig.first(hit.get("_source") or {}, f)
        return None if v is None else str(v)

    def pull(self, since_ms: int) -> Iterator[Record]:
        index = str(self.mcfg.get("index", "logs-*"))
        ts_field = str(self.mcfg.get("ts_field", "@timestamp"))
        size = int(self.ccfg.get("page_size", 1000))
        max_pages = int(self.ccfg.get("max_pages_per_cycle", 100))
        bounds = {"gte": ig.iso_ms(since_ms)}
        if self.until_ms is not None:
            bounds["lte"] = ig.iso_ms(self.until_ms)  # not-yet-settled and future-dated rows stay for later
        rng = {"range": {ts_field: {**bounds, "format": "strict_date_optional_time"}}}
        extra = self.mcfg.get("query") or {"match_all": {}}
        query = {"bool": {"filter": [rng, extra]}}
        pit = self._open_pit(index)
        tb = str(self.mcfg.get("tiebreak_field") or "_doc")
        if not pit and tb == "_doc":
            # _doc is per shard, not unique across the index: search_after on it can skip or repeat rows
            raise ValueError("elastic: no point-in-time available and tiebreak_field is _doc; set "
                             f"connectors.elastic.{self.mode}.tiebreak_field to a field that is unique and present "
                             "in every document (e.g. event.id), or allow PIT (use_pit: true, read privilege)")
        tie = {"_shard_doc": "asc"} if pit else {tb: {"order": "asc", "unmapped_type": "keyword"}}
        body: dict[str, Any] = {"size": size, "query": query, "sort": [{ts_field: {"order": "asc"}}, tie],
                                "track_total_hits": False}
        after: list[Any] | None = None
        try:
            for page in range(max_pages):
                if after is not None:
                    body["search_after"] = after
                if pit:
                    body["pit"] = {"id": pit, "keep_alive": "2m"}
                    res = self._post("/_search", body)
                    pit = str(res.get("pit_id") or pit)
                else:
                    res = self._post(f"/{index}/_search", body)
                hits = ((res.get("hits") or {}).get("hits")) or []
                for h in hits:
                    src = h.get("_source") or {}
                    doc = src if self.mode == "events" else {"_id": h.get("_id"), **src}
                    yield Record(ig.to_ms(ig.first(src, ts_field)), self._rid(h), doc)
                yield PAGE_END
                if len(hits) < size:
                    return
                after = hits[-1].get("sort")
                if not after:
                    raise httpc.HttpError("elastic: hits carry no sort values; cannot page with search_after")
            log.info("connect elastic: max_pages_per_cycle (%d) reached; continuing next cycle", max_pages)
        finally:
            if pit:
                self._close_pit(pit)
