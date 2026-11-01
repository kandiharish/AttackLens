"""Set up and seed a real Elasticsearch 8.x container for the live connector tests (no product code used here).

- Waits for HTTPS on the auto-generated CA (http_ca.crt copied out of the container), elastic / password.
- Creates two least-privilege API keys: `reader` (read on logs-attacklens-*: the connector's documented minimum) and
  `writer` (create_doc + auto_configure on the incident data stream, index + auto_configure on a plain index: the
  elastic_bulk sink's documented minimum).
- Seeds ECS JSON into the data stream logs-attacklens-default with bulk `create`, incl. one large group of documents
  that share a single @timestamp so search_after paging crosses a page boundary inside the tie.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from splunk_seed import ecs_line
from vhttp import Resp, basic, req

STREAM = "logs-attacklens-default"
SINK_STREAM = "logs-attacklens.incidents-default"
SINK_INDEX = "attacklens-incidents-live"


def plan(n: int, now_ms: int, tie_from: int, tie_len: int) -> list[int]:
    """Timestamps for seq 0..n-1: now-50 min, 2 s apart, except seq tie_from..tie_from+tie_len-1 share one ms."""
    base = now_ms - 50 * 60_000
    out, t = [], base + 311
    for i in range(n):
        if tie_from < i < tie_from + tie_len:
            out.append(out[-1])
            continue
        out.append(t)
        t += 2_000
    return out


@dataclass
class Elastic:
    url: str
    password: str
    ca_file: str

    def call(self, method: str, path: str, body: Any = None, raw: bytes | None = None,
             headers: dict[str, str] | None = None, timeout: float = 60) -> Resp:
        h = headers if headers is not None else basic("elastic", self.password)
        return req(method, f"{self.url}{path}", headers=h, body=body, raw=raw,
                   content_type="application/x-ndjson" if raw is not None else None, ca_file=self.ca_file,
                   timeout=timeout)

    def ok(self, r: Resp, what: str) -> Any:
        if r.status >= 300:
            raise RuntimeError(f"elastic {what}: HTTP {r.status} {r.text[:300]}")
        return r.json()

    def wait_ready(self, timeout: float = 300) -> dict[str, Any]:
        end, last = time.monotonic() + timeout, ""
        while time.monotonic() < end:
            try:
                r = self.call("GET", "/_cluster/health?wait_for_status=yellow&timeout=5s")
                if r.status == 200:
                    return self.ok(self.call("GET", "/"), "root")
                last = f"HTTP {r.status}"
            except OSError as exc:
                last = f"{type(exc).__name__} {str(exc)[:120]}"
            time.sleep(3)
        raise TimeoutError(f"elasticsearch not ready after {timeout:g}s: {last}")

    def api_key(self, name: str, indices: list[dict[str, Any]], cluster: list[str] | None = None) -> str:
        role = {"indices": indices, **({"cluster": cluster} if cluster else {})}
        d = self.ok(self.call("POST", "/_security/api_key",
                              {"name": name, "expiration": "3h", "role_descriptors": {name: role}}), "api key")
        return str(d["encoded"])

    def bulk_create(self, index: str, docs: list[str], batch: int = 500) -> None:
        for i in range(0, len(docs), batch):
            lines = "".join('{"create":{}}\n' + d + "\n" for d in docs[i:i + batch])
            res = self.ok(self.call("POST", f"/{index}/_bulk?refresh=wait_for", raw=lines.encode()), "bulk")
            if res.get("errors"):
                bad = [it for it in res["items"] if next(iter(it.values())).get("error")]
                raise RuntimeError(f"bulk seed errors: {json.dumps(bad[:2])[:400]}")

    def count(self, index: str) -> int:
        self.call("POST", f"/{index}/_refresh")
        r = self.call("GET", f"/{index}/_count")
        return int(r.json().get("count", -1)) if r.status == 200 else -1

    def pit_stats(self) -> dict[str, int] | None:
        """Cluster-wide search stats: point_in_time_total / point_in_time_current (None if not reported)."""
        d = self.ok(self.call("GET", "/_nodes/stats/indices/search"), "node stats")
        tot = cur = 0
        seen = False
        for node in (d.get("nodes") or {}).values():
            s = ((node.get("indices") or {}).get("search") or {})
            if "point_in_time_total" in s:
                seen = True
                tot += int(s["point_in_time_total"])
                cur += int(s.get("point_in_time_current", 0))
        return {"total": tot, "current": cur} if seen else None


def setup(es: Elastic) -> dict[str, Any]:
    root = es.wait_ready()
    reader = es.api_key("al_live_reader", [{"names": ["logs-attacklens-*"], "privileges": ["read"]}])
    writer = es.api_key("al_live_writer", [
        {"names": ["logs-attacklens.incidents-*"], "privileges": ["create_doc", "auto_configure"]},
        {"names": [f"{SINK_INDEX}*"], "privileges": ["index", "auto_configure"]}])
    return {"version": root.get("version", {}).get("number"), "reader": reader, "writer": writer}


def seed(es: Elastic, n: int, run: str, now_ms: int, tie_from: int, tie_len: int) -> list[int]:
    ts = plan(n, now_ms, tie_from, tie_len)
    es.bulk_create(STREAM, [ecs_line(i, t, run) for i, t in enumerate(ts)])
    got = es.count(STREAM)
    if got != n:
        raise AssertionError(f"seeded {n} docs but {STREAM} counts {got}")
    return ts
