"""Local mock SIEM for AttackLens connector / sink tests and the offline demo (stdlib only; DEVELOPMENT.md §8b).

    python tools/mock_siem.py --data data/raw/<set> --port 9200 [--splunk-token T] [--hec-token T] ...

In tests:
    with MockSIEM(data_dir, hec_token="t") as m:   # free 127.0.0.1 port
        m.url                                       # http://127.0.0.1:<port>
        m.fail(r"^/logs-\\*/_search", status=500, times=1)    # fault injection (status and/or delay_s)
        m.received["hec" | "bulk" | "webhook" | "syslog"]    # everything pushed to the mock
        m.indexed[(index, id)]                      # current Elastic doc per (index, _id) after _bulk

Endpoints (one HTTP port serves every vendor; paths don't overlap):
  Elastic   GET /                                   cluster info (reachability)
            POST /<index>/_pit?keep_alive=, POST /_search {"pit":...}, DELETE /_pit   point in time: a snapshot
                                                    of the files at open; `_shard_doc` sort only with a PIT
            GET|POST /<index>/_search               events (any index) or alerts (.alerts-security.alerts-*) or
                                                    docs received through _bulk (e.g. attacklens-incidents)
            POST /_bulk, /<index>/_bulk             receiver (index/create/update/delete; create on an existing id
                                                    -> 409 like Elasticsearch); GET /<index>/_doc/<id>
  Splunk    POST /services/search/jobs/export       output_mode=json, NDJSON {"preview":false,"offset":n,"result":{}}
                                                    `index=notable` -> notables from the alert fixture
            GET  /services/server/info              reachability
            POST /services/collector[/event]        HEC receiver; `Authorization: Splunk <token>` checked
  Sentinel  POST /v1/workspaces/<id>/query          {"query": KQL, "timespan": ...} -> tables[0].columns/rows;
                                                    `SecurityAlert` -> alert fixture, any other table -> events
                                                    (TimeGenerated, Computer, RawData = stripped JSON, _ItemId)
  Generic   POST /webhook[/<anything>]              receiver
  Cloud     Azure token + Log Analytics AzureActivity/SigninLogs/AuditLogs (mock_cloud.py), AWS CloudTrail
            LookupEvents + S3 trail files (mock_cloud_aws.py), GCP token + entries:list (mock_cloud.py); seed data and
            the attack story's ground truth in mock_cloud_seed.py (GET /_mock/cloud/ground_truth, never in records)
  Control   GET /_mock/received, GET /_mock/stats, POST /_mock/reset,
            POST /_mock/fault {path (regex or FAULT_TARGETS alias), status, times, after, delay_s, retry_after},
            GET|POST /_mock/cloud {tie_burst, late_after, late_ts_ms, future_row, expire_tokens, add_rows_ts_ms}
  Faults    m.fail(...) / --fault TARGET,STATUS[,times=,after=,retry_after=,delay=] / ?mock_fault=401|429|500|slow
            (&mock_retry_after=S, &mock_delay=S) on any request
  Syslog    optional UDP receiver (syslog_udp=True; address in .syslog_addr), lines in received["syslog"];
            optional TCP receiver (syslog_tcp=True; .syslog_tcp_addr), RFC 6587 octet-counted or LF framing;
            send_syslog(addr, lines, proto, framing) forwards like a SIEM (to test the AttackLens listener)
  HEC ack   hec_ack=True: X-Splunk-Request-Channel required (400 code 10), ackId per channel, POST
            /services/collector/ack; hec_max_bytes -> 413

Auth: a vendor's check is active only when its token is set (None = open). Served events have the generator label
fields stripped (mock_siem_store.strip_labels). The alert feed comes from tools/mock_siem_alerts.json (hand-written).
Loopback only by default: the mock is for synthetic data on this machine.
"""

from __future__ import annotations

import argparse
import collections
import fnmatch
import gzip
import heapq
import json
import logging
import os
import re
import socket
import socketserver
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mock_cloud as mc  # noqa: E402
import mock_cloud_aws as mca  # noqa: E402
import mock_siem_query as mq  # noqa: E402
from mock_siem_store import Cand, EventStore, MemSource, iso_ms, parse_iso_ms  # noqa: E402

log = logging.getLogger("mock_siem")
ALERTS_FIXTURE = Path(__file__).resolve().parent / "mock_siem_alerts.json"
ELASTIC_ALERTS_INDEX = ".alerts-security.alerts-default"
EVENTS_INDEX_NAME = "mock-events-000001"


def load_alerts(path: Path | str = ALERTS_FIXTURE) -> list[dict[str, Any]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))["alerts"]


# fault target aliases (CLI --fault / POST /_mock/fault): name -> (path regex, method)
FAULT_TARGETS = {"azure_token": (r"^/[^/]+/oauth2/v2\.0/token$", "POST"),
                 "loganalytics": (r"^/v1/workspaces/[^/]+/query$", "POST"),
                 "sentinel": (r"^/v1/workspaces/[^/]+/query$", "POST"),
                 "cloudtrail": (r"^/$", "POST"), "s3": (r"^/attacklens-mock-trail(/|$)", "GET"),
                 "gcp_token": (r"^/(token|oauth2/v4/token)$", "POST"), "gcp_logs": (r"^/v2/entries:list$", "POST"),
                 "elastic": (r"/_search$", None), "splunk": (r"^/services/search/jobs/export$", "POST"),
                 "hec": (r"^/services/collector", "POST")}


class Fault:
    def __init__(self, path_re: str, status: int | None, times: int | None, delay_s: float, body: Any,
                 method: str | None, after: int = 0, headers: dict[str, str] | None = None) -> None:
        self.rx, self.status, self.times, self.delay_s, self.body = re.compile(path_re), status, times, delay_s, body
        self.method, self.after, self.headers = method, after, headers or {}


class MockSIEM:
    def __init__(self, data_dir: Path | str | None = None, *, host: str = "127.0.0.1", port: int = 0,
                 alerts: list[dict[str, Any]] | Path | str | None = None, elastic_api_key: str | None = None,
                 splunk_token: str | None = None, hec_token: str | None = None,
                 sentinel_token: str | None = None, webhook_token: str | None = None,
                 workspace_id: str | None = None, sentinel_max_rows: int = 500_000,
                 now_ms: Callable[[], int] | None = None, syslog_udp: bool = False, syslog_tcp: bool = False,
                 hec_ack: bool = False, hec_max_bytes: int | None = None,
                 cloud: dict[str, Any] | None = None) -> None:
        self.store = EventStore(data_dir)
        raw_alerts = alerts if isinstance(alerts, list) else load_alerts(alerts or ALERTS_FIXTURE)
        self.alerts = [dict(a, ts_ms=parse_iso_ms(a["ts"])) for a in raw_alerts]
        self.host, self.port = host, port
        self.tokens = {"elastic": elastic_api_key, "splunk": splunk_token, "hec": hec_token,
                       "sentinel": sentinel_token, "webhook": webhook_token}
        self.workspace_id, self.sentinel_max_rows = workspace_id, sentinel_max_rows
        self.now_ms = now_ms or (lambda: int(time.time() * 1000))
        self.cloud = mc.CloudState(now_ms=self.now_ms, **(cloud or {}))
        self.hec_ack, self.hec_max_bytes = hec_ack, hec_max_bytes
        self.hec_acks: dict[str, int] = {}                       # channel -> next ackId
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.faults: list[Fault] = []
        self.requests: collections.deque[dict[str, Any]] = collections.deque(maxlen=10_000)
        self.received: dict[str, list[Any]] = {"hec": [], "bulk": [], "webhook": [], "syslog": []}
        self.indexed: dict[tuple[str, str], dict[str, Any]] = {}
        self.versions: dict[tuple[str, str], int] = {}
        self.served: collections.Counter[str] = collections.Counter()
        self.pits: dict[str, tuple[str, dict[str, int]]] = {}
        self._httpd: ThreadingHTTPServer | None = None
        self._threads: list[threading.Thread] = []
        self._syslog_udp, self._syslog_tcp = syslog_udp, syslog_tcp
        self._udp: socketserver.UDPServer | None = None
        self._tcp: socketserver.ThreadingTCPServer | None = None
        self.syslog_addr: tuple[str, int] | None = None
        self.syslog_tcp_addr: tuple[str, int] | None = None

    # ------------------------------------------------------------------ lifecycle
    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "MockSIEM":
        self._httpd = ThreadingHTTPServer((self.host, self.port), _make_handler(self))
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        t = threading.Thread(target=self._httpd.serve_forever, args=(0.05,), name="mock-siem-http", daemon=True)
        t.start()
        self._threads.append(t)
        if self._syslog_udp:
            mock = self

            class _Udp(socketserver.BaseRequestHandler):
                def handle(self) -> None:
                    data = self.request[0].decode("utf-8", "replace")
                    with mock.lock:
                        mock.received["syslog"] += [ln for ln in data.splitlines() if ln.strip()]

            self._udp = socketserver.UDPServer((self.host, 0), _Udp)
            self.syslog_addr = self._udp.server_address[:2]
            u = threading.Thread(target=self._udp.serve_forever, args=(0.05,), name="mock-siem-syslog", daemon=True)
            u.start()
            self._threads.append(u)
        if self._syslog_tcp:
            self._tcp = _syslog_tcp_server(self)
            self.syslog_tcp_addr = self._tcp.server_address[:2]
            tt = threading.Thread(target=self._tcp.serve_forever, args=(0.05,), name="mock-siem-syslog-tcp",
                                  daemon=True)
            tt.start()
            self._threads.append(tt)
        log.info("mock SIEM on %s (data %s)", self.url, self.store.root)
        return self

    def stop(self) -> None:
        self.stop_event.set()
        for srv in (self._httpd, self._udp, self._tcp):
            if srv is not None:
                srv.shutdown()
                srv.server_close()
        for t in self._threads:
            t.join(timeout=5)

    def __enter__(self) -> "MockSIEM":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # ------------------------------------------------------------------ test controls
    def fail(self, path_re: str, status: int | None = 500, times: int | None = 1, delay_s: float = 0.0,
             body: Any = None, method: str | None = None, after: int = 0, retry_after: float | None = None,
             headers: dict[str, str] | None = None) -> None:
        """After `after` matching requests pass untouched, the next `times` requests whose path matches path_re
        (None = forever) wait delay_s, then get `status` (None = served normally after the delay). path_re may be
        a FAULT_TARGETS alias (cloudtrail, loganalytics, gcp_logs, ...). retry_after -> Retry-After header."""
        if path_re in FAULT_TARGETS:
            path_re, method = FAULT_TARGETS[path_re][0], method or FAULT_TARGETS[path_re][1]
        hdr = dict(headers or {})
        if retry_after is not None:
            hdr["Retry-After"] = str(int(retry_after)) if float(retry_after).is_integer() else str(retry_after)
        with self.lock:
            self.faults.append(Fault(path_re, status, times, delay_s, body, method, after, hdr))

    def clear_faults(self) -> None:
        with self.lock:
            self.faults.clear()

    def reset(self) -> None:
        with self.lock:
            for v in self.received.values():
                v.clear()
            self.indexed.clear()
            self.versions.clear()
            self.requests.clear()
            self.served.clear()
            self.faults.clear()
            self.hec_acks.clear()

    def take_fault(self, method: str, path: str) -> Fault | None:
        with self.lock:
            for f in self.faults:
                if f.rx.search(path) and (f.method is None or f.method == method) and (f.times is None or f.times > 0):
                    if f.after > 0:
                        f.after -= 1
                        continue
                    if f.times is not None:
                        f.times -= 1
                    return f
        return None

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {"received": json.loads(json.dumps(self.received, default=str)),
                    "indexed": [{"_index": i, "_id": d, "_source": s} for (i, d), s in self.indexed.items()],
                    "served": dict(self.served), "requests": list(self.requests)}

    # ------------------------------------------------------------------ sources
    def alert_source_elastic(self) -> MemSource:
        return MemSource([(f"mock-alert-{a['id']}", mq.elastic_alert(a)) for a in self.alerts])

    def bulk_source(self, patterns: list[str]) -> MemSource | None:
        patterns = [p for p in patterns if p not in ("*", "_all")]  # bare wildcard = the event data
        with self.lock:
            docs = [(d, src) for (i, d), src in self.indexed.items() if any(fnmatch.fnmatch(i, p) for p in patterns)]
            names = {i for (i, _) in self.indexed}
        if not any(fnmatch.fnmatch(n, p) for n in names for p in patterns):
            return None
        return MemSource([(d, {**src, "@timestamp": src.get("@timestamp") or src.get("first_ts") or ""})
                          for d, src in docs])


# ====================================================================== HTTP
def _make_handler(mock: MockSIEM) -> type[BaseHTTPRequestHandler]:
    class H(_Handler):
        m = mock
    return H


class _Handler(BaseHTTPRequestHandler):
    m: MockSIEM
    protocol_version = "HTTP/1.1"
    server_version = "AttackLensMockSIEM/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet; requests are recorded in m.requests
        log.debug("%s " + fmt, self.address_string(), *args)

    # ------------------------------------------------------------------ plumbing
    def _body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = b""
            while True:
                n = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if n == 0:
                    self.rfile.readline()
                    break
                data += self.rfile.read(n)
                self.rfile.readline()
        else:
            data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            data = gzip.decompress(data)
        return data

    def _send(self, status: int, payload: Any, ctype: str = "application/json",
              headers: dict[str, str] | None = None) -> None:
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self._status = status

    def _record(self, status: int) -> None:
        with self.m.lock:
            self.m.requests.append({"method": self.command, "path": self.path, "status": status,
                                    "auth": "Authorization" in self.headers})

    def _auth(self, vendor: str, schemes: tuple[str, ...]) -> bool:
        want = self.m.tokens[vendor]
        if want is None:
            return True
        got = self.headers.get("Authorization", "")
        return any(got == f"{s} {want}" for s in schemes)

    def _dispatch(self) -> None:
        self._status = 0
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        try:
            body = self._body() if self.command in ("POST", "PUT") else (
                self._body() if self.headers.get("Content-Length") else b"")
            params = dict(parse_qsl(parts.query, keep_blank_values=True))
            fault = _param_fault(params) or self.m.take_fault(self.command, path)
            if fault is not None:
                if fault.delay_s:
                    self.m.stop_event.wait(fault.delay_s)
                if fault.status is not None:
                    self._send(fault.status, fault.body if fault.body is not None else
                               {"error": {"type": "mock_injected_fault", "reason": f"injected {fault.status}"},
                                "status": fault.status}, headers=fault.headers)
                    return
            self._route(path, params, body)
        except mq.QueryError as e:
            self._send(e.status, {"error": {"type": e.kind, "reason": str(e)}, "status": e.status})
        except (BrokenPipeError, ConnectionResetError):
            self._status = -1
        except Exception as e:  # a mock bug must surface as a 500, never as a hang
            log.exception("mock SIEM handler error")
            if not self._status:
                self._send(500, {"error": {"type": "mock_internal_error", "reason": repr(e)}, "status": 500})
        finally:
            self._record(self._status)

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = lambda self: self._dispatch()  # noqa: E731

    def _route(self, path: str, params: dict[str, str], body: bytes) -> None:
        if path.startswith("/_mock/"):
            return self._control(path, body)
        if self.headers.get("X-Amz-Target"):
            return mca.cloudtrail(self, body)
        if path == "/v2/entries:list":
            return mc.gcp_list(self, body)
        tok = re.fullmatch(r"/([^/]+)/oauth2/v2\.0/token", path)
        if tok:
            return mc.azure_token(self, tok.group(1), body)
        if path in ("/token", "/oauth2/v4/token") and self.command == "POST":
            return mc.gcp_token(self, body)
        if path.startswith("/v1/workspaces/") and mc.la_table(body):
            return mc.la_query(self, path, body)
        if mca.is_s3(self, path):
            return mca.s3(self, path, params)
        if path.startswith("/services/collector"):
            return self._hec(path, body)
        if path.startswith("/services/"):
            return self._splunk(path, params, body)
        if path.startswith("/v1/workspaces/"):
            return self._sentinel(path, body)
        if path == "/webhook" or path.startswith("/webhook/"):
            return self._webhook(path, body)
        return self._elastic(path, params, body)

    # ------------------------------------------------------------------ control
    def _control(self, path: str, body: bytes = b"") -> None:
        m = self.m
        req = json.loads(body) if body.strip() else {}
        if path == "/_mock/fault" and self.command == "POST":
            m.fail(req.get("path", ".*"), status=req.get("status", 500), times=req.get("times", 1),
                   delay_s=float(req.get("delay_s", 0)), method=req.get("method"), after=int(req.get("after", 0)),
                   retry_after=req.get("retry_after"))
            return self._send(200, {"faults": len(m.faults)})
        if path == "/_mock/cloud" and self.command == "POST":
            if req.pop("expire_tokens", None):
                m.cloud.expire_tokens(req.pop("vendor", None))
            if "add_rows_ts_ms" in req:
                added = m.cloud.add_rows(int(req.pop("add_rows_ts_ms")))
                if not req:
                    return self._send(200, {"added": added})
            try:
                return self._send(200, {"switches": m.cloud.configure(**req)})
            except (TypeError, ValueError) as e:
                return self._send(400, {"error": str(e)})
        if path == "/_mock/cloud":
            return self._send(200, {"switches": m.cloud.switches, "anchor_ms": m.cloud.anchor_ms,
                                    "queries": dict(m.cloud.queries), "token_requests": dict(m.cloud.token_requests),
                                    "feeds": {k: len(v) for k, v in m.cloud.seed.feeds.items()}})
        if path == "/_mock/cloud/ground_truth":
            return self._send(200, m.cloud.ground_truth())
        if path == "/_mock/received":
            return self._send(200, self.m.snapshot())
        if path == "/_mock/stats":
            return self._send(200, {"served": dict(self.m.served), "malformed_lines": self.m.store.malformed_lines,
                                    "files": [r for r, _ in self.m.store.files()]})
        if path == "/_mock/reset" and self.command == "POST":
            self.m.reset()
            return self._send(200, {"reset": True})
        self._send(404, {"error": "unknown mock control path"})

    # ------------------------------------------------------------------ Elastic
    def _es_auth_fail(self) -> None:
        self._send(401, {"error": {"type": "security_exception", "reason": "unable to authenticate request"},
                         "status": 401}, headers={"WWW-Authenticate": 'ApiKey, Basic realm="security"'})

    def _elastic(self, path: str, params: dict[str, str], body: bytes) -> None:
        if not self._auth("elastic", ("ApiKey", "Bearer")):
            return self._es_auth_fail()
        segs = [s for s in path.split("/") if s]
        if not segs:
            return self._send(200, {"name": "mock-siem", "cluster_name": "attacklens-mock",
                                    "version": {"number": "8.15.0"}, "tagline": "You Know, for Search"})
        if segs == ["_pit"] and self.command == "DELETE":
            pit = json.loads(body or b"{}").get("id")
            with self.m.lock:
                freed = self.m.pits.pop(str(pit), None) is not None
            return self._send(200 if freed else 404, {"succeeded": freed, "num_freed": int(freed)})
        if len(segs) == 2 and segs[1] == "_pit" and self.command == "POST":
            if "keep_alive" not in params:
                raise mq.QueryError("[keep_alive] is required", kind="action_request_validation_exception")
            pit = "mockpit-" + uuid.uuid4().hex
            with self.m.lock:
                self.m.pits[pit] = (segs[0], self.m.store.snapshot())
            return self._send(200, {"id": pit})
        if segs == ["_search"]:
            return self._search("*", params, body, pit_ok=True)
        if segs[-1] == "_bulk":
            return self._bulk(segs[0] if len(segs) == 2 else None, body)
        if len(segs) == 2 and segs[1] == "_search":
            return self._search(segs[0], params, body)
        if len(segs) == 3 and segs[1] == "_doc" and self.command == "GET":
            with self.m.lock:
                src = self.m.indexed.get((segs[0], segs[2]))
                ver = self.m.versions.get((segs[0], segs[2]))
            if src is None:
                return self._send(404, {"_index": segs[0], "_id": segs[2], "found": False})
            return self._send(200, {"_index": segs[0], "_id": segs[2], "_version": ver, "found": True,
                                    "_source": src})
        self._send(400, {"error": {"type": "mock_unsupported", "reason": f"mock: no handler for {path}"},
                         "status": 400})

    def _search(self, index: str, params: dict[str, str], body: bytes, pit_ok: bool = False) -> None:
        m = self.m
        req = json.loads(body) if body.strip() else {}
        pit_id, snap = None, None
        if req.get("pit"):
            if not pit_ok:
                raise mq.QueryError("[indices] cannot be used with point in time. Do not specify any index with "
                                    "point in time.", kind="action_request_validation_exception")
            pit_id = str(req["pit"].get("id"))
            with m.lock:
                entry = m.pits.get(pit_id)
            if entry is None:
                raise mq.QueryError(f"No search context found for id [{pit_id}]", status=404,
                                    kind="search_context_missing_exception")
            index, snap = entry
        patterns = index.split(",")
        now = m.now_ms()
        if any(fnmatch.fnmatch(ELASTIC_ALERTS_INDEX, p) and p.startswith(".alerts") for p in patterns):
            src, feed, idx_name = m.alert_source_elastic(), "elastic_alerts", ELASTIC_ALERTS_INDEX
        else:
            bulk = m.bulk_source(patterns)
            if bulk is not None:
                src, feed, idx_name = bulk, "elastic_bulk", patterns[0]
            else:
                src, feed, idx_name = m.store, "elastic_events", (index if "*" not in index else EVENTS_INDEX_NAME)
        size = int(req.get("size", params.get("size", 10)))
        frm = int(req.get("from", params.get("from", 0)))
        if size < 0 or frm < 0:
            raise mq.QueryError("[size] and [from] must be >= 0")
        if frm + size > mq.MAX_RESULT_WINDOW:
            raise mq.QueryError(f"Result window is too large, from + size must be less than or equal to: "
                                f"[{mq.MAX_RESULT_WINDOW}] but was [{frm + size}].")
        sort = mq.es_sort_spec(req.get("sort"))
        if any(f == "_shard_doc" for f, _ in sort) and pit_id is None:
            raise mq.QueryError("[_shard_doc] sort field cannot be used without [point in time]")
        after = req.get("search_after")
        if after is not None:
            if not sort:
                raise mq.QueryError("Sort must contain at least one field.", kind="parsing_exception")
            if len(after) != len(sort):
                raise mq.QueryError(f"search_after has {len(after)} value(s) but sort has {len(sort)}.")
            if frm:
                raise mq.QueryError("[from] parameter must be set to 0 when [search_after] is used.")
        q = req.get("query")
        lo, hi = mq.es_ts_bounds(q, now)
        needs = mq.es_needs_doc(q) or any(f not in ("@timestamp", "_id", "_doc", "_shard_doc") for f, _ in sort)
        orders = [o for _, o in sort]
        after_key = mq.SortKey([mq.es_after_value(f, v, now) for (f, _), v in zip(sort, after)], orders) \
            if after is not None else None
        total = 0

        def matches():
            nonlocal total
            for c in src.candidates(lo, hi, snapshot=snap if src is m.store else None):
                doc = c.load() if needs else None
                if needs and doc is None:
                    continue
                if needs and not mq.es_match(q, doc, c, now):
                    continue
                if not needs and q and not mq.es_match(q, {}, c, now):
                    continue
                total += 1
                key = mq.SortKey([mq.es_sort_value(f, c, doc) for f, _ in sort], orders) if sort else \
                    mq.SortKey([c.seq], ["asc"])
                if after_key is not None and not after_key < key:
                    continue
                yield key, c, doc

        gen = matches()
        if size:
            page = heapq.nsmallest(frm + size, gen, key=lambda t: t[0])[frm:]
        else:
            page = []
            for _ in gen:  # size 0: still count the total
                pass
        hits = []
        for key, c, doc in page:
            d = doc if doc is not None else c.load()
            h: dict[str, Any] = {"_index": idx_name, "_id": c.doc_id, "_score": None if sort else 1.0, "_source": d}
            if sort:
                h["sort"] = [mq.es_hit_sort(f, o, v) for (f, o), v in zip(sort, key.vals)]
            hits.append(h)
        with m.lock:
            m.served[feed] += len(hits)
        track = req.get("track_total_hits", 10_000)
        tot: dict[str, Any] | None = {"value": total, "relation": "eq"}
        if track is False:
            tot = None                                         # Elasticsearch omits hits.total
        elif track is not True and isinstance(track, int) and total > track:
            tot = {"value": int(track), "relation": "gte"}
        hits_obj: dict[str, Any] = {"max_score": None if sort else 1.0, "hits": hits}
        if tot is not None:
            hits_obj = {"total": tot, **hits_obj}
        resp: dict[str, Any] = {"took": 1, "timed_out": False,
                                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0}, "hits": hits_obj}
        if pit_id is not None:
            resp = {"pit_id": pit_id, **resp}
        self._send(200, resp)

    def _bulk(self, default_index: str | None, body: bytes) -> None:
        ctype = self.headers.get("Content-Type", "application/x-ndjson").split(";")[0].strip().lower()
        if ctype not in ("application/x-ndjson", "application/json", "application/vnd.elasticsearch+x-ndjson"):
            return self._send(406, {"error": f"Content-Type header [{ctype}] is not supported", "status": 406})
        if not body.endswith(b"\n"):
            raise mq.QueryError("The bulk request must be terminated by a newline [\\n]")
        lines = [ln for ln in body.split(b"\n") if ln.strip()]
        items, errors, i = [], False, 0
        while i < len(lines):
            action = json.loads(lines[i])
            (op, meta), = action.items()
            idx = meta.get("_index") or default_index
            if idx is None:
                raise mq.QueryError("Validation Failed: 1: index is missing;", kind="action_request_validation")
            doc_id = meta.get("_id") or uuid.uuid4().hex[:20]
            src = None
            if op != "delete":
                i += 1
                src = json.loads(lines[i])
            i += 1
            key = (idx, doc_id)
            with self.m.lock:
                exists = key in self.m.indexed
                self.m.received["bulk"].append({"op": op, "_index": idx, "_id": doc_id, "_source": src})
                if op == "create" and exists:
                    errors = True
                    items.append({op: {"_index": idx, "_id": doc_id, "status": 409, "error": {
                        "type": "version_conflict_engine_exception",
                        "reason": f"[{doc_id}]: version conflict, document already exists"}}})
                    continue
                if op == "delete":
                    if exists:
                        del self.m.indexed[key]
                    items.append({op: {"_index": idx, "_id": doc_id, "result": "deleted" if exists else "not_found",
                                       "status": 200 if exists else 404}})
                    continue
                if op == "update":
                    if not exists and not (src or {}).get("doc_as_upsert"):
                        errors = True
                        items.append({op: {"_index": idx, "_id": doc_id, "status": 404,
                                           "error": {"type": "document_missing_exception"}}})
                        continue
                    new = {**self.m.indexed.get(key, {}), **((src or {}).get("doc") or {})}
                else:
                    new = src or {}
                self.m.indexed[key] = new
                self.m.versions[key] = self.m.versions.get(key, 0) + 1
                items.append({op: {"_index": idx, "_id": doc_id, "_version": self.m.versions[key],
                                   "result": "updated" if exists else "created",
                                   "status": 200 if exists else 201}})
        self._send(200, {"took": 1, "errors": errors, "items": items})

    # ------------------------------------------------------------------ Splunk
    def _splunk(self, path: str, params: dict[str, str], body: bytes) -> None:
        if not self._auth("splunk", ("Bearer", "Splunk")):
            return self._send(401, {"messages": [{"type": "WARN", "text": "call not properly authenticated"}]})
        if path.rstrip("/") == "/services/server/info":
            return self._send(200, {"entry": [{"name": "server-info", "content": {
                "serverName": "mock-splunk", "version": "9.2.0"}}]})
        if path.rstrip("/") != "/services/search/jobs/export" or self.command != "POST":
            return self._send(404, {"messages": [{"type": "ERROR", "text": f"mock: no handler for {path}"}]})
        form = dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
        p = {**params, **form}
        if p.get("output_mode", "xml") != "json":
            return self._send(400, {"messages": [{"type": "ERROR", "text": "mock supports output_mode=json only"}]})
        spec = mq.parse_spl(p.get("search", ""), p, self.m.now_ms())
        lo, hi_x = spec["lo"], spec["hi_excl"]
        if spec["feed"] == "notable":
            rows = [(a["ts_ms"], i, a) for i, a in enumerate(self.m.alerts)
                    if (lo is None or a["ts_ms"] >= lo) and (hi_x is None or a["ts_ms"] < hi_x)]
            rows.sort(key=lambda r: (r[0], r[1]), reverse=not spec["ascending"])
            results = (mq.splunk_notable(a, ts) for ts, _, a in rows[:spec["head"]])
            feed = "splunk_notable"
        else:
            cands = [c.light(self.m.store) for c in self.m.store.candidates(lo, None if hi_x is None else hi_x - 1)]
            ordered = mq.sort_cands(cands, spec["ascending"])[:spec["head"]]
            results = (r for c in ordered if (r := _splunk_event(c)) is not None)
            feed = "splunk_events"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self._status = 200
        n = 0
        for n, r in enumerate(results, 1):
            self.wfile.write(json.dumps({"preview": False, "offset": n - 1, "result": r}).encode() + b"\n")
        with self.m.lock:
            self.m.served[feed] += n

    def _hec(self, path: str, body: bytes) -> None:
        want = self.m.tokens["hec"]
        got = self.headers.get("Authorization", "")
        if want is not None and not got:
            return self._send(401, {"text": "Token is required", "code": 2})
        if want is not None and got != f"Splunk {want}":
            return self._send(403, {"text": "Invalid token", "code": 4})
        if path.rstrip("/") == "/services/collector/health":
            return self._send(200, {"text": "HEC is healthy", "code": 17})
        if self.m.hec_max_bytes is not None and len(body) > self.m.hec_max_bytes:
            return self._send(413, {"text": "Content request too large", "code": 413})
        channel = self.headers.get("X-Splunk-Request-Channel") or ""
        if self.m.hec_ack and not channel:
            return self._send(400, {"text": "Data channel is missing", "code": 10})
        if path.rstrip("/") == "/services/collector/ack":
            if not self.m.hec_ack:
                return self._send(400, {"text": "ACK is disabled", "code": 14})
            with self.m.lock:
                issued = self.m.hec_acks.get(channel, 0)
            ids = (json.loads(body or b"{}").get("acks") or [])
            return self._send(200, {"acks": {str(i): isinstance(i, int) and 0 <= i < issued for i in ids}})
        text = body.decode("utf-8", "replace").strip()
        if not text:
            return self._send(400, {"text": "No data", "code": 5})
        dec, pos, events = json.JSONDecoder(), 0, []
        try:
            while pos < len(text):
                obj, end = dec.raw_decode(text, pos)
                if not isinstance(obj, dict) or "event" not in obj:
                    return self._send(400, {"text": "Event field is required", "code": 12})
                events.append(obj)
                pos = end
                while pos < len(text) and text[pos].isspace():
                    pos += 1
        except ValueError:
            return self._send(400, {"text": "Invalid data format", "code": 6})
        with self.m.lock:
            self.m.received["hec"] += events
            if self.m.hec_ack:
                ack = self.m.hec_acks.get(channel, 0)
                self.m.hec_acks[channel] = ack + 1
        if self.m.hec_ack:
            return self._send(200, {"text": "Success", "code": 0, "ackId": ack})
        self._send(200, {"text": "Success", "code": 0})

    # ------------------------------------------------------------------ Sentinel
    def _sentinel(self, path: str, body: bytes) -> None:
        if self.m.cloud.sentinel_oauth:
            if mc.azure_auth_error(self):
                return
        elif not self._auth("sentinel", ("Bearer",)):
            return self._send(401, {"error": {"code": "InvalidAuthenticationToken",
                                              "message": "Valid authentication was not provided"}})
        segs = [s for s in path.split("/") if s]
        if len(segs) != 4 or segs[3] != "query" or self.command != "POST":
            return self._send(404, {"error": {"code": "PathNotFoundError", "message": path}})
        if self.m.workspace_id is not None and segs[2] != self.m.workspace_id:
            return self._send(404, {"error": {"code": "WorkspaceNotFoundError",
                                              "message": f"workspace {segs[2]} not found"}})
        req = json.loads(body or b"{}")
        if not req.get("query"):
            raise mq.QueryError("query is required")
        now = self.m.now_ms()
        kq = mq.parse_kql(req["query"], now)
        t_lo, t_hi_x = mq.timespan_bounds(req.get("timespan"), now)
        preds = list(kq["preds"])
        if t_lo is not None:
            preds += [(">=", t_lo), ("<", t_hi_x)]
        lo, hi = mq.kql_bounds(preds)

        def ok(r: dict[str, Any]) -> bool:
            for col, op, val in kq["filters"]:
                v = r.get(col)
                if not (v == val if op == "==" else str(v).lower() == val.lower() if op == "=~" else v != val):
                    return False
            return True

        cap = self.m.sentinel_max_rows if kq["take"] is None else min(self.m.sentinel_max_rows, kq["take"])
        post = bool(kq["extend"] or kq["keyset"] or len(kq["order_by"]) > 1)   # needs every row before the cap
        if kq["table"] == "SecurityAlert":
            cols = mq.SECURITY_ALERT_COLUMNS
            rows = [(a["ts_ms"], i, mq.sentinel_alert_row(a)) for i, a in enumerate(self.m.alerts)
                    if mq.kql_pred_ok(a["ts_ms"], preds)]
            if kq["order"]:
                rows.sort(key=lambda r: (r[0], r[1]), reverse=kq["order"] == "desc")
            pairs = [(ts, r) for ts, _, r in rows if ok(r)]
            dict_rows = mq.kql_post(kq, pairs)[:cap + 1] if post else [r for _, r in pairs][:cap + 1]
            feed = "sentinel_alerts"
        else:
            cols = mq.EVENT_COLUMNS
            cands = [c.light(self.m.store) for c in self.m.store.candidates(lo, hi)
                     if mq.kql_pred_ok(c.ts, preds)]
            if kq["order"]:
                cands = mq.sort_cands(cands, kq["order"] == "asc")
            dict_rows, pairs = [], []
            for c in cands:
                if len(dict_rows) > cap and not post:
                    break
                d = c.load()
                if d is not None:
                    row = {"TimeGenerated": iso_ms(c.ts) if c.ts is not None else None,
                                      "Computer": (d.get("host") or {}).get("name") if isinstance(d.get("host"), dict)
                                      else None, "RawData": json.dumps(d, separators=(",", ":")),
                                      "_ItemId": c.doc_id, "Type": kq["table"]}
                    if ok(row):
                        dict_rows.append(row)
                        pairs.append((c.ts, row))
            if post:
                dict_rows = mq.kql_post(kq, pairs)[:cap + 1]
            feed = "sentinel_events"
        if kq["take"] is not None:
            dict_rows = dict_rows[:kq["take"]]
        out: dict[str, Any] = {}
        if len(dict_rows) > self.m.sentinel_max_rows:
            dict_rows = dict_rows[:self.m.sentinel_max_rows]
            out["error"] = {"code": "PartialError", "message": "There were some errors when processing your query.",
                            "details": [{"code": "EngineError", "message": "Query result set has exceeded the "
                                         f"internal record count limit {self.m.sentinel_max_rows} records."}]}
        cols = list(cols) + [(c, "string") for c in kq["extend"] if c not in dict(cols)]
        names = [c for c, _ in cols]
        if kq["project"]:
            unknown = [c for c in kq["project"] if c not in names]
            if unknown:
                raise mq.QueryError(f"Failed to resolve column '{unknown[0]}'")
            types = dict(cols)
            cols = [(c, types[c]) for c in kq["project"]]  # KQL project keeps the listed order
            names = [c for c, _ in cols]
        with self.m.lock:
            self.m.served[feed] += len(dict_rows)
        self._send(200, {"tables": [{"name": "PrimaryResult",
                                     "columns": [{"name": c, "type": t} for c, t in cols],
                                     "rows": [[r.get(c) for c in names] for r in dict_rows]}], **out})

    # ------------------------------------------------------------------ webhook
    def _webhook(self, path: str, body: bytes) -> None:
        if self.command != "POST":
            return self._send(405, {"error": "POST only"})
        if not self._auth("webhook", ("Bearer",)):
            return self._send(401, {"error": "unauthorized"})
        try:
            payload: Any = json.loads(body) if body.strip() else None
        except ValueError:
            payload = body.decode("utf-8", "replace")
        with self.m.lock:
            self.m.received["webhook"].append({"path": path, "headers": {k.lower(): v for k, v in
                                                                         self.headers.items()}, "body": payload})
        self._send(200, {"ok": True})


def _splunk_event(c: Cand) -> dict[str, Any] | None:
    d = c.load()
    if d is None:
        return None
    host = d.get("host")
    return {"_time": iso_ms(c.ts, "+00:00") if c.ts is not None else None,
            "_raw": json.dumps(d, separators=(",", ":")), "_cd": f"{c.doc_id}",
            "host": host.get("name") if isinstance(host, dict) else host, "source": c.rel,
            "sourcetype": "_json", "index": "main", "splunk_server": "mock-splunk"}


def _param_fault(params: dict[str, str]) -> Fault | None:
    """?mock_fault=401|429|500|slow[&mock_retry_after=S][&mock_delay=S] on any request (popped from params)."""
    kind = params.pop("mock_fault", None)
    ra, delay = params.pop("mock_retry_after", None), float(params.pop("mock_delay", 0) or 0)
    if kind is None:
        return None
    if kind == "slow":
        return Fault(".*", None, 1, delay or 30.0, None, None)
    return Fault(".*", int(kind), 1, delay, None, None, headers={"Retry-After": ra or "1"} if kind == "429" else {})


def split_syslog_frames(buf: bytes) -> tuple[list[bytes], bytes]:
    """RFC 6587 framing on a TCP stream: octet counting (`<len> <msg>`) when a frame starts with a digit, else
    newline-terminated. Returns (complete frames, remainder)."""
    out = []
    while buf:
        mm = re.match(rb"(\d{1,9}) ", buf)
        if mm:
            n, start = int(mm.group(1)), mm.end()
            if len(buf) < start + n:
                break
            out.append(buf[start:start + n])
            buf = buf[start + n:]
            continue
        nl = buf.find(b"\n")
        if nl < 0:
            break
        out.append(buf[:nl].rstrip(b"\r"))
        buf = buf[nl + 1:]
    return [f for f in out if f.strip()], buf


def _syslog_tcp_server(mock: MockSIEM) -> socketserver.ThreadingTCPServer:
    class _Tcp(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            buf = b""
            self.request.settimeout(0.5)
            while not mock.stop_event.is_set():
                try:
                    chunk = self.request.recv(65536)
                except (socket.timeout, TimeoutError):
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                frames, buf = split_syslog_frames(buf + chunk)
                with mock.lock:
                    mock.received["syslog"] += [f.decode("utf-8", "replace") for f in frames]
            if buf.strip():  # unterminated trailing line at close
                with mock.lock:
                    mock.received["syslog"].append(buf.decode("utf-8", "replace").rstrip("\r\n"))

    srv = socketserver.ThreadingTCPServer((mock.host, 0), _Tcp)
    srv.daemon_threads = True
    return srv


def send_syslog(addr: tuple[str, int], lines: list[str], proto: str = "tcp", framing: str = "octet") -> None:
    """Forward lines like a SIEM would: UDP one datagram per line; TCP octet-counted (`<len> <msg>`, no newline)
    or newline-framed. For testing the AttackLens syslog listener."""
    if proto == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for ln in lines:
                s.sendto(ln.encode("utf-8"), addr)
        return
    data = b"".join((f"{len(b)} ".encode() + b) if framing == "octet" else b + b"\n"
                    for b in (ln.encode("utf-8") for ln in lines))
    with socket.create_connection(addr, timeout=5) as s:
        s.sendall(data)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ====================================================================== CLI
def parse_fault_spec(spec: str) -> dict[str, Any]:
    """'cloudtrail,429,after=1,retry_after=2' -> kwargs for MockSIEM.fail()."""
    target, status, *kv = [x.strip() for x in spec.split(",")]
    opts = dict(x.split("=", 1) for x in kv)
    bad = set(opts) - {"times", "after", "retry_after", "delay"}
    if bad:
        raise ValueError(f"unknown --fault keys {sorted(bad)}")
    times = int(opts.get("times", 1))
    return {"path_re": target, "status": None if status == "slow" else int(status), "times": times or None,
            "after": int(opts.get("after", 0)),
            "retry_after": float(opts["retry_after"]) if "retry_after" in opts else (1.0 if status == "429" else None),
            "delay_s": float(opts.get("delay", 30.0 if status == "slow" else 0.0))}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mock_siem", description="Local mock SIEM (Elastic/Splunk/Sentinel/webhook)")
    ap.add_argument("--data", help="folder of ECS JSON-lines (e.g. data/raw/g1); streamed, never loaded whole")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9200)
    ap.add_argument("--alerts", default=str(ALERTS_FIXTURE), help="alert fixture JSON")
    for name in ("elastic-api-key", "splunk-token", "hec-token", "sentinel-token", "webhook-token"):
        ap.add_argument(f"--{name}", help=f"require this {name} (default: open); or env MOCK_SIEM_"
                                          f"{name.upper().replace('-', '_')}")
    ap.add_argument("--workspace-id")
    ap.add_argument("--syslog-udp", action="store_true", help="also receive syslog on a UDP port")
    ap.add_argument("--syslog-tcp", action="store_true", help="also receive syslog on TCP (octet-counted or LF)")
    ap.add_argument("--hec-ack", action="store_true", help="HEC indexer acknowledgement on (channel header needed)")
    ap.add_argument("--hec-max-bytes", type=int, help="HEC body size limit -> 413")
    cl = ap.add_argument_group("cloud (Azure / AWS / GCP); unset credential = any value accepted")
    cl.add_argument("--azure-tenant")
    cl.add_argument("--azure-client-id")
    cl.add_argument("--azure-client-secret", help="or env MOCK_AZURE_CLIENT_SECRET; wrong secret -> 401")
    cl.add_argument("--azure-token-ttl", type=int, default=3599, help="expires_in of issued tokens (s)")
    cl.add_argument("--sentinel-oauth", action="store_true",
                    help="Sentinel tables also need a token from the mock Azure token endpoint")
    cl.add_argument("--aws-access-key-id")
    cl.add_argument("--s3-bucket", default=mc.seed.S3_BUCKET)
    cl.add_argument("--gcp-project", default=mc.seed.PROJECT)
    cl.add_argument("--gcp-client-email")
    cl.add_argument("--gcp-token-ttl", type=int, default=3599)
    cl.add_argument("--cloud-anchor", default="now",
                    help="now (seed ends ~50 min ago, inside a 24h first pull) | fixed (2026-10-31T00:00Z) | epoch ms")
    cl.add_argument("--tie-burst", type=int, default=0, help="N extra rows at ONE timestamp per tie feed")
    cl.add_argument("--late-after", type=int, default=0,
                    help="one old-dated row per feed appears only after N queries of that feed")
    cl.add_argument("--future-row", action="store_true", help="one row per feed dated now + 6h")
    ap.add_argument("--fault", action="append", default=[], metavar="TARGET,STATUS[,k=v...]",
                    help="TARGET = alias (" + ", ".join(FAULT_TARGETS) + ") or path regex; STATUS = 401|429|500|"
                         "slow; keys times (default 1, 0 = forever), after, retry_after, delay")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    tok = {k: getattr(a, k) or os.environ.get(f"MOCK_SIEM_{k.upper()}")
           for k in ("elastic_api_key", "splunk_token", "hec_token", "sentinel_token", "webhook_token")}
    now = int(time.time() * 1000)
    anchor = mc.seed.ANCHOR_MS if a.cloud_anchor == "fixed" else (
        mc.seed.now_anchor(now) if a.cloud_anchor == "now" else int(a.cloud_anchor))
    cloud = {"anchor_ms": anchor, "azure_tenant": a.azure_tenant, "azure_client_id": a.azure_client_id,
             "azure_client_secret": a.azure_client_secret or os.environ.get("MOCK_AZURE_CLIENT_SECRET"),
             "azure_token_ttl_s": a.azure_token_ttl, "sentinel_oauth": a.sentinel_oauth,
             "aws_access_key_id": a.aws_access_key_id, "s3_bucket": a.s3_bucket, "gcp_project": a.gcp_project,
             "gcp_client_email": a.gcp_client_email, "gcp_token_ttl_s": a.gcp_token_ttl, "tie_burst": a.tie_burst,
             "late_after": a.late_after, "future_row": a.future_row}
    m = MockSIEM(a.data, host=a.host, port=a.port, alerts=a.alerts, workspace_id=a.workspace_id,
                 syslog_udp=a.syslog_udp, syslog_tcp=a.syslog_tcp, hec_ack=a.hec_ack,
                 hec_max_bytes=a.hec_max_bytes, cloud=cloud, **tok)
    for spec in a.fault:
        m.fail(**parse_fault_spec(spec))
    m.start()
    log.info("mock SIEM listening on %s%s%s (Ctrl+C to stop); cloud seed anchor %s", m.url,
             f", syslog udp {m.syslog_addr[0]}:{m.syslog_addr[1]}" if m.syslog_addr else "",
             f", syslog tcp {m.syslog_tcp_addr[0]}:{m.syslog_tcp_addr[1]}" if m.syslog_tcp_addr else "",
             mc.seed.iso(anchor))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        m.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
