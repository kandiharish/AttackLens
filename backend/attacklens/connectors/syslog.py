"""Syslog / CEF listener (UDP and/or TCP) for lines forwarded by a SIEM (QRadar, ArcSight, Splunk, Sentinel AMA).

Received lines are buffered (bounded: max_buffer_lines, overflow counted as buffer_full) and flushed every
flush_interval_s into one spool file per format (events mode, routed by content by Stage 0 later) or mapped from
CEF to raw_alerts rows (alerts mode). There is no checkpoint (push source); counters live in the state file.
UDP: one reader thread on a socket with a large receive buffer (udp_rcvbuf_bytes, default 8 MB), so bursts queue in
the kernel instead of spawning a thread per datagram. TCP: newline-delimited or RFC 6587 octet-counted frames
(`<len> <msg>`), detected per message.
"""

from __future__ import annotations

import logging
import re
import socket
import socketserver
import threading
import time
from datetime import datetime, timezone
from typing import Any, Iterator

from attacklens import integrations as ig
from attacklens.connectors import catalog_fields as cf
from attacklens.connectors.base import Checkpoint, Connector, CycleStats, Record, SpoolWriter

log = logging.getLogger("attacklens.connect")

_CEF_START = re.compile(r"CEF:\d+\|")
_EXT_KEY = re.compile(r"(?:^|(?<=\s))([A-Za-z0-9_.\[\]-]+)=")
_CEF_RT_FORMATS = ("%b %d %Y %H:%M:%S.%f", "%b %d %Y %H:%M:%S", "%b %d %H:%M:%S.%f", "%b %d %H:%M:%S")
_SYSLOG_TS = re.compile(r"^(?:<\d+>)?(?:1 )?(\d{4}-\d\d-\d\dT\S+|[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)")


def _unescape(s: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "r": "\r"}.get(m.group(1), m.group(1)), s).strip()


def parse_cef(line: str) -> dict[str, Any] | None:
    """CEF line (optionally behind a syslog header) -> {"cef.vendor", ..., "cef.name", "cef.severity", ext keys}."""
    m = _CEF_START.search(line)
    if not m:
        return None
    body = line[m.start():]
    head: list[str] = []
    i, cur = 0, []
    while i < len(body) and len(head) < 7:
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            cur.append(body[i + 1])
            i += 2
            continue
        if c == "|":
            head.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if len(head) < 7:
        return None
    out: dict[str, Any] = dict(zip(("cef.version", "cef.vendor", "cef.product", "cef.device_version",
                                    "cef.signature_id", "cef.name", "cef.severity"), head))
    ext = body[i:]
    keys = list(_EXT_KEY.finditer(ext))
    for k, nk in zip(keys, keys[1:] + [None]):
        out[k.group(1)] = _unescape(ext[k.end(): nk.start() if nk else len(ext)])
    return out


def _read_octet_count(rfile: Any) -> tuple[bytes | None, int | None]:
    """RFC 6587 framing detection on a stream: read up to 10 digits one byte at a time, then a space, then peek for
    '<' (a syslog PRI). -> (b"", length) for an octet-counted frame; (bytes already consumed, None) for a
    newline-delimited line (the caller prepends them); (None, None) at end of stream."""
    digits = b""
    while len(digits) < 10:
        c = rfile.read(1)
        if not c:
            return (None, None) if not digits else (digits, None)
        if not c.isdigit():
            if c == b" " and digits and digits[:1] != b"0" and rfile.peek(1)[:1] == b"<":
                return b"", int(digits)
            return digits + c, None
        digits += c
    return digits, None


def cef_date_ms(v: Any) -> int | None:
    """CEF date: epoch ms, ISO-8601, or `MMM dd [yyyy] HH:mm:ss[.SSS] [zone]` (zone UTC/GMT/Z or +hh:mm; other zone
    names are read as UTC). A date without a year takes the current UTC year."""
    ms = ig.to_ms(v)
    if ms is not None:
        return ms
    s = " ".join(str(v).split())
    off = 0
    m = re.search(r"\s([+-])(\d\d):?(\d\d)$", s)
    if m:
        off = (1 if m.group(1) == "+" else -1) * (int(m.group(2)) * 60 + int(m.group(3))) * 60_000
        s = s[:m.start()]
    elif re.search(r"\s[A-Za-z]{1,5}$", s):
        s = s.rsplit(" ", 1)[0]
    for fmt in _CEF_RT_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
        except ValueError:
            continue
        if "%Y" not in fmt:
            dt = dt.replace(year=datetime.now(timezone.utc).year)
        return int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000) - off
    return None


def cef_ts(doc: dict[str, Any], line: str) -> int | None:
    for k in ("rt", "end", "start", "deviceReceiptTime"):
        if doc.get(k):
            ms = cef_date_ms(doc[k])
            if ms is not None:
                return ms
    m = _SYSLOG_TS.match(line)
    if m and "T" in m.group(1):
        return ig.to_ms(m.group(1))
    return ig.now_ms()  # receive time: forwarded alerts are near-real-time


class _Buffer:
    def __init__(self, max_lines: int) -> None:
        self.lines: list[str] = []
        self.lock = threading.Lock()
        self.max = max_lines
        self.received = 0
        self.overflow = 0
        self.oversize = 0

    def add(self, text: str) -> None:
        with self.lock:
            for ln in text.splitlines():
                ln = ln.strip("\x00").strip()
                if not ln:
                    continue
                self.received += 1
                if len(self.lines) >= self.max:
                    self.overflow += 1
                else:
                    self.lines.append(ln)

    def take(self) -> tuple[list[str], int, int, int]:
        with self.lock:
            out, n, o, big = self.lines, self.received, self.overflow, self.oversize
            self.lines, self.received, self.overflow, self.oversize = [], 0, 0, 0
        return out, n, o, big


CATALOG: dict[str, Any] = {
    "id": "syslog", "kind": "siem", "name": "Syslog / CEF listener (QRadar, ArcSight, ...)",
    "modes": ["events", "alerts"],
    "docs_url": "https://datatracker.ietf.org/doc/html/rfc6587",
    "help": "No credentials: point the SIEM's syslog / CEF forwarder at this host and port.",
    "fields": [
        cf.field("bind", "Listen address", "select", options=["127.0.0.1", "0.0.0.0"], default="127.0.0.1",
                 help="0.0.0.0 only on a trusted network segment."),
        cf.field("udp_port", "UDP port", "number", default=5514, min=1, max=65535),
        cf.field("tcp_port", "TCP port", "number", default=5514, min=1, max=65535),
    ],
}


class SyslogConnector(Connector):
    name = "syslog"
    PUSH = True

    def __init__(self, cfg: dict[str, Any], mode: str, since_ms: int | None = None, reset: bool = False) -> None:
        super().__init__(cfg, mode, since_ms, reset)
        self.buf = _Buffer(int(self.ccfg.get("max_buffer_lines", 200_000)))
        self.max_line = int(self.ccfg.get("max_line_bytes", 65536))
        self._servers: list[Any] = []
        self._udp: list[tuple[socket.socket, threading.Event, threading.Thread]] = []
        self._pending: list[str] = []

    AUTH_ENV_KEYS: tuple[str, ...] = ()

    def alert_fields(self) -> dict[str, Any]:
        return (self.ccfg.get("alerts") or {}).get("fields") or {}

    # ---- listeners -----------------------------------------------------------------------------------------------
    def start(self) -> list[tuple[str, int]]:
        bind = str(self.ccfg.get("bind", "127.0.0.1"))
        buf, max_line = self.buf, self.max_line
        bound: list[tuple[str, int]] = []

        class Tcp(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                while True:
                    pre, n = _read_octet_count(self.rfile)
                    if pre is None:
                        return
                    if n is not None:  # RFC 6587 octet counting: "<len> <msg>"
                        if n > max_line:
                            with buf.lock:
                                buf.received += 1
                                buf.oversize += 1
                            while n > 0:  # discard the frame in bounded reads
                                got = self.rfile.read(min(n, 65536))
                                if not got:
                                    return
                                n -= len(got)
                            continue
                        msg = self.rfile.read(n)
                        if len(msg) < n:
                            return  # connection closed mid-frame
                        text = msg.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")
                        buf.add(text if text.strip() else "")
                        continue
                    line = pre if pre.endswith(b"\n") else pre + self.rfile.readline(max_line + 1 - len(pre))
                    if not line:
                        return
                    if len(line) > max_line and not line.endswith(b"\n"):
                        with buf.lock:
                            buf.received += 1
                            buf.oversize += 1
                        self.rfile.readline()  # discard the rest of the line
                        continue
                    buf.add(line.decode("utf-8", errors="replace"))

        udp_port = self.ccfg.get("udp_port")
        if udp_port is not None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            want = int(self.ccfg.get("udp_rcvbuf_bytes", 8 * 2**20))
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, want)
            except OSError as exc:
                log.warning("connect syslog: SO_RCVBUF %d refused (%s)", want, exc)
            sock.bind((bind, int(udp_port)))
            sock.settimeout(0.2)
            stop = threading.Event()
            th = threading.Thread(target=self._udp_loop, args=(sock, stop), name="syslog-udp", daemon=True)
            th.start()
            self._udp.append((sock, stop, th))
            bound.append(("udp", sock.getsockname()[1]))
            log.info("connect syslog: listening udp %s:%d (%s mode, rcvbuf %d)", bind, sock.getsockname()[1],
                     self.mode, sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
        tcp_port = self.ccfg.get("tcp_port")
        if tcp_port is not None:
            socketserver.ThreadingTCPServer.allow_reuse_address = True
            srv = socketserver.ThreadingTCPServer((bind, int(tcp_port)), Tcp)
            srv.daemon_threads = True
            threading.Thread(target=srv.serve_forever, name="syslog-tcp", daemon=True).start()
            self._servers.append(srv)
            bound.append(("tcp", srv.server_address[1]))
            log.info("connect syslog: listening tcp %s:%d (%s mode)", bind, srv.server_address[1], self.mode)
        if not bound:
            raise ValueError("syslog: neither udp_port nor tcp_port configured")
        return bound

    def _udp_loop(self, sock: socket.socket, stop: threading.Event) -> None:
        """Single reader: datagrams queue in the kernel buffer between reads, no thread per datagram."""
        buf, max_line = self.buf, self.max_line
        while not stop.is_set():
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                return  # socket closed by stop()
            if len(data) > max_line:
                with buf.lock:
                    buf.received += 1
                    buf.oversize += 1
                continue
            buf.add(data.decode("utf-8", errors="replace"))

    def stop(self) -> None:
        for sock, ev, th in self._udp:
            ev.set()
            th.join(timeout=2)
            sock.close()
        self._udp = []
        for s in self._servers:
            s.shutdown()
            s.server_close()
        self._servers = []

    # ---- cycle ---------------------------------------------------------------------------------------------------
    def pull(self, since_ms: int) -> Iterator[Record]:
        for ln in self._pending:
            doc = parse_cef(ln) if self.mode == "alerts" else None
            yield Record(cef_ts(doc, ln) if doc else None, None, doc if self.mode == "alerts" else ln)

    def handle(self, rec: Record, st: CycleStats, w: SpoolWriter) -> None:
        if self.mode == "alerts" and rec.doc is None:
            st.fail("not_cef")
            return
        super().handle(rec, st, w)

    def flush(self) -> dict[str, Any]:
        lines, received, overflow, oversize = self.buf.take()
        self._pending = lines
        self.checkpoint = Checkpoint()  # push source: no checkpoint filtering
        self.default_since = 0
        stats = self.cycle()
        extra = CycleStats()
        if overflow:
            extra.fail("buffer_full", overflow)
        if oversize:
            extra.fail("line_too_long", oversize)
        if extra.failed:  # counted but never pulled into a cycle: add them to the totals
            add = sum(extra.failed.values())
            self.totals["pulled"] = self.totals.get("pulled", 0) + add
            self.totals["failed"] = self.totals.get("failed", 0) + add
            ig.update_status(self.cfg, "connectors", self.key, {"totals": dict(self.totals),
                                                                "dropped_before_spool": extra.failed})
        stats["received"] = received
        self._pending = []
        return stats

    def run(self, once: bool) -> int:
        self.start()
        interval = float(self.ccfg.get("flush_interval_s", 2))
        try:
            if once:
                time.sleep(float(self.ccfg.get("once_seconds", 5)))
                self.flush()
                return 0
            while True:
                time.sleep(interval)
                self.flush()
        except KeyboardInterrupt:
            log.info("connect syslog: stopped")
            self.flush()
        finally:
            self.stop()
        return 0


def send_lines(lines: list[str], host: str, port: int, protocol: str = "udp", timeout: float = 5.0) -> None:
    """Small sender used by the CEF sink and tests."""
    if protocol == "tcp":
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall("".join(ln.rstrip("\n") + "\n" for ln in lines).encode("utf-8"))
        return
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for ln in lines:
            s.sendto(ln.encode("utf-8"), (host, port))
