"""Event storage for tools/mock_siem.py (stdlib only).

- EventStore streams ECS JSON-lines files from a folder. It never holds the data set in memory: every query
  re-scans the files, pulls `@timestamp` out of each raw line with a regex and only parses lines that pass the
  time bounds. Per-file min/max timestamps are cached (keyed by size + mtime) so later scans skip whole files.
- Served documents have the generator label fields removed (`threat`, `rule`, `labels`, `labels_extra`,
  `event.kind`, `event.severity`), the same set ingest must never read (CLAUDE.md "Detect from raw fields only").
- MemSource holds small in-memory document lists (the alert fixture, documents received through `_bulk`).
- Every document has a stable `doc_id` / `seq` derived from (relative path, byte offset): re-scans, restarts and
  appended files never change an existing document's identity.
"""

from __future__ import annotations

import json
import re
import threading
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

LABEL_KEYS = ("threat", "rule", "labels", "labels_extra")
EVENT_LABEL_KEYS = ("kind", "severity")
DATA_SUFFIXES = {".jsonl", ".ndjson", ".json"}
SKIP_NAMES = {"manifest.json"}
TS_RE = re.compile(rb'"@timestamp"\s*:\s*"([^"]*)"')
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MS = timedelta(milliseconds=1)
LONG_MAX = 9_223_372_036_854_775_807
BOM = b"\xef\xbb\xbf"


# ----------------------------------------------------------------------------- time
def parse_iso_ms(s: str) -> int | None:
    """ISO-8601 (Z, offsets, naive = UTC) -> epoch ms; None if unparseable."""
    try:
        dt = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - EPOCH) // MS


def iso_ms(ms: int, sep: str = "Z") -> str:
    """epoch ms -> '2026-10-24T02:00:00.123Z' (sep='+00:00' gives Splunk's style)."""
    dt = EPOCH + timedelta(milliseconds=ms)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}" + sep


_UNIT_MS = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000, "w": 604_800_000}


def duration_ms(n: str | int, unit: str) -> int:
    return int(n) * _UNIT_MS[unit]


# ----------------------------------------------------------------------------- documents
def strip_labels(doc: dict[str, Any]) -> dict[str, Any]:
    """Remove generator ground truth in place (top-level label keys, event.kind, event.severity)."""
    for k in LABEL_KEYS:
        doc.pop(k, None)
    ev = doc.get("event")
    if isinstance(ev, dict):
        for k in EVENT_LABEL_KEYS:
            ev.pop(k, None)
    for k in ("event.kind", "event.severity"):  # flattened ECS keys
        doc.pop(k, None)
    return doc


def get_path(obj: Any, path: str) -> Any:
    """Dotted lookup that accepts nested objects and flat dotted keys ('kibana.alert.rule.name')."""
    if not isinstance(obj, dict):
        return None
    if path in obj:
        return obj[path]
    parts = path.split(".")
    for i in range(len(parts) - 1, 0, -1):
        head = ".".join(parts[:i])
        if head in obj:
            return get_path(obj[head], ".".join(parts[i:]))
    return None


@dataclass
class Cand:
    """One stored document: identity + time, the document itself loaded on demand."""
    ts: int | None
    seq: int
    doc_id: str
    rel: str
    offset: int
    loader: Callable[[], dict[str, Any] | None] = field(repr=False)

    def load(self) -> dict[str, Any] | None:
        return self.loader()

    def light(self, store: "EventStore | None") -> "Cand":
        """Same document without the raw line held in memory (re-read by offset on load)."""
        if store is None or self.rel == "mem":
            return self
        rel, off = self.rel, self.offset  # don't capture self: it holds the raw line
        return Cand(self.ts, self.seq, self.doc_id, rel, off, lambda: store.read_at(rel, off))


class MemSource:
    """Small in-memory document list (alerts fixture, bulk-received docs). Docs are copied on load."""

    def __init__(self, docs: list[tuple[str, dict[str, Any]]] | None = None) -> None:
        self._docs: list[tuple[str, dict[str, Any]]] = list(docs or [])

    def candidates(self, lo: int | None = None, hi: int | None = None,
                   snapshot: dict[str, int] | None = None) -> Iterator[Cand]:
        for i, (doc_id, d) in enumerate(list(self._docs)):
            ts = parse_iso_ms(str(d.get("@timestamp", "")))
            if (lo is not None or hi is not None) and ts is None:
                continue
            if (lo is not None and ts < lo) or (hi is not None and ts > hi):
                continue
            yield Cand(ts, i, doc_id, "mem", i, lambda d=d: json.loads(json.dumps(d)))


class EventStore:
    """Lazily streamed ECS JSON-lines folder (see module docstring)."""

    def __init__(self, root: Path | str | None) -> None:
        self.root = Path(root).resolve() if root else None
        self._stats: dict[tuple[str, int, int], tuple[int | None, int | None, bool]] = {}
        self._lock = threading.Lock()
        self.malformed_lines = 0  # lines that are not a JSON object (never served; counted)

    def files(self) -> list[tuple[str, Path]]:
        if self.root is None or not self.root.is_dir():
            return []
        out = []
        for p in sorted(self.root.rglob("*")):
            rel = p.relative_to(self.root).as_posix()
            if (p.is_file() and p.suffix.lower() in DATA_SUFFIXES and p.name not in SKIP_NAMES
                    and "ground_truth" not in rel.split("/")):
                out.append((rel, p))
        return out

    @staticmethod
    def ident(rel: str, offset: int) -> tuple[int, str]:
        crc = zlib.crc32(rel.encode())
        return (crc << 40) | offset, f"{crc:08x}-{offset:012x}"

    def read_at(self, rel: str, offset: int) -> dict[str, Any] | None:
        assert self.root is not None
        with open(self.root / rel, "rb") as f:
            f.seek(offset)
            return self._parse(f.readline())

    @staticmethod
    def _parse(line: bytes) -> dict[str, Any] | None:
        line = line.strip()
        if line.startswith(BOM):
            line = line[3:]
        try:
            d = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            return None
        return strip_labels(d) if isinstance(d, dict) else None

    def snapshot(self) -> dict[str, int]:
        """{relative path: size} now: a point-in-time view (later appends and new files stay invisible)."""
        out = {}
        for rel, p in self.files():
            try:
                out[rel] = p.stat().st_size
            except OSError:
                pass
        return out

    def candidates(self, lo: int | None = None, hi: int | None = None,
                   snapshot: dict[str, int] | None = None) -> Iterator[Cand]:
        """Documents with lo <= ts <= hi (bounds inclusive; None = unbounded). Without bounds, documents without a
        parseable @timestamp are yielded too (ts None). snapshot limits the view to bytes present at snapshot()."""
        bounded = lo is not None or hi is not None
        for rel, path in self.files():
            if snapshot is not None and rel not in snapshot:
                continue
            limit = snapshot[rel] if snapshot is not None else None
            try:
                st = path.stat()
            except OSError:
                continue
            if limit is not None and limit >= st.st_size:
                limit = None
            key = (rel, st.st_size, st.st_mtime_ns)
            cached = self._stats.get(key)
            if cached is not None and bounded:
                mn, mx, _ = cached
                if mn is None or (lo is not None and mx < lo) or (hi is not None and mn > hi):
                    continue
            mn = mx = None
            missing = False
            malformed = 0
            off = 0
            with open(path, "rb") as f:
                for raw in f:
                    if limit is not None and off >= limit:
                        break
                    start, off = off, off + len(raw)
                    line = raw.strip()
                    if not line or line == BOM:
                        continue
                    m = TS_RE.search(line)
                    ts = parse_iso_ms(m.group(1).decode("utf-8", "replace")) if m else None
                    if ts is None:
                        if self._parse(line) is None:
                            malformed += 1
                            continue
                        missing = True
                    else:
                        mn = ts if mn is None or ts < mn else mn
                        mx = ts if mx is None or ts > mx else mx
                    if bounded and (ts is None or (lo is not None and ts < lo) or (hi is not None and ts > hi)):
                        continue
                    seq, doc_id = self.ident(rel, start)
                    yield Cand(ts, seq, doc_id, rel, start, lambda line=line: self._parse(line))
            with self._lock:
                if key not in self._stats and limit is None:
                    self._stats[key] = (mn, mx, missing)
                    self.malformed_lines += malformed

    def count(self) -> int:
        return sum(1 for c in self.candidates() if c.load() is not None)

    def all_docs(self) -> list[dict[str, Any]]:
        """For tests on tiny fixtures only (loads everything)."""
        return [d for c in self.candidates() if (d := c.load()) is not None]
