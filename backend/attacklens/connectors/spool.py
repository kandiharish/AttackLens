"""Connector primitives: Record, Checkpoint, SpoolWriter, CycleStats (used by connectors/base.py).

Checkpoint = last timestamp pulled + ids seen at exactly that timestamp (tie-break) + the ids seen inside the
overlap window before it (`recent`), so an overlapping re-read writes late-indexed rows once and re-reads nothing
twice. SpoolWriter writes dot-prefixed `.part` files and publishes them with os.link (never overwrites,
all-or-nothing per commit).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attacklens import integrations as ig

MAX_IDS = 5000       # ids remembered at the checkpoint timestamp (tie-break)
MAX_RECENT = 20000   # ids remembered inside the overlap window (late-arrival dedupe)


@dataclass
class Record:
    ts_ms: int | None
    rid: str | None
    doc: Any                 # dict (JSON doc / alert) or str (raw line)
    bucket: str = ""         # events spool sub-folder for JSON docs ("" -> "json"); one source type per folder
    fail: str = ""           # set: nothing to write, count one failed row with this reason (e.g. an unwrap failure)


class _PageEnd(Record):
    """Marker a connector yields after each page / chunk (never counted as a row)."""


PAGE_END = _PageEnd(None, None, None)


@dataclass
class Checkpoint:
    """Last timestamp pulled + the ids already seen at exactly that timestamp + recent ids (overlap dedupe)."""
    last_ts_ms: int | None = None
    ids: list[str] = field(default_factory=list)
    recent: dict[str, int] = field(default_factory=dict)

    def advance(self, ts: int | None, rid: str | None) -> None:
        if ts is None:
            return
        if rid:
            if len(self.recent) >= MAX_RECENT and rid not in self.recent:
                self.recent.pop(min(self.recent, key=self.recent.__getitem__))  # oldest first (rare, bounded)
            self.recent[rid] = ts
        if self.last_ts_ms is None or ts > self.last_ts_ms:
            self.last_ts_ms, self.ids = ts, ([rid] if rid else [])
        elif ts == self.last_ts_ms and rid and rid not in self.ids and len(self.ids) < MAX_IDS:
            self.ids.append(rid)

    def has(self, ts: int | None, rid: str | None) -> bool:
        if ts is None or rid is None:
            return False
        if ts == self.last_ts_ms and rid in self.ids:
            return True
        return rid in self.recent  # ids are unique per source: a re-delivery may carry another timestamp

    def prune(self, overlap_ms: int) -> None:
        """Keep only recent ids inside [last_ts - overlap, last_ts]."""
        if self.last_ts_ms is None or overlap_ms <= 0:
            self.recent = {}
            return
        lo = self.last_ts_ms - overlap_ms
        self.recent = {k: v for k, v in self.recent.items() if v >= lo}

    def copy(self) -> "Checkpoint":
        return Checkpoint(self.last_ts_ms, list(self.ids), dict(self.recent))

    def to_json(self) -> dict[str, Any]:
        return {"last_ts_ms": self.last_ts_ms, "last_ts": ig.iso_ms(self.last_ts_ms), "ids_at_last_ts": self.ids,
                "recent_ids": [[k, v] for k, v in self.recent.items()]}

    @classmethod
    def from_json(cls, d: dict[str, Any] | None) -> "Checkpoint":
        d = d or {}
        recent: dict[str, int] = {}
        for item in d.get("recent_ids") or []:
            if isinstance(item, list) and len(item) == 2 and isinstance(item[1], int):
                recent[str(item[0])] = item[1]
        return cls(d.get("last_ts_ms"), list(d.get("ids_at_last_ts") or []), recent)


class SpoolWriter:
    """Per-cycle files in <dir>/<source>/[<format>/]; dot-prefixed until commit()."""

    def __init__(self, root: Path, source: str, tag: str, max_bytes: int) -> None:
        self.root, self.source, self.tag, self.max_bytes = root / source, source, tag, max_bytes
        self._files: dict[str, tuple[Any, Path, int]] = {}
        self._parts: list[Path] = []
        self._seq = 0

    def write(self, line: str, bucket: str = "", ext: str = "jsonl") -> None:
        data = (line.replace("\r", " ").replace("\n", " ") + "\n").encode("utf-8")
        cur = self._files.get(bucket)
        if cur is not None and cur[2] + len(data) > self.max_bytes:
            cur[0].close()
            cur = None
        if cur is None:
            self._seq += 1
            d = self.root / bucket if bucket else self.root
            d.mkdir(parents=True, exist_ok=True)
            p = d / f".{self.source}-{self.tag}-{self._seq:04d}.{ext}.part"
            cur = (p.open("wb"), p, 0)
            self._parts.append(p)
        cur[0].write(data)
        self._files[bucket] = (cur[0], cur[1], cur[2] + len(data))

    def _close(self) -> None:
        for fh, _, _ in self._files.values():
            fh.close()
        self._files = {}

    def commit(self) -> list[Path]:
        """Publish the part files under their final names. Never overwrites: if any final name exists, nothing is
        published (FileExistsError; the caller aborts the cycle and counts its rows)."""
        self._close()
        pairs = [(p, p.with_name(p.name[1:-len(".part")])) for p in self._parts]
        clash = [f.name for _, f in pairs if f.exists()]
        if clash:
            raise FileExistsError(f"spool file already exists, not overwriting: {clash[0]}")
        done: list[Path] = []
        try:
            for p, final in pairs:
                os.link(p, final)  # atomic, fails if `final` appeared meanwhile (no silent overwrite)
                done.append(final)
        except OSError:
            for f in done:  # all-or-nothing: the cycle is retried from the same checkpoint
                f.unlink(missing_ok=True)
            raise
        for p, _ in pairs:
            p.unlink(missing_ok=True)
        self._parts = []
        return done

    def abort(self) -> None:
        self._close()
        for p in self._parts:
            p.unlink(missing_ok=True)
        self._parts = []


@dataclass
class CycleStats:
    pulled: int = 0
    written: int = 0
    skipped: dict[str, int] = field(default_factory=dict)
    failed: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def fail(self, reason: str, n: int = 1) -> None:
        self.failed[reason] = self.failed.get(reason, 0) + n

    def to_json(self) -> dict[str, Any]:
        return {"pulled": self.pulled, "written": self.written, "skipped": sum(self.skipped.values()),
                "failed": sum(self.failed.values()), "skipped_reasons": dict(self.skipped),
                "failed_reasons": dict(self.failed)}
