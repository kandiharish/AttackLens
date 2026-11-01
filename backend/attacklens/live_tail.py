"""Live mode helpers: byte-offset folder tail with file identity + atomic JSON files (used by live.py)."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("attacklens.live")

NL = b"\n"
HEAD_BYTES = 64


def write_json(path: Path, obj: Any, retries: int = 20) -> None:
    """Atomic write (tmp + replace). On Windows os.replace fails while a reader holds the file open
    (PermissionError): retry for ~1 s before giving up."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")
    for i in range(retries):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if i == retries - 1:
                raise
            time.sleep(0.05)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _first_line(chunk: bytes) -> str:
    line = chunk.split(NL, 1)[0].decode("utf-8", errors="replace")
    return line.lstrip("﻿").rstrip("\r")


def _head(p: Path) -> str:
    with p.open("rb") as fh:
        return fh.read(HEAD_BYTES).hex()


class Tailer:
    """Byte-offset tail of every file under watch_dir; returns only complete (newline-terminated) lines.

    Per file it keeps {offset, size, ino, dev, head (first 64 bytes), header}. Identity = (ino, dev) + head:
    - same path, different identity (replaced / rotated by copy) -> restart at 0, re-detect the CSV header;
      the old file's unread bytes (last size - offset) are counted in `skipped_bytes`.
    - new path whose identity matches a vanished tracked path (rename rotation) -> carry its offset + header.
    - same identity but smaller (truncated in place) -> restart at 0.
    poll() stages changes; commit() applies them only after the batch was processed (the engine persists
    state() atomically with its own state), so a failed cycle re-reads the same bytes. CSV: the header seen
    at offset 0 is prepended to every later chunk. Skip rules = profile skip rules.
    """

    def __init__(self, watch: Path, pcfg: dict[str, Any], max_read: int,
                 is_csv_header: Callable[[str], bool], state: dict[str, Any] | None = None) -> None:
        self.watch, self.max_read, self.is_csv_header = watch, max_read, is_csv_header
        state = state or {}
        self.files: dict[str, dict[str, Any]] = {k: dict(v) for k, v in (state.get("files") or {}).items()}
        self.counters: dict[str, int] = {"skipped_bytes": 0, "rotations": 0, "renames": 0,
                                         **(state.get("counters") or {})}
        self._pending: dict[str, dict[str, Any]] = {}
        self._pending_counters: dict[str, int] = {}
        self._pending_drop: list[str] = []
        self.skip_names = set(pcfg.get("skip_names") or ["manifest.json"])
        self.skip_suffixes = tuple(pcfg.get("skip_suffixes") or [".md"])
        self.skip_dirs = set(pcfg.get("skip_dir_components") or ["ground_truth"])

    def _skip(self, p: Path) -> bool:
        rel = p.relative_to(self.watch)
        return (p.name in self.skip_names or p.name.endswith(self.skip_suffixes) or p.name.startswith(".")
                or bool(self.skip_dirs.intersection(rel.parts[:-1])))

    def _count(self, key: str, n: int = 1) -> None:
        self._pending_counters[key] = self._pending_counters.get(key, 0) + n

    @staticmethod
    def _same(rec: dict[str, Any], st: os.stat_result, head: str) -> bool:
        old = str(rec.get("head", ""))
        return (rec.get("ino"), rec.get("dev")) == (st.st_ino, st.st_dev) and head[: len(old)] == old

    def _assign(self, infos: dict[str, tuple[Path, os.stat_result, str]]) -> dict[str, dict[str, Any]]:
        """Which tracked record each present path continues (pre-pass, so a rename is never a new file)."""
        assign: dict[str, dict[str, Any]] = {}
        self._pending_drop = []
        for old_rel, rec in self.files.items():
            target = None
            if old_rel in infos and self._same(rec, infos[old_rel][1], infos[old_rel][2]):
                target = old_rel
            else:
                for rel, (_, st, head) in infos.items():
                    mine = self.files.get(rel)
                    fresh = not (mine is not None and self._same(mine, st, head))
                    if rel != old_rel and rel not in assign and fresh and self._same(rec, st, head):
                        target = rel
                        break
            if target is None:  # identity gone: the old file's unread tail can no longer be read
                lost = max(0, int(rec.get("size", 0)) - int(rec.get("offset", 0)))
                if lost:
                    log.warning("live: %s replaced/removed with %d unread bytes", old_rel, lost)
                self._count("skipped_bytes", lost)
                self._count("rotations")
                self._pending_drop.append(old_rel)
                continue
            if target != old_rel:
                log.info("live: %s is the renamed %s; continuing at offset %d", target, old_rel, rec["offset"])
                self._count("renames")
                self._pending_drop.append(old_rel)
            assign[target] = rec
        return assign

    def poll(self) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        self._pending, self._pending_counters = {}, {}
        if not self.watch.is_dir():
            return out
        infos: dict[str, tuple[Path, os.stat_result, str]] = {}
        for p in sorted(self.watch.rglob("*")):
            if p.is_file() and not self._skip(p):
                st = p.stat()
                if st.st_size:
                    infos[p.relative_to(self.watch).as_posix()] = (p, st, _head(p))
        assign = self._assign(infos)
        for rel, (p, st, head) in infos.items():
            rec = assign.get(rel, {"offset": 0, "header": None})
            off = int(rec.get("offset", 0))
            header = rec.get("header")
            if st.st_size < off:  # same file truncated in place
                log.warning("live: %s truncated (%d < %d); re-reading from 0", rel, st.st_size, off)
                self._count("rotations")
                off, header = 0, None
            new = {"offset": off, "size": st.st_size, "ino": st.st_ino, "dev": st.st_dev, "head": head,
                   "header": header}
            if st.st_size > off:
                with p.open("rb") as fh:
                    fh.seek(off)
                    data = fh.read(min(st.st_size - off, self.max_read))
                cut = data.rfind(NL)
                if cut >= 0:
                    chunk = data[: cut + 1]
                    if off == 0:
                        first = _first_line(chunk)
                        new["header"] = first if self.is_csv_header(first) else None
                    elif new["header"] is not None:
                        chunk = new["header"].encode("utf-8") + NL + chunk
                    new["offset"] = off + cut + 1
                    out[rel] = chunk
            if new != self.files.get(rel):
                self._pending[rel] = new
        return out

    def has_pending(self) -> bool:
        return bool(self._pending or self._pending_drop or self._pending_counters)

    def commit(self) -> None:
        for rel in self._pending_drop:
            if rel not in self._pending:
                self.files.pop(rel, None)
        self.files.update(self._pending)
        for k, n in self._pending_counters.items():
            self.counters[k] = self.counters.get(k, 0) + n
        self._pending, self._pending_counters, self._pending_drop = {}, {}, []

    def state(self) -> dict[str, Any]:
        return {"files": {k: dict(v) for k, v in self.files.items()}, "counters": dict(self.counters)}
