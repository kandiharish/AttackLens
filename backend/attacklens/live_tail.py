"""Live mode helpers: byte-offset folder tail + atomic JSON files (used by live.py)."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("attacklens.live")

NL = b"\n"


def write_json(path: Path, obj: Any) -> None:
    """Atomic write (tmp + replace) so the API never reads a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _first_line(chunk: bytes) -> str:
    line = chunk.split(NL, 1)[0].decode("utf-8", errors="replace")
    return line.lstrip("﻿").rstrip("\r")


class Tailer:
    """Byte-offset tail of every file under watch_dir; returns only complete (newline-terminated) lines.

    poll() stages new offsets; commit() applies them only after the batch was processed (the engine persists
    state() atomically together with its own state), so a failed cycle re-reads the same bytes. Files that
    shrink are re-read from 0. CSV: the header line seen at offset 0 is remembered and prepended to every later
    chunk, so each chunk is a self-describing CSV file for Stage 0/1. Skip rules = profile skip rules.
    """

    def __init__(self, watch: Path, pcfg: dict[str, Any], max_read: int,
                 is_csv_header: Callable[[str], bool], state: dict[str, Any] | None = None) -> None:
        self.watch, self.max_read, self.is_csv_header = watch, max_read, is_csv_header
        state = state or {}
        self.offsets: dict[str, int] = dict(state.get("offsets") or {})
        self.headers: dict[str, str] = dict(state.get("headers") or {})
        self._pending: dict[str, int] = {}
        self._pending_headers: dict[str, str | None] = {}
        self.skip_names = set(pcfg.get("skip_names") or ["manifest.json"])
        self.skip_suffixes = tuple(pcfg.get("skip_suffixes") or [".md"])
        self.skip_dirs = set(pcfg.get("skip_dir_components") or ["ground_truth"])

    def _skip(self, p: Path) -> bool:
        rel = p.relative_to(self.watch)
        return (p.name in self.skip_names or p.name.endswith(self.skip_suffixes) or p.name.startswith(".")
                or bool(self.skip_dirs.intersection(rel.parts[:-1])))

    def poll(self) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        self._pending, self._pending_headers = {}, {}
        if not self.watch.is_dir():
            return out
        for p in sorted(x for x in self.watch.rglob("*") if x.is_file()):
            if self._skip(p):
                continue
            rel = p.relative_to(self.watch).as_posix()
            off = self.offsets.get(rel, 0)
            size = p.stat().st_size
            if size < off:  # truncated / replaced -> start again
                log.warning("live: %s shrank (%d < %d); re-reading from 0", rel, size, off)
                off = 0
            if size == off:
                continue
            with p.open("rb") as fh:
                fh.seek(off)
                data = fh.read(min(size - off, self.max_read))
            cut = data.rfind(NL)
            if cut < 0:
                continue  # no complete line yet
            chunk = data[: cut + 1]
            header = self.headers.get(rel)
            if off == 0:
                first = _first_line(chunk)
                header = first if self.is_csv_header(first) else None
                self._pending_headers[rel] = header
            elif header is not None:
                chunk = header.encode("utf-8") + NL + chunk
            out[rel] = chunk
            self._pending[rel] = off + cut + 1
        return out

    def commit(self) -> None:
        self.offsets.update(self._pending)
        for rel, h in self._pending_headers.items():
            if h is None:
                self.headers.pop(rel, None)
            else:
                self.headers[rel] = h
        self._pending, self._pending_headers = {}, {}

    def state(self) -> dict[str, Any]:
        return {"offsets": dict(self.offsets), "headers": dict(self.headers)}
