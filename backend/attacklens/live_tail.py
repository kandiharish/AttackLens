"""Live mode helpers: byte-offset folder tail + atomic JSON files (used by live.py)."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger("attacklens.live")


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


class Tailer:
    """Byte-offset tail of every file under watch_dir; returns only complete ('\\n'-terminated) lines.

    poll() stages new offsets; commit() makes them durable only after the batch was processed, so a failed
    cycle re-reads the same bytes. Files that shrink are re-read from 0. Skip rules = profile skip rules.
    """

    def __init__(self, watch: Path, state_file: Path, pcfg: dict[str, Any], max_read: int) -> None:
        self.watch, self.state_file, self.max_read = watch, state_file, max_read
        self.offsets: dict[str, int] = read_json(state_file, {})
        self._pending: dict[str, int] = {}
        self.skip_names = set(pcfg.get("skip_names") or ["manifest.json"])
        self.skip_suffixes = tuple(pcfg.get("skip_suffixes") or [".md"])
        self.skip_dirs = set(pcfg.get("skip_dir_components") or ["ground_truth"])

    def _skip(self, p: Path) -> bool:
        rel = p.relative_to(self.watch)
        return (p.name in self.skip_names or p.name.endswith(self.skip_suffixes) or p.name.startswith(".")
                or bool(self.skip_dirs.intersection(rel.parts[:-1])))

    def poll(self) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        self._pending = {}
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
            cut = data.rfind(b"\n")
            if cut < 0:
                continue  # no complete line yet
            out[rel] = data[: cut + 1]
            self._pending[rel] = off + cut + 1
        return out

    def commit(self) -> None:
        self.offsets.update(self._pending)
        self._pending = {}
        write_json(self.state_file, self.offsets)
