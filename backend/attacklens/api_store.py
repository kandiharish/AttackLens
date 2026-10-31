"""In-memory store of published JSON (incidents, index, metrics) for the API. Reads never touch disk.

Snapshots are immutable and swapped atomically, so request threads never see a half-loaded state.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from attacklens.config import REPO_ROOT
from attacklens.models import Incident

log = logging.getLogger(__name__)

ENV_OUT = "ATTACKLENS_OUT"
INDEX_FILE = "incidents_index.json"
METRIC_FILES = {"run_metrics": "run_metrics.json", "eval_scorecard": "eval_scorecard.json",
                "ingest_accounting": "ingest_accounting.json"}
PATH_KEYS = ("id", "backbone", "branches", "edges")


def _dumps(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        log.warning("api: cannot read %s: %s", path, exc)
        return None


def _mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def default_out_dir() -> Path | None:
    """$ATTACKLENS_OUT, else the most recently modified data/out/<set> holding incidents_index.json."""
    env = os.environ.get(ENV_OUT)
    if env:
        return Path(env).resolve()
    root = REPO_ROOT / "data" / "out"
    cands = [p.parent for p in root.glob(f"*/{INDEX_FILE}")] if root.is_dir() else []
    return max(cands, key=lambda d: _mtime(d / INDEX_FILE) or 0.0) if cands else None


@dataclass(frozen=True)
class Snapshot:
    out_dir: Path | None
    loaded_at: float
    index_bytes: bytes = b"[]"
    incident_bytes: dict[str, bytes] = field(default_factory=dict)
    path_bytes: dict[str, bytes] = field(default_factory=dict)
    metrics_bytes: bytes = b'{"run_metrics":null,"eval_scorecard":null,"ingest_accounting":null}'
    stamps: tuple[float | None, ...] = ()
    count: int = 0
    invalid: int = 0


def _stamps(out_dir: Path | None) -> tuple[float | None, ...]:
    if out_dir is None:
        return ()
    return tuple(_mtime(out_dir / f) for f in (INDEX_FILE, *METRIC_FILES.values()))


def load_snapshot(out_dir: Path | None) -> Snapshot:
    stamps = _stamps(out_dir)
    if out_dir is None:
        return Snapshot(None, time.time())
    index = _read_json(out_dir / INDEX_FILE)
    if isinstance(index, dict):  # tolerate {"incidents": [...]}
        index = index.get("incidents")
    rows = [r for r in index if isinstance(r, dict) and "id" in r] if isinstance(index, list) else []
    rows.sort(key=lambda r: (-(r.get("risk") or 0), str(r.get("id"))))
    incidents: dict[str, bytes] = {}
    paths: dict[str, bytes] = {}
    invalid = 0
    for row in rows:
        inc_id = str(row["id"])
        data = _read_json(out_dir / "incidents" / f"{inc_id}.json")
        if not isinstance(data, dict):
            log.warning("api: incident %s listed in index but file missing/unreadable", inc_id)
            continue
        try:
            Incident.model_validate(data)
        except ValidationError as exc:  # serve it anyway; the contract test is the gate
            invalid += 1
            log.warning("api: incident %s does not match the contract: %s", inc_id, exc.errors()[:3])
        incidents[inc_id] = _dumps(data)
        paths[inc_id] = _dumps({k: data.get(k, [] if k != "id" else inc_id) for k in PATH_KEYS})
    metrics = {k: _read_json(out_dir / f) for k, f in METRIC_FILES.items()}
    log.info("api: loaded %d incidents from %s (%d off-contract)", len(incidents), out_dir, invalid)
    return Snapshot(out_dir, time.time(), _dumps(rows), incidents, paths, _dumps(metrics), stamps,
                    len(incidents), invalid)


class Store:
    """The single app-state object: current snapshot + rate-limited mtime check."""

    def __init__(self, check_interval_s: float = 1.0) -> None:
        self._snap: Snapshot | None = None
        self._lock = threading.Lock()
        self._last_check = 0.0
        self._interval = check_interval_s
        self._pinned: Path | None = None  # out dir chosen by a finished run (when $ATTACKLENS_OUT is unset)

    def _target(self) -> Path | None:
        if os.environ.get(ENV_OUT):
            return default_out_dir()
        return self._pinned or default_out_dir()

    @property
    def snap(self) -> Snapshot:
        snap = self._snap
        if snap is None:
            return self.reload()
        return snap

    def reload(self, out_dir: Path | None = None) -> Snapshot:
        with self._lock:
            if out_dir is not None and not os.environ.get(ENV_OUT):
                self._pinned = out_dir.resolve()
            snap = load_snapshot(self._target())
            self._snap = snap
            self._last_check = time.monotonic()
            return snap

    def maybe_reload(self) -> None:
        """At most once per interval: reload if the out dir changed or any watched file's mtime changed."""
        now = time.monotonic()
        if self._snap is not None and now - self._last_check < self._interval:
            return
        self._last_check = now
        snap = self._snap
        target = self._target()
        if snap is None or snap.out_dir != target or _stamps(target) != snap.stamps:
            self.reload()
