"""Run telemetry: RSS sampled every interval (process + children) and per-stage wall time / peak RSS.

Usage:
    tel = Telemetry(interval_s=0.5); tel.start()
    with tel.stage("ingest"): ...
    tel.write(out_dir / "run_metrics.json", extra={...})
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import psutil

log = logging.getLogger(__name__)


def rss_mb(proc: psutil.Process) -> float:
    """RSS of the process plus all its children, in MB."""
    total = 0
    try:
        total = proc.memory_info().rss
        for child in proc.children(recursive=True):
            try:
                total += child.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return total / (1024 * 1024)


class Telemetry:
    def __init__(self, interval_s: float = 0.5) -> None:
        self.interval_s = float(interval_s)
        self._proc = psutil.Process()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._t0 = time.perf_counter()
        self.peak_rss_mb = 0.0
        self._stage_peak: float | None = None
        self.stages: list[dict[str, Any]] = []

    def _sample(self) -> None:
        mb = rss_mb(self._proc)
        with self._lock:
            self.peak_rss_mb = max(self.peak_rss_mb, mb)
            if self._stage_peak is not None:
                self._stage_peak = max(self._stage_peak, mb)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_s):
            self._sample()

    def start(self) -> Telemetry:
        if self._thread is None:
            self._sample()
            self._thread = threading.Thread(target=self._loop, name="telemetry", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2 * self.interval_s + 1)
            self._thread = None
        self._sample()

    @contextmanager
    def stage(self, name: str) -> Iterator[dict[str, Any]]:
        """Record wall seconds and peak RSS of the enclosed block; yields the (mutable) stage record."""
        rec: dict[str, Any] = {"name": name}
        with self._lock:
            self._stage_peak = 0.0
        self._sample()
        t0 = time.perf_counter()
        try:
            yield rec
        finally:
            self._sample()
            with self._lock:
                rec["wall_s"] = round(time.perf_counter() - t0, 3)
                rec["peak_rss_mb"] = round(self._stage_peak or 0.0, 1)
                self._stage_peak = None
            self.stages.append(rec)

    def total_wall_s(self) -> float:
        return round(time.perf_counter() - self._t0, 3)

    def summary(self, rows: int | None = None) -> dict[str, Any]:
        total = self.total_wall_s()
        return {"total_wall_s": total, "peak_rss_mb": round(self.peak_rss_mb, 1),
                "rows_per_s": round(rows / total, 1) if rows and total > 0 else None,
                "stages": [dict(s) for s in self.stages]}

    def write(self, path: Path, extra: dict[str, Any] | None = None, rows: int | None = None) -> dict[str, Any]:
        """Write run_metrics.json = summary() merged with `extra` (extra never overrides measured keys)."""
        self._sample()
        data = dict(extra or {})
        data.update(self.summary(rows))
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        log.info("run metrics -> %s (total %.1f s, peak %.0f MB)", path, data["total_wall_s"], data["peak_rss_mb"])
        return data
