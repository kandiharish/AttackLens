"""Pipeline runs started from the API: one subprocess per run (`python -m attacklens.run ...`), progress from its log."""

from __future__ import annotations

import logging
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil

from attacklens.config import REPO_ROOT

log = logging.getLogger(__name__)

# Stage name -> percent complete when that stage STARTS (order = DEVELOPMENT.md §1).
STAGE_PERCENT: dict[str, int] = {
    "profile": 2, "ingest": 5, "lookups": 45, "detect": 50, "episodes": 65,
    "link": 72, "incidents": 80, "publish": 90, "eval": 96,
}
_STAGE_RE = re.compile(r"\b(" + "|".join(STAGE_PERCENT) + r")\b", re.IGNORECASE)
_TAIL_BYTES = 64 * 1024


@dataclass
class RunJob:
    run_id: str
    raw_dir: Path
    out_dir: Path
    log_path: Path
    cmd: list[str]
    proc: subprocess.Popen[bytes]
    started: float = field(default_factory=time.monotonic)
    finished: float | None = None
    stage: str = "starting"
    peak_rss_mb: float = 0.0
    reloaded: bool = False

    @property
    def status(self) -> str:
        rc = self.proc.poll()
        if rc is None:
            return "running"
        return "succeeded" if rc == 0 else "failed"


def _rss_mb(pid: int) -> float:
    try:
        p = psutil.Process(pid)
        procs = [p, *p.children(recursive=True)]
        return sum(q.memory_info().rss for q in procs) / 2**20
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0.0


def _furthest_stage(log_path: Path) -> str | None:
    """Furthest stage name mentioned in the log tail (monotonic, robust to log wording)."""
    try:
        with log_path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - _TAIL_BYTES))
            tail = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return None
    seen = {m.group(1).lower() for m in _STAGE_RE.finditer(tail)}
    return max(seen, key=lambda s: STAGE_PERCENT[s]) if seen else None


def resolve_path(p: str) -> Path:
    path = Path(p)
    return (path if path.is_absolute() else REPO_ROOT / path).resolve()


class RunManager:
    """Owns the run subprocesses. One run at a time (the pipeline needs the whole RAM budget)."""

    def __init__(self, runs_dir: Path | None = None) -> None:
        self._runs: dict[str, RunJob] = {}
        self._lock = threading.Lock()
        self._runs_dir = runs_dir or REPO_ROOT / "data" / "runs"

    def active(self) -> RunJob | None:
        with self._lock:
            return next((j for j in self._runs.values() if j.status == "running"), None)

    def start(self, raw_dir: str, out_dir: str | None, ground_truth: str | None) -> RunJob:
        raw = resolve_path(raw_dir)
        if not raw.is_dir():
            raise ValueError(f"raw_dir is not a directory: {raw_dir}")
        out = resolve_path(out_dir) if out_dir else REPO_ROOT / "data" / "out" / raw.name
        cmd = [sys.executable, "-m", "attacklens.run", "--raw", str(raw), "--out", str(out)]
        if ground_truth:
            gt = resolve_path(ground_truth)
            if not gt.is_file():
                raise ValueError(f"ground_truth is not a file: {ground_truth}")
            cmd += ["--ground-truth", str(gt)]
        if self.active() is not None:
            raise RuntimeError("a run is already in progress")
        run_id = uuid.uuid4().hex[:12]
        self._runs_dir.mkdir(parents=True, exist_ok=True)
        log_path = self._runs_dir / f"run-{run_id}.log"
        with log_path.open("wb") as fh:
            proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    cwd=str(REPO_ROOT))
        job = RunJob(run_id, raw, out, log_path, cmd, proc)
        with self._lock:
            self._runs[run_id] = job
        log.info("run %s started: %s (log %s)", run_id, " ".join(cmd), log_path)
        return job

    def get(self, run_id: str) -> RunJob | None:
        with self._lock:
            return self._runs.get(run_id)

    def jobs(self) -> list[RunJob]:
        with self._lock:
            return list(self._runs.values())

    def status(self, job: RunJob) -> dict[str, Any]:
        st = job.status
        stage = _furthest_stage(job.log_path)
        if stage:
            job.stage = stage
        if st == "running":
            rss = _rss_mb(job.proc.pid)
            job.peak_rss_mb = max(job.peak_rss_mb, rss)
            percent = STAGE_PERCENT.get(job.stage, 0)
        else:
            if job.finished is None:
                job.finished = time.monotonic()
                log.info("run %s finished: %s (rc=%s)", job.run_id, st, job.proc.returncode)
            rss = 0.0
            percent = 100 if st == "succeeded" else STAGE_PERCENT.get(job.stage, 0)
            job.stage = "done" if st == "succeeded" else job.stage
        end = job.finished if job.finished is not None else time.monotonic()
        return {
            "run_id": job.run_id, "status": st, "stage": job.stage, "percent": percent,
            "elapsed_s": round(end - job.started, 1), "rss_mb": round(rss, 1),
            "peak_rss_mb": round(job.peak_rss_mb, 1), "returncode": job.proc.returncode,
            "out_dir": str(job.out_dir), "log": str(job.log_path),
        }
