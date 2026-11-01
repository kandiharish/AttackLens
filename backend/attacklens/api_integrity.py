"""Log integrity (tamper check) endpoints. Reports come from attacklens.integrity (integrity_report.json).

GET  /api/integrity                     report of the dataset the API serves now (<served out_dir>/integrity_report.json)
GET  /api/runs/{run_id}/integrity       that run's report (404 until written by that run)
POST /api/uploads/{upload_id}/integrity (re)start the QUICK scan (raw files only) -> 202 {"status"}; 404 / 409
GET  /api/uploads/{upload_id}/integrity {"status": pending|running|done|failed, "report", "error"}

Quick scans run on a bounded thread pool (max_workers, default 2; never on the event loop) into
<out_root>/_integrity/<upload_id>/ (upload_id validated against the upload id pattern, never a raw path). The report
is written to a temp dir and moved into place, so a reader never sees a half-written file; reports persist, so a GET
after an API restart returns the stored report (status done). A completed upload auto-starts its quick scan
(UploadManager.on_complete).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from attacklens.api_runs import run_integrity_report, sanitize_error
from attacklens.api_upload import UploadManager

log = logging.getLogger(__name__)

REPORT = "integrity_report.json"
QUICK_DIR = "_integrity"
_NO_REPORT = {"detail": "no integrity report"}

ScanFn = Callable[[Path, Path], dict[str, Any]]


def _read(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("verdict"), str) else None


def _replace(src: Path, dst: Path, tries: int = 5) -> None:
    """os.replace, retried briefly: on Windows a reader holding dst open makes it fail with PermissionError."""
    for i in range(tries):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if i == tries - 1:
                raise
            time.sleep(0.05 * (i + 1))


def quick_scan(raw_dir: Path, out_dir: Path) -> dict[str, Any]:
    """integrity.check on the raw files only: parquet_dir points at a directory that never exists, so the event
    checks are skipped even when a pipeline run already wrote data/parquet/<upload_id>."""
    from attacklens import integrity  # lazy: pulls in DuckDB

    rep = integrity.check(raw_dir, out_dir, parquet_dir=out_dir / "_no_events")
    rep.setdefault("scope", "quick")
    return rep


@dataclass
class _Job:
    status: str           # pending | running | done | failed
    error: str | None = None
    finished: threading.Event = field(default_factory=threading.Event)  # set once status is done | failed


class IntegrityScans:
    """Background quick scans of uploads (bounded pool, one job per upload id at a time)."""

    def __init__(self, uploads: UploadManager, out_root: Path, max_workers: int = 2,
                 scan: ScanFn | None = None) -> None:
        self.uploads, self.root = uploads, Path(out_root) / QUICK_DIR
        self._scan = scan or quick_scan
        self.max_workers = max(1, int(max_workers))
        self._pool = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="integrity-scan")
        self._jobs: dict[str, _Job] = {}
        self._lock = threading.Lock()   # guards _jobs: check-and-set per upload id is atomic

    def out_dir(self, uid: str) -> Path:
        return self.root / uid

    def start(self, uid: str) -> str:
        """Queue the quick scan of upload uid; returns its status. KeyError: unknown upload; RuntimeError: busy."""
        raw = self.uploads.upload_dir(uid)
        if raw is None:
            raise KeyError(uid)
        with self._lock:
            job = self._jobs.get(uid)
            if job is not None and job.status in ("pending", "running"):
                raise RuntimeError("integrity scan already running")
            busy = sum(1 for j in self._jobs.values() if j.status in ("pending", "running"))
            # "running" when a pool worker is free (it starts now), "pending" while queued behind max_workers scans
            job = self._jobs[uid] = _Job("running" if busy < self.max_workers else "pending")
        self._pool.submit(self._work, uid, raw, job)
        return job.status

    def auto_start(self, info: dict[str, Any]) -> dict[str, Any] | None:
        """UploadManager.on_complete hook: start the quick scan of a just-finished upload."""
        try:
            return {"status": self.start(str(info.get("upload_id")))}
        except (KeyError, RuntimeError) as exc:
            log.warning("integrity: auto-start for %s skipped: %s", info.get("upload_id"), exc)
            return None

    def _work(self, uid: str, raw: Path, job: _Job) -> None:
        with self._lock:
            job.status = "running"
        final = self.out_dir(uid)
        tmp_parent = self.root / f".tmp-{uuid.uuid4().hex[:8]}"
        tmp = tmp_parent / uid   # report "set" = out dir name = the upload id
        try:
            tmp.mkdir(parents=True, exist_ok=True)
            self._scan(raw, tmp)
            rep = _read(tmp / REPORT)
            if rep is None:
                raise RuntimeError("scan wrote no readable integrity_report.json")
            if rep.get("scope") is None:  # the stored file itself says what was checked (files only)
                rep["scope"] = "quick"
                (tmp / REPORT).write_text(json.dumps(rep, indent=2, default=str), encoding="utf-8")
            final.mkdir(parents=True, exist_ok=True)
            _replace(tmp / REPORT, final / REPORT)
            status, error = "done", None
            log.info("integrity: quick scan of %s done -> %s", uid, (final / REPORT).as_posix())
        except Exception as exc:  # noqa: BLE001 - any failure becomes status 'failed' with a sanitized message
            log.exception("integrity: quick scan of %s failed", uid)
            status, error = "failed", sanitize_error(f"{type(exc).__name__}: {exc}")[:300]
            (final / REPORT).unlink(missing_ok=True)   # an older report would describe the files as they were
        finally:
            shutil.rmtree(tmp_parent, ignore_errors=True)
        with self._lock:
            job.status, job.error = status, error
        job.finished.set()

    def wait(self, uid: str, timeout: float | None = None) -> bool:
        """Block until upload uid's current scan is done/failed (True), or timeout (False). No scan known: True."""
        with self._lock:
            job = self._jobs.get(uid)
        return True if job is None else job.finished.wait(timeout)

    def get(self, uid: str) -> dict[str, Any]:
        """Status + report of upload uid. KeyError: unknown upload."""
        if self.uploads.upload_dir(uid) is None:
            raise KeyError(uid)
        with self._lock:
            job = self._jobs.get(uid)
            status, error = (job.status, job.error) if job is not None else (None, None)
        if status in ("pending", "running", "failed"):
            return {"status": status, "report": None, "error": error}
        rep = _read(self.out_dir(uid) / REPORT)
        if rep is None:
            if status == "done":
                return {"status": "failed", "report": None, "error": "integrity report missing or unreadable"}
            return {"status": "pending", "report": None, "error": None}
        rep.setdefault("scope", "quick")
        return {"status": "done", "report": rep, "error": None}

    def shutdown(self, wait: bool = False) -> None:
        """Cancel queued scans; wait=True also blocks until a running scan finishes (app shutdown, tests)."""
        self._pool.shutdown(wait=wait, cancel_futures=True)
        with self._lock:  # queued scans that were cancelled never run _work: settle them so wait() returns
            for job in self._jobs.values():
                if job.status == "pending":
                    job.status, job.error = "failed", "cancelled: API shutting down"
                    job.finished.set()


def create_router(state: Any, run_id_re: re.Pattern[str]) -> APIRouter:
    """state: api.AppState (store, runs, uploads, refresh). Wires the upload auto-start hook."""
    scans: IntegrityScans | None = getattr(state, "integrity_scans", None)
    if scans is None:
        scans = IntegrityScans(state.uploads, state.runs.out_root)
        state.integrity_scans = scans
    state.uploads.on_complete = scans.auto_start
    router = APIRouter()

    @router.get("/api/integrity", response_model=None)
    def served() -> dict[str, Any] | JSONResponse:
        state.refresh()
        out = state.store.snap.out_dir
        rep = _read(Path(out) / REPORT) if out is not None else None
        if rep is None:
            return JSONResponse(_NO_REPORT, status_code=404)
        rep.setdefault("scope", "full")
        return rep

    @router.get("/api/runs/{run_id}/integrity", response_model=None)
    def run_report(run_id: str) -> dict[str, Any] | JSONResponse:
        job = state.runs.get(run_id) if run_id_re.match(run_id) else None
        if job is None:
            raise HTTPException(status_code=404, detail="run not found")
        rep = run_integrity_report(job)
        return rep if rep is not None else JSONResponse(_NO_REPORT, status_code=404)

    @router.post("/api/uploads/{upload_id}/integrity", status_code=202)
    def start_scan(upload_id: str) -> dict[str, Any]:
        try:
            return {"status": scans.start(upload_id)}
        except KeyError:
            raise HTTPException(status_code=404, detail="upload not found") from None
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None

    @router.get("/api/uploads/{upload_id}/integrity")
    def scan_status(upload_id: str) -> dict[str, Any]:
        try:
            return scans.get(upload_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="upload not found") from None

    return router
