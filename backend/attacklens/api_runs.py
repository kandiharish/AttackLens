"""Pipeline runs started from the API: one subprocess per run (`python -m attacklens.run ...`), progress from its log
(stage, percent) and from <out_dir>/progress.json (stage fraction, bytes, ETA: progress_eta.py)."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psutil
import yaml

from attacklens.config import REPO_ROOT
from attacklens.progress import PROGRESS_FILE, EtaConfig, parse_iso, read_json
from attacklens.progress_eta import Estimator, status_fields

log = logging.getLogger(__name__)

# Stage name -> percent complete when that stage STARTS (order = DEVELOPMENT.md §1).
STAGE_PERCENT: dict[str, int] = {
    "profile": 2, "ingest": 5, "lookups": 45, "detect": 50, "episodes": 65,
    "link": 72, "incidents": 80, "publish": 90, "integrity": 93, "eval": 96,
}
INTEGRITY_FILE = "integrity_report.json"
INTEGRITY_KEYS = ("verdict", "trust_score", "summary", "scope")
# only run.py's "stage <name> start|done" lines count: a file named integrity.log / eval-notes.txt that profile logs
# must not move the shown stage
_STAGE_RE = re.compile(r"\bstage (" + "|".join(STAGE_PERCENT) + r") (?:start|done)\b", re.IGNORECASE)
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
    started_at: float = field(default_factory=time.time)
    finished: float | None = None
    stage: str = "starting"
    peak_rss_mb: float = 0.0
    reloaded: bool = False
    error: str | None = None  # cached failure reason (status 'failed' only)
    final_progress: dict[str, Any] | None = None  # progress keys of a finished run (from its run_metrics.json)
    integrity: dict[str, Any] | None = None       # cached integrity summary once a finished run's report exists
    last_progress: dict[str, Any] | None = None   # last readable progress.json (a read racing os.replace fails)

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


_SAFE_PART = re.compile(r"^[A-Za-z0-9._-]+$")


_FAILED_RE = re.compile(r"pipeline failed: (.+)$")
_EXC_RE = re.compile(r"^([A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt|Missing))(?:: (.*))?$")
_LOG_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}[ T][\d:,.]+\s+[A-Z]+\s+[\w.]+:\s*")
_STAGE_START_RE = re.compile(r"\bstage (\w+) start\b")
_ERR_MAX = 300
_REDACTED = "<redacted>"
# DuckDB (and most parsers) quote the offending input value, then add "LINE n: <sql>" / "near <text>" /
# "Input: <text>" context: everything from those markers on is dropped.
_TAIL_CUT = re.compile(r"(?:\bLINE\b|\bnear\b|\bInput:).*$")
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"|`[^`]*`")  # an escaped quote leaves an odd one: _OPEN_QUOTE eats it
_OPEN_QUOTE = re.compile(r"['\"`].*$")  # an unterminated quote (message cut in the log) runs to the end
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_error(msg: str) -> str:
    """'<Type>: <message>' with every quoted literal and everything after LINE / near / Input: redacted, control
    chars stripped. The exception type is kept verbatim; the message never carries input values."""
    msg = _CTRL.sub(" ", msg).strip()
    head, sep, rest = msg.partition(": ")
    if not sep or not re.fullmatch(r"[A-Za-z_][\w.]*", head):
        head, rest = "", msg
    rest = _TAIL_CUT.sub(_REDACTED, rest)
    rest = re.sub(r"\\.", "_", rest)  # escaped quotes (\' \") must not end a quoted literal early
    rest = _QUOTED.sub(_REDACTED, rest)
    rest = _OPEN_QUOTE.sub(_REDACTED, rest)
    rest = re.sub(r"\s+", " ", rest).strip()
    return f"{head}: {rest}" if head and rest else (head or rest)


def _cap(msg: str, n: int = _ERR_MAX) -> str:
    return msg if len(msg) <= n else msg[: n - 3] + "..."


def run_error(log_path: Path) -> str:
    """Short failure reason for a run with rc != 0, from the pipeline's own messages only:
    run.py's "pipeline failed: <Type>: <msg>" line, else the last exception line of a traceback, else a generic
    note. Never an arbitrary log line, and the message is sanitized (sanitize_error: DuckDB errors quote input
    values). Suffix "(stage <name>)" = the last stage that started. Control chars stripped, <= 300 chars."""
    try:
        with log_path.open("rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - _TAIL_BYTES))
            lines = fh.read().decode("utf-8", errors="replace").splitlines()
    except OSError:
        return "run failed (log unreadable)"
    failed = exc = stage = None
    for raw in lines:
        line = _LOG_PREFIX.sub("", raw.strip())
        if (m := _FAILED_RE.search(line)) is not None:
            failed = m.group(1)
        elif _EXC_RE.match(line):
            exc = line
        elif (st := _STAGE_START_RE.search(line)) is not None and st.group(1).lower() in STAGE_PERCENT:
            stage = st.group(1).lower()
    if failed or exc:
        msg = sanitize_error(failed or exc or "")
    else:
        msg = "run failed (no exception message in the log)"
    suffix = f" (stage {stage})" if stage else ""
    return _cap(msg, _ERR_MAX - len(suffix)) + suffix


def resolve_path(p: str) -> Path:
    path = Path(p)
    return (path if path.is_absolute() else REPO_ROOT / path).resolve()


def _shown(root: Path) -> str:
    """Root as shown in error messages: repo-relative when possible (never the submitted path)."""
    try:
        return root.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return root.name


def confined(p: str, root: Path, what: str, depth: int | None = None) -> Path:
    """Resolve p and require it strictly under root with plain name parts (paths end up in DuckDB SQL).
    depth: exact number of path parts below root (out_dir = data/out/<one name>, because the default parquet dir
    is data/parquet/<basename of out>: a nested out dir could map onto another run's events). Errors never echo
    the submitted path."""
    try:
        path = resolve_path(p)
        rel = path.relative_to(root.resolve())
    except (ValueError, OSError):
        raise ValueError(f"{what} must be under {_shown(root)}/") from None
    if not rel.parts or not all(_SAFE_PART.match(x) for x in rel.parts):
        raise ValueError(f"{what} must be a sub-directory of {_shown(root)}/ "
                         f"with names of [A-Za-z0-9._-]")
    if depth is not None and len(rel.parts) != depth:
        raise ValueError(f"{what} must be exactly {_shown(root)}/<name>")
    return path


def _norm(p: Path) -> Path:
    """Case-folded absolute path for comparisons (NTFS is case-insensitive)."""
    return Path(os.path.normcase(str(p.resolve())))


def confined_raw(p: str, raw_root: Path, upload_root: Path) -> Path:
    """raw_dir must be exactly data/raw/<set> or <upload root>/<upload_id>: never the upload root itself, a folder
    holding it (data/raw), anything deeper, or a dot-directory (.incoming / .meta hold partial uploads and metadata)."""
    raw = confined(p, raw_root, "raw_dir")
    shape = f"raw_dir must be {_shown(raw_root)}/<set> or {_shown(upload_root)}/<upload_id>"
    if any(x.startswith(".") for x in raw.relative_to(raw_root.resolve()).parts):
        raise ValueError(f"{shape} (no hidden directories)")
    r, up, root = _norm(raw), _norm(upload_root), _norm(raw_root)
    if r == up or up.is_relative_to(r):
        raise ValueError(f"{shape}, not a directory that holds uploads")
    depth = len(r.relative_to(up).parts) if r.is_relative_to(up) else None
    if (depth if depth is not None else len(r.relative_to(root).parts)) != 1:
        raise ValueError(shape)
    return raw


def _live_owned(out: Path) -> bool:
    """True if out is live.yaml's out_dir or holds a fresh live_status.json (a batch run there would race it)."""
    try:
        lcfg = yaml.safe_load((REPO_ROOT / "config" / "live.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        lcfg = {}
    live_out = resolve_path(str(lcfg.get("out_dir", "data/out/live")))
    if out.resolve() == live_out:
        return True
    from attacklens import live  # lazy: pulls in the pipeline modules

    return bool(live.status(out, {"live": lcfg}).get("enabled"))


def _own_file(path: Path, job: RunJob) -> dict[str, Any] | None:
    """path's JSON if this job wrote it (not a stale file of an earlier run in the same out dir), else None."""
    data = read_json(path)
    if data is None:
        return None
    if path.name == PROGRESS_FILE:
        started = parse_iso(data.get("run_started_utc"))
        ok = data.get("pid") == job.proc.pid or (started is not None and started >= job.started_at - 1.0)
    else:
        try:
            ok = path.stat().st_mtime >= job.started_at - 1.0
        except OSError:
            ok = False
    return data if ok else None


def run_integrity_report(job: RunJob) -> dict[str, Any] | None:
    """This run's <out_dir>/integrity_report.json (None until it exists, is complete, and was written by this run).
    A report without "scope" is a full (files + events) check."""
    rep = _own_file(job.out_dir / INTEGRITY_FILE, job)
    if rep is None or not isinstance(rep.get("verdict"), str):
        return None
    rep.setdefault("scope", "full")
    return rep


def _typed_summary(rep: Any) -> dict[str, Any] | None:
    """The INTEGRITY_KEYS of a report with the types the UI expects (types.ts RunIntegritySummary), else None."""
    if not isinstance(rep, dict):
        return None
    verdict, score, summary, scope = (rep.get(k) for k in INTEGRITY_KEYS)
    if verdict not in ("trusted", "suspect", "tampered") or not isinstance(summary, str):
        return None
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        return None
    return {"verdict": verdict, "trust_score": score, "summary": summary,
            "scope": scope if scope in ("quick", "full") else "full"}  # missing scope = full (contract)


def integrity_summary(job: RunJob) -> dict[str, Any] | None:
    """{"verdict", "trust_score", "summary", "scope"} of this run's integrity report, or None (never raises)."""
    if job.integrity is not None:
        return job.integrity
    try:
        rep = run_integrity_report(job)
    except Exception:  # noqa: BLE001 - the integrity summary never breaks GET /api/runs
        log.warning("run %s: integrity summary failed", job.run_id, exc_info=True)
        return None
    if rep is None:
        return None
    summary = _typed_summary(rep)
    if summary is None:
        log.warning("run %s: malformed integrity report ignored", job.run_id)
        return None
    if job.status != "running":  # the report of a finished run no longer changes
        job.integrity = summary
    return summary


def default_estimator() -> Estimator:
    """ETA estimator from config/pipeline.yaml `eta:` (history glob relative to the repo root)."""
    try:
        pcfg = yaml.safe_load((REPO_ROOT / "config" / "pipeline.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        pcfg = {}
    return Estimator(EtaConfig.from_dict(pcfg.get("eta") if isinstance(pcfg, dict) else None), REPO_ROOT)


class RunManager:
    """Owns the run subprocesses. One run at a time (the pipeline needs the whole RAM budget)."""

    def __init__(self, runs_dir: Path | None = None, raw_root: Path | None = None,
                 out_root: Path | None = None, runner: list[str] | None = None,
                 upload_root: Path | None = None, parquet_root: Path | None = None,
                 estimator: Estimator | None = None) -> None:
        # runner: command prefix before "--raw ... --out ..." (tests inject a stub pipeline)
        self.runner = runner or [sys.executable, "-m", "attacklens.run"]
        self.raw_root = raw_root or REPO_ROOT / "data" / "raw"
        self.out_root = out_root or REPO_ROOT / "data" / "out"
        self.upload_root = upload_root or self.raw_root / "uploads"   # pipeline.yaml upload.root
        self.parquet_root = parquet_root or REPO_ROOT / "data" / "parquet"   # pipeline.yaml parquet_root
        self._runs: dict[str, RunJob] = {}
        self._lock = threading.Lock()        # guards _runs
        self._start_lock = threading.Lock()  # serializes start() end to end
        self._runs_dir = runs_dir or REPO_ROOT / "data" / "runs"
        self.estimator = estimator or default_estimator()

    def active(self) -> RunJob | None:
        with self._lock:
            return next((j for j in self._runs.values() if j.status == "running"), None)

    def start(self, raw_dir: str, out_dir: str | None, ground_truth: str | None,
              protect: Iterable[Path | None] = ()) -> RunJob:
        """protect: out dirs the API serves now. A run never writes into one (the store's mtime watcher would load
        half-written output and a failed run would leave it mixed): an explicit out_dir there is refused, the
        default data/out/<raw name> becomes data/out/<raw name>-<run_id> (parquet dir kept at <raw name>, which the
        API never reads). The store switches to the new dir only after rc 0 (AppState.refresh)."""
        raw = confined_raw(raw_dir, self.raw_root, self.upload_root)
        if not raw.is_dir():
            raise ValueError("raw_dir is not an existing directory")
        run_id = uuid.uuid4().hex[:12]
        guarded = {_norm(p) for p in protect if p is not None}
        extra: list[str] = []
        if out_dir:
            out = confined(out_dir, self.out_root, "out_dir", depth=1)
            if _norm(out) in guarded:
                raise ValueError("out_dir is the output the API is serving now; omit out_dir (a fresh one is used) "
                                 "or choose another name")
        else:
            out = confined(str(self.out_root / raw.name), self.out_root, "out_dir", depth=1)
            if _norm(out) in guarded:
                out = confined(str(self.out_root / f"{raw.name}-{run_id}"), self.out_root, "out_dir", depth=1)
                extra = ["--parquet", str(self.parquet_root / raw.name)]
        if _live_owned(out):
            raise ValueError("out_dir is the live-mode output (live.yaml out_dir or a running live engine)")
        cmd = [*self.runner, "--raw", str(raw), "--out", str(out), *extra]
        if ground_truth:
            gt = confined(ground_truth, self.raw_root, "ground_truth")
            if not gt.is_file():
                raise ValueError("ground_truth is not an existing file")
            cmd += ["--ground-truth", str(gt)]
        with self._start_lock:  # check + spawn + register atomically: two concurrent POSTs cannot both start
            if self.active() is not None:
                raise RuntimeError("a run is already in progress")
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

    @staticmethod
    def _fail_reason(job: RunJob) -> str:
        job.error = run_error(job.log_path)
        return job.error

    def list(self) -> list[dict[str, Any]]:
        """GET /api/runs: every job, newest first, same shape as GET /api/runs/{id}."""
        return [self.status(j) for j in sorted(self.jobs(), key=lambda j: j.started_at, reverse=True)]

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
            "error": job.error if st != "failed" else (job.error or self._fail_reason(job)),
            "elapsed_s": round(end - job.started, 1), "rss_mb": round(rss, 1),
            "peak_rss_mb": round(job.peak_rss_mb, 1), "returncode": job.proc.returncode,
            "out_dir": str(job.out_dir), "log": str(job.log_path), "raw_dir": str(job.raw_dir),
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(job.started_at)),
            "integrity": integrity_summary(job),
            **self._progress(job, st),
        }

    def _progress(self, job: RunJob, st: str) -> dict[str, Any]:
        """stage_elapsed_s, stage_fraction, stages_done, bytes_*, rows_done, ingest_mb_s, eta_s, eta_basis,
        eta_total_s. A missing / partial / garbled / stale progress.json or run_metrics.json gives nulls."""
        try:
            if st == "running":
                prog = _own_file(job.out_dir / PROGRESS_FILE, job) or job.last_progress
                job.last_progress = prog
                return status_fields(prog, None, True, self.estimator, job.out_dir)
            if job.final_progress is None:
                metrics = _own_file(job.out_dir / "run_metrics.json", job)
                job.final_progress = status_fields(None, metrics, False, None, job.out_dir)
            return dict(job.final_progress)
        except Exception:  # noqa: BLE001 - progress keys never break GET /api/runs
            log.warning("run %s: progress keys failed", job.run_id, exc_info=True)
            return status_fields(None, None, True, None, None)
