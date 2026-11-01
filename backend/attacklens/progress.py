"""Run progress and ETA.

Pipeline side (run.py): ProgressWriter writes <out_dir>/progress.json atomically (tmp + os.replace) every
eta.progress_interval_s and at every stage boundary:
    {"run_started_utc", "stage", "stage_index", "stages_total", "stage_started_utc", "stage_fraction",
     "bytes_total", "bytes_done", "rows_done", "stages_done": [{"stage", "wall_s"}], "updated_utc",
     + extras: "pid", "stages_planned", "source_type", "query_fraction", "finished", "error"}
stage_fraction is only set for ingest (batches finished + DuckDB query_progress() of the running COPY x its bytes);
other stages run many queries, so their fraction is null and the ETA uses history. No event data is read here.

API side: progress_eta.py (history-based ETA + the status() keys). All knobs: config/pipeline.yaml `eta:`.
"""

from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import duckdb

log = logging.getLogger(__name__)

PROGRESS_FILE = "progress.json"


@dataclass(frozen=True)
class EtaConfig:
    progress_interval_s: float = 2.0
    query_progress: bool = True              # poll DuckDB query_progress() for the ingest fraction
    ingest_copy_share: float = 0.9           # share of ingest wall spent in the COPY batches (rest: accounting)
    history_glob: str = "data/out/*/run_metrics.json"
    history_ttl_s: float = 60.0
    similar_runs: int = 5
    small_input_bytes: float = 1.0e8
    additive: bool = True                    # expected = floor + marginal rate x MB (else max(floor, rate x MB))
    live_min_fraction: float = 0.05
    live_blend: bool = True                  # remaining = f x live + (1 - f) x history (f = stage_fraction)
    overrun_share: float = 0.5               # no-fraction stage: knee at (1 - this) x expected (progress_eta.py)
    overrun_decay: bool = True               # past the knee the remaining time decays (False: max(exp - t, share x t))
    calibrate: bool = True                   # scale history by (actual / expected) of this run's finished stages
    calibrate_min_expected_s: float = 2.0
    calibrate_overrun: bool = False          # an overrunning current stage also slows the future stages
    calibrate_skip: tuple[str, ...] = ("profile",)   # stages not used for calibration (I/O-bound, cold cache)
    gap_estimate: bool = True                # add this run's measured time between stages to the remaining ones
    calibrate_min: float = 0.5
    calibrate_max: float = 2.0
    no_history_zero: tuple[str, ...] = ("integrity",)  # future stages that count 0 s (not null ETA) without history

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> EtaConfig:
        """Known keys, coerced to the default's type (YAML 1.1 reads `1.0e8` as a string); a bad value keeps
        the default (logged)."""
        out: dict[str, Any] = {}
        for f in fields(cls):
            v = (d or {}).get(f.name) if isinstance(d, dict) else None
            if v is None:
                continue
            kind = type(f.default)
            try:
                if kind is tuple:
                    if not isinstance(v, (list, tuple)):
                        raise ValueError(f"not a list: {v!r}")
                    out[f.name] = tuple(str(x) for x in v)
                    continue
                out[f.name] = v if kind is bool and isinstance(v, bool) else kind(float(v)) if kind in (int, float) \
                    else kind(v)
                if kind is bool and not isinstance(v, bool):
                    raise ValueError(f"not a bool: {v!r}")
            except (TypeError, ValueError):
                out.pop(f.name, None)
                log.warning("pipeline.yaml eta.%s=%r ignored (default %r)", f.name, v, f.default)
        return cls(**out)


# ---------------------------------------------------------------- small IO helpers

def iso_z(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def parse_iso(s: Any) -> float | None:
    if not isinstance(s, str) or not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).timestamp()


def write_json_atomic(path: Path, data: dict[str, Any], retries: int = 5) -> bool:
    """tmp file in the same dir + os.replace. On Windows a reader holding the file open makes replace fail
    (PermissionError): retried briefly, then this snapshot is skipped. Never raises."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(data, default=str), encoding="utf-8")
        for i in range(retries):
            try:
                os.replace(tmp, path)
                return True
            except PermissionError:
                time.sleep(0.02 * (i + 1))
        tmp.unlink(missing_ok=True)
    except OSError as exc:
        log.debug("progress write failed: %s", exc)
    return False


def read_json(path: Path, retries: int = 5) -> dict[str, Any] | None:
    """A JSON object from path, or None (missing, partial, garbled, not an object). On Windows a read that
    races the writer's os.replace gets PermissionError: retried briefly."""
    for i in range(retries):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except PermissionError:
            time.sleep(0.02 * (i + 1))
            continue
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None
    return None


def num(x: Any) -> float | None:
    return float(x) if isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) else None


def stage_walls(metrics: dict[str, Any]) -> dict[str, float]:
    """{stage: wall_s} from run_metrics.json (`stages` list, else stage_stats.<stage>.wall_s)."""
    out: dict[str, float] = {}
    stages, stats = metrics.get("stages"), metrics.get("stage_stats")
    for s in stages if isinstance(stages, list) else []:
        if isinstance(s, dict) and isinstance(s.get("name"), str) and num(s.get("wall_s")) is not None:
            out[s["name"]] = float(s["wall_s"])
    for name, st in (stats if isinstance(stats, dict) else {}).items():
        if name not in out and isinstance(st, dict) and num(st.get("wall_s")) is not None:
            out[name] = float(st["wall_s"])
    return out


# ---------------------------------------------------------------- pipeline side

class ProgressWriter:
    """Background writer of progress.json. Every public method swallows its errors: progress never breaks a run."""

    def __init__(self, out_dir: Path, planned: list[tuple[int, str]], stages_total: int, raw_dir: Path,
                 con: duckdb.DuckDBPyConnection | None, cfg: EtaConfig, batch_bytes: float | None = None) -> None:
        self.path = Path(out_dir) / PROGRESS_FILE
        self.cfg = cfg
        # pipeline.yaml ingest.batch_bytes: sizes the running COPY before ingest logs its batch plan
        self.batch_bytes = float(batch_bytes) if batch_bytes and float(batch_bytes) > 0 else None
        self._con = con if cfg.query_progress else None
        self._lock = threading.Lock()      # guards state / _batch
        self._io_lock = threading.Lock()   # one writer of the tmp file at a time
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._handler: _BatchHandler | None = None
        self._logger_level: int | None = None
        now = time.time()
        self.state: dict[str, Any] = {
            "run_started_utc": iso_z(now), "stage": planned[0][1] if planned else None,
            "stage_index": planned[0][0] if planned else 0, "stages_total": stages_total,
            "stage_started_utc": iso_z(now), "stage_fraction": None, "bytes_total": _dir_bytes(raw_dir),
            "bytes_done": None, "rows_done": None, "stages_done": [], "updated_utc": iso_z(now),
            "pid": os.getpid(), "stages_planned": [n for _, n in planned], "source_type": None,
            "query_fraction": None, "finished": False, "error": None, "first_stage_started_utc": None,
        }
        self._batch = {"done": 0, "total": 0, "bytes": 0.0, "rows": None}

    # lifecycle
    def start(self) -> ProgressWriter:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            lg = logging.getLogger("attacklens.ingest")
            self._handler = _BatchHandler(self)
            lg.addHandler(self._handler)
            if lg.getEffectiveLevel() > logging.INFO:  # batch records must reach the handler
                self._logger_level = lg.level
                lg.setLevel(logging.INFO)
            self.flush()
            self._thread = threading.Thread(target=self._loop, name="progress", daemon=True)
            self._thread.start()
        except Exception:  # noqa: BLE001 - progress must never break the run
            log.warning("progress writer not started", exc_info=True)
        return self

    def _loop(self) -> None:
        while not self._stop.wait(max(0.05, float(self.cfg.progress_interval_s))):
            self.flush()

    def finish(self, error: str | None = None) -> None:
        try:
            self._stop.set()
            if self._thread is not None:
                self._thread.join(timeout=5)
            lg = logging.getLogger("attacklens.ingest")
            if self._handler is not None:
                lg.removeHandler(self._handler)
            if self._logger_level is not None:
                lg.setLevel(self._logger_level)
            self._con = None
            with self._lock:
                self.state.update(finished=True, error=error, query_fraction=None)
                if error is None:
                    self.state["stage_fraction"] = 1.0
            self.flush()
        except Exception:  # noqa: BLE001
            log.warning("progress writer finish failed", exc_info=True)

    # stage boundaries (called from the run.py stage loop)
    def stage_start(self, index: int, name: str) -> None:
        try:
            with self._lock:
                self.state.update(stage=name, stage_index=index, stage_started_utc=iso_z(time.time()),
                                  stage_fraction=0.0 if name == "ingest" else None)
                self.state["first_stage_started_utc"] = self.state["first_stage_started_utc"] or                     self.state["stage_started_utc"]
                if name == "ingest":
                    self.state["bytes_done"] = 0
            self.flush()
        except Exception:  # noqa: BLE001
            log.debug("progress stage_start failed", exc_info=True)

    def stage_done(self, name: str, wall_s: float, result: dict[str, Any] | None = None,
                   profile: dict[str, Any] | None = None) -> None:
        try:
            with self._lock:
                self.state["stages_done"].append({"stage": name, "wall_s": round(float(wall_s), 3)})
                if name == "profile" and profile:
                    self._set_profile(profile)
                if name == "ingest" and isinstance(result, dict):
                    if num(result.get("bytes_in")) is not None:
                        self.state["bytes_total"] = int(result["bytes_in"])
                    self.state["bytes_done"] = self.state["bytes_total"]
                    self.state["rows_done"] = result.get("rows_in")
                    self.state["stage_fraction"] = 1.0
            self.flush()
        except Exception:  # noqa: BLE001
            log.debug("progress stage_done failed", exc_info=True)

    def _set_profile(self, profile: dict[str, Any]) -> None:
        by_src: dict[str, int] = {}
        for f in profile.get("files") or []:
            if isinstance(f, dict) and f.get("format") != "unrecognized" and num(f.get("size")) is not None:
                src = str(f.get("source_type") or "unknown")
                by_src[src] = by_src.get(src, 0) + int(f["size"])
        if by_src:
            self.state["bytes_total"] = sum(by_src.values())
            self.state["source_type"] = max(by_src.items(), key=lambda kv: kv[1])[0]

    def on_batch(self, done: int, total: int, mb: float, rows: int | None) -> None:
        with self._lock:
            self._batch["done"], self._batch["total"] = done, total
            self._batch["bytes"] += mb * 1e6
            self._batch["rows"] = rows

    def _query_fraction(self) -> float | None:
        con = self._con
        if con is None:
            return None
        try:
            p = float(con.query_progress())
        except Exception:  # noqa: BLE001 - closed connection, no query
            return None
        return min(1.0, p / 100.0) if p >= 0 else None

    def flush(self) -> None:
        try:
            q = self._query_fraction()
            with self._lock:
                st = self.state
                st["query_fraction"] = None if q is None else round(q, 4)
                if st["stage"] == "ingest" and not st["finished"] and not any(
                        d["stage"] == "ingest" for d in st["stages_done"]):
                    self._ingest_fraction(q)
                st["updated_utc"] = iso_z(time.time())
                snap = json.loads(json.dumps(st, default=str))
            with self._io_lock:
                write_json_atomic(self.path, snap)
        except Exception:  # noqa: BLE001
            log.debug("progress flush failed", exc_info=True)

    def _ingest_fraction(self, q: float | None) -> None:
        """stage_fraction / bytes_done of ingest: finished batches + query_progress() x the running COPY's bytes.

        The running COPY's bytes = the bytes left / the batches left. Batches left come from the "ingest batch
        i/n" records once one has arrived; before that (the first COPY) from ceil(left / batch_bytes), so the
        first batch of a multi-batch input is never measured against the whole input. Both values never move
        backwards within ingest (an estimate that was a little high stays until the real progress passes it)."""
        st, b = self.state, self._batch
        total = float(st["bytes_total"] or 0)
        done = min(b["bytes"], total) if total else b["bytes"]
        if b["total"] and b["done"] >= b["total"]:   # all COPYs finished: accounting phase
            frac, cur = 1.0, 0.0
        else:
            left = max(0.0, total - done)
            if b["total"]:
                n_left = b["total"] - b["done"]
            elif self.batch_bytes:
                n_left = math.ceil(left / self.batch_bytes) if left > 0 else 1
            else:
                n_left = 1
            cur = left / max(1, n_left) * min(1.0, max(0.0, q or 0.0))
            frac = (done + cur) / total if total else 0.0
        new_frac = round(min(1.0, frac) * self.cfg.ingest_copy_share, 4)
        new_bytes = int(min(total, done + cur)) if total else int(done + cur)
        prev_frac, prev_bytes = num(st.get("stage_fraction")), st.get("bytes_done")
        st["stage_fraction"] = max(new_frac, prev_frac) if prev_frac is not None else new_frac
        st["bytes_done"] = max(new_bytes, prev_bytes) if isinstance(prev_bytes, int) else new_bytes
        st["rows_done"] = b["rows"]


class _BatchHandler(logging.Handler):
    """Picks up ingest.py's "ingest batch %d/%d: %d files, %.1f MB, %d rows so far" records (args, not text)."""

    def __init__(self, writer: ProgressWriter) -> None:
        super().__init__(logging.INFO)
        self.writer = writer

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if isinstance(record.msg, str) and record.msg.startswith("ingest batch %d/%d") and \
                    isinstance(record.args, tuple) and len(record.args) >= 5:
                done, total, _files, mb, rows = record.args[:5]
                self.writer.on_batch(int(done), int(total), float(mb), int(rows))
        except Exception:  # noqa: BLE001
            pass


def _dir_bytes(root: Path) -> int | None:
    """Sum of file sizes under root (metadata only; Stage 0 replaces it with the profiled bytes)."""
    total = 0
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "ground_truth"]
            for fn in filenames:
                try:
                    total += os.stat(os.path.join(dirpath, fn)).st_size
                except OSError:
                    continue
    except OSError:
        return None
    return total


def as_int(x: Any) -> int | None:
    v = num(x)
    return None if v is None else int(v)
