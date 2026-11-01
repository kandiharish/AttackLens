"""ETA for a running pipeline + the progress keys of GET /api/runs/{id} (API side of progress.py).

Each remaining stage's expected wall comes from earlier successful run_metrics.json under eta.history_glob
(same dominant source type if any, else all): floor = median wall of small runs (< small_input_bytes, the fixed
overhead) + marginal seconds per MB (median over the `similar_runs` runs nearest in input size) x MB. History is
scaled by this run's actual / expected wall over its finished stages (calibrate, clipped). Once the current stage
reports stage_fraction >= live_min_fraction, its remaining time blends the live rate (elapsed / fraction) with
history, weighted by the fraction. A stage without a fraction runs down linearly to the knee
(1 - overrun_share) x expected, then decays as overrun_share x expected x knee / elapsed (the ETA never rises
while the stage overruns). The measured time between stages so far is added per remaining boundary. If any
remaining planned stage has no history, the ETA is null (never a partial sum that reads as the whole run), except
stages in eta.no_history_zero (appended non-fatal stages, e.g. integrity), which count 0 s until history exists.
eta_basis: "history" | "live" | "history+live". All knobs: config/pipeline.yaml `eta:`.
"""

from __future__ import annotations

import json
import logging
import math
import os
import statistics
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from attacklens.progress import EtaConfig, as_int, num, parse_iso, read_json, stage_walls

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class HistRun:
    out_dir: str
    mb: float
    source: str | None
    walls: dict[str, float]


def hist_run(path: Path) -> HistRun | None:
    """One usable history entry from a run_metrics.json: no error, input bytes known, stage walls present."""
    m = read_json(path)
    if not m or m.get("error") or num(m.get("bytes_in")) is None or float(m["bytes_in"]) <= 0:
        return None
    walls = stage_walls(m)
    if not walls:
        return None
    rows = ((m.get("stage_stats") or {}).get("ingest") or {}).get("sources")
    if not isinstance(rows, dict) or not rows:
        rows = _accounting_rows(path.parent / "ingest_accounting.json")
    rows = {k: v for k, v in rows.items() if num(v) is not None}
    source = max(rows.items(), key=lambda kv: kv[1])[0] if rows else None
    return HistRun(os.path.normcase(str(path.parent.resolve())), float(m["bytes_in"]) / 1e6, source, walls)


def _accounting_rows(path: Path) -> dict[str, Any]:
    """{source_type: rows_ok} from ingest_accounting.json (a list of per-source entries), {} if unreadable."""
    try:
        acc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(acc, list):
        return {}
    return {str(a["source_type"]): a.get("rows_ok") for a in acc if isinstance(a, dict) and a.get("source_type")}


class Estimator:
    """History-based ETA. The history scan is cached for history_ttl_s; files are re-parsed only on mtime change."""

    def __init__(self, cfg: EtaConfig, root: Path) -> None:
        self.cfg = cfg
        self.root = Path(root)
        self._lock = threading.Lock()
        self._files: dict[str, tuple[float, HistRun | None]] = {}
        self._runs: list[HistRun] = []
        self._scanned = -math.inf

    def history(self) -> list[HistRun]:
        with self._lock:
            if time.monotonic() - self._scanned < self.cfg.history_ttl_s:
                return self._runs
            files: dict[str, tuple[float, HistRun | None]] = {}
            for p in sorted(self.root.glob(self.cfg.history_glob)):
                try:
                    mt = p.stat().st_mtime
                except OSError:
                    continue
                old = self._files.get(str(p))
                files[str(p)] = old if old and old[0] == mt else (mt, hist_run(p))
            self._files = files
            self._runs = [r for _, r in files.values() if r is not None]
            self._scanned = time.monotonic()
            return self._runs

    def expected(self, stage: str, mb: float | None, source: str | None, runs: list[HistRun]) -> float | None:
        """Expected wall seconds of `stage` for an input of `mb` MB, or None without history for it."""
        cands = [r for r in runs if stage in r.walls]
        same = [r for r in cands if source and r.source == source]
        cands = same or cands
        if not cands:
            return None
        small_mb = self.cfg.small_input_bytes / 1e6
        small = [r.walls[stage] for r in cands if r.mb < small_mb]
        floor = statistics.median(small) if small else 0.0
        large = [r for r in cands if r.mb >= small_mb]
        if not large or not mb:
            return floor if small else statistics.median(r.walls[stage] for r in cands)
        near = sorted(large, key=lambda r: abs(math.log(r.mb / mb)))[: max(1, int(self.cfg.similar_runs))]
        if self.cfg.additive:   # fixed overhead (floor) + marginal seconds per MB above it
            rate = statistics.median(max(0.0, r.walls[stage] - floor) / r.mb for r in near)
            return floor + rate * mb
        rate = statistics.median(r.walls[stage] / r.mb for r in near)
        return max(floor, rate * mb)

    def estimate(self, prog: dict[str, Any], now: float | None = None,
                 exclude: Path | None = None) -> dict[str, Any]:
        """{eta_s, eta_basis, eta_total_s} for a running pipeline's progress.json dict (all None if unknown)."""
        none = {"eta_s": None, "eta_basis": None, "eta_total_s": None}
        now = time.time() if now is None else now
        stage, planned = prog.get("stage"), prog.get("stages_planned")
        if not isinstance(stage, str):
            return none
        planned = [s for s in planned if isinstance(s, str)] if isinstance(planned, list) else [stage]
        ex = os.path.normcase(str(Path(exclude).resolve())) if exclude else None
        runs = [r for r in self.history() if r.out_dir != ex]
        mb = (num(prog.get("bytes_total")) or 0.0) / 1e6 or None
        src = prog.get("source_type") if isinstance(prog.get("source_type"), str) else None
        done = {d.get("stage"): num(d.get("wall_s")) for d in _list(prog.get("stages_done")) if isinstance(d, dict)}
        factor = self._factor(done, mb, src, runs)
        elapsed = max(0.0, now - (parse_iso(prog.get("stage_started_utc")) or now))
        frac = num(prog.get("stage_fraction"))
        hist_cur = self.expected(stage, mb, src, runs)
        live = frac is not None and frac >= self.cfg.live_min_fraction and stage not in done
        fut_factor, hist_rem = factor, None
        if hist_cur is not None:
            exp_cur = hist_cur * factor
            hist_rem = (1.0 - frac) * exp_cur if frac is not None else self._history_rem(exp_cur, elapsed)
            if self.cfg.calibrate_overrun and elapsed > exp_cur and stage not in done:
                fut_factor = self._factor({**done, stage: elapsed}, mb, src, runs)   # this run is slower now
        if live:
            f = frac or 1.0
            live_rem = elapsed * (1.0 - min(f, 1.0)) / f
            # live_blend: weight the live rate by how far the stage is (DuckDB progress is not linear in time)
            rem_cur = f * live_rem + (1.0 - f) * hist_rem if self.cfg.live_blend and hist_rem is not None \
                else live_rem
        elif hist_rem is not None:
            rem_cur = hist_rem
        else:
            return none
        after = planned[planned.index(stage) + 1:] if stage in planned else []
        fut = [self._expected_future(s, mb, src, runs) for s in after if s not in done]
        if any(f is None for f in fut):   # a partial sum would read as the whole run's remaining time
            return none
        known = [f for f in fut if f is not None]
        if stage in done:
            rem_cur = 0.0
        blended = self.cfg.live_blend and hist_rem is not None
        basis = ("history+live" if known or blended else "live") if live else "history"
        started = parse_iso(prog.get("run_started_utc"))
        first = parse_iso(prog.get("first_stage_started_utc"))
        gaps = 0.0
        if self.cfg.gap_estimate and first is not None and after and done:
            # time between stages so far (stage module imports, events view registration) per stage boundary
            walls = sum(w for w in done.values() if w is not None)
            between = (now - first) - walls - (0.0 if stage in done else elapsed)
            gaps = max(0.0, between) / max(1, len(done) - (1 if stage in done else 0)) * len(after)
        eta = max(0.0, rem_cur + sum(known) * fut_factor + gaps)
        total = (now - started + eta) if started is not None else None
        return {"eta_s": round(eta, 1), "eta_basis": basis, "eta_total_s": None if total is None else round(total, 1)}

    def _expected_future(self, stage: str, mb: float | None, src: str | None, runs: list[HistRun]) -> float | None:
        """expected() for a stage after the current one; a no_history_zero stage (appended later, e.g. integrity)
        without history counts 0 s instead of nulling the whole ETA (history runs predate it)."""
        exp = self.expected(stage, mb, src, runs)
        return 0.0 if exp is None and stage in self.cfg.no_history_zero else exp

    def _history_rem(self, exp: float, elapsed: float) -> float:
        """Remaining seconds of a stage without a live fraction, `elapsed` into an expected `exp`.

        overrun_decay: linear (exp - elapsed) down to the knee (1 - overrun_share) x exp, then
        overrun_share x exp x knee / elapsed: continuous, never increasing, never 0 while the stage runs.
        Without it (old rule): max(exp - elapsed, overrun_share x elapsed), which grows past the knee."""
        share = min(max(self.cfg.overrun_share, 0.0), 1.0)
        if not self.cfg.overrun_decay:
            return max(exp - elapsed, share * elapsed)
        knee = (1.0 - share) * exp
        if elapsed <= knee or knee <= 0:
            return max(exp - elapsed, 0.0)
        return share * exp * knee / elapsed

    def _factor(self, done: dict[Any, float | None], mb: float | None, src: str | None,
                runs: list[HistRun]) -> float:
        """Speed of this run vs history over its finished stages (machine load), clipped; 1.0 if unknown."""
        if not self.cfg.calibrate:
            return 1.0
        act = exp = 0.0
        for st, wall in done.items():
            if st in self.cfg.calibrate_skip:
                continue
            e = self.expected(str(st), mb, src, runs) if wall is not None else None
            if e is not None and wall is not None and e >= self.cfg.calibrate_min_expected_s:
                act, exp = act + wall, exp + e
        if exp <= 0:
            return 1.0
        return min(self.cfg.calibrate_max, max(self.cfg.calibrate_min, act / exp))


def status_fields(prog: dict[str, Any] | None, metrics: dict[str, Any] | None, running: bool,
                  estimator: Estimator | None, exclude: Path | None, now: float | None = None) -> dict[str, Any]:
    """The progress keys of GET /api/runs/{id}: from progress.json while running, from run_metrics.json after."""
    now = time.time() if now is None else now
    out: dict[str, Any] = {"stage_elapsed_s": None, "stage_fraction": None, "stages_done": [], "bytes_total": None,
                           "bytes_done": None, "rows_done": None, "ingest_mb_s": None, "eta_s": None,
                           "eta_basis": None, "eta_total_s": None}
    if running:
        if not prog:
            return out
        done = [{"stage": str(d["stage"]), "wall_s": float(d["wall_s"])} for d in _list(prog.get("stages_done"))
                if isinstance(d, dict) and isinstance(d.get("stage"), str) and num(d.get("wall_s")) is not None]
        started = parse_iso(prog.get("stage_started_utc"))
        frac = num(prog.get("stage_fraction"))
        out.update(stage_elapsed_s=None if started is None else round(max(0.0, now - started), 1),
                   stage_fraction=None if frac is None else round(min(1.0, max(0.0, frac)), 4), stages_done=done,
                   bytes_total=as_int(prog.get("bytes_total")), bytes_done=as_int(prog.get("bytes_done")),
                   rows_done=as_int(prog.get("rows_done")))
        ing = next((d["wall_s"] for d in done if d["stage"] == "ingest"), None)
        if ing and out["bytes_total"]:
            out["ingest_mb_s"] = round(out["bytes_total"] / 1e6 / ing, 2)
        elif prog.get("stage") == "ingest" and out["bytes_done"] and out["stage_elapsed_s"]:
            out["ingest_mb_s"] = round(out["bytes_done"] / 1e6 / out["stage_elapsed_s"], 2)
        if estimator is not None:
            try:
                out.update(estimator.estimate(prog, now, exclude))
            except Exception:  # noqa: BLE001 - a bad history file must never break status()
                log.warning("eta estimate failed", exc_info=True)
        return out
    out.update(eta_s=0.0)
    if not metrics:
        return out
    walls = stage_walls(metrics)
    order = [s.get("name") for s in _list(metrics.get("stages")) if isinstance(s, dict)]
    out["stages_done"] = [{"stage": s, "wall_s": walls[s]} for s in order if s in walls]
    b, rows = as_int(metrics.get("bytes_in")), as_int(metrics.get("rows_in"))
    out.update(bytes_total=b, bytes_done=b, rows_done=rows, eta_total_s=num(metrics.get("total_wall_s")))
    if b and walls.get("ingest"):
        out["ingest_mb_s"] = round(b / 1e6 / walls["ingest"], 2)
    return out


def _list(x: Any) -> list[Any]:
    return x if isinstance(x, list) else []
