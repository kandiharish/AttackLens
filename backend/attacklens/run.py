"""Pipeline CLI: python -m attacklens.run --raw DIR --out DIR [--parquet DIR] [--ground-truth FILE]
[--from-stage N] [--config DIR] [--strict] [--siem-alerts].

--siem-alerts (alert-input mode) also unions the SIEM alert spool (config/integrations.yaml spool.alerts_dir) into
raw_alerts. It is refused together with --ground-truth: the scored eval run is raw-events-only. run_metrics.json
`inputs` records what was read.

Stages (index): 0 profile, 1 ingest, 2 lookups, 3 detect, 4 episodes, 5 link, 6 incidents, 7 publish, 8 integrity.
Each stage module exposes run(ctx) -> dict. Stages in NON_FATAL (integrity: log tamper checks, writes
integrity_report.json) never fail the run: an exception is logged and recorded as stage_stats.<name>.error
(+ run_metrics `nonfatal_errors`), and the stage still counts as done. Progress lines (parsed by the API):
    stage <name> start
    stage <name> done wall_s=<x>
and <out>/progress.json (progress.ProgressWriter, every pipeline.yaml eta.progress_interval_s) for the ETA.
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import sys
from pathlib import Path
from typing import Any

from attacklens.config import REPO_ROOT, load_config
from attacklens.context import RunContext
from attacklens.db import connect, register_events
from attacklens.progress import EtaConfig, ProgressWriter
from attacklens.telemetry import Telemetry

log = logging.getLogger("attacklens.run")

STAGES: tuple[str, ...] = ("profile", "ingest", "lookups", "detect", "episodes", "link", "incidents", "publish",
                           "integrity")
NON_FATAL: frozenset[str] = frozenset({"integrity"})


class StageMissing(RuntimeError):
    pass


def _repo_path(p: str | Path) -> Path:
    p = Path(p)
    return p if p.is_absolute() else REPO_ROOT / p


def _load_stage(name: str, strict: bool) -> Any | None:
    try:
        mod = importlib.import_module(f"attacklens.{name}")
    except ModuleNotFoundError as exc:
        if exc.name != f"attacklens.{name}":
            raise  # the module exists but one of its imports is broken: a real error
        if strict:
            raise StageMissing(f"stage module attacklens.{name} not found") from exc
        log.warning("stage %s skipped: module attacklens.%s not found", name, name)
        return None
    fn = getattr(mod, "run", None)
    if not callable(fn):
        if strict:
            raise StageMissing(f"attacklens.{name} has no run(ctx)")
        log.warning("stage %s skipped: attacklens.%s has no run(ctx)", name, name)
        return None
    return fn


def _register(ctx: RunContext) -> bool:
    events = Path(ctx.parquet_dir) / "events"
    if events.exists() and any(events.rglob("*.parquet")):
        register_events(ctx.con, ctx.events_glob)
        return True
    log.warning("no events Parquet under %s; `events` view not registered", events)
    return False


def _run_eval(ctx: RunContext, tel: Telemetry, strict: bool) -> dict[str, Any] | None:
    try:
        harness = importlib.import_module("eval.harness")
    except ModuleNotFoundError as exc:
        if strict:
            raise StageMissing("eval.harness not found") from exc
        log.warning("eval skipped: eval.harness not found")
        return None
    log.info("stage eval start")
    with tel.stage("eval") as rec:
        score = harness.evaluate(ctx.out_dir, ctx.ground_truth)
        (ctx.out_dir / "eval_scorecard.json").write_text(json.dumps(score, indent=2, default=str),
                                                          encoding="utf-8")
    log.info("stage eval done wall_s=%s", rec["wall_s"])
    return score


def _broken(exc: Exception) -> Any:
    """Stage function that re-raises the import error of a NON_FATAL stage (recorded by _call_stage)."""
    def fn(_ctx: RunContext) -> dict[str, Any]:
        raise exc
    return fn


def _call_stage(name: str, fn: Any, ctx: RunContext, nonfatal: dict[str, str]) -> dict[str, Any]:
    """fn(ctx) or {}; for a NON_FATAL stage an exception becomes {"error": ...} (logged, recorded in nonfatal)."""
    if name not in NON_FATAL:
        return fn(ctx) or {}
    try:
        return fn(ctx) or {}
    except Exception as exc:  # noqa: BLE001 - a non-fatal stage never fails the run
        msg = f"{type(exc).__name__}: {exc}"[:500]
        log.exception("stage %s failed (non-fatal, run continues): %s", name, msg)
        nonfatal[name] = msg
        return {"error": msg}


def _first(stats: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if isinstance(stats, dict) and stats.get(k) is not None:
            return stats[k]
    return None


def _batch_bytes(pipe: dict[str, Any]) -> float | None:
    """pipeline.yaml ingest.batch_bytes (same default and coercion as ingest.py), None if unusable."""
    try:
        return float((pipe.get("ingest") or {}).get("batch_bytes", 2e9))
    except (TypeError, ValueError):
        return None


def run_pipeline(raw: str | Path, out: str | Path, parquet: str | Path | None = None,
                 ground_truth: str | Path | None = None, from_stage: int = 0, strict: bool = False,
                 config_dir: str | Path | None = None, siem_alerts: bool = False) -> dict[str, Any]:
    """Run stages from_stage..8 (+ eval if ground_truth). Returns the run_metrics dict (also written)."""
    if siem_alerts and ground_truth:
        raise ValueError("--siem-alerts cannot be combined with --ground-truth (the eval is raw-events-only)")
    cfg = load_config(Path(config_dir) if config_dir else None)
    pipe = cfg.get("pipeline") or {}
    tel = Telemetry(float((pipe.get("telemetry") or {}).get("interval_s", 0.5))).start()
    raw_dir, out_dir = Path(raw).resolve(), Path(out).resolve()
    pq = Path(parquet).resolve() if parquet else _repo_path(pipe.get("parquet_root", "data/parquet")) / out_dir.name
    out_dir.mkdir(parents=True, exist_ok=True)
    con = connect(memory_limit=str(pipe.get("memory_limit", "5GB")), threads=pipe.get("threads"),
                  temp_directory=_repo_path(pipe.get("temp_directory", "data/spill")))
    eta_cfg = EtaConfig.from_dict(pipe.get("eta"))
    # query_progress() (progress.json ingest fraction) needs the progress bar on (DuckDB 2.0 returns -1 otherwise);
    # it is never printed, so stderr stays parseable (the API tracks the stage log lines)
    con.execute(f"SET enable_progress_bar={'true' if eta_cfg.query_progress else 'false'}")
    con.execute("SET enable_progress_bar_print=false")
    ctx = RunContext(set_name=out_dir.name, raw_dir=raw_dir, parquet_dir=pq, out_dir=out_dir, con=con, cfg=cfg,
                     ground_truth=Path(ground_truth).resolve() if ground_truth else None, siem_alerts=siem_alerts)
    stage_stats: dict[str, Any] = {}
    nonfatal: dict[str, str] = {}
    error: str | None = None
    planned = [(i, n) for i, n in enumerate(STAGES) if i >= from_stage]
    if ctx.ground_truth is not None:
        planned.append((len(STAGES), "eval"))
    prog = ProgressWriter(out_dir, planned, len(STAGES) + (ctx.ground_truth is not None), raw_dir, con,
                          eta_cfg, batch_bytes=_batch_bytes(pipe)).start()
    try:
        if from_stage >= 2:
            _register(ctx)
        for idx, name in enumerate(STAGES):
            if idx < from_stage:
                continue
            try:
                fn = _load_stage(name, strict)
            except Exception as exc:  # noqa: BLE001 - a broken non-fatal stage module is recorded, not raised
                if name not in NON_FATAL or isinstance(exc, StageMissing):
                    raise
                fn = _broken(exc)
            if fn is None:
                continue
            log.info("stage %s start", name)
            prog.stage_start(idx, name)
            with tel.stage(name) as rec:
                result = _call_stage(name, fn, ctx, nonfatal)
            stage_stats[name] = result
            log.info("stage %s done wall_s=%s", name, rec["wall_s"])
            prog.stage_done(name, rec["wall_s"], result, ctx.stats.get("profile") if name == "profile" else None)
            if name == "ingest":
                _register(ctx)
        if ctx.ground_truth is not None:
            prog.stage_start(len(STAGES), "eval")
            if _run_eval(ctx, tel, strict) is not None and tel.stages and tel.stages[-1]["name"] == "eval":
                prog.stage_done("eval", tel.stages[-1]["wall_s"])
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        log.exception("pipeline failed: %s", error)
        raise
    finally:
        tel.stop()
        ing = stage_stats.get("ingest") or {}
        epi = stage_stats.get("episodes") or {}
        inc = stage_stats.get("incidents") or {}
        siem = (stage_stats.get("detect") or {}).get("siem_alerts") or {}
        extra = {
            "set": ctx.set_name, "raw_dir": raw_dir.as_posix(), "out_dir": out_dir.as_posix(),
            "parquet_dir": pq.as_posix(), "from_stage": from_stage, "error": error,
            "rows_in": ing.get("rows_in"), "rows_ok": ing.get("rows_ok"), "bytes_in": ing.get("bytes_in"),
            "episodes": _first(epi, ("episodes", "episodes_kept", "kept", "count")),
            "episodes_spilled": _first(epi, ("episodes_spilled", "spilled")),
            "incidents": _first(inc, ("incidents", "count", "kept")),
            "input_mode": "file+siem_alerts" if siem_alerts else "file",
            "inputs": {"raw_events": raw_dir.as_posix(), "siem_alerts": bool(siem_alerts),
                       "siem_alert_rows": siem.get("rows"), "siem_alert_dir": siem.get("dir"),
                       "ground_truth": ctx.ground_truth is not None},
            "stage_stats": stage_stats,
            "nonfatal_errors": nonfatal,
            "effective_config": {k: v for k, v in cfg.items() if k != "attack"},
        }
        try:
            metrics = tel.write(out_dir / "run_metrics.json", extra=extra, rows=ing.get("rows_in"))
        finally:
            prog.finish(error)  # stops the writer thread before the connection it polls is closed
            con.close()
    return metrics


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="attacklens.run", description="AttackLens batch pipeline")
    ap.add_argument("--raw", required=True, help="raw log directory (data/raw/<set>)")
    ap.add_argument("--out", required=True, help="output directory (data/out/<set>)")
    ap.add_argument("--parquet", help="parquet directory (default data/parquet/<basename of --out>)")
    ap.add_argument("--ground-truth", help="ground truth attacks.json -> eval_scorecard.json")
    ap.add_argument("--from-stage", type=int, default=0, choices=range(len(STAGES)),
                    help="first stage index: " + ", ".join(f"{i} {s}" for i, s in enumerate(STAGES)))
    ap.add_argument("--config", help="config directory (default <repo>/config)")
    ap.add_argument("--strict", action="store_true", help="missing stage module is an error, not a skip")
    ap.add_argument("--siem-alerts", action="store_true",
                    help="alert-input mode: also read the SIEM alert spool (not allowed with --ground-truth)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if a.siem_alerts and a.ground_truth:
        ap.error("--siem-alerts cannot be combined with --ground-truth (the eval is raw-events-only)")
    try:
        m = run_pipeline(a.raw, a.out, a.parquet, a.ground_truth, a.from_stage, a.strict, a.config, a.siem_alerts)
    except Exception:
        return 1
    log.info("done in %.1f s, peak RSS %.0f MB, %s rows/s", m["total_wall_s"], m["peak_rss_mb"], m["rows_per_s"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
