"""Pipeline CLI: python -m attacklens.run --raw DIR --out DIR [--parquet DIR] [--ground-truth FILE]
[--from-stage N] [--config DIR] [--strict].

Stages (index): 0 profile, 1 ingest, 2 lookups, 3 detect, 4 episodes, 5 link, 6 incidents, 7 publish.
Each stage module exposes run(ctx) -> dict. Progress lines (parsed by the API):
    stage <name> start
    stage <name> done wall_s=<x>
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
from attacklens.telemetry import Telemetry

log = logging.getLogger("attacklens.run")

STAGES: tuple[str, ...] = ("profile", "ingest", "lookups", "detect", "episodes", "link", "incidents", "publish")


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


def _first(stats: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if isinstance(stats, dict) and stats.get(k) is not None:
            return stats[k]
    return None


def run_pipeline(raw: str | Path, out: str | Path, parquet: str | Path | None = None,
                 ground_truth: str | Path | None = None, from_stage: int = 0, strict: bool = False,
                 config_dir: str | Path | None = None) -> dict[str, Any]:
    """Run stages from_stage..7 (+ eval if ground_truth). Returns the run_metrics dict (also written)."""
    cfg = load_config(Path(config_dir) if config_dir else None)
    pipe = cfg.get("pipeline") or {}
    tel = Telemetry(float((pipe.get("telemetry") or {}).get("interval_s", 0.5))).start()
    raw_dir, out_dir = Path(raw).resolve(), Path(out).resolve()
    pq = Path(parquet).resolve() if parquet else _repo_path(pipe.get("parquet_root", "data/parquet")) / out_dir.name
    out_dir.mkdir(parents=True, exist_ok=True)
    con = connect(memory_limit=str(pipe.get("memory_limit", "5GB")), threads=pipe.get("threads"),
                  temp_directory=_repo_path(pipe.get("temp_directory", "data/spill")))
    con.execute("SET enable_progress_bar=false")  # keep stderr parseable (API tracks stage log lines)
    ctx = RunContext(set_name=out_dir.name, raw_dir=raw_dir, parquet_dir=pq, out_dir=out_dir, con=con, cfg=cfg,
                     ground_truth=Path(ground_truth).resolve() if ground_truth else None)
    stage_stats: dict[str, Any] = {}
    error: str | None = None
    try:
        if from_stage >= 2:
            _register(ctx)
        for idx, name in enumerate(STAGES):
            if idx < from_stage:
                continue
            fn = _load_stage(name, strict)
            if fn is None:
                continue
            log.info("stage %s start", name)
            with tel.stage(name) as rec:
                result = fn(ctx) or {}
            stage_stats[name] = result
            log.info("stage %s done wall_s=%s", name, rec["wall_s"])
            if name == "ingest":
                _register(ctx)
        if ctx.ground_truth is not None:
            _run_eval(ctx, tel, strict)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        log.exception("pipeline failed: %s", error)
        raise
    finally:
        tel.stop()
        ing = stage_stats.get("ingest") or {}
        epi = stage_stats.get("episodes") or {}
        inc = stage_stats.get("incidents") or {}
        extra = {
            "set": ctx.set_name, "raw_dir": raw_dir.as_posix(), "out_dir": out_dir.as_posix(),
            "parquet_dir": pq.as_posix(), "from_stage": from_stage, "error": error,
            "rows_in": ing.get("rows_in"), "rows_ok": ing.get("rows_ok"), "bytes_in": ing.get("bytes_in"),
            "episodes": _first(epi, ("episodes", "episodes_kept", "kept", "count")),
            "episodes_spilled": _first(epi, ("episodes_spilled", "spilled")),
            "incidents": _first(inc, ("incidents", "count", "kept")),
            "stage_stats": stage_stats,
            "effective_config": {k: v for k, v in cfg.items() if k != "attack"},
        }
        metrics = tel.write(out_dir / "run_metrics.json", extra=extra, rows=ing.get("rows_in"))
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
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        m = run_pipeline(a.raw, a.out, a.parquet, a.ground_truth, a.from_stage, a.strict, a.config)
    except Exception:
        return 1
    log.info("done in %.1f s, peak RSS %.0f MB, %s rows/s", m["total_wall_s"], m["peak_rss_mb"], m["rows_per_s"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
