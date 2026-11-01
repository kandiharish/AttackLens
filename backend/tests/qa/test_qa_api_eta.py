"""QA unit tests (track qa_api): the run ETA behind GET /api/runs/{id} `eta_s` (progress_eta.Estimator), on a
hand-built one-run history. Feeds the UI's "time remaining" display.

Fixture, hand-checked: one history run, bytes_in 1e9 (1000 MB, above small_input_bytes 1e8, so no floor runs),
walls ingest 100 s, detect 50 s. Expected wall for this run's 1000 MB: floor 0 + (100 - 0) / 1000 s/MB x 1000 MB
= 100 s ingest, 50 s detect. No finished stages, so calibration factor 1.0 and no between-stage gaps.
Progress: stage ingest, stage_fraction 0.02 (below live_min_fraction 0.05, history only).
  remaining = (1 - 0.02) x 100 + 50 = 148.0 s.

Product bugs are strict xfails named test_qa_api_bug_*; the bug id is in the reason (reports/qa/qa_api.md).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from attacklens.progress import EtaConfig
from attacklens.progress_eta import Estimator

NOW = 1_800_000_000.0


def iso(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).isoformat().replace("+00:00", "Z")


@pytest.fixture()
def est(tmp_path: Path) -> Estimator:
    run = tmp_path / "out" / "hist1"
    run.mkdir(parents=True)
    (run / "run_metrics.json").write_text(json.dumps({
        "bytes_in": 1_000_000_000, "rows_in": 1_000_000,
        "stages": [{"name": "ingest", "wall_s": 100.0}, {"name": "detect", "wall_s": 50.0}],
        "stage_stats": {"ingest": {"sources": {"fortigate_kv": 1_000_000}}}}), encoding="utf-8")
    return Estimator(EtaConfig.from_dict({"history_glob": "out/*/run_metrics.json"}), tmp_path)


def prog(elapsed_s: float, frac: float | None) -> dict:
    return {"stage": "ingest", "stages_planned": ["ingest", "detect"], "bytes_total": 1_000_000_000,
            "source_type": "fortigate_kv", "stage_fraction": frac, "stages_done": [],
            "stage_started_utc": iso(NOW - elapsed_s), "run_started_utc": iso(NOW - elapsed_s),
            "first_stage_started_utc": iso(NOW - elapsed_s)}


def test_eta_history_exact(est: Estimator) -> None:
    r = est.estimate(prog(30.0, 0.02), now=NOW)
    assert r == {"eta_s": 148.0, "eta_basis": "history", "eta_total_s": 178.0}


def test_eta_without_fraction_counts_down(est: Estimator) -> None:
    """Near-miss control: with no stage_fraction the history ETA does count down, monotonically.
    overrun_share 0.5, overrun_decay on: knee = (1 - 0.5) x 100 = 50 s; remaining ingest = 100 - t up to the knee,
    then 0.5 x 100 x 50 / t (decays, never plateaus or rises); + detect 50."""
    eta = [est.estimate(prog(t, None), now=NOW)["eta_s"] for t in (30.0, 50.0, 60.0, 90.0)]
    assert eta == [120.0, 100.0, 91.7, 77.8]   # 70 + 50, 50 + 50, 2500 / 60 + 50, 2500 / 90 + 50
    assert eta == sorted(eta, reverse=True)


def test_eta_live_fraction_moves_with_elapsed(est: Estimator) -> None:
    """At fraction 0.5 (live blend) elapsed matters: 0.5 x live(t) + 0.5 x 50 + 50."""
    assert est.estimate(prog(40.0, 0.5), now=NOW)["eta_s"] == 0.5 * 40.0 + 0.5 * 50.0 + 50.0   # 95.0
    assert est.estimate(prog(80.0, 0.5), now=NOW)["eta_s"] == 0.5 * 80.0 + 0.5 * 50.0 + 50.0   # 115.0


@pytest.mark.xfail(strict=True, reason="QA-API-06: with 0 < stage_fraction < live_min_fraction the ETA is "
                                       "(1 - f) x expected, independent of elapsed: it freezes while time passes "
                                       "(progress_eta.py Estimator.estimate hist_rem)")
def test_qa_api_bug_eta_counts_down_while_fraction_is_stuck(est: Estimator) -> None:
    # Same progress.json (fraction stuck at 0.02, as DuckDB query_progress often is early in a COPY), 60 s later.
    # Measured on f1 via the API: eta_s 114.5 for 72 s of polls. The no-fraction path gives 120.0 then 95.0.
    early = est.estimate(prog(30.0, 0.02), now=NOW)["eta_s"]
    late = est.estimate(prog(90.0, 0.02), now=NOW)["eta_s"]
    assert late < early
