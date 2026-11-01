"""progress.json writer, ETA estimator and the GET /api/runs progress keys (progress.py, progress_eta.py, api_runs.py).

Proposed for backend/tests/test_progress.py (owned by test-engineer).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

from attacklens import api_runs
from attacklens.progress import PROGRESS_FILE, EtaConfig, ProgressWriter, iso_z, read_json, write_json_atomic
from attacklens.progress_eta import Estimator, status_fields

REPO = Path(__file__).resolve().parents[2] if (Path(__file__).resolve().parents[1] / "attacklens").exists() \
    else Path("C:/cyberforge")
NOW = 1_800_000_000.0
KEYS = {"stage_elapsed_s": (float, type(None)), "stage_fraction": (float, type(None)), "stages_done": (list,),
        "bytes_total": (int, type(None)), "bytes_done": (int, type(None)), "rows_done": (int, type(None)),
        "ingest_mb_s": (float, type(None)), "eta_s": (float, type(None)), "eta_basis": (str, type(None)),
        "eta_total_s": (float, type(None))}
PLAN = ["profile", "ingest", "lookups", "detect", "episodes", "link", "incidents", "publish"]


def _hist(root: Path, name: str, mb: float, walls: dict[str, float], source: str = "ecs_json",
          error: str | None = None) -> None:
    d = root / "data" / "out" / name
    d.mkdir(parents=True, exist_ok=True)
    m = {"error": error, "bytes_in": int(mb * 1e6), "rows_in": 10,
         "stage_stats": {"ingest": {"sources": {source: 10}}},
         "stages": [{"name": k, "wall_s": v} for k, v in walls.items()], "total_wall_s": sum(walls.values())}
    (d / "run_metrics.json").write_text(json.dumps(m), encoding="utf-8")


def _est(root: Path, **kw: object) -> Estimator:
    return Estimator(EtaConfig.from_dict({"calibrate": False, **kw}), root)


def _prog(stage: str, elapsed: float, frac: float | None = None, mb: float = 1000.0,
          done: list[tuple[str, float]] | None = None, run_elapsed: float = 100.0) -> dict:
    return {"run_started_utc": iso_z(NOW - run_elapsed), "stage": stage, "stage_index": PLAN.index(stage),
            "stages_total": len(PLAN), "stage_started_utc": iso_z(NOW - elapsed), "stage_fraction": frac,
            "bytes_total": int(mb * 1e6), "bytes_done": None, "rows_done": None, "source_type": "ecs_json",
            "stages_done": [{"stage": s, "wall_s": w} for s, w in (done or [])], "stages_planned": PLAN,
            "updated_utc": iso_z(NOW)}


# ---------------------------------------------------------------- ETA math

def test_eta_history_only(tmp_path: Path) -> None:
    # 0.01 s/MB for every stage at 1000 and 2000 MB -> 10 s per stage for a 1000 MB input
    walls = {s: 10.0 for s in PLAN}
    _hist(tmp_path, "a", 1000, walls)
    _hist(tmp_path, "b", 2000, {s: 20.0 for s in PLAN})
    r = _est(tmp_path).estimate(_prog("lookups", elapsed=4.0), now=NOW)
    # lookups: 10 - 4 left; detect..publish: 5 x 10
    assert r["eta_basis"] == "history"
    assert r["eta_s"] == pytest.approx(6.0 + 50.0, abs=0.1)
    assert r["eta_total_s"] == pytest.approx(100.0 + 56.0, abs=0.1)


def test_eta_overrun_legacy_rule_grows_with_elapsed(tmp_path: Path) -> None:
    _hist(tmp_path, "a", 1000, {s: 10.0 for s in PLAN})
    r = _est(tmp_path, overrun_decay=False).estimate(_prog("publish", elapsed=50.0), now=NOW)
    assert r["eta_s"] == pytest.approx(25.0, abs=0.1)   # past the expected 10 s: overrun_share 0.5 x elapsed
    r = _est(tmp_path, overrun_decay=False, overrun_share=0.1).estimate(_prog("publish", elapsed=50.0), now=NOW)
    assert r["eta_s"] == pytest.approx(5.0, abs=0.1)


def test_eta_overrun_decay_never_rises(tmp_path: Path) -> None:
    # detect expected 100 s (no stage_fraction), then 4 stages x 10 s. share 0.5 -> knee at 50 s:
    # remaining detect = 100 - t up to 50 s, then 0.5 x 100 x 50 / t
    _hist(tmp_path, "a", 1000, {**{s: 10.0 for s in PLAN}, "detect": 100.0})
    est = _est(tmp_path)
    assert est.cfg.overrun_decay is True                                  # the default
    eta = [est.estimate(_prog("detect", elapsed=t), now=NOW)["eta_s"] for t in (20, 50, 80, 100, 200, 1000)]
    assert eta == pytest.approx([80 + 40, 50 + 40, 2500 / 80 + 40, 25 + 40, 12.5 + 40, 2.5 + 40], abs=0.1)
    fine = [est.estimate(_prog("detect", elapsed=t / 2), now=NOW)["eta_s"] for t in range(0, 400)]
    assert all(b <= a for a, b in zip(fine, fine[1:]))                   # monotonic, continuous at the knee
    assert all(e > 40.0 for e in fine)                                    # never 0 while detect runs
    # the legacy rule rises on the same polls (the reported "About N min remaining" climbing)
    old = _est(tmp_path, overrun_decay=False)
    assert old.estimate(_prog("detect", elapsed=200), now=NOW)["eta_s"] > \
        old.estimate(_prog("detect", elapsed=80), now=NOW)["eta_s"]


def test_eta_overrun_slows_future_stages(tmp_path: Path) -> None:
    _hist(tmp_path, "a", 1000, {s: 10.0 for s in PLAN})
    est = Estimator(EtaConfig.from_dict({"calibrate": True, "calibrate_overrun": True, "calibrate_max": 5}), tmp_path)
    # incidents expected 10 s, already 30 s in (3x): publish (10 s in history) is expected 30 s
    r = est.estimate(_prog("incidents", elapsed=30.0), now=NOW)
    assert r["eta_s"] == pytest.approx(0.5 * 10 * 5 / 30 + 30.0, abs=0.1)   # decay (knee 5 s) + publish at 3x


def test_eta_live_only(tmp_path: Path) -> None:
    p = _prog("publish", elapsed=10.0, frac=0.25)              # last planned stage, no history at all
    r = _est(tmp_path).estimate(p, now=NOW)
    assert r["eta_basis"] == "live"
    assert r["eta_s"] == pytest.approx(30.0, abs=0.1)        # 10 s for 25 % -> 30 s left


def test_eta_null_when_a_future_stage_has_no_history(tmp_path: Path) -> None:
    # empty history (fresh clone / Docker): ingest's own 30 s left is NOT the run's remaining time
    assert _est(tmp_path).estimate(_prog("ingest", elapsed=10.0, frac=0.25), now=NOW) ==         {"eta_s": None, "eta_basis": None, "eta_total_s": None}
    # partial history: eval missing from every past run, this run has ground truth -> null, not a sum without eval
    _hist(tmp_path, "a", 1000, {s: 10.0 for s in PLAN})
    p = _prog("detect", elapsed=4.0)
    assert _est(tmp_path).estimate(p, now=NOW)["eta_s"] == pytest.approx(6.0 + 40.0, abs=0.1)
    p["stages_planned"] = PLAN + ["eval"]
    assert _est(tmp_path).estimate(p, now=NOW)["eta_s"] is None


def test_eta_history_plus_live(tmp_path: Path) -> None:
    _hist(tmp_path, "a", 1000, {s: 10.0 for s in PLAN})
    r = _est(tmp_path, live_blend=False).estimate(_prog("ingest", elapsed=10.0, frac=0.5), now=NOW)
    assert r["eta_basis"] == "history+live"
    assert r["eta_s"] == pytest.approx(10.0 + 6 * 10.0, abs=0.1)        # live 10 s left + 6 stages x 10 s
    r = _est(tmp_path, live_blend=True).estimate(_prog("ingest", elapsed=10.0, frac=0.5), now=NOW)
    assert r["eta_s"] == pytest.approx(0.5 * 10.0 + 0.5 * 5.0 + 60.0, abs=0.1)   # blend live 10 / history 5


def test_eta_low_fraction_uses_history(tmp_path: Path) -> None:
    _hist(tmp_path, "a", 1000, {s: 10.0 for s in PLAN})
    r = _est(tmp_path).estimate(_prog("ingest", elapsed=1.0, frac=0.01), now=NOW)
    assert r["eta_basis"] == "history"
    assert r["eta_s"] == pytest.approx(0.99 * 10.0 + 60.0, abs=0.1)


def test_eta_no_history_no_fraction_is_null(tmp_path: Path) -> None:
    r = _est(tmp_path).estimate(_prog("detect", elapsed=3.0), now=NOW)
    assert r == {"eta_s": None, "eta_basis": None, "eta_total_s": None}


def test_eta_ignores_errored_runs_and_current_dir(tmp_path: Path) -> None:
    _hist(tmp_path, "bad", 1000, {s: 99.0 for s in PLAN}, error="BinderException: x")
    _hist(tmp_path, "self", 1000, {s: 99.0 for s in PLAN})
    est = _est(tmp_path)
    r = est.estimate(_prog("detect", elapsed=0.0), now=NOW, exclude=tmp_path / "data" / "out" / "self")
    assert r["eta_s"] is None
    _hist(tmp_path, "good", 1000, {s: 1.0 for s in PLAN})
    est2 = _est(tmp_path)
    r2 = est2.estimate(_prog("detect", elapsed=0.0), now=NOW, exclude=tmp_path / "data" / "out" / "self")
    assert r2["eta_s"] == pytest.approx(5.0, abs=0.1)


def test_eta_tiny_input_floor(tmp_path: Path) -> None:
    # small runs (< 100 MB): fixed ~12 s overhead per stage; a 1000 MB run took 22 s
    _hist(tmp_path, "big", 1000, {s: 22.0 for s in PLAN})
    _hist(tmp_path, "s1", 0.01, {s: 10.0 for s in PLAN})
    _hist(tmp_path, "s2", 0.02, {s: 14.0 for s in PLAN})
    add = _est(tmp_path, additive=True)     # floor 12 + (22 - 12) / 1000 s per MB
    assert add.expected("detect", 0.005, "ecs_json", add.history()) == pytest.approx(12.0, abs=0.01)
    assert add.expected("detect", 5000, "ecs_json", add.history()) == pytest.approx(62.0)
    mx = _est(tmp_path, additive=False)     # max(floor 12, 0.022 s/MB x MB)
    assert mx.expected("detect", 0.005, "ecs_json", mx.history()) == pytest.approx(12.0)   # floor, not 1e-4 s
    assert mx.expected("detect", 5000, "ecs_json", mx.history()) == pytest.approx(110.0)


def test_eta_prefers_same_source(tmp_path: Path) -> None:
    _hist(tmp_path, "ecs", 1000, {"detect": 10.0}, source="ecs_json")
    _hist(tmp_path, "fg", 1000, {"detect": 90.0}, source="fortigate_kv")
    est = _est(tmp_path)
    assert est.expected("detect", 1000, "fortigate_kv", est.history()) == pytest.approx(90.0)
    assert est.expected("detect", 1000, "syslog", est.history()) == pytest.approx(50.0)   # no match: all runs


def test_eta_calibration_scales_history(tmp_path: Path) -> None:
    _hist(tmp_path, "a", 1000, {s: 10.0 for s in PLAN})
    est = Estimator(EtaConfig.from_dict({"calibrate": True}), tmp_path)
    p = _prog("lookups", elapsed=0.0, done=[("profile", 20.0), ("ingest", 20.0)])   # this run is 2x slower
    assert est.estimate(p, now=NOW)["eta_s"] == pytest.approx(6 * 20.0, abs=0.1)


def test_eta_adds_measured_gaps_between_stages(tmp_path: Path) -> None:
    _hist(tmp_path, "a", 1000, {s: 10.0 for s in PLAN})
    p = _prog("lookups", elapsed=4.0, done=[("profile", 10.0), ("ingest", 10.0)])
    p["first_stage_started_utc"] = iso_z(NOW - 30.0)       # 30 - 20 - 4 = 6 s over 2 boundaries
    assert _est(tmp_path, gap_estimate=True).estimate(p, now=NOW)["eta_s"] == pytest.approx(6 + 50 + 5 * 3, abs=0.1)
    assert _est(tmp_path, gap_estimate=False).estimate(p, now=NOW)["eta_s"] == pytest.approx(56.0, abs=0.1)


def test_eta_history_cached(tmp_path: Path) -> None:
    _hist(tmp_path, "a", 1000, {"detect": 10.0})
    est = _est(tmp_path, history_ttl_s=3600)
    assert len(est.history()) == 1
    _hist(tmp_path, "b", 1000, {"detect": 10.0})
    assert len(est.history()) == 1                       # within the TTL: no rescan
    assert len(_est(tmp_path, history_ttl_s=0).history()) == 2


# ---------------------------------------------------------------- progress.json IO

def test_atomic_write_never_partial(tmp_path: Path) -> None:
    path = tmp_path / PROGRESS_FILE
    big = {"stage": "ingest", "pad": "x" * 200_000}
    write_json_atomic(path, big)
    stop = threading.Event()

    def writer() -> None:
        i = 0
        while not stop.is_set():   # far faster than the real 2 s period
            write_json_atomic(path, {**big, "i": i})
            i += 1
            time.sleep(0.002)

    t = threading.Thread(target=writer)
    t.start()
    try:
        for _ in range(300):
            assert read_json(path) is not None           # never a half-written file
    finally:
        stop.set()
        t.join()
    assert not list(tmp_path.glob(".*.tmp"))


# ---------------------------------------------------------------- RunManager.status()

@pytest.fixture()
def job(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    j = api_runs.RunJob("r1", tmp_path / "raw", out, tmp_path / "run.log", [], proc)
    yield j
    proc.kill()
    proc.wait()


def _mgr(tmp_path: Path) -> api_runs.RunManager:
    return api_runs.RunManager(runs_dir=tmp_path / "runs", estimator=_est(tmp_path))


def _check_types(st: dict) -> None:
    for k, types in KEYS.items():
        assert k in st, k
        assert isinstance(st[k], types), (k, st[k])
    for d in st["stages_done"]:
        assert isinstance(d["stage"], str) and isinstance(d["wall_s"], float)
    for k in ("run_id", "status", "stage", "percent", "elapsed_s", "rss_mb", "out_dir", "started"):
        assert k in st                                   # existing keys unchanged


def test_status_running_with_progress(tmp_path: Path, job: api_runs.RunJob) -> None:
    _hist(tmp_path, "a", 1000, {s: 10.0 for s in PLAN})
    p = _prog("ingest", elapsed=10.0, frac=0.5, done=[("profile", 2.0)])
    p.update(run_started_utc=iso_z(time.time() - 12), stage_started_utc=iso_z(time.time() - 10),
             bytes_done=500_000_000, rows_done=1000, pid=job.proc.pid)
    write_json_atomic(job.out_dir / PROGRESS_FILE, p)
    st = _mgr(tmp_path).status(job)
    _check_types(st)
    assert st["status"] == "running" and st["stage_fraction"] == 0.5
    assert st["stages_done"] == [{"stage": "profile", "wall_s": 2.0}]
    assert st["eta_basis"] == "history+live" and st["eta_s"] > 0
    assert st["ingest_mb_s"] == pytest.approx(50.0, rel=0.1)
    assert st["bytes_total"] == 1_000_000_000 and st["rows_done"] == 1000


@pytest.mark.parametrize("content", [None, "", "{\"stage\": \"ing", "[1, 2]", "null",
                                     json.dumps({"stage": 5, "stages_done": 7, "stage_fraction": "x",
                                                 "bytes_total": "big", "pid": None})])
def test_status_tolerates_bad_progress(tmp_path: Path, job: api_runs.RunJob, content: str | None) -> None:
    if content is not None:
        (job.out_dir / PROGRESS_FILE).write_text(content, encoding="utf-8")
    st = _mgr(tmp_path).status(job)
    _check_types(st)
    assert st["status"] == "running"


def test_status_ignores_stale_progress(tmp_path: Path, job: api_runs.RunJob) -> None:
    p = _prog("detect", elapsed=10.0, done=[("profile", 2.0)])
    p.update(run_started_utc=iso_z(job.started_at - 3600), pid=-1)   # an earlier run in the same out dir
    write_json_atomic(job.out_dir / PROGRESS_FILE, p)
    st = _mgr(tmp_path).status(job)
    assert st["stages_done"] == [] and st["eta_s"] is None


def test_status_finished_from_run_metrics(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    j = api_runs.RunJob("r2", tmp_path / "raw", out, tmp_path / "run.log", [], proc)
    m = {"bytes_in": 200_000_000, "rows_in": 5000, "total_wall_s": 30.0,
         "stages": [{"name": "profile", "wall_s": 1.0}, {"name": "ingest", "wall_s": 10.0}]}
    (out / "run_metrics.json").write_text(json.dumps(m), encoding="utf-8")
    st = _mgr(tmp_path).status(j)
    _check_types(st)
    assert st["status"] == "succeeded" and st["eta_s"] == 0.0 and st["eta_total_s"] == 30.0
    assert [d["stage"] for d in st["stages_done"]] == ["profile", "ingest"]
    assert st["ingest_mb_s"] == pytest.approx(20.0)


def test_status_fields_pure_defaults() -> None:
    st = status_fields(None, None, True, None, None)
    assert set(st) == set(KEYS) and st["stages_done"] == []


# ---------------------------------------------------------------- real tiny pipeline

def test_tiny_pipeline_writes_progress(tmp_path: Path) -> None:
    src = REPO / "data" / "raw" / "smoke" / "edr.jsonl"
    if not src.exists():
        pytest.skip("data/raw/smoke not generated")
    raw = tmp_path / "raw"
    raw.mkdir()
    with src.open("rb") as fh, (raw / "edr.jsonl").open("wb") as dst:
        for _ in range(2000):
            dst.write(fh.readline())
    cfg = tmp_path / "config"
    shutil.copytree(REPO / "config", cfg, ignore=shutil.ignore_patterns("sigma"))  # sigma off below
    pipe = yaml.safe_load((cfg / "pipeline.yaml").read_text(encoding="utf-8"))
    pipe["sigma"]["enabled"] = False
    pipe["eta"]["progress_interval_s"] = 0.1
    (cfg / "pipeline.yaml").write_text(yaml.safe_dump(pipe), encoding="utf-8")
    out = tmp_path / "out"
    seen: list[dict] = []
    stop = threading.Event()

    def poll() -> None:
        while not stop.is_set():
            p = read_json(out / PROGRESS_FILE)
            if p:
                seen.append(p)
            time.sleep(0.05)

    t = threading.Thread(target=poll)
    t.start()
    from attacklens.run import STAGES, run_pipeline
    try:
        run_pipeline(raw, out, parquet=tmp_path / "pq", config_dir=cfg)
    finally:
        stop.set()
        t.join()
    final = read_json(out / PROGRESS_FILE)
    assert final is not None and final["finished"] is True and final["error"] is None
    assert [d["stage"] for d in final["stages_done"]] == list(STAGES)
    assert final["bytes_total"] == (raw / "edr.jsonl").stat().st_size
    assert final["rows_done"] == 2000 and final["source_type"] == "ecs_json"
    idx = [p["stage_index"] for p in seen + [final]]
    assert idx == sorted(idx) and len(set(idx)) >= 2       # monotonic, several stages observed
    contract = {"run_started_utc", "stage", "stage_index", "stages_total", "stage_started_utc", "stage_fraction",
                "bytes_total", "bytes_done", "rows_done", "stages_done", "updated_utc"}
    for p in seen:
        assert contract <= set(p) and p["stage"] in STAGES
        f = p["stage_fraction"]
        assert f is None or 0.0 <= f <= 1.0


def test_eta_config_coerces_yaml_strings(caplog: pytest.LogCaptureFixture) -> None:
    # YAML 1.1 (PyYAML) reads `1.0e8` as a string: it must still become a float, bad values keep the default
    c = EtaConfig.from_dict({"small_input_bytes": "1.0e8", "similar_runs": "7", "x": 1})
    assert c.small_input_bytes == 1.0e8 and c.similar_runs == 7
    with caplog.at_level("WARNING", logger="attacklens.progress"):
        c = EtaConfig.from_dict({"calibrate": "no", "overrun_decay": "no"})    # strings are not bools
    assert c.calibrate is True and c.overrun_decay is True                     # rejected: the defaults
    assert "eta.calibrate='no' ignored" in caplog.text and "eta.overrun_decay='no' ignored" in caplog.text
    assert EtaConfig.from_dict({"calibrate": False}).calibrate is False
    shipped = yaml.safe_load((REPO / "config" / "pipeline.yaml").read_text(encoding="utf-8"))["eta"]
    assert isinstance(EtaConfig.from_dict(shipped).small_input_bytes, float)
    assert EtaConfig.from_dict(shipped).overrun_decay is True                   # shipped config: decay on
    assert EtaConfig.from_dict({"calibrate_skip": ["profile", "ingest"]}).calibrate_skip == ("profile", "ingest")
    assert EtaConfig.from_dict({"calibrate_skip": "profile"}).calibrate_skip == ("profile",)   # bad: default


# ---------------------------------------------------------------- multi-batch ingest fraction

def _ingest_writer(tmp_path: Path, total: int, batch_bytes: float | None) -> ProgressWriter:
    raw = tmp_path / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    w = ProgressWriter(tmp_path / "out", [(1, "ingest")], 8, raw, None,
                       EtaConfig.from_dict({"progress_interval_s": 3600}), batch_bytes=batch_bytes)
    w.state["bytes_total"] = total
    w.stage_start(1, "ingest")
    return w


def _batch_record(done: int, total: int, mb: float, rows: int) -> logging.LogRecord:
    return logging.LogRecord("attacklens.ingest", logging.INFO, __file__, 1,
                             "ingest batch %d/%d: %d files, %.1f MB, %d rows so far", (done, total, 3, mb, rows), None)


def test_ingest_fraction_first_batch_of_many(tmp_path: Path) -> None:
    # 10 GB, batch_bytes 2e9: before the first "ingest batch 1/5" record the running COPY is ~2 GB, not 10 GB
    w = _ingest_writer(tmp_path, 10_000_000_000, 2e9)
    w._ingest_fraction(0.5)
    assert w.state["bytes_done"] == 1_000_000_000 and w.state["stage_fraction"] == pytest.approx(0.1 * 0.9)
    w._ingest_fraction(0.95)
    assert w.state["bytes_done"] == 1_900_000_000 and w.state["stage_fraction"] == pytest.approx(0.19 * 0.9)
    w.on_batch(1, 5, 2000.0, 100)                       # batch 1 finished
    w._ingest_fraction(0.02)                           # batch 2 at 2 %: 2 GB + 8 GB / 4 x 0.02
    assert w.state["bytes_done"] == 2_040_000_000 and w.state["stage_fraction"] == pytest.approx(0.204 * 0.9)
    assert w.state["rows_done"] == 100
    for b in range(2, 6):
        w.on_batch(b, 5, 2000.0, 100 * b)
    w._ingest_fraction(None)                           # all COPYs done: accounting phase
    assert w.state["stage_fraction"] == pytest.approx(0.9) and w.state["bytes_done"] == 10_000_000_000


def test_ingest_fraction_never_moves_backwards(tmp_path: Path) -> None:
    # 5 GB: ceil(5 / 2) = 3 batches estimated (1.67 GB each); the real batch 1 was 2 GB -> no step back
    w = _ingest_writer(tmp_path, 5_000_000_000, 2e9)
    seen = []
    for q in (0.1, 0.5, 0.9, 1.0):
        w._ingest_fraction(q)
        seen.append((w.state["stage_fraction"], w.state["bytes_done"]))
    w.on_batch(1, 3, 2000.0, 1)
    for q in (0.0, 0.3, 1.0):
        w._ingest_fraction(q)
        seen.append((w.state["stage_fraction"], w.state["bytes_done"]))
    assert seen == sorted(seen) and all(0.0 <= f <= 0.9 for f, _ in seen)
    assert all(b <= 5_000_000_000 for _, b in seen)


def test_ingest_fraction_single_batch_and_unknown_batch_bytes(tmp_path: Path) -> None:
    small = _ingest_writer(tmp_path / "a", 210_000_000, 2e9)       # one batch: the COPY is the whole input
    small._ingest_fraction(0.5)
    assert small.state["bytes_done"] == 105_000_000 and small.state["stage_fraction"] == pytest.approx(0.45)
    legacy = _ingest_writer(tmp_path / "b", 210_000_000, None)     # batch_bytes unknown: same as one batch
    legacy._ingest_fraction(0.5)
    assert legacy.state["bytes_done"] == 105_000_000
    w = _ingest_writer(tmp_path / "c", 1_000_000, 2e9)
    w._ingest_fraction(7.0)                                        # a bogus query_progress() is clipped
    assert w.state["bytes_done"] == 1_000_000 and w.state["stage_fraction"] == pytest.approx(0.9)


def test_batch_handler_reads_record_args(tmp_path: Path) -> None:
    from attacklens.progress import _BatchHandler
    w = _ingest_writer(tmp_path, 10_000_000_000, 2e9)
    h = _BatchHandler(w)
    h.emit(_batch_record(1, 5, 2000.0, 1234))
    assert w._batch == {"done": 1, "total": 5, "bytes": pytest.approx(2e9), "rows": 1234}
    h.emit(logging.LogRecord("attacklens.ingest", logging.INFO, __file__, 1, "ingest batch %d SQL: %s",
                             (0, "COPY ..."), None))               # debug SQL line: ignored
    h.emit(logging.LogRecord("attacklens.ingest", logging.INFO, __file__, 1, "ingest batch %d/%d: %d files",
                             (2, 5), None))                       # too few args: ignored, never raises
    h.emit(_batch_record(2, 5, 2000.0, 2468))
    assert w._batch["done"] == 2 and w._batch["bytes"] == pytest.approx(4e9) and w._batch["rows"] == 2468


def test_batch_handler_via_ingest_logger(tmp_path: Path) -> None:
    w = _ingest_writer(tmp_path, 10_000_000_000, 2e9).start()     # start() attaches the handler at INFO
    try:
        logging.getLogger("attacklens.ingest").info("ingest batch %d/%d: %d files, %.1f MB, %d rows so far",
                                                    1, 5, 3, 2000.0, 77)
        w.flush()
        p = read_json(w.path)
        assert p is not None and p["bytes_done"] == 2_000_000_000 and p["rows_done"] == 77
    finally:
        w.finish()
    assert w._handler not in logging.getLogger("attacklens.ingest").handlers


def test_run_batch_bytes_from_config() -> None:
    from attacklens.run import _batch_bytes
    assert _batch_bytes({"ingest": {"batch_bytes": "2.0e9"}}) == 2e9   # YAML 1.1 string
    assert _batch_bytes({}) == 2e9                                     # ingest.py's default
    assert _batch_bytes({"ingest": {"batch_bytes": "big"}}) is None
