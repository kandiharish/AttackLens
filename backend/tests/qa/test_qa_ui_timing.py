"""QA track qa_ui: run-time and ETA display logic (Add data -> RunStepper, footer), on the real TypeScript.

The helpers are imported from frontend/src/lib/{addData,metrics,format}.ts through `node --experimental-strip-types`
(type-only imports are erased, so no bundler is needed). Every expected value below is hand-computed in the comments.

The last block pins the run-progress contract: the optional progress keys of RunStatus in frontend/src/api.ts must be
exactly the keys backend/attacklens/progress_eta.status_fields() sends in GET /api/runs/{id}.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
LIB = REPO / "frontend" / "src" / "lib"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None or not (LIB / "addData.ts").exists(), reason="node or frontend sources missing")


def node_eval(module: str, body: str, arg: object = None) -> object:
    """Import frontend/src/lib/<module>.ts as `m`, bind `a` = JSON arg, evaluate `body` and return its JSON value."""
    script = (
        "const m = await import(process.argv[1]); const a = JSON.parse(process.argv[2]);"
        f"const out = ({body}); process.stdout.write(JSON.stringify(out === undefined ? null : out));"
    )
    res = subprocess.run(
        [NODE, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script,
         (LIB / f"{module}.ts").as_uri(), json.dumps(arg)],
        capture_output=True, text=True, encoding="utf-8", timeout=60, check=True,
    )
    return json.loads(res.stdout)


# ---------- fmtEta: headline for the remaining time ----------

def test_fmt_eta_exact_bands() -> None:
    cases = [None, float("nan"), -5, 0, 9.9, 10, 12.4, 12.5, 44, 60, 89, 91, 371, 3569, 3570, 5400, 7200, 7230]
    got = node_eval("addData", "a.map(x => m.fmtEta(x))", [c if c is None or c == c else "nan" for c in cases])
    # "nan" is a string (JSON has no NaN): not finite -> "Estimating time..." like null.
    assert got == [
        "Estimating time…",            # null: backend has no estimate
        "Estimating time…",            # non-number
        "Finishing…",                  # -5 clamps to 0 (< 10 s)
        "Finishing…",                  # 0
        "Finishing…",                  # 9.9 < 10
        "About 10 s remaining",        # 10 -> round(2)*5
        "About 10 s remaining",        # 12.4 -> round(2.48)=2 -> 10
        "About 15 s remaining",        # 12.5 -> round(2.5)=3 -> 15
        "About 45 s remaining",        # 44 -> round(8.8)=9 -> 45
        "About 1 min remaining",       # 60 -> minutes band
        "About 1 min remaining",       # 89 -> round(1.48)=1
        "About 2 min remaining",       # 91 -> round(1.52)=2
        "About 6 min remaining",       # 371 -> round(6.18)=6
        "About 59 min remaining",      # 3569 -> round(59.48)=59 (last minutes value)
        "About 1 h remaining",         # 3570 -> m=round(59.5)=60 -> 1 h, no "0 min"
        "About 1 h 30 min remaining",  # 5400 -> 90 min
        "About 2 h remaining",         # 7200
        "About 2 h 1 min remaining",   # 7230 -> round(120.5)=121 min
    ]


# ---------- smoothEta: EMA (alpha 0.35), <= 20 % (min +3 s) growth per poll within a stage ----------

SEQ = [  # (elapsed_s, stage, raw eta_s) -- the same noisy sequence as frontend/src/dev/RunStepperHarness.tsx
    (10, "ingest", None), (12, "ingest", 420), (14, "ingest", 380), (16, "ingest", 650), (18, "ingest", 300),
    (20, "ingest", 410), (22, "detect", 900), (24, "detect", 860), (26, "detect", -5),
]


def _smooth(seq: list[tuple[float, str, float | None]], run_ids: list[str] | None = None) -> list[float | None]:
    arg = [{"t": t, "stage": s, "raw": r, "run": (run_ids[i] if run_ids else "r1")} for i, (t, s, r) in enumerate(seq)]
    body = "(() => { let p = null; return a.map(x => { p = m.smoothEta(p, x.raw, x.run, x.stage, x.t); return p ? p.eta : null }) })()"
    return node_eval("addData", body, arg)  # type: ignore[return-value]


def test_smooth_eta_exact_sequence() -> None:
    # t12: first value -> 420.  t14: pred 418, 0.35*380+0.65*418 = 404.7 (cap 504, not hit).
    # t16: pred 402.7, 0.35*650+0.65*402.7 = 489.255 > cap 404.7*1.2 = 485.64 -> 485.64 (CAPPED).
    # t18: pred 483.64 -> 105+314.366 = 419.366.  t20: pred 417.366 -> 143.5+271.2879 = 414.7879.
    # t22 (stage change, cap lifted): pred 412.7879 -> 315+268.312135 = 583.312135 (cap would be 497.745).
    # t24: pred 581.312135 -> 301+377.85288775 = 678.85288775 (< cap 699.97).  t26 raw -5 -> 0: 0.65*676.85288775.
    want = [None, 420, 404.7, 485.64, 419.366, 414.7879, 583.312135, 678.85288775, 439.9543770375]
    got = _smooth(SEQ)
    assert got[0] is None
    assert got[1:] == pytest.approx(want[1:], abs=1e-6)


def test_smooth_eta_growth_floor_three_seconds() -> None:
    # prev 2 s, next poll +1 s, raw 100: pred 1 -> 35+0.65 = 35.65; cap max(2*1.2, 2+3) = 5 -> 5.
    assert _smooth([(10, "detect", 2), (11, "detect", 100)]) == pytest.approx([2, 5])


def test_smooth_eta_resets_near_misses() -> None:
    # Another run id -> raw value as-is (no blending with the old run).
    assert _smooth([(10, "ingest", 100), (12, "ingest", 300)], run_ids=["r1", "r2"]) == pytest.approx([100, 300])
    # Clock went backwards (elapsed 12 -> 5): reset to raw.
    assert _smooth([(12, "ingest", 100), (5, "ingest", 300)]) == pytest.approx([100, 300])
    # Same poll seen twice (same elapsed, same stage): unchanged even with a different raw.
    assert _smooth([(12, "ingest", 100), (12, "ingest", 300)]) == pytest.approx([100, 100])
    # Raw null mid-run: null (headline "Estimating time..."), then a fresh start from the next raw.
    assert _smooth([(12, "ingest", 100), (14, "ingest", None), (16, "ingest", 50)]) == [100, None, 50]


# ---------- ingestLine / stepTimes ----------

def test_ingest_line_exact() -> None:
    gb = 1024 ** 3
    arg = [
        {"bytes_total": 6.5 * gb, "bytes_done": 3.2 * gb, "ingest_mb_s": 31.4},  # rate >= 10 -> rounded
        {"bytes_total": 6.5 * gb, "bytes_done": 3.2 * gb, "ingest_mb_s": 4.2},   # rate < 10 -> 1 decimal
        {"bytes_total": 2 * 1024 ** 2},                                           # no done, no rate
        {"bytes_total": 1024, "bytes_done": 5000, "ingest_mb_s": 0},              # done clamps to total; rate 0 hidden
        {"bytes_total": 0, "bytes_done": 0},                                      # near miss: empty total -> null
        {"bytes_done": 10},                                                       # near miss: no total -> null
        None,
    ]
    assert node_eval("addData", "a.map(x => m.ingestLine(x))", arg) == [
        "Ingestion: 3.20 GB of 6.50 GB · 31 MB/s",
        "Ingestion: 3.20 GB of 6.50 GB · 4.2 MB/s",
        "Ingestion: 2.0 MB to read",
        "Ingestion: 1 KB of 1 KB",
        None, None, None,
    ]


def test_step_times_groups_backend_stages() -> None:
    done = [{"stage": "profile", "wall_s": 8}, {"stage": "ingest", "wall_s": 320}, {"stage": "lookups", "wall_s": 19},
            {"stage": "detect", "wall_s": 120}, {"stage": "episodes", "wall_s": -3}, {"stage": "bogus", "wall_s": 5},
            {"stage": "link", "wall_s": None}, {"stage": "PUBLISH", "wall_s": 3.5}]
    # Reading = 8+320+19; Detecting = 120 + max(0,-3); bogus ignored; link wall_s null ignored -> null; publish (case-insensitive).
    assert node_eval("addData", "m.stepTimes(a)", done) == [347, 120, None, 3.5, None]
    assert node_eval("addData", "m.stepTimes(a)", None) == [None, None, None, None, None]


# ---------- footer timing (lib/metrics readRunTiming + formatters) ----------

def test_read_run_timing_exact_and_fallbacks() -> None:
    arg = [
        # g1x shape (values hand-copied from a run_metrics.json): top-level rows_in, stages[name=ingest].wall_s.
        {"run_metrics": {"rows_in": 1305412, "total_wall_s": 28.561,
                         "stages": [{"name": "profile", "wall_s": 4.551}, {"name": "ingest", "wall_s": 14.193}],
                         "stage_stats": {"ingest": {"rows_in": 9, "wall_s": 99}}}},
        # No top-level rows_in / stages: stage_stats.ingest fallbacks; no total_wall_s -> null.
        {"run_metrics": {"stage_stats": {"ingest": {"rows_in": 7, "wall_s": 2.5}}}},
        # Only ingest_accounting: rows = sum(rows_in) = 3 + 4.
        {"run_metrics": {}, "ingest_accounting": [{"rows_in": 3}, {"rows_in": 4}]},
        None,
    ]
    assert node_eval("metrics", "a.map(x => m.readRunTiming(x))", arg) == [
        {"rows": 1305412, "ingestS": 14.193, "totalS": 28.561},
        {"rows": 7, "ingestS": 2.5, "totalS": None},
        {"rows": 7, "ingestS": None, "totalS": None},
        {"rows": None, "ingestS": None, "totalS": None},
    ]


def test_footer_formatters_exact() -> None:
    body = ("({count: [0, 9999, 10000, 1305412, 2.5e9].map(m.fmtCount),"
            " secs: [null, -1, 0, 14.193, 59.96, 60, 214.1, 3599.4, 3600, 5400].map(m.fmtSeconds)})")
    assert node_eval("metrics", body) == {
        "count": ["0", "9,999", "10.0 k", "1.3 M", "2.50 B"],
        # 59.96 -> "60.0 s" (one decimal under a minute); 214.1 -> 3m 34s; 3599.4 -> 59m 59s; 5400 -> 1h 30m.
        "secs": ["—", "—", "0.0 s", "14.2 s", "60.0 s", "1m 0s", "3m 34s", "59m 59s", "1h 00m", "1h 30m"],
    }
    assert node_eval("format", "a.map(m.baseName)", ["C:\\cyberforge\\data\\out\\g1x", "/app/data/out/demo/", "x"]) == ["g1x", "demo", "x"]


# ---------- run progress contract: GET /api/runs/{id} keys == frontend RunStatus optional keys ----------

API_TS = REPO / "frontend" / "src" / "api.ts"
# Optional RunStatus fields that are NOT progress/ETA keys (not from progress_eta.status_fields), wherever api.ts
# declares them: integrity = api_runs.integrity_summary (log-integrity verdict of the run's integrity_report.json).
NON_PROGRESS_RUN_KEYS = {"integrity"}


def _frontend_progress_keys() -> set[str]:
    """Keys declared after the 'progress keys' comment in the RunStatus interface of frontend/src/api.ts,
    minus the named NON_PROGRESS_RUN_KEYS."""
    src = API_TS.read_text(encoding="utf-8")
    body = src[src.index("export interface RunStatus"):]
    body = body[:body.index("\n}")]
    tail = body[body.index("progress keys"):]
    return set(re.findall(r"^\s+(\w+)\?:", tail, flags=re.M)) - NON_PROGRESS_RUN_KEYS


def test_run_progress_keys_match_frontend_contract() -> None:
    from attacklens.progress_eta import status_fields

    backend = set(status_fields(None, None, True, None, None))
    assert backend == _frontend_progress_keys() == {
        "stage_elapsed_s", "stage_fraction", "stages_done", "bytes_total", "bytes_done", "rows_done",
        "ingest_mb_s", "eta_s", "eta_basis", "eta_total_s"}


def test_run_progress_fields_exact_while_ingesting() -> None:
    """Hand-made progress.json during ingest, fixed clock: what the stepper will be given."""
    from attacklens.progress import iso_z
    from attacklens.progress_eta import status_fields

    now = 1_800_000_000.0
    prog = {"stage": "ingest", "stage_started_utc": iso_z(now - 100), "stage_fraction": 1.7,
            "stages_done": [{"stage": "profile", "wall_s": 8}, {"stage": "bad"}, "junk"],
            "bytes_total": 4_000_000_000, "bytes_done": 1_000_000_000, "rows_done": 12}
    got = status_fields(prog, None, True, None, None, now=now)
    # fraction clamps to 1.0; malformed stages_done entries dropped; rate = 1e9 B / 1e6 / 100 s = 10.0 (decimal MB/s).
    assert got == {"stage_elapsed_s": 100.0, "stage_fraction": 1.0, "stages_done": [{"stage": "profile", "wall_s": 8.0}],
                   "bytes_total": 4_000_000_000, "bytes_done": 1_000_000_000, "rows_done": 12, "ingest_mb_s": 10.0,
                   "eta_s": None, "eta_basis": None, "eta_total_s": None}


def test_run_progress_fields_near_miss_no_progress_file() -> None:
    """Running but no progress.json yet: every progress key null / empty -> UI shows 'Estimating time...'."""
    from attacklens.progress_eta import status_fields

    got = status_fields(None, None, True, None, None)
    assert got["eta_s"] is None and got["stages_done"] == [] and got["bytes_total"] is None
    assert node_eval("addData", "[m.fmtEta(a.eta_s), m.ingestLine(a)]", got) == ["Estimating time…", None]


def test_run_status_running_job_has_progress_keys(tmp_path: Path) -> None:
    """A real RunManager (tmp roots) on a running stub process in stage ingest: base keys + all progress keys."""
    from attacklens.api_runs import RunJob, RunManager

    log_path = tmp_path / "run.log"
    log_path.write_text("12:00:00 INFO stage profile start\n12:00:01 INFO stage ingest start\n", encoding="utf-8")
    mgr = RunManager(runs_dir=tmp_path / "runs", raw_root=tmp_path, out_root=tmp_path / "out")
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    try:
        st = mgr.status(RunJob("qa000000001", tmp_path, tmp_path / "out" / "x", log_path, ["x"], proc))
    finally:
        proc.kill()
        proc.wait(timeout=10)
    assert (st["status"], st["stage"], st["percent"]) == ("running", "ingest", 5)
    assert _frontend_progress_keys() <= set(st)
    assert st["eta_s"] is None  # no progress.json in the out dir
