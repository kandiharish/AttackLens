"""Measure the accuracy of GET /api/runs/{id} `eta_s` on a real run (track qa_api; UI time-remaining feature).

Starts one run through a private API (never :8000), polls every --poll-s, and records (t, stage, percent, eta_s,
eta_basis, stage_fraction, bytes_done). When the run is done, each sample's predicted finish (t + eta_s) is compared
with the measured finish.

    .venv/Scripts/python tools/qa/qa_eta_live.py --port 8031 --raw data/raw/smoke --out data/out/qa_api_eta_smoke \
        --json data/tmp/qa_api/eta_live_smoke.json --cleanup
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import sys
import time
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parents[2]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", required=True, help="repo-relative data/out/<name> (must not exist or be qa_*)")
    ap.add_argument("--json", required=True)
    ap.add_argument("--poll-s", type=float, default=1.0)
    ap.add_argument("--limit-s", type=float, default=1800)
    ap.add_argument("--cleanup", action="store_true", help="remove the out dir, its parquet dir and the run log")
    a = ap.parse_args()
    if a.port in (8000, 5173):
        raise SystemExit("refusing a shared port")
    name = Path(a.out).name
    if not name.startswith("qa_"):
        raise SystemExit("--out basename must start with qa_")
    samples: list[dict[str, Any]] = []
    with httpx.Client(base_url=f"http://127.0.0.1:{a.port}", timeout=30) as c:
        r = c.post("/api/runs", json={"raw_dir": a.raw, "out_dir": a.out})
        if r.status_code != 202:
            raise SystemExit(f"POST /api/runs -> {r.status_code} {r.text[:200]}")
        rid = r.json()["run_id"]
        t0 = time.monotonic()
        while True:
            s = c.get(f"/api/runs/{rid}").json()
            t = round(time.monotonic() - t0, 2)
            samples.append({"t": t, **{k: s.get(k) for k in ("status", "stage", "percent", "elapsed_s", "eta_s",
                                                             "eta_basis", "eta_total_s", "stage_fraction",
                                                             "stage_elapsed_s", "bytes_done", "bytes_total",
                                                             "rows_done", "ingest_mb_s")}})
            if s["status"] != "running" or t > a.limit_s:
                break
            time.sleep(a.poll_s)
    final = samples[-1]
    finish = final["elapsed_s"]
    errs = []
    for x in samples[:-1]:
        if isinstance(x.get("eta_s"), (int, float)) and isinstance(x.get("elapsed_s"), (int, float)):
            pred = x["elapsed_s"] + x["eta_s"]
            x["pred_finish_s"] = round(pred, 1)
            x["err_s"] = round(pred - finish, 1)
            x["err_pct_of_total"] = round(100 * (pred - finish) / finish, 1) if finish else None
            errs.append(abs(x["err_s"]))
    running = samples[:-1]
    with_eta = [x for x in running if isinstance(x.get("eta_s"), (int, float))]
    res = {"run_id": rid, "raw": a.raw, "status": final["status"], "total_elapsed_s": finish,
           "eta_total_s_final": final.get("eta_total_s"), "polls_running": len(running),
           "polls_with_eta": len(with_eta), "polls_eta_null": len(running) - len(with_eta),
           "abs_err_s": {"p50": round(statistics.median(errs), 1), "max": round(max(errs), 1)} if errs else None,
           "abs_err_pct_of_total": {"p50": round(100 * statistics.median(errs) / finish, 1),
                                    "max": round(100 * max(errs) / finish, 1)} if errs and finish else None,
           "eta_negative": sum(1 for x in with_eta if x["eta_s"] < 0),
           "bases": sorted({str(x.get("eta_basis")) for x in running}),
           "percent_monotonic": all(b["percent"] >= p["percent"] for p, b in zip(samples, samples[1:])),
           "samples": samples}
    Path(a.json).write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "samples"}, indent=1))
    if a.cleanup:
        for d in (REPO / "data" / "out" / name, REPO / "data" / "parquet" / name):
            shutil.rmtree(d, ignore_errors=True)
        (REPO / "data" / "runs" / f"run-{rid}.log").unlink(missing_ok=True)
    return 0 if final["status"] == "succeeded" else 1


if __name__ == "__main__":
    sys.exit(main())
