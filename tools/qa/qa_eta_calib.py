"""How good would an ETA built on GET /api/runs/{id} `percent` be? (track qa_api; input for the UI time-remaining work)

The API reports percent = api_runs.STAGE_PERCENT[stage] when a stage STARTS. This tool reads finished runs'
run_metrics.json `stages` (wall_s per stage), computes the real share of wall time elapsed at each stage start,
and the error of the naive ETA a UI would show: remaining = elapsed * (100 / percent - 1).

    .venv/Scripts/python tools/qa/qa_eta_calib.py --json reports/qa/qa_api_eta.json data/out/g10 data/out/smoke ...

Reads run_metrics.json only (timings and row counts, no log content), so organiser sets are safe to include.
Also fits per-stage seconds-per-row rates (median over the given sets) as a candidate for a rows-based ETA.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))
from attacklens.api_runs import STAGE_PERCENT  # noqa: E402


def analyse(run_dir: Path) -> dict[str, Any] | None:
    try:
        m = json.loads((run_dir / "run_metrics.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    stages = [s for s in m.get("stages") or [] if isinstance(s, dict) and "wall_s" in s]
    if not stages or m.get("error") or m.get("from_stage", 0) not in (0, None):
        return None
    total = sum(float(s["wall_s"]) for s in stages)
    if total <= 0:
        return None
    t, rows, worst_pct, worst_rel = 0.0, [], 0.0, 0.0
    for s in stages:
        name = s["name"]
        p = STAGE_PERCENT.get(name)
        if p:
            actual = 100.0 * t / total
            eta_remaining = t * (100.0 / p - 1.0)
            true_remaining = total - t
            err_s = eta_remaining - true_remaining
            rows.append({"stage": name, "start_s": round(t, 1), "api_percent": p, "actual_percent": round(actual, 1),
                         "naive_eta_remaining_s": round(eta_remaining, 1), "true_remaining_s": round(true_remaining, 1),
                         "eta_error_s": round(err_s, 1), "eta_error_pct_of_total": round(100 * err_s / total, 1)})
            worst_pct = max(worst_pct, abs(p - actual))
            if t > 0:
                worst_rel = max(worst_rel, abs(err_s) / total)
        t += float(s["wall_s"])
    return {"set": run_dir.name, "rows_in": m.get("rows_in"), "bytes_in": m.get("bytes_in"),
            "total_wall_s": round(total, 1), "stage_wall_s": {s["name"]: s["wall_s"] for s in stages},
            "stage_share_pct": {s["name"]: round(100 * float(s["wall_s"]) / total, 1) for s in stages},
            "by_stage_start": rows, "max_abs_percent_gap": round(worst_pct, 1),
            "max_abs_eta_error_pct_of_total": round(100 * worst_rel, 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--json", required=True)
    a = ap.parse_args()
    out = [r for r in (analyse(Path(d)) for d in a.dirs) if r]
    rates: dict[str, list[float]] = {}
    for r in out:
        rin = r["rows_in"]
        if isinstance(rin, int) and rin >= 1_000_000:
            for k, v in r["stage_wall_s"].items():
                rates.setdefault(k, []).append(float(v) / rin * 1e6)
    big = [r for r in out if isinstance(r["rows_in"], int) and r["rows_in"] >= 1_000_000]
    share = {k: round(statistics.median(r["stage_share_pct"].get(k, 0.0) for r in big), 1) for k in STAGE_PERCENT}
    res = {"stage_percent_in_api": STAGE_PERCENT, "runs": out,
           "median_stage_share_pct_rows_ge_1M": share,
           "median_s_per_million_rows": {k: round(statistics.median(v), 2) for k, v in rates.items()}}
    Path(a.json).write_text(json.dumps(res, indent=1), encoding="utf-8")
    for r in out:
        print(f"{r['set']:<22} rows={r['rows_in']!s:>10} total={r['total_wall_s']:>7}s "
              f"max|percent gap|={r['max_abs_percent_gap']:>5} max|ETA err|={r['max_abs_eta_error_pct_of_total']:>6}% "
              f"share={r['stage_share_pct']}")
    print("median share (rows>=1M):", share)
    return 0


if __name__ == "__main__":
    sys.exit(main())
