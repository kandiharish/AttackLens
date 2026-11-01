"""Fit per-rule scaling exponents from scale_detect.py results.

For every series (a list of slice names whose rows grow along one axis) and every detect rule / step / Sigma group,
fit time ~ rows^k by least squares on log-log points, for wall seconds and for DuckDB CPU seconds (profile
cpu_s, less sensitive to other jobs on the box). Also fits k for alerts out and rows through window operators,
so data-driven growth (more qualifying rows) is visible next to algorithmic growth (cost per row rising).

  python tools/perf/fit_scaling.py --series span=n30_d2,n30_d4,n30_d7 --series density=n30_b30_1of3,...
      [--dir reports/perf/round0] [--md out.md] [--json out.json]

Output: counts, timings and rule ids only.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
SUPER = 1.15


def slope(xs: list[float], ys: list[float]) -> float | None:
    pts = [(math.log(x), math.log(y)) for x, y in zip(xs, ys) if x and y and x > 0 and y > 0]
    if len(pts) < 2:
        return None
    mx = sum(p[0] for p in pts) / len(pts)
    my = sum(p[1] for p in pts) / len(pts)
    den = sum((p[0] - mx) ** 2 for p in pts)
    return round(sum((p[0] - mx) * (p[1] - my) for p in pts) / den, 2) if den else None


def entries(res: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """name -> {wall, cpu, alerts, window_rows, scan_out_rows, spill, rss, others, plan}"""
    out: dict[str, dict[str, Any]] = {}

    def put(name: str, r: dict[str, Any], alerts: Any = None) -> None:
        p = r.get("profile") or {}
        att = [a.get("wall_s") for a in r.get("attempts") or [] if a.get("wall_s")]
        out[name] = {"wall": min(att) if att else r.get("wall_s"), "cpu": r.get("proc_cpu_s"), "op_cpu": p.get("cpu_s"), "alerts": alerts if alerts is not None
                     else r.get("alerts"), "window_rows": p.get("window_rows"), "scan_out_rows": p.get("scan_out_rows"),
                     "spill_mb": max(float(p.get("peak_temp_dir_mb") or 0), float(r.get("spill_dir_peak_mb") or 0)),
                     "rss_mb": r.get("peak_rss_mb"), "others": r.get("cpu_others_mean"),
                     "pre_idle": r.get("pre_cpu_idle_load"), "free_mb": r.get("free_ram_min_mb"),
                     "plan_s": p.get("plan_s"), "n_scans": p.get("n_scans"), "page_faults": r.get("page_faults")}

    for rid, r in (res.get("rules") or {}).items():
        put(rid, r)
    for k in ("match_scan", "relabel", "copy_raw_alerts", "baseline"):
        if isinstance((res.get("steps") or {}).get(k), dict):
            put(f"[{k}]", res["steps"][k])
    sg = res.get("sigma")
    if sg:
        put("[sigma total]", sg, (sg.get("stats") or {}).get("sigma_alerts"))
        groups: dict[str, dict[str, Any]] = {}
        seen: dict[str, int] = {}
        for st in sg.get("statements") or []:
            if st.get("kind") != "group_total":
                continue
            lab = st["label"]
            seen[lab] = seen.get(lab, 0) + 1
            key = f"sigma:{lab}" + ("+" * (seen[lab] - 1))
            groups[key] = {"wall": st["wall_s"], "tuples": st.get("tuples"), "matched": st.get("matched_tuples")}
        # statement-level CPU per group (sum over the group's statements, in order)
        cur: dict[str, float] = {}
        seen2: dict[str, int] = {}
        pending: list[dict[str, Any]] = []
        for st in sg.get("statements") or []:
            if st.get("kind") == "group_total":
                lab = st["label"]
                seen2[lab] = seen2.get(lab, 0) + 1
                key = f"sigma:{lab}" + ("+" * (seen2[lab] - 1))
                cur[key] = sum(float((p.get("profile") or {}).get("cpu_s") or 0) for p in pending)  # DuckDB op CPU
                groups[key]["spill_mb"] = max([float((p.get("profile") or {}).get("peak_temp_dir_mb") or 0)
                                               for p in pending] or [0])
                groups[key]["stmts"] = {p["kind"]: round(p["wall_s"], 2) for p in pending}
                pending = []
            else:
                pending.append(st)
        for key, g in groups.items():
            out[key] = {"wall": g["wall"], "cpu": None, "op_cpu": cur.get(key), "alerts": g.get("matched"),
                        "window_rows": None, "scan_out_rows": g.get("tuples"), "spill_mb": g.get("spill_mb"),
                        "stmts": g.get("stmts")}
    return out


def load(d: Path, name: str) -> dict[str, Any]:
    return json.loads((d / f"{name}.json").read_text(encoding="utf-8"))


def fit_series(d: Path, names: list[str]) -> dict[str, Any]:
    runs = [load(d, n) for n in names]
    rows = [float(r["rows"]) for r in runs]
    ents = [entries(r) for r in runs]
    keys = list(dict.fromkeys(k for e in ents for k in e))
    out: dict[str, Any] = {"slices": names, "rows": [int(x) for x in rows], "items": {}}
    for k in keys:
        vals = [e.get(k) or {} for e in ents]
        item = {f: [v.get(f) for v in vals] for f in ("wall", "cpu", "op_cpu", "alerts", "window_rows", "scan_out_rows",
                                                      "spill_mb", "rss_mb", "others", "pre_idle", "free_mb",
                                                      "page_faults")}
        item["k_wall"] = slope(rows, [v.get("wall") or 0 for v in vals])
        item["k_cpu"] = slope(rows, [v.get("cpu") or 0 for v in vals])
        item["k_op_cpu"] = slope(rows, [v.get("op_cpu") or 0 for v in vals])
        item["k_alerts"] = slope(rows, [v.get("alerts") or 0 for v in vals])
        item["k_window_rows"] = slope(rows, [v.get("window_rows") or 0 for v in vals])
        item["k_scan_rows"] = slope(rows, [v.get("scan_out_rows") or 0 for v in vals])
        if any(v.get("stmts") for v in vals):
            item["stmts"] = [v.get("stmts") for v in vals]
        out["items"][k] = item
    return out


def _f(v: Any, nd: int = 1) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


def markdown(fits: dict[str, dict[str, Any]], min_wall: float) -> str:
    lines = []
    for name, f in fits.items():
        lines.append(f"### Series `{name}`: {', '.join(f['slices'])}")
        lines.append("")
        lines.append("rows: " + " / ".join(f"{r:,}" for r in f["rows"]) + "  (ratio "
                     + " : ".join(f"{r / f['rows'][0]:.2f}" for r in f["rows"]) + ")")
        lines.append("")
        lines.append("| rule / step | wall s | k wall | proc cpu s | k cpu | alerts | k alerts | window rows | k win rows "
                     "| spill MB | others % (pre-idle) | flag |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
        items = sorted(f["items"].items(), key=lambda kv: -max([x or 0 for x in kv[1]["wall"]] or [0]))
        for k, it in items:
            if max([x or 0 for x in it["wall"]] or [0]) < min_wall:
                continue
            kk = [x for x in (it["k_wall"], it["k_cpu"]) if x is not None]
            flag = "SUPER" if kk and min(kk) > SUPER else ("super?" if kk and max(kk) > SUPER else "")
            lines.append(
                f"| {k} | {' / '.join(_f(x) for x in it['wall'])} | {_f(it['k_wall'], 2)} "
                f"| {' / '.join(_f(x) for x in it['cpu'])} | {_f(it['k_cpu'], 2)} "
                f"| {' / '.join(_f(x) for x in it['alerts'])} | {_f(it['k_alerts'], 2)} "
                f"| {' / '.join(_f(x) for x in it['window_rows'])} | {_f(it['k_window_rows'], 2)} "
                f"| {' / '.join(_f(x, 0) for x in it['spill_mb'])} "
                f"| {' / '.join(_f(x, 0) for x in it['others'])} ({' / '.join(_f(x, 0) for x in it['pre_idle'])}) "
                f"| {flag} |")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", type=Path, default=REPO / "reports" / "perf" / "round0")
    ap.add_argument("--series", action="append", required=True, help="name=slice1,slice2,...")
    ap.add_argument("--md", type=Path, default=None)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--min-wall", type=float, default=1.0, help="hide items below this wall in every slice")
    a = ap.parse_args(argv)
    fits = {}
    for s in a.series:
        name, _, lst = s.partition("=")
        fits[name] = fit_series(a.dir, [x for x in lst.split(",") if x])
    md = markdown(fits, a.min_wall)
    if a.md:
        a.md.write_text(md, encoding="utf-8")
    if a.json:
        a.json.write_text(json.dumps(fits, indent=1), encoding="utf-8")
    print(md)   # noqa: T201 (CLI)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
