"""Summarize a coverage.py JSON report (branch mode) for the QA coverage track.

Usage:
    python tools/qa/cov_summary.py data/tmp/qa_cov/before.json [--after data/tmp/qa_cov/after.json]
        [--critical] [--missing] [--md]

Prints per-module line % and branch % (branch % = covered_branches / num_branches; a module without branches
prints '-'). --critical restricts to the QA critical-module list; --missing lists uncovered branch arcs
(from_line -> to_line, negative to_line = function exit) per critical module; --md emits a markdown table.
Read-only: never writes anything.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

CRITICAL = ("ingest_sql.py", "ingest.py", "telemetry.py", "detect.py", "detect_sql.py", "detect_templates.py",
            "detect_templates2.py", "detect_templates3.py", "detect_templates_net.py", "sigma_compile.py",
            "sigma_rules.py", "sigma_detect.py", "episodes.py", "link.py", "paths.py", "incidents.py",
            "incident_gate.py", "reach.py", "publish.py", "api_upload.py", "api_runs.py")


def load(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}
    for fname, rec in data["files"].items():
        out[Path(fname).name if "attacklens" in Path(fname).parts[-2:-1] else Path(fname).as_posix()] = rec
    return out


def pct(rec: dict[str, Any]) -> tuple[float, float | None, int, int, int, int]:
    s = rec["summary"]
    stm, cov = s["num_statements"], s["covered_lines"]
    nb, cb = s.get("num_branches", 0), s.get("covered_branches", 0)
    line = 100.0 * cov / stm if stm else 100.0
    br = 100.0 * cb / nb if nb else None
    return line, br, stm, cov, nb, cb


def fmt(x: float | None) -> str:
    return "-" if x is None else f"{x:.1f}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("before", type=Path)
    ap.add_argument("--after", type=Path)
    ap.add_argument("--critical", action="store_true")
    ap.add_argument("--missing", action="store_true")
    ap.add_argument("--md", action="store_true")
    a = ap.parse_args(argv)
    b = load(a.before)
    af = load(a.after) if a.after else {}
    names = sorted(n for n in b if (not a.critical or n in CRITICAL))
    if a.md:
        hdr = "| module | stmts | line % | branches | branch %" + (" | line % after | branch % after |" if af else " |")
        print(hdr)
        print("|---" * (hdr.count("|") - 1) + "|")
    for n in names:
        line, br, stm, _, nb, _ = pct(b[n])
        row = [n, str(stm), fmt(line), str(nb), fmt(br)]
        if af:
            l2, b2, *_ = pct(af[n]) if n in af else (None, None)
            row += [fmt(l2), fmt(b2)]
        print(("| " + " | ".join(row) + " |") if a.md else "  ".join(f"{c:>22}" if i == 0 else f"{c:>8}"
                                                                      for i, c in enumerate(row)))
    tot = json.loads(a.before.read_text(encoding="utf-8"))["totals"]
    print(f"TOTAL before: line {tot['percent_covered']:.1f}% (combined line+branch), "
          f"statements {tot['covered_lines']}/{tot['num_statements']}, "
          f"branches {tot.get('covered_branches', 0)}/{tot.get('num_branches', 0)}")
    if a.after:
        t2 = json.loads(a.after.read_text(encoding="utf-8"))["totals"]
        print(f"TOTAL after:  line {t2['percent_covered']:.1f}% (combined line+branch), "
              f"statements {t2['covered_lines']}/{t2['num_statements']}, "
              f"branches {t2.get('covered_branches', 0)}/{t2.get('num_branches', 0)}")
    if a.missing:
        src = af or b
        for n in names:
            if n not in CRITICAL:
                continue
            mb = src[n].get("missing_branches") or []
            print(f"\n## {n}: {len(mb)} uncovered branch arcs; missing lines {len(src[n].get('missing_lines', []))}")
            print("   " + ", ".join(f"{x}->{y}" for x, y in mb))
    return 0


if __name__ == "__main__":
    sys.exit(main())
