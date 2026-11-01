"""Summarise data/live/results/{vendors,checks}.jsonl (written by backend/tests/live) as Markdown tables.

    .venv/Scripts/python tools/live/report.py            # prints the tables to paste into reports/integrations/live.md
Only the LAST run per vendor / test is shown (rows are appended per run).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[2] / "data" / "live" / "results"


def _rows(name: str) -> list[dict]:
    p = RESULTS / f"{name}.jsonl"
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()] if p.exists() else []


def main() -> int:
    vendors = {r["vendor"]: r for r in _rows("vendors")}
    print("| vendor | status | image | digest | pull s | start s | setup s | seed s |")
    print("|---|---|---|---|---|---|---|---|")
    for v, r in vendors.items():
        print(f"| {v} | {r.get('status')} | {r.get('image', '')} | {r.get('digest') or r.get('reason', '')} | "
              f"{r.get('pull_s', '')} | {r.get('start_s', '')} | {r.get('setup_s', '')} | {r.get('seed_s', '')} |")
    checks = {(r["module"], r["test"]): r for r in _rows("checks")}
    print("\n| module | check | result | s | details |")
    print("|---|---|---|---|---|")
    for (mod, test), r in checks.items():
        det = ", ".join(f"{k}={v}" for k, v in (r.get("props") or {}).items())
        if r["outcome"] != "passed":
            det = (det + " | " if det else "") + r.get("message", "")
        print(f"| {mod.rsplit('.', 1)[-1]} | {test} | {r['outcome']} | {r['duration_s']} | {det[:400]} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
