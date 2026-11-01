"""Render data/tmp/qa_mut/results.json (tools/qa/mutate.py) as Markdown tables for reports/qa/qa_mutation.md.

Usage: .venv/Scripts/python tools/qa/mutate_report.py [--results data/tmp/qa_mut/results.json] [--json]

Final class per mutant, existing suite (no QA tests):
  killed      plain run failed a test, or (plain run hit the cap) a +focus run of existing suite tests failed
  survived    plain run passed every test of the module's test files
  equivalent  listed in mutants.EQUIVALENT (proved by reading the code); excluded from the score
  unresolved  plain run hit the cap and no +focus run killed it (a focus pass proves nothing)
With QA tests: killed if the existing suite killed it or a +qa run (backend/tests/qa/test_qa_mutants.py) did.
score = killed / (killed + survived + unresolved); equivalents and errors are excluded. Unresolved mutants count
against the score, so a contended machine can only make it look worse, never better.
Only ids, operators, module-code snippets and counts are printed (no log data).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from mutants import EQUIVALENT, MUTANTS  # noqa: E402

REPO = HERE.parents[1]


def _cell(s: str, n: int = 60) -> str:
    s = s.replace("\n", "\\n").replace("|", "\\|").strip()
    return "`" + (s if len(s) <= n else s[: n - 1] + "...") + "`" if s else "(removed)"


def classify(results: dict[str, Any], mid: str) -> tuple[str, str, str]:
    """(final existing-suite class, with-QA class, evidence)."""
    plain = results.get(mid) or {"result": "not_run", "detail": ""}
    focus = results.get(mid + "+focus") or {}
    qa = results.get(mid + "+qa") or {}
    if mid in EQUIVALENT:
        return "equivalent", "equivalent", "equivalent: " + EQUIVALENT[mid]
    if plain["result"] == "killed":
        fin, ev = "killed", plain.get("detail", "")
    elif plain["result"] == "survived":
        fin, ev = "survived", plain.get("detail", "")
    elif plain["result"] == "timeout" and focus.get("result") == "killed":
        fin, ev = "killed", "focus: " + focus.get("detail", "")
    elif plain["result"] == "timeout":
        fin, ev = "unresolved", plain.get("detail", "") + (" ; focus passed" if focus else "")
    else:
        fin, ev = "error", plain.get("detail", "")
    withqa = "killed" if fin == "killed" or qa.get("result") == "killed" else fin
    if withqa == "killed" and fin != "killed":
        ev += " ; QA: " + qa.get("detail", "")
    return fin, withqa, ev


def summary(results: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for m in MUTANTS:
        fin, wq, _ = classify(results, m["id"])
        s = out.setdefault(m["module"], {"mutants": 0, "killed": 0, "survived": 0, "unresolved": 0, "equivalent": 0,
                                         "error": 0, "killed_with_qa": 0, "survived_with_qa": 0,
                                         "unresolved_with_qa": 0})
        s["mutants"] += 1
        s[fin if fin in s else "error"] += 1
        if wq in ("killed", "survived", "unresolved"):
            s[f"{wq}_with_qa"] += 1
    tot: dict[str, Any] = {}
    for s in out.values():
        for k, v in s.items():
            tot[k] = tot.get(k, 0) + v
    out["total"] = tot
    for s in out.values():
        v = s["killed"] + s["survived"] + s["unresolved"]
        vq = s["killed_with_qa"] + s["survived_with_qa"] + s["unresolved_with_qa"]
        s["score_pct"] = round(100 * s["killed"] / v, 1) if v else None
        s["score_with_qa_pct"] = round(100 * s["killed_with_qa"] / vq, 1) if vq else None
    return out


def tables(results: dict[str, Any]) -> str:
    sm = summary(results)
    lines = ["| module | mutants | killed | survived | unresolved (cap) | equivalent | error | score | "
             "killed with QA tests | score with QA |", "|---|---|---|---|---|---|---|---|---|---|"]
    for mod, s in sm.items():
        b = "**" if mod == "total" else ""
        lines.append(f"| {b}{mod}{b} | {s['mutants']} | {s['killed']} | {s['survived']} | {s['unresolved']} | "
                     f"{s['equivalent']} | {s['error']} | {b}{s['score_pct']} %{b} | {s['killed_with_qa']} | "
                     f"{b}{s['score_with_qa_pct']} %{b} |")
    lines += ["", "| id | op | mutation (old -> new) | intent | existing suite | with QA | evidence |",
              "|---|---|---|---|---|---|---|"]
    for m in MUTANTS:
        fin, wq, ev = classify(results, m["id"])
        lines.append(f"| {m['id']} | {m['op']} | {_cell(m['old'], 44)} -> {_cell(m['new'], 44)} | {m['why']} | "
                     f"{fin} | {wq} | {_cell(ev.replace('tests/', ''), 90)} |")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(REPO / "data" / "tmp" / "qa_mut" / "results.json"))
    ap.add_argument("--json", action="store_true", help="print the per-module summary as JSON")
    a = ap.parse_args()
    res = json.loads(Path(a.results).read_text(encoding="utf-8"))
    print(json.dumps(summary(res), indent=1) if a.json else tables(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
