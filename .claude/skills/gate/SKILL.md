---
name: gate
description: Check an AttackLens build gate (G1–G5 from docs/DEVELOPMENT.md §10) with measured evidence and report PASS/FAIL. Use only when the user or orchestrator asks to check a gate.
argument-hint: [G1|G2|G3|G4|G5]
disable-model-invocation: true
---
Check gate $0 from docs/DEVELOPMENT.md §10.

1. Run the fast suite: `.venv/Scripts/python -m pytest backend -q -m "not stress"`; paste the summary line.
2. Collect the evidence the gate requires from files, not memory:
   - G1: latest `data/out/*/ingest_accounting.json` (0 unexplained drops) and `backend/eval/test_probes.py` result.
   - G2: an `eval_scorecard.json` containing all four accuracy metrics on the dev set.
   - G3: the same file meets the PRD Good column (docs/PRD.md §4) on every metric.
   - G4: Great column on the dev set + `reports/stress/g10.md` (and the real 15 GB tier report if available) PASS,
     peak RSS < 8 GB, wall time < 1 h.
   - G5: clean-clone `docker compose up` works; README numbers equal the metric files; demo rehearsed.
3. Print a table: requirement | evidence (file + value) | PASS/FAIL.
4. Verdict. If FAIL: the failing requirement, the owning agent, and the smallest next action.
5. If PASS: tick the matching box in CLAUDE.md "Status" and suggest the commit message `gate $0: <summary>`.
