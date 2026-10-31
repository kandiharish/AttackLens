---
name: stress-test
description: Run a full AttackLens stress test at a given size (generate, run, measure time, peak RAM, accuracy, API latency) via the stress-tester agent and write reports/stress/g<size>.md. Use only when explicitly asked.
argument-hint: [size: 1G | 10G | 30G | 50G | t15 | t30 | t50]
disable-model-invocation: true
---
Stress test `$0` following docs/TESTING.md §6.

1. Pre-checks yourself: fast suite green; if `$0` is 30G, `reports/stress/g10.md` must say PASS; if 50G, `g30.md`
   must say PASS. `t15/t30/t50` mean the organisers' real tiers in `data/raw/t15` etc. (no generation).
2. Delegate to the `stress-tester` agent with this prompt, filled in:
   ROLE: stress-tester · GOAL: stress test $0 per docs/TESTING.md §6.2 and write reports/stress/g$0.md ·
   OWNS: data/**, reports/stress/** · DO NOT TOUCH: code, config, tests ·
   ACCEPTANCE: report filled per §6.4, every number from metric files, verdict against §6.3.
3. When the report arrives, read `reports/stress/g$0.md` yourself and confirm the verdict against §6.3.
4. If FAIL: write the failing check as an issue for the owning builder (failing test first via test-engineer).
   If PASS: say which next size is allowed.
