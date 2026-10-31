# AttackLens — Kill Chain & Attack Path Analysis (Mitigata CyberForge finals)

Offline hackathon, Bengaluru, **31 Oct 2026 10:00 → 1 Nov 2026**. Team of 2. Build + live demo.
Problem 01: stream 15–50 GB of security logs, detect the hidden attack, label every step with MITRE ATT&CK,
link the steps into one attack path, show a timeline + graph, and show what the attacker can reach next.

Read these before writing code — they are the source of truth, in this order:
1. `docs/PRD.md` — the organiser's requirements, targets and hackathon rules (scored against these).
2. `docs/DEVELOPMENT.md` — architecture, schemas, formulas, build order, agent roster, dos and don'ts.
3. `docs/TESTING.md` — test layers, data generation from `reports/edr_log_generator.py`, 10/30/50 GB stress tests.

## Status
- [ ] Phase 0: repo bootstrap (git, venv, folders) — see DEVELOPMENT.md §10
- [ ] Phase 1: Stage 0–1 ingest + accounting + eval harness + probes
- [ ] Phase 2: Stage 2 detection + Stage 2.5 episodes
- [ ] Phase 3: Stage 3 links + Stage 4 incidents/path/reach-next
- [ ] Phase 4: API + UI + narrative
- [ ] Phase 5: stress tests 10G → 30G → 50G (TESTING.md), live mode, Docker, README
Update this checklist when a phase's gate passes. Nothing else belongs in this section.

## Non-negotiable rules
- **Measure, never assert.** Every accuracy/time/RAM number shown anywhere comes from `data/out/eval_scorecard.json`
  or `data/out/run_metrics.json` of the run being shown.
- **No silent data loss.** Every ingest writes `ingest_accounting.json` (rows in / rows ok / dropped per source).
  A drop > 0.1 % without a logged reason is a bug.
- **The eval harness is never tuned to look better.** Tune rules and thresholds against it. Its probe tests
  (`backend/eval/test_probes.py`) must pass on every commit.
- **Detect from raw fields only.** Generator labels (`threat`, `rule`, `labels`, `labels_extra`, `event.kind`,
  `event.severity`) are ground truth. They are stripped before ingest and must never be read by detection code.
- **Bounded memory.** Never load all events into Python. DuckDB does ingest, detection and joins with
  `memory_limit='5GB'`; Python holds only episodes (≤ 25 000) and incidents.
- **UTC everywhere.** `SET TimeZone='UTC'` on every DuckDB connection. Never cast a timestamp to text and re-parse it.
- **Config, not code**, for rules, thresholds, field aliases and link windows (`config/*.yaml`).
- **LLM safety.** The narrative model sees placeholders (`{{HOST_1}}`) and enums only, never raw log text.
  No API key, any error, unknown token, or missing step → deterministic template. The demo never needs network.
- **Synthetic / provided data only.** No scanning or attacking real systems. No real credentials in the repo.
- **Disclose every third-party library, dataset and tool** in `README.md` (hackathon rule).

## Commands (Windows, Git Bash; PowerShell equivalents in DEVELOPMENT.md)
```
python -m venv .venv && .venv/Scripts/python -m pip install -e "backend[dev]"
.venv/Scripts/python -m pytest backend -q -m "not stress"            # fast tests, < 60 s
.venv/Scripts/python -m attacklens.run --raw data/raw/<set> --out data/out/<set> [--ground-truth ...]
.venv/Scripts/python tools/gen_dataset.py --size 1G --out data/raw/g1    # synthetic data (TESTING.md §3)
.venv/Scripts/python -m uvicorn attacklens.api:app --port 8000
cd frontend && npm run dev                                            # http://localhost:5173, /api -> :8000
```
Slash commands: `/gate <name>`, `/eval <set>`, `/gen-data <size>`, `/stress-test <size>`.

## Multi-agent workflow (details: DEVELOPMENT.md §9, TESTING.md §8)
The main session is the **orchestrator**: it plans, delegates, merges and runs gates. It does not write large code itself.
| Agent (`.claude/agents/`) | Owns (may edit) | Never edits |
|---|---|---|
| `backend-builder` | `backend/attacklens/**`, `config/**`, `backend/pyproject.toml` | `frontend/**`, `backend/eval/**`, `docs/**` |
| `frontend-builder` | `frontend/**` | `backend/**`, `config/**` |
| `test-engineer` | `backend/tests/**`, `backend/eval/**`, `tools/**` | product code |
| `stress-tester` | `data/**`, `reports/stress/**` (reports only) | any code |
| `code-reviewer` | nothing (read-only, reports findings) | everything |
| `doc-writer` | `README.md`, `docs/**` (except PRD.md), slides notes | code |
Rules: one owner per file; run builders in parallel only on disjoint folders; after each delegation the
orchestrator runs the fast tests and the relevant gate before delegating the next step; agents report
**what changed, test output, open issues** — never "done" without test output.

## Contract
`backend/attacklens/models.py` (Pydantic) and `frontend/src/types.ts` + `frontend/src/mock/incident.json`
describe the same `Incident` JSON. Change them together, in one delegation, with a test.

## Conventions
- Python 3.12, type hints, small modules (< 400 lines), no global mutable state, `logging` not `print`.
- Entity strings are `type:value` (`host:ws-fin-010`, `user:svc_backup`, `ip:203.0.113.57`), lower-case, normalized.
- ATT&CK v20 tactic order (15 tactics, Defense Evasion split into Stealth TA0005 + Defense Impairment TA0112).
- User prefers short, simple bullet-point explanations with examples.
- Commit after every passed gate: `git add -A && git commit -m "<phase>: <what>"`.
