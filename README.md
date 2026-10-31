# AttackLens — Kill Chain and Attack Path Analysis

Mitigata CyberForge finals, Problem 01. Team of 2.

AttackLens reads a large security-log data set (15–50 GB) as a stream, detects suspicious events, labels each one
with a MITRE ATT&CK technique and kill-chain stage, and links the steps into one evidence-linked attack path per
incident. For each incident it shows a timeline, a host/user graph, a risk score, how many raw alerts were merged,
and which hosts the attacker could reach next. Heavy work runs in DuckDB (bounded memory). The API serves
precomputed JSON. The UI is React with Cytoscape.js. Nothing needs the network.

| Requirement | Where in the product |
|---|---|
| FR-1 Read all data without loading it into memory | Stage 1 ingest: one DuckDB `COPY` to Parquet, `memory_limit='5GB'`; peak RSS in `run_metrics.json` |
| FR-2 Detect suspicious events | Stage 2: every rule in `config/rules.yaml` is one SQL query |
| FR-3 ATT&CK technique + kill-chain stage | Each alert and step carries `technique_id` and `tactic` (ATT&CK v20); badges in the UI |
| FR-4 Link events into one incident | Stage 3 link (4 keyed joins on host, user, IP, time) + Stage 4 components |
| FR-5 Timeline and graph | Incident screen: ordered steps, kill-chain bar, Cytoscape graph; `GET /api/incidents/{id}/path` |
| FR-6 What the attacker can reach next | Stage 4 reach-next (BFS ≤ 3 hops over admin/group/flow edges); "Reach next" list with evidence |
| FR-7 API or page + short README | FastAPI (table below) + web UI + this README |
| B-1 Risk score, worst on top | `risk` 0–100 per incident; list sorted by risk |
| B-2 Plain-English incident report | Narrative panel, with a `llm` or `template` source badge |
| B-3 Alerts merged per incident | `merged_alert_count` ("312 alerts → 1 incident") |
| B-4 Add a rule by editing config | `config/rules.yaml` (see below), optional `config/sigma/*.yml` |
| B-5 Live mode | `live.py` tails `data/raw/live/` in 2 s micro-batches; `GET /api/live/status` |

Status of items marked "coming" below is tracked in `CLAUDE.md`. Anything not built yet is labelled.

## 1. Prerequisites

| Tool | Version |
|---|---|
| Python | 3.12 |
| Node.js | 20 or newer (with npm) |
| Disk | about 2.5x the raw data size free (Parquet plus spill) |
| RAM | 16 GB recommended; the pipeline caps DuckDB at 5 GB |
| Docker (optional) | Docker Desktop / Engine with Compose v2 |

## 2. Quick start

### 2.1 Install

Windows, Git Bash:
```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e "backend[dev]"
```
Windows, PowerShell:
```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e "backend[dev]"
```
Linux / macOS:
```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e "backend[dev]"
```
Below, `PY` means `.venv/Scripts/python` (Windows) or `.venv/bin/python` (Linux/macOS).

### 2.2 Get data

Option A: your own data folder. Put the log files (JSON lines / ECS, CSV, syslog, CEF) in `data/raw/<set>/`.
Formats are detected by content, not by file name. Any path containing `ground_truth`, `manifest.json` and `*.md`
files are skipped.

Option B: synthetic data with planted attacks (wraps the provided `reports/edr_log_generator.py`):
```bash
PY tools/gen_dataset.py --size 1G --out data/raw/g1
```
Sizes accept `K/M/G`. Same seed gives the same attacks at every size. Full options: `docs/TESTING.md` §3.1.

### 2.3 Run the pipeline

```bash
PY -m attacklens.run --raw data/raw/g1 --out data/out/g1 \
   --ground-truth data/raw/g1/ground_truth/attacks.json
```
`--ground-truth` is optional. Without it the run skips the accuracy scorecard. Other flags: `--parquet <dir>`
(default `data/parquet/<out basename>`), `--from-stage N` (re-run from a stage on existing Parquet).

To point it at your own folder: `--raw <your folder> --out data/out/<name>`.

Where results appear:

| File | Content |
|---|---|
| `data/out/<set>/incidents/{id}.json` | one incident: backbone, branches, edges, graph, reach-next, narrative |
| `data/out/<set>/incidents_index.json` | list of incidents, risk descending |
| `data/out/<set>/ingest_accounting.json` | rows in / ok / dropped per source |
| `data/out/<set>/run_metrics.json` | per-stage wall time, peak RSS, rows/s |
| `data/out/<set>/eval_scorecard.json` | accuracy vs ground truth (only with `--ground-truth`) |
| `data/out/<set>/suppressed.json` | components removed by the gate or allowlist |

### 2.4 Start the API

From the repo root:
```bash
ATTACKLENS_OUT=data/out/g1 PY -m uvicorn attacklens.api:app --port 8000
```
PowerShell:
```powershell
$env:ATTACKLENS_OUT="data/out/g1"; .\.venv\Scripts\python -m uvicorn attacklens.api:app --port 8000
```
Check: `http://localhost:8000/api/health`.

### 2.5 Start the UI

```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:5173. Requests to `/api` are proxied to port 8000.

Mock mode (no backend, reads `frontend/src/mock/incident.json`):
```bash
VITE_USE_MOCK=true npm run dev
```
PowerShell: `$env:VITE_USE_MOCK="true"; npm run dev`

### 2.6 Docker Compose

```bash
docker compose up
```
Coming in W5. Not available yet. Use the native steps above.

### 2.7 Tests

```bash
PY -m pytest backend -q -m "not stress"
```
The probe tests in `backend/eval/test_probes.py` check that the evaluation harness is not generous. They must pass.

## 3. Architecture

```
data/raw/<set>/*            (JSON lines / ECS, CSV, syslog, CEF)
   |
   v Stage 0  profile.py     sniff format by content, resolve field aliases -> source_profile.json
   v Stage 1  ingest.py      ONE DuckDB COPY -> data/parquet/<set>/events/source_type=*/ts_ok=*/event_day=*/
   |                         + ingest_accounting.json (rows in / ok / dropped per source)
   v Stage 1b lookups.py     host_ip_map, background_hubs, rule_host_baseline (small Parquet tables)
   v Stage 2  detect.py      every rule = one SQL query over events -> raw_alerts.parquet
   v Stage 2.5 episodes.py   5-min episodes, IP->host resolution, merged_alert_count, seed-safe 25K cap
   v Stage 3  link.py        4 keyed DuckDB joins (R1-R4) -> edges.parquet with weight + why_linked
   v Stage 4  incidents.py   components -> gate -> risk -> host-monotonic path DP -> reach-next BFS
   v Stage 5  publish.py     data/out/<set>/incidents/{id}.json, incidents_index.json, narrative
   |
   +-- eval/harness.py       (if ground truth given) -> eval_scorecard.json
   +-- telemetry.py          RSS sampled every 500 ms from process start -> run_metrics.json
API (FastAPI) serves precomputed JSON from memory; UI (React + Vite + Cytoscape.js) renders it.
Live mode (B-5) tails a folder in 2 s micro-batches and re-runs Stages 1-5 on the delta window.
```

| Stage | What it does |
|---|---|
| 0 profile | Detects each file's format from its content and resolves field names via `config/sources.yaml` |
| 1 ingest | Streams all sources into partitioned Parquet in one pass; counts rows in, ok, dropped |
| 1b lookups | Builds the IP-to-host map, high-fan-out "hub" list and per-rule host baselines |
| 2 detect | Runs each rule as SQL; each hit is an alert with technique, tactic, severity |
| 2.5 episodes | Groups alerts into 5-minute episodes per entity; counts merged alerts |
| 3 link | Joins episodes on shared host, user, IP within time windows; stores why each link exists |
| 4 incidents | Connected components, confidence gate, risk score, best ordered path, reach-next |
| 5 publish | Writes incident JSON and the narrative |

Correlation is evidence-linked, not causal. Two steps are linked when they share entities inside a time window.
AttackLens does not claim that one step caused the next.

Design rules:
- DuckDB does all heavy work and spills to disk. Python never iterates over raw events.
- Every stage reads and writes files, so any stage can be re-run alone.
- Ingest once per data set. Tuning detection re-runs Stage 2 onward in seconds.
- Detection uses raw fields only. Generator labels are ground truth and are stripped before ingest.
- All times are UTC.

## 4. API

Base URL `http://localhost:8000`. All reads come from memory.

| Method and path | Returns |
|---|---|
| `GET /api/health` | liveness |
| `GET /api/incidents` | incident index, risk descending |
| `GET /api/incidents/{id}` | full incident JSON |
| `GET /api/incidents/{id}/path` | backbone, branches and edges only (FR-5, FR-7) |
| `GET /api/metrics` | `run_metrics` + `eval_scorecard` + `ingest_accounting` |
| `POST /api/runs` body `{raw_dir, ground_truth?}` | starts a background pipeline run |
| `GET /api/runs/{id}` | stage, percent, elapsed, RSS |
| `GET /api/live/status` | live-mode state |

Example: `curl http://localhost:8000/api/incidents/inc-3f2a9c1e/path`

## 5. Results

<!-- numbers must be copied from metric files only. Do not type a number here by hand. -->
<!-- Fill each cell from the named file of the run you show, and note the git commit. -->

Run shown: `TBD (data set name)` — commit `TBD` — machine `TBD`.

### 5.1 Accuracy vs PRD targets

| Measure | PRD good / great | Result |
|---|---|---|
| Detection (planted steps found) | > 70 % / > 90 % | TBD (from data/out/<set>/eval_scorecard.json) |
| Correct labels | > 60 % / > 85 % | TBD (from data/out/<set>/eval_scorecard.json) |
| Attack path (attacks rebuilt) | half / all | TBD (from data/out/<set>/eval_scorecard.json) |
| False alarms, strict | < 30 % / < 10 % | TBD (from data/out/<set>/eval_scorecard.json) |
| False alarms, lenient | (same targets) | TBD (from data/out/<set>/eval_scorecard.json) |
| Singleton recall | n/a | TBD (from data/out/<set>/eval_scorecard.json) |

### 5.2 Speed and memory vs PRD targets

| Measure | PRD good / great | Result |
|---|---|---|
| Processing time, full tier | < 3 h / < 1 h | TBD (from data/out/<set>/run_metrics.json) |
| Peak memory | < 16 GB / < 8 GB | TBD (from data/out/<set>/run_metrics.json) |
| Open one incident's path | < 2 s / < 500 ms | TBD (from reports/stress/<set>.md, path API latency) |

### 5.3 Scale

| Set | Raw size | Wall time | Peak RSS | Detection | Rebuilt | Strict FA |
|---|---|---|---|---|---|---|
| g1 | TBD | TBD (run_metrics.json) | TBD (run_metrics.json) | TBD (eval_scorecard.json) | TBD (eval_scorecard.json) | TBD (eval_scorecard.json) |
| g10 | TBD | TBD | TBD | TBD | TBD | TBD |
| g30 | TBD | TBD | TBD | TBD | TBD | TBD |
| g50 | TBD | TBD | TBD | TBD | TBD | TBD |
| Organiser tier (real) | TBD | TBD | TBD | TBD | TBD | TBD |

### 5.4 Ingest accounting

| Source | Rows in | Rows ok | Dropped | Reason |
|---|---|---|---|---|
| TBD (from data/out/<set>/ingest_accounting.json) | TBD | TBD | TBD | TBD |

## 6. Add a detection rule (B-4)

Edit `config/rules.yaml`. No code change. Restart the run from Stage 2:
```bash
PY -m attacklens.run --raw data/raw/g1 --out data/out/g1 --from-stage 2
```
Example, a `match` rule. `where` is a SQL predicate over canonical event columns:
```yaml
rules:
  - id: office_spawns_script
    kind: match                       # match | template | sigma
    where: "action='proc_start' AND parent_process IN ('winword.exe','excel.exe','outlook.exe')
            AND process_name IN ('powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe')"
    technique: T1059.001
    tactic: Execution
    severity: 80
```
Rules:
- `technique` must exist in `config/attack_v20.json`. A test fails otherwise.
- `severity` is 1–100. Confidence = severity scaled by how rare the rule is on that host.
- `kind: template` rules (for example `brute_force_then_success`) use thresholds from the `thresholds:` block.
- Optional: drop Sigma rules into `config/sigma/*.yml` (needs `pysigma`).
- Rules come from trusted config. Do not load rule files from untrusted sources.

## 7. LLM safety

- The narrative model sees placeholders (`{{HOST_1}}`, `{{USER_1}}`) and enums (technique, tactic), never raw log text.
- No API key, any error, an unknown token in the output, or a missing step: the deterministic template is used.
- The template is the default. The demo needs no network and no key.
- The UI shows a `llm` or `template` badge on every narrative.
- Log content is never rendered as HTML in the UI.

## 8. Data handling

- Synthetic or organiser-provided data only. AttackLens does not scan or attack any system.
- No real credentials are in the repo.
- Organiser-provided data sets are confidential. They are used only for this hackathon and are not published.
  `data/` is git-ignored.

## 9. Disclosures (third-party components)

Libraries and data used. Licenses as published by each project.

| Component | License | Use |
|---|---|---|
| DuckDB | MIT | ingest, detection, joins |
| NetworkX | BSD-3-Clause | graph helpers |
| FastAPI | MIT | API |
| Uvicorn | BSD-3-Clause | API server |
| Pydantic | MIT | incident contract |
| PyYAML | MIT | config loading |
| psutil | BSD-3-Clause | memory telemetry |
| Jinja2 | BSD-3-Clause | template narrative |
| Anthropic SDK | MIT | optional narrative wording; off without a key |
| pySigma | LGPL-2.1 | optional Sigma rule compile, unmodified |
| Sigma rules | Detection Rule License (DRL) 1.1 | rule ideas, attribution kept |
| MITRE ATT&CK v20 | MITRE Terms of Use | technique and tactic names and order |
| mitreattack-python | Apache-2.0 | generate `config/attack_v20.json` |
| React | MIT | UI |
| Vite | MIT | UI build and dev server |
| Tailwind CSS | MIT | UI styling |
| Cytoscape.js | MIT | graph rendering |
| cytoscape-dagre | MIT | left-to-right graph layout |
| pytest | MIT | tests |
| `reports/edr_log_generator.py` | organiser/team-provided test-data tool | synthetic log generation; wrapped by `tools/gen_dataset.py`, not edited |

<!-- Before release: compare this table with backend/pyproject.toml and frontend/package.json and add anything new. -->

AI tools: Claude Code (Anthropic) was used for development, including code, tests and documentation.

Ideas only (no code copied) from: Zircolite, Chainsaw, Hayabusa, Elastic detection-rules, BloodHound, and the
RapSheet, HOLMES, NoDoze, Hopper and SAGE papers.

## 10. More documents

| File | Content |
|---|---|
| `docs/PRD.md` | organiser's requirements |
| `docs/DEVELOPMENT.md` | architecture, schemas, formulas |
| `docs/TESTING.md` | tests, data generation, stress tests |
| `docs/DEMO.md` | 5-minute live demo script |
| `reports/stress/` | stress-test reports per data size |
