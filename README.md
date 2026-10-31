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
| FR-2 Detect suspicious events | Stage 3 detect: every rule in `config/rules.yaml` is one SQL query |
| FR-3 ATT&CK technique + kill-chain stage | Each alert and step carries `technique_id` and `tactic` (ATT&CK v20); badges in the UI |
| FR-4 Link events into one incident | Stage 5 link (keyed joins on host, user, IP, time) + Stage 6 components |
| FR-5 Timeline and graph | Incident screen: ordered steps, kill-chain bar, Cytoscape graph; `GET /api/incidents/{id}/path` |
| FR-6 What the attacker can reach next | Stage 6 reach-next (BFS ≤ 3 hops over admin/group/flow edges); "Reach next" list with evidence |
| FR-7 API or page + short README | FastAPI (table below) + web UI + this README |
| B-1 Risk score, worst on top | `risk` 0–100 per incident; list sorted by risk |
| B-2 Plain-English incident report | Narrative panel, with a `llm` or `template` source badge |
| B-3 Alerts merged per incident | `merged_alert_count` ("312 alerts → 1 incident") |
| B-4 Add a rule by editing config | `config/rules.yaml` (see section 8), optional `config/sigma/*.yml` |
| B-5 Live mode | `python -m attacklens.live --watch data/raw/live --out data/out/live`; `GET /api/live/status` |

Phase status is tracked in `CLAUDE.md`. Anything not finished is labelled in this file.

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
The optional LLM narrative needs `pip install -e "backend[llm]"`. It is not needed for the demo.

### 2.2 Get data

Option A: your own data folder. Put the log files in `data/raw/<set>/`. Formats are listed in section 3 and are
detected by content, not by file name.

Option B: synthetic data with planted attacks (wraps the provided `reports/edr_log_generator.py`):
```bash
PY tools/gen_dataset.py --size 1G --out data/raw/g1
```
Sizes accept `K/M/G`. The same seed gives the same attacks at every size. Full options: `docs/TESTING.md` §3.1.

### 2.3 Run the pipeline

```bash
PY -m attacklens.run --raw data/raw/g1 --out data/out/g1 \
   --ground-truth data/raw/g1/ground_truth/attacks.json
```
`--ground-truth` is optional. Without it the run skips the accuracy scorecard. Other flags: `--parquet <dir>`
(default `data/parquet/<out basename>`), `--from-stage N` (re-run from a stage on existing Parquet).

To point it at your own folder: `--raw <your folder> --out data/out/<name>`.

Stage numbers for `--from-stage`:

| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|
| profile | ingest | lookups | detect | episodes | link | incidents | publish |

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
`ATTACKLENS_OUT` is the data directory the API serves. If unset, the API uses the most recently modified
`data/out/<set>` that contains an `incidents_index.json`. Check: `http://localhost:8000/api/health`.

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

### 2.6 Live mode (B-5)

```bash
PY -m attacklens.live --watch data/raw/live --out data/out/live [--reset]
ATTACKLENS_OUT=data/out/live PY -m uvicorn attacklens.api:app --port 8000
```
Append log lines to files in `data/raw/live/`. The watcher tails by byte offset in 2 s micro-batches and updates the
incidents under `data/out/live`. Live-update latency: not measured yet.

### 2.7 Docker Compose

```bash
docker compose up
```
`Dockerfile` and `docker-compose.yml` exist. Being verified. Until the verification is recorded, use the native steps.

### 2.8 Tests

```bash
PY -m pytest backend -q -m "not stress"
```
The probe tests in `backend/eval/test_probes.py` check that the evaluation harness is not generous. They must pass.

## 3. Data formats

Ingest routes each file by content. File extensions are not used. Paths containing `ground_truth`,
`manifest.json` and `*.md` files are skipped.

| Format | `source_type` | Note |
|---|---|---|
| ECS JSON lines | `ecs_json` | the provided generator's format; used for the synthetic sets |
| Windows EVTX exported as JSON | see `source_profile.json` | flat or nested `Event.System` / `Event.EventData` |
| Firewall CSV | `firewall_csv` | |
| Syslog (RFC 3164 / ISO-prefixed) | see `source_profile.json` | |
| CEF | see `source_profile.json` | extension keys only; the header name is not read |
| FortiGate key=value | `fortigate_kv` | the official tier format (50 GB sample, 10G and 30G logs) |

Field aliases per format live in `config/sources.yaml`. Stage 0 writes `source_profile.json` with what it found.

Ingest accounting: every run writes `ingest_accounting.json` with rows in, rows ok, dropped, drop reasons and
quarantined rows per source. A drop above 0.1 % without a logged reason is treated as a bug. Example (g1x):

| Source | Rows in | Rows ok | Dropped |
|---|---|---|---|
| ecs_json | 1305412 | 1305412 | 0 |

Source: `data/out/g1x/ingest_accounting.json`.

FortiGate note: one device logs everything, so the host is the device name and internal endpoints are identified
by IP. Details: `docs/DEVELOPMENT.md` §15.9.

## 4. Architecture

```
data/raw/<set>/*            (ECS JSON, EVTX JSON, CSV, syslog, CEF, FortiGate key=value)
   |
   v Stage 0  profile.py     sniff format by content, resolve field aliases -> source_profile.json
   v Stage 1  ingest.py      ONE DuckDB COPY -> data/parquet/<set>/events/source_type=*/ts_ok=*/event_day=*/
   |                         + ingest_accounting.json (rows in / ok / dropped per source)
   v Stage 2  lookups.py     host_ip_map, background_hubs, rule_host_baseline (small Parquet tables)
   v Stage 3  detect.py      every rule = one SQL query over events -> raw_alerts.parquet
   v Stage 4  episodes.py    5-min episodes, IP->host resolution, merged_alert_count, seed-safe 25K cap
   v Stage 5  link.py        keyed DuckDB joins (R1-R4) -> edges.parquet with weight + why_linked
   v Stage 6  incidents.py   components -> gate -> risk -> host-monotonic path DP -> reach-next BFS
   v Stage 7  publish.py     data/out/<set>/incidents/{id}.json, incidents_index.json, narrative
   |
   +-- eval/harness.py       (if ground truth given) -> eval_scorecard.json
   +-- telemetry.py          RSS sampled every 500 ms from process start -> run_metrics.json
API (FastAPI) serves precomputed JSON from memory; UI (React + Vite + Cytoscape.js) renders it.
Live mode (B-5) tails a folder in 2 s micro-batches and re-runs the detect-onward stages on the delta window.
```

| Stage | What it does |
|---|---|
| 0 profile | Detects each file's format from its content and resolves field names via `config/sources.yaml` |
| 1 ingest | Streams all sources into partitioned Parquet in one pass; counts rows in, ok, dropped |
| 2 lookups | Builds the IP-to-host map, high-fan-out "hub" list and per-rule host baselines |
| 3 detect | Runs each rule as SQL; each hit is an alert with technique, tactic, severity |
| 4 episodes | Groups alerts into 5-minute episodes per entity; counts merged alerts |
| 5 link | Joins episodes on shared host, user, IP within time windows; stores why each link exists |
| 6 incidents | Connected components, confidence gate, risk score, best ordered path, reach-next |
| 7 publish | Writes incident JSON and the narrative |

Correlation is evidence-linked, not causal. Two steps are linked when they share entities inside a time window.
AttackLens does not claim that one step caused the next.

Design rules:
- DuckDB does all heavy work and spills to disk. Python never iterates over raw events.
- Every stage reads and writes files, so any stage can be re-run alone.
- Ingest once per data set. Tuning detection re-runs from Stage 2 in seconds.
- Detection uses raw fields only. Generator labels are ground truth and are stripped before ingest.
- All times are UTC.

## 5. Design decisions (deviations from the written spec)

Each one is switchable in config. Source: `docs/DEVELOPMENT.md` §15.7.

- **Path order rule.** Initial Access, Credential Access and Lateral Movement do not raise the per-host tactic floor.
  Real attacks run Credential Access (9) then Initial Access (3), and Lateral Movement (11) then Execution (4). The
  literal rule makes that order impossible.
- **Linking rule R3.** The source step must be Credential Access, Persistence, Privilege Escalation or Initial Access
  with confidence ≥ 60, and the target user must match. Without this, 12 shared user names linked all the noise.
- **Gate.** Episodes with confidence < 40 join a component but do not count toward the tactic count. A single-tactic
  component passes the critical path only if its top episode merged at least 5 alerts. Both cut noise-only incidents.
- **Several incidents per component.** Incidents are peeled from large components, so one noise chain cannot hide a
  second attack. Branch tails that pass the gate alone become their own incident.
- **Hub and baseline thresholds.** `hub_min_median_daily_peers: 40` and `baseline_max_other_rules: 99`, chosen by a
  sweep on g1, because generator users touch all 28 hosts daily.
- **new_admin_logon.** Skipped for routine (user, host) pairs with at least 3 earlier non-privileged logons during
  08–19 UTC. This separates an admin-work decoy without using labels.
- **Source-host link window.** R1 source-host variant uses 6 h instead of 24 h.
- **Risk scale.** `raw_ref_score: 30.8` (S1's raw score on g1) instead of 15, because 15 saturated S1 and S4 at 100.
- **Tactic names.** ATT&CK v20 (15 tactics). Stealth and Defense Impairment replace Defense Evasion.
  The harness maps them back to Defense Evasion if the organiser's ground truth uses the old name.

## 6. Detection coverage

Generated from `config/rules.yaml`. One primary technique and tactic per rule.

| Rule id | Technique | Tactic | Signal |
|---|---|---|---|
| brute_force_then_success | T1110.001 (+ T1078 on success) | Credential Access | burst of failed logins per user and host, then a success |
| password_spray | T1110.003 (+ T1078) | Credential Access | one source IP failing for many users |
| account_created_then_elevated | T1136 (+ T1098) | Persistence | account created, then added to a group within 24 h |
| beaconing | T1071.001 | Command and Control | regular-interval connections to one destination |
| ransom_rename | T1486 | Impact | mass file renames in 60 s |
| exfil_volume | T1048 | Exfiltration | large outbound volume to an external IP in 15 min |
| new_admin_logon | T1021 (+ T1078) | Lateral Movement | rare privileged network logon for a user and host pair |
| office_spawns_script | T1059.001 | Execution | Office app starts a script engine |
| encoded_powershell | T1059.001 | Execution | encoded or hidden PowerShell, download cradle |
| run_key_persistence | T1547.001 | Persistence | Run registry key set by a script engine |
| ioc_destination | T1071.001 | Command and Control | destination IP or domain in `config/ioc.yaml` |
| ransom_extension | T1486 | Impact | file written or renamed with a ransom extension |
| discovery_commands | T1087.002 | Discovery | `net user`, `net group`, `nltest`, `get-aduser` |
| discovery_system | T1082 | Discovery | `whoami`, `systeminfo` |
| service_or_task | T1543.003 | Persistence | service installed or `sc create` |
| scheduled_task | T1053.005 | Persistence | scheduled task created |
| log_cleared | T1070.001 | Defense Impairment | event log cleared or `wevtutil cl` |
| archive_staging | T1560.001 | Collection | 7z, rar, zip, tar, Compress-Archive |
| suspicious_cmd | T1059.003 | Execution | cmd.exe under an unusual parent |
| wmi_exec | T1047 | Execution | WMI-spawned shell or `wmic process call create` |
| unix_reverse_shell | T1059.004 | Execution | `bash -i`, `/dev/tcp/`, curl or wget piped to sh |
| indicator_removal_files | T1070.004 | Defense Impairment | `rm -rf /var/log`, `del /f /q` |
| disable_security_tools | T1562.001 | Defense Impairment | `Set-MpPreference -Disable...` |
| sudo_escalation | T1548.003 | Privilege Escalation | sudo on a rare user and host pair |
| lsass_dump | T1003.001 | Credential Access | mimikatz, sekurlsa, procdump on lsass |
| kerberoasting | T1558.003 | Credential Access | many service tickets with RC4 for one account |
| pass_the_hash | T1550.002 | Lateral Movement | logon type 9 with NTLM/negotiate on a rare pair |
| fw_admin_bruteforce | T1110.001 (+ T1078) | Credential Access | firewall admin login failures from an external IP, then success |
| fw_admin_spray | T1110.003 (+ T1078) | Credential Access | one external IP failing for many firewall admin accounts |
| vpn_bruteforce_success | T1110.001 (+ T1133) | Credential Access | VPN failures then success for one user |
| ips_signatures | T1190, T1110, T1071, T1590.002, T1210 | Initial Access and others (per signature) | IPS signature mapped to a technique |
| av_malware_download | T1105 | Command and Control | antivirus alert on a transfer |
| port_scan | T1046 | Discovery | many ports on one host or many hosts on one port in 60 s |
| internal_lateral | T1021 | Lateral Movement | rare internal SMB/RDP/WinRM/SSH connection |
| fw_config_change_after_login | T1562.004 | Defense Impairment | firewall config change soon after an external login |
| tor_or_proxy_app | T1090.003 | Command and Control | anonymising proxy app seen by app control |
| web_malicious_category | T1189 | Initial Access | web filter blocked a malicious category |

## 7. Results

<!-- numbers must be copied from metric files only. Do not type a number here by hand. -->
<!-- Each number below names its source file. Metric files do not record a git commit; commit: not recorded. -->

How to read this section:
- **g1x** is the honest synthetic 1 GB set. The attacker IPs are not in the IOC list, so detection does not lean on a
  threat-intel hit. Lead with this one.
- **g1** is the first synthetic 1 GB set. Same planted attacks.
- Both have planted ground truth, so they have an accuracy score. Both are synthetic data from the provided generator.
- **The real FortiGate tiers have no ground truth.** For them we report time, memory, ingest accounting and the
  incidents found (reviewed by hand). We do not report an accuracy score for them.

### 7.1 Accuracy vs PRD targets (synthetic, with ground truth)

| Measure | PRD good / great | g1x | g1 |
|---|---|---|---|
| Detection (planted steps found) | > 70 % / > 90 % | 100.0 % | 100.0 % |
| Correct labels | > 60 % / > 85 % | 100.0 % | 100.0 % |
| Attack path (attacks rebuilt) | half / all | 100.0 % | 100.0 % |
| False alarms, strict | < 30 % / < 10 % | 0.0 % | 0.0 % |
| False alarms, lenient | (same targets) | 0.0 % | 0.0 % |
| Singleton recall | n/a | 100.0 % | 100.0 % |

Sources: `data/out/g1x/eval_scorecard.json` and `data/out/g1/eval_scorecard.json`
(`detection_pct`, `labels_pct`, `rebuilt_pct`, `false_alarms_strict_pct`, `false_alarms_lenient_pct`,
`singleton_recall_pct`).

Counts behind the percentages (same two files, `counts`):

| Count | g1x | g1 |
|---|---|---|
| Planted attacks | 5 | 5 |
| Planted steps | 21 | 21 |
| Steps matched | 21 | 21 |
| Incidents produced | 5 | 5 |
| Incidents not matched to a planted attack | 0 | 0 |
| Noise alerts detected / detectable | 494 / 494 | 494 / 494 |

Caution: these sets have 5 attacks and 21 steps. A score of 100 % on this small a set does not show the same score on
real data. Real-data accuracy: not measured (no ground truth).

### 7.2 Speed and memory vs PRD targets

| Measure | PRD good / great | g1x (1 GB) | g1 (1 GB) |
|---|---|---|---|
| Processing time | < 3 h / < 1 h (full tier) | 24.893 s | 39.223 s |
| Peak memory | < 16 GB / < 8 GB | 3249.9 MB | 3401.3 MB |
| Rows per second | n/a | 52440.9 | 33281.6 |
| Rows in | n/a | 1305412 | 1305403 |
| Episodes / incidents | n/a | 517 / 5 | 522 / 5 |
| Open one incident's path | < 2 s / < 500 ms | not measured yet | not measured yet |

Sources: `data/out/g1x/run_metrics.json` and `data/out/g1/run_metrics.json`
(`total_wall_s`, `peak_rss_mb`, `rows_per_s`, `rows_in`, `episodes`, `incidents`).
These are 1 GB runs. They say nothing yet about the 15 GB tier.

### 7.3 Scale

| Set | Raw size | Wall time | Peak RSS | Accuracy | Status |
|---|---|---|---|---|---|
| g1x | 1074061398 bytes (`data/out/g1x/run_metrics.json`) | 24.893 s | 3249.9 MB | see 7.1 | complete |
| g1 | 1074055241 bytes (`data/out/g1/run_metrics.json`) | 39.223 s | 3401.3 MB | see 7.1 | complete |
| g10 (synthetic, 10 GB) | 10737422333 bytes (`reports/stress/g10.md`) | not completed | 4922.5 MB at abort | none | FAILED: Stage 1 ingest out of memory at the 5 GB DuckDB limit, per `reports/stress/g10.md` (commit 3c1d175e2223584513815b94aadc1cff5d0c2ce3). TBD (run pending): re-run after the fix |
| g30 | TBD (run pending) | TBD (run pending) | TBD (run pending) | TBD (run pending) | blocked by g10 |
| g50 | TBD (run pending) | TBD (run pending) | TBD (run pending) | TBD (run pending) | blocked by g10 |
| Synthetic FortiGate set (with ground truth) | TBD (run pending) | TBD (run pending) | TBD (run pending) | TBD (run pending) | TBD (run pending) |
| Real FortiGate 10G tier (no ground truth) | TBD (run pending) | TBD (run pending) | TBD (run pending) | not scored (no ground truth) | TBD (run pending) |
| Real FortiGate 30G tier (no ground truth) | TBD (run pending) | TBD (run pending) | TBD (run pending) | not scored (no ground truth) | TBD (run pending) |
| Real FortiGate 50G tier (no ground truth) | TBD (run pending) | TBD (run pending) | TBD (run pending) | not scored (no ground truth) | TBD (run pending) |

The g10 row reflects the stress report as it stood when this table was written. Check `reports/stress/` for a newer one.

### 7.4 Real FortiGate tiers

No planted attacks, no score. For each real tier we will report:

| Item | Source |
|---|---|
| Wall time and peak RSS | TBD (run pending) (`data/out/<set>/run_metrics.json`) |
| Rows in / ok / dropped per source | TBD (run pending) (`data/out/<set>/ingest_accounting.json`) |
| Incidents found, with hand review notes | TBD (run pending) (`data/out/<set>/incidents_index.json`) |

## 8. Add a detection rule (B-4)

Edit `config/rules.yaml`. No code change. After editing, re-run from Stage 2 (lookups are cheap):
```bash
PY -m attacklens.run --raw data/raw/g1 --out data/out/g1 --from-stage 2
```
Example, a `match` rule. `where` is a SQL predicate over canonical event columns:
```yaml
rules:
  - id: office_spawns_script
    kind: match                       # match | template | sigma
    where: >-
      action = 'proc_start'
      AND lower(parent_process) IN ('winword.exe','excel.exe','outlook.exe')
      AND lower(process_name) IN ('powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe')
    technique: T1059
    sub_technique: T1059.001
    tactic: Execution
    severity: 80
```
Rules:
- `technique` must exist in `config/attack_v20.json` and `tactic` must be a v20 tactic name. A test fails otherwise.
- `severity` is 1–100. Confidence = severity scaled by how rare the rule is on that host.
- `where` can use `{ioc.ips}`, `{ioc.domains}` and other lists from `config/ioc.yaml`.
- `kind: template` rules (for example `brute_force_then_success`) use thresholds from the `thresholds:` block.
- Optional: drop Sigma rules into `config/sigma/*.yml` (needs `pysigma`).
- Rules come from trusted config. Do not load rule files from untrusted sources.

## 9. API

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

Example: `curl http://localhost:8000/api/incidents/inc-dfa2f6d9/path` (an S1 incident id from `data/out/g1x`;
ids differ per run, list them with `GET /api/incidents`).

## 10. LLM safety

- The narrative model sees placeholders (`{{HOST_1}}`, `{{USER_1}}`) and enums (technique, tactic), never raw log text.
- No API key, any error, an unknown token in the output, or a missing step: the deterministic template is used.
- The template is the default. The demo needs no network and no key.
- The UI shows a `llm` or `template` badge on every narrative.
- Log content is never rendered as HTML in the UI.

## 11. Data handling

- Synthetic or organiser-provided data only. AttackLens does not scan or attack any system.
- No real credentials are in the repo.
- Organiser-provided data sets (the FortiGate tiers) are confidential. They are used only for this hackathon, are not
  published, and are not copied into tests, fixtures or reports. `data/` is git-ignored.
- Accuracy for FortiGate logs is measured on synthetic data from `tools/fortigate_gen.py`. No real log lines are copied.

## 12. Disclosures (third-party components)

Checked against `backend/pyproject.toml`, `frontend/package.json`, `Dockerfile` and `docker-compose.yml`. Licenses as
published by each project.

### Python (backend)

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
| Anthropic SDK | MIT | optional (`backend[llm]`); narrative wording; off without a key |
| pySigma | LGPL-2.1 | optional Sigma rule compile, unmodified |
| mitreattack-python | Apache-2.0 | generate `config/attack_v20.json` |
| pytest | MIT | tests (dev) |
| httpx | BSD-3-Clause | API tests (dev) |

### JavaScript (frontend)

| Component | License | Use |
|---|---|---|
| React, React DOM | MIT | UI |
| Vite | MIT | build and dev server |
| @vitejs/plugin-react | MIT | React support in Vite |
| Tailwind CSS | MIT | styling |
| @tailwindcss/vite | MIT | Tailwind integration |
| Cytoscape.js | MIT | graph rendering |
| cytoscape-dagre | MIT | left-to-right graph layout |
| TypeScript | Apache-2.0 | type checking |
| oxlint | MIT | linting |
| @types/cytoscape, @types/cytoscape-dagre, @types/node, @types/react, @types/react-dom | MIT | type definitions (DefinitelyTyped) |

### Container images

| Image | Use |
|---|---|
| `python:3.12-slim` | backend container |
| `node:22-slim` | frontend container |

### Data, rules and tools

| Component | License / terms | Use |
|---|---|---|
| MITRE ATT&CK v20 | MITRE Terms of Use | technique and tactic names and order |
| Sigma rules | Detection Rule License (DRL) 1.1 | rule ideas, attribution kept |
| `reports/edr_log_generator.py` | organiser/team-provided test-data tool | synthetic log generation; wrapped by `tools/gen_dataset.py`, not edited |
| Organiser FortiGate log tiers | confidential, organiser-provided | hackathon use only; not published |

Licenses of the JavaScript packages and Docker base images are as listed by their projects. Verify against the
installed versions before release.

AI tools: Claude Code (Anthropic) was used for development, including code, tests and documentation.

Ideas only (no code copied) from: Zircolite, Chainsaw, Hayabusa, Elastic detection-rules, BloodHound, and the
RapSheet, HOLMES, NoDoze, Hopper and SAGE papers.

## 13. More documents

| File | Content |
|---|---|
| `docs/PRD.md` | organiser's requirements |
| `docs/DEVELOPMENT.md` | architecture, schemas, formulas |
| `docs/TESTING.md` | tests, data generation, stress tests |
| `docs/DEMO.md` | 5-minute live demo script |
| `reports/stress/` | stress-test reports per data size |
