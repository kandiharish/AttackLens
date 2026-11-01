# AttackLens — Kill Chain and Attack Path Analysis

Mitigata CyberForge finals, Problem 01. Team of 2.

## For judges: run it with Docker (3 commands)

You need **Docker Desktop** (Windows / macOS) or Docker Engine with the Compose plugin, about **8 GB RAM** free
and **3 GB** of disk. No Python, Node or internet access is needed after the image is built.

```bash
git clone https://github.com/kandiharish/AttackLens.git
cd AttackLens
docker compose up -d --build
```

Then open **http://localhost:8000**.

| What happens | Time on our laptop (i5-13420H, 16 GB, Windows 11) |
|---|---|
| Build the image (frontend + backend) | 2.4 min with some layers cached; longer on a first build, which downloads Node, Python and packages |
| First start: generate a 200 MB synthetic log set with planted attacks, then analyse it | about 11 min: the analysis took 650.7 s (`data/out/docker_demo/run_metrics.json`), plus generating the data |
| Later starts (data is kept in `./data`) | a few seconds |

Follow progress with `docker compose logs -f`. The app is ready when the log shows `Uvicorn running` and
`docker compose ps` shows `healthy`.

| Task | Command |
|---|---|
| Port 8000 already in use | `ATTACKLENS_PORT=8001 docker compose up -d` (PowerShell: `$env:ATTACKLENS_PORT=8001; docker compose up -d`) |
| Stop | `docker compose down` |
| Start again from scratch | `docker compose down`, delete `data/raw/docker_demo` and `data/out/docker_demo`, then `docker compose up -d` |
| Analyse your own logs | Open **Add data** in the app and upload files. Files you copy into `./data` on your machine are visible inside the container under `/app/data` |

### What to look at (2 minutes)

1. **Scorecard** (top row): attacks found, steps detected, false alarms, rows processed. These numbers are read from
   `eval_scorecard.json` / `run_metrics.json` of the run on screen, compared with the planted ground truth.
   Click **Details** for memory, run time per stage and dropped rows.
2. **Incident list** (left): thousands of alerts merged into a few incidents, riskiest first.
3. **Open the top incident** and use the tabs:
   - **Overview**: plain-English summary and the attack steps in order.
   - **Step by step**: the MITRE ATT&CK kill-chain bar, technique and tactic per step, and *why* each pair of steps is linked.
   - **Graph**: hosts, users and IPs; compromised nodes in red; hover an arrow to see why it is linked.
   - **Evidence**: the raw log lines behind every step.
   - **Reach next**: machines the attacker can reach from what is already compromised.
   - **Report**: a share-ready incident report (works offline).
4. **Add data**: upload your own logs (firewall, Windows, EDR, syslog, CEF, CSV, JSON) and press Analyse.

### Repository layout

| Folder | What is in it |
|---|---|
| `backend/attacklens/` | Python pipeline (ingest, detect, link, incidents, reach-next) and the FastAPI API |
| `backend/tests/`, `backend/eval/` | tests and the evaluation harness that scores runs against planted ground truth |
| `frontend/` | React + Cytoscape.js web UI |
| `config/` | detection rules, field aliases, link windows, ATT&CK data, SigmaHQ rules (edit config, not code) |
| `tools/` | synthetic data generator, mock SIEM / cloud services, QA and perf scripts |
| `docs/` | requirements, architecture, testing, demo script, benchmark |
| `reports/` | measured stress, QA and benchmark reports |
| `slides/` | finals presentation |

The rest of this README covers the native (non-Docker) setup, the design, measured results and disclosures.

**AttackLens works on top of your SIEM.** It is a correlation and attack-path layer, not a SIEM replacement. Your
SIEM keeps collecting logs and running its detections. AttackLens pulls events or alerts, stitches them into one
ATT&CK-labelled attack path, and pushes the incident back with queries that open the raw events in your SIEM.
SIEM connectors exist and are tested against a local mock SIEM only (see "Integrations" below). File ingest is the
scored path.

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
| B-4 Add a rule by editing config | `config/rules.yaml` (see section 8), plus the SigmaHQ catalogue in `config/sigma/` (section 6.1) |
| B-5 Live mode | `python -m attacklens.live --watch data/raw/live --out data/out/live`; `GET /api/live/status` |

Anything not finished is labelled in this file.

## Integrations (SIEM layer)

Status: code is in place. **Verified only against the local mock SIEM (`tools/mock_siem.py`). Nothing has been tested
against a real Elastic, Splunk, Sentinel or syslog source.** Design: `docs/DEVELOPMENT.md` section 8b.
Everything is disabled by default. Nothing touches the network until you set `enabled: true` in
`config/integrations.yaml`. The connectors use stdlib `urllib`. Only the AWS CloudTrail connector and the GCP
service-account signing need an optional pip extra (`backend[cloud]`: boto3, cryptography; see section 12).

| SIEM | Inbound (pull) | Outbound (push) |
|---|---|---|
| Elastic / OpenSearch | `_search` with `search_after` (PIT when supported), raw events or alerts | sink `elastic_bulk`, index `attacklens-incidents`, doc id = incident id |
| Splunk | `services/search/jobs/export`, raw events or notables | sink `splunk_hec` |
| Microsoft Sentinel | Log Analytics KQL query, raw events or `SecurityAlert` | sink `webhook` |
| Generic syslog / CEF (e.g. QRadar) | syslog / CEF listener (UDP and TCP) | sink `syslog_cef` |
| Mitigata Gordon AI SOC | alerts (to confirm) | sink `webhook` (to confirm) |
| Any SOAR | none | sink `webhook` (`incident`, `summary` or `slack` payload) |

Sinks are disabled by default, send an incident again only when its content changed (`only_changed`), and never fail
a run. A sink error is logged and recorded in `run_metrics.json` (`stage_stats.publish.sinks`) and in the status file.

### Cloud logs

- Formats in `config/sources.yaml`: `cloudtrail_json` (AWS CloudTrail, one record per line), `azure_signin_json`
  (Entra ID sign-in), `azure_activity_json` (Azure Activity Log), `azure_storageblob_json` (Azure Storage blob logs),
  `gcp_audit_json` (GCP Cloud Audit Logs).
- Pull connectors: `aws_cloudtrail`, `azure_monitor`, `sentinel`, `gcp_logging` (plus `elastic`, `syslog`). All are
  `enabled: false` in `config/integrations.yaml`. Exported JSON files also work without any connector.
- Rules: `config/rules_cloud.yaml` (69 native + 18 behavioural, per `reports/cloud/README.md`). Settings:
  `config/cloud.yaml`. Sources of the rule logic: section 12.
- Optional offline IP to ASN file: set `geo.asn_db_path` in `config/cloud.yaml` to a local iptoasn table.
  Nothing is downloaded at runtime. Without it, a network is the /16 (IPv4) or /48 (IPv6) prefix.
- Unverified values: Entra and Azure role ids, Entra error codes and some AWS request shapes were not checked
  against live tenants (`reports/cloud/README.md`).
- Cloud accuracy, run time and RAM: not measured yet.

### Input modes

| Mode | Command | Where it lands | Labels come from |
|---|---|---|---|
| events | `python -m attacklens.connect --source <s> --mode events` | `<live watch_dir>/siem/<source>/<bucket>/` (default `data/raw/live/siem/...`); live mode ingests it | AttackLens rules |
| alerts | `python -m attacklens.connect --source <s> --mode alerts` | `data/spool/siem_alerts/<source>/*.jsonl` | the vendor's MITRE field |

- Pull command: `python -m attacklens.connect --source elastic|splunk|sentinel|syslog [--mode events|alerts] [--since 24h] [--once] [--reset] [--config DIR]`.
  Exit code 2 if the connector is disabled, 1 if a `--once` cycle failed.
- `--since` is used only when there is no checkpoint. `--reset` forgets the checkpoint.
- Checkpoints: `data/spool/state/<source>_<mode>.json`. Status: `data/spool/connector_status.json`.
  Per cycle: `pulled` = `written` + `skipped` + `failed`, each with reasons.
- Alert rows become `raw_alerts` with `rule_id` `siem:<vendor>:<rule>`. The technique is the vendor MITRE field, else
  `alert_input.rule_technique_map` (rule-name substring), else the alert is dropped as `no_technique` (counted).
- Batch alert mode: `python -m attacklens.run --raw <dir> --out data/out/<name> --siem-alerts`. It is refused together
  with `--ground-truth`.
- Live alert mode: set `alert_input.enabled: true` in `config/integrations.yaml`, then run `attacklens.live` as usual.
- Scored runs (file ingest, with `eval_scorecard.json`) use raw events only. Vendor MITRE labels are used only in alert
  mode. `run_metrics.json` records `input_mode` (`file`, `file+siem_alerts`) and `inputs`; `live_status.json` records
  `input_mode` (`live`, `live+siem_alerts`) and `inputs`.
- Never quote file-ingest accuracy for an alert-mode run. It has no accuracy score.
- Secrets: `config/integrations.yaml` holds the names of environment variables (`token_env`, `api_key_env`, ...),
  never values. If a named variable is not set, the connector refuses to call the SIEM and counts an error. For the
  mock without tokens, set those keys to `null`.
- Pivot-back queries: `GET /api/incidents/{id}/pivots` returns, per step, a ready-to-run SPL, KQL or Lucene query
  (plus an Elasticsearch query DSL body) scoped to the step's host, user and IPs within +-15 min (`pivots.window_ms`).
  Values are escaped for each query language. Pivots only generate text, so they are on by default. A URL is added
  only when `base_url` is set for that SIEM.

### Run it offline against the mock SIEM

The mock serves Elastic, Splunk, Sentinel and webhook endpoints on one port, serves ECS JSON lines from a folder with
the generator label fields stripped, and serves a hand-written alert fixture (`tools/mock_siem_alerts.json`).
It listens on 127.0.0.1 only. Steps (each in its own terminal where it keeps running):

1. Start the mock: `PY tools/mock_siem.py --data data/raw/g1 --port 9200`
   (options: `--alerts <fixture>`, `--elastic-api-key`, `--splunk-token`, `--hec-token`, `--sentinel-token`,
   `--webhook-token`, `--workspace-id`, `--syslog-udp`, `-v`).
2. In `config/integrations.yaml` set `connectors.elastic.enabled: true` and `api_key_env`, `user_env`, `password_env`
   to `null` (the mock has no auth). To also test a sink, set `sinks.elastic_bulk.enabled: true` and
   `api_key_env`, `user_env`, `password_env` to `null`. Revert after the demo.
3. Pull the SIEM's alerts: `PY -m attacklens.connect --source elastic --mode alerts --since 7d --once`
4. Build incidents from them: `PY -m attacklens.run --raw data/raw/g1 --out data/out/siem1 --siem-alerts`
   (no `--ground-truth`).
5. Serve and open: `ATTACKLENS_OUT=data/out/siem1 PY -m uvicorn attacklens.api:app --port 8000`, then
   `curl http://localhost:8000/api/incidents/<id>/pivots` and `curl http://localhost:8000/api/integrations/status`.
6. For raw events instead of alerts: `PY -m attacklens.connect --source elastic --mode events --once`, then run
   `PY -m attacklens.live --watch data/raw/live --out data/out/live`.

The `--since 7d` window is relative to now. The fixture alerts and the g1 events carry their own timestamps. If the
pull returns `pulled: 0`, widen `--since` and check `data/spool/connector_status.json`.
Pull speed, alert-to-incident ratio and accuracy against a real SIEM: not measured yet.

### Known limits

- No overlap window: data indexed late in the SIEM (timestamp older than the checkpoint) is not pulled.
- Sentinel can get stuck on a page where every row has the same timestamp.
- A Splunk first pull is all-or-nothing: if it fails part-way, nothing from it is kept.
- The Elastic PIT path is untested against a real Elastic cluster (mock only).
- Connectors write many small spool files.
- The Gordon AI SOC row and the Sentinel push (generic webhook, e.g. to a Logic App) are to confirm; nothing was
  written against their real APIs.

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
detected by content, not by file name. Without a terminal: use the "Add data" page (section 2.9).

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
SIEM events pulled by `attacklens.connect` land under `data/raw/live/siem/` and are picked up the same way.

### 2.7 Docker Compose

```bash
docker compose up -d --build
```
Verified on 2026-11-01 on Windows 11 with Docker 29.7.2 and Compose v5.3.1: the image builds, the container
reports `healthy`, `/api/health` lists 5 incidents and the UI loads at http://localhost:8000. Details and timings are
in "For judges" at the top of this file.

### 2.8 Tests

```bash
PY -m pytest backend -q -m "not stress"
```
The probe tests in `backend/eval/test_probes.py` check that the evaluation harness is not generous. They must pass.

### 2.9 Add your own data (UI or API)

Use this when a judge brings a log file. No terminal is needed. Start the API and UI first (2.4, 2.5), or use
`docker compose up` and open http://localhost:8000.

**In the UI** (page "Add data", address `#add-data`):

| Step | What to do | What happens |
|---|---|---|
| 1. Choose logs | Drag and drop files onto "Drop log files here", or use "Use a file already on this computer" and type the full path | Drop: the browser streams the file to the API with a progress bar per file. Path: the API makes a hard link, so nothing is copied |
| 2. Analyse | Press "Analyse these logs" | Starts the pipeline. A stage tracker shows profile, ingest, lookups, detect, episodes, link, incidents, publish, with percent, elapsed time and RSS |
| 3. Results | When the run succeeds, open an incident from the results | The API serves the new run's output folder from then on |

- Accepted file types: `.log .txt .csv .json .jsonl .ndjson .cef .syslog`. Other types are refused with HTTP 415.
  The type check is on the extension only. Once accepted, ingest still routes each file by content (section 3).
- For a 10-50 GB file use "Use a file already on this computer". A browser upload is also streamed (no
  file is held in memory, no temp copy), but it still writes a second copy of the whole file to disk.
- A hard link needs the file to be on the same disk volume as `data/raw/uploads`. If the link fails (other disk,
  FAT, no permission) the API falls back to a streamed copy and needs free disk for it. The response says
  `"mode": "link"` or `"mode": "copy"`.
- Docker: the container only sees the repo's `data/` folder (mounted at `/app/data`). Put the file under `data/` on
  the host and give the container path, for example `/app/data/mylogs/firex.log`.
- Only one run can be active at a time (a second start returns 409). The pipeline needs the whole RAM budget.

**Same thing with the API** (default base URL `http://localhost:8000`):

| Call | Body | Success | Errors |
|---|---|---|---|
| `POST /api/uploads` | `multipart/form-data`, repeat the field `files` once per file | 201 | 400 not multipart, empty or unsafe file name (`..`, absolute path), no `files` part, client disconnected (partial upload removed); 413 over `upload.max_bytes`; 415 extension not allowed; 507 not enough free disk |
| `POST /api/uploads/local` | JSON `{"path": "<absolute path on this machine>"}` | 201 | 400 path not absolute or not a regular file; 403 path outside `upload.local_roots`; 404 not found; 413 file over `upload.max_bytes`; 415 extension; 507 no free disk (copy fallback only) |
| `GET /api/uploads` | none | 200, list, newest first | none |
| `POST /api/runs` | JSON `{"raw_dir": "...", "out_dir"?: "...", "ground_truth"?: "..."}` | 202 `{"run_id": "<12 hex>"}` | 400 invalid path or not a directory; 409 a run is already in progress |
| `GET /api/runs` | none | 200, every run since the API started, newest first | none |
| `GET /api/runs/{id}` | none | 200 | 404 unknown run id |
| `GET /api/health` | none | 200, includes `served_out_dir` (the folder the API serves now) and `out_dir_source` (`api_run`, `env` or `newest`) | none |

An upload response looks like this (`mode` is `upload`, `link` or `copy`):
```json
{"upload_id": "up-20261031-101500-a1b2c3", "raw_dir": "data/raw/uploads/up-20261031-101500-a1b2c3",
 "files": [{"name": "firex-10G.log", "bytes": 123}], "total_bytes": 123, "mode": "link",
 "created_at": "2026-10-31T10:15:00Z"}
```
The values above are a format example, not a measurement.

Command-line version of the whole flow (bash; replace the file path):
```bash
# 1. register a file already on this machine (hard link, no copy)
curl -s -X POST http://localhost:8000/api/uploads/local \
  -H "Content-Type: application/json" -d '{"path": "C:/logs/firex-10G.log"}'
# or upload files (field name is "files")
curl -s -X POST http://localhost:8000/api/uploads -F "files=@/path/to/a.log" -F "files=@/path/to/b.csv"
# 2. start the run with the raw_dir from the response
curl -s -X POST http://localhost:8000/api/runs \
  -H "Content-Type: application/json" -d '{"raw_dir": "data/raw/uploads/up-20261031-101500-a1b2c3"}'
# 3. poll until status is "succeeded" (stage, percent, elapsed_s, rss_mb, peak_rss_mb, error)
curl -s http://localhost:8000/api/runs/<run_id>
# 4. results, then check which folder is served
curl -s http://localhost:8000/api/incidents
curl -s http://localhost:8000/api/health
```

Rules the API enforces (from `backend/attacklens/api_upload.py`, `api_runs.py`, `config/pipeline.yaml` `upload:`):

| Rule | Value |
|---|---|
| Upload folder | `data/raw/uploads/<upload_id>/` (`up-YYYYMMDD-HHMMSS-xxxxxx`). Written under `.incoming/` first and renamed when complete, so a partial upload is never listed or analysed. Any error deletes the partial folder |
| File names | basename only, characters outside `[A-Za-z0-9._-]` become `_`, leading dots removed, duplicates get `-1`, `-2` |
| `upload.max_bytes` | 68719476736 (64 GiB for all files of one upload together) |
| `upload.min_free_bytes` | 2147483648 (2 GiB must stay free; checked before the write and every `disk_check_every_bytes` = 268435456 during it) |
| `upload.chunk_bytes` | 1048576 (1 MiB write buffer) |
| `upload.local_roots` | `null` = any local path. Set a list of folders to restrict `POST /api/uploads/local` |
| `raw_dir` for `POST /api/runs` | must be inside `data/raw/` and made of `[A-Za-z0-9._-]` names |
| `out_dir` | optional, must be exactly `data/out/<name>`. Default `data/out/<last part of raw_dir>`. The live-mode output folder is refused |
| `ground_truth` | optional, a file inside `data/raw/`. Without it the run has no accuracy scorecard |

**Security: the API binds to 127.0.0.1 only. Keep it that way.** `POST /api/uploads/local` lets the caller make
the API read any file the API process can read. `POST /api/runs` starts jobs. Neither has authentication.
uvicorn binds to 127.0.0.1 by default, and `docker-compose.yml` publishes the port as `127.0.0.1:8000` only.
Do not run `uvicorn --host 0.0.0.0` and do not publish the port on a shared network. If you must, set
`upload.local_roots` first.

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
SIEM (Elastic, Splunk, Sentinel, syslog/CEF)         optional, off by default
   | python -m attacklens.connect  (events -> <live watch_dir>/siem/..., alerts -> data/spool/siem_alerts/..)
   v
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
   +-- siem_alerts.py        (--siem-alerts) unions the alert spool into raw_alerts at Stage 3
   +-- sinks/*               Stage 7 pushes incidents to Splunk HEC / Elastic bulk / webhook / syslog CEF (off by default)
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

### 6.1 Detection rules: our own plus the SigmaHQ catalogue

Two rule sources run in Stage 3 (detect) and write into the same `raw_alerts`:

| Source | Where | Count | Notes |
|---|---|---|---|
| Our rules | `config/rules.yaml` | the table above | hand-written, tuned against the eval harness, SQL over canonical columns |
| SigmaHQ rules | `config/sigma/` (mapping in `config/sigma_map.yaml`) | 3779 files (`config/sigma/SOURCE.md`) | vendored unmodified, compiled by pySigma to DuckDB SQL, cached in `data/cache/sigma/` |

- Sigma alerts are labelled from the rule's own ATT&CK tag. A rule with no technique tag is skipped
  (`no_attack_technique_tag`).
- A Sigma alert is dropped when one of our own rules already covers the same event and host with the same
  technique or tactic. The count is `sigma_alerts_deduped`. Our hand-tuned label wins.
- Each rule may raise at most `sigma.max_alerts_per_rule` alerts per run (1000). Overflow is counted
  (`sigma_alerts_capped_by_rule`).
- Settings: `sigma:` block in `config/pipeline.yaml` (`enabled`, `min_level`, `status`, `max_alerts_per_rule`,
  `live`, `live_min_level`). Live mode runs only `high` and `critical` Sigma rules.

**Most Sigma rules do not apply to every data set.** They are written for Windows and Linux endpoint logs
(process creation, registry, file events, PowerShell, auditd) and for cloud audit logs. A rule can only run if the
data has its log source and the fields it tests. FortiGate logs are firewall logs, so only these rule families can
apply there: `firewall`, `proxy`, `dns`, `webserver` and `fortigate_event` (the `logsources:` list in
`config/sigma_map.yaml`). The hundreds of process-creation rules cannot fire on a firewall-only data set.
A rule that compiled is not a rule that detected something.

How to read the numbers: `total` = rule files parsed. `compiled` = turned into SQL and accepted by DuckDB.
`running` = compiled, and passing the level and status filter. `applicable` = running rules whose log source
had at least one candidate row in the data. `fired` = rules with at least one alert. `alerts` = Sigma alerts after the
per-rule cap and de-duplication. `skipped_by_reason` = why the rest did not run.

Measured coverage. Source for every number: `stage_stats.detect.sigma` in `data/out/g50m_sigma/run_metrics.json`
(a 50 MB synthetic ECS set, 64176 rows; `total_wall_s` 31.09, `peak_rss_mb` 255.0 in the same file). That file was
written before the flat `sigma_*` keys existed, so it has the same data in the older nested layout. Commit: not
recorded in the metric file.

| Measure | g50m_sigma | Key in the file |
|---|---|---|
| Rule files parsed (`sigma_rules_total`) | 3779 | `coverage.parsed` |
| Compiled (`sigma_rules_compiled`) | 1672 | `coverage.compiled` |
| Running (`sigma_rules_running`) | 1657 | `rules_running` |
| Applicable (`sigma_rules_applicable`) | not measured yet | key added after this run |
| Fired (`sigma_rules_fired`) | 11 | `rules_fired` |
| Alerts (`sigma_alerts`) | 1414 | `alerts` |
| Deduplicated (`sigma_alerts_deduped`) | not measured yet | key added after this run |
| Skipped, `unmapped_logsource` | 1183 | `coverage.skipped_by_reason` |
| Skipped, `unmapped_field` | 659 | `coverage.skipped_by_reason` |
| Skipped, `no_attack_technique_tag` | 260 | `coverage.skipped_by_reason` |
| Skipped, `keyword_search_unmapped` | 3 | `coverage.skipped_by_reason` |
| Skipped, `unsatisfiable_without_unmapped` | 1 | `coverage.skipped_by_reason` |
| Skipped, `value_type` | 1 | `coverage.skipped_by_reason` |
| Filtered, `below_min_level:informational` | 15 | `coverage.filtered_out` |
| Sigma load / scan time | 4.31 s / 9.044 s | `load_s`, `scan_s` |

Running rules by log source in that run (`coverage.running_by_logsource`): process_creation 1204, file_event 182,
registry 67, network_connection 55, win_system 50, win_security 27, dns_query 25, linux_syslog 19, antivirus 9,
dns 9, proxy 9, firewall 1. In that run the `webserver` rules were skipped as `unmapped_logsource`
(86 rules with log source `None/webserver/None`, `coverage.skipped_top_details`). `config/sigma_map.yaml` now
has a `webserver` and a `fortigate_event` log source. No stored run used the current map.

Per data set:

| Data set | Sigma numbers | Source |
|---|---|---|
| g50m_sigma (synthetic ECS, 50 MB) | see the table above | `data/out/g50m_sigma/run_metrics.json` |
| g1x, g1 (synthetic ECS, 1 GB) | not measured yet (runs have no Sigma keys) | `data/out/g1x/run_metrics.json`, `data/out/g1/run_metrics.json` |
| f1 (synthetic FortiGate) | not measured yet (run has no Sigma keys) | `data/out/f1/run_metrics.json` |
| t10, t30, t50s (real FortiGate tiers) | not measured yet (runs have no Sigma keys) | `data/out/t10/run_metrics.json` and the other two |

Honest limits:
- AttackLens does not detect every attack. The 1657 running rules in the table cover only the log sources and
  fields that `config/sigma_map.yaml` maps. 2107 of 3779 rules were skipped in that run.
- Sigma changes accuracy on the one pair of runs we have (table below). Sigma on raised false alarms on that set.
  Do not read the Sigma-on row as a gain.
- The Sigma alert count (1414) is raw alerts, not incidents. Most of them are `sigma_f17211f1` (1314 in
  `top_rules`), one rule. Alert counts say nothing about accuracy.
- Re-running `PY -m attacklens.run` on any data set now writes the flat `sigma_*` keys into
  `stage_stats.detect`. Until that is done and recorded, the table above is the only Sigma measurement.

Sigma off against Sigma on, same synthetic 50 MB set (g50m, 21 planted steps). Sources:
`data/out/g50m_nosigma/eval_scorecard.json` and `data/out/g50m_sigma/eval_scorecard.json`
(`detection_pct`, `labels_pct`, `rebuilt_pct`, `false_alarms_strict_pct`, `false_alarms_lenient_pct`,
`singleton_recall_pct`, `counts.incidents`, `counts.predicted_steps`; run state: no commit recorded).

| Measure | Sigma off (g50m_nosigma) | Sigma on (g50m_sigma) |
|---|---|---|
| Detection | 100.0 % | 100.0 % |
| Correct labels | 100.0 % | 95.24 % |
| Attacks rebuilt | 100.0 % | 100.0 % |
| False alarms, strict | 0.0 % | 28.57 % |
| False alarms, lenient | 0.0 % | 28.57 % |
| Singleton recall | 100.0 % | 100.0 % |
| Incidents | 5 | 7 |
| Predicted steps | 31 | 46 |

Metric files do not record the commit, so a new run on current code may differ. Re-run both before quoting. Other runs in `data/out/` named
`g50m_v_*`, `g1_v_*` and `f1_v_*` look like Sigma setting variants. Their meaning is not recorded in the metric files,
so they are not quoted here.

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
- Sigma rules: the vendored SigmaHQ catalogue in `config/sigma/` runs by default (section 6.1). To add a Sigma
  rule, put a `.yml` file under `config/sigma/`. It compiles at the next run (cache is keyed on file content).
- Rules come from trusted config. Do not load rule files from untrusted sources.

## 9. API

Base URL `http://localhost:8000`. All reads come from memory.

| Method and path | Returns |
|---|---|
| `GET /api/health` | liveness, incident count, `served_out_dir`, `out_dir_source` |
| `GET /api/incidents` | incident index, risk descending |
| `GET /api/incidents/{id}` | full incident JSON |
| `GET /api/incidents/{id}/path` | backbone, branches and edges only (FR-5, FR-7) |
| `GET /api/metrics` | `run_metrics` + `eval_scorecard` + `ingest_accounting` |
| `POST /api/uploads` multipart field `files` | streams files into `data/raw/uploads/<upload_id>/` (201) |
| `POST /api/uploads/local` body `{path}` | hard-links a file already on this machine (201). 127.0.0.1 only, see 2.9 |
| `GET /api/uploads` | uploads, newest first |
| `POST /api/runs` body `{raw_dir, out_dir?, ground_truth?}` | starts a background pipeline run (202, `{run_id}`; 409 if one is running) |
| `GET /api/runs` | all runs since the API started, newest first |
| `GET /api/runs/{id}` | stage, percent, elapsed, RSS, error |
| `GET /api/live/status` | live-mode state |
| `GET /api/incidents/{id}/pivots` | per step: SPL / KQL / Lucene query (+ DSL body) that opens the raw events in the SIEM |
| `GET /api/integrations/status` | connectors, sinks, pivot SIEMs: enabled, last pull, counts, whether each env var is set (never its value) |
| `POST /api/reload` | re-read the output directory |

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
| python-multipart | Apache-2.0 | streaming multipart parser for `POST /api/uploads` (0.0.33 installed) |
| Anthropic SDK | MIT | optional (`backend[llm]`); narrative wording; off without a key |
| pySigma | LGPL-2.1-only | required dependency (`backend/pyproject.toml`, `pysigma>=2.0.1,<3`); parses and compiles the vendored SigmaHQ rules; used unmodified (2.0.1 installed) |
| mitreattack-python | Apache-2.0 | listed in an earlier plan for `config/attack_v20.json`; not in `backend/pyproject.toml`; the file's own note names the STIX bundle as its source (see "Data, rules and tools") |
| boto3 (and botocore) | Apache-2.0 | optional (`backend[cloud]`, `boto3>=1.28`); AWS CloudTrail connector; imported lazily; off by default. Version not checked here |
| cryptography | Apache-2.0 OR BSD-3-Clause | optional (`backend[cloud]`, `cryptography>=42`); RS256 signing of the GCP service-account JWT; imported lazily |
| pytest | MIT | tests (dev) |
| httpx | BSD-3-Clause | API tests (dev) |

Transitive Python packages that matter for licensing. Licenses read from the installed `.dist-info/METADATA`
under `.venv/Lib/site-packages` (Windows venv). `pip show` was not run; the METADATA files are what it prints.

| Package (installed version) | License | Pulled in by | Note |
|---|---|---|---|
| diskcache 5.6.3 | Apache-2.0 | pySigma | cache for compiled rules |
| diskcache-stubs 5.6.3.6.20240818 | Apache-2.0 | pySigma | type stubs |
| google-re2 1.1.20251105 | BSD (classifier `BSD License`) | pySigma | regex engine |
| jq 1.13.0 | BSD-2-Clause | pySigma | |
| packaging 26.3 | Apache-2.0 OR BSD-2-Clause | pySigma | |
| pyparsing 3.3.3 | MIT | pySigma | condition parser |
| requests 2.34.2 | Apache-2.0 | pySigma | |
| types-PyYAML 6.0.12.20261030 | Apache-2.0 | pySigma | type stubs |
| urllib3 2.8.0 | MIT | requests | |
| certifi 2026.10.23 | MPL-2.0 | requests | CA bundle, unmodified |
| charset-normalizer 3.5.2 | MIT | requests | |
| idna 3.20 | BSD-3-Clause | requests | |
| Starlette 1.10.0 | BSD-3-Clause | FastAPI | |
| anyio 4.15.1 | MIT | Starlette | imported directly by `api_upload.py` |

pySigma's own dependency list (`Requires-Dist`) also names Jinja2 and PyYAML. Both are listed above as direct
dependencies. certifi is MPL-2.0 (file-level copyleft). It is used as installed, not modified.

### JavaScript (frontend)

| Component | License | Use |
|---|---|---|
| React, React DOM | MIT | UI |
| Vite | MIT | build and dev server |
| @vitejs/plugin-react | MIT | React support in Vite |
| Tailwind CSS | MIT | styling |
| @tailwindcss/vite | MIT | Tailwind integration |
| @fontsource-variable/geist | OFL-1.1 | Geist font (5.3.0 in `node_modules`), served locally, no CDN |
| @fontsource-variable/geist-mono | OFL-1.1 | Geist Mono font (5.3.0 in `node_modules`), served locally, no CDN |
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
| MITRE ATT&CK v20 (`config/attack_v20.json`) | MITRE Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) | technique and tactic names and order; technique ids in cloud rules. The file's note says: Enterprise v20, 61 entries hand-checked, the rest merged on 2026-10-31 from the official STIX bundle `enterprise-attack-20.0.json` (repo `mitre-attack/attack-stix-data`). ATT&CK(R) is a registered trademark of The MITRE Corporation |
| SigmaHQ detection rules (`config/sigma/`) | Detection Rule License (DRL) 1.1 | also `rules/cloud`: logic re-expressed in our native cloud rules (`config/rules_cloud.yaml`) with attribution. 3779 rule files vendored unmodified from https://github.com/SigmaHQ/sigma at commit `05d1031f537e830b76da53bae2400c5814c89165` (committed 2026-10-21, vendored 2026-10-31). Source: `config/sigma/SOURCE.md` |
| DataDog Stratus Red Team (attack technique docs) | Apache-2.0 | cloud: technique list, event names, test plan |
| Splunk security_content (`detections/cloud`) | Apache-2.0 | cloud rules: thresholds and patterns |
| Azure-Sentinel (Entra ID / Azure Activity analytic rules) | MIT | cloud rules: operation names, result codes, thresholds |
| Panther panther-analysis (`aws_cloudtrail_rules`) | Apache-2.0 | cloud rules: lists and patterns |
| Elastic detection-rules | Elastic License 2.0 | cloud rules: logic inspired by; no query text copied, all SQL is original |
| iptoasn.com ip2asn tables (optional, not shipped) | PDDL 1.0 | offline IP to ASN / country (`geo.asn_db_path` in `config/cloud.yaml`) |
| AWS `ip-ranges.json`, Google `cloud.json`, Azure Service Tags (optional, not shipped) | public feeds | cloud provider IP ranges (`geo.provider_ranges`) |
| `reports/edr_log_generator.py` | organiser/team-provided test-data tool | synthetic log generation; wrapped by `tools/gen_dataset.py`, not edited |
| Organiser FortiGate log tiers | confidential, organiser-provided | hackathon use only; not published |

#### Sigma attribution (DRL 1.1)

The rules are licensed under the Detection Rule License 1.1. Full text: `config/sigma/LICENSE.Detection.Rules.md`
(from https://github.com/SigmaHQ/Detection-Rule-License). Repository notice: `config/sigma/LICENSE.md`.

What DRL 1.1 requires, and what we do:

| DRL 1.1 condition | How AttackLens meets it |
|---|---|
| When you share the rules, keep the `author` field and any other attribution in the rule | Rule files are copied unmodified. Each keeps `author`, `id`, `references` |
| When you share the rules, keep a link to the rule set | https://github.com/SigmaHQ/sigma (commit above) |
| When you share the rules, say they are under the DRL and link or include its text | This section and `config/sigma/LICENSE.Detection.Rules.md` |
| When you use the rules on data, messages based on a match keep the rule's `author` | Alerts carry the rule id `sigma_<first 8 hex of the Sigma id>`. The coverage file `data/out/<set>/work/sigma_coverage.json` maps each fired id to its title. Whether the UI shows the rule author on each alert: not verified |

Rule authors are credited in each rule file under `config/sigma/`. Sigma is a project of the SigmaHQ community.

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
| `docs/BENCHMARK.md` | our measured numbers next to other tools' published claims |
| `reports/stress/` | stress-test reports per data size |
