# AttackLens — Development Guide (for the orchestrating LLM and its agents)

Audience: the Claude Code session that builds AttackLens and the subagents it delegates to. Read it top to bottom
once; afterwards jump to the section a task needs. Requirements live in `docs/PRD.md`; testing in `docs/TESTING.md`.

Contents: §1 Architecture · §2 Repository layout · §3 Canonical event schema · §4 Stages · §5 Detection rules ·
§6 Formulas · §7 Incident contract + API · §8 UI · §9 Multi-agent orchestration · §10 Build plan and gates ·
§11 Dos and don'ts · §12 Known pitfalls (verified) · §13 Definition of done · §14 Disclosures

---

## 1. Architecture

One batch pipeline over Parquet, plus two measuring components every run passes through.

```
data/raw/<set>/*            (JSON lines / ECS, CSV, syslog, CEF)
   │
   ▼ Stage 0  profile.py     sniff format by content, resolve field aliases → source_profile.json
   ▼ Stage 1  ingest.py      ONE DuckDB COPY → data/parquet/<set>/events/source_type=*/ts_ok=*/event_day=*/
   │                         + ingest_accounting.json (rows in / ok / dropped per source)
   ▼ Stage 1b lookups.py     host_ip_map, background_hubs, rule_host_baseline (small Parquet tables)
   ▼ Stage 2  detect.py      every rule = one SQL query over events → raw_alerts.parquet
   ▼ Stage 2.5 episodes.py   5-min episodes, IP→host resolution, merged_alert_count, seed-safe 25K cap
   ▼ Stage 3  link.py        4 keyed DuckDB joins (R1–R4) → edges.parquet with weight + why_linked
   ▼ Stage 4  incidents.py   components → gate → risk → host-monotonic path DP → reach-next BFS
   ▼ Stage 5  publish.py     data/out/<set>/incidents/{id}.json, incidents_index.json, narrative
   │
   ├── eval/harness.py       (if ground truth given) → eval_scorecard.json
   └── telemetry.py          RSS sampled every 500 ms from process start → run_metrics.json
API (FastAPI) serves precomputed JSON from memory; UI (React + Vite + Cytoscape.js) renders it.
Live mode (B-5) tails a folder in 2 s micro-batches and re-runs Stages 1–5 on the delta window.
```

Design principles (each one closes a failure we already hit in review or testing):
- DuckDB does all heavy work (C++, all cores, spills to disk). Python never iterates over raw events.
- Every stage reads and writes files, so any stage can be re-run alone and tested alone.
- Ingest once per data set; tuning detection re-runs Stage 2+ in seconds against the same Parquet.
- Correlation is **evidence-linked** (co-occurrence on shared entities within windows), never called "causal".

## 2. Repository layout

```
cyberforge/                       (git repo root — Phase 0 creates it)
  CLAUDE.md  README.md  docker-compose.yml  .gitignore
  .claude/agents/*.md             subagent definitions (§9)
  .claude/skills/*/SKILL.md       /gate /eval /gen-data /stress-test
  .claude/settings.json           Stop hook: fast tests must pass
  config/
    sources.yaml                  field aliases per source format (§3.2)
    rules.yaml                    detection rules + thresholds (§5)
    sigma/*.yml                   optional Sigma rules compiled by pySigma
    attack_v20.json               technique → name, tactic, tactic index (generated, §5.4)
    ioc.yaml                      threat-intel lists (domains, IPs, ransom extensions)
    allowlist.yaml                known scanners / backup jobs / admin hosts
  backend/
    pyproject.toml                package "attacklens" (pip install -e backend[dev])
    attacklens/                   models.py profile.py ingest.py lookups.py detect.py episodes.py link.py
                                  incidents.py reach.py narrative.py publish.py telemetry.py run.py api.py live.py
    eval/                         harness.py match.py test_probes.py
    tests/                        fixtures/ test_*.py (fast) · stress/ (marked "stress")
  frontend/                       Vite + React 19 + Tailwind 4 + Cytoscape.js
  tools/                          gen_dataset.py scenarios.py (TESTING.md §3)
  reports/edr_log_generator.py    the provided log generator — DO NOT EDIT, wrap it
  data/                           raw/ parquet/ out/   (git-ignored)
  docs/                           PRD.md DEVELOPMENT.md TESTING.md
```

## 3. Canonical event schema

### 3.1 Columns (every source maps into exactly these)
| Column | Type | Notes |
|---|---|---|
| ts_ms | BIGINT | UTC epoch ms; NULL → row quarantined (`ts_ok=false`), counted, never silently lost |
| ts_ok, event_day | BOOLEAN, DATE | partition keys |
| source_type | VARCHAR | `ecs_json`, `win_json`, `firewall_csv`, `syslog`, `cef` |
| source_seq | UBIGINT | `hash(filename, raw_line)` — deterministic tie-breaker, no window function |
| action | VARCHAR | normalized verb (table 3.3) — **rules use this, not raw event IDs** |
| event_id | INTEGER | native Windows/Sysmon ID when present |
| outcome | VARCHAR | success / failure / NULL |
| logon_id, logon_type | VARCHAR, INTEGER | logon_type normalized: Interactive 2, Network 3, Batch 4, Service 5, RemoteInteractive 10 |
| host, host_ip | VARCHAR | host lower-case; host_ip = first reporting IP |
| src_user, target_user | VARCHAR | NFC, lower, `DOMAIN\` and `@domain` stripped; for logon actions the logged-on account goes in `target_user` |
| is_machine | BOOLEAN | account ends with `$` |
| group_name | VARCHAR | group in membership changes |
| src_ip, src_port, dst_ip, dst_port, dst_domain | | `-` and empty → NULL |
| process_name, process_path, parent_process, command_line | | process_name = lower basename |
| file_path, file_ext, registry_path | | |
| bytes_out | BIGINT | outbound bytes |
| raw_line | VARCHAR | original line (minus stripped label fields) for evidence display |

### 3.2 Field aliases (`config/sources.yaml`)
Aliases are JSON paths for JSON sources and column names for CSV. First non-null alias wins.
For the provided generator (ECS JSON) the mapping is (verified against `reports/edr_log_generator.py`):
| Canonical | ECS path | Canonical | ECS path |
|---|---|---|---|
| ts | `$."@timestamp"` | process_name | `$.process.name` |
| host | `$.host.name` | process_path | `$.process.executable` |
| host_ip | `$.host.ip[0]` | parent_process | `$.process.parent.name` |
| user (→ src_user or target_user) | `$.user.name` | command_line | `$.process.command_line` |
| event_action | `$.event.action` | dst_ip / dst_port / dst_domain | `$.destination.ip` / `.port` / `.domain` |
| outcome | `$.event.outcome` | src_ip / src_port | `$.source.ip` / `.port` |
| event_id | `$.winlog.event_id` | bytes_out | `$.network.bytes` |
| logon_type | `$.winlog.logon.type` | file_path / file_ext | `$.file.path` / `$.file.extension` |
| registry_path | `$.registry.path` | — | — |
Also add aliases for Windows EVTX JSON (`TimeCreated`, `EventID`, `Computer`, `TargetUserName`, `SubjectUserName`,
`IpAddress`, `TargetLogonId`, `LogonType`, `WorkstationName`, `Image`, `ParentImage`, `CommandLine`), firewall CSV
(`timestamp|time`, `device|host`, `src`, `dst`, `dport`, `bytes_sent`, `action|disposition`) and finish the map
against the real 100 MB sample at kickoff (Stage 0 prints every field it sees per source).

**Never read** `threat`, `rule`, `labels`, `labels_extra`, `event.kind`, `event.severity`, `event.module`,
`event.dataset` — those are generator ground truth/hints. `tools/gen_dataset.py` strips them anyway.

### 3.3 Action vocabulary
`login_failed, login_success, priv_assigned, user_created, group_member_added, proc_start, conn_out, conn_allowed,
conn_denied, dns_query, file_write, file_rename, reg_set, service_installed, scheduled_task, log_cleared, other`.
ECS mapping: `user_logon`+failure → login_failed, +success → login_success; `process_created` → proc_start;
`network_connection` → conn_out; `dns_query` → dns_query; `file_modified` → file_write; `file_rename` → file_rename;
`registry_value_set` → reg_set. Windows IDs: 4625/4771 failed, 4624 success, 4672 priv, 4720 user created,
4728/4732/4756 group add, 4688 & Sysmon 1 proc_start, 4698 task, 7045/4697 service, 1102/104 log cleared.

## 4. Stages (behaviour, output, acceptance)

### Stage 0 — profile (`profile.py`)
- Sniff each file's first non-empty line: `{` → JSON lines; `CEF:` → cef; `^[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d \S+ ` → syslog;
  else CSV. Never route by extension (a firewall export may be `.log`, Sysmon may be `.txt`).
- For JSON sources, read with `read_ndjson_objects(files)` (one JSON column) and extract with
  `json_extract_string(json, '<path>')`. Do **not** rely on `read_json` auto-schema: it infers from a sample and can
  miss rare fields; the object approach measured 0.12 s per 42 MB.
- Output `source_profile.json`: files per format, top-level field paths seen with counts, actions/event IDs seen.
- Acceptance: unknown format → listed under `unrecognized` with a warning, never a crash.

### Stage 1 — ingest (`ingest.py`)
- One connection: `SET TimeZone='UTC'; SET memory_limit='5GB'; SET temp_directory='data/spill';
  SET preserve_insertion_order=false; SET threads=<cpu_count>`.
- Timestamp: `epoch_ms(coalesce(try_cast(x AS TIMESTAMPTZ), try_strptime(x, [formats])::TIMESTAMPTZ))` on the
  **string** value. Syslog: prefix the configured `baseline_year`.
- Absent alias → `NULL`, never a binder error (build SQL from the profile, `DESCRIBE`/paths seen).
- Every `regexp_extract` wrapped in `NULLIF(…, '')`.
- One `COPY (… UNION ALL BY NAME …) TO 'data/parquet/<set>/events' (FORMAT PARQUET, PARTITION_BY (source_type,
  ts_ok, event_day), COMPRESSION ZSTD)`. No `ORDER BY`, no window functions over the input.
- Write `ingest_accounting.json` = `[{source_type, rows_in, rows_ok, dropped}]`.
- Acceptance: fixture tests in TESTING.md §4.2 (row counts exact, UTC values exact, users normalized).

### Stage 1b — lookups (`lookups.py`)
- `host_ip_map(ip, host, first_ms, last_ms)`: from logon events with logon_type 3/10 (+ workstation name), host_ip of
  each host's own events, sshd `from <ip>`; exclude 127.0.0.0/8, `::1`, `-`.
- `background_hubs(entity)`: median over days of daily distinct peers > `hub_min_median_daily_peers` (20), using
  login user = `coalesce(target_user, src_user)` for logon actions.
- `rule_host_baseline(rule_id, base_freq)`: filled after Stage 2 — median hosts/day the rule fired on days where that
  host had no other detection. Victims of a wide attack must not count.

### Stage 2 — detect (`detect.py`)
- Load `config/rules.yaml` (+ `config/sigma/*.yml` via pySigma, optional). Each rule → one SQL query over the
  `events` view (`WHERE ts_ok`), output rows with: rule_id, technique_id, sub_technique_id, tactic, tactic_idx,
  severity, ts_ms, host, subject_host, src_user, target_user, src_ip, dst_ip, dst_host, raw_alert_count,
  evidence_lines (≤ 3), source_keys (≤ 50 source_seq).
- `subject_host` = for firewall/flow rows the resolved source host, else `host` (firewalls log themselves as host).
- Filter before windows: every threshold/sequence template first selects only its candidate actions.
- Acceptance: each template has a fixture test with a positive and a near-miss negative case.

### Stage 2.5 — episodes (`episodes.py`)
- Bucket alerts by `(rule_id, subject_host, src_user, target_user, dst_host, floor(ts_ms/300000))`, fixed 5 min on
  every tier. `merged_alert_count = sum(raw_alert_count)` (B-3). Resolve IPs→hosts here with an ASOF join on
  `host_ip_map` (thousands of rows, never a Parquet rewrite).
- If episodes > 25 000: keep every episode within 2 hops (shared non-hub entity, 24 h) of a seed with
  Confidence ≥ 65; spill the rest to `episodes_spilled.parquet` and record the count in run_metrics.

### Stage 3 — link (`link.py`)
Four keyed equality joins in DuckDB (never Python pairwise loops), each with its window filter
`0 ≤ t_j − t_i ≤ τ_R` and tie-break `(ts_ms, source_seq)`:
| Rule | Join | τ | M_R | why_linked template |
|---|---|---|---|---|
| R1 handoff | `i.dst_host = j.subject_host` or `i.subject_host = j.src_host` | 24 h | 1.5 | "Activity moved from {a} to {b} {dt} later" |
| R2 session | same `subject_host` and same user (`coalesce(target_user, src_user)`) | 2 h | 1.0 | "Same session: {user} on {host}, {dt} apart" |
| R3 pivot | `i.target_user = j.src_user` (account created/elevated/brute-forced, then used) | 72 h | 1.3 | "Account {user} from step {i} used in step {j}" |
| R4 egress | same `subject_host`, i.tactic = Collection, j.tactic = Exfiltration | 24 h | 1.2 | "Data staged on {host} sent to {dst}" |
Hubs (`background_hubs`) are barred as join keys in R2/R3; a hub may be the **target** of R1. No tactic-order rule on
edges (order is enforced in the path DP). Output `edges.parquet(i, j, rule, weight, why_linked)`.

### Stage 4 — incidents (`incidents.py`, `reach.py`)
1. Weakly connected components over episodes + edges (NetworkX on ≤ 25 K nodes).
2. Gate (§6.3); suppressed components go to `suppressed.json` with the reason (for the FA review).
3. Risk (§6.4), path DP (§6.5), kill-chain gaps (tactics between first and last backbone tactic not observed).
4. Reach-next (§6.6) from the frontier: users and hosts of the last two backbone steps + any elevated account.
5. Sort incidents by risk; ids are stable: `inc-<sha1(sorted episode keys)[:8]>`.

### Stage 5 — publish + narrative (`publish.py`, `narrative.py`)
- Write `incidents/{id}.json` (contract §7.1), `incidents_index.json`, `run_metrics.json`, and if ground truth was
  given run `eval/harness.py` → `eval_scorecard.json`.
- Narrative: replace every host/user/IP/technique with typed placeholders (`{{HOST_1}}` …); prompt contains only
  placeholders, technique IDs, tactic names, counts, times. Reject output with unknown placeholders or missing
  backbone steps; on reject, no key, timeout (10 s) or any error → Jinja2 template. Then substitute real values.

### Live mode (`live.py`, B-5)
Tail files in `data/raw/live/` by byte offset every 2 s; append rows; re-run Stage 2+ on events newer than
(watermark − longest rule window); dedupe alerts on (rule_id, key, window_start); recompute only changed components.
Budget: `memory_limit='1.5GB'`. Target: UI path updates within 5 s of a line being written.

## 5. Detection rules

### 5.1 Rule format (`config/rules.yaml`)
```yaml
thresholds: {bf_min_failures: 50, bf_gap_ms: 600000, bf_success_window_ms: 900000, emit_t1078_on_bruteforce: true,
             spray_min_users: 15, exfil_min_bytes: 50000000, exfil_window_ms: 900000, exfil_baseline_mult: 5.0,
             mass_rename_min: 100, beacon_min_conns: 6, hub_min_median_daily_peers: 20,
             seed_confidence: 65, critical_confidence: 90, raw_ref_score: 15.0}
rules:
  - id: office_spawns_script
    kind: match                       # match | template | sigma
    where: "action='proc_start' AND parent_process IN ('winword.exe','excel.exe','outlook.exe')
            AND process_name IN ('powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe')"
    technique: T1059.001
    tactic: Execution
    severity: 80
  - id: brute_force_then_success
    kind: template
    template: brute_force_then_success  # implemented in detect_templates.py, params from thresholds
    technique: T1110
    sub_technique: T1110.001
    tactic: Credential Access
    severity: 85
```
`where` is a SQL predicate over canonical columns only; rules come from trusted config. Every rule must name a
technique in `attack_v20.json`; a test fails otherwise.

### 5.2 Starter catalogue (cover PRD examples + generator signals + injected scenarios)
| id | kind | Technique → tactic | Signal |
|---|---|---|---|
| brute_force_then_success | template | T1110 → Credential Access (+ T1078 → Initial Access if toggle) | ≥ 50 login_failed per target_user, bursts split on 10-min gaps, ASOF success ≤ 15 min |
| password_spray | template | T1110.003 → Credential Access | one src_ip, ≥ 15 distinct target users failing in 10 min |
| account_created_then_elevated | template | T1136 → Persistence, T1098 → Privilege Escalation | user_created then group_member_added same account ≤ 24 h (two steps) |
| office_spawns_script | match | T1059.001 → Execution | office parent → script engine |
| encoded_powershell | match | T1059.001 → Execution | `command_line ILIKE '%-enc%' OR ILIKE '%-encodedcommand%'` |
| run_key_persistence | match | T1547.001 → Persistence | `registry_path ILIKE '%\\CurrentVersion\\Run%'` by script engine |
| ioc_destination | match | T1071.001 → Command and Control | dst_domain / dst_ip in `config/ioc.yaml` |
| beaconing | template | T1071.001 → Command and Control | same host→dst ≥ 6 conns, interval coefficient of variation < 0.2 |
| ransom_rename | template + match | T1486 → Impact | ≥ 100 file_rename per host in 60 s, or `file_ext` in ransom list |
| exfil_volume | template | T1048 → Exfiltration | sliding 15-min sum(bytes_out) per (subject_host, dst_ip), external dst, > max(50 MB, 5 × host daily median) |
| new_admin_logon | template | T1021 / T1078 → Lateral Movement | login_success type 3/10 + priv_assigned (same logon_id) on a (user, host) pair seen ≤ 2 times in the data set |
| discovery_commands | match | T1087 / T1082 → Discovery | `whoami`, `net user`, `net group`, `nltest`, `systeminfo` in command_line |
| service_or_task | match | T1543.003 / T1053.005 → Persistence | service_installed / scheduled_task actions |
| log_cleared | match | T1070.001 → Defense Impairment | log_cleared action |
| archive_staging | match | T1560.001 → Collection | 7z/rar/zip/Compress-Archive in command_line |
Choose and tune against the **real** sample: run Stage 0, look at actions present, keep only rules whose signals exist.

### 5.3 Labelling policy
One primary technique and one primary tactic per rule (context-specific, e.g. T1078 after a brute force =
Initial Access). Store `technique_id` (parent) and `sub_technique_id`; the harness accepts either. Pin ATT&CK v20.

### 5.4 ATT&CK data
Generate `config/attack_v20.json` once from the official STIX data with `mitreattack-python` (or hand-check the ~20
techniques used). Tactic index order (v20): 1 Reconnaissance, 2 Resource Development, 3 Initial Access, 4 Execution,
5 Persistence, 6 Privilege Escalation, 7 Stealth, 8 Defense Impairment, 9 Credential Access, 10 Discovery,
11 Lateral Movement, 12 Collection, 13 Command and Control, 14 Exfiltration, 15 Impact.
If the organisers' ground truth uses the old "Defense Evasion", map Stealth/Defense Impairment → Defense Evasion in the
harness only.

## 6. Formulas (all parameters in `config/rules.yaml`)
N = hosts seen; BaseFreq(r) from `rule_host_baseline`.
1. **Rarity:** `rarity(r) = ln(1 + N / max(1, BaseFreq(r))) / ln(1 + N)`
2. **Confidence:** `Confidence(v) = min(100, sev_v × max(rarity(r_v), 0.65 if sev_v ≥ 80 else 0))`
3. **Gate:** keep component C iff `(|tactics(C)| ≥ 2 and max Confidence ≥ 65) or max Confidence ≥ 90`;
   components containing only allowlisted entities are suppressed.
4. **Risk (B-1):** `S_t` = max severity at tactic t on 1–10; `w_t = (10 + t)/10`; `raw = Σ w_t·ln(S_t)`;
   `risk = min(100, round(90·raw/raw_ref) + min(10, round(2·ln(1+|hosts|) + ln(1+merged_alerts))))`.
   raw_ref = highest planted attack's raw on the dev sample (default 15).
5. **Edge weight:** `w_ij = M_R × rarity(r_j) × exp(−(t_j − t_i)/τ_R)`.
6. **Path DP (FR-5):** sort by (ts_ms, source_seq, episode_id);
   `S(j) = sev_j + max(0, max_{i∈Pred(j), ok(i,j)} S(i) + w_ij)`, `ok(i,j) ⇔ tactic_idx(j) ≥ tactic_idx(i) or rule(i,j)=R1`.
   Backtrack from argmax S → backbone; keep branches with end score ≥ 0.5 × max.
7. **Reach-next (FR-6):** edges AdminTo(user,host) = login_success type 3/10 joined to priv_assigned on
   (host, logon_id) — exclude logon_id 0x3e7/0x3e4/0x3e5 and machine accounts — plus sudo/root SSH; MemberOf from
   group adds; CanReach(host,host,port) from allowed flows on 22/445/3389/5985 via host_ip_map. BFS ≤ 3 hops; output
   each reachable host with hop count and the evidence event; untouched hosts first, then crown-jewel tags (`dc`, `file`, `db`).

## 7. Incident contract and API

### 7.1 `incidents/{id}.json` (Pydantic `Incident` in `models.py` = TS type in `frontend/src/types.ts`)
```json
{"id":"inc-3f2a9c1e","risk":86,"first_ts":"2026-10-30T01:00:00Z","last_ts":"2026-10-30T07:40:00Z",
 "merged_alert_count":312,"episode_count":9,"entry_point":{"step":0,"summary":"brute force from ip:203.0.113.57"},
 "tactics":["Credential Access","Initial Access","Execution","Lateral Movement","Exfiltration"],
 "gaps":["Discovery"],
 "backbone":[{"step":0,"episode_id":"e12","ts":"…","technique_id":"T1110","sub_technique_id":"T1110.001",
   "tactic":"Credential Access","host":"srv-dc-01","user":"svc_backup","src_ip":"203.0.113.57","dst_ip":null,
   "severity":85,"confidence":85,"merged_alert_count":61,"evidence":["<raw line>", "…"]}],
 "branches":[[…]],
 "edges":[{"from":"e12","to":"e15","rule":"R3","weight":2.1,"why_linked":"Account svc_backup …"}],
 "graph":{"nodes":[{"id":"host:srv-dc-01","type":"host","label":"SRV-DC-01","compromised":true}],
          "edges":[{"source":"ip:203.0.113.57","target":"host:srv-dc-01","label":"T1110","step":0}]},
 "reach_next":[{"host":"srv-file-01","hops":1,"via_user":"svc_backup","evidence":"4624 type 3 + 4672 at …",
   "crown_jewel":"file","touched":false}],
 "narrative":{"text":"…","source":"llm|template"}}
```
### 7.2 API (FastAPI, `api.py`) — all reads from memory, target < 10 ms
`GET /api/health` · `GET /api/incidents` (index, risk desc) · `GET /api/incidents/{id}` · `GET /api/incidents/{id}/path`
(backbone + branches + edges only) · `GET /api/metrics` (run_metrics + eval_scorecard + ingest_accounting) ·
`POST /api/runs {raw_dir, ground_truth?}` (background job) · `GET /api/runs/{id}` (stage, % , elapsed, RSS) ·
`GET /api/live/status`. Use one DuckDB cursor per request if any query is needed; never share a connection across threads.

## 8. UI (frontend-builder)
One incident screen, top to bottom: header (risk, "312 alerts → 1 incident", time span) · entry point · kill-chain
bar with gaps (dashed) · ordered steps with technique badges + confidence · 2–3 evidence lines per step (escaped,
truncated 300 chars) · why-linked on edge hover · Cytoscape graph (dagre, left→right, compromised nodes highlighted)
· reach-next list with evidence · narrative with source badge. Global header: scorecard banner (from
`/api/metrics`), peak RSS, total time. Incident list sorted by risk. Mock mode `VITE_USE_MOCK=true` reads
`src/mock/incident.json`. Never render raw strings as HTML (XSS from log content).

## 9. Multi-agent orchestration

### 9.1 Roles (definitions in `.claude/agents/`)
| Agent | Model | Tools | Owns | Typical task |
|---|---|---|---|---|
| orchestrator (main session) | strongest | all | plan, merges, gates, CLAUDE.md status | split work, delegate, verify |
| backend-builder | inherit | Read, Edit, Write, Bash, Glob, Grep | `backend/attacklens/**`, `config/**`, `backend/pyproject.toml` | implement a stage |
| frontend-builder | inherit | Read, Edit, Write, Bash, Glob, Grep | `frontend/**` | screens, API client |
| test-engineer | inherit | Read, Edit, Write, Bash, Glob, Grep | `backend/tests/**`, `backend/eval/**`, `tools/**` | fixtures, harness, generators |
| stress-tester | inherit | Read, Write, Bash, Glob, Grep | `reports/stress/**`, `data/**` | run 10/30/50 GB, write reports |
| code-reviewer | inherit | Read, Glob, Grep, Bash | none (read-only) | review a phase diff for bugs |
| doc-writer | sonnet | Read, Edit, Write, Glob, Grep | `README.md`, `docs/**` except PRD.md | README, disclosures, demo script |
No agent has the `Agent` tool: subagents never spawn subagents. Only the orchestrator delegates.

### 9.2 Facts about Claude Code subagents that shape this workflow
- A subagent starts with a fresh context: it sees `CLAUDE.md` and its own definition, **not** this conversation.
  Every delegation prompt must be self-contained (§9.3).
- It returns only its final report; the orchestrator must verify by running tests itself, not trust "done".
- Subagents cannot ask the user questions; they must state assumptions in the report.
- Background subagents surface permission prompts in the main session; keep their tool lists minimal.
- Worktree isolation (`isolation: worktree`) needs a git repo and does **not** copy `.venv`, `node_modules` or
  untracked data. For this project use **one working tree with disjoint folder ownership**; use a worktree only for
  a throw-away experiment (e.g. an alternative linking algorithm), then cherry-pick.

### 9.3 Delegation prompt template (copy, fill, send)
```
ROLE: <agent name>
GOAL: <one deliverable, one sentence>
READ FIRST: docs/DEVELOPMENT.md §<n>, docs/TESTING.md §<n>, files: <paths>
OWNS (may edit): <paths>        DO NOT TOUCH: <paths>
INPUTS: <data set / fixtures / config to use>
ACCEPTANCE (must pass, paste output): <exact commands> → <expected result>
CONSTRAINTS: <memory, UTC, no label fields, etc.>
REPORT FORMAT: 1) files changed  2) acceptance output (last 30 lines)  3) assumptions  4) open issues / risks
```

### 9.4 Waves (parallel only where ownership is disjoint)
| Wave | In parallel | Then orchestrator runs |
|---|---|---|
| W0 bootstrap | orchestrator alone (Phase 0) | `pytest -q` (empty suite passes), `npm run build` |
| W1 | backend-builder: Stage 0–1 · test-engineer: harness + probes + fixtures + `gen_dataset.py` · frontend-builder: shell + list + mock | gate G1 |
| W2 | backend-builder: Stage 1b + 2 + 2.5 · test-engineer: `scenarios.py` + detection fixtures · frontend-builder: incident view | gate G2 |
| W3 | backend-builder: Stage 3 + 4 + reach · test-engineer: link/path tests · frontend-builder: graph + timeline + reach panel | gate G3, code-reviewer on W1–W3 |
| W4 | backend-builder: API + narrative + live · frontend-builder: API wiring + scorecard banner · doc-writer: README draft | gate G4 |
| W5 | stress-tester: 1G → 10G → 30G → 50G (sequential, one tier on disk at a time) · backend-builder fixes from reports · doc-writer: disclosures, demo script | gate G5, freeze |

### 9.5 Orchestrator loop (every delegation)
1. Write the prompt (§9.3). 2. Delegate (parallel only within a wave). 3. When reports arrive: read them, then run
`pytest backend -q -m "not stress"` and the wave's gate yourself. 4. If red: send the failure output back to the same
agent (resume it) with a narrowed goal; never fix silently in another agent's folder. 5. If green: commit, tick the
CLAUDE.md status box, start the next wave. 6. After W3 and W5, delegate a read-only review to code-reviewer and route
each confirmed finding to its owner.

## 10. Build plan and gates (H0 = the moment implementation starts)

### Phase 0 bootstrap (orchestrator, ≤ 30 min)
```
git init && git add -A && git commit -m "docs: plan"           # repo needed for review diffs and worktrees
python -m venv .venv && .venv/Scripts/python -m pip install -U pip
# create backend/pyproject.toml: deps duckdb>=1.1 pyyaml networkx fastapi uvicorn pydantic psutil jinja2;
# optional: anthropic pysigma; dev: pytest httpx
.venv/Scripts/python -m pip install -e "backend[dev]"
npm create vite@latest frontend -- --template react && cd frontend && npm i && npm i cytoscape cytoscape-dagre
mkdir -p config data/raw data/parquet data/out tools backend/tests/fixtures backend/eval reports/stress
```
`.gitignore`: `data/`, `.venv/`, `node_modules/`, `dist/`, `.claude/worktrees/`, `*.parquet`, `.env`.
Windows: add `C:\cyberforge\data` to Microsoft Defender exclusions (Windows Security → Virus & threat protection →
Exclusions) before timed runs — real-time scanning can slow I/O several-fold.

| Gate | By | Must be true (measured) |
|---|---|---|
| G1 rows + probes | H+3 | 100 MB sample (or 1G synthetic) ingested, 0 unexplained drops; harness probes pass; GT format known |
| G2 end to end | H+8 | pipeline prints all 4 accuracy metrics on the dev set |
| G3 Good | H+12 | Good column on every metric (dev set) |
| G4 Great + 10/15 GB | H+16 | Great column on dev set; 10 GB synthetic and real 15 GB tier finish, accuracy unchanged, < 8 GB, < 1 h |
| G5 freeze | H+21 | `docker compose up` cold start works; slides numbers = files; rehearsed |
Missed gate → cut scope (live mode, 50 GB, Sigma pack, adjacency extras), never move the freeze.

## 11. Dos and don'ts
**Do**
- Run Stage 0 on the real sample first and update `sources.yaml` before writing rules.
- Keep each stage runnable alone: `python -m attacklens.run --from-stage 2 --set <set>`.
- Count everything: rows in/out, alerts per rule, episodes, components kept/suppressed, spilled episodes.
- Put every threshold in YAML; log the effective config into run_metrics.json.
- Test each detection template with a positive and a near-miss negative fixture.
- Keep evidence lines short (≤ 300 chars) and escape them in the UI.
- Commit after every green gate; tag the demo commit.
**Don't**
- Don't load raw events into Python lists, pandas DataFrames or Pydantic models.
- Don't `ORDER BY` or use window functions over the whole input; filter first.
- Don't cast timestamps to text and re-parse; don't rely on the laptop time zone.
- Don't route files by extension; don't use `read_json` auto-schema for heterogeneous JSON.
- Don't read generator label fields in detection; don't tune the harness.
- Don't let two agents edit the same file in one wave; don't let subagents spawn subagents.
- Don't keep 10/30/50 GB raw tiers on disk together (151 GB free on the build laptop).
- Don't claim a number on a slide that isn't in a metrics file from the demo commit.
- Don't call the LLM with raw log text; don't block the UI on the LLM.

## 12. Known pitfalls (verified on this machine, DuckDB 2.0.0)
| Pitfall | Symptom | Fix |
|---|---|---|
| Typed timestamp cast to text renders in local zone (`+05:30`) | rows get NULL ts and vanish | `SET TimeZone='UTC'`; `try_cast(x AS TIMESTAMPTZ)` first |
| Column named in SQL missing from a file | Binder Error, run crashes | aliases + NULL for absent; build SQL from profile |
| `file_row_number` / `filename_row_number` | "not supported by this reader" for CSV/JSON | `hash(filename, raw_line)` |
| `regexp_extract` no match | returns `''`, joins on empty string | `NULLIF(…, '')` |
| Syslog process regex unanchored | process = `04` (from the time) | anchor after the host field |
| sshd "port N" | client source port stored as dst | `src_port`; `dst_port=22` for sshd |
| DuckDB relation `.fetchone()` | AttributeError in 2.0 | use `con.execute(...).fetchone()` or `.fetchall()` |
| Generator `FileSink` opens in append mode | re-runs duplicate data | delete output first (gen_dataset.py does) |
| Generator timestamps = wall clock | 10 GB spans ~5 min → threshold rules fire everywhere | simulated clock in gen_dataset.py |
| Generator `uuid4` not seeded | event ids differ between runs | gen_dataset.py patches uuid4 with seeded RNG |
| Windows Defender scanning `data/` | throughput drops several-fold | Defender exclusion |
| Docker Desktop bind mounts | slow I/O | time runs natively; Docker only for judges' cold start |

## 13. Definition of done
All PRD Great targets green on the chosen tier from one commit (`eval_scorecard.json`, `run_metrics.json`); FR-1…FR-7
and B-1…B-5 demoable; fast tests + probes green; stress report for every tier attempted (TESTING.md §6);
README with run steps, measured tables and disclosures; `docker compose up` works on a clean clone.

## 14. Disclosures (README)
DuckDB (MIT), NetworkX (BSD-3), FastAPI (MIT), Uvicorn (BSD-3), Pydantic (MIT), PyYAML (MIT), psutil (BSD-3),
Jinja2 (BSD-3), Anthropic SDK (MIT, optional), pySigma (LGPL-2.1, optional, unmodified), Sigma rules (DRL 1.1,
attribution), MITRE ATT&CK v20 (MITRE ToU), mitreattack-python (Apache-2.0), React, Vite, Tailwind, Cytoscape.js,
cytoscape-dagre (MIT), pytest (MIT); the provided `edr_log_generator.py` (organiser/team-provided test data tool).
Ideas only (no code) from Zircolite, Chainsaw, Hayabusa, Elastic detection-rules, BloodHound, and the RapSheet,
HOLMES, NoDoze, Hopper, SAGE papers.

## 15. Interfaces pinned at kickoff (orchestrator, 31 Oct) — all agents code against these

### 15.1 Shared modules (already written; extend, don't rename)
- `attacklens/db.py`: `connect(memory_limit, threads, temp_directory)` (UTC, spill, no insertion order) and
  `register_events(con, ctx.events_glob)` → view `events` (canonical §3.1 columns + hive partitions).
- `attacklens/config.py`: `load_config()` → `{"sources","rules","pipeline","ioc","allowlist", "attack"}` (one key per
  `config/<name>.yaml`; `attack` = `attack_v20.json`).
- `attacklens/context.py`: `RunContext(set_name, raw_dir, parquet_dir, out_dir, con, cfg, ground_truth)`;
  `ctx.work_dir` = `data/out/<set>/work/`; `ctx.events_glob`.
- `attacklens/models.py`: the Incident contract (§7.1). `technique_name`, `rule_id` added to Step;
  `IncidentSummary` = one row of `incidents_index.json`.

### 15.2 Stage functions — every stage module exposes `run(ctx: RunContext) -> dict` (stats for run_metrics)
| Module | Reads | Writes |
|---|---|---|
| profile | `ctx.raw_dir` | `out/source_profile.json` |
| ingest | raw_dir + profile | `parquet/<set>/events/…`, `out/ingest_accounting.json` |
| lookups | events | `work/host_ip_map.parquet`, `work/background_hubs.parquet` |
| detect | events, lookups, config.rules | `work/raw_alerts.parquet`, `work/rule_host_baseline.parquet` |
| episodes | raw_alerts, lookups | `work/episodes.parquet`, `work/episodes_spilled.parquet` |
| link | episodes, hubs | `work/edges.parquet` |
| incidents | episodes, edges, events (reach) | `work/incidents.json` (list of Incident dicts, narrative = template stub), `out/suppressed.json` |
| publish | `work/incidents.json` | `out/incidents/{id}.json`, `out/incidents_index.json` (calls `narrative.generate`) |
`run.py` (CLI `python -m attacklens.run --raw … --out … [--parquet …] [--ground-truth …] [--from-stage N]`) calls them
in order, wraps each in telemetry, writes `out/run_metrics.json`, then if ground truth is given calls
`eval.harness.evaluate(out_dir: Path, ground_truth: Path) -> dict` and writes `out/eval_scorecard.json`.
`narrative.generate(incident: Incident, cfg: dict) -> Narrative`. Default parquet dir = `data/parquet/<basename of out>`.

### 15.3 Raw directory layout (what `tools/gen_dataset.py` writes and ingest reads)
`data/raw/<set>/part-<k>.jsonl` (noise, labels stripped) · `scenarios.jsonl` (planted attacks + decoys) ·
`manifest.json` · `ground_truth/attacks.json` · `ground_truth/noise_alerts.jsonl`.
**Ingest skips** any path with a `ground_truth` component, `manifest.json`, and `*.md`. Everything else is routed by content.

### 15.4 Intermediate Parquet schemas (column names are binding)
- `raw_alerts`: rule_id, technique_id, sub_technique_id, technique_name, tactic, tactic_idx INT, severity INT,
  ts_ms, last_ts_ms, source_seq UBIGINT (min of the alert's rows), host, subject_host, src_host, dst_host,
  src_user, target_user, src_ip, dst_ip, raw_alert_count BIGINT, evidence_lines VARCHAR[] (≤ 3, ≤ 300 chars),
  source_keys UBIGINT[] (≤ 50).
- `episodes`: episode_id VARCHAR (`'e' || substr(md5(key), 1, 10)`, key = rule_id|subject_host|src_user|target_user|
  dst_host|bucket|technique_id), every raw_alerts column above (ts_ms = first, last_ts_ms = last,
  raw_alert_count summed as `merged_alert_count`), plus `user` = coalesce(target_user, src_user), rarity DOUBLE,
  confidence DOUBLE, is_seed BOOLEAN.
- `edges`: i, j (episode_id), rule ('R1'..'R4'), weight DOUBLE, dt_ms BIGINT, why_linked VARCHAR.
- `host_ip_map`: ip, host, first_ms, last_ms. `background_hubs`: entity (`user:x` / `host:x` / `ip:x`).
- `rule_host_baseline`: rule_id, base_freq DOUBLE.

### 15.5 Scenario event conventions (ECS JSON; `tools/scenarios.py` emits, `config/sources.yaml` maps)
Built from the generator's `base_event()`; `host.name` upper-case as in the generator; `user.domain = "CORP"`.
| Event | Fields |
|---|---|
| logon | `event.action=user_logon`, `event.outcome`, `winlog.event_id` 4624/4625, `winlog.logon.type` (`Network`/`RemoteInteractive`/`Interactive`), `winlog.logon.id` (hex, e.g. `0x8a3f21`), `source.ip`; `user.name` = the account logged on (→ `target_user`) |
| special privileges | `event.action=special_privileges_assigned`, `winlog.event_id=4672`, same `winlog.logon.id`, `user.name` |
| user created | `event.action=user_created`, 4720, `user.name` = actor (→ src_user), `user.target.name` = new account (→ target_user) |
| group add | `event.action=group_member_added`, 4732 (4728/4756), `user.target.name` = member, `group.name` |
| service | `event.action=service_installed`, 7045, `service.name`, `process.executable` |
| log cleared | `event.action=log_cleared`, 1102 |
| SSH logon (linux) | `event.action=user_logon`, `process.name=sshd`, `source.ip`, `destination.port=22`, no winlog → canonical `logon_type=10` |
| process / network / file / registry | as the generator (`process_created`, `network_connection` with `network.bytes` + `network.direction=outbound`, `file_rename` with `file.extension`, `registry_value_set`) |
Action map precedence: `winlog.event_id` (§3.3 table) → `event.action` → `other`. Logon types: names and numbers both map
to the integers in §3.1. `bytes_out` = `network.bytes` when direction is outbound or absent.
