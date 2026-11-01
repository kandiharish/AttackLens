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

Alert input (§8b): when `config/integrations.yaml` `alert_input.enabled: true`, detect also unions the SIEM alert spool
(`data/spool/siem_alerts/`) into `raw_alerts` every cycle. A change in the spool alone (no new event bytes) triggers a
stages-only cycle. Alerts older than the window start (`alert_input.lookback_ms`) or dated later than now +
`max_future_skew_s` are skipped and counted. `live_status.json` records `input_mode` (`live` | `live+siem_alerts`)
and `inputs`. SIEM events pulled in events mode sit under `<watch_dir>/siem/<source>/<bucket>/`, so live mode tails,
windows, rolls back and accounts them like any other file.

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
`POST /api/runs {raw_dir, out_dir?, ground_truth?}` (background job; 202, 409 if one is running) · `GET /api/runs` ·
`GET /api/runs/{id}` (stage, % , elapsed, RSS, error) · `POST /api/uploads` · `POST /api/uploads/local {path}` ·
`GET /api/uploads` (contract: §15.6a) ·
`GET /api/live/status` · `GET /api/incidents/{id}/pivots` (per step SPL / KQL / Lucene + ES DSL, §8b) ·
`GET /api/integrations/status` (connectors, sinks, pivot SIEMs; env var set true/false, never the value) ·
`POST /api/reload`. Use one DuckDB cursor per request if any query is needed; never share a connection across threads.

## 8. UI (frontend-builder)
One incident screen, top to bottom: header (risk, "312 alerts → 1 incident", time span) · entry point · kill-chain
bar with gaps (dashed) · ordered steps with technique badges + confidence · 2–3 evidence lines per step (escaped,
truncated 300 chars) · why-linked on edge hover · Cytoscape graph (dagre, left→right, compromised nodes highlighted)
· reach-next list with evidence · narrative with source badge. Global header: scorecard banner (from
`/api/metrics`), peak RSS, total time. Incident list sorted by risk. Mock mode `VITE_USE_MOCK=true` reads
`src/mock/incident.json`. Never render raw strings as HTML (XSS from log content).

## 8b. Integration architecture (on top of a SIEM)

Status: **implemented, verified against the local mock SIEM only.** No real Elastic, Splunk, Sentinel or syslog source
has been tested. Uses stdlib `urllib` (`httpc.py`), so no new third-party library.

AttackLens is a correlation and attack-path layer. It does not replace the SOC's SIEM.
- The SIEM keeps collecting, storing and running its own detections.
- AttackLens reads from it, builds one ATT&CK-labelled path, and writes the incident back.

```
 SIEM / SOAR (Elastic, Splunk, Sentinel, syslog/CEF, Gordon AI SOC (to confirm))
    |  pull: raw events or the SIEM's own alerts
    v
 connectors/*  (python -m attacklens.connect)   elastic, splunk, sentinel, syslog; checkpoint per source+mode
    |  events: JSONL / CEF / syslog files            alerts: raw_alerts rows (siem_alerts.map_alert)
    v                                                v
 <live watch_dir>/siem/<source>/<bucket>/       data/spool/siem_alerts/<source>/*.jsonl
    |  live mode tails, windows, accounts           |  read only in alert-input mode
    v                                                v
 pipeline: detect (events) / union_into (alerts) -> episodes -> link -> incidents -> publish
    |
    v
 sinks/*   splunk_hec · elastic_bulk · webhook · syslog_cef    (called from publish.py)
    |  push incident
    v
 SIEM index / SOAR webhook / syslog CEF      analyst opens GET /api/incidents/{id}/pivots to see raw events
```

File ingest (Stages 0–1 on `data/raw/<set>/`) is unchanged. It is how the 15–50 GB tiers are scored.

### Modules and files
| Item | Name |
|---|---|
| Config | `config/integrations.yaml` (all connectors, sinks and `alert_input` disabled by default) |
| Pull CLI | `python -m attacklens.connect --source elastic\|splunk\|sentinel\|syslog [--mode events\|alerts] [--since 24h] [--once] [--reset] [--config DIR]` |
| Connectors | `attacklens/connectors/{base,elastic,splunk,sentinel,syslog}.py` |
| Alert mapping | `attacklens/siem_alerts.py` (`map_alert`, `union_into`) |
| Sinks | `attacklens/sinks/{splunk_hec,elastic_bulk,webhook,syslog_cef}.py` |
| Pivot queries | `attacklens/pivots.py`, `GET /api/incidents/{id}/pivots` |
| Status | `attacklens/integrations_status.py`, `GET /api/integrations/status` |
| Mock SIEM | `tools/mock_siem.py` (+ `mock_siem_query.py`, `mock_siem_store.py`, `mock_siem_alerts.json`) |

### Spool and state
| Path | Content |
|---|---|
| `<live.yaml watch_dir>/siem/<source>/<bucket>/` | events mode output (`spool.events_dir: null` -> this default) |
| `data/spool/siem_alerts/<source>/*.jsonl` | alerts mode output (`spool.alerts_dir`) |
| `data/spool/state/<source>_<mode>.json` | checkpoint: last timestamp + ids seen at that timestamp |
| `data/spool/state/sink_<name>.json` | per-incident content hash for `only_changed` |
| `data/spool/connector_status.json` | per cycle: `pulled` = `written` + `skipped` + `failed`, each with reasons; also sink results |

Label keys (`threat`, `rule`, `labels`, `labels_extra`, `signal`, `kibana`, `event.kind|severity|module|dataset|risk_score`)
are stripped from the events spool (`spool.strip_keys`, `strip_nested_keys`).

### Input modes
| Mode | Reads | Detection | Labels come from |
|---|---|---|---|
| `events` | raw log events | AttackLens rules (`config/rules.yaml`) | AttackLens rules |
| `alerts` | the SIEM's own alerts | none; alerts become `raw_alerts` rows, then episodes | the vendor's MITRE field, mapped to v20 |

- Example (events): Elastic search on `logs-*` -> ECS JSON lines in the spool -> Stage 0–1 ingest -> our rules fire.
- Example (alerts): Sentinel `SecurityAlert` with `Techniques=T1110` -> a `raw_alerts` row, `rule_id` `siem:sentinel:<AlertName>`.
- Alert technique: vendor MITRE field (`connectors.<s>.alerts.fields.technique`), else `alert_input.rule_technique_map`
  (lower-case substring of the rule name, first hit wins), else dropped as `no_technique` (counted).
- Severity: vendor word via `alert_input.severity_map`, numbers 0..100 as-is (CEF 0..10 x10), else `default_severity`.
- Batch: `python -m attacklens.run --raw <dir> --out <dir> --siem-alerts`. Live: `alert_input.enabled: true`.

### Connectors
| Source | Transport | Paging and checkpoint |
|---|---|---|
| `elastic` | `_search` on Elastic or OpenSearch (`flavor`) | `search_after`; PIT with `_shard_doc` tie-break when `use_pit`, else sort on `tiebreak_field`; checkpoint = (last ts, ids at that ts) |
| `splunk` | `services/search/jobs/export`, `output_mode=json`, streamed | earliest/latest from the checkpoint |
| `sentinel` | `POST /v1/workspaces/{id}/query` (KQL) | `TimeGenerated >= since`, `take page_size`; rows at `since` with a seen id are skipped |
| `syslog` | UDP/TCP listener (default `127.0.0.1:5514`) | one spool file per flush (atomic rename); `--once` listens `once_seconds`; lines over `max_buffer_lines` are dropped and counted as `buffer_full` |

### Sinks
| Sink | Target | Notes |
|---|---|---|
| `splunk_hec` | `POST <base_url>/services/collector/event`, `Authorization: Splunk <token>` | sourcetype `attacklens:incident` |
| `elastic_bulk` | `POST <base_url>/_bulk`, index `attacklens-incidents` | doc id = incident id, so a re-send overwrites |
| `webhook` | generic JSON POST | `payload`: `incident` (full JSON) \| `summary` (index row) \| `slack` |
| `syslog_cef` | UDP or TCP, vendor `Mitigata`, product `AttackLens` | one CEF line per incident and per step |

All disabled by default. `only_changed: true` re-sends an incident only when its content hash changed. A sink failure is
logged and recorded (`run_metrics.json` `stage_stats.publish.sinks`, `connector_status.json` `sinks`); it never fails the run.

### Eval-honesty rule
- Scored runs (anything that writes `eval_scorecard.json`) are **raw-events-only**. Same as today: detection from raw fields.
- Vendor MITRE labels are used **only in alert mode**. They are never mixed into a scored run.
- Enforced twice: `run.py` refuses `--siem-alerts` with `--ground-truth`, and `siem_alerts.union_into` raises
  `EvalGuardError` if a ground truth is set.
- Every run records its mode: `run_metrics.json` `input_mode` = `file` \| `file+siem_alerts`, plus `inputs`
  (`raw_events`, `siem_alerts`, `siem_alert_rows`, `siem_alert_dir`, `ground_truth`). Live: `live_status.json`
  `input_mode` = `live` \| `live+siem_alerts`.
- Alert-mode runs show no accuracy banner. Never quote file-ingest accuracy for them.

### Secrets rule
- `config/integrations.yaml` holds env var **names** only, e.g. `token_env: SPLUNK_HEC_TOKEN`.
- Values come from the environment. No token, password or key in the repo, logs, `run_metrics.json` or API output.
- `GET /api/integrations/status` reports per connector and sink: enabled, `base_url` (user info and query string
  removed), `auth_env_set` (true/false per env var name), last pull / publish time, last error, counts. Never a value.
- If a `*_env` key is named but the variable is unset, the connector refuses to call the SIEM (counted error, names
  logged). It does not crash other components. Set those keys to `null` for a SIEM without auth (the mock).

### Pivot-back queries
- Per step, one query per enabled SIEM (`pivots.siems.splunk|sentinel|elastic`): SPL, KQL, Lucene plus an ES query DSL
  body. Scope: the step's host, user and IPs within `ts +- pivots.window_ms` (900000 in config).
- Entity values come from logs, so they are escaped for each language (`pivots.escape`) and never pasted raw.
- Generated text only, no network call, so on by default (`enabled: null` follows the connector flag). A URL is added only
  when that SIEM's `base_url` is set.

### Offline mock
- `python tools/mock_siem.py --data data/raw/<set> --port 9200 [--alerts F] [--elastic-api-key K] [--splunk-token T]
  [--hec-token T] [--sentinel-token T] [--webhook-token T] [--workspace-id W] [--syslog-udp] [-v]`.
- One port serves Elastic (`_search`, `_pit`, `_bulk`), Splunk (`export`, HEC), Sentinel (workspace query) and
  `/webhook`. Control: `GET /_mock/received`, `GET /_mock/stats`, `POST /_mock/reset`. Loopback by default.
- Served events have the generator labels stripped. Alerts come from the hand-written `tools/mock_siem_alerts.json`.
- The demo runs fully offline against it. Tests use the same mock (`backend/tests/test_mock_siem.py`,
  `test_integrations.py`). Connector accuracy is not claimed against real vendors until tested on one.

### Known limits
- No overlap window: late-indexed data (timestamp older than the checkpoint) is not pulled.
- Sentinel can get stuck on a page where all rows share one timestamp.
- A Splunk first pull is all-or-nothing.
- Elastic PIT is untested against a real Elastic cluster.
- Many small spool files.
- Gordon AI SOC and Sentinel push (Logic App via `webhook`) are to confirm; no real API was used.
- Pull speed and alert-mode accuracy: not measured yet.

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
Jinja2 (BSD-3), python-multipart (Apache-2.0, upload parsing), Anthropic SDK (MIT, optional), pySigma (LGPL-2.1-only,
required dependency, unmodified) and its dependencies (diskcache, diskcache-stubs, types-PyYAML, requests: Apache-2.0;
google-re2: BSD; jq: BSD-2; packaging: Apache-2.0 OR BSD-2; pyparsing, urllib3, charset-normalizer: MIT; idna: BSD-3;
certifi: MPL-2.0), SigmaHQ rules in `config/sigma/` (DRL 1.1, attribution; commit in `config/sigma/SOURCE.md`),
MITRE ATT&CK v20 (MITRE ToU; `config/attack_v20.json`), React, Vite, Tailwind, Cytoscape.js, cytoscape-dagre (MIT),
Geist and Geist Mono via @fontsource-variable (OFL-1.1), pytest (MIT); the provided `edr_log_generator.py`
(organiser/team-provided test data tool). The full table with versions lives in `README.md` §12; keep both in step.
(The earlier mention of mitreattack-python is dropped here: it is not in `backend/pyproject.toml`.)
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
  src_user, target_user, src_ip, dst_ip, raw_alert_count BIGINT, evidence_lines VARCHAR[] (≤ 3, ≤ evidence_max_chars + 1 = 301 chars: the extra char lets the incident clip
  show the cut, see `detect_sql.evidence_chars`; incident step evidence is ≤ 300),
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

### 15.6 Metric file keys (binding for harness, run.py and UI)
- `eval_scorecard.json` top level: `detection_pct`, `labels_pct`, `rebuilt_pct`, `false_alarms_strict_pct`,
  `false_alarms_lenient_pct`, `singleton_recall_pct` (all 0–100 floats, `null` if not computable), plus
  `per_attack`, `per_rule_alerts`, `unmatched_incidents`, `targets` (Good/Great pass flags).
- `run_metrics.json` top level: `total_wall_s`, `peak_rss_mb`, `rows_per_s`, `stages` [{name, wall_s, peak_rss_mb}],
  `episodes`, `episodes_spilled`, `incidents`, `effective_config`.

Added keys. Definitions are from `backend/eval/harness.py` (`card["rules"]` and the code above it). A metric whose
denominator is 0 is `null` and passes no target.

`eval_scorecard.json` top level:
| Key | Definition | Example |
|---|---|---|
| `labels_technique_only_pct` | matched steps whose technique is right (parent or exact sub), tactic not checked / matched steps | right technique, wrong tactic still counts here, not in `labels_pct` |
| `step_precision_pct` | steps matched one-to-one (same tolerance as step match) to **their own** incident's attack / all predicted steps in incidents that matched an attack | if 10 of 12 predicted steps in matched incidents belong to their own attack: 83.33 (arithmetic example, not a measurement) |
| `step_precision_all_pct` | all matched steps / all predicted steps, over **every** incident (including unmatched ones) | noise-only incidents lower this, not `step_precision_pct` |
| `predicted_steps` | number of predicted steps (episodes shown as steps) over all incidents | copy of `counts.predicted_steps` |
| `gt_steps` | number of planted ground-truth steps | copy of `counts.gt_steps` |

`eval_scorecard.json` → `counts`:
| Key | Definition |
|---|---|
| `predicted_steps` | all predicted steps (denominator of `step_precision_all_pct`) |
| `predicted_steps_in_matched_incidents` | predicted steps whose incident was matched to an attack (denominator of `step_precision_pct`) |
| `steps_matched_to_own_attack` | matched steps where the step's incident is the incident matched to that step's own attack (numerator of `step_precision_pct`) |
| `steps_matched` | all matched steps (numerator of `step_precision_all_pct` and of `detection_pct`) |

Scorecards written before these keys existed do not have them. Checked: `data/out/g1x/eval_scorecard.json` has
`step_precision*`; `data/out/g1/eval_scorecard.json`, `g50m_sigma` and `g50m_nosigma` do not.
Say "not measured yet" rather than computing them by hand.

`run_metrics.json` → `stage_stats.detect` (flat Sigma keys, written by `sigma_detect.run`; absent when
`sigma.enabled: false`):
| Key | Definition |
|---|---|
| `sigma_rules_total` | Sigma rule files parsed (`coverage.parsed`) |
| `sigma_rules_compiled` | rules turned into SQL that DuckDB accepted (`coverage.compiled`) |
| `sigma_rules_running` | compiled rules left after the `min_level` and `status` filters (live mode: also `live_min_level`) |
| `sigma_rules_applicable` | running rules whose log-source gate matched at least one candidate row in the data (`group_tuples[*].tuples > 0`) |
| `sigma_rules_fired` | rules with at least one alert after cap and dedupe |
| `sigma_rules_skipped_by_reason` | dict reason → rule count. Reasons seen: `unmapped_logsource`, `unmapped_field`, `no_attack_technique_tag`, `keyword_search_unmapped`, `unsatisfiable_without_unmapped`, `value_type`, plus `below_min_level`, `status_filtered`, `disabled` |
| `sigma_alerts` | Sigma alerts left in `raw_alerts` after cap and dedupe |
| `sigma_alerts_capped_by_rule` | dict rule id → alerts dropped over `sigma.max_alerts_per_rule` |
| `sigma_alerts_deduped` | Sigma alerts dropped because a native (`rules.yaml`) alert covers the same event and host with the same technique or tactic |
| `sigma_wall_s` | wall time of the Sigma step |
| `sigma_defense_evasion_mapped` | dict of old ATT&CK Defense Evasion tags mapped to Stealth / Defense Impairment |

Other keys in the same block: `rows_matched`, `load_s`, `scan_s`, `group_s`, `group_tuples`, `batches`, `top_rules`,
`coverage`. `data/out/<set>/work/sigma_coverage.json` holds the same plus `alerts_per_rule` and `titles`.
Older runs (for example `data/out/g50m_sigma/run_metrics.json`) hold the data nested under
`stage_stats.detect.sigma` (`rules_running`, `rules_fired`, `alerts`, `coverage.*`) and have no `sigma_rules_applicable`
or `sigma_alerts_deduped`.

#### 15.6a Upload API contract (`api_upload.py`, `api.py`)
| Call | Request | Response |
|---|---|---|
| `POST /api/uploads` | `multipart/form-data`, field `files` repeated. Other field names are ignored | 201 `{upload_id, raw_dir, files:[{name, bytes}], total_bytes, mode:"upload", created_at}` |
| `POST /api/uploads/local` | JSON `{path}`, absolute path of a regular file on this machine | 201, same shape, `mode` is `link` (hard link) or `copy` (fallback when the link fails) |
| `GET /api/uploads` | none | 200 list of the same objects, newest first (`created_at`, then id) |
| `POST /api/runs` | JSON `{raw_dir, out_dir?, ground_truth?}` | 202 `{run_id}` |

Errors (body `{"detail": "..."}`):
| Status | When |
|---|---|
| 400 | not multipart or no boundary; empty name; name has `..`; absolute name; no `files` part; client disconnected (partial dir removed); `/local` path not absolute or not a regular file; `/runs` path outside `data/raw` or `data/out`, not a directory, or `out_dir` not exactly `data/out/<name>`, or the live output folder |
| 403 | `/local` path outside `upload.local_roots` |
| 404 | `/local` path not found; `GET /api/runs/{id}` unknown id |
| 409 | `POST /api/runs` while another run is running (one at a time) |
| 413 | total bytes over `upload.max_bytes` (also checked up front from `Content-Length`) |
| 415 | extension not in `upload.allowed_extensions` |
| 507 | free disk under `upload.min_free_bytes` after the incoming bytes (checked before and every `disk_check_every_bytes`) |

Behaviour that tests should keep:
- Upload goes to `<root>/.incoming/<id>/`, then `os.replace` to `<root>/<id>/`. Metadata: `<root>/.meta/<id>.json`.
  `GET /api/uploads` lists only dirs named `up-YYYYMMDD-HHMMSS-xxxxxx`.
- File names are sanitized to `[A-Za-z0-9._-]`; a duplicate name gets `-1`, `-2`. The raw filename is read from the
  header, because the multipart parser silently strips `C:\` style paths.
- Multipart is parsed incrementally, nothing is spooled to a temp file and no file is held in memory.
- Security: `/local` lets the caller read any file the API process can read, and `/runs` starts jobs. There is no auth.
  Keep the API on 127.0.0.1 (`docker-compose.yml` publishes `127.0.0.1:${ATTACKLENS_PORT:-8000}`). Narrow it with
  `upload.local_roots`.
- After a run started through the API succeeds, the store pins that run's `out_dir` (also over `ATTACKLENS_OUT`).
  `GET /api/health` shows `served_out_dir` and `out_dir_source` (`api_run`, `env`, `newest`).

#### 15.6b `config/pipeline.yaml` blocks
```yaml
sigma:
  enabled: true
  dir: "config/sigma"                  # vendored SigmaHQ rules, DRL 1.1 (config/sigma/SOURCE.md)
  cache_dir: "data/cache/sigma"        # compiled once per content hash of rules + sigma_map.yaml + attack data
  min_level: "low"                     # informational < low < medium < high < critical
  status: [stable, test, experimental] # deprecated / unsupported are never run
  batch_size: 250                      # rule predicates per events scan
  check_batch: 400                     # rules per EXPLAIN compile check (bisected on error)
  max_alerts_per_rule: 1000            # per run; overflow counted in sigma_alerts_capped_by_rule
  live: true                           # run Sigma in live cycles ...
  live_min_level: high                 # ... but only high/critical rules
upload:
  root: "data/raw/uploads"             # must stay under data/raw so POST /api/runs accepts the folder
  allowed_extensions: [".log", ".txt", ".csv", ".json", ".jsonl", ".ndjson", ".cef", ".syslog"]
  max_bytes: 68719476736               # 64 GiB, all files of one upload together
  min_free_bytes: 2147483648           # 2 GiB reserve
  chunk_bytes: 1048576                 # 1 MiB
  disk_check_every_bytes: 268435456    # 256 MiB
  local_roots: null                    # null = any path for /api/uploads/local; else a list of allowed folders
```
Mapping of Sigma log sources and fields to canonical columns: `config/sigma_map.yaml` (`logsources:`, `fields:`,
`unmapped_field_policy: skip`, `disable:`). A rule that needs an unmapped log source or field is skipped and counted,
never run on a guess.

### 15.7 Accepted deviations from §4–§6 (orchestrator sign-off, 31 Oct; each switchable in config)
| Spec | Deviation | Why | Literal behaviour |
|---|---|---|---|
| §6.6 `ok(i,j)` tactic order | Initial Access, Credential Access, Lateral Movement don't raise the per-host tactic floor (`linking.yaml path.floor_exempt_tactics`) | planted order CredAccess(9)→InitialAccess(3), LatMove(11)→Execution(4) is impossible under the literal rule | `[]` |
| §4 R3 join | source i must be Credential Access/Persistence/PrivEsc/Initial Access with confidence ≥ 60; also `i.target_user = j.target_user` | 12 shared user names linked all noise | `r3_*` keys |
| §6.3 gate | episodes with confidence < 40 join the component but don't count toward \|tactics\| (`gate.min_tactic_confidence`) | noise-only incidents 9/20 seeds → 1/20 | `0` |
| §4 Stage 4 | incidents are peeled from big components (DP path + directly linked episodes; rest re-gated, ≤ 20 per component) | one noise chain can't hide a second attack | `max_incidents_per_component: 1` |
| §4 Stage 1b hubs | `hub_min_median_daily_peers: 40`, `baseline_max_other_rules: 99` | g1 sweep (§5.3): generator users touch all 28 hosts daily | 20 / 0 |
| §5.2 new_admin_logon | skipped for routine pairs (≥ 3 prior non-priv logons) during 08–19 UTC | separates the admin decoy without labels | `new_admin_routine_min_logons` very high |
| §6.3 gate critical path | single-tactic component passes the ≥ 90 path only if top episode merged_alert_count ≥ 5 (`gate.critical_min_merged_alerts`) | 30M: lone `.locked` noise singletons were 54.5 % strict FA | `1` |
| §4 R1 | source-host variant (`i.subject_host = j.src_host`) window 6 h (`R1.src_tau_ms`); dst variant stays 24 h | 20-seed sweep: noise in backbones 13 → 7, bridge failures 1 → 0 | `86400000` |
| §4 Stage 4 branches | branch tails that pass the gate on their own are peeled into their own incident (`path.peel_standalone_branch_tails`) | seed-6 S2 glued onto S1 | `false` |
| §6.4 risk | `raw_ref_score: 30.8` = S1 raw on g1 (`linking.yaml risk`) | default 15 saturated S1/S4 at 100 | `15` |

### 15.8 Canonical columns added 31 Oct (detection coverage round)
`auth_package`, `ticket_encryption`, `service_name` (schemas.CANONICAL_COLUMNS). New actions: `kerberos_tgs` (4769),
`explicit_creds` (4648). Logon type `NewCredentials` → 9. Rules for T1059.003/.004, T1047, T1548.003, T1070.004,
T1562.001, T1003.001, T1558.003, T1550.002, T1046, T1021.002 admin shares, T1021.006 WinRM, plus command-line variants of
T1053.005 / T1543.003 / T1547.001 / T1070.001 / T1059.001.

### 15.9 Real data = FortiGate key=value (official tiers; no ground truth) — 31 Oct
`logs/firex-10G.log`, `logs/firex-30G.log`, `50g.txt` (small sample; line 1 is a URL) are the organisers' tiers.
Confidential: gitignored, never copied into tests/fixtures/reports. New source_type `fortigate_kv`; new canonical
columns `signature`, `vendor_severity`, `app`, `src_zone`, `dst_zone`, `bytes_in`. One device logs everything, so
`host` = devname and the **entity for internal endpoints is the IP** (`subject_host` = internal src IP when no host
name resolves). Accuracy is measured on synthetic FortiGate data from `tools/fortigate_gen.py` (planted scenarios +
ground truth, distribution modelled on the real profile counts, no real lines copied); the real tiers report time,
memory, accounting and "found" incidents (hand-reviewed, never a score).
| §6.6 DP | node score = confidence (`path.dp_node_score`) | g10: severity-scored DP started S1 from noise (95.2 / 80) | `severity` |
| §4 Stage 4 | every seed in a component is shown as a branch, never silently absorbed; invariant in_incidents + in_suppressed = episodes logged per run | g10 S4 steps hidden as absorbed members | — |
| §4 R3 | ≤ 5 successors per source (`r3_max_succs_per_source`) | g10: ~65 svc_backup R3 links | large value |
| §4 R1/R2 (firewall) | log devices (devname) barred as R2/R1 host keys; R2 keyed on IP for user-less IP subjects; R1 attacker-IP handoff (same external src_ip, 2 h) and R1 `i.dst_ip = j.subject_host` | f1: endpoint steps had no edges | `r2_ip_session: false`, `r1_ext_ip: false` |
