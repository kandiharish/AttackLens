# External Windows evaluation: real public attack logs (OTRF Security-Datasets)

Date: 2026-11-01 · agent "ext-eval Windows" for orchestrator cyberforge-6e · no commits.
Every number below is copied from the run's own `eval_scorecard.json`, `run_metrics.json` or `ingest_accounting.json`
under `data/out/ext_win_<set>/`. Lines marked **DIAGNOSTIC** come from helper scripts that read the run outputs. They
are not scorecard metrics.

## 0. Setup and deviations

- **Frozen snapshot:** `data/snap/ext_win`, built at **2026-11-01T02:56:24Z** from the working tree (copies of
  `backend/attacklens`, `config`, `data/cache/sigma`, plus `backend/eval` so the harness is frozen too).
  - md5 over `backend/attacklens/*.py` + `config/*.yaml`: `7cfaae58d89e4c87000d0148d503b993` at build time,
    `174012a290ba6ac2a5dba65d5b0be3f0` after the edit below. Every run used the edited state.
  - md5 over `backend/eval/*.py`: `c0276fa6a786896b4284119081b6a6e0`.
  - `COMPILER_VERSION = "6"` in `sigma_rules.py`.
- **Deviation from the production config** (orchestrator instruction; RAM on the shared machine was 0.9–2 GB free):
  the snapshot's `config/pipeline.yaml` has `memory_limit: "1GB"` (production 5GB) and `threads: 2` (production
  null = all cores). Runs went **directly, without jobq**, one at a time, each gated on ≥ 600 MB free RAM
  (`tools/ext/win_run_direct.sh`). Wall times are therefore 2-thread times on a loaded machine.
- **Sigma:** nothing was recompiled (1792 compiled rules came from cache `sigma_851cc83de4aea1e2.json`).
  - The FIRST run spent **183.8 s** in Sigma load. Of that, `key_s` = 183.1 s was hashing rule content for the cache
    key. It is counted inside lsass_comsvcs' 225.8 s wall time.
  - Every later run loaded Sigma in 0.7–1.2 s. Sigma scan time per run was 15–100 s at 2 threads.
- **Ground-truth hashes**, recorded when each file was finished, before any pipeline run. None was ever edited.
  The `_conv` sets carry byte-identical copies.

| set | attacks.json sha256 |
|---|---|
| apt29d1 (25 emulation steps) | b40c7b9840dbd56e4056c8f4b8155acdc8cc608f2bce794229ff9abb7a3ade18 |
| apt29d1 substeps (78 sub-steps, secondary) | 838bf46b42b06bf21f30a11a417e1e98e22a40b0fb00425c7e772f479a65d2b1 |
| lsass_comsvcs | 0396698491016bfd996977c644d7440623cc05f61250510a2f12bbc38b970ac0 |
| vbs_launcher | c643c41905140dff344c9890fe1fffeed340ae498cda5e741638fc8b3e9431b5 |
| runkeys | 77457b0e7a6e7f62092f9bbd2ea046ba2b919c52e081a99085f344efef28bae3 |
| psexec | 5c263caf33d781daf7476abc968dccb67cbf03d10af5501ca6104125fc8c62ab |
| sharpwmi | 20bc3e4f09a8f5b0a7a313a1b43de3780f5137b5920b97719db846784c3a7bf6 |
| overpth | ef90decf419520319b1867c98a5253f2f6adc7845660a3e35f58782545904a5e |
| evtlog_disable | 8939a8ac757883f89b67517f324a716831ca25b6d863d89ca09fe1c388ead694 |

### How the ground truth was built (tools/ext/win_build_gt.py, documentation only)

**APT29 day 1.**
- Steps, hosts and users come from the emulation plan (`apt29.xlsx` in Security-Datasets).
- Techniques and times come from OTRF ThreatHunter-Playbook step YAMLs (commit f7a58156, the last one before they were
  deleted).
- Granularity: one GT step per lettered emulation step (1.A … 10.B, 25 steps).
  - Technique = the step's first sub-step (`.1`), mapped from the legacy IDs to v20 (revoked-by), e.g. T1086 → T1059.001,
    T1122 → T1546.015, T1050 → T1543.003, T1107 → T1070.004.
  - Tactic = the plan stage, when that tactic is valid for the technique in v20. Otherwise, the first valid tactic in
    kill-chain order.
- Time = the earliest Sysmon `UtcTime` printed in OTRF's documented query output for the step.
  - One documented copy error was skipped: 4.A.1's output is 2.A's Draft.Zip, so a time earlier than the previous
    step was ignored.
  - 2.B and 10.B have no documented time. They use the midpoint of the window between the neighbouring documented steps
    (stated in `gt_notes`).
- The 78-sub-step file is a secondary, stricter view, scored with the same frozen harness into
  `eval_scorecard_substeps.json`. T1043 has no v20 successor and was dropped.

**Atomic sets.**
- Technique and tactic come from the dataset's metadata yaml. Host and user come from the documented adversary view
  (Empire agent table, target ComputerName).
- Time: the docs give no exact time. One raw event was located by a documented string from the metadata (e.g. the
  `comsvcs.dll, MiniDump` command, the 4624 LogonType 9 of over-pass-the-hash, the 7045/4697 service of invoke_psexec),
  and only its time was read. Each recording spans 0.5–2.3 min, so the ±10 min tolerance is never the deciding factor.
- Where the docs name no account (lsass_comsvcs, vbs_launcher, sharpwmi), the account of that anchor event was used.
  This is stated in each step's `gt_notes`.
- overpth: the metadata lists TA0005 and TA0008. TA0005 maps to v20 Stealth and is listed first, so GT tactic = Stealth.
- evtlog_disable: T1562.002 is absent from v20; it was mapped by name to T1685.001 (Disable or Modify Windows Event
  Log) in the v20 bundle.

## 1. Results (every run, as-is and converted)

"as-is" = the published JSON lines unchanged. "_conv" = `tools/ext/win_reshape.py`, which only changes structure:
- `@timestamp` moves to `TimeCreated.SystemTime`, or is renamed `_collector_timestamp` when `TimeCreated` exists;
- a `TimeCreated` string with no time zone is renamed `TimeCreatedLocal`;
- no value is added or changed.

| set | source | rows in | ok | dropped (reason) | wall s | peak RSS MB | episodes | incidents | det % | labels % | tech-only % | rebuilt % | FA strict % | FA lenient % | step prec % | step prec all % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| lsass_comsvcs | win_json | 184 | 183 | 1 (malformed_line 1) | 225.809 | 186.8 | 3 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| lsass_comsvcs_conv | win_json | 184 | 147 | 37 (malformed_line 1; missing_or_unparseable_timestamp 36) | 57.819 | 160.0 | 2 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| vbs_launcher | ecs_json | 2067 | 2065 | 2 (malformed_line 2) | 20.256 | 104.5 | 0 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| vbs_launcher_conv | win_json | 2067 | 2065 | 2 (malformed_line 2) | 103.3 | 180.0 | 4 | 1 | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 0.0 | 25.0 | 25.0 |
| runkeys | ecs_json | 40569 | 40104 | 465 (malformed_line 465) | 19.319 | 292.8 | 0 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| runkeys_conv | win_json | 40569 | 40104 | 465 (malformed_line 465) | 29.979 | 296.4 | 20 | 2 | 100.0 | 0.0 | 0.0 | 100.0 | 50.0 | 50.0 | 20.0 | 6.67 |
| psexec | ecs_json | 4348 | 4149 | 199 (malformed_line 199) | 13.48 | 101.0 | 0 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| psexec_conv | win_json | 4348 | 4149 | 199 (malformed_line 199) | 32.222 | 195.2 | 14 | 3 | 100.0 | 0.0 | 0.0 | 100.0 | 66.67 | 66.67 | 50.0 | 11.11 |
| sharpwmi | ecs_json | 2343 | 2259 | 84 (malformed_line 84) | 29.054 | 104.0 | 0 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| sharpwmi_conv | win_json | 2343 | 2259 | 84 (malformed_line 84) | 80.797 | 180.0 | 3 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| overpth | ecs_json | 10271 | 10270 | 1 (malformed_line 1) | 15.77 | 191.8 | 0 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| overpth_conv | win_json | 10271 | 10270 | 1 (malformed_line 1) | 24.882 | 177.7 | 3 | 1 | 100.0 | 0.0 | 100.0 | 100.0 | 0.0 | 0.0 | 50.0 | 50.0 |
| evtlog_disable | ecs_json | 6563 | 6558 | 5 (malformed_line 5) | 25.529 | 113.8 | 0 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| evtlog_disable_conv | win_json | 6563 | 6558 | 5 (malformed_line 5) | 31.78 | 167.0 | 1 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| apt29d1 | ecs_json | 196081 | 194898 | 1183 (malformed_line 1183) | 36.226 | 859.1 | 0 | 0 | 0.0 | None | None | 0.0 | None | None | None | None |
| apt29d1_conv | win_json | 196081 | 194898 | 1183 (malformed_line 1183) | 92.947 | 863.7 | 71 | 4 | 68.0 | 11.76 | 11.76 | 0.0 | 75.0 | 75.0 | 91.67 | 77.27 |

- `None` = the harness's denominator was 0 (no incidents or no matched steps).
- Singleton recall is null on every set (no noise file).
- **APT29 sub-step view** (`eval_scorecard_substeps.json`, 78 sub-steps): detection 23.08, labels 33.33, rebuilt 0.0,
  FA strict 75.0, step precision 100.0. 18 sub-steps matched, 6 with correct labels: 1.B.1, 1.B.2, 4.A.2, 7.B.4, 9.B.1,
  9.B.6.
- **DIAGNOSTIC** episode-level recall, before the gate (`episode_recall_diag*.json`, same match rule):
  - APT29: 23/25 steps (labels 3).
  - APT29 sub-steps: 28/78.
  - lsass_conv 1/1, sharpwmi_conv 1/1 (label wrong). The other conv sets match the scorecard.

### 1.1 Per-step results, atomic sets (converted runs; every as-is run detected nothing)

| set | GT step | detected (scorecard)? | rule / technique that matched | in right incident? | why not / note |
|---|---|---|---|---|---|
| lsass_comsvcs | T1003.001 CA, workstation5, wardog | no | `lsass_dump` T1003.001 + `sigma_a5a2d357` fired at Δt = 0 s | – | **gate**: "critical single-tactic component: top episode has 1 merged alert(s) < 5". As-is: alerts 16 h off (naive 12-hour TimeCreated read as UTC) |
| vbs_launcher | T1059.005 Exec | yes, label ok | `sigma_1e33157c` T1059 (Δt 0) | yes (rebuilt) | step precision 25 %: 3 more stager steps in the incident (attack activity, but not in GT) |
| runkeys | T1547.001 Persist | yes, **label wrong** | harness paired `sigma_78d5cab4` T1133 (Δt 180 s) | yes | `run_key_persistence` T1547.001 fired at Δt 1 s with **no user**: Sysmon EID 13 has no User field, so the harness cannot match it. 1 FA incident (WORKSTATION5$ machine-account activity) |
| psexec | T1021 LM, workstation6 | yes, **label wrong** | `new_admin_logon` T1078 Initial Access (Δt 0) | yes | `service_or_task` T1543 also fired. No rule labels remote service creation as T1021/T1569. 2 FA incidents: the SYSTEM stager launched by the service, seen once in Sysmon (user system) and once in 4688 (user workstation6$), not merged |
| sharpwmi | T1047 Exec, workstation6 | no | DIAGNOSTIC: `sigma_c260b6db` T1059 at Δt 1 s | – | `wmi_exec` needs a cmd/powershell child of wmiprvse.exe; the child was GruntHTTP2.exe. **gate** "fewer than 2 tactics, max confidence 75 < 90" |
| overpth | T1550.002 Stealth | yes, **label wrong (tactic only)** | `pass_the_hash` T1550 Lateral Movement (Δt 0) | yes (rebuilt) | technique-only labels = 100 %. The metadata lists both TA0005 and TA0008; the GT took the first |
| evtlog_disable | T1685.001 DI, Pedro01 | no | none | – | no rule for `HKLM\...\Services\EventLog\Start` = 4 (Set-Service) or the PowerShell command. The published TimeCreated/@timestamp is also **7 h off** Sysmon UtcTime (08:37Z vs 15:37Z) |

### 1.2 Per-step results, APT29 day 1 (converted run)

Matched incident `inc-4f663909` (SCRANTON, 23 episodes). The other incidents:
- `inc-494aaf0f`: NASHUA, the lateral-movement half of the same attack;
- `inc-3b7c3f83` and `inc-44e98050`: SCRANTON after the reboot, split by user `system` vs `scranton$`.

All three count as strict false alarms. LCS ratio 0.28, so not rebuilt.

| GT | step | GT technique | found? | pred technique (rule) | incident | label | miss cause |
|---|---|---|---|---|---|---|---|
| 1 | 1.A user executes RTLO .scr | T1204 | **missed** | – | – | – | missing rule (explorer → `.scr` with RTLO char / masquerade) |
| 2 | 1.B cmd → powershell | T1059 | found | T1059 (Sigma) Δt 159 s | main | **ok** | – |
| 3 | 2.A file discovery + Compress-Archive | T1083 | **missed** | – | – | – | missing rule (PowerShell 4104 ScriptBlockText is not an aliased field) |
| 4 | 2.B exfil over C2 | T1041 | **missed** | – | – | – | no host telemetry (OTRF: "no detection"); GT time is a window midpoint |
| 5 | 3.A monkey.png upload | T1105 | **missed** | – | – | – | missing rule (file write by the C2 process) |
| 6 | 3.B COM hijack + sdclt UAC bypass | T1546.015 | found | T1059 Δt 13 s | main | wrong | missing rule for HKCU\Software\Classes\Folder\shell\open\command. A Sigma T1548 episode existed at Δt 14 s (pre-gate) |
| 7 | 3.C delete hijack key | T1112 | found | T1059 Δt 28 s | main | wrong | missing rule (Sysmon 12 DeleteKey) |
| 8 | 4.A tools upload / expand | T1105 | **missed** | – | – | – | missing rule |
| 9 | 4.B Get-Process / kill pupy | T1057 | **missed** | – | – | – | missing rule (scriptblock only); pre-gate only a T1588 Sigma episode |
| 10 | 4.C recon script | T1083 | **missed** | – | – | – | missing rule (scriptblock / API) |
| 11 | 5.A new service | T1543.003 | **missed** | – | – | – | `service_or_task` T1543 fired Δt 1 s (user pbeesly) but is **not in any incident**: linking/gate |
| 12 | 5.B startup-folder payload | T1547.001 | found | T1587 Δt 415 s | main | wrong | right-technique Sigma episodes at Δt 1 s have **no user** (Sysmon 11): entity gap |
| 13 | 6.A browser creds (accesschk) | T1552.001 | found | T1048 Δt 349 s | main | wrong | Sigma T1552 episode Δt 24 s, no user: entity gap |
| 14 | 6.B private keys | T1552.004 | found | T1048 Δt 326 s | main | wrong | Sigma T1552 episode Δt 1 s, no user: entity gap |
| 15 | 6.C hash dump | T1003 | found | T1048 Δt 215 s | main | wrong | Sigma T1003 episode Δt −286 s, no user: entity gap |
| 16 | 7.A screenshot / clipboard / keylog | T1113 | found | T1059 Δt 89 s | main | wrong | missing rule (CopyFromScreen, System.Drawing load) |
| 17 | 7.B collect / 7z | T1005 | found | T1059 Δt 17 s | main | wrong | missing rule; `archive_staging` did not fire on SCRANTON |
| 18 | 8.A LDAP host discovery | T1018 | found | T1048 Δt 13 s | main | wrong | missing rule (powershell → DC:389) |
| 19 | 8.B python.exe via ADMIN$ to NASHUA | T1105 | found | T1059 Δt 60 s | NASHUA inc | wrong | missing rule (5145 / System writes .exe to ADMIN$) |
| 20 | 8.C PsExec with Pam's creds | T1078 | found | T1543 (`service_or_task`) Δt 1 s | NASHUA inc | wrong | 4624 type 3 pbeesly from 10.0.1.4 exists; `new_admin_logon` did not fire |
| 21 | 9.A rar.exe drop | T1105 | found | T1543 Δt 27 s | NASHUA inc | wrong | missing rule |
| 22 | 9.B powershell from python.exe | T1059.001 | found | T1059 Δt 384 s | NASHUA inc | **ok** | – |
| 23 | 9.C sdelete | T1070.004 | found | T1560 Δt 34 s | NASHUA inc | wrong | missing rule (sdelete / indicator_removal_files did not fire) |
| 24 | 10.A javamtsup service at boot | T1569.002 | found | T1021 (Sigma) Δt 46 s | reboot inc | wrong | separate incident (user system vs scranton$) |
| 25 | 10.B startup LNK at login | T1547.001 | found | T1059 Δt 94 s | main | wrong | GT time is a window midpoint; no right-technique episode |

- Scorecard: 17/25 steps "found" (68 %), but only **2 have the right label**. Most matches are Sigma
  T1059 / T1048 / T1543 episodes of the same PowerShell session that happen to fall inside ±10 min. The 68 % is the
  harness's number. It should not be read as 68 % of steps identified.
- **DIAGNOSTIC** (`tools/ext/win_tech_near.py`): 7/25 steps have an episode with the right parent technique within
  10 min on the right host; only 3 of those carry a user or IP.

## 2. Top misses, grouped by cause

1. **Format / ingest gap (blocks everything as-is).**
   - *Wrong source:* 7 of 8 published files are NXLog/Logstash flat JSON with `@timestamp`. `profile.py` checks
     `ecs_json` first and its `detect_any` contains `@timestamp`, so they are read as ecs_json. Only `ts` is filled:
     host, event_id, user and process are 100 % NULL (checked in the sharpwmi parquet), and there are 0 alerts. Result:
     detection 0 % on every as-is set, including APT29.
   - *Time-zone traps:*
     - lsass_comsvcs: `TimeCreated` "2020-10-18 07:49:39.776" is a 12-hour clock with no AM/PM and no zone. Read as
       UTC, it is 16 h off.
     - evtlog_disable: the published `TimeCreated`/`@timestamp` are 7 h behind Sysmon `UtcTime` (dataset defect).
     - After conversion, the 36 lsass Security rows with no UtcTime are dropped as `missing_or_unparseable_timestamp`
       (accounted).
   - **Ingest BUG (reproduced): `attacklens/db.py` `line_reader` passes `delim='\0'` in SQL.** DuckDB reads that as the
     two-character delimiter backslash + `0`, not NUL. So every line containing JSON-escaped `\\0`
     (registry `...\0000`, `DataStore\Machine\0\...`) is cut at that point and counted as `malformed_line`. The line is
     valid JSON (`json_valid` true; Python `json.loads` OK).
     - The count of lines containing `\\0` equals the malformed count exactly on every set: APT29 1183 (Sysmon 12/13 555/507,
       11 60, …), runkeys 465, psexec 199, sharpwmi 84, evtlog 5, vbs 2, lsass 1, overpth 1.
     - Accounting does record these rows. But the drop reason is misleading, and Sysmon registry telemetry (which
       run-key / COM-hijack rules need) is lost.
     - Repro: read_csv with `delim='\0'` on `{"k":"HKLM\\Class\\0000"}` gives `{"k":"HKLM\\Class\` (json_valid false);
       with `delim=chr(0)` the line is whole.
2. **Missing detection rule** (largest gap after conversion): APT29 steps 1, 3, 5, 8, 9, 10, 16–19, 21, 23; evtlog_disable;
   sharpwmi (WMI child not cmd/powershell). 18/25 APT29 steps have no right-technique episode at all.
   - Much of APT29's evidence sits only in PowerShell 4103/4104 ScriptBlockText / Payload, which no alias maps.
3. **Entity gap → wrong label.** Sysmon EID 11/12/13 carry no `User`, so right-technique episodes have user NULL. The
   harness needs host AND (user OR IP), so it pairs a co-timed episode of another technique instead: runkeys, APT29
   steps 12–15.
4. **Linking / gate suppressed it.**
   - The gate suppressed single-step atomic detections: lsass_comsvcs ("critical single-tactic, merged 1 < 5") and
     sharpwmi ("fewer than 2 tactics, conf < 90"). APT29: 37 components suppressed, all "fewer than 2 tactics"; 5.A's
     `service_or_task` episode was among them.
   - No lateral linking: `host_ip_map` = 0 (these logs have no host-IP field). R1 could not join NASHUA's 4624 from
     10.0.1.4 to SCRANTON, so APT29 split into 4 incidents. 3 count as false alarms (75 % strict) and rebuilt = 0.
   - Duplicate Sysmon EID 1 + Security 4688 of the same process yield two incidents differing only by user
     (`system` vs `<host>$`): psexec, APT29 reboot.
5. **Wrong technique label (rule exists, wrong ATT&CK ID):**
   - psexec remote service → `new_admin_logon` T1078 / `service_or_task` T1543 instead of T1021 / T1569.002;
   - APT29 10.A service execution → Sigma T1021.

## 3. Recommendations (owners: backend-builder for config/rules; test-engineer for tests)

1. **Fix `db.line_reader` delimiter:** use `delim=chr(0)` (or `E'\0'`), plus a fixture with `\\0000` in a JSON value.
   This recovers 1183 APT29 rows and 465 runkeys rows. No rule change needed.
2. **Source detection for NXLog / Logstash Windows JSON** (config/sources.yaml):
   - drop `@timestamp` from `ecs_json.detect_any`, or require `ecs.version` / `event.action` / `winlog.*`;
   - or add `win_json` detection on `EventID` + `Channel` / `SourceName` and order it before ecs_json;
   - add `$."@timestamp"` and `$.EventTime` (with `tz` unknown → prefer `UtcTime`) to `win_json.ts`, placing `UtcTime`
     before naive strings.
   - Then these files ingest as-is; today detection is 0 without the reshaper.
3. **Naive / 12-hour `TimeCreated`:** treat a zone-less `TimeCreated` as low-trust and prefer `UtcTime` (Sysmon) when
   present. Don't parse a naive string as UTC.
4. **User enrichment for Sysmon 7/10/11/12/13:** fill user from the EID 1 process create via `ProcessGuid` (DuckDB
   join, bounded). Closes the runkeys label and APT29 5.B / 6.A / 6.B / 6.C entity gaps.
5. **Host-IP map for Windows logs:** derive `host_ip` from Sysmon EID 3 `SourceIp` where `SourceHostname`/`Hostname`
   is the local host, or from Security 5156 `SourceAddress`. Enables R1 (SCRANTON 10.0.1.4 → NASHUA) so APT29 becomes
   one incident.
6. **New rules / aliases** (config/rules.yaml):
   - alias PowerShell `ScriptBlockText` / `Payload` (4103 / 4104) to a searchable field, and add scriptblock rules:
     Compress-Archive / ChildItem -Include (T1083 / T1560), Get-Process (T1057), CopyFromScreen / Get-Clipboard
     (T1113 / T1115), Set-Service EventLog Disabled (T1685.001);
   - `wmi_exec`: any non-system child of wmiprvse.exe (sharpwmi GruntHTTP2.exe);
   - registry: `Services\EventLog\Start` = 4 (T1685.001), HKCU `Classes\Folder\shell\open\command` / `DelegateExecute`
     (T1546.015 / T1548.002), Sysmon 12 DeleteKey of the same (T1112);
   - service created remotely (7045 / 4697 within N s of a 4624 type 3 from another host) → T1021.002 / T1569.002 rather
     than T1078 / T1543;
   - sdelete / file-deletion (T1070.004); file write to ADMIN$ via 5145 (T1021.002 / T1105).
7. **Process dedup:** merge Sysmon EID 1 and Security 4688 of the same process (host, ts ±2 s, image, command line)
   before episodes, keeping the non-machine user.
8. **Gate:** single-step, high-severity credential-access hits (lsass_dump, conf 90) are suppressed by "merged < 5".
   Consider admitting conf ≥ 90 Credential Access singletons, then measure the FA cost on g1 / n10 first.

## 4. Datasets, licences, tools (README third-party disclosure)

| item | source | licence |
|---|---|---|
| APT29 ATT&CK Evals day 1 host logs (`apt29_evals_day1_manual.zip`, 196 081 events) | github.com/OTRF/Security-Datasets `datasets/compound/apt29/day1` (master d9d40ef1) | MIT |
| APT29 emulation plan (`apt29.xlsx`) | OTRF/Security-Datasets `datasets/compound/apt29/emulationplans` | MIT |
| APT29 step documentation (79 YAMLs) | github.com/OTRF/ThreatHunter-Playbook `docs/evals/apt29/steps` @ f7a58156 | MIT |
| Atomic datasets SDWIN-201018195009 (lsass comsvcs), SDWIN-190518182022 (Empire VBS), SDWIN-190319023812 (Empire run keys), SDWIN-190518210652 (Empire PsExec), SDWIN-200806035621 (Covenant SharpWMI), SDWIN-190319131123 (Empire over-pass-the-hash), SDWIN-220708104215 (EventLog service disabled) + their metadata yaml | OTRF/Security-Datasets `datasets/atomic/windows/**`, `_metadata/` | MIT |
| Tools | curl, Python 3.12 stdlib (zipfile, xml.etree), DuckDB 2.0.0, PyYAML 6.0.3, psutil (already in the venv) | – |

- No new packages were installed.
- EVTX-ATTACK-SAMPLES was **not** done: python-evtx is not installed, and the shared venv / machine was RAM-constrained.
- Per-file sha256, sizes and row counts are in `data/raw/ext_win_<set>/SOURCE.md` (and `_conv/SOURCE.md` for the
  reshaped copies). Total download: about 58 MB.
- **Not evaluated:**
  - `empire_schtasks_creation_execution_elevated_user`: Windows Defender blocked reading the extracted file
    (Permission denied, ACLs fine). It was deleted, not bypassed, and replaced by the run-keys dataset.
  - APT29 day 2: downloaded, then removed. OTRF publishes step timestamps only for day 1, so a doc-derived GT was not
    possible.

## 5. Files

- Tools: `tools/ext/win_ziplist.py` (list / safe-extract zips), `win_xlsx_dump.py`, `win_otrf_steps.py`,
  `win_build_gt.py`, `win_source_md.py`, `win_reshape.py` (structure-only converter), `win_run.sh` (jobq; unused after
  the RAM stall), `win_run_direct.sh`, `win_collect.py`, `win_table.py`, `win_alerts.py`, `win_episode_recall.py` and
  `win_tech_near.py` (DIAGNOSTIC), `win_score_alt.py` (sub-step scorecard).
- Data: `data/raw/ext_win_<set>/` (`.dl/` downloads, `src/` logs, `ground_truth/`, `.logs/` run logs, `SOURCE.md`),
  `data/out/ext_win_<set>/`, `data/parquet/ext_win_<set>/`.
- Sets: lsass_comsvcs, vbs_launcher, runkeys, psexec, sharpwmi, overpth, evtlog_disable, apt29d1, each also `_conv`.
