# Reliability run: OTRF PowerShell Remoting (WinRM)

## Summary
- **The assigned dataset could not be used.** Windows Defender blocked `empire_psremoting_stager` (OTRF SDWIN-190518211456).
  It flagged the extracted JSON as `VirTool:PowerShell/Empire.MM!MTB` (ThreatID 2147895685, 2026-11-01 10:59:22) and refused every read.
  The extracted file and the zip were deleted. Antivirus was not bypassed. No ground truth was written and no pipeline ran on it.
- **Replacement:** `covenant_psremoting_command` (OTRF **SDWIN-200806115603**, Covenant PowerShellRemotingCommand).
  It uses the same technique (T1021.006 over WinRM) in the same lab (WORKSTATION5 to WORKSTATION6, user pgustavo) and has no Empire stager.
  Set name: `rel_otrf_covenant_psremoting`.
- **Result: 0 % detection, 0 incidents.** Ingest worked: 4284/4284 rows, 0 dropped.
  Detection did see the attack: Sigma "Remote PowerShell Session Host Process (WinRM)" fired on WORKSTATION6 for pgustavo, 9 s after the GT time.
  But the incident gate suppressed it as single-tactic with confidence 55, and its label was Execution/T1059.001, not Lateral Movement/T1021.006.

## Dataset
| item | value |
|---|---|
| URL | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/covenant_psremoting_command.zip |
| docs | https://github.com/OTRF/Security-Datasets/blob/master/datasets/atomic/_metadata/SDWIN-200806115603.yaml |
| licence | MIT (OTRF/Security-Datasets) |
| zip | 359550 B, sha256 4a2e0f9688c87a90b17b608ff38fb2230ceb7305ea0368703dcfe53269e3f096, one member (path checked) |
| src file | covenant_psremoting_command_2020-08-06115603.json, 9592189 B, 4284 lines, sha256 2e749fa04bf44837d8bf78db303cdd1937b05e15f89f5cd67bb982f14f103de2 |
| documented techniques | T1021.006 with tactics TA0002 (Execution) and TA0008 (Lateral Movement) |

## Ground truth (frozen before the run)
`data/raw/rel_otrf_covenant_psremoting/ground_truth/attacks.json`, sha256 **1f7d551a2d88e71208b3bb3878167d83f0737a2bf42d42dbea7043b6b4e308f8**.

| step | ts (UTC) | technique | tactic | host | user | src_ip |
|---|---|---|---|---|---|---|
| 1 | 2020-08-06 15:56:13 | T1021.006 | Lateral Movement | WORKSTATION6.theshire.local | pgustavo | null |

- Built only from the metadata. I did not read any raw event to build it.
- The time is the documented "PowerShellRemotingCommand completed" line.
- The host is the documented `/computername` plus `/domain`.
- The docs list TA0002 but name no separate execution technique, so Execution is not a separate scored step.

## Run (frozen snapshot `data/snap/rel`, hash 159f2c2c6abf, memory_limit 1GB, threads 2)
- Free RAM was 506 MB at first, so the run waited. One 30 s poll later it was 949 MB and the run started.
- Exit code 0.

| metric | value (verbatim) |
|---|---|
| detection_pct | 0.0 |
| labels_pct | null |
| rebuilt_pct | 0.0 |
| false_alarms_strict_pct | null (0 incidents) |
| step_precision_pct | null |
| predicted_steps / gt_steps | 0 / 1 |
| total_wall_s | 26.075 |
| peak_rss_mb | 177.9 |
| incidents | 0 |

### Ingest accounting
| source_type | file | detected_by | rows_in | rows_ok | dropped | drop_reasons |
|---|---|---|---:|---:|---:|---|
| win_json | src/covenant_psremoting_command_2020-08-06115603.json | signature:EventID+Channel | 4284 | 4284 | 0 | {} |

- All rows had `ts_ok=true`, across 3 hosts: workstation6 3256 rows, workstation5 695, mordordc 333.
- The `.dl/` folder (zip and yaml) was skipped as a hidden directory (profile.py:39).

### Pipeline internals
- **Raw alerts: 5.**
  - `sigma_734f8d9b` "Remote PowerShell Session Host Process (WinRM)" fired 2 times: T1059/T1059.001, Execution, severity 55.
    The hits are Sysmon 1 at 15:56:22.486 and 4688 at 15:56:24.429, both wsmprovhost.exe on workstation6 with user pgustavo.
  - `sigma_93ff0ceb` "Scheduled Task Created - Registry" fired 3 times: T1053.005, Execution, severity 35.
    These are TaskCache SetValue events on workstation6 during Windows servicing. They are noise, not part of the attack.
- **Episodes: 3.** One link edge: R2 "Same session: pgustavo on workstation6, 1s apart".
- **Incidents: 0.** Both components went to `suppressed.json`:
  - {e37cc1f14a2, e0150e06d5b}: tactics [Execution], max confidence 55. Reason: "fewer than 2 tactics and max confidence 55 < 90".
  - {e6692e3ff08}: tactics [], max confidence 35. Reason: "fewer than 2 tactics and max confidence 35 < 90".

## Diagnosis of the missed step (step 1, T1021.006, WORKSTATION6, pgustavo)
I read the raw evidence only after the run.
It shows a clean WinRM attack:
- WORKSTATION5 `grunthttp.exe` (the Covenant implant, user pgustavo) connects to 172.18.39.6:5985 three times. These appear as Sysmon 3 and as WFP 5156 on both hosts.
- WORKSTATION5 logs 4648 explicit credentials for pgustavo.
- WORKSTATION6 logs 5 pairs of 4624 type 3 (Kerberos) plus 4672 for pgustavo, wsmprovhost.exe -Embedding (Sysmon 1 and 4688), and a 4103 `CommandInvocation(Get-Process)`.

| # | cause | evidence | where |
|---|---|---|---|
| 1 | **gate_or_link (primary)** | The correct host, user and time were detected (dt about 9 s, inside the 10 min tolerance). The only component is single-tactic with confidence 55, below critical 90, so it was suppressed. 0 incidents means the harness has no predicted step to match. | snap `backend/attacklens/incident_gate.py:201-209` (min_tactics 2, critical_confidence 90) |
| 2 | **wrong_label** | The Sigma rule 734f8d9b carries the tags `attack.execution, attack.lateral-movement, attack.t1059.001, attack.t1021.006`. The compiler takes the first tagged sub-technique (T1059.001) and the earliest tactic (Execution), so the WinRM host process is never labelled Lateral Movement/T1021.006. Even if the step had been kept, label_ok would be false. | snap `backend/attacklens/sigma_rules.py:280-309`. Config fix point: `config/sigma_map.yaml` `label_override` (line 453) |
| 3 | **missing_rule / threshold** (new_admin_logon) | WinRM opened 5 privileged type-3 logons (4624+4672, same logon_id) for (pgustavo, workstation6) within 12 s. `new_admin_max_pair_seen: 2` treats a pair with more than 2 privileged logons as routine, so the native T1021 template stayed silent. The 4624 also has `IpAddress '-'`, so src_ip is NULL. That would have given sub T1021.002, not .006, because the template picks the sub-technique from logon_type, not from the WinRM port. | snap `config/rules.yaml:36`; `detect_templates.py:266-321` |
| 4 | **missing_rule** (internal_lateral) | The 5985 connections exist only as host telemetry. The template reads only firewall `conn_allowed`. Sysmon 3 maps to `conn_out`, and WFP 5156 maps to action `other` with `dst_port` NULL, because the win_json `dst_port` aliases lack `DestPort` and the 5156 event id is not mapped. So `lateral_ports {5985: T1021.006}` is never applied. | snap `detect_templates3.py:17,52`; `config/sources.yaml:133` (dst_port aliases), `:1028` (3 -> conn_out) |
| 5 | **entity / link gap (source side)** | No alert fires on WORKSTATION5: 4648 explicit creds, implant `grunthttp.exe` connecting to 5985. The 4624 on the target has no source IP. So no cross-host R1 edge from WORKSTATION5 to WORKSTATION6 is possible, and a 2-tactic component never forms. | (no rule) |

## Takeaways
- Ingest of this OTRF Windows JSON is reliable: 0 drops, 0 timestamp failures, and the right source_type.
- Detection is close. It already sees the WinRM session on the right host and user within seconds.
  It fails on labelling (first Sigma tag wins) and on the gate (an atomic one-technique set never gets 2 tactics).
- Possible config-only fixes, for the owners to evaluate against the eval harness. None were applied here.
  - Add a `label_override` for Sigma 734f8d9b to T1021.006 / Lateral Movement.
  - Alias `DestPort`/`SourcePort`/`DestAddress`/`SourceAddress` for WFP 5156 and let internal_lateral accept host `conn_out` on lateral ports.
  - Review `new_admin_max_pair_seen` for multi-session WinRM bursts.
- The run cannot measure false alarms: there were 0 incidents, so `false_alarms_strict_pct` is null.

## Files
- `data/raw/rel_otrf_empire_psremoting/SOURCE.md`: record of the Defender block (metadata yaml kept).
- `data/raw/rel_otrf_covenant_psremoting/` (SOURCE.md, .dl/, src/, ground_truth/attacks.json)
- `data/out/rel_otrf_covenant_psremoting/` (eval_scorecard.json, run_metrics.json, ingest_accounting.json, source_profile.json, suppressed.json)
- `data/parquet/rel_otrf_covenant_psremoting/`
