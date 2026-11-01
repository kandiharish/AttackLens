# Verification: rel_otrf_empire_psremoting (replaced by rel_otrf_covenant_psremoting)

Independent check, 2026-11-01. Verify outputs: `data/out/rel_otrf_empire_psremoting_verify/` (parquet under `parquet/` there).

## Verdict
- **The assigned set (SDWIN-190518211456, Empire Invoke PSRemoting) was never run.** It has no data and no GT. No accuracy number exists for it.
- **The Defender block is real.** `Get-MpThreatDetection` shows ThreatID 2147895685 at 2026-11-01 10:59:22, with the resource
  `data\raw\rel_otrf_empire_psremoting\src\empire_psremoting_stager_2020-09-20170827.json`. `Get-MpThreat` names it `VirTool:PowerShell/Empire.MM!MTB`.
  `src/` and `ground_truth/` are empty, and only the metadata yaml is left. That yaml's sha256 b0f5d293… matches upstream.
- **The replacement result (SDWIN-200806115603, Covenant PSRemoting) is confirmed.** The GT is justified, the run reproduces
  exactly, the data was run as published, and all three miss causes are correct.

## 1. Ground truth (replacement set)
- I re-downloaded the upstream metadata yaml and the zip. Both sha256 values match `.dl/` (c70d1699…, 4a2e0f96…).
- The zip has one member. It is byte-identical to `src/…115603.json` (sha256 2e749fa0…, 9592189 B, 4284 lines).
- The GT step is T1021.006 / Lateral Movement on WORKSTATION6.theshire.local, user pgustavo. Each field comes from the docs:
  `attack_mappings` T1021 sub 006, and `/computername:"WORKSTATION6" /domain:"theshire.local" /username:"pgustavo"`.
- The ts 1596729373000 is 2020-08-06 15:56:13 UTC, the documented "completed" line. The observed WinRM activity is 15:56:22–15:56:36, inside the 10 min tolerance.
- The docs list TA0002 but name no other technique, so one step is right. No documented step is missing.
- The GT was frozen before the run:
  - `attacks.json` mtime 11:07:21
  - zip downloaded 11:07:41
  - src extracted 11:08:22
  - run outputs from 11:09:38
  - sha256 matches the claim: 1f7d551a…f8.

## 2. Reproduction (same snapshot 159f2c2c6abf, free RAM 1384 MB at start)
- Exit 0. 4284/4284 rows, 0 dropped, 3 episodes, 0 incidents.
- `eval_scorecard.json` is identical to the original, apart from the GT path field. `ingest_accounting.json`, `suppressed.json` and `incidents_index.json` are byte-identical.
- Deterministic: yes. Only the time and memory numbers differ, as expected:
  - wall 39.8 s vs 26.1 s
  - peak RSS 153 MB vs 178 MB

## 3. Miss causes (checked against outputs and code)
- **gate_or_link: confirmed.**
  - `raw_alerts`: sigma_734f8d9b fired on workstation6 for pgustavo at 15:56:22.486 (Sysmon 1) and 15:56:24.429 (4688). That is 9.5 s after the GT ts.
  - The two alerts became episodes e37cc1f14a2 and e0150e06d5b, joined by an R2 edge.
  - `suppressed.json`: "fewer than 2 tactics and max confidence 55 < 90". This comes from `incident_gate.gate()`.
- **wrong_label: confirmed.**
  - The rule's tags are execution, lateral-movement, t1059.001, t1021.006.
  - `sigma_rules.labels()` picks the first sub-technique and the earliest tactic, which gives T1059.001/Execution.
  - `sigma_map.yaml` has no `label_override` for 734f8d9b.
- **missing_rule: confirmed.**
  - (a) There are 5 type-3 4624 logons for pgustavo on ws6 between 15:56:24.386 and 15:56:36.439. All have src_ip NULL.
  - (b) Sysmon 3 to 172.18.39.6:5985 is ingested as `conn_out`. 6 WFP 5156 rows carry `"DestPort":"5985"` in the raw line but are ingested as action `other` with dst_port NULL. The win_json dst_port aliases have no DestPort. internal_lateral reads only `conn_allowed`.
  - (c) WORKSTATION5 has five 4648 `explicit_creds` events for pgustavo and GruntHTTP.exe connecting to :5985. No rule uses them.

## 4. As published
- Yes. The source was extracted from the upstream zip unchanged (hash-identical). It was detected as `win_json` by `signature:EventID+Channel` and ingested with 0 drops.
