# Stress n30 (organiser 30G tier) — 2026-11-01 — run by session cyberforge-16 (read-only collection)
Provenance: this report does not come from a stress-tester run. Session cyberforge-16 ran `attacklens.run --raw data/raw/n30 --out data/out/n30` from the **live working tree** in C:\cyberforge (commit 6fbfe3c plus uncommitted changes). The code loaded at 01:35 IST (20:05:34Z) and it is **not** the frozen C:\alf3 snapshot. Other heavy jobs ran at the same time (tools/qa/mutate.py, tools/qa/inject.py --keys n50, several fast-suite pytest runs with QA CLI sub-runs, a qa_f1 pipeline run). The stress-tester only read its outputs, on the orchestrator's instruction, and wrote nothing into those folders.
Machine: Intel i5-13420H, 12 threads, 16 GB RAM. Conditions at the run's own start were not recorded, because the run was not ours. Observed at about 20:20Z, in mid-run: CPU load 96 %, free RAM 0.57 GiB (Win32 FreePhysicalMemory 592 880 KB), free disk 64 079 945 728 B. After the run: free disk 59 355 422 720 B.
Input: 1 file, fortigate_kv, 19 621 285 387 B (18.274 GiB). No ground truth, so there is no eval_scorecard.json.
Pre-flight: the stress-tester did not run the fast suite, because the orchestrator asked for no added load during the benchmark.
Sources: data/out/n30/run_metrics.json, data/out/n30/ingest_accounting.json, data/out/n30/work/raw_alerts.parquet, data/out/n30/incidents/*.json, data/out/_logs/n30_run.log (+ .rc, .start, .end), and the API probe output.

| Stage | Wall s | Peak RSS MB | Rows/s |
|---|---|---|---|
| 0 profile | 7.510 | 1086.3 | — |
| 1 ingest | 549.742 | 2745.5 | 67 637 (35.69 MB/s) |
| lookups | 38.847 | 4254.4 | — |
| 2 detect | 2236.830 | 3400.2 | 16 623 |
| 2.5 episodes | 43.042 | 1067.8 | — |
| 3 link | 6.043 | 562.6 | — |
| 4 incidents | 13.972 | 777.1 | — |
| publish | 1.305 | 741.2 | — |
| **total** | **2903.943** | **4254.4** | **12 804.3 (6.76 MB/s)** |
rc 0 (n30_run.rc), error null. The run log has 31 lines and none are WARNING or ERROR. start 2026-10-31T20:05:34Z, end 2026-10-31T20:54:04Z.
Rows/s and MB/s for ingest and detect are rows or bytes divided by stage wall time. The total row is run_metrics `rows_per_s`, with MB/s as bytes divided by total_wall_s (MB = 10^6 B).

Ingest accounting: fortigate_kv rows_in 37 183 090, ok 37 183 090, dropped 0 (0.000 %), quarantined 0, drop_reasons {}. rows_written 37 183 090. Parquet 3 163 628 951 B in 8 files (16.1 % of raw).
DuckDB spill: not sampled every 10 s, because the run was not ours. Its temp_directory resolved to C:\cyberforge\data\spill (the working-tree cwd). One reading, taken during detect at about 20:40Z, was 1.1 GiB (du). After the run it was 4 KB. Free RAM at about 20:40Z was 0.45 GiB (472 820 KB).

Detection: 125 779 raw alerts in raw_alerts.parquet. This matches detect.raw_alerts. match_hits 7534. 11 rules fired and 31 of 42 gave 0 alerts.
| Rule id | Alerts |
|---|---|
| ips_signatures | 50 642 |
| ips_blocked | 46 245 |
| av_blocked | 11 088 |
| web_malicious_category | 7 531 |
| fw_admin_spray | 5 175 |
| fw_admin_bruteforce | 4 088 |
| sigma_fa0c05b6 | 1 000 (capped; sigma_alerts_capped_by_rule 14 976) |
| beaconing | 4 |
| av_malware_download | 3 |
| port_scan | 2 |
| internal_lateral | 1 |
Slowest rules (rule_seconds): fw_admin_spray 722.653, port_scan 493.812, sigma 382.545, fw_admin_bruteforce 220.961, exfil_volume 141.680, beaconing 103.473, ips_signatures 36.148, match_scan 29.832, internal_lateral 24.237, ips_blocked 23.759, av_blocked 17.115, inbound_remote_service 13.479.
Sigma: sigma_rules_total 3779, sigma_rules_compiled 1657, sigma_rules_running 1642, sigma_rules_applicable 143, sigma_rules_fired 1, sigma_alerts 1000, sigma_alerts_capped_by_rule {sigma_fa0c05b6: 14976}, sigma_alerts_deduped 0, sigma_wall_s 382.491, sigma_load_s 0.535, sigma_batches_failed 0, sigma_rules_failed 0, sigma_failed_rule_ids [], sigma_defense_evasion_mapped {}. sigma_rules_skipped_by_reason: unmapped_logsource 1090, unmapped_field 771, no_attack_technique_tag 253, below_min_level 14, keyword_search_unmapped 7, value_type 1, disabled 1. Slowest sigma groups (group_s): network_connection+ 205.691 (22 127 887 tuples, 0 matched), network_connection 55.821 (18 115 803 tuples, 0 matched), firewall 48.897 (23 794 741 tuples, 0 matched), dns_query 26.966, antivirus 25.124 (557 127 tuples, 15 976 matched).

Episodes: total 85 061, kept 25 000 (at the cap of 25 000), spilled 60 061 (70.61 %). seeds 2563, kept_seed 2563 (no seed spilled), kept_seed_neighbourhood 13 906 of 16 469, kept_fill 8531.
episode_accounting: in_incidents 1054, in_suppressed 23 946, missing 0, duplicated 0, ok true.
Link: 26 921 edges. By rule: R1 7, R2 23 169, R3 3745. 232 hubs, 1 device, max_preds_per_rule 5.
Incidents: 11 174 components, largest 1021, peeled_subcomponents 48, kept 229, suppressed 10 993 (fewer than 2 tactics 9384, low confidence 1587, extracted path fails gate 22), kept_via_burst 0. Reach: flow_edges 89, admin_edges 0, ssh_edges 0. Narrative: template 229.

Incident summary (229 incidents):
- Risk: max 49, min 10, median 26. By band: 10–19: 52, 20–29: 95, 30–39: 63, 40–49: 19.
- Backbone steps: 1 step 61, 2 steps 76, 3 steps 47, 4 steps 30, 5 steps 7, 6 steps 3, 7 steps 4, 8 steps 1.
- Branches: 0 → 89, 1 → 97, 2 → 40, 3 → 3.
- Episodes per incident: max 11, sum 1054.
- Tactics per incident: 1 tactic 26, 2 tactics 60, 3 tactics 84, 4 tactics 47, 5 tactics 12.
- Incidents containing each backbone rule: sigma_fa0c05b6 223, ips_signatures 163, ips_blocked 65, web_malicious_category 4, beaconing 1, internal_lateral 1.
- Incidents containing each technique: T1204 223, T1190 101, T1110 59, T1210 47, T1590.002 32, T1071 14, T1189 4, T1071.001 1, T1021.002 1.
- reach_next is non-empty for 1 incident (inc-1c2b5b23).
- Time span: first_ts min 2026-10-23T03:27:03Z, last_ts max 2026-10-29T01:17:31Z.

Top 10 by risk, then raw risk:
| Incident | Risk (raw) | Tactics | Techniques (backbone) | Steps | Episodes | first_ts | last_ts |
|---|---|---|---|---|---|---|---|
| inc-22e26e89 | 49 (15.757) | Initial Access, Execution, Credential Access, Lateral Movement, Command and Control | T1210, T1071 | 2 | 5 | 2026-10-23T08:23:32Z | 2026-10-23T16:37:09Z |
| inc-afa3e5ae | 49 (15.508) | Reconnaissance, Initial Access, Execution, Lateral Movement, Command and Control | T1204 x2, T1210 x2, T1590.002 | 5 | 8 | 2026-10-23T06:36:23Z | 2026-10-23T18:11:33Z |
| inc-dca555d5 | 49 (15.192) | Initial Access, Execution, Lateral Movement, Command and Control | T1190 x2, T1210 x2, T1204, T1189, T1071 | 7 | 9 | 2026-10-23T08:02:19Z | 2026-10-23T19:36:51Z |
| inc-521fc8ef | 48 (14.571) | Initial Access, Execution, Lateral Movement, Command and Control | T1190 x2, T1210, T1204, T1071 | 5 | 6 | 2026-10-23T08:31:28Z | 2026-10-23T22:27:52Z |
| inc-fd35d0b2 | 47 (14.576) | Reconnaissance, Initial Access, Execution, Credential Access, Lateral Movement | T1110 x2, T1590.002 x2, T1190 x2, T1204, T1210 | 8 | 9 | 2026-10-23T08:35:46Z | 2026-10-23T13:37:54Z |
| inc-25551955 | 47 (14.542) | Reconnaissance, Initial Access, Execution, Lateral Movement, Command and Control | T1190 x2, T1204, T1210 | 4 | 7 | 2026-10-23T06:23:25Z | 2026-10-23T20:28:40Z |
| inc-30f2bee5 | 45 (14.462) | Reconnaissance, Initial Access, Execution, Credential Access, Command and Control | T1110, T1204, T1071 | 3 | 6 | 2026-10-23T09:55:50Z | 2026-10-23T14:47:41Z |
| inc-258bc46d | 44 (13.753) | Reconnaissance, Initial Access, Execution, Credential Access, Lateral Movement | T1204, T1110, T1190 | 3 | 8 | 2026-10-23T08:01:32Z | 2026-10-23T23:01:47Z |
| inc-bebb509e | 44 (13.214) | Reconnaissance, Initial Access, Execution, Credential Access, Lateral Movement | T1190 x2, T1110, T1204, T1210, T1590.002 | 6 | 10 | 2026-10-23T06:30:53Z | 2026-10-23T20:24:04Z |
| inc-74ac376b | 43 (13.715) | Initial Access, Execution, Credential Access, Lateral Movement | T1110, T1190, T1210, T1204 | 4 | 5 | 2026-10-23T10:26:57Z | 2026-10-23T12:02:45Z |
The full list of 229 incidents, with entities, is in the gitignored reports/stress/n30_pipeline_findings.md.

API (temporary uvicorn on :8021 from C:\alf3, ATTACKLENS_OUT=data/out/n30, GET only). The out dir file list, sizes and mtimes were the same before and after. The n50 run of cyberforge-16 was running during the probe.
| Endpoint | n | p50 ms | p95 ms | max ms |
|---|---|---|---|---|
| /api/incidents (229 items, 70 301 B) | 20 | 15.32 | 31.53 | 124.62 |
| /api/incidents/inc-22e26e89 | 20 | 8.32 | 36.04 | 239.66 |
| /api/incidents/inc-22e26e89/path | 200 | 3.57 | 28.48 | 722.46 |

Accuracy: not measured. There is no ground truth for organiser data, so detection, labels, rebuilt and FA are N/A.

Comparison with n10 (reports/stress/n10_pipeline.md; snapshot code, so not like-for-like):
- Rows ×3.00 (12 398 551 → 37 183 090).
- Ingest wall ×2.67 (206.0 → 549.7 s).
- Detect wall ×7.62 (293.6 → 2236.8 s).
  - fw_admin_spray ×11.4 (63.2 → 722.7 s).
  - port_scan ×6.1 (80.5 → 493.8 s).
  - sigma ×8.3 (46.0 → 382.5 s).
  - fw_admin_bruteforce ×12.7 (17.4 → 221.0 s).
- Incidents 1 → 229. Seeds 280 → 2563.

Anomalies:
- **Wall time over the 30G target.** 2903.9 s against 1800 s, and the input is only 18.27 GiB. Detect is 77 % of the wall time. Detect grew 7.6× while rows grew 3×. That points to superlinear cost in fw_admin_spray, fw_admin_bruteforce, port_scan and sigma. Some of the growth could be CPU contention from the overlapping jobs (CPU at 96–100 %, free RAM at or below 0.57 GiB when observed). The split between the two causes was not measured.
- **Incident count jumped from 1 (n10) to 229.** 223 of 229 contain sigma_fa0c05b6 (T1204, Execution). That rule hit its 1000-alert cap, and 14 976 alerts were dropped by the cap. The incident set depends on which 1000 alerts survive the cap.
- **Single-tactic incidents.** 26 incidents have only 1 tactic (Execution, all sigma_fa0c05b6), yet 9384 components were suppressed for "fewer than 2 tactics". 23 of the 26 have a single backbone step. 61 incidents in total have a single backbone step. Suspected stage: 4 incidents gate (not verified).
- **Incident tactics differ from backbone tactics.** For many incidents the tactics list has more entries than the backbone steps' tactics (for example 5 tactics with 1 backbone tactic). The extra tactics come from branches or merged alerts. Not verified.
- **Initial Access labels on outbound traffic.** T1190 appears in 101 incidents, from ips_signatures and ips_blocked, which is the same weak labelling noted at n10.
- **Peak RSS was in lookups, not detect.** lookups 4254.4 MB vs detect 3400.2 MB.
- **Sigma network groups.** network_connection+, network_connection and firewall scanned 64.0 M tuples in 310.4 s with 0 matches.
- **Some measurements were not possible.** Spill was not sampled at 10 s, and CPU, RAM and disk at the run's start were not recorded, because the run belonged to another session.

Pass criteria (§6.3, 30G):
- Ingest accounting, 0 drops: PASS.
- **Wall time 2903.9 s, target < 1800 s: FAIL.**
- Peak RSS 4254.4 MB, target < 6.5 GB: PASS.
- Path p95 28.48 ms, target < 50 ms: PASS.
- Episodes spilled: reported (60 061, 0 seeds spilled).
- Accuracy and FA: N/A (no ground truth).

Verdict: FAIL.
- Failing check: wall time.
- Suspected stage: 2 detect (fw_admin_spray, port_scan, sigma, fw_admin_bruteforce), possibly made worse by overlapping jobs.
- Next action: backend-builder profiles these rules at 30G, then a clean, uncontended rerun from the frozen snapshot.
