# Stress n10 (organiser 10G tier) — 2026-11-01 — commit 6fbfe3c + snapshot C:\alf3
Code: frozen snapshot C:\alf3 (commit 6fbfe3c + 133 uncommitted files; `diff -rq` against the repo found no differences in backend/attacklens or config right before the run).
Machine: Intel i5-13420H, 12 threads, 16 GB RAM. At start: free disk 44.93 GiB, CPU load 31 %, free RAM 3.17 GB (Win32 FreePhysicalMemory).
Input: 1 file, fortigate_kv, 6 543 120 032 B (6.094 GiB). No ground truth, so there is no eval_scorecard.json.
Pre-flight: fast suite green (989 passed, 2 skipped, 3 xfailed, 257.4 s). The suite ran in C:\cyberforge because the snapshot has no tools/.
Sources: data/out/n10/run_metrics.json, data/out/n10/ingest_accounting.json, work/raw_alerts.parquet, a 10 s sampler (data/out/n10_monitor.jsonl), and the API benchmark output.

| Stage | Wall s | Peak RSS MB | Rows/s |
|---|---|---|---|
| 0 profile | 3.073 | 842.7 | — |
| 1 ingest | 206.048 | 2504.8 | 60 173 (31.76 MB/s) |
| lookups | 11.397 | 1444.5 | — |
| 2 detect | 293.582 | 3115.8 | 42 232 |
| 2.5 episodes | 12.648 | 1212.0 | — |
| 3 link | 3.159 | 392.6 | — |
| 4 incidents | 5.095 | 498.6 | — |
| publish | 0.260 | 451.1 | — |
| **total** | **538.814** | **3115.8** | **23 010.8 (12.14 MB/s)** |
rc 0, error null, 0 WARNING/ERROR lines in the run log (31 lines).
Rows/s and MB/s are computed from rows and bytes divided by the stage wall time (ingest, detect) or taken from run_metrics `rows_per_s` (total).

Ingest accounting: fortigate_kv rows_in 12 398 551, ok 12 398 551, dropped 0 (0.000 %), quarantined 0, drop_reasons {}. rows_written 12 398 551. Parquet 1013 MB (15.5 % of raw).
DuckDB spill (temp_directory C:\alf3\data\spill): 0 B in all 30 samples. Free disk fell to 43.34 GiB at the lowest. Available RAM fell to 0.44 GiB at the lowest (system-wide). Mean CPU was 90.1 %.

Detection: 65 263 raw alerts in raw_alerts.parquet. This matches detect.raw_alerts. match_hits 2546. 11 rules fired and 31 rules gave 0 alerts.
| Rule id | Alerts |
|---|---|
| ips_blocked | 32 613 |
| ips_signatures | 16 705 |
| av_blocked | 11 050 |
| web_malicious_category | 2 543 |
| fw_admin_bruteforce | 1 078 |
| sigma_fa0c05b6 | 1 000 (capped; sigma_alerts_capped_by_rule 4 323) |
| fw_admin_spray | 258 |
| internal_lateral | 7 |
| beaconing | 4 |
| av_malware_download | 3 |
| port_scan | 2 |
Slowest rules (rule_seconds): port_scan 80.5, fw_admin_spray 63.2, sigma 46.0, ips_signatures 24.7, fw_admin_bruteforce 17.4, beaconing 12.1, exfil_volume 11.1. The rule_seconds add up to 292.2 s.
Sigma: sigma_rules_total 3779, sigma_rules_compiled 1657, sigma_rules_running 1642, sigma_rules_applicable 143, sigma_rules_fired 1, sigma_alerts 1000, sigma_alerts_deduped 0, sigma_wall_s 46.031, sigma_load_s 0.595, sigma_batches_failed 0, sigma_rules_failed 0, sigma_failed_rule_ids [], sigma_defense_evasion_mapped {}. sigma_rules_skipped_by_reason: unmapped_logsource 1090, unmapped_field 771, no_attack_technique_tag 253, below_min_level 14, keyword_search_unmapped 7, value_type 1, disabled 1.

Episodes: total 56 170, kept 25 000 (at the cap of 25 000), spilled 31 170 (55.49 %). seeds 280, kept_seed 280 (no seed spilled), kept_seed_neighbourhood 153 of 433, kept_fill 24 567.
episode_accounting: in_incidents 36, in_suppressed 24 964, missing 0, duplicated 0, ok true.
Link: 48 437 edges. By rule: R1 29, R2 47 416, R3 992. 232 hubs, 1 device, max_preds_per_rule 5.
Incidents: 10 915 components, largest 224, peeled_subcomponents 1, kept 1, suppressed 10 915 (fewer than 2 tactics 9 590, low confidence 1 325), kept_via_burst 0. Reach: flow_edges 90, admin_edges 0, ssh_edges 0. Narrative: template 1.

| Incident | Risk (raw) | Tactics | Techniques (backbone) | Backbone steps | Branches | Episodes | Merged alerts |
|---|---|---|---|---|---|---|---|
| inc-f513bc01 | 44 (12.17) | Reconnaissance, Initial Access, Credential Access, Lateral Movement | T1021.002 x5, T1190 x4, T1189, T1110, T1590.002 | 12 | 3 | 36 | 472 |
The incident spans 2 hosts on the backbone. 16 graph nodes, 17 edges (R2 15, R1 2). reach_next is empty.

API (temporary uvicorn on :8021, ATTACKLENS_OUT=data/out/n10):
| Endpoint | n | p50 ms | p95 ms | max ms |
|---|---|---|---|---|
| /api/incidents | 20 | 3.82 | 26.43 | 26.87 |
| /api/incidents/inc-f513bc01 | 20 | 3.77 | 27.00 | 28.18 |
| /api/incidents/inc-f513bc01/path | 200 | 15.07 | 27.50 | 34.77 |

Accuracy: not measured. There is no ground truth for organiser data, so detection, labels, rebuilt and FA are N/A.

Anomalies:
- Timestamp pile-up in the source data: 8 550 308 of 12 398 551 events (69.0 %) share one second (the max ts of the file). 21 015 of 65 263 alerts (32.2 %) fall in that same second. A 13.7 k-row sample showed one distinct raw date/time and one eventtime value, and ts_ok is true for all rows. So the parser reports the file as written and does not clamp. 5 of the 12 backbone steps are 0 s apart, and the R2 count (47 416) is probably inflated by this second (estimate, not measured).
- The incident has Initial Access steps (T1190, T1189) after Lateral Movement steps. Those steps come from ips_blocked or web_malicious_category alerts with confidence 3–22, on outbound traffic from internal hosts. The backbone order is time-based, and the T1190 label on outbound blocks looks semantically weak.
- Incident first_ts comes from a branch step and is 24 min earlier than backbone step 0. The narrative "started at" uses backbone step 0.
- One branch step has a dst_ip that differs from the dstip in its first evidence line (merged_alert_count 3). This may be correct for a merged group, but it is not verified.
- sigma_fa0c05b6 hit the per-rule cap (4 323 alerts dropped by the cap, counted).
- The sampler got 30 samples in 536 s, not 54, because of CPU contention while sampling. System available RAM fell to 0.44 GiB because other processes held memory. Pipeline RSS stayed at or below 3116 MB.
- The fast suite took 257 s, over the 60 s target.

Pass criteria (§6.3, 10G): ingest accounting 0 drops PASS. Wall 538.8 s < 900 s PASS. Peak RSS 3115.8 MB < 6.5 GB PASS. Path p95 27.50 ms < 50 ms PASS. Episodes spilled reported (31 170, 0 seeds). Accuracy and FA N/A (no ground truth).
Verdict: PASS (for the measurable checks).
