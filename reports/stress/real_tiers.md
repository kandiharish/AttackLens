# Run with Sigma on, 2026-10-31 (snapshot C:\alf2)

**Verdict: PASS on the checks that can be measured** (ingest accounting, wall time, peak RSS, API p95). Accuracy
checks are **n/a**: there is no ground truth, so there is no `eval_scorecard.json` and no accuracy number.

**Code under test**
- Frozen snapshot `C:\alf2`: git HEAD 6fbfe3c plus 117 uncommitted files, taken 2026-10-31T22:32:16+05:30
  (`C:\alf2\SNAPSHOT.txt`).
- `attacklens` was imported from `C:\alf2\backend\attacklens\__init__.py`. DuckDB 2.0.0, `memory_limit 5GB`.
- Sigma on (`config/pipeline.yaml` `sigma.enabled: true`, `min_level: low`, `max_alerts_per_rule: 1000`). 3 779
  rule files, compiled set loaded from the cache `data/cache/sigma/sigma_0474bb89dd203703.json` on all tiers.
- Command: `cd /c/alf2 && PYTHONPATH=backend python -m attacklens.run --raw <raw> --out C:\cyberforge\data\out\<rt> --parquet C:\alf2\data\parquet\<rt>`.
  No `--ground-truth`. Tiers ran one at a time.

**Fast suite in the snapshot: not fully green, for environment reasons only**
- Result: 560 passed, 2 skipped, 3 xfailed, 2 failed, 91 errors (262.9 s). 6 modules were not collected
  (`--ignore`) because they import `tools/` modules.
- Every failure and error is a missing file outside `backend/`, because the snapshot has no `frontend/` and no
  `tools/` folder:
  - `frontend/src/mock/incident.json`: 59 errors, plus the 2 failures (`test_contract`, `test_live`).
  - `tools/fortigate_gen.py`: 26 errors.
  - `tools/gen_dataset.py`: 8 errors.
- No product-code assertion failed.

**Machine and contention**
- Machine: same laptop as the section below (8 cores / 12 threads, 15.7 GiB RAM).
- Other agents were running on this machine the whole time: fast-suite pytest runs, two uvicorn on :8000 and vite
  on :5173. I did not touch :8000 or :5173.
- The API probe used a temporary uvicorn on :8021. It was stopped after each probe, and :8021 was free afterwards.

| at tier start | rt50 | rt10 | rt30 |
|---|---|---|---|
| UTC | 17:16:02Z | 17:18:36Z | 17:34:18Z |
| free RAM MB | 3 086 | 2 534 | 4 251 |
| CPU load % | 49 | 28 | 31 |
| foreign python > 50 MB | 1 pytest (172 MB) | 2 pytest (204, 82 MB) | 1 pytest (151 MB) |
| free disk C: bytes | 95 111 323 648 | 95 020 826 624 | 92 636 225 536 |
| spill dir `C:\alf2\data\spill` before / peak / after (bytes) | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |

- Spill was sampled every 5 s. No DuckDB spill was seen on any tier.
- Free RAM at the start was below the 5 GB DuckDB `memory_limit` on every tier.
- Free disk after rt30 was 91 806 273 536 bytes, never close to the 20 GB floor, so no Parquet was deleted.

**Input files**
- **"50 GB" tier (rt50):** the true size of `50g.txt` is **45 474 446 bytes (43.4 MiB)**, not 50 GB. It is a small
  text sample.
- firex-10G.log: 6 543 120 032 bytes.
- firex-30G.log: 19 621 285 387 bytes.

## Summary per tier (`run_metrics.json`, `ingest_accounting.json`)
| | rt50 (50g.txt) | rt10 (firex-10G.log) | rt30 (firex-30G.log) |
|---|---|---|---|
| bytes_in | 45 474 446 | 6 543 120 032 | 19 621 285 387 |
| rows_in (physical lines) / rows_ok / dropped | 85 937 / 85 936 / 1 | 22 453 023 / 9 125 382 / 13 327 641 | 8 138 881 / 8 138 878 / 3 |
| drop % of rows_in | 0.0012 % | **59.36 %** | 0.00004 % |
| drop reasons | unparseable_line 1 | decode_error (invalid UTF-8) 13 187 868; unparseable_line 139 773 | unparseable_line 2; line_too_long (> 16 777 216 bytes) 1 |
| quarantined (kept, ts_ok=false) / rows_written | 1 / 85 937 | 139 773 / 9 265 155 | 2 / 8 138 880 |
| total wall s (pipeline) / outer wall s | 60.398 / 61.251 | 336.702 / 337.612 | 222.439 / 223.120 |
| peak RSS MB (stage) | 206.8 (ingest) | 2 758.4 (ingest) | 2 444.6 (ingest) |
| rows/s (rows_in / wall) | 1 422.8 | 66 685.1 | 36 589.3 |
| read MB/s (bytes_in / wall) | 0.8 | 19.4 | 88.2 |
| raw_alerts rows / sum raw_alert_count | 2 395 / 3 773 | 59 534 / 1 476 419 | 23 773 / 1 980 442 |
| distinct alert ts_ms | 2 372 | 44 013 | **1** |
| episodes kept / spilled / total (seeds) | 2 382 / 0 / 2 382 (5) | 426 / **54 159** / 54 585 (277) | 14 390 / 0 / 14 390 (5) |
| link hubs / edges (by rule) | 158 / 1 447 (R2 1 447) | 232 / 1 273 (R1 29, R2 258, R3 986) | 232 / 51 138 (R2 51 138) |
| components / largest / kept / suppressed | 1 276 / 5 / 0 / 1 276 | 108 / 222 / 1 / 108 (1 peeled) | 1 389 / 13 / 0 / 1 389 |
| suppressed by reason | fewer than 2 tactics 1 274; low confidence 2 | fewer than 2 tactics 104; low confidence 4 | fewer than 2 tactics 184; low confidence 1 205 |
| episode accounting (missing / duplicated) | 0 / 0, ok | 0 / 0, ok | 0 / 0, ok |
| incidents | 0 | 1 | 0 |
| reach edges admin / flow / ssh | 0 / 0 / 0 | 0 / 90 / 0 | 0 / 0 / 0 |
| Parquet bytes | 7 963 068 | 794 113 285 | 667 968 836 |

## Per-stage wall s / peak RSS MB (`run_metrics.json` `stages`)
| Stage | rt50 | rt10 | rt30 |
|---|---|---|---|
| profile | 0.928 / 100.1 | 2.501 / 1 086.4 | 2.062 / 737.7 |
| ingest | 7.214 / 206.8 | 172.75 / 2 758.4 | 117.445 / 2 444.6 |
| lookups | 0.172 / 70.3 | 7.661 / 1 189.4 | 5.218 / 942.8 |
| detect | 50.874 / 162.7 | 140.674 / 2 424.8 | 93.879 / 2 218.8 |
| episodes | 0.173 / 179.2 | 10.193 / 722.8 | 1.226 / 402.0 |
| link | 0.216 / 179.2 | 0.973 / 382.1 | 0.982 / 387.4 |
| incidents | 0.17 / 140.4 | 1.163 / 375.0 | 1.068 / 347.8 |
| publish | 0.013 / 140.4 | 0.104 / 376.0 | 0.021 / 314.7 |
| **total** | **60.398 / 206.8** | **336.702 / 2 758.4** | **222.439 / 2 444.6** |

Detect share of wall time: rt50 84.2 %, rt10 41.8 %, rt30 42.2 %.

## Sigma (`stage_stats.detect` `sigma_*` keys and `stage_stats.detect.sigma`)
| key | rt50 | rt10 | rt30 |
|---|---|---|---|
| sigma_rules_total | 3 779 | 3 779 | 3 779 |
| sigma_rules_compiled | 1 707 | 1 707 | 1 707 |
| sigma_rules_running | 1 691 | 1 691 | 1 691 |
| sigma_rules_applicable | 112 | 143 | 112 |
| sigma_rules_fired | 1 | 1 | 1 |
| sigma_alerts (after cap) | 37 | 1 000 | 1 000 |
| rows_matched | 37 | 3 906 | 3 568 |
| sigma_alerts_capped_by_rule | {} | sigma_fa0c05b6: 2 906 | sigma_fa0c05b6: 2 568 |
| sigma_alerts_deduped | 0 | 0 | 0 |
| sigma_wall_s (load_s / scan_s) | 46.245 (43.68 / 0.954) | 38.655 (2.507 / 32.002) | 43.551 (22.636 / 18.576) |
| batches | 20 | 20 | 20 |
| sigma_defense_evasion_mapped | {} | {} | {} |

`sigma_rules_skipped_by_reason` was the same on all three tiers:

| reason | rules |
|---|---|
| unmapped_logsource | 1 090 |
| unmapped_field | 711 |
| no_attack_technique_tag | 262 |
| below_min_level | 15 |
| keyword_search_unmapped | 7 |
| unsatisfiable_without_unmapped | 1 |
| value_type | 1 |
| disabled | 1 |

The only rule that fired is `sigma_fa0c05b6`: SigmaHQ "Antivirus - Hacktool Signature", level high, T1204 (Execution).

## Alerts per rule (`work/raw_alerts.parquet`, rows / sum raw_alert_count)
| rule_id | technique | rt50 | rt10 | rt30 |
|---|---|---|---|---|
| ips_blocked | T1190 | 1 172 / 1 881 | 19 158 / 196 729 | 2 772 / 175 430 |
| ips_blocked | T1110 | 47 / 48 | 3 316 / 5 538 | 1 352 / 5 007 |
| ips_blocked | T1590 | 52 / 54 | 3 279 / 5 420 | 1 350 / 4 963 |
| ips_blocked | T1071 | 50 / 50 | 3 263 / 5 435 | 1 335 / 4 823 |
| ips_blocked | T1210 | 50 / 52 | 3 212 / 5 482 | 1 340 / 4 822 |
| av_blocked | T1105 | 837 / 1 324 | 11 050 / 135 620 | 1 386 / 122 635 |
| ips_signatures | T1190 | 75 / 75 | 6 857 / 6 857 | 6 060 / 6 060 |
| ips_signatures | T1590 | 9 / 9 | 1 423 / 1 423 | 1 220 / 1 220 |
| ips_signatures | T1210 | 13 / 13 | 1 388 / 1 388 | 1 220 / 1 220 |
| ips_signatures | T1071 | 9 / 9 | 1 378 / 1 378 | 1 232 / 1 232 |
| ips_signatures | T1110 | 12 / 12 | 1 346 / 1 346 | 1 190 / 1 190 |
| web_malicious_category | T1189 | 23 / 23 | 1 849 / 1 849 | 1 634 / 1 634 |
| sigma_fa0c05b6 | T1204 | 37 / 37 | 1 000 / 1 000 | 1 000 / 1 000 |
| fw_admin_bruteforce | T1110 | — | 741 / 358 427 | 525 / 509 735 |
| fw_admin_spray | T1110 | 9 / 186 | 258 / 742 841 | 157 / 1 139 471 |
| internal_lateral | T1021 | — | 7 / 7 | — |
| beaconing | T1071 | — | 4 / 4 412 | — |
| av_malware_download | T1105 | — | 3 / 3 | — |
| port_scan | T1595 | — | 2 / 1 264 | — |

## Incidents (no entity values; id and entities are in `rt10_findings.md`)
| tier | # | risk | tactics | technique ids | backbone / branch steps | episodes | merged alerts | path edges | reach_next | span | narrative |
|---|---|---|---|---|---|---|---|---|---|---|---|
| rt10 | 1 | 36 | Reconnaissance, Initial Access, Credential Access, Lateral Movement | T1021, T1110, T1189, T1190, T1210, T1590 | 10 / 7 (1 branch) | 35 | 323 | 16 (R1 2, R2 14) | 20 (all 1 hop, no crown jewel) | 94 549 s (26 h 16 min) | template |

- Rules in the rt10 incident: internal_lateral, ips_blocked, ips_signatures, web_malicious_category.
- Gaps: Execution, Persistence, Privilege Escalation, Stealth, Defense Impairment, Discovery.
- The backbone is time-ordered. Its step confidences are 3, 65, 65, 3, 65, 65, 65, 65, 65, 10.
- rt50 and rt30 have 0 incidents.

## API latency (temporary uvicorn :8021, `ATTACKLENS_OUT=<out>`, 1 warm-up excluded, all HTTP 200)
| endpoint | rt50 | rt10 | rt30 |
|---|---|---|---|
| 20 × `/api/incidents` p50 / p95 / max ms | 15.24 / 15.77 / 16.10 (2 B, empty) | 3.22 / 21.62 / 27.78 (343 B) | 15.47 / 17.12 / 26.86 (2 B, empty) |
| 20 × `/api/incidents/<top id>` p50 / p95 / max ms | n/a (0 incidents) | 3.22 / 27.48 / 27.83 (26 141 B) | n/a (0 incidents) |
| 200 × `/api/incidents/<top id>/path` (§6.2 step 5) | n/a | 15.25 / 16.98 / 27.48 (17 137 B) | n/a |

## §6.3 checks (real tiers, no ground truth)
| Check | rt50 | rt10 | rt30 |
|---|---|---|---|
| Ingest accounting: 0 unexplained drops | PASS (1, reason logged) | PASS (13 327 641, all with a reason, see below) | PASS (3, reason logged) |
| Wall time (< 60 / < 15 / < 30 min) | PASS 60.4 s | PASS 336.7 s | PASS 222.4 s |
| Peak RSS (< 8 / < 6.5 / < 6.5 GB) | PASS 206.8 MB | PASS 2 758.4 MB | PASS 2 444.6 MB |
| Detection / labels / rebuilt / strict FA | n/a (no GT) | n/a (no GT) | n/a (no GT) |
| API p95 < 50 ms | PASS 15.77 | PASS 27.48 (detail), 16.98 (path) | PASS 17.12 |
| Episodes spilled | 0 | **54 159** (reported, see anomaly 1) | 0 |

## File problems re-verified (my offset-only scan; counts and offsets only, no content read out)
**firex-10G.log**
- First non-UTF-8 line starts at byte **4 815 675 121** (73.6 %), confirmed. The binary tail is 1 727 444 911
  bytes (26.4 %).
- The first NUL byte is at **4 815 675 445**. The earlier report said 4 815 675 419, so this re-measurement differs
  by 26 bytes.
- The last valid key=value line starts at byte 4 815 674 550, confirmed.
- Line counts:
  - The file holds 15 848 039 LF, 6 711 606 CR bytes and 17 336 449 NUL bytes in 7 925 152 runs. The largest NUL
    run is 3 907 038 bytes.
  - LF-split lines in the tail: 6 646 811 are invalid UTF-8 and 3 374 417 contain NUL. The invalid UTF-8 count
    is 435 lower than in the earlier report. My scan checks only the first 1 MiB of each line, which probably
    explains the difference.
- **Valid key=value lines: 9 125 382, exactly rows_ok.**
- One eventtime second covers **5 277 139 lines (57.83 %)**, confirmed. That block starts at byte 2 030 827 472
  (valid line #3 848 244).
- Distinct eventtime seconds: 599 505. Range max − min: 604 799 s.

**firex-30G.log**
- NUL padding runs from byte **4 294 967 296 (2^32)** to EOF, 15 326 318 091 bytes (78.1 %), confirmed.
- A second NUL run of 61 941 bytes sits at bytes 2 441 416 203 – 2 441 478 144, confirmed. Total NUL bytes:
  15 326 380 032.
- 8 138 880 LF and 0 CR. The longest "line" is 15 326 318 664 bytes: the NUL tail has no LF.
- Valid key=value lines: 8 138 878, exactly rows_ok. The last one starts at byte 4 294 966 460.
- **Distinct eventtime seconds: 1** (100 % of valid lines), confirmed.

**50g.txt**
- 85 936 valid key=value lines, exactly rows_ok. 5 454 distinct eventtime seconds.
- 0 NUL and 0 invalid UTF-8.
- The 1 dropped line is the non-key=value first line (DEVELOPMENT.md §15.9).

**How the accounting handles the corruption (dropped with a reason, not silently lost)**
- `rows_in` is a byte-level count of physical non-empty lines, split like the DuckDB reader (LF, CRLF, lone CR)
  (`ingest.py` `scan_lines`).
- Lines the reader never writes to Parquet are counted as `rows_in − rows_written`. They are booked as
  `line_too_long` (over 16 777 216 bytes) up to the count of over-long lines, and the rest as `decode_error`.
- The `decode_error` count is therefore a **residual with a logged reason**. It is not a per-line observation.
- Lines that are read but cannot be parsed are kept in Parquet with `ts_ok=false, action=malformed` and counted
  as `unparseable_line`.
- rt10: 13 187 868 decode_error + 139 773 unparseable = 13 327 641 dropped. The independent scan finds exactly
  rows_ok valid lines, so **no valid line was lost**.
  - I did not reconcile the residual 13 187 868 line by line against my LF-based counts. **Estimate:** the gap
    comes from lone-CR splitting inside the binary tail.
- rt30: the 15.3 GB NUL tail is one line without LF. It is booked as 1 `line_too_long`. The before-run booked the
  same tail as 1 `decode_error`. The other 2 non-valid lines are `unparseable_line`. No valid line was lost.
- **No drop > 0.1 % without a logged reason on any tier.**
- rt10's 59.36 % drop is entirely file corruption. It is explained, but the demo should say it.

## Before (c76e212, section below) vs after (snapshot C:\alf2, Sigma on)
| key | t50s → rt50 | t10 → rt10 | t30 → rt30 |
|---|---|---|---|
| rows in / ok / dropped | unchanged (85 937 / 85 936 / 1) | unchanged (22 453 023 / 9 125 382 / 13 327 641) | unchanged (8 138 881 / 8 138 878 / 3) |
| drop reasons | unchanged | unchanged | decode_error 1 → **line_too_long 1** |
| total wall s | 11.292 → **60.398** | 564.161 → **336.702** | 250.163 → **222.439** |
| peak RSS MB | 261.2 → 206.8 | 4 338.2 (detect) → 2 758.4 (ingest) | 4 244.9 (detect) → 2 444.6 (ingest) |
| rows/s | 7 610.4 → 1 422.8 | 39 799.0 → 66 685.1 | 32 534.3 → 36 589.3 |
| ingest s | 6.597 → 7.214 | 198.983 → 172.75 | 133.507 → 117.445 |
| detect s / MB | 2.583 / 150.0 → 50.874 / 162.7 | 333.038 / 4 338.2 → 140.674 / 2 424.8 | 94.92 / 4 244.9 → 93.879 / 2 218.8 |
| raw_alerts rows / sum | 1 951 / 2 128 → 2 395 / 3 773 | 200 163 / 1 306 886 → 59 534 / 1 476 419 | 179 504 / 1 827 955 → 23 773 / 1 980 442 |
| sigma alerts | none (no Sigma in that build) → 37 | none → 1 000 (+2 906 capped) | none → 1 000 (+2 568 capped) |
| episodes kept / spilled / total (seeds) | 1 895 / 0 / 1 895 (5) → 2 382 / 0 / 2 382 (5) | 1 604 / 90 402 / 92 006 (307) → 426 / 54 159 / 54 585 (277) | 9 205 / 0 / 9 205 (5) → 14 390 / 0 / 14 390 (5) |
| link edges | 0 → 1 447 (R2) | 1 317 (R1 326, R3 991) → 1 273 (R1 29, R2 258, R3 986) | 0 → 51 138 (R2) |
| components / largest / kept / suppressed | 1 895 / 1 / 0 / 1 895 → 1 276 / 5 / 0 / 1 276 | 1 093 / 201 / 13 / 1 082 → 108 / 222 / 1 / 108 | 9 205 / 1 / 0 / 9 205 → 1 389 / 13 / 0 / 1 389 |
| incidents | 0 → 0 | **13 → 1** | 0 → 0 |
| top risk | n/a | 49 → 36 | n/a |
| path API p95 (200 × path) | n/a | 2.71 ms → 16.98 ms | n/a |

Most `av_malware_download` / `ips_signatures` alerts are now emitted as `av_blocked` / `ips_blocked`. For example,
on rt10 `av_malware_download` went from 135 623 to 3 rows, and `av_blocked` now has 11 050 rows carrying 135 620
raw alerts. The new rules merge more raw alerts into each row, so there are far fewer alert rows.

## Anomalies for the orchestrator
1. **rt10 episode spill keeps far fewer than the cap.**
   - Measured: 54 585 episodes is above `episode_cap` 25 000, yet only **426** were kept (0.8 %) and 54 159 spilled.
   - Cause: in spill mode, `episodes.py` keeps only episodes within `spill_hops` 2 / 24 h of the 277 seeds. It does
     not fill up to the cap.
   - Effect: the before-run's 13 incidents dropped to 1.
   - Suspected stage: Stage 2.5 episodes (spill policy). Owner: backend-builder.
2. **The only Sigma rule that fires, `sigma_fa0c05b6`, hits its per-run cap on rt10 and rt30.**
   - 2 906 of 3 906 matched rows (74 %) were discarded on rt10, and 2 568 of 3 568 on rt30. They are counted in
     `sigma_alerts_capped_by_rule`, not lost silently.
3. **Sigma `load_s` from cache varies a lot: 43.68 s (rt50), 2.507 s (rt10), 22.636 s (rt30).**
   - Every tier loaded the same cache file.
   - On rt50 this is 72 % of the 60.4 s wall time, so the 45 MB tier is now 5.3× slower than before (11.3 s → 60.4 s).
   - The cause is not measured. **Estimate:** contention with the concurrent pytest runs, or a cold file cache.
4. **Only 112–143 of 1 691 running Sigma rules apply to FortiGate data, and 1 fires.**
   - 1 090 rules are skipped for unmapped logsource and 711 for unmapped field.
5. **rt30 has one alert timestamp and no incidents.**
   - All 23 773 alert rows share 1 distinct ts_ms (constant eventtime in the file).
   - Linking now builds 51 138 R2 edges (0 before), but every component is suppressed: 1 205 low confidence,
     184 fewer than 2 tactics.
   - rt30 cannot show a time-ordered path. This is a data limit; I don't claim it as a code bug.
6. **The rt10 incident backbone includes 3 steps with confidence 3–10.** These are ips_blocked and ips_signatures
   steps. They need human review.
7. **`data/out/t10` and `data/out/t30` on disk were overwritten by a later run.** Their `run_metrics.json` shows
   425.051 s / 313.047 s with sigma keys present. They no longer match the "before" section below. The comparison
   above uses the numbers written in this file.
8. **Contention:** every tier ran next to other agents' pytest runs, with free RAM 2.5–4.3 GB at the start. The
   wall times include that contention.

## Files read
- `C:\cyberforge\data\out\rt50\run_metrics.json`, `ingest_accounting.json`, `work\raw_alerts.parquet`,
  `work\episodes_spilled.parquet`
- The same files under `C:\cyberforge\data\out\rt10\` and `C:\cyberforge\data\out\rt30\`, plus
  `C:\cyberforge\data\out\rt10\incidents\*.json`
- Run logs `C:\cyberforge\data\out\rt50_run.log`, `rt10_run.log`, `rt30_run.log`
- Gitignored findings (entity values): `reports/stress/rt50_findings.md`, `rt10_findings.md`, `rt30_findings.md`
  (`git check-ignore` confirmed: `.gitignore:16 reports/stress/*_findings.md`)

## Cleanup
- Kept Parquet: `C:\alf2\data\parquet\rt50` (7 963 068 B), `rt10` (794 113 285 B) and `rt30` (667 968 836 B).
  Free disk never came near 20 GB, so nothing was deleted.
- `data/raw/*` and `logs/` were not touched. The spill dir is empty. :8021 is stopped.

---

# Real tiers (FortiGate key=value) — 2026-10-31 — commit c76e212b9dae0284c1685933d3408b187ccc7db3

**No ground truth exists for these files, so no accuracy number is claimed here.** Detection, labels, rebuilt and FA are
measured only on synthetic data (DEVELOPMENT.md §15.9). The incidents below are "found", not scored, and need a
human review (`*_findings.md`).

Confidential data: this report holds counts, timings, byte offsets, rule/technique ids and incident ids only. No log
lines or fragments of them.

Code: frozen worktree `C:\cyberforge\.claude\worktrees\stress` at c76e212 (`attacklens` imported from the worktree's
`backend\attacklens\__init__.py`). Fast suite there: 487 passed, 2 skipped, 3 xfailed.
Machine: Intel64 Family 6 Model 186 (8 cores / 12 threads), 15.7 GiB RAM, 84 GB free on C: before, 83 GB after.
DuckDB 2.0.0, `memory_limit 5GB`.
Inputs are NTFS hard links (link count 2, no copies) in `data/raw/t50s`, `data/raw/t10`, `data/raw/t30`, pointing to
`C:\cyberforge\50g.txt`, `C:\cyberforge\logs\firex-10G.log` and `C:\cyberforge\logs\firex-30G.log`.
Runs were sequential, without `--ground-truth`.

## Summary
| | t50s (50g.txt sample) | t10 (firex-10G.log) | t30 (firex-30G.log) |
|---|---|---|---|
| bytes_in | 45 474 446 | 6 543 120 032 | 19 621 285 387 |
| rows in / ok / dropped | 85 937 / 85 936 / 1 | 22 453 023 / 9 125 382 / **13 327 641** | 8 138 881 / 8 138 878 / 3 |
| drop reasons | unparseable_line 1 | decode_error (invalid UTF-8) 13 187 868; unparseable_line 139 773 | unparseable_line 2; decode_error 1 |
| quarantined | 1 | 139 773 | 2 |
| total wall s | 11.292 | 564.161 | 250.163 |
| peak RSS MB | 261.2 | 4338.2 (detect) | 4244.9 (detect) |
| rows/s | 7 610.4 | 39 799.0 | 32 534.3 |
| raw_alerts rows / sum raw_alert_count | 1 951 / 2 128 | 200 163 / 1 306 886 | 179 504 / 1 827 955 |
| episodes kept / spilled / total (seeds) | 1 895 / 0 / 1 895 (5) | 1 604 / **90 402** / 92 006 (307) | 9 205 / 0 / 9 205 (5) |
| link hubs / edges | 158 / 0 | 232 / 1 317 (R1 326, R3 991) | 232 / 0 |
| components / largest / kept / suppressed | 1 895 / 1 / 0 / 1 895 | 1 093 / 201 / 13 / 1 082 | 9 205 / 1 / 0 / 9 205 |
| incidents | 0 | 13 | 0 |
| path API p50 / p95 / max | n/a (0 incidents) | 2.07 / **2.71** / 3.01 ms | n/a (0 incidents) |
| budgets: wall < 1 h, peak < 8 GB | met | met | met |

The t10 path probe used 200 × `GET /api/incidents/inc-79027bf3/path` (top risk 49, 5 725 bytes), with 1 warm-up excluded.
Suppression reasons were all "fewer than 2 tactics" (t50s 1 895, t10 1 082, t30 9 205).

## Per-stage wall s / peak RSS MB (`run_metrics.json`)
| Stage | t50s | t10 | t30 |
|---|---|---|---|
| profile | 0.72 / 100.4 | 1.958 / 837.3 | 1.786 / 826.4 |
| ingest | 6.597 / 261.2 | 198.983 / 2314.1 | 133.507 / 2442.1 |
| lookups | 0.146 / 69.4 | 10.411 / 1052.0 | 6.664 / 969.0 |
| detect | 2.583 / 150.0 | 333.038 / 4338.2 | 94.92 / 4244.9 |
| episodes | 0.174 / 164.5 | 15.622 / 1120.8 | 9.973 / 990.2 |
| link | 0.108 / 167.2 | 0.544 / 441.4 | 0.51 / 317.4 |
| incidents | 0.146 / 186.6 | 1.258 / 539.0 | 1.435 / 412.7 |
| publish | 0.019 / 186.6 | 0.161 / 539.4 | 0.014 / 412.7 |

## Alerts per rule (`work/raw_alerts.parquet`, rows / sum raw_alert_count)
| rule_id | technique | t50s | t10 | t30 |
|---|---|---|---|---|
| av_malware_download | T1105 | 1 324 / 1 324 | 135 623 / 135 623 | 122 635 / 122 635 |
| ips_signatures | T1190 | 348 / 348 | 34 231 / 34 231 | 30 089 / 30 089 |
| ips_signatures | T1110 | 60 / 60 | 6 884 / 6 884 | 6 197 / 6 197 |
| ips_signatures | T1210 | 65 / 65 | 6 870 / 6 870 | 6 042 / 6 042 |
| ips_signatures | T1590 | 63 / 63 | 6 843 / 6 843 | 6 183 / 6 183 |
| ips_signatures | T1071 | 59 / 59 | 6 813 / 6 813 | 6 055 / 6 055 |
| web_malicious_category | T1189 | 23 / 23 | 1 849 / 1 849 | 1 634 / 1 634 |
| fw_admin_bruteforce | T1110 | — | 748 / 358 469 | 512 / 509 649 |
| fw_admin_spray | T1110 | 9 / 186 | 258 / 742 841 | 157 / 1 139 471 |
| beaconing | T1071 | — | 35 / 5 192 | — |
| internal_lateral | T1021 | — | 7 / 7 | — |
| port_scan | T1046 | — | 2 / 1 264 | — |

t10 incidents (id, risk, episodes, merged alerts, tactic count):
- inc-79027bf3 49/10/10/4
- inc-5e7949d1 43/8/8/4
- inc-d0feb01e 38/13/13/3
- inc-a0bf5ca1 35/10/10/3
- inc-357698b5 31/16/689/2
- inc-58f52c34 28/2/2/2
- inc-03e62386, inc-ba279361, inc-d3b1d153, inc-b0679e85, inc-1211b1ce, inc-f0bc7eeb (risk 27 each)
- inc-dc992bab (risk 26)

The seven risk 26–27 incidents all start between 2026-10-24T20:34Z and 20:38Z. All 13 still need human review.

## Corruption findings (measured with offset-only scans; no content read out)
**firex-10G.log (6 543 120 032 bytes)**
- **Binary tail:** the first non-UTF-8 line starts at byte **4 815 675 121** (73.6 % into the file). The first NUL
  appears at byte 4 815 675 419. The last valid key=value line starts at byte 4 815 674 550. So the last
  1 727 444 911 bytes (26.4 %) are binary.
  - In newline-split lines, 6 647 246 lines in that region are invalid UTF-8 and 3 374 417 contain NUL.
  - The pipeline counted 13 187 868 `decode_error` rows plus 139 773 `unparseable_line` rows (quarantined). The file
    holds 6 711 606 CR bytes. **Estimate:** the reader also splits on CR, which would explain why its count is about
    2× the newline count. Not verified.
  - Valid key=value lines: 9 125 382, exactly the pipeline's rows_ok. **No valid line was lost**; every drop is in
    the binary tail and has a logged reason.
- **Constant timestamp (not expected in 10G):** 5 277 139 of the 9 125 382 valid lines (57.8 %) carry the same
  eventtime second, 1793350105 (2026-10-30T08:48:25Z). The block runs from byte **2 030 827 472** (valid line
  #3 848 244) to the last valid line at byte 4 815 674 550. Sampled date/time fields inside the block are also one
  value. Only the first ~42 % of the valid lines have real time spread.
- 58.7 % of rows_in were dropped. This is "explained" under the CLAUDE.md rule (every drop has a reason), but it is
  far above 0.1 % and comes entirely from file corruption.

**firex-30G.log (19 621 285 387 bytes)**
- **NUL padding:** one NUL run from byte **4 294 967 296** (exactly 2^32 = 4 GiB) to EOF, 15 326 318 091 bytes
  (78.1 % of the file). A second NUL run of 61 941 bytes sits at bytes **2 441 416 203 – 2 441 478 144**, inside a
  line. Total NUL bytes in the file: 15 326 380 032. Newlines: 8 138 880; longest line 62 415 bytes. The 3 dropped
  rows are this corruption (2 unparseable, 1 decode_error). The real content is the first 4 GiB only.
- **Constant timestamp:** all 8 138 879 eventtime values are the same second, 1793350116 (2026-10-30T08:48:36Z), from
  byte 36 to byte 4 294 966 753. That is 11 s after the 10G constant.
  - **Effect (measured):** 0 link edges and 0 incidents. All 9 205 episodes are single-episode components.
  - **Likely cause (not verified):** with no time spread, the time-windowed rules and links can't order anything.

**50g.txt (45 474 446 bytes):** 1 unparseable line (§15.9: line 1 is a URL). Otherwise clean, but 0 link edges and
0 incidents at this size.

## Anomalies for the orchestrator
- t10 spilled **90 402 of 92 006 episodes**; only 1 604 were kept for linking. Episodes on real data run about 3.7×
  over the 25 000 Python budget before the spill cap. The spill keeps memory bounded, but most episodes never reach
  linking.
- t10 detect is the slowest stage: 333.0 s, 59 % of wall time, at peak 4338.2 MB. On t30 it takes 94.9 s on a similar
  row count.
- fw_admin_spray / fw_admin_bruteforce merge very large raw counts: t30 1 139 471 raw alerts into 157 rows. That
  burst collapse likely comes from the constant timestamp.
- Because of the constant timestamps, t30 (and 57.8 % of t10) cannot show a time-ordered attack path. The demo
  narrative should say this rather than claim a path.

## Contention
- 13:03Z, before t50s: a foreign python job (pid 29604, about 1.26 GB) and two foreign fast-suite pytest runs (about
  130 MB each) were running; 2.2 GB available. t50s is small (11 s), so I didn't wait. t10 started at 13:03:58Z; its
  start conditions were not sampled separately.
- 13:16Z, after t10 / before t30: 5.1 GB available, no foreign python above 20 MB.
- 13:20Z, after t30: foreign `fwbench.py gen` (518 MB) and two pytest runs (143–170 MB). They may have overlapped
  the end of t30.

## Files
- `C:\cyberforge\data\out\t50s\`, `C:\cyberforge\data\out\t10\`, `C:\cyberforge\data\out\t30\`. Each holds
  `run_metrics.json`, `ingest_accounting.json`, `incidents_index.json`, `suppressed.json`, `work\raw_alerts.parquet`
  and run logs `C:\cyberforge\data\out\t*_run.log`. There is no `eval_scorecard.json` because there is no ground truth.
- Findings (`tools/review_findings.py --redact-ips`): `C:\cyberforge\reports\stress\t50s_findings.md`,
  `t10_findings.md`, `t30_findings.md`. 0 public IPs. t10 lists 11 internal IPs as entity ids. No key=value fragments
  (grep-checked). These files are NOT gitignored.

## Cleanup
Deleted `data/parquet/t50s` (7.6 MB), `data/parquet/t10` (758 MB) and `data/parquet/t30` (638 MB). Kept the out
dirs and the hard links in `data/raw/t*` (they take no extra space; deleting them removes only the links). The
:8011 server is stopped and the port is free.
