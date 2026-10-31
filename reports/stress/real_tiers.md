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
