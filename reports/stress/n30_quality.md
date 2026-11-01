# n30 data quality: firex-30G.log (new organiser extract), 2026-11-01, commit 6fbfe3c (dirty tree)

This report has only counts, sizes, offsets, percentages and vendor enums. It contains no raw log values.

## Pre-flight
| Item | Value |
|---|---|
| Machine | 16 GB RAM, shared with other agents |
| Free RAM | 371 008 KB at task start, 989 136 KB when the scans started, 2 265 212 KB at the end |
| Free disk on C: | 63 453 065 216 B at the start, 47 938 015 232 B at the end. Other sessions were writing at the same time. |
| Orphan jobs | An `attacklens.run` on n30 was still running at the start. I waited for it, without killing it, until it exited at 02:23:59 (rc 0). Per the orchestrator, I also held all n30 scans until `data/out/_logs/n30_run.rc` existed. `tools/qa/inject.py --keys n50` was still running throughout. It does not touch n30. |
| Fast tests | Not run. This task has no pipeline run, other sessions were running pytest, and the orchestrator asked me to keep CPU low. |
| Method | Every DuckDB connection used memory_limit 1GB, threads 2 and TimeZone UTC, with temp in `data/tmp/n30q`. The reader options are the same as `db.line_reader`. Stages: eventtime seconds (187.2 s), byte scan in Python (510.1 s), enums and key sets in one GROUP BY (1294.1 s), duplicates via `hash()` (49.1 s), top-second sub-seconds (92.6 s), duplicate split (165.5 s), and an exact line-level block layout in Python (97.7 s). |
| Aborted attempt | My first DuckDB pass was killed from outside after about 38 min (exit 137). I did not kill it. It saved nothing, so I redid the work as the resumable stages above. |

Not applicable: the §6.4 stage, RSS and accuracy table. No pipeline run was part of this task.

## Integrity
| Check | Byte scan | DuckDB |
|---|---|---|
| Size | 19 621 285 387 B | – |
| Physical lines (LF) | 37 183 090 | 37 183 090 rows read |
| Valid FortiGate kv lines (`logid=` and `type=`) | – | 37 183 090 (100 %) |
| Matching `line_regex` from sources.yaml | – | 37 183 090 (100 %) |
| Empty lines | – | 0 NULL rows |
| CR / CRLF | 0 / 0 | – |
| Lines over 64 KiB | 0. Max line is 673 B | max length 673 |
| NUL bytes / control bytes / invalid UTF-8 bytes | 0 / 0 / 0, so there are 0 bad regions (0 % of file) | – |
| File ends with LF | yes. There are 0 trailing bytes without LF. | – |
| Exact duplicate lines | – | **4 505 437 (12.12 %)** in 155 201 groups, using 64-bit `hash()`. The largest group has 240 308 lines. |
| Keys repeated within one line | – | 0 lines |
| Pipeline ingest_accounting.json (data/out/n30) | rows_in 37 183 090, rows_ok 37 183 090, dropped 0. This equals the LF count. | – |

**Compared with the old t30 copy (reports/stress/real_tiers.md)**
- The old corruption is gone:
  - The NUL tail from byte 4 294 967 296 to EOF (15 326 318 091 B, 78.1 %) is gone.
  - The 61 941 B NUL run at byte 2 441 416 203 is gone.
  - This copy has 0 NUL bytes.
- Valid lines rose from 8 138 878 in the old copy to 37 183 090 here.
- Distinct eventtime seconds rose from 1 in the old copy to 604 796 here.
- **But the n10-style pile-up block is present** (see Timestamps). Its layout is the same as in n10_quality.md:
  - It is one contiguous block running to EOF.
  - Its eventtime is clamped to the last second of the range.
  - Its duplicates sit only inside the block.

## Timestamps
| Item | Value |
|---|---|
| eventtime format | 19-digit ns epoch on 100 % of lines |
| tz | 1 distinct value, `+0530`, on 100 % of lines |
| eventtime − naive(date+time) | 0 s on 100 % of lines. So eventtime is **local time written as UTC**, and `eventtime_is_local: true` is correct. |
| Range (local-as-UTC) | 2026-10-23 08:48:37 → 2026-10-30 08:48:36 (604 799 s) |
| Range (true UTC = −5h30) | 2026-10-23 03:18:37 → 2026-10-30 03:18:36 |
| Distinct seconds | 604 796 |
| Single most common second | **26 113 539 lines (70.23 %)**. This is the last second of the range, local 2026-10-30 08:48:36. 26 113 525 of these lines have the sub-second part clamped to `.999999000`, and 14 have other sub-second values. |
| Most common second outside the block | 81 lines |
| Pile-up block layout | It is one contiguous run from byte 5 840 989 655 (line #11 069 552) to EOF: 13 780 295 732 B, 70.23 % of the file. There is 1 state change and 0 non-block lines after the block starts. |
| Gaps | There are 169 hourly buckets over a 169-hour span, so 0 hours are empty. The largest gap between consecutive distinct seconds is 2 s. |

**Events per 4 h (true UTC, 43 buckets; label = bucket start, MM-DD HH)**

| bucket | lines | bucket | lines | bucket | lines | bucket | lines |
|---|---|---|---|---|---|---|---|
| 10-23 00 | 26 095 | 10-24 12 | 364 007 | 10-26 00 | 286 033 | 10-27 12 | 364 597 |
| 10-23 04 | 140 243 | 10-24 16 | 192 733 | 10-26 04 | 106 463 | 10-27 16 | 192 715 |
| 10-23 08 | 619 210 | 10-24 20 | 106 362 | 10-26 08 | 492 525 | 10-27 20 | 106 540 |
| 10-23 12 | 416 625 | 10-25 00 | 285 611 | 10-26 12 | 364 855 | 10-28 00 | 285 839 |
| 10-23 16 | 192 670 | 10-25 04 | 106 598 | 10-26 16 | 192 681 | 10-28 04 | 106 323 |
| 10-23 20 | 106 479 | 10-25 08 | 492 838 | 10-26 20 | 106 175 | 10-28 08 | 504 398 |
| 10-24 00 | 285 803 | 10-25 12 | 364 959 | 10-27 00 | 285 558 | 10-28 12 | 364 410 |
| 10-24 04 | 107 442 | 10-25 16 | 193 165 | 10-27 04 | 106 730 | 10-28 16 | 192 680 |
| 10-24 08 | 492 753 | 10-25 20 | 106 735 | 10-27 08 | 492 324 | 10-28 20 | 106 265 |
| 10-29 00 | 285 040 | 10-29 08 | 492 503 | 10-29 16 | 192 849 | **10-30 00** | **26 378 079** |
| 10-29 04 | 107 399 | 10-29 12 | 363 859 | 10-29 20 | 105 922 | | |

- Before the block, the 11 069 551 lines follow a regular daily cycle. The peak hour holds 207 447 lines, at UTC 11.
- Bucket 10-30 00 holds the 26 113 539 lines of the block plus 264 540 normal lines.
- The 10-23 08 bucket (619 210) is higher than the same bucket on later days (about 492 k). 10-28 08 (504 398) is also slightly raised.

## Source diversity
| Field | Distinct values |
|---|---|
| devname / devid / vd | 1 / 1 / 1. All lines come from one firewall and one VDOM. |
| type | 3: traffic 23 804 137 (64.02 %), event 7 802 543 (20.98 %), utm 5 576 410 (15.00 %) |
| level | 5: notice 26 592 581, alert 6 313 319, information 3 595 579, warning 570 132, error 111 479 |
| logid | 16 (all listed below) |
| action | 19 (all listed below) |
| distinct key sets | 23 |

**type/subtype (all 12)**

| type/subtype | lines |
|---|---|
| traffic/forward | 23 804 137 |
| event/system | 5 880 799 |
| utm/webfilter | 1 674 592 |
| utm/dns | 1 117 823 |
| utm/app-ctrl | 1 113 487 |
| utm/ips | 1 113 381 |
| utm/virus | 557 127 |
| event/vpn | 556 491 |
| event/connector | 341 756 |
| event/dhcp | 341 653 |
| event/sdwan | 341 511 |
| event/ha | 340 333 |

**action (all 19)**

| action | lines |
|---|---|
| accept | 22 128 249 |
| login | 5 199 943 |
| pass | 2 231 310 |
| deny | 1 675 888 |
| passthrough | 1 506 826 |
| N/A | 1 363 732 |
| dropped | 890 780 |
| blocked | 724 890 |
| connect | 341 756 |
| perf-stats | 340 616 |
| negotiate | 222 693 |
| detected | 222 604 |
| ssl-login | 111 469 |
| install_sa | 111 265 |
| tunnel-stats | 111 060 |
| tunnel-up | 4 |
| Edit | 3 |
| Add | 1 |
| Delete | 1 |

**logid (all 16)**

| logid | lines |
|---|---|
| 0000000013 | 23 804 137 |
| 0100032002 | 5 199 938 |
| 0316013056 | 1 674 592 |
| 1501054600 | 1 117 823 |
| 1059028704 | 1 113 487 |
| 0419016384 | 1 113 381 |
| 0100032101 | 1 022 607 |
| 0211008192 | 557 127 |
| 0101037141 | 556 487 |
| 0102043008 | 341 653 |
| 0113022923 | 341 511 |
| 0105048901 | 340 333 |
| 0100032001 | 5 |
| 0101039947 | 4 |
| 0100044546 | 3 |
| 0100044547 | 2 |

**Event/system and VPN detail (vendor enums)**
- Admin logins:
  - "Admin login failed" (status failed): 5 199 938 lines.
  - "Admin login successful" (status success): 5 lines.
- Config changes: Edit 3, Add 1, Delete 1. The logdesc values are "Attribute configured" and "Object attribute configured".
- VPN:
  - ssl-login: 111 469 lines with **no status and no logdesc key**.
  - tunnel-up: 4 lines, with status success and logdesc "SSL VPN tunnel up".
  - Also present: negotiate 222 693, install_sa 111 265, tunnel-stats 111 060.
- The rare-event counts (5 successful logins, 4 tunnel-up rows, 5 config changes) are **identical to n10**. Every other count is about 3 times higher.

## Key inventory (49 keys) vs AttackLens mapping
- **Mapped and present.** These keys are in config/sources.yaml `fortigate_kv` fields, ts, actions and outcome_from_action:
  - date, time, eventtime, tz, devname, type, subtype, action, level, logdesc and status
  - srcip, srcport, dstip, dstport, sentbyte, rcvdbyte and service
  - user, ui, hostname, url, app, attack, virus, catdesc, severity, srcintfrole and dstintfrole
- **Mapped but absent (0 lines):** remip, tunnelip, tranip, trandisp, qname.

**Unmapped keys present in more than 0.1 % of lines (37 183 lines)**

| key | lines | % |
|---|---|---|
| logid | 37 183 090 | 100.00 |
| devid | 37 183 090 | 100.00 |
| vd | 37 183 090 | 100.00 |
| srccountry | 35 136 986 | 94.50 |
| dstcountry | 35 136 986 | 94.50 |
| proto | 35 136 986 | 94.50 |
| srcintf | 34 580 499 | 93.00 |
| dstintf | 34 580 370 | 93.00 |
| sessionid | 29 379 047 | 79.01 |
| policyid | 29 364 073 | 78.97 |
| sentpkt | 23 806 272 | 64.02 |
| rcvdpkt | 23 806 272 | 64.02 |
| duration | 23 787 293 | 63.97 |
| appcat | 14 197 080 | 38.18 |
| apprisk | 14 197 080 | 38.18 |
| msg | 7 802 543 | 20.98 |
| method | 5 199 948 | 13.98 |
| reason | 5 199 938 | 13.98 |
| attackid | 1 113 381 | 2.99 |

`crscore` is the only other unmapped key. It is on 550 lines (0.0015 %), which is below the threshold.

## Data problems that hurt detection
1. **Timestamp pile-up: 70.23 % of the lines share one second.**
   - Where: bytes 5 840 989 655 to EOF, 26 113 539 lines, with eventtime clamped to the last second of the range.
   - Effect: time windows, sequence order, burst counts and R1/R3 link windows cannot be trusted for these lines.
   - The 11 069 551 lines before the block already cover the full 7-day range with a normal daily cycle.
   - So the block is extra volume, 2.36 times the rest of the week. That reading is an inference: the original times cannot be recovered from the line.
2. **Exact duplicates: 12.12 % of the file.**
   - 4 505 437 lines in 155 201 groups. All of them are inside the block: 0 outside it and 0 groups mixed with lines outside.
   - Breakdown of the duplicate lines:
     - admin login: 3 469 104 (the 3 largest login groups have 10 085, 10 030 and 10 004 lines)
     - event/dhcp N/A: 240 307
     - event/sdwan N/A: 239 873
     - event/ha N/A: 239 022
     - event/system N/A: 238 800
     - VPN ssl-login: 78 316
     - all others: 15
   - Brute-force counts are therefore inflated: 3 469 104 of the 5 199 943 login rows are exact copies.
3. **VPN ssl-login rows carry no status.** None of the 111 469 rows has one. The sources.yaml ssl-login rules need status success or failed, so these rows get no login action.
4. **Unused fields that carry detection signal:**
   - `reason` (on every failed login)
   - `sessionid` (79 %)
   - `duration`, `sentpkt`, `rcvdpkt` (64 %: beaconing and exfil shape)
   - `proto`, `policyid`, `apprisk`, `attackid`, `method`
5. **Single source.** There is one devname, one devid and one vd. Entity diversity comes only from IPs and users, and there is no host or endpoint telemetry.

The integrity verdict is PASS: no NUL bytes, no invalid UTF-8, no lost lines, and 100 % of lines are kv-valid. The timestamp quality verdict is FAIL for 70.23 % of lines.

## Cleanup
- `data/tmp/n30q/` has been deleted: stage JSONs and the DuckDB temp directory.
- No files under `logs/` or `data/raw/` were modified.
