# n10 data quality: firex-10G.log (new organiser extract), 2026-11-01, commit 6fbfe3c (dirty tree)

Only counts, sizes, offsets, percentages and vendor enums appear here. There are no raw log values.

## Pre-flight
| Item | Value |
|---|---|
| Machine | 12 logical CPUs, 16 GB RAM, shared with other agents |
| Free disk on C: at start | 54 888 419 328 B |
| Fast tests | 989 passed, 2 skipped, 3 xfailed in 341.79 s. That is over the 60 s budget, probably because the machine is loaded. |
| Method | Pass 1 was a chunked Python byte/line scanner with 2 processes (812.7 s). Pass 2 profiled the pile-up block, key sets and replay (952.2 s). An independent DuckDB `read_csv` cross-check used the same reader options as `db.line_reader` (memory_limit 1GB, threads 2, UTC) and took 82.4 s. |

Not applicable: the §6.4 stage, RSS and accuracy table. No pipeline run was part of this task.

## Integrity
| Check | Python scan | DuckDB |
|---|---|---|
| Size | 6 543 120 032 B | – |
| Physical lines (LF) | 12 398 551 | 12 398 551 rows read |
| Valid FortiGate kv lines (`logid=` and `type=`) | 12 398 551 (100 %) | 12 398 551 |
| Matching `line_regex` from sources.yaml | 12 398 551 (100 %) | 12 398 551 |
| Empty lines | 0 | 0 NULL |
| CRLF / inner CR | 0 / 0 | – |
| Lines over 64 KiB | 0. Max line is 673 B | max length 673 |
| NUL bytes / other control bytes / invalid UTF-8 lines | 0 / 0 / 0, so there are 0 bad regions (0 % of file) | – |
| File ends with LF | yes | – |
| Exact duplicate lines | **1 383 105 (11.16 %)** in 120 430 groups, using 64-bit blake2b | 1 383 119 using DuckDB `hash()`. The 14-line gap is probably hash collisions (estimate). |
| Keys repeated within one line | 0 lines | – |

**Compared with the old t10 copy (reports/stress/real_tiers.md)**
- The old binary tail is gone. The old copy had non-UTF-8 data from byte 4 815 675 121 and 17 336 449 NUL bytes. This copy has neither.
- The old copy had 9 125 382 valid lines. This copy has 12 398 551, which is 3 273 169 more.
- The pile-up block has **not** been fixed:
  - It starts at the same byte, 2 030 827 472 (line #3 848 244).
  - It has the same 3 848 243 lines before it.
  - It now runs to EOF and holds 8 550 308 lines. The old copy had 5 277 139.
- The distinct eventtime seconds (599 505) and the range (604 799 s) are identical to the old copy.

## Timestamps
| Item | Value |
|---|---|
| eventtime format | 19-digit ns epoch on 100 % of lines |
| tz | 1 distinct value, `+0530`, on 100 % of lines |
| eventtime − naive(date+time) | 0 s on 100 % of lines. So eventtime is **local time written as UTC**, and `eventtime_is_local: true` is correct. |
| Range (local-as-UTC) | 2026-10-23 08:48:26 → 2026-10-30 08:48:25 (604 799 s) |
| Range (true UTC = −5h30) | 2026-10-23 03:18:26 → 2026-10-30 03:18:25 |
| Distinct seconds | 599 505 |
| Single most common second | **8 550 308 lines (68.96 %)**. This is the last second of the range, local 2026-10-30 08:48:25, raw ns value `…105999999000` (clamped to .999999 s). |
| Most common second outside the block | 33 lines |
| Pile-up block layout | It is one contiguous run from byte 2 030 827 472 to EOF (4 512 292 560 B, 68.96 % of the file). Every line from that byte onward is in it, and there are only 2 state changes (non-block → block). In the block, 8 550 304 lines have the clamped ns value and 4 lines have other ns values in the same second. |
| Gaps (before the block) | 0 empty hours across the 169 hourly buckets. The largest gap between consecutive distinct seconds is 4 s. |

**Events per 4 h (true UTC, 43 buckets; label = bucket start, MM-DD HH)**

| bucket | lines | bucket | lines | bucket | lines | bucket | lines |
|---|---|---|---|---|---|---|---|
| 10-23 00 | 8 660 | 10-24 12 | 151 013 | 10-26 00 | 95 391 | 10-27 12 | 122 964 |
| 10-23 04 | 44 219 | 10-24 16 | 64 061 | 10-26 04 | 35 597 | 10-27 16 | 64 857 |
| 10-23 08 | 204 684 | 10-24 20 | 35 545 | 10-26 08 | 164 459 | 10-27 20 | 35 711 |
| 10-23 12 | 151 399 | 10-25 00 | 95 159 | 10-26 12 | 121 860 | 10-28 00 | 95 322 |
| 10-23 16 | 80 054 | 10-25 04 | 44 309 | 10-26 16 | 64 279 | 10-28 04 | 35 846 |
| 10-23 20 | 44 227 | 10-25 08 | 163 918 | 10-26 20 | 35 594 | 10-28 08 | 164 267 |
| 10-24 00 | 124 659 | 10-25 12 | 125 410 | 10-27 00 | 95 632 | 10-28 12 | 121 810 |
| 10-24 04 | 44 237 | 10-25 16 | 64 221 | 10-27 04 | 38 092 | 10-28 16 | 64 628 |
| 10-24 08 | 205 110 | 10-25 20 | 35 515 | 10-27 08 | 164 359 | 10-28 20 | 36 228 |
| 10-29 00 | 95 363 | 10-29 08 | 164 340 | 10-29 16 | 64 058 | **10-30 00** | **8 638 648** |
| 10-29 04 | 36 219 | 10-29 12 | 121 207 | 10-29 20 | 35 420 | | |

- Before the block, the 3 848 243 lines follow a regular daily cycle: the peak hour is about 69 k lines, at UTC 10–11.
- The hour UTC 10-30 03 holds 8 554 410 lines, of which 8 550 308 are the block.

## Source diversity
| Field | Distinct values |
|---|---|
| devname / devid / vd | 1 / 1 / 1. All lines come from one firewall and one VDOM. |
| type | 3: traffic 7 947 493 (64.10 %), event 2 596 430 (20.94 %), utm 1 854 628 (14.96 %) |
| level | 5: notice 8 864 918, alert 2 102 873, information 1 196 308, warning 197 391, error 37 061 |
| logid | 16 (all listed below) |
| action | 19 (all listed below) |

**type/subtype (all 12)**

| type/subtype | lines |
|---|---|
| traffic/forward | 7 947 493 |
| event/system | 1 957 947 |
| utm/webfilter | 555 143 |
| utm/dns | 372 222 |
| utm/app-ctrl | 371 517 |
| utm/ips | 371 360 |
| event/vpn | 185 283 |
| utm/virus | 184 386 |
| event/sdwan | 113 676 |
| event/ha | 113 388 |
| event/connector | 113 187 |
| event/dhcp | 112 949 |

**action (all 19)**

| action | lines |
|---|---|
| accept | 7 378 960 |
| login | 1 731 518 |
| pass | 743 739 |
| deny | 568 533 |
| passthrough | 499 878 |
| N/A | 453 164 |
| dropped | 297 257 |
| blocked | 239 648 |
| perf-stats | 113 273 |
| connect | 113 187 |
| negotiate | 74 245 |
| detected | 74 106 |
| install_sa | 37 081 |
| ssl-login | 36 982 |
| tunnel-stats | 36 971 |
| tunnel-up | 4 |
| Edit | 3 |
| Add | 1 |
| Delete | 1 |

**logid (all 16)**

| logid | lines |
|---|---|
| 0000000013 | 7 947 493 |
| 0100032002 | 1 731 513 |
| 0316013056 | 555 143 |
| 1501054600 | 372 222 |
| 1059028704 | 371 517 |
| 0419016384 | 371 360 |
| 0100032101 | 339 611 |
| 0101037141 | 185 279 |
| 0211008192 | 184 386 |
| 0113022923 | 113 676 |
| 0105048901 | 113 388 |
| 0102043008 | 112 949 |
| 0100032001 | 5 |
| 0101039947 | 4 |
| 0100044546 | 3 |
| 0100044547 | 2 |

**Event/system and VPN detail (vendor enums)**
- Admin logins:
  - "Admin login failed" (status failed, reason name_invalid): 1 731 513 lines.
  - The pile-up block holds 1 197 254 of the 1 731 518 action=login rows (69.1 %).
  - "Admin login successful": 5 lines.
- Config changes: Edit 3, Add 1, Delete 1. The logdesc values are "Attribute configured" and "Object attribute configured".
- VPN:
  - ssl-login: 36 982 lines with **no status, reason or logdesc key**.
  - tunnel-up: 4 lines, all with status success.
  - Also present: negotiate 74 245, install_sa 37 081, tunnel-stats 36 971.
- There are 23 distinct key sets in total.

## Key inventory (49 keys) vs AttackLens mapping
- **Mapped and present.** These keys are in config/sources.yaml `kv_sources.fortigate_kv` fields, ts, actions and outcome_from_action:
  - date, time, eventtime, tz, devname, type, subtype, action, level, logdesc and status
  - srcip, srcport, dstip, dstport, sentbyte, rcvdbyte and service
  - user, ui, hostname, url, app, attack, virus, catdesc, severity, srcintfrole and dstintfrole
- **Mapped but absent (0 lines):** remip, tunnelip, tranip, trandisp, qname.
  - DNS rows carry `hostname`, so dst_domain is still filled.
  - VPN rows have no remip, so src_ip falls back to srcip.

**Unmapped keys present in more than 0.1 % of lines (12 399 lines)**

| key | lines | % |
|---|---|---|
| logid | 12 398 551 | 100.00 |
| devid | 12 398 551 | 100.00 |
| vd | 12 398 551 | 100.00 |
| srccountry | 11 718 927 | 94.52 |
| dstcountry | 11 718 927 | 94.52 |
| proto | 11 718 927 | 94.52 |
| srcintf | 11 533 648 | 93.02 |
| dstintf | 11 533 519 | 93.02 |
| sessionid | 9 800 621 | 79.05 |
| policyid | 9 785 647 | 78.93 |
| sentpkt | 7 949 628 | 64.12 |
| rcvdpkt | 7 949 628 | 64.12 |
| duration | 7 930 649 | 63.96 |
| appcat | 4 738 154 | 38.22 |
| apprisk | 4 738 154 | 38.22 |
| msg | 2 596 430 | 20.94 |
| method | 1 731 523 | 13.97 |
| reason | 1 731 513 | 13.97 |
| attackid | 371 360 | 3.00 |

`crscore` is the only other unmapped key. It is on 550 lines (0.0044 %), which is below the threshold.

## Data problems that hurt detection
1. **Timestamp pile-up: 68.96 % of the lines share one second.**
   - Where: bytes 2 030 827 472 to EOF, 8 550 308 lines, with eventtime clamped to the last second of the range.
   - Effect: time windows, sequence order, burst counts and R1/R3 link windows cannot be trusted for these lines.
   - Example: 1 197 254 admin-login rows (the file has 1 731 513 failed and 5 successful) and 5 090 725 accepted forward sessions all fall in one second.
   - The 3 848 243 lines before the block already cover the full 7-day range with a normal daily cycle.
   - So the block is extra volume, 2.2 times the rest of the week, with its timestamps clamped to the range end. That reading is an inference: the original times cannot be recovered from the line.
   - The block's type/subtype mix matches the lines before it.
2. **Exact duplicates: 11.16 % of the file.**
   - 1 383 105 lines in 120 430 groups. All of them are inside the block (0 outside it), and 2 739 sit next to an identical line.
   - Counts in count-based rules (brute force, scan, exfil volume) are inflated by up to 16.2 % within the block.
   - After stripping date, time, eventtime and tz:
     - 1 432 914 block lines (16.76 %) have a body that also appears before the block.
     - The block has 7 167 201 distinct bodies across 8 550 308 lines.
3. **VPN ssl-login rows carry no status.** None of the 36 982 rows has one. The sources.yaml ssl-login rules need status success or failed, so these rows get no login action.
4. **Unused fields that carry detection signal:**
   - `reason` (name_invalid on every failed login: username guessing)
   - `sessionid` (79 %: session linking)
   - `duration`, `sentpkt`, `rcvdpkt` (beaconing and exfil shape)
   - `proto`, `policyid`, `apprisk`, `attackid`, `method`
5. **Single source.** There is one devname, one devid and one vd. Entity diversity comes only from IPs and users, and there is no host or endpoint telemetry.

The integrity verdict is PASS: no NUL bytes, no binary data, no lost lines, and 100 % of lines are kv-valid. The timestamp quality verdict is FAIL for 68.96 % of lines.

## Cleanup
- `data/tmp/n10q/` has been deleted: scan JSONs, hash buckets and the DuckDB temp directory.
- No files under `logs/` or `data/raw/` were modified.
