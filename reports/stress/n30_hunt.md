# n30 independent hunt (counts, ids and tactics only)

Entity values are in the gitignored `reports/stress/n30_hunt_findings.md`. This file has no IPs, users, hosts, URLs or raw values.
The AttackLens pipeline and its outputs were not used.

## Input and extraction
- Raw file: 19,621,285,387 B. Parquet has 37,183,090 rows, 0 unparsed (all have date, logid and type), 0 duplicate keys.
- Extraction: DuckDB regexp_extract_all over 61 keys at memory_limit=1GB, threads=2 (the machine was shared).
  - The first single-pass attempt ran out of memory after 19 min (Parquet row groups of 500k rows). The retry with 100k-row groups was killed from outside after 18 min.
  - The final run copied 19 newline-aligned chunks of about 1 GiB and wrote one Parquet part each, resumable. Part 0 took 6.5 min and parts 1-18 took 60.1 min. Parquet is 1,330,775,226 B in total.
- Time span: 2026-10-23 08:48:37 to 2026-10-30 08:48:36 (wall clock, tz +0530).
- **Filler block:** 26,113,539 rows (70.2 %) all share the last second of the file. They are only the background mix. All hunt queries exclude that second; 11,069,551 rows remain.
- One device and one tz value. The only key outside the 61 extracted is `crscore` (550 rows).

## Attack steps (28 steps, 24,139 events outside the filler)
| n | first | last | technique | tactic | what | count | conf |
|---|---|---|---|---|---|---|---|
| 1 | 10-23 10:22:31 | 10-23 11:37:23 | T1071.004 (+T1048) | Command and Control | DNS tunnelling: 1,500 unique 40-char subdomains under one domain | 1,500 | high |
| 2 | 10-23 15:22:12 | 10-23 15:32:12 | T1498.002 | Impact | DNS reflection: 4,000 denies of 3.0-4.1 KB to the firewall's WAN IP | 4,000 | high |
| 3 | 10-23 16:31:42 | 10-29 06:47:31 | T1071.001 | Command and Control | HTTPS beacon every 300 s (+/- 8 s) | 1,612 | high |
| 4 | 10-24 02:44:29 | 10-24 02:45:12 | T1046 | Discovery | port scan of ports 1-240, all denied (chain A) | 240 | high |
| 5 | 10-24 03:00:16 | 10-24 03:04:12 | T1190 | Initial Access | SQL injection: 6 passed (detected), 54 dropped (chain A) | 60 | high |
| 6 | 10-24 03:34:42 | 10-24 03:54:12 | T1505.003 | Persistence | web-shell access: 4 script files in upload/tmp paths (chain A) | 40 | high |
| 7 | 10-24 08:05:32 | 10-24 08:32:23 | T1021.001, T1021.002 | Lateral Movement | LAN host does 6 rounds over 30 DMZ hosts, alternating RDP and SMB | 180 | high |
| 8 | 10-24 09:55:11 | 10-26 08:29:58 | T1039 (+T1021.002) | Collection | LAN host reads SMB from 59 DMZ hosts; 4,929,907,509 B received | 2,400 | high |
| 9 | 10-24 11:02:15 | 10-24 13:32:00 | T1041, T1048 | Exfiltration | web server sends about 20.5 KB every 15 s; 12,310,695 B (chain A) | 600 | high |
| 10 | 10-24 11:45:48 | 10-24 11:55:01 | T1190 | Initial Access | SQL injection: 20 passed (detected), 200 dropped | 220 | medium |
| 11 | 10-24 17:57:59 | 10-27 18:25:01 | T1567.002, T1030 | Exfiltration | DMZ host sends about 20.5 KB every 90-170 s; 40,969,278 B | 2,000 | medium |
| 12 | 10-25 09:26:11 | 10-25 09:35:18 | T1110.003 | Credential Access | admin password spray from one /24: 29 failures, 28 sources, 17 usernames (chain C) | 29 | high |
| 13 | 10-25 09:35:41 | 10-25 09:35:41 | T1078 | Initial Access | admin login success from a spray source, 2 min after its own failure; the source is not the user's VPN home (chain C) | 1 | high |
| 14 | 10-25 15:38:24 | 10-25 15:47:00 | T1190 (attempt) | Initial Access | XSS attempts against the web portal, all dropped | 60 | low |
| 15 | 10-26 19:43:44 | 10-26 20:05:03 | T1133, T1078 | Initial Access | SSL VPN user's tunnels alternate between the home source and a new-country source | 4 | medium |
| 16 | 10-26 20:05:47 | 10-27 02:00:43 | T1110.003 (failed) | Credential Access | second admin spray from another /24: 90 failures, 72 sources, 51 usernames; no success | 90 | medium |
| 17 | 10-27 08:47:22 | 10-27 08:51:22 | T1204.002, T1105 | Execution | malicious archive download flagged as detected but **not blocked** (chain B) | 3 | high |
| 18 | 10-27 08:47:39 | 10-27 08:57:23 | T1190 | Initial Access | command injection: 11 passed, 44 dropped | 55 | medium |
| 19 | 10-27 09:40:22 | 10-28 18:55:22 | T1071.001 | Command and Control | beacon every 300 s exactly to the step-17 server (chain B) | 400 | high |
| 20 | 10-27 15:09:13 | 10-27 15:26:02 | T1566.002, T1204.002 | Initial Access | repeated malicious executable download, blocked every time | 12 | medium |
| 21 | 10-28 06:13:50 | 10-28 06:24:37 | T1136.001, T1078, T1070.009 | Persistence / Stealth | the step-13 admin creates a new admin, logs in with it 5 min later, deletes it 5 min after that (chain C) | 3 | high |
| 22 | 10-28 09:04:06 | 10-28 12:53:25 | T1685, T1686 | Defense Impairment | admin turns disk logging off, purges the firewall policy, turns logging back on. No login event, and the source is new for that user | 3 | high |
| 23 | 10-28 14:55:53 | 10-28 17:52:09 | T1505.003 | Persistence | the same 4 web-shell paths as step 6, from a different source | 120 | high |
| 24 | 10-28 15:18:19 | 10-28 15:27:20 | T1498.001 | Impact | flood of 44-byte denies from 8,409 sources in one /16, during step 23 | 9,000 | high |
| 25 | 10-28 23:50:02 | 10-29 02:03:02 | T1041 | Exfiltration | step-17 host sends about 20.5 KB every 20 s to its C2; 8,199,195 B (chain B) | 400 | high |
| 26 | 10-29 03:17:00 | 10-29 04:18:22 | T1078 | Initial Access | 3 admin logins 30 min apart at night from a never-seen source | 3 | medium |
| 27 | 10-29 07:48:44 | 10-29 07:58:08 | T1190 | Initial Access | path traversal / LFI: 12 passed, 68 dropped | 80 | medium |
| 28 | 10-29 11:51:53 | 10-29 11:53:41 | T1046 | Discovery | port scan of ports 1-1024, all denied | 1,024 | high |

- **Chain A:** steps 4 → 5 → 6 → 9, one external source against the web portal (scan, exploit, web shell, exfil). 940 events.
- **Chain B:** steps 17 → 19 → 25, one workstation (delivery not blocked, then C2, then exfil). 803 events.
- **Chain C:** steps 12 → 13 → 21, one admin account (spray, success, then a backdoor admin is created, used and deleted 3 days later from a new source). 33 events. The 13 → 21 link rests on the shared account only.
- The other steps are independent scenarios, each with its own entities. It is the same scenario family as n10 with new entities and times. New in n30: the two spray bursts and the failure-then-success on step 13.

## Hunt categories (summary)
- **Recon:** 2 port scans (steps 4 and 28). The wide port fan-out from each internal host is background noise.
- **Brute force:** 1,546,662 background admin failures outside the filler (5,199,938 in the whole file). They come from 158 sources, all with the "invalid name" reason and a LAN-side destination role, and none succeeds. The 119 spray failures (steps 12 and 16) use a WAN-side destination role and come in /24 bursts. Of the 5 admin successes, 1 comes from a spray source (step 13); the other 4 come from sources with 0 failures.
- **Exploitation:** 475 IPS hits from the WAN side, all against one portal: 49 passed (detected) and 426 dropped, 4 signatures. Background IPS traffic is LAN/DMZ-outbound with 65 random signature names.
- **Malware/C2:** 3 AV events with "detected" (step 17) and 12 blocked deliveries (step 20). The beacons are steps 3 and 19; botnet/proxy app categories show nothing beyond the random background.
- **DNS:** 1 tunnel (step 1). No other hostname is longer than 21 characters.
- **Admin:** 5 configuration events (steps 21 and 22) and 5 admin login successes (steps 13, 21 and 26). Every admin success and configuration event comes from a source that is not the user's VPN home.
- **VPN:** 4 tunnel-up events (step 15). Each of the 40 SSL VPN users uses one fixed source, except in step 15.
- **Lateral movement:** 2,580 LAN-to-DMZ flows (steps 7 and 8). There is no other internal-to-internal traffic.
- **Exfiltration:** no single session is above 9.0 MB (that is the background maximum). Exfil only shows up as repeated sessions of about 20.5 KB to one destination (steps 9, 11 and 25).
- **Rare logids:** in the whole file, the only logids below 300,000 rows are 0100044547 (2), 0100044546 (3), 0101039947 (4) and 0100032001 (5); they are all attack steps.

## Noise a detector could mistake for attacks
- The filler second (26.1 M rows, 3.32 M sources, 17.6 M destinations). Volume, scan and DoS rules all fire on it unless it is excluded or rate-normalised.
- The admin-login-failure background: 158 sources, flat all week, never succeeds. A per-source failure threshold drowns the 119 real spray rows.
- Outbound IPS, AV and webfilter alerts with random signature names, categories and hosts. 16,444 IPS rows carry botnet/C2-like signature names on random hosts. AV "blocked" on one generic path covers 1,386 hosts.
- Every LAN host talks to about 4,177 random destinations on about 760 ports (mean per host). That looks like scanning or beaconing breadth, but it is not.
- Random per-row geo and app fields. App category and risk do not mean anything.
- IPsec phase 1/2 errors (33,299), cloud-connector failures (35,639) and SD-WAN out-of-SLA flaps (50,862).
- Exfil rows in steps 9 and 25 have interfaces that do not match the IPs (step 9 has source and destination swapped). Direction logic that uses srcip will get these wrong.
- Coincident timing: steps 17 and 18 start 17 s apart but share no entity, and the step-24 flood overlaps the step-23 web shell. A time-only correlator will merge them.

## Resources
DuckDB memory_limit=1GB, threads=2, TimeZone=UTC, temp_directory under data/tmp/hunt_n30/duck (deleted afterwards). Free RAM at start was 867 MB.
The Parquet parts (data/tmp/hunt_n30/parts/) and the non-filler view (data/tmp/hunt_n30/h.parquet, 437,783,080 B) are kept; data/ is gitignored.
