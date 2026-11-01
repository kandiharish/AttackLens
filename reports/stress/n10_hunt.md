# n10 independent hunt (counts, ids and tactics only)

Entity values are in the gitignored `reports/stress/n10_hunt_findings.md`. This file has no IPs, users, hosts, URLs or raw values.

## Input and extraction
- Raw file: 6,543,120,032 B, 12,398,551 lines (`wc -l`); Parquet has 12,398,551 rows, 0 unparsed (all have date, logid and type).
- Extraction: one DuckDB pass, 60 keys via regexp_extract, 1,618.3 s at memory_limit=1GB, threads=2 (the machine was shared). Parquet is 433,161,956 B.
- Time span: 2026-10-23 08:48:26 to 2026-10-30 08:48:25 (wall clock, tz +0530).
- **Filler block:** 8,550,308 rows (69.0 %) all share the last second of the file. They are only the background mix. All hunt queries exclude that second; 3,848,243 rows remain.
- **Timestamp quirk:** `eventtime` is the local wall clock written as if it were UTC, so it is 5 h 30 min ahead of true UTC.

## Attack steps (26 injected steps, 24,020 events outside the filler)
| n | first | last | technique | tactic | what | count | conf |
|---|---|---|---|---|---|---|---|
| 1 | 10-23 16:22:40 | 10-23 16:31:44 | T1190 (attempt) | Initial Access | XSS attempts against the web portal, all dropped | 60 | low |
| 2 | 10-23 16:31:43 | 10-23 20:36:18 | T1685, T1686 | Defense Impairment | admin turns disk logging off, purges the firewall policy, turns logging back on. No login event, and the source is new for that user | 3 | high |
| 3 | 10-23 23:22:11 | 10-29 13:39:56 | T1071.001 | Command and Control | HTTPS beacon every 300 s (+/- 7 s) | 1,612 | high |
| 4 | 10-24 06:31:54 | 10-24 06:46:38 | T1566.002, T1204.002 | Initial Access | repeated malicious executable download, blocked every time | 12 | medium |
| 5 | 10-24 19:58:06 | 10-24 21:12:30 | T1071.004 (+T1048) | Command and Control | DNS tunnelling: 1,500 unique 40-char subdomains under one domain | 1,500 | high |
| 6 | 10-24 19:59:30 | 10-24 19:59:30 | T1078 | Initial Access | admin login success from a never-seen source | 1 | low |
| 7 | 10-25 02:04:06 | 10-25 02:30:26 | T1021.001, T1021.002 | Lateral Movement | LAN host does 6 rounds over 30 DMZ hosts, alternating RDP and SMB | 180 | high |
| 8 | 10-25 09:39:48 | 10-25 10:23:21 | T1498.001 | Impact | flood of 44-byte denies from 8,424 sources in one /16 | 9,000 | high |
| 9 | 10-25 19:46:15 | 10-25 19:56:15 | T1498.002 | Impact | DNS reflection: 4,000 denies of about 3.5 KB to the firewall's WAN IP | 4,000 | high |
| 10 | 10-25 20:04:37 | 10-25 20:13:43 | T1190 | Initial Access | SQL injection: 20 passed (detected), 200 dropped | 220 | medium |
| 11 | 10-26 08:22:00 | 10-26 08:26:00 | T1204.002, T1105 | Execution | malicious archive download flagged as detected but **not blocked** | 3 | high |
| 12 | 10-26 09:15:00 | 10-27 18:30:00 | T1071.001 | Command and Control | beacon every 300 s exactly to the step-11 server | 400 | high |
| 13 | 10-26 10:08:34 | 10-29 10:25:20 | T1567.002, T1030 | Exfiltration | DMZ host sends about 20.5 KB every 90-160 s; 41,073,535 B in total | 2,000 | medium |
| 14 | 10-26 16:59:17 | 10-26 17:08:29 | T1190 | Initial Access | command injection: 11 passed, 44 dropped | 55 | medium |
| 15 | 10-27 06:47:15 | 10-27 09:43:56 | T1505.003 | Persistence | web-shell access: 4 script files in upload/tmp paths | 120 | high |
| 16 | 10-27 09:48:01 | 10-29 08:37:34 | T1039 (+T1021.002) | Collection | LAN host reads SMB from 60 DMZ hosts; 4,898,089,800 B received | 2,400 | high |
| 17 | 10-27 21:07:50 | 10-27 21:09:38 | T1046 | Discovery | port scan of ports 1-1024, all denied | 1,024 | high |
| 18 | 10-27 23:24:40 | 10-28 01:37:40 | T1041 | Exfiltration | step-11 host sends about 20.5 KB every 20 s to its C2; 8,200,231 B | 400 | high |
| 19 | 10-28 02:15:27 | 10-28 02:37:24 | T1133, T1078 | Initial Access | SSL VPN user's tunnels alternate between the home source and a new-country source | 4 | medium |
| 20 | 10-28 03:17:00 | 10-28 04:17:51 | T1078 | Initial Access | 3 admin logins 30 min apart at night from a never-seen source | 3 | medium |
| 21 | 10-28 11:15:26 | 10-28 11:24:28 | T1190 | Initial Access | path traversal / LFI: 12 passed, 68 dropped | 80 | medium |
| 22 | 10-29 01:51:23 | 10-29 01:52:26 | T1046 | Discovery | port scan of ports 1-240, all denied (chain A) | 240 | high |
| 23 | 10-29 02:07:10 | 10-29 02:11:06 | T1190 | Initial Access | SQL injection: 6 passed, 54 dropped (chain A) | 60 | high |
| 24 | 10-29 02:41:36 | 10-29 03:01:06 | T1505.003 | Persistence | the same 4 web-shell paths (chain A) | 40 | high |
| 25 | 10-29 03:55:43 | 10-29 04:07:25 | T1136.001, T1078, T1070.009 | Persistence / Stealth | an admin creates a new admin, logs in with it 6 min later, deletes it 5 min after that | 3 | high |
| 26 | 10-29 10:09:09 | 10-29 12:38:54 | T1041, T1048 | Exfiltration | web server sends about 20.5 KB every 15 s; 12,315,920 B (chain A) | 600 | high |

- **Chain A:** steps 22 → 23 → 24 → 26, one external source against the web portal (scan, exploit, web shell, exfil). 940 events.
- **Chain B:** steps 11 → 12 → 18, one workstation (delivery not blocked, then C2, then exfil). 803 events.
- The other steps are independent scenarios, each with its own entities.

## Hunt categories (summary)
- **Recon:** 2 port scans (steps 17 and 22). The wide port fan-out from each internal host is background noise.
- **Brute force:** 1,731,513 failed admin logins in total (534,259 outside the filler). They come from 264 sources trying 956 usernames, all with the "invalid name" reason. No source that failed ever succeeded. The 5 admin successes come from sources with 0 failures. This is noise.
- **Exploitation:** 475 IPS hits from the WAN side, all against one portal: 49 passed (detected) and 426 dropped. Background IPS traffic is LAN/DMZ-outbound with 69 random signature names.
- **Malware/C2:** 3 AV events with "detected" (step 11) and 12 blocked deliveries (step 4). The beacons are steps 3 and 12; botnet/proxy app categories show nothing beyond the random background.
- **DNS:** 1 tunnel (step 5). No other hostname is longer than 21 characters.
- **Admin:** 5 configuration events (steps 2 and 25) and 5 admin login successes (steps 6, 20 and 25).
- **VPN:** 4 tunnel-up events (step 19). The 40 SSL VPN users each use one fixed source, except in step 19.
- **Lateral movement:** 2,580 LAN-to-DMZ flows (steps 7 and 16). There is no other internal-to-internal traffic.
- **Exfiltration:** no single session is above 9.0 MB (that is the background maximum). Exfil only shows up as repeated sessions of about 20.5 KB to one destination (steps 13, 18 and 26).

## Noise a detector could mistake for attacks
- The filler second (8.55 M rows, 1.09 M sources, 5.77 M destinations). Volume, scan and DoS rules all fire on it unless it is excluded or rate-normalised.
- Password-spray background: 264 sources, flat all week, never succeeds.
- Outbound IPS, AV and webfilter alerts with random signature names, categories and hosts. AV "blocked" on one generic path covers 1,386 hosts.
- Every internal host talks to about 1,450 random destinations on about 310 ports. That looks like scanning or beaconing breadth, but it is not.
- Random per-row geo and app fields. App category and risk do not mean anything.
- IPsec negotiate errors (11,441), cloud-connector failures (12,283) and SD-WAN SLA flaps.
- 2026-10-24 has about 25 % more events in hours 00-20, evenly across all subtypes.
- Exfil rows in steps 18 and 26 have interfaces that do not match the IPs (step 26 has source and destination swapped). Direction logic that uses srcip will get these wrong.

## Resources
DuckDB memory_limit=1GB, threads=2, TimeZone=UTC, temp_directory under data/tmp/hunt_n10 (deleted afterwards). The Parquet file is kept at data/tmp/hunt_n10/events.parquet; it is gitignored.
