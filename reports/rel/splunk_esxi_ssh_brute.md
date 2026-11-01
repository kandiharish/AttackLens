# Reliability run: rel_splunk_esxi_ssh_brute (unseen public data)

**Dataset:** splunk/attack_data `T1110/esxi_ssh_brute_force` (Apache-2.0). 1 file, 5,255 B, 28 lines, sourcetype `vmw-syslog`.
sha256 of the log: `19f8cb2e6f07b840f59333038e4c9ebf358104e8088be0c85497c711dab78e22`.
**Run:** frozen snapshot `data/snap/rel` (memory_limit 1GB, threads 2), used as published with no converter. 2026-11-01 11:04 UTC.
Before the run, free RAM was below 700 MB for about 4 minutes (low point 312 MB). The run started once 760 MB were free.

## Ground truth (frozen before the run)
- `ground_truth/attacks.json` sha256 **`3a1934c4fedf60b8c979ef7e7cfcdaba47ca209649b6d2010aeb04f386da10cf`**
- The yml gives only `T1110` and "ssh brute force attempt against an ESXi server". It gives no time, host or user. So I located ONE event, the first line matching `sshd.*authentication failure` (line 4), and read only its time, host, user and rhost.
- 1 attack, 1 step: T1110 / Credential Access, `2025-05-07T18:06:27.948Z` (ts_ms 1746641187948), host `localhost.localdomain`, user `root`, src_ip `192.168.196.95`.
- Caveat (found after freezing, GT not changed): the file is in reverse time order. The main burst is on 2025-05-06 13:43–13:52 against user `badguy` (11 PAM failures + 11 sshd errors). The `root` attempts (2 + 2 lines on 05-07) are smaller.

## Scorecard (verbatim, `data/out/rel_splunk_esxi_ssh_brute/eval_scorecard.json`)
| metric | value |
|---|---|
| detection_pct | **0.0** |
| labels_pct | null |
| rebuilt_pct | 0.0 |
| false_alarms_strict_pct | null (0 incidents) |
| step_precision_pct | null |
| gt_steps / predicted_steps | 1 / 0 |

## Run metrics and ingest accounting
| total_wall_s | peak_rss_mb | incidents |
|---|---|---|
| 21.349 | 109.0 | 0 |

| source_type (source_profile) | rows_in | rows_ok | dropped | drop_reasons |
|---|---|---|---|---|
| syslog (`src/esxi_ssh_brute_force.log`) | 28 | 28 | 0 | {} |

`suppressed.json`: total 0. Detection: 0 raw alerts from every rule. Sigma: 1,712 rules loaded, 0 fired. Integrity verdict: TRUSTED, score 100.

## What ingest actually produced (parquet)
All 28 rows look like this: `host='192.168.8.233'`, `process_name='2025-05-06t13'`, `action='other'`, `outcome/src_ip/target_user = NULL`, ts = **2026**-05-06 13:43:09 …

## Diagnosis of the missed step (GT step 1, T1110)
The step is missed because of 4 separate problems. Fixing any one of them alone does not bring the detection back.
1. **ingest_format (main cause).** `config/sources.yaml:860` `line_regex` expects `[ts] host proc[pid]: msg`. The relay layout is `BSD-ts relay-IP ISO-ts host proc[pid]: msg`, so:
   - group 3 (host) takes the relay IP `192.168.8.233`;
   - group 4 (process) takes `2025-05-07T18`, because `[^\s\[:]+` stops at the first `:`;
   - the real host `localhost.localdomain` and the process `sshd-session` end up inside the message.

   The rows count as ok (28/28, 0 dropped), so accounting shows nothing wrong. This is silent field loss, not row loss.
2. **missing message patterns.** `sources.yaml:863-880` only matches process `sshd` with `Failed … for … from … port`, `Accepted …` or `Invalid user …`. There is no pattern for:
   - process `sshd-session` (OpenSSH ≥ 9.8 / ESXi 8);
   - PAM `pam_unix(sshd:auth): authentication failure; … rhost=X user=Y`;
   - `error: PAM: Authentication failure for Y from X`.

   So `action` stays `other` and `src_ip`/`target_user` stay NULL. The `brute_force_then_success` template needs `action = 'login_failed'` (`backend/attacklens/detect_templates.py:136`), so it has no input.
3. **timestamp.** When a BSD timestamp is present, it wins over the ISO one (`backend/attacklens/ingest_sql.py:158-160`), and it gets `baseline_year: 2026` (`config/pipeline.yaml:11`). Every event lands in 2026, 1 year (~3.15e10 ms) after the GT time. The 10-min tolerance can never match. The precise inner ISO time (`2025-05-07T18:06:27.948Z`) is in the line but is never used. The `timestamps` integrity check found nothing (0 findings), so the year shift is not flagged.
4. **threshold (missing rule for low-volume SSH guessing).** Even with a perfect parse, `bf_min_failures: 50` per (target_user, host) burst with a 10-min gap (`config/rules.yaml:10-11`) cannot fire:
   - the largest burst is 11 `badguy` attempts (22 lines if both the PAM line and the sshd error line are counted);
   - the GT `root` step has 2 attempts, and its two bursts (17:28 and 18:06) are more than 10 min apart;
   - `password_spray` needs 15 users (`rules.yaml:17`), but there are only 2.

   No Sigma linux/sshd rule covers auth failures (`lnx_sshd_susp_ssh.yml` is protocol-error keywords only).
5. **entity mismatch (would follow from 1).** The predicted host would be `192.168.8.233`, while the GT host is `localhost.localdomain`. The `badguy` / `root` user would also only match if parsed.

## Reliability verdict
- The pipeline is robust: no crash, accounting is exact (28/28), and it ran in 21 s with 109 MB.
- On real relayed ESXi/OpenSSH syslog it is **blind**: wrong host, process and year, and no auth-failure parsing.
- The worst part is that nothing reports the problem. Accounting says 0 dropped, integrity says TRUSTED, and 100 % of rows end up `action='other'`.

Suggested fixes (owner: backend-builder, not done here):
- **Line format:** add a relay-prefix variant to `line_regex` (`BSD-ts relay-host ISO-ts host proc[pid]:`) that prefers the ISO time and the inner host.
- **Process name:** treat `sshd-session` as an alias of `sshd`.
- **Message patterns:** add PAM `authentication failure; … rhost= user=` and `PAM: Authentication failure for U from IP` patterns that emit `login_failed`.
- **Integrity check:** add a check for "≥ 90 % of a source's rows have `action='other'`".
- **Threshold:** consider a lower-threshold SSH brute-force rule keyed on (src_ip, host).
