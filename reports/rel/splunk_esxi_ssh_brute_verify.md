# Verify: rel_splunk_esxi_ssh_brute (independent check)

Verdict: **CONFIRMED** (detection 0 %, 28/28 rows, 0 dropped, 0 incidents). Run reproduced and deterministic.

## 1. Ground truth
- yml (fetched 2026-11-01): `mitre_technique: [T1110]`, description "ssh brute force attempt against an ESXi server". It gives no time, host, user or IP.
- `attacks.json` sha256 = `3a1934c4...0cf`, same as claimed. mtime 05:29:20 UTC. The first run output (source_profile.json) is 05:34:10 UTC, so the GT was frozen before the run.
- T1110 / Credential Access: justified by the docs.
- Host, user, IP and time come from one log line (line 4), not from the docs. Documented, but chosen by hand.
- GT issue: the anchor is the root attempt (2025-05-07 18:06). The main brute force is the `badguy` burst (2025-05-06 13:43-13:52, 11 PAM + 11 sshd lines, one burst because the largest gap is 8 min). That would be a better anchor. The result does not change: nothing was detected anywhere in the file.
- No documented step is missing. Lines 1-2 are local console `login[]` failures, not SSH. They are correctly left out.

## 2. Reproduce
- Same snapshot command into `data/out/rel_splunk_esxi_ssh_brute_verify`. Exit 0, 11.6 s, peak 114 MB. I waited until free RAM was at least 700 MB.
- eval_scorecard.json, ingest_accounting.json, suppressed.json and incidents_index.json are byte-for-byte identical as JSON to the original run. Integrity is TRUSTED/100 in both. raw_alerts has 0 rows.
- Wall time differs: 21.3 s before, 11.6 s now. That is expected.

## 3. Miss causes (checked against parquet and code)
- **ingest_format: confirmed.** The parquet has all 28 rows with host `192.168.8.233`, process_name like `2025-05-06t13`, action `other`, and src_ip/target_user NULL. Cause: `sources.yaml:860` regex. Its BSD|ISO alternation takes only the BSD time. Host then takes the relay IP, and `[^\s\[:]+` stops process at the first `:`. The only message patterns are `sshd` Accepted/Failed/Invalid user (lines 863-880). There is nothing for `sshd-session` or the PAM failure lines.
- **timestamp: confirmed.** In `ingest_sql.py:158-160` the BSD time wins. Also, the regex never fills the ISO group when a BSD time comes first. Year comes from `baseline_year: 2026`. Stored min ts is 1778074989000 (2026-05-06T13:43:09Z). The `timestamps` integrity check found 0 issues.
- **missing_rule: confirmed.** `bf_min_failures: 50` and `bf_gap_ms: 600000` (`rules.yaml:10-11`). The largest burst is 11 attempts (22 lines). `spray_min_users: 15`, but only 2 users appear. `vpn_bruteforce_success` (min 10) needs a success, and there is none.
- Accounting is exact. The failure is silent: integrity says TRUSTED/100 while 100 % of rows are `action='other'`.

## 4. As published
- Upstream file downloaded again: HTTP 200, 5,255 B, sha256 `19f8cb2e...e22`. It is byte-identical to `src/esxi_ssh_brute_force.log`. There was no converter. The profile sees 1 syslog file.
