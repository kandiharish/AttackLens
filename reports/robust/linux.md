# Robustness sweep: Linux / Unix host logs

Run date 2026-11-01. Probe: `tools/robust/ingest_only.py` (profile + ingest only, `data/snap/robust_cfg`, 512 MB / 1 thread).
The snapshot's `syslog` section is byte-identical to the live `config/sources.yaml`, so these results hold for the live tree.
Fixtures: `data/raw/robust_linux/<variant>/` (3-8 hand-written lines each, RFC 5737 IPs, invented hosts and users).
Probe output: `data/out/robust_linux/<variant>/ingest_probe.json`.
True UTC of every fixture line: the written wall time is UTC (host clock UTC, year 2026), except where the variant says otherwise.

**Result: 5 of 25 variants pass.** Classic Debian/RHEL `auth.log` / `secure` (RFC 3164 with hostname, or RSYSLOG_FileFormat ISO) works well:
sshd password / publickey logins, invalid user, sudo, useradd and usermod all map with the right ts, host, user, src_ip, port and command.
Everything else fails: RFC 5424, 3164 without hostname or with a year, year rollover, journald, rsyslog JSON, auditd, Auditbeat
actions, OpenSSH 9.8+ `sshd-session`, cron, sudo failures, UFW and gzip rotations.

| # | Variant | Shape | Doc | Probe result | Verdict |
|---|---|---|---|---|---|
| 1 | rfc3164_authlog | `Oct 30 08:15:02 web01 sshd[2211]: Failed password ...` (TraditionalFileFormat, no PRI) | [RFC 3164 §4.1.2](https://www.rfc-editor.org/rfc/rfc3164), [rsyslog templates](https://www.rsyslog.com/doc/configuration/templates.html) | syslog 6/6 ok, ts exact (also `Oct  3` with 2 spaces), host / user / src_ip / port / sudo cmd all filled | PASS |
| 2 | rfc3164_pri | `<38>Oct 30 08:15:02 web01 sshd[...]` | RFC 3164 §4.1.1 | 3/3 ok, all fields | PASS |
| 3 | rfc3164_nohost | `<38>Oct 30 08:15:02 sshd[2211]: ...` (no HOSTNAME) | RFC 3164 §4.3.2-4.3.3 | 3/3 rows **ts NULL**, host / process / user / ip all NULL, action `other` (line_regex does not match at all) | GAP |
| 4 | rfc3164_withyear | `<38>Oct 30 2026 08:15:02 web01 sshd[...]` | RFC 3164 §4.3.2 (non-conforming TIMESTAMP), common device format | **file unrecognized**, 2/2 dropped `unrecognized_format` | GAP |
| 5 | rfc3164_rollover | `Dec 31 23:59:58` ... `Jan  1 00:00:03` (true: 2025-12-31 -> 2026-01-01) | RFC 3164 §4.1.2 (no year) | Dec lines -> **2026-12-31** (one year late, in the future, after the Jan lines) | GAP |
| 6 | rfc3164_localtz | auth.log of a host on Asia/Kolkata (true UTC 02:45:02) | RFC 3164 §4.1.2 (local time) | ts 08:15:02Z: local wall clock read as UTC, no knob to set a zone | GAP |
| 7 | rfc5424 | `<38>1 2026-10-30T08:15:02.003Z web01.example.com sshd 2211 - [sd] msg` | [RFC 5424 §6](https://www.rfc-editor.org/rfc/rfc5424) | routed syslog, but 4/4 **ts NULL**, host=`1`, process=`2026-10-30t08`, no message fields | GAP |
| 8 | rsyslog_fileformat | `2026-10-30T13:45:02.123456+05:30 web01 sshd[2211]: ...` | [rsyslog RSYSLOG_FileFormat](https://www.rsyslog.com/doc/configuration/templates.html) | 3/3 ok, offsets converted to exact UTC (ms kept) | PASS |
| 9 | rsyslog_jsonmesg | `%jsonmesg%` (msg, timereported, hostname, programname, procid ...) | [rsyslog properties: jsonmesg](https://www.rsyslog.com/doc/configuration/properties.html) | **unrecognized**, 3/3 dropped | GAP |
| 10 | rsyslog_elk_template | `{"@timestamp","host":"web01","programname","message",...}` | rsyslog list template for Logstash ([templates](https://www.rsyslog.com/doc/configuration/templates.html)) | ecs_json, ts ok, but host / process / user / ip / action all empty (`host` is a string, message never parsed) | GAP |
| 11 | journald_json | `journalctl -o json` (`__REALTIME_TIMESTAMP` us, `_HOSTNAME`, `SYSLOG_IDENTIFIER`, `MESSAGE`) | [journalctl -o json](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html), [journal fields](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html) | **unrecognized**, 4/4 dropped. Also `ts_expr` returns NULL for 16-digit us / 19-digit ns epochs | GAP |
| 12 | auditd_raw | `type=SYSCALL msg=audit(1793348232.003:4521): ... comm="cat" exe=...` + EXECVE / USER_LOGIN / USER_AUTH / ADD_USER | [RHEL audit log files](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening) | **misrouted as fortigate_kv**, 8/8 ts NULL (quarantined), `hostname=` lands in dst_domain | GAP |
| 13 | auditd_enriched | same + `0x1D` + `AUID="alice" UID="root"` (log_format=ENRICHED, RHEL 8+ default) | [auditd.conf(5)](https://man7.org/linux/man-pages/man5/auditd.conf.5.html) | same as 12 (fortigate_kv, 3/3 ts NULL) | GAP |
| 14 | auditd_via_syslog | `Oct 30 ... web01 audisp-syslog: type=SYSCALL msg=audit(...)` | [audisp-syslog(8)](https://man7.org/linux/man-pages/man8/audisp-syslog.8.html) | syslog, ts ok, but auditd payload not parsed (no user / exe / cmd / ip; action other) | GAP |
| 15 | auditbeat_ecs | Auditbeat auditd module: `event.action` executed / authenticated / logged-in / added-user-account, `process.args` | [Auditbeat auditd module](https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-module-auditd.html) | ecs_json, ts exact. `executed` -> other, no command_line (args / title not read), **`logged-in` + outcome failure -> login_success**, `authenticated` failure -> other. added-user-account ok | GAP |
| 16 | auditbeat_system | Auditbeat system module: `user_login`, `process_started` | [Auditbeat system module](https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-module-system.html) | ecs_json, ts ok; `user_login` -> other (failed SSH login lost), `process_started` -> other | GAP |
| 17 | sshd_edge | `message repeated 3 times: [ Failed password ...]`, `Connection closed by authenticating user`, `pam_unix(sshd:auth): authentication failure`, `maximum authentication attempts exceeded`, IPv6 src, keyboard-interactive | [OpenSSH auth.c](https://github.com/openssh/openssh-portable/blob/master/auth.c) | 4/8 ok (publickey fail, IPv6, `Failed none`, keyboard-interactive). The 4 failure shapes above -> other; the "repeated 3 times" line counts as 0 failures | GAP |
| 18 | sshd_session_98 | `sshd-session[2211]: Failed password ...` (OpenSSH >= 9.8) | [OpenSSH 9.8 release notes](https://www.openssh.com/txt/release-9.8) | 3/3 action other: every sshd pattern needs `process: sshd` | GAP |
| 19 | sudo_su | sudo ok / `3 incorrect password attempts` / `user NOT in sudoers` / `ENV=` before COMMAND / su session / `FAILED SU` / pam sudo auth failure | [sudoers(5) log format](https://www.sudo.ws/docs/man/sudoers.man/) | **failed sudo -> proc_start outcome success** (2 rows); `ENV=... ; COMMAND=` -> other; su lines -> other | GAP |
| 20 | cron | `CRON[3311]: (root) CMD (...)`, `CROND[...]`, `crontab[...]: (alice) REPLACE (alice)` | [cron(8) Debian](https://manpages.debian.org/bookworm/cron/cron.8.en.html), cronie | 6/6 action other, no user, no command_line (the `curl ... \| bash` cron job is invisible to unix_reverse_shell) | GAP |
| 21 | useradd_family | groupadd / useradd new group + new user / usermod add to group (+shadow) / gpasswd / passwd / userdel | [shadow-utils useradd.c](https://github.com/shadow-maint/shadow/blob/master/src/useradd.c) | user_created (backdoor), group_member_added (sudo, docker, actor alice) ok; the rest `other` (no canonical action exists) | PASS |
| 22 | kernel_ufw | `kernel: [88123.45] [UFW BLOCK] IN=eth0 ... SRC= DST= PROTO=TCP SPT= DPT=` | [iptables LOG target](https://ipset.netfilter.org/iptables-extensions.man.html), [ufw(8)](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html) | syslog, ts ok, but src/dst ip, ports, conn_denied / conn_allowed all empty | GAP |
| 23 | enc_crlf_bom | auth.log with UTF-8 BOM + CRLF | - | 3/3 ok, all fields | PASS |
| 24 | enc_gzip | logrotate `auth.log.2.gz` | [logrotate(8) compress](https://man7.org/linux/man-pages/man8/logrotate.8.html) | **unrecognized**; rows_in = 2 *binary* lines (true count 3), all dropped | GAP (in-flight: cloud_unpack is not wired into the stage pipeline yet) |
| 25 | enc_latin1 | one line with a raw 0xE9 byte | - | 2/3 ok, 1 dropped `decode_error` (counted) | GAP (minor) |

## Root causes and fixes (owner: backend-builder; config first)

1. **Syslog header regex only knows one shape.** Root cause: `config/sources.yaml` syslog line_regex (≈ line 819) and `profile.py:30` SYSLOG_RES.
   - RFC 5424 `<PRI>1 TS HOST APP PROCID MSGID SD MSG`: add a separate `line_regex_5424`, used when the line starts `<\d+>1 `. Map APP -> proc, PROCID -> pid, skip SD (`-` or `[...]+`).
   - No hostname: if the main regex does not match, try a fallback without the host group (RE2 has no lookahead, so use `coalesce` of two extracts).
   - BSD timestamp with a year (`Oct 30 2026 08:15:02`): allow `(?:\s+\d{4})?` in group 1 and in SYSLOG_RES[0]. When the year is present, parse it with the existing `%b %d %Y %H:%M:%S` instead of adding baseline_year.
2. **The year is a fixed constant.** Root cause: `pipeline.yaml baseline_year: 2026`, applied in `ingest.py:115` and `ingest_sql.syslog_select`. Fix: per-file reference time (file mtime from profile, or `baseline_year: auto` = run time). year = ref year, and if the result is more than 1 day after ref, use year - 1. This fixes the Dec -> Jan rollover and last year's files (today Dec lines land in the future). Record the chosen year and the shifted-row count in source_profile.json.
3. **No time zone for local-time syslog.** Fix: `syslog.naive_tz` (IANA, optionally per path glob) applied with `timezone()`, recorded in source_profile. Default stays UTC, with a warning.
4. **Epoch us / ns not parsed.** Root cause: `ingest_sql.ts_expr` (line 45) handles only 9-10 and 12-13 digit epochs. Add 16-digit (us // 1000) and 19-digit (ns // 1e6) branches. journald needs it, and so do many other sources.
5. **journald / rsyslog JSON have no source.** Fix: new json_sources entries listed before ecs_json (signatures win in pass 1):
   - `journald_json`: signature `[__REALTIME_TIMESTAMP, MESSAGE]`. ts `__REALTIME_TIMESTAMP`, host `_HOSTNAME`, proc `SYSLOG_IDENTIFIER` / `_COMM`, process_path `_EXE`, pid `_PID`.
   - `rsyslog_json`: signatures `[programname, timereported]` / `[programname, message]`. ts `timereported` / `@timestamp`, host `hostname` / `sysloghost` / `host` (when it is a string), proc `programname`, msg `msg` / `message`.
   - Then run the existing `syslog.messages` patterns over the message field (a reusable "message_parser: syslog" for JSON sources). Extend the sigma `linux_syslog` gate to include these source types.
6. **auditd misrouted to FortiGate.** Root cause: kv_sources `fortigate_kv.detect_regex` `'^(?:[a-z_0-9]+=...){3}'` (sources.yaml ≈ line 867) matches `type=SYSCALL msg=audit(...): arch=...`.
   - Add an `auditd_kv` kv source before fortigate_kv, detected by `^(?:node=\S+ )?type=[A-Z_]+ msg=audit\(\d+\.\d+:\d+\):`. Its ts comes from the `audit(epoch.ms:serial)` regex.
   - Fields: host `node`, process_name `comm`, process_path `exe`, user `acct` / `UID`, auid -> subject, src_ip `addr` (not `?`).
   - Command line: from EXECVE `a0..aN`, or from PROCTITLE hex (unhex, NUL -> space).
   - Actions: SYSCALL execve(59/322) / EXECVE -> proc_start; USER_LOGIN / USER_AUTH with res=success|failed -> login_success / login_failed; ADD_USER -> user_created; ADD_GROUP / GRP_MGMT -> group_member_added; USER_CMD -> proc_start.
   - Accept upper-case keys and split at 0x1D for ENRICHED. Run the same parser on syslog lines from audisp-syslog / audispd.
7. **Auditbeat action vocabulary.** Root cause: `sources.yaml action_map.event_actions` (`logged-in: login_success` with no outcome split; executed / process_started / user_login / authenticated missing) and the ecs_json `command_line` alias.
   - Make `logged-in`, `user_login` and `authenticated` outcome-split {success: login_success, failure: login_failed}.
   - Add `executed: proc_start` and `process_started: proc_start`.
   - command_line fallback: `process.args` joined with spaces, then `process.title`.
   - subject_user from `user.audit.name` (the real actor behind `root`).
8. **OpenSSH 9.8+ `sshd-session`.** Root cause: `process: sshd` on every sshd message (sources.yaml ≈ 822-840) and `detect_templates.py:279/282`, `ingest_sql.py:344` comparing `process_name = 'sshd'`. Fix: match `^sshd(-session|-auth)?$` (allow a process regex or a list) and normalise the process to `sshd` at ingest.
9. **sshd failure shapes missing.** Fix:
   - Unwrap `message repeated N times: [ ... ]` before matching, and keep N.
   - Add `maximum authentication attempts exceeded for (invalid user )?U from IP port P`, `Connection closed by (authenticating|invalid) user U IP port P [preauth]`, `Disconnected from (invalid|authenticating) user U IP port P`.
   - Add pam_unix `authentication failure; ... rhost=IP user=U` (for su / sudo / login; for sshd it duplicates `Failed password`, so tag it and do not double-count).
10. **sudo failures counted as successful commands.** Root cause: sudo regex `'^\s*(\S+) : .*USER=(\S+) ; COMMAND=(.*)$'` (sources.yaml ≈ 855) matches `3 incorrect password attempts` / `user NOT in sudoers`, and it needs COMMAND right after USER, so `ENV=` / `GROUP=` / `TSID=` break it. Fix:
    - Add a failure entry first: `^\s*(\S+) : (\d+ incorrect password attempts|user NOT in sudoers|command not allowed|a password is required|user NOT authorized on host) ; .*USER=(\S+) ; (?:.*? ; )?COMMAND=(.*)$`, outcome failure, action e.g. `priv_denied`.
    - Allow optional `(?:\S+=\S* ; )*` segments before COMMAND.
    - Add `su` (pam session opened for U by A; `FAILED SU (to U) A on`).
11. **cron not parsed.** Fix:
    - process `cron|crond` with `^\((\S+)\) CMD \((.*)\)$` -> proc_start, user 1, command_line 2, parent_process cron.
    - process `crontab` with `^\((\S+)\) REPLACE \((\S+)\)` -> scheduled_task (T1053.003).
12. **Kernel firewall lines not parsed.** Fix: process `kernel` with `\[UFW (BLOCK|AUDIT)\].*SRC=(\S+) DST=(\S+).*PROTO=(\S+)(?:.*SPT=(\d+) DPT=(\d+))?` -> conn_denied, and the same for UFW ALLOW -> conn_allowed. Also a generic iptables `IN=... OUT=... SRC= DST=` pattern.
13. **gzip rotations.** cloud_unpack (in flight) must run before profile for text members too. Until then rows_in counts binary physical lines (2 here, not the true 3), so the accounting is also wrong.
14. **Invalid UTF-8 line dropped.** It is counted, but the event is lost. Re-read rejected lines of line formats with `encoding='latin-1'` (line_reader already supports it) and keep them (flagged), instead of dropping them.

## Notes
- Every drop seen here is accounted (`ingest_accounting.json`: unrecognized_format / missing_or_unparseable_timestamp / decode_error). None was silent. But for nohost / RFC 5424 / auditd, 100 % of rows end in ts_ok=false, which detection ignores.
- Doc shapes were written from the cited specifications and man pages (from knowledge). No third-party sample file was copied.
