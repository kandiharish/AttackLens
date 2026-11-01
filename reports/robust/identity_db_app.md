# Robustness sweep: identity_db_app (web servers, databases, containers, Vault, Duo, VPN)

- Date: 2026-11-01. Probe: `tools/robust/ingest_only.py` (profile + ingest only, config `data/snap/robust_cfg`,
  512 MB / 1 thread). One probe at a time, free RAM checked before each (451 to 1 890 MB, never below 400 MB).
- Fixtures: `data/raw/robust_identity_db_app/<variant>/`. Each folder has the log file plus `manifest.json` (doc URL,
  shape, true UTC range). `profile.py` skips `manifest.json`. Every value is invented: RFC 5737 IPs, example.com, fake users.
  Generator: hand-written fixture script (scratchpad), base time 2026-10-31T10:00:00Z, one line per minute.
- Results: `data/out/robust_identity_db_app/<variant>/ingest_probe.json`.
- Note: the probe snapshot `data/snap/robust_cfg/sources.yaml` is older than the live `config/sources.yaml` (it lacks
  the Azure Key Vault / Graph / risk sources). No section used by this family differs between the two files.

## Summary

- 28 variants. **2 pass** (Duo v2 items, k8s audit). **4 routed but wrong or empty** (ASA relay, OpenVPN syslog,
  Postgres syslog, nginx JSON with `@timestamp`). **3 lose their timestamp or are misrouted** (GlobalProtect syslog,
  CRI container log, SQL 33205 via NXLog). **19 unrecognized.** Their rows are counted as dropped, so the loss is not
  silent, but 3 of them are counted wrongly (gz, two UTF-16 files).
- No crashes. In every variant rows_in = rows_ok + dropped. The row counts are wrong only when the file is not plain
  UTF-8 text.
- In practice, a real environment's web server, database, VPN and container logs mostly reach detection as nothing:
  either unrecognized, or as `syslog` rows with only host and process filled. The Sigma `webserver` logsource
  (`config/sigma_map.yaml`) can never fire on real Apache, Nginx or IIS logs.

## Results per variant

| # | Variant | Shape | Doc | Probe result | Verdict |
|---|---|---|---|---|---|
| 1 | apache_combined | Apache combined, `[31/Oct/2026:03:00:00 -0700]` | https://httpd.apache.org/docs/2.4/logs.html#combined | unrecognized, 5/5 dropped `unrecognized_format`. Reason given: "delimited header matches no csv source" (the `;` in the User-Agent) | GAP: no web access source |
| 2 | apache_combined_gz | same, logrotate `.gz` | same | unrecognized "first line matches no known format". rows_in = **4**, counted from newline bytes inside the gzip stream (5 real lines) | GAP: compressed text not decoded, row count wrong |
| 3 | nginx_json_timelocal | `log_format escape=json` with `$time_local` (+0530) | https://nginx.org/en/docs/http/ngx_http_log_module.html#log_format | unrecognized "JSON with no known source fields", 5/5 counted | GAP (first-class web access) |
| 4 | nginx_json_iso8601 | nginx JSON with `"@timestamp":"$time_iso8601"` (+05:30) | same | **routed to ecs_json** (`any:@timestamp`). ts exact (10:00Z to 10:04Z). Every other field NULL (src_ip, URI, status, host). action = other | GAP: misrouted, fields empty, no warning |
| 5 | nginx_error | `2026/10/31 10:00:00 [error] ... client: ..., server: ...` | https://nginx.org/en/docs/ngx_core_module.html#error_log | unrecognized, 3/3 counted (misleading CSV reason) | acceptable (counted); minor reason text |
| 6 | iis_w3c | IIS W3C extended, `#Software/#Version/#Date/#Fields` header, CRLF, UTC | https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging | unrecognized, 8/8 counted (the 4 header lines are counted as data rows) | GAP (first-class W3C) |
| 7 | mssql_audit_csv | `sys.fn_get_audit_file` export CSV (event_time UTC, action_id, server_principal_name, client_ip, statement) | https://learn.microsoft.com/en-us/sql/relational-databases/system-functions/sys-fn-get-audit-file-transact-sql | unrecognized "delimited header matches no csv source", 6/6 counted | GAP (first-class DB audit) |
| 8 | mssql_audit_csv_utf16 | same CSV, UTF-16LE + BOM (Windows PowerShell 5.1 `Out-File`) | same | unrecognized "no text line found (empty or binary)". rows_in = **13** (6 real lines: `\r\0\n\0` counted as 2 breaks) | GAP: UTF-16 not decoded, row count wrong |
| 9 | mssql_audit_evt33205_nxlog | SQL Audit to Application log 33205, NXLog im_msvistalog JSON, EventTime naive local (IST) | https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/write-sql-server-audit-events-to-the-security-log | win_json (`signature:EventID+Channel`), host and event_id filled, **ts NULL on 3/3** (naive EventTime, naive_tz null). user, client_ip and statement are only inside `Message`, so they stay NULL | GAP: ts known in-flight (NXLog); Message field parsing is new |
| 10 | mssql_errorlog_utf16 | SQL Server ERRORLOG (native UTF-16LE + BOM), 18456 failed logins | https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/mssqlserver-18456-database-engine-error | unrecognized "binary". rows_in = **13** (6 real lines) | GAP (same UTF-16 root cause) |
| 11 | postgres_csvlog | csvlog, 26 cols, no header, `... UTC` | https://www.postgresql.org/docs/16/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-CSVLOG | unrecognized (first data row read as a CSV header), 4/4 counted | GAP (first-class DB) |
| 12 | postgres_stderr | stderr log, prefix `%m [%p] %q%u@%d `, log_timezone CET | ...#GUC-LOG-LINE-PREFIX | unrecognized, 6/6 counted | acceptable (counted); free-form prefix |
| 13 | postgres_syslog | `Oct 31 10:00:00 db01 postgres[4321]: [3-1] user=alice,db=appdb,...,client=198.51.100.23 FATAL: password authentication failed` | ...#GUC-SYSLOG-FACILITY | syslog. ts exact, host db01, process postgres. user, src_ip and action empty (action = other) | GAP (fields empty) |
| 14 | mysql_general | MySQL 8 general log (3 header lines, TAB separated, Z timestamps) | https://dev.mysql.com/doc/refman/8.0/en/query-log.html | unrecognized, 8/8 counted | acceptable (counted) |
| 15 | mysql_enterprise_audit_json | Enterprise Audit JSON: pretty-printed array, unterminated, naive UTC `timestamp` | https://dev.mysql.com/doc/refman/8.0/en/audit-log-file-formats.html | sniffed json from line 2, no valid line, so unrecognized. 91 physical lines counted (4 records) | GAP (array / pretty JSON) |
| 16 | percona_audit_json | `{"audit_record":{...}}` per line | https://docs.percona.com/percona-server/8.0/audit-log-plugin.html | unrecognized "JSON with no known source fields", 3/3 counted | GAP (first-class DB audit, niche) |
| 17 | mariadb_server_audit | `20261031 10:00:00,db01,alice,198.51.100.23,12,0,CONNECT,appdb,,0` | https://mariadb.com/kb/en/mariadb-audit-plugin-log-format/ | unrecognized, 4/4 counted | acceptable (counted), niche |
| 18 | k8s_audit | audit.k8s.io/v1 Event per line (RequestReceived + ResponseComplete, exec 101, 403, impersonation) | https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/ | k8s_audit_json (`any:auditID`), 5/5 ok. ts exact. src_user, src_ip, file_path=URI, signature=verb, app=resource filled. Impersonated user goes to target_user. Outcome 101/200 = success, 403 = failure, RequestReceived = NULL. host NULL (a native apiserver file has no cluster name) | **PASS** (note: host NULL) |
| 19 | docker_jsonfile | `{"log":"...\n","stream":"stdout","time":"...Z"}` | https://docs.docker.com/engine/logging/drivers/json-file/ | unrecognized "JSON with no known source fields", 3/3 counted | GAP (container envelope) |
| 20 | cri_containerd | `2026-10-31T10:00:00.123456789Z stdout F <msg>` (P/F partials) | https://github.com/kubernetes/design-proposals-archive/blob/main/node/kubelet-cri-logging.md | **sniffed as syslog** (ISO prefix). line_regex fails, so **ts NULL on 4/4** (the RFC3339 ts is present), host NULL. Reason given: "missing_or_unparseable_timestamp" | GAP: misrouted, ts lost |
| 21 | vault_audit | Vault file audit device request/response JSON | https://developer.hashicorp.com/vault/docs/audit | unrecognized, 5/5 counted | GAP (first-class secrets audit, niche) |
| 22 | duo_auth_v2 | Admin API v2 authentication items, one per line | https://duo.com/docs/adminapi#authentication-logs | duo_auth_json, 4/4 ok. ts exact. login_success / login_failed, outcome, target_user, src_ip = access_device.ip, host = application, signature = reason, app = factor | **PASS** |
| 23 | duo_api_envelope | raw API page `{"response":{"authlogs":[...],"metadata":{}},"stat":"OK"}` | same | unrecognized, counted as **1** row (4 records) | GAP (envelope not in unwrap.yaml) |
| 24 | openvpn_syslog | OpenVPN 2.6 via syslog: `TLS: Username/Password authentication succeeded for username 'alice'`, `MULTI_sva: pool returned IPv4=10.8.0.6`, `TLS Auth Error` | https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/ | syslog. ts exact, host vpn01, process openvpn. **No login action, user, src_ip or assigned IP** | GAP (fields empty) |
| 25 | openvpn_logfile | OpenVPN `--log` file, `YYYY-MM-DD HH:MM:SS msg` | same | unrecognized (misleading CSV reason), 6/6 counted | acceptable (counted) |
| 26 | asa_anyconnect_ts_year | `<166>Oct 31 2026 10:00:00 asa01 : %ASA-6-113004: ...` ('logging timestamp' + device-id) | https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html | **unrecognized** "first line matches no known format", 6/6 counted | GAP: default ASA timestamp form not syslog |
| 27 | asa_anyconnect_relay | `Oct 31 10:00:00 192.0.2.1 %ASA-6-113005: AAA user authentication Rejected : ... user = mallory : user IP = 203.0.113.66` | same | syslog. ts exact, host = relay IP, process_name = `%asa-6-113005`. **No login action, user or src_ip** for 113004/113005/113015/113039/722051/113019 | GAP (fields empty) |
| 28 | globalprotect_syslog | PAN-OS 10.x GLOBALPROTECT CSV over BSD syslog, firewall clock IST | https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/globalprotect-log-fields | syslog by sniff. line_regex fails (no `tag:`), so **ts NULL on 4/4** and every field empty. Even if parsed, a BSD header carries local 15:30, while the line's own High Res Timestamp `2026-10-31T15:30:00.000+05:30` = 10:00Z | GAP: ts lost, fields empty |

## Root causes (ranked)

1. **The syslog parse regex requires `tag:`** (`config/sources.yaml` `syslog.line_regex`, applied at
   `backend/attacklens/ingest_sql.py:163`). The sniff regexes (`profile.py:30` `SYSLOG_RES`) accept any `<ts> <host> ...`
   line. When the parse fails, every group is empty, the BSD or ISO timestamp is thrown away, and the row is counted
   as a missing timestamp. Affected here: PAN-OS (GlobalProtect, and also TRAFFIC/THREAT, which share the header) and
   CRI container logs. Fix: make `tag:` optional with a fallback regex `^(?:<\d+>)?(?:(bsd)|(iso))\s+(\S+)\s+(.*)$`
   (ts + host + msg), and count non-matching lines as `unparseable_line`, not as a missing timestamp.
2. **`@timestamp` alone routes any JSON to ecs_json** (`config/sources.yaml:45` `ecs_json.detect_any`). Logstash,
   Fluentd and nginx recipes all add `@timestamp`, so a non-ECS JSON log gets ts only and every other field NULL, with
   no warning. Fix: require `@timestamp` together with an ECS namespace (`event.*`, `source.ip`, `host.name`, `ecs.version`,
   `process.*`) as a detect_signature, and drop bare `@timestamp` from detect_any. Also warn in profile when the routed
   source fills fewer than 2 entity columns on the sample.
3. **No decoding before sniff** (`profile.py:54` treats more than 5 % NUL as binary, and there is no gzip or BOM-16
   handling; `ingest.py` `physical_lines` counts raw `\n` / `\r` bytes). Results: UTF-16 files and `.gz` are reported
   as binary or garbage, and rows_in is wrong (13 vs 6, 4 vs 5). Fix: wire `cloud_unpack.py` (in flight: it already
   detects gzip/bz2/xz/zip/tar by magic and copies text members line by line) into Stage 0 for every file, and add
   UTF-16LE/BE BOM (or NUL-pattern) transcoding to UTF-8 in the same pre-step, so accounting counts decoded lines.
4. **No web access source.** Apache/Nginx combined, nginx JSON and IIS W3C are all unrecognized, so the Sigma
   `webserver` and `proxy` gates (`action IN ('web_access','web_blocked')`) never see them.
5. **No DB / secrets audit sources** (SQL Server audit CSV, PostgreSQL csvlog, MySQL/Percona audit JSON, Vault).
6. **Syslog `messages` only know sshd/useradd/usermod/gpasswd/sudo.** VPN logins (ASA 113004/113005/113015/722051/113019,
   OpenVPN, GlobalProtect) and Postgres auth failures yield no `login_*` action, user or src_ip. The brute-force
   template (`detect_templates.py:136/188`) and the VPN template (`detect_templates3.py:174`, logon_type 10) can never
   use them.
7. **The ASA `logging timestamp` form `Mmm dd yyyy hh:mm:ss host : %ASA-...` is not a syslog shape.** pipeline.yaml
   already lists `%b %d %Y %H:%M:%S` among ts_formats, but no sniff or parse regex accepts the year.

## Proposed first-class support (priority)

- **P0 (very common in any SOC):**
  - syslog parse fallback (1).
  - Stage 0 decode: gzip and UTF-16 (3).
  - ASA year timestamp plus ASA messages 113004/113005/113015/113039/722051/113019/716001/722022 as syslog `messages`
    entries (`process: '%asa-6-113005'` style, or a `process_regex`).
  - **web_access source**: Apache/Nginx combined line regex (`%h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-agent}i"`,
    ts format `%d/%b/%Y:%H:%M:%S %z` already exists), plus IIS W3C driven by `#Fields` (a per-file header like CSV,
    space delimited, `#` lines skipped and counted as `header_line`). Canonical fields: src_ip = c-ip / %h,
    dst_ip = s-ip, user = cs-username / %u, file_path = URI + query, outcome from status, action web_access, app = UA.
  - nginx JSON source keyed on `remote_addr` + `request` / `request_uri`.
  - ECS detection tightening (2).
- **P1 (common):**
  - OpenVPN and GlobalProtect message patterns. For GlobalProtect, a CSV-after-header kv parser keyed on field 4 =
    GLOBALPROTECT, with ts from High Res Timestamp, which carries an offset.
  - SQL Server audit CSV (`event_time,action_id,succeeded,server_principal_name,client_ip,statement`: LGIF -> login_failed,
    LGIS -> login_success, statement -> command_line).
  - 33205 Message `key:value` extraction for win_json.
  - PostgreSQL csvlog (headerless: a fixed 22–26 column schema chosen by count, with connection_from split ip:port).
  - Docker json-file and CRI unwrap: take `log` / msg as the inner line, `time` as ts, and re-sniff the inner line.
  - Duo API page envelope `response.authlogs` added to unwrap.yaml `array_envelopes`, with siblings [metadata].
- **P2 (niche):** Vault audit JSON (user = auth.metadata.username / display_name, src_ip = request.remote_address,
  file_path = request.path, outcome = error present), Percona / MySQL Enterprise audit JSON (pretty array: unwrap),
  MariaDB server_audit, MySQL general log, Postgres stderr. Until then, their unrecognized counts are acceptable.
- **Minor:** the unrecognized reason "delimited header matches no csv source" is shown for Apache, nginx error and
  OpenVPN lines that merely contain `;` or `,`. It should say "first line matches no known format (looked like CSV
  data, not a header)". k8s native audit files have no cluster name, so host is NULL: allow a per-upload
  `host_hint` or use the file's parent folder name.

## Passes

- duo_auth_v2: all canonical fields that Duo has are filled, ts exact to the second, 0 drops.
- k8s_audit: correct routing, ts, user, IP, verb, resource, outcome and impersonation, 0 drops. host NULL is inherent
  to the native file.
