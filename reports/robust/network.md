# Robustness sweep: network / firewall / proxy / IDS

- Date: 2026-11-01. Probe: `tools/robust/ingest_only.py` (profile + ingest only, 512MB / 1 thread, config `data/snap/robust_cfg`;
  its network sections (`cef`, `syslog`, `kv_sources`, `csv_sources.firewall_csv`, `action_map`) match the live `config/sources.yaml`.
  The code is the live tree.)
- Fixtures: `data/raw/robust_network/<variant>/`, hand-written in the documented shapes, invented values (RFC 5737 IPs, example.com).
  Outputs: `data/out/robust_network/<variant>/ingest_probe.json`.
- True UTC of line i is `2026-10-31T10:0i:00Z` (epoch 1793440800 + 60 i), unless the row says otherwise. Device-local formats
  (FortiGate tz=+0530, Suricata +0530) are written in local time with their offset.
- Result: **39 variants, 4 PASS, 35 FAIL.** 20 variants are not recognised at all, so every row is dropped (`unrecognized_format`).
  12 are routed (mostly to `syslog`) but get no timestamp or no network fields. 3 have a CEF timestamp or field problem.

## Results

| # | Variant | Shape | Doc | Probe result | Verdict |
|---|---|---|---|---|---|
| 1 | cef_bsd_epoch | `<PRI>MMM dd HH:MM:SS host CEF:0|…|rt=<epoch ms> src spt dst dpt act suser dvchost out in request` | [CEF] | cef 3/3, ts exact, host/ip/port/user/action filled | **PASS** (minor: `in`, `request`, `proto` not mapped) |
| 2 | cef_crlf | same, CRLF line endings | [CEF] | same as #1 | **PASS** |
| 3 | cef_utf16le_bom | same, UTF-16LE + BOM | [CEF] | unrecognized "no text line found (empty or binary)", 4/4 dropped | FAIL data_loss |
| 4 | cef_escapes | header with `\|`, ext with `\=` / `\\` / spaces | [CEF] §escaping | line 1 ts NULL (rt follows the header directly and is lost) | FAIL wrong_time |
| 5 | cef_ts_formats | rt in spec formats: `… UTC`, `.SSS UTC`, `.SSS`, plain, `MMM dd HH:mm:ss`, `+0530`, `end=` epoch | [CEF] rt formats | 3/7 ok; `UTC` suffix, no-year and `+0530` -> ts NULL | FAIL wrong_time |
| 6 | cef_rfc5424 | `<PRI>1 ISO host app - - - CEF:…`, no dvchost | [CEF], [RFC5424] | ts ok, **host NULL** | FAIL fields_empty |
| 7 | cef_syslog_ts_only | CEF without rt/start/end; time only in syslog header | [CEF] | 3/3 ts NULL (ts_ok=false) | FAIL wrong_time |
| 8 | cef_paloalto | PAN-OS CEF: `rt=Oct 31 2026 10:00:00 GMT`, `cs1Label=Rule cs1=allow-web`, in/out, app | [PAN-CEF] | ts NULL (GMT); **command_line = "allow-web"** (rule name); app, bytes_in empty | FAIL wrong_time + misrouted field |
| 9 | cef_fortigate | FortiGate CEF: `FTNTFGTeventtime`, `act=close`, no rt | [FGT-CEF] | ts NULL; action `other` (close not mapped) | FAIL wrong_time |
| 10 | leef1_tab | LEEF 1.0, tab-separated, devTime + devTimeFormat (1 line with syslog header, 1 bare line) | [LEEF] | routed `syslog` (process "leef"), no fields; bare line ts NULL | FAIL fields_empty |
| 11 | leef2_caret | LEEF 2.0, `^` delimiter (also `x5E`), devTime epoch | [LEEF] | unrecognized (read as a `|` CSV header), 2/2 dropped | FAIL data_loss |
| 12 | panos_syslog_bsd | `<14>MMM dd HH:MM:SS pa-vm01 1,2026/10/31 …,TRAFFIC/THREAT,…` | [PAN-TRAFFIC], [PAN-THREAT] | routed syslog; line regex fails: ts/host NULL, 3/3 ts_ok=false | FAIL wrong_time |
| 13 | panos_syslog_iso | same with RFC 5424 header | [PAN-TRAFFIC] | syslog, host="1", process="2026-10-31t10", ts NULL | FAIL wrong_time |
| 14 | panos_csv_export | WebUI Monitor export, header "Receive Time,Source address,…" | [PAN-TRAFFIC] | unrecognized csv header, 3/3 dropped | FAIL data_loss |
| 15 | asa_bsd_host | `<166>MMM dd HH:MM:SS asa01 %ASA-6-302013: Built …` (302013/106023/302014/113004/605004) | [ASA] | syslog ts+host ok, process=`%asa-6-302013`; no ip/port/user, action other | FAIL fields_empty |
| 16 | asa_device_ts_year | `<166>Oct 31 2026 10:00:00 asa01 : %ASA-…` (`logging timestamp`) | [ASA] | unrecognized, 5/5 dropped | FAIL data_loss |
| 17 | asa_no_header | `<166>%ASA-6-…` (no timestamp / device id) | [ASA] | unrecognized, 5/5 dropped | FAIL data_loss |
| 18 | checkpoint_syslog | Log Exporter syslog: `<134>1 ISO gw-01 CheckPoint pid - [action:"Accept"; src:"…"; …]` | [CP-LE] | syslog, host="1", ts NULL, no fields | FAIL wrong_time |
| 19 | pfsense_bsd | `<134>MMM dd … pfsense filterlog[pid]: 5,,,1000000103,igb1,match,block,in,4,…` | [PF] | syslog ts+host ok, process filterlog; no ip/port/action | FAIL fields_empty |
| 20 | pfsense_bsd_nohost | `MMM dd HH:MM:SS filterlog[pid]: …` (local log file, no host) | [PF] | line regex fails: ts NULL | FAIL wrong_time |
| 21 | pfsense_rfc5424 | `<134>1 ISO pfsense filterlog pid - - …` | [PF] | host="1", ts NULL | FAIL wrong_time |
| 22 | fortigate_pri_prefix | `<189>date=… time=… devname="FGT-01" … tz="+0530"` (raw UDP syslog) | [FGT] | unrecognized, 2/2 dropped | FAIL data_loss |
| 23 | fortigate_relay_bsd | `MMM dd HH:MM:SS 192.0.2.1 date=… ` (rsyslog / syslog-ng relay) | [FGT] | routed syslog, line regex fails: ts/host/all fields NULL | FAIL wrong_time |
| 24 | fortigate_quoted_tzcolon | all values quoted, `tz="+05:30"`, eventtime ns (true UTC) | [FGT] | fortigate_kv 2/2, ts exact UTC, all fields | **PASS** |
| 25 | fortianalyzer_csv | FortiAnalyzer Log View CSV download: `date,time,devname,…,srcip,dstip,…,sentbyte,rcvdbyte` | [FAZ] | unrecognized csv header, 3/3 dropped | FAIL data_loss |
| 26 | zeek_conn_tsv | `#separator \x09` … `#fields ts uid id.orig_h …` / `#types` / rows / `#close` | [ZEEK-FMT], [ZEEK-CONN] | unrecognized, 12/12 dropped (headers included) | FAIL data_loss |
| 27 | zeek_conn_tsv_gz | same, `conn.log.gz` (rotated Zeek logs) | [ZEEK-FMT] | unrecognized (binary read as CSV); rows_in = 5 "lines" of compressed bytes (true: 3 records) | FAIL data_loss + wrong accounting |
| 28 | zeek_dns_tsv | dns.log TSV | [ZEEK-DNS] | unrecognized, 11/11 dropped | FAIL data_loss |
| 29 | zeek_conn_json | JSON streaming (`LogAscii::use_json=T`), ts epoch float, `"id.orig_h"` dotted keys | [ZEEK-FMT] | "JSON with no known source fields", 3/3 dropped | FAIL data_loss |
| 30 | zeek_dns_json | dns.log JSON | [ZEEK-DNS] | unrecognized, dropped | FAIL data_loss |
| 31 | zeek_http_json_iso | http.log JSON, `ts` ISO8601 (`JSON::TS_ISO8601`) | [ZEEK-HTTP] | unrecognized, dropped | FAIL data_loss |
| 32 | suricata_eve_alert | eve.json alert, `timestamp …+0530`, alert.signature/severity/action | [EVE] | unrecognized, 2/2 dropped | FAIL data_loss |
| 33 | suricata_eve_flow | eve flow, flow.bytes_toserver/toclient | [EVE] | unrecognized | FAIL data_loss |
| 34 | suricata_eve_dns | eve dns v2 (`dns.rrname`) + v3 (`dns.queries[0].rrname`) | [EVE] | unrecognized | FAIL data_loss |
| 35 | suricata_eve_http | eve http (hostname, url, status) | [EVE] | unrecognized | FAIL data_loss |
| 36 | squid_native | `epoch.ms elapsed client CODE/status bytes method URL user HIER/peer type` | [SQUID] | unrecognized, 3/3 dropped | FAIL data_loss |
| 37 | squid_combined | Apache-combined + `squid_status:hier` | [SQUID] | unrecognized | FAIL data_loss |
| 38 | windns_debug | Windows DNS Server debug log (`dns.log`), header block + `M/D/YYYY h:mm:ss AM … PACKET … (3)www(7)example(3)com(0)` | [WINDNS] | unrecognized, 10/10 dropped | FAIL data_loss |
| 39 | firewall_csv_control | `timestamp,device,src,sport,dst,dport,action,bytes_sent,user` | (built-in) | firewall_csv 2/2, ts exact, all fields | **PASS** |

Every drop above has a logged reason (`unrecognized_format` / `missing_or_unparseable_timestamp`), so nothing is lost
without a count. But for 20 of the 39 shapes, 100 % of the rows are dropped.

## Root causes (ranked)

1. **RFC 5424 syslog header misparsed** (`config/sources.yaml` `syslog.line_regex`, line 819). `profile.py` SYSLOG_RES[1]
   accepts `<PRI>1 ISO …`, but the line regex has no `1 ` version token. It reads host="1", process="2026-10-31t10" and
   ts=NULL. Affects Check Point, PAN-OS, pfSense and any RFC 5424 sender. The CEF prefix host regex (`ingest_sql.py:111`) has the same gap.
2. **Syslog lines without a `tag:`** (PAN-OS CSV, relayed FortiGate kv, `filterlog[pid]:` without host): the whole line regex fails,
   so ts and host are NULL (`syslog_select`, `ingest_sql.py:126-165`). The header (ts + host) should always be taken, even when the tag/message part does not match.
3. **No inner-payload dispatch**: a syslog line that carries kv / CSV / CEF / LEEF / `%ASA-` / `[k:"v"; …]` stays a bare
   `syslog` row with action `other`. Vendor parsers needed: PAN-OS positional CSV, ASA message ids, pfSense filterlog CSV,
   Check Point structured data, LEEF 1.0/2.0, FortiGate kv after a syslog header or a bare `<PRI>`.
4. **No line source for IDS / proxy / DNS formats**: Zeek (TSV and JSON), Suricata EVE, Squid, Windows DNS debug.
5. **CEF**: ts comes only from `rt/start/end` (no syslog-header or vendor epoch fallback); `UTC`/`GMT`/offset/no-year rt
   formats not in `pipeline.yaml ingest.ts_formats`; the header extension regex does not skip `\|`; and `cs1` is mapped to
   command_line whatever its `cs1Label` says.
6. **Encodings / compression**: UTF-16LE (BOM) files are treated as binary (`profile.first_lines` NUL heuristic). `.gz`
   is sniffed as a CSV, and its compressed bytes are counted as rows_in. The cloud_unpack work in flight covers CloudTrail only. The fix should be generic.
7. **CSV exports with vendor header names** (FortiAnalyzer, PAN-OS WebUI) match no `csv_sources` entry. Even if they matched,
   `firewall_csv.ts` would pick `time` alone ("15:30:00"): separate date + time + tz columns are not supported.

## Doc references

- [CEF] ArcSight CEF Implementation Standard: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/
- [RFC5424] https://datatracker.ietf.org/doc/html/rfc5424#section-6
- [LEEF] IBM QRadar LEEF: https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components
- [PAN-TRAFFIC] https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields
- [PAN-THREAT] https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/threat-log-fields
- [PAN-CEF] https://docs.paloaltonetworks.com/resources/cef (PAN-OS CEF configuration guide)
- [ASA] Cisco ASA Series Syslog Messages: https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog.html
- [CP-LE] Check Point Log Exporter: https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter.htm
- [PF] pfSense raw filter log format: https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html
- [FGT] FortiOS log message reference: https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference/
- [FGT-CEF] FortiOS CEF support: https://docs.fortinet.com/document/fortigate/7.4.0/fortios-log-message-reference/357866/log-messages-in-cef-format
- [FAZ] FortiAnalyzer Log View download: https://docs.fortinet.com/document/fortianalyzer/7.4.0/administration-guide/
- [ZEEK-FMT] https://docs.zeek.org/en/master/log-formats.html ; [ZEEK-CONN] https://docs.zeek.org/en/master/logs/conn.html ;
  [ZEEK-DNS] https://docs.zeek.org/en/master/logs/dns.html ; [ZEEK-HTTP] https://docs.zeek.org/en/master/logs/http.html
- [EVE] https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- [SQUID] https://wiki.squid-cache.org/Features/LogFormat
- [WINDNS] https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v=ws.11)
