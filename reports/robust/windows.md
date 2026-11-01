# Robustness sweep: Windows event logs

Date 2026-11-01. Probe: `tools/robust/ingest_only.py` (profile + ingest only, config `data/snap/robust_cfg`, 512 MB / 1 thread).
The `ecs_json` / `win_json` sections and `action_map` of the snapshot are identical to live `config/sources.yaml`
(the only diff is the Azure block), and the probe imports the live `backend/attacklens` code, so these results match the live tree.

Fixtures: `data/raw/robust_windows/<variant>/`. Every variant renders the same invented events (RFC 5737 IPs, example.com):
Security 4624 / 4625 / 4688 / 4697 / 4720 / 4728 / 4769 / 5145 / 1102, Sysmon 1 / 3 / 11 / 13 / 22, PowerShell 4104
(+ System 7045 in evtx_dump). Each line has a known true UTC (2026-10-31T09:15:01.123Z + n s; local clocks are IST +05:30).
Per-row checks against expected canonical values: `data/out/robust_windows/<variant>/check.json`. Raw probe output:
`data/out/robust_windows/<variant>/ingest_probe.json`.

Verdicts: PASS = right source, exact UTC ts, key fields filled, 0 drops. PARTIAL = rows ingested, some fields or ts wrong.
FAIL = rows not ingested (all counted as `unrecognized_format`, so accounting holds, but the data never reaches detection).

| # | Variant | Shape | Doc | Probe result | Verdict |
|---|---|---|---|---|---|
| 1 | wlb7_security_ecs | Winlogbeat 7.17 security module (ECS), winlog.event_id int | https://www.elastic.co/guide/en/beats/winlogbeat/7.17/winlogbeat-module-security.html | ecs_json, 9/9 rows, ts exact; 4697 process_path empty (ServiceFileName), 5145 file_path empty | PARTIAL |
| 2 | wlb8_security_ecs | Winlogbeat 8.15 security module, winlog.event_id string | https://www.elastic.co/guide/en/beats/winlogbeat/8.15/winlogbeat-module-security.html | same as #1 (4624/4625/4688/4720/4728/4769/1102 all correct) | PARTIAL |
| 3 | wlb8_sysmon_ps_ecs | Winlogbeat sysmon + powershell modules (ECS, event_data renamed) | https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-module-sysmon.html , .../winlogbeat-module-powershell.html | Sysmon 1/3/11/13/22 all fields + ts exact; 4104 command_line empty (powershell.file.script_block_text not aliased) | PARTIAL |
| 4 | wlb8_raw_wec_noecs | Winlogbeat 8 without ingest pipeline (file/Logstash output), via WEC: host.name = collector | https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html | ecs_json 15/15, host from winlog.computer_name (correct), Sysmon OK; 4104 command_line empty (winlog.event_data.ScriptBlockText), 4697 process_path empty, 4769 src_ip `::ffff:203.0.113.57`, 1102 src_user empty (winlog.user_data), 5145 file_path empty | PARTIAL |
| 5 | elastic_agent_flat | Elastic Agent windows + system integrations (_source docs, data_stream.*) | https://docs.elastic.co/integrations/windows , https://docs.elastic.co/integrations/system | 8/8, security + sysmon correct; 4104 command_line empty | PARTIAL |
| 6 | elasticdump_hits | same docs wrapped as ES hits `{"_index","_id","_source":{...}}` (elasticdump / _search export) | https://github.com/elasticsearch-dump/elasticsearch-dump | unrecognized "JSON with no known source fields", 8/8 dropped | FAIL |
| 7 | kibana_csv | Kibana Discover CSV (dotted ECS column names, `Oct 31, 2026 @ 14:45:01.123` browser-local) | https://www.elastic.co/guide/en/kibana/current/reporting-getting-started.html | unrecognized "delimited header matches no csv source", 5/5 lines dropped | FAIL |
| 8 | nxlog_flat_security | NXLog im_msvistalog + to_json, flat; EventTime naive local, no UtcTime | https://docs.nxlog.co/refman/current/im/msvistalog.html | win_json (signature EventID+Channel), fields correct, but ts NULL on 9/9 (ts_ok=false, counted); 4769 `::ffff:` ip; 4697 process_path and 5145 file_path empty | PARTIAL (ts lost) |
| 9 | nxlog_flat_sysmon_ps | NXLog flat Sysmon + PowerShell 4104 | https://docs.nxlog.co/refman/current/im/msvistalog.html | Sysmon 5/5 exact (UtcTime); 4104 command_line filled (in-flight alias works) but ts NULL | PARTIAL |
| 10 | evtx_xml_lines | rendered `<Event xmlns="...">` one per line (EventRecord.ToXml / wevtutil) | https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-schema | unrecognized "first line matches no known format", 15/15 dropped | FAIL |
| 11 | splunk_xmlwineventlog_raw | Splunk XmlWinEventLog `_raw` (single-quoted attrs, CRLF) incl. Sysmon + 4104 | https://docs.splunk.com/Documentation/WindowsAddOn/latest/User/SourcetypesandCIMdatamodelinfo | unrecognized, 15/15 dropped | FAIL |
| 12 | wevtutil_xml_concat | `wevtutil qe Security /f:xml` (events back to back, one physical line) | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil | unrecognized (sniffed as a CSV header; the whole 9-event line is copied into `reason`), 1 line dropped = 9 events | FAIL |
| 13 | evtx_xml_pretty | `<?xml?><Events>` pretty-printed multi-line XML (Event Viewer "Save as XML") | https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-schema | unrecognized, 331 physical lines dropped (10 events) | FAIL |
| 14 | wef_rendered_xml | WEF ForwardedEvents with `<RenderingInfo>` (Message holds CRLF + TAB, so one event spans lines) | https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-renderinginfotype-complextype | unrecognized, 20 physical lines dropped (5 events) | FAIL |
| 15 | splunk_json_export | Splunk `search/jobs/export output_mode=json`: `{"preview":false,"result":{"_raw":"<Event...>","_time":"...+05:30",EventCode,...}}` | https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch#search.2Fjobs.2Fexport | unrecognized "JSON with no known source fields", 15/15 dropped | FAIL |
| 16 | splunk_wineventlog_classic | Splunk classic WinEventLog `_raw`: multi-line `LogName=/EventCode=/Message=` block, 12-h local clock | https://docs.splunk.com/Documentation/Splunk/latest/Data/MonitorWindowseventlogdata | unrecognized, 54 physical lines dropped (3 events) | FAIL |
| 17 | evtx_dump_jsonl | omerbenamram `evtx_dump -o jsonl`: `Event.System.TimeCreated.#attributes.SystemTime`, `EventID {"#attributes":{Qualifiers},"#text"}` | https://github.com/omerbenamram/evtx | win_json 16/16 rows, but ts NULL on 11/16 (all non-Sysmon); 7045 event_id NULL so action is 'other'; 4688 process_path/parent empty; Sysmon User/SourceIp/DestinationHostname empty; 1102 user empty | PARTIAL (ts lost) |
| 18 | velociraptor_evtx_json | Velociraptor parse_evtx: `System.EventID.Value`, `System.TimeCreated.SystemTime` epoch float, `EventData.*` | https://docs.velociraptor.app/vql_reference/parsers/parse_evtx/ | win_json 7/7, ts exact, but event_id NULL on 7/7 so every action is 'other'; EventData.NewProcessName/CommandLine/Image/User/SourceIp/... empty; 4728 target_user = group name | PARTIAL (no actions) |
| 19 | ps51_getwinevent_json_compress | `Get-WinEvent \| % { $_ \| ConvertTo-Json -Compress }`: Id, MachineName, TimeCreated `/Date(ms)/`, Properties[] | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent | win_json (any:TimeCreated) 5/5, ts exact, but event_id / host / every other field NULL | PARTIAL (fields empty) |
| 20 | ps7_getwinevent_json_array | PS 7 `ConvertTo-Json` default: pretty JSON array, TimeCreated `...1234560+05:30` | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-json | unrecognized, 411 physical lines dropped (5 events) | FAIL |
| 21 | ps_getwinevent_export_csv | `Get-WinEvent \| Export-Csv` (PS 5.1 `#TYPE` line, multi-line quoted Message, local 12-h TimeCreated) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-csv | unrecognized, 12 lines dropped | FAIL |
| 22 | ts_win_json_shapes | flat win_json 4688, one file per ts shape | https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-systempropertiestype-complextype | exact: TimeCreated.SystemTime 7-digit Z, 7-digit Z, +05:30, -04:00 7-digit, naive EventTime + Z @timestamp, epoch ms. Naive EventTime only / naive TimeCreated give ts NULL (counted, by policy) | PASS (policy-conformant) |
| 23 | ts_ecs_shapes | Winlogbeat raw doc with @timestamp variants | https://www.elastic.co/guide/en/elasticsearch/reference/current/date_nanos.html | +05:30, nanos Z, no-fraction Z exact; naive `2026-10-31T14:45:04.123` silently read as UTC (+5.5 h, ts_ok=true) | PARTIAL (wrong ts) |
| 24 | enc_utf16le_bom | UTF-16LE + BOM + CRLF NDJSON (PowerShell 5.1 `>` / Out-File default) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding | unrecognized "no text line found (empty or binary)", 31 lines dropped (15 events) | FAIL |
| 25 | enc_utf8_bom_crlf | UTF-8 BOM + CRLF NDJSON | (same) | 15/15, identical to #4 (BOM/CRLF handled) | PASS (encoding) |
| 26 | enc_gzip | `winlogbeat-*.ndjson.gz` | https://www.rfc-editor.org/rfc/rfc1952 | unrecognized, 24 "lines" dropped (15 events) | FAIL |
| 27 | enc_zip | zip with one NDJSON member | https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT | unrecognized, 10 "lines" dropped (15 events) | FAIL |

## Gaps (root cause and fix)

1. **No Windows XML reader at all** (#10-#14, and the `_raw` inside #15). `profile.sniff` knows json / cef / syslog / kv / csv only;
   `<Event` falls to the CSV-header branch or "no known format". Fix: an `xml_win` format in `profile.sniff`
   (`^\s*(<\?xml|<Events>|<Event[ >])`) and a streaming record splitter in Stage 0. It should split on `</Event>`, not on newlines, so
   pretty-printed XML, concatenated wevtutil output and WEF RenderingInfo messages with CRLF all work. It emits one JSON line per event
   in the existing `win_json` nested shape (`Event.System.*`, `Event.EventData.<Data Name>`, `Event.UserData.*`), so the existing
   win_json aliases, ts_policy and the Sigma `win_security` gate apply unchanged. Use the stdlib `xml.etree.ElementTree.iterparse` with
   bounded memory (`elem.clear()`) and accounting per event. SystemTime 7-digit fractions already parse (#22).
2. **Envelopes not unwrapped**: Splunk `{"result":{...}}` (#15), ES hits `{"_source":{...}}` (#6), JSON arrays (#20). Fix: add
   `result` (siblings preview/offset/lastrow) and `_source` (siblings _index/_id) as single-record envelopes in `config/unwrap.yaml`
   (the cloud_unpack work in flight already handles JSON arrays). Then route Splunk `result._raw` XML through gap 1, or map the
   Splunk_TA_windows extracted fields (EventCode, Computer, TargetUserName, ...) with a `splunk_win_json` source.
3. **ECS PowerShell 4104 / 4103 text not aliased** (#3, #4, #5, #24, #25): `ecs_json.fields.command_line` lacks
   `$.powershell.file.script_block_text`, `$.winlog.event_data.ScriptBlockText` and `$.winlog.event_data.Payload`. The 4103/4104 rule
   (`config/rules.yaml:375`) can never fire on Winlogbeat / Elastic Agent data. Still broken in the live tree.
4. **NXLog EventTime is naive local, so every non-Sysmon row loses its timestamp** (#8, and 4104 in #9). Fix: a per-run `naive_tz`
   (CLI / API / upload form). Also auto-derive the offset per file/host from the median `EventTime - UtcTime` skew that `profile_ts`
   already measures (`skew_vs_utc_s.naive_as_utc`) when Sysmon rows exist, rounded to 15 min, and record the inferred zone in
   source_profile.json.
5. **evtx_dump / xmltodict nesting** (#17): add `$.Event.System.TimeCreated."#attributes".SystemTime` (and `@SystemTime`) to ts,
   `$.Event.System.EventID."#text"` to event_id, the `Event.EventData.*` twins of every flat alias (NewProcessName,
   ParentProcessName, User, SourceIp, SourcePort, DestinationHostname, ImagePath, ServiceFileName, RelativeTargetName), and
   `Event.UserData.LogFileCleared.SubjectUserName`.
6. **Velociraptor** (#18): add `$.System.EventID.Value` for event_id and the `$.EventData.*` twins (NewProcessName, CommandLine, Image,
   ParentImage, User, SourceIp, DestinationIp, DestinationPort, DestinationHostname, QueryName, TargetFilename, TargetObject, ...).
   The existing `$.EventID.value` alias is lower-case and top-level, so it matches neither shape.
7. **Get-WinEvent ConvertTo-Json** (#19): map `$.Id` to event_id, `$.MachineName` to host, and `$.LogName`. EventData is positional
   (`Properties[n].Value`), so it needs either a per-event-id positional map in config or parsing of the rendered `Message`. At minimum
   fill event_id and host.
8. **UTF-16 text rejected as binary** (#24): `profile.first_lines` treats > 5 % NUL as binary. Fix: detect the BOM FF FE / FE FF (or
   alternating NULs) and transcode to UTF-8 into the work dir before profiling, with accounting. DuckDB read_csv also supports
   `encoding='utf-16'`.
9. **gzip / zip not opened** (#26, #27): generalise the in-flight cloud_unpack .gz / .zip handling to pass through any NDJSON or text member.
10. **4697 ServiceFileName is not mapped to process_path** in ecs_json or win_json (#1-#4, #8, #17), so `remote_service_exec`
    (detect_templates2.py:86) cannot match PsExec image patterns on 4697.
11. **IPv4-mapped IPv6 not normalised** (#4, #8, #17): `::ffff:203.0.113.57` stays as is, so 4769 / 4624 rows from DCs do not join
    the same ip entity. Fix in `normalize_sql`: `regexp_replace(lower(f_src_ip), '^::ffff:(\d+\.\d+\.\d+\.\d+)$', '\1')`.
12. **1102 UserData actor** (#4, #17): add `$.winlog.user_data.SubjectUserName` (ecs) and `$.Event.UserData.LogFileCleared.SubjectUserName`.
13. **Naive ECS @timestamp read as UTC** (#23): ecs_json has no ts_policy, so a zone-less value is silently taken as UTC (5.5 h off with
    ts_ok=true). Give ecs_json the same `explicit` policy as win_json (a naive value falls to the next alias or to naive_tz).
14. **Kibana CSV, PowerShell Export-Csv, Splunk classic WinEventLog** (#7, #21, #16): there is no csv source with dotted ECS headers or
    Get-WinEvent columns, and no multi-line kv record reader. Lower priority than gaps 1-9.
15. **5145 share path** (#1-#4): `ShareName` + `RelativeTargetName` are not mapped to file_path, and 5145 is not in action_map. Minor.

Also: `profile.sniff` copies the whole first line into `reason` (`cols[:12]` caps the number of columns, not their length), so #12
put a 9-event XML blob into source_profile.json. Cap it at about 200 characters.

## Passes
- Winlogbeat 7.x and 8.x ECS security: 4624 / 4625 / 4688 / 4720 / 4728 / 4769 / 1102 have every canonical field exact, with event_id as int or string.
- Winlogbeat / Elastic Agent Sysmon 1 / 3 / 11 / 13 / 22 (ECS-renamed fields), and raw winlog.event_data Sysmon.
- WEC: winlog.computer_name beats host.name (the collector).
- NXLog flat: routing (signature EventID+Channel), flat 4104 ScriptBlockText to command_line (the in-flight fix works), Sysmon UtcTime.
- Timestamps: SystemTime 7-digit fractions, ISO +05:30 / -04:00, nanosecond Z, epoch ms, epoch float, .NET `/Date(ms)/`, UTF-8 BOM + CRLF.
- db.py line_reader uses chr(1), so the '\0' delimiter bug is fixed in the live tree.
- Accounting: in every variant rows_in = rows_ok + dropped, each drop with a reason (`unrecognized_format` or `missing_or_unparseable_timestamp`).

Fixture shapes were written from the vendor schemas and docs cited above, from prior knowledge of those documents (no page was
fetched during this run), with invented values only.
