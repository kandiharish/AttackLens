# Robustness sweep: EDR / SIEM export shapes (`edr_siem_exports`)

Date: 2026-11-01. Probe: `tools/robust/ingest_only.py` (profile + ingest only, 512MB / 1 thread, default config
`data/snap/robust_cfg`). The variants that failed were probed again with the **live** `config/sources.yaml`
(`data/out/robust_edr_siem_exports/cfg_live`, same low-RAM pipeline.yaml). The results were the same.
Fixtures: `data/raw/robust_edr_siem_exports/<variant>/`. Probe output: `data/out/robust_edr_siem_exports/<variant>/ingest_probe.json`.
True UTC of every fixture row: `data/out/robust_edr_siem_exports/fixture_truth.json`.
All values are invented (RFC 5737 IPs, `*.example.com`). The fixtures were written by hand from the documented field shapes, not copied.

**Result: 3 of 21 variants pass.** The two repo-generator controls pass, and so does a firewall CSV saved by Excel with a BOM, CRLF and quoted commas. Every vendor EDR export except Elastic Defend
(MDE, CrowdStrike, SentinelOne) is `unrecognized`. So is every SIEM export (Splunk, Elastic dump, QRadar, Sentinel). That means 100 % of their rows are dropped. The drops are accounted, so the loss is not silent, but the data is gone. One CSV shape crashes the whole ingest.

## Variant table

| # | Variant | Shape | Doc URL | Probe result (snapshot cfg; live cfg identical) | Verdict |
|---|---|---|---|---|---|
| 1 | control_generator_json | `reports/edr_log_generator.py --format json` (ECS) | repo | ecs_json, 12/12 ok, ts ms exact, proc_start / conn_out / dns_query / login_success mapped, host/user/process/cmd/parent filled | PASS |
| 2 | control_generator_cef | generator `--format cef` | repo | cef, 12/12 ok, ts exact, actions mapped. The `user_logon` row maps to `other` because the generator's CEF carries no outcome | PASS (note) |
| 3 | mde_ah_csv | Defender advanced hunting portal CSV (DeviceProcessEvents columns, 7-digit `...Z`) | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table | **routed as `syslog`**: header + 3 rows -> 4 rows with ts NULL, host = a whole CSV line, all other fields empty | GAP misrouted |
| 4 | mde_ah_api_json | Advanced hunting API response `{"Stats","Schema","Results":[...]}` pretty-printed | https://learn.microsoft.com/en-us/defender-endpoint/api/run-advanced-query-api | unrecognized. 254 *lines* dropped (3 records). In-flight cloud_unpack emits it as **1** record (does not split `Results`) | GAP data_loss |
| 5 | mde_streaming_json | Streaming API to storage/Event Hub: `{time, tenantId, operationName, category:"AdvancedHunting-Device*Events", properties:{...}}` per line | https://learn.microsoft.com/en-us/defender-xdr/streaming-api-storage | unrecognized, 4/4 dropped | GAP data_loss |
| 6 | sentinel_la_csv | Log Analytics / Sentinel portal CSV export (`TimeGenerated [UTC]` = `10/30/2026, 10:15:02.123 AM`, UTF-8 BOM) | https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-tutorial | unrecognized, 4/4 dropped (header counted). The ts format is also not in ts_formats | GAP data_loss |
| 7 | crowdstrike_fdr_json | Falcon Data Replicator NDJSON: ProcessRollup2 / NetworkConnectIP4 / DnsRequest, `timestamp` epoch-ms string | https://www.elastic.co/docs/reference/integrations/crowdstrike (FDR data stream) | unrecognized, 5/5 dropped | GAP data_loss |
| 8 | crowdstrike_fdr_gz | Same as #7, gzip (FDR S3 delivery `part-00000.gz`) | same | sniffed as a garbage CSV header -> unrecognized. rows_in=5 is counted over **compressed** bytes, so the match with 5 is a coincidence | GAP data_loss |
| 9 | s1_dv_json | SentinelOne Deep Visibility API / export items (camelCase: `eventType`, `tgtProcCmdLine`, `agentName`) | SentinelOne mgmt API v2.1 `/web/api/v2.1/dv/events` (tenant Swagger, login required) | unrecognized, 5/5 dropped | GAP data_loss |
| 10 | s1_cloud_funnel_json | SentinelOne Cloud Funnel (flat **dotted keys** `src.process.cmdline`, `event.time` epoch ms) | https://www.elastic.co/docs/reference/integrations/sentinel_one_cloud_funnel | unrecognized, 5/5 dropped | GAP data_loss |
| 11 | elastic_endpoint_ecs | Elastic Defend events (`event.action` start / connection_attempted / lookup_requested) | https://www.elastic.co/docs/reference/integrations/endpoint | ecs_json, 5/5 ok, ts exact, fields filled, but **action = `other` on all 5** (no proc_start / conn_out / dns_query) | GAP fields_empty |
| 12 | es_search_hits_json | Elasticsearch `_search` response `{"hits":{"hits":[{"_source":{...}}]}}` pretty-printed | https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search | unrecognized. 335 *lines* dropped (5 records). cloud_unpack emits it as 1 record | GAP data_loss |
| 13 | es_ndjson_source | elasticdump / scroll NDJSON `{"_index","_id","_source":{ECS}}` | https://github.com/elasticsearch-dump/elasticsearch-dump | unrecognized, 5/5 dropped | GAP data_loss |
| 14 | splunk_export_json_rawjson | Splunk export `{"preview":false,"offset":n,"result":{"_raw":"<json>","_time":"...+05:30",host,...}}` (+`lastrow`) | https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch#search.2Fjobs.2Fexport | unrecognized, 5/5 dropped. cloud_unpack passes it through untouched | GAP data_loss |
| 15 | splunk_export_json_xmlwineventlog | Same envelope, `_raw` = XmlWinEventLog Sysmon EID 1 / 3 | https://docs.splunk.com/Documentation/AddOns/released/MSSysmon/About | unrecognized, 4/4 dropped. No Windows-XML parser exists | GAP data_loss |
| 16 | splunk_export_csv_raw | Splunk CSV export `_raw,_time,host,index,...` | https://docs.splunk.com/Documentation/Splunk/latest/Search/Exportsearchresults | unrecognized, 5/5 dropped (header counted) | GAP data_loss |
| 17 | qradar_csv | QRadar Log Activity "Export to CSV, visible columns" (`Start Time` = `Oct 30, 2026, 3:45:02 PM`, console TZ) | https://www.ibm.com/docs/en/SSKMKU/com.ibm.qradar.doc/t_qradar_export_events.html | unrecognized, 5/5 dropped | GAP data_loss |
| 18 | excel_csv_bom_crlf | Firewall CSV saved by Excel: UTF-8 BOM, CRLF, quoted commas and `""` | RFC 4180 https://www.rfc-editor.org/rfc/rfc4180 | firewall_csv, 3/3 ok, ts exact, src/dst/port/action/user right | PASS |
| 19 | excel_resaved_dates | Same file after an Excel re-save: `10/30/2026 10:18` (no seconds) | https://support.microsoft.com/en-us/office/format-a-date-the-way-you-want-8e10019e-d5d8-47a1-ba95-db95123d273e | firewall_csv, 3 rows **ts NULL** (accounted `ts_ok=false`, quarantined 3) | GAP wrong_time |
| 20 | excel_utf16_tab | Excel "Unicode Text": UTF-16LE + BOM, TAB, CRLF | https://support.microsoft.com/en-us/office/file-formats-that-are-supported-in-excel-0943ff2c-6014-4e8d-aaea-b83d51d46247 | "binary" -> unrecognized. rows_in = **9** for 4 physical lines (CR and LF counted separately around the NUL bytes) | GAP data_loss |
| 21 | csv_filename_column | Any CSV a csv_source matches that has a `filename` / `FileName` column | (DuckDB read_csv `filename` option) | **crash**: `BinderException: Option filename adds column "filename", but a column with this name is also in the file`. Ingest aborts and **no ingest_accounting.json** is written | GAP crash |

## Root causes (precise)

1. **`backend/attacklens/ingest_sql.py:187` csv_select**: `read_csv(..., filename=true, ...)` collides with a header column
   named `filename` (DuckDB compares names case-insensitively). MDE (`FileName`), Sentinel, proxy and DLP exports all carry one. The fix is
   `filename='__al_src_file'` (and `_rel()` reading that name), the same in `line_reader` for safety. Verified: with a sandbox
   `mde_csv` source, both MDE CSV variants hit this crash.
2. **`backend/attacklens/profile.py:71-84` sniff_lines + `:30` SYSLOG_RES[1]**: an unrecognized CSV header falls through to line 2. Any
   data row that starts with an ISO timestamp and contains a space then matches `^\d{4}-..T..:..:..\S* \S+ \S+`, and the
   whole CSV becomes syslog. A delimited first line whose next lines have the same delimiter count should stay `csv` (unrecognized
   or mapped), never fall through to the syslog/CEF sniff.
3. **No EDR / SIEM sources in `config/sources.yaml`** (json_sources from line 24, csv_sources at line 762): nothing for MDE (`DeviceName` +
   `ActionType`), CrowdStrike (`event_simpleName` + `aid`), SentinelOne (`agentUuid` / `endpoint.name`), Elastic dumps
   (`_source.*`), Splunk (`result._raw`), QRadar or Sentinel CSV. In `action_map.event_actions` (line 1038) none of the vendor
   verbs appear: `ProcessCreated`, `ConnectionSuccess`, `ProcessRollup2`, `NetworkConnectIP4`, `DnsRequest`, `Process Creation`,
   `IP Connect`, `DNS Resolved`. Elastic Defend's `start`, `connection_attempted` and `lookup_requested` are missing too. A sandbox config
   (`data/out/robust_edr_siem_exports/cfg_proposed/sources.yaml`) with 4 new json_sources + these verbs ingests
   crowdstrike_fdr_json, mde_streaming_json, s1_dv_json, s1_cloud_funnel_json and es_ndjson_source with 0 drops, exact ts and
   proc_start / conn_out / dns_query. Results: `data/out/robust_edr_siem_exports/proposed_cfg/*`.
4. **Envelopes** (`config/unwrap.yaml:23` array_envelopes, `:38` string_json): the in-flight cloud_unpack splits `Records` /
   `records` / `value` / ... but not `Results` (MDE API), `hits.hits[]._source` (ES) or `result._raw` (Splunk). Each of these files
   becomes 1 record or passes through unchanged. cloud_unpack is also not called from `run.py` / the probe yet. It does
   gunzip the FDR `.gz` correctly (5 records).
5. **`profile.py:50-58` first_lines**: reads raw bytes. Gzip is treated as text (garbage CSV header) and UTF-16 is treated as binary. There is no
   decode or decompress by magic bytes (`1f 8b`, `ff fe` / `fe ff`).
6. **`backend/attacklens/ingest.py:216` scan_lines / `:262` _unrecognized**: counts byte lines, so UTF-16 CRLF is counted twice (9 vs 4).
   Gzip is counted over compressed bytes, and pretty JSON is counted per line (335 / 254) instead of per record. Drop counts are then
   misleading, though never silently zero.
7. **`config/pipeline.yaml:24` ts_formats**: no `%m/%d/%Y %H:%M` (Excel re-save), no `%m/%d/%Y, %I:%M:%S.%g %p` (Log Analytics
   export) and no `%b %d, %Y, %-I:%M:%S %p` (QRadar). Verified in DuckDB: all three parse with try_strptime. QRadar and Excel values
   are local wall clock, so they also need a per-source `ts_policy.naive_tz`.

## Proposed fixes (owner: backend-builder, config + ingest; one test per shape)
- Rename DuckDB's `filename` pseudo-column in csv_select / line_reader (crash, 2 lines).
- Keep a delimited header file as `csv` in sniff_lines (no fall-through to syslog when line 1 is a delimited header and line 2 has
  the same delimiter count).
- New json_sources `crowdstrike_fdr_json`, `mde_json` (flat API rows + streaming `properties.*`), `sentinelone_json` (DV
  camelCase + Cloud Funnel dotted keys via `$."src.process.cmdline"`) and `ecs_es_dump_json` (ecs_json paths under `$._source`).
  Add the vendor verbs to `action_map.event_actions`. For Elastic Defend, map by `event.category` + `event.type` (process/start ->
  proc_start, network/start -> conn_out, dns -> dns_query) so the generic `start` does not clash with the generator's
  authentication/start. CrowdStrike ts order should be `ContextTimeStamp`, `ProcessStartTime`, then `timestamp` (`timestamp` is cloud receipt
  time, +41 ms in the fixture). host = `aid` and user = `UserSid` until aidmaster / UserIdentity joins exist.
- New csv_sources `mde_csv` (DeviceName / ActionType / InitiatingProcessFileName, plus `Timestamp [UTC]` / `TimeGenerated [UTC]`),
  `qradar_csv` (Start Time / Source IP / Destination IP / Username / Event Name) and `splunk_csv` (`_raw` + `_time`). `_raw` re-dispatch
  needs a Stage-0 step.
- unwrap.yaml: `Results: [Schema, Stats]`, a `hits.hits[]._source` envelope, and a Splunk `result` envelope that re-sniffs `_raw`
  (JSON -> json_sources, XML -> new Windows XML parser, text -> syslog/kv) and keeps `_time` as a fallback ts. Wire cloud_unpack into run.py.
- profile / scan_lines: decode UTF-16 by BOM (or transcode in Stage 0) and gunzip by magic. Count rows per decoded line or record.
