# Robustness sweep: encoding_transport

Probe: `tools/robust/ingest_only.py` (profile + ingest, 512MB / 1 thread, config snapshot `data/snap/robust_cfg`), live tree 2026-11-01.
Controls: one FortiGate kv traffic line shape (FortiOS 7.x: `date= time= devname= eventtime=<ns UTC> tz="+0530" ... srcip= dstip= user=`)
and one ECS 8.11 JSON process event. True UTC for every row is 2026-10-30T10:00:0N Z unless stated otherwise.
Fixtures: `data/raw/robust_encoding_transport/<variant>/`. Outputs: `data/out/robust_encoding_transport/<variant>/ingest_probe.json`.
The lines were written by hand. A scratch script produced the gzip/bz2/zip/tar/UTF-16/latin-1 variants with the Python stdlib.

## Results

| # | Variant | Shape | Doc | Probe result (rows_in / ok / dropped, routing, ts) | Verdict |
|---|---|---|---|---|---|
| 1 | control_plain | 3 kv + 3 ECS, LF | [FortiOS log ref](https://docs.fortinet.com/document/fortigate/7.6.6/fortios-log-message-reference/32146), [ECS base](https://www.elastic.co/guide/en/ecs/current/ecs-base.html) | fortigate_kv 3/3/0, ecs_json 3/3/0, ts exact (kv keeps the eventtime ms .123) | PASS |
| 2 | gzip | fgt.log.gz, ecs.json.gz | [RFC 1952](https://www.rfc-editor.org/rfc/rfc1952) | both unrecognized. rows_in 9 (the `\n` bytes in the compressed data; truth 6), all dropped | GAP (in-flight unpacker, not wired) |
| 3 | bzip2 | .bz2 | [bzip2](https://sourceware.org/bzip2/) | unrecognized, rows_in 13 (truth 6) | GAP (in-flight, not wired) |
| 4 | zip_multi | one zip: fgt.log, ecs.json, sub/fgt2.log | [APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) | unrecognized (binary), rows_in 13 (truth 9) | GAP (in-flight, not wired) |
| 5 | tar | logs/fgt.log + logs/ecs.json | [GNU tar format](https://www.gnu.org/software/tar/manual/html_node/Standard.html) | unrecognized, rows_in 7 (truth 6) | GAP (in-flight, not wired) |
| 6 | tar_gz | same as tar, gzipped | same | **misrouted**: profile sniffs the raw gz bytes as json, then DuckDB gunzips by the `.gz` extension, so the whole tar stream is read as ecs_json: 7 rows, 5 malformed (the FortiGate lines plus tar headers), 2 ok | GAP misrouted |
| 7 | nested_dirs | dirs 6 levels deep, dir names with a space and `ñ` | - | kv 6/6, ecs 3/3, ts exact | PASS |
| 8 | utf8_bom | BOM + LF | [Unicode BOM FAQ](https://www.unicode.org/faq/utf_bom.html) | 3/3 + 3/3, exact | PASS |
| 9 | utf8bom_crlf_notrail | BOM + CRLF + no final newline (Notepad / PS7 utf8BOM) | same | 3/3 + 3/3, exact | PASS |
| 10 | utf16le_bom | FF FE + CRLF (the Windows PowerShell 5.1 `Out-File` / `>` default) | [Out-File 5.1](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/out-file?view=powershell-5.1) | both files unrecognized as "binary". rows_in 14 (truth 6: each `\r\0\n\0` counts as 2 lines), all dropped | GAP data loss |
| 11 | utf16be_bom | FE FF | Unicode BOM FAQ | unrecognized, 3 dropped | GAP data loss |
| 12 | latin1 | `José` with byte E9 in the user field (a cp1252 / latin-1 export) | [CP1252](https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1252.TXT) | the whole line is dropped as `decode_error` (kv 3/2/1, ecs 3/2/1). The count is right | GAP data loss (accounted) |
| 13 | crlf | CRLF | [JSON Lines](https://jsonlines.org/) | 3/3 + 3/3 | PASS |
| 14 | mixed_endings | CRLF, LF, lone CR | - | **the byte after a lone CR is swallowed**: the ECS line after `\r` loses its `{` and goes malformed (4/3/1). The kv line loses the `d` of `date=` but stays ts_ok (silent field loss) | GAP corruption |
| 15 | no_trailing_newline | last line without LF | - | 3/3 + 3/3 | PASS |
| 16 | long_line_1mb | 1.5 MB command_line, 1.2 MB kv url | [DuckDB CSV max_line_size](https://duckdb.org/docs/stable/data/csv/overview) | 3/3 + 3/3. The full command_line (1 500 020 chars) is kept | PASS |
| 17 | long_line_17mb | one 17 MB JSON line | same | 3/2/1 `line_too_long (> 16777216 bytes)` | PASS (dropped with reason) |
| 18 | nul_bytes | 3 lines + 4 KB NUL tail (small file), NUL inside a kv line | - | both files called "binary" and unrecognized (NUL is > 5 % of the first 4 KB). 8 rows dropped (truth 6, plus 2 NUL runs) | GAP data loss |
| 19 | nul_bytes_big | 300 lines + NUL inside line 2 + 4 KB NUL tail | - | 301/300/1 each (the NUL tail is 1 malformed row, kept). The row with a NUL inside is ok | PASS |
| 20 | truncated_last_line | last line cut mid-record | - | ecs 3/2/1 malformed (kept). The cut kv line is kept as ts_ok=true, action other, src_ip/user NULL, with no note | PASS (minor note) |
| 21 | empty_files | 0-byte, only newlines, only spaces + tab, plus a good kv file | - | the 0-byte file is listed as empty. The newline and space files are "unrecognized", and the `" \t "` line counts as 1 unrecognized_format drop | minor GAP |
| 22 | json_array_oneline | `[{...},{...},{...}]` on one line | [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) | misread as a CSV header, so unrecognized. rows_in 1 (truth 3) | GAP (in-flight, not wired) |
| 23 | json_array_pretty | `json.dumps(list, indent=2)` | RFC 8259 | unrecognized, rows_in 113 (physical lines; truth 3) | GAP (in-flight, not wired) |
| 24 | json_pretty_objects | 3 concatenated pretty-printed objects (jq output) | RFC 8259 | unrecognized, rows_in 111 (truth 3) | GAP (in-flight, not wired) |
| 25 | json_array_huge | 60 000 records on one 30 MB line | RFC 8259 | unrecognized, rows_in **1** (truth 60 000) | GAP (in-flight, not wired) |
| 26 | jsonl_blank_comments | blank lines, `#` / `//` comment lines, a tab-only line | [JSON Lines](https://jsonlines.org/), [NDJSON](https://github.com/ndjson/ndjson-spec) | 6/3/3: the 2 comments and the tab-only line are `malformed_line` (kept, accounted). Records exact | PASS (tab line: see #21) |
| 27 | extensions | .log .txt .csv none / .json .ndjson .jsonl .txt none | - | routing by content works: kv 12/12, ecs 15/15 | PASS |
| 28 | ts_epoch_ecs | @timestamp as number / string in s, ms, us, ns, and float s | [ES date formats](https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-date-format.html) | s, ms, float s and digit strings in s/ms are exact. **us and ns (number and string) give ts_ok=false** (9/5/4) | GAP |
| 29 | ts_epoch_fgt | eventtime with 10/13/16/19 digits | FortiOS log ref | 4/4 exact (ms/us/ns sub-second kept) | PASS |
| 30 | ts_iso_ecs | Z, naive, +05:30, -08:00, +0530, 9-digit fraction, space separator, `t..z`, `+00:00`, RFC 5322, space before the offset | [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339), [RFC 5322 §3.3](https://www.rfc-editor.org/rfc/rfc5322#section-3.3) | 8 exact. Lowercase `t/z`, `Fri, 30 Oct 2026 10:00:09 +0000` and `...T15:30:10 +05:30` give ts_ok=false (accounted) | minor GAP |
| 31 | ts_offset_fgt | tz `+05:30`, `-0800`, `-08:00`, `+0000`, no tz, no eventtime | FortiOS log ref | 6/6 exact (no tz is read as UTC) | PASS |
| 32 | ts_dst | US fall-back repeated 01:30 (-07/-08) and the spring-forward edge, ECS offsets + kv tz | [IANA tz](https://www.iana.org/time-zones) | 8/8 exact (08:30Z and 09:30Z kept apart) | PASS |
| 33 | ts_two_digit_year | `10/30/26`, `30-Oct-26`, `26-10-30T..Z`, `30/10/26`; kv `date=26-10-30`, `date=10/30/26` | [Windows DHCP audit log (MM/DD/YY)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd183591(v=ws.10)) | **ts_ok=true with year 0026 / 0030** (`30/10/26` becomes 0030-10-26 through `%Y/%m/%d`). 2 left unparsed | GAP wrong_time |

## Check of the in-flight unpacker (not wired yet)
I ran `python -m attacklens.cloud_unpack` by hand on variants 2-6 and 23-25 (outputs in `data/out/robust_encoding_transport/unpacked_*`) and probed the result.
gzip, bzip2, zip_multi, tar, tar_gz, json_array_pretty, json_pretty_objects and json_array_huge all come out exact (the huge array gives 60 000/60 000).
So wiring `cloud_unpack` into Stage 0 fixes 2-6 and 22-25. It does **not** fix UTF-16 (passed through unchanged) or latin-1.
`run.STAGES` still starts at `profile`, so none of these work in the live tree yet.

## Gaps the in-flight work does not cover
1. UTF-16LE/BE (BOM) Windows exports are dropped as "binary", and the row count is wrong.
2. Latin-1 / cp1252 bytes: the whole event is dropped (`decode_error`) because of one accented character.
3. A lone CR in a CRLF file: DuckDB swallows the first byte of the next line (JSON goes malformed, kv silently loses a key).
4. JSON epoch timestamps in us / ns are not parsed (`ingest_sql.ts_expr` only knows 9-10 and 12-13 digits).
5. Two-digit years parse to year 0026 / 0030 with ts_ok=true, and there is no check that the year is plausible.
6. A small file with a NUL tail is called binary, so every good line in it is lost.
7. Minor: tab / whitespace-only lines and files count as drops. RFC 5322 dates, lowercase RFC 3339 and a space before the offset are not parsed. Truncated kv lines are kept with no note.
