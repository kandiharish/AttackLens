# QA track qa_cli_blackbox: `python -m attacklens.run` on hostile inputs (1 Nov 2026, base commit 6fbfe3c + working tree)

The CLI is treated as a black box. Every input is our own synthetic content (FortiGate kv / ECS JSON / CEF / syslog
lines written by `tools/qa/cli_cases.py`). No organiser logs were read, and no runs touched n10/n30/n50/t*.
Each case ran `python -m attacklens.run --raw <case>/raw --out <case>/out --parquet <case>/pq`. We recorded rc, the
stderr verdict, which output files exist, accounting totals and reasons, and "unaccounted" lines. Unaccounted means
input lines minus accounting rows_in, where the input line count comes from what the case wrote, not from the product.

- Evidence: `reports/qa/qa_cli_blackbox_results.json` (both matrices, compact). Raw run dirs and full stderr are in
  `data/tmp/qa_cli_full/results.json` (unmodified repo config) and `data/tmp/qa_cli/results_fast.json` (config copy with
  `sigma.enabled: false`). Both are gitignored.
- Both matrices give the same rc, rows_in, rows_ok and dropped for every case. Only one verdict differs:
  nul_padding_large in the Sigma-off run. That run came before the spec fix (the NUL tail counts as one physical line).
- Tests: `backend/tests/qa/test_qa_cli.py`. The fast part has 13 cases, 21 passed + 7 strict xfail, 50.6 s. The
  stress-marked part has 11 cases, 7 passed + 1 skip + 4 strict xfail, 41.5 s. Every xfail is
  `strict=True, raises=AssertionError` and was checked with `--runxfail` to fail on its intended assertion.
- Machine load: CPU 99 % / 1.4 GB free at the start, and 90 % / 2.3 GB free during the repo-config matrix. A shared
  real-log job was running, so all wall times are **contended**.

### Re-run 1 Nov 2026 01:48-01:53 IST (working tree after the 01:11 ingest_sql.py / ingest_maps.py / sources.yaml edits)
- Repo-config matrix re-run (`tools/qa/cli_cases.py --base data/tmp/qa_cli_full --jobs 2`, 5 m 08 s wall). Every one
  of the 24 cases gives the same result, rc, rows_in, rows_ok, dropped, unaccounted, drop_reasons and output files as
  the first run. The only difference: the not-run symlink case has no `files` field. All 7 bugs below still
  reproduce, and their line references are re-checked against the current files.
- `reports/qa/qa_cli_blackbox_results.json`: `repo_config` is now this re-run (with `peak_rss_mb` per case),
  `repo_config_prev_0035` is the first run, and `sigma_off_copy` is unchanged.
- Module, both parts (`pytest backend/tests/qa/test_qa_cli.py -q`): 28 passed, 1 skipped (symlink), 11 strict xfailed
  in 287.68 s. Load: CPU 100 %, 1.12 GB free, with an n30 pipeline (about 1.6 GB RSS) and several other pytest
  sessions on the box, so the timing is **contended**.

## Matrix (repo config; rows = accounting totals)
| Case | Input | rc | rows_in / ok / dropped | Reasons | Unaccounted | Result |
|---|---|---|---|---|---|---|
| empty_file | one 0-byte file | 0 | 0 / 0 / 0 | listed in profile `empty_files` | 0 | fail (QA-CLI-06) |
| empty_dir | no files | 0 | 0 / 0 / 0 | warning "no recognized source files" | 0 | fail (QA-CLI-06) |
| binary_only | 64 KiB random bytes | 0 | 533 / 0 / 533 | unrecognized_format | n/a | accounting pass; rc fail (QA-CLI-06) |
| nul_padding_small | 10 FGT lines + 8 KiB NUL | 0 | 11 / 0 / 11 | unrecognized_format | 0 | fail (QA-CLI-03: 10 valid rows lost) |
| nul_padding_large | 400 FGT lines + 8 KiB NUL | 0 | 401 / 400 / 1 | unparseable_line (NUL tail) | 0 | pass |
| crlf | 20 FGT, CRLF | 0 | 20 / 20 / 0 | - | 0 | pass (ts_ms exact, no CR in raw_line) |
| utf16le_bom | 20 FGT, UTF-16 LE BOM, CRLF | 0 | 41 / 0 / 41 | unrecognized_format | -21 (over-count) | fail (QA-CLI-04) |
| utf16le_bom_lf | 20 FGT, UTF-16 LE BOM, LF | 0 | 21 / 0 / 21 | unrecognized_format | -1 | fail (QA-CLI-04) |
| utf8_bom | 20 FGT, UTF-8 BOM | 0 | 20 / 20 / 0 | - | 0 | pass (BOM stripped, ts exact) |
| huge_line | 10 FGT + one 2 MiB FGT line | 0 | 11 / 11 / 0 | - | 0 | pass (raw_line kept > 2 MiB) |
| same_ts | 50 FGT, one timestamp | 0 | 50 / 50 / 0 | - | 0 | pass (50 distinct source_seq) |
| future_ts | 20 FGT dated 2099 | 0 | 20 / 20 / 0 | - | 0 | pass (accepted as ts_ok, see open issues) |
| mixed_formats | FGT + ECS + CEF + syslog, 10 each | 0 | 40 / 40 / 0 | - | 0 | pass (4 source types x 10) |
| unknown_format | 15 prose lines | 0 | 15 / 0 / 15 | unrecognized_format | 0 | accounting pass; rc fail (QA-CLI-06) |
| gzip | `.gz` of 20 FGT lines | 0 | 7 / 0 / 7 | unrecognized_format | 13 | fail (QA-CLI-05) |
| hardlink | a.log + hard link b.log | 0 | 40 / 40 / 0 | - | 0 | pass (duplicates counted, 40 source_seq) |
| symlink | file symlink | - | - | - | - | not_run (WinError 1314, no symlink privilege) |
| readonly_out | out dir ACL denies write | 1 | - | ERROR PermissionError + traceback | n/a | pass |
| out_is_file | `--out` is a regular file | 1 | - | **stderr empty** | n/a | fail (QA-CLI-01) |
| missing_raw | `--raw` does not exist | 1 | - | ERROR "raw dir not found" + traceback; run_metrics.error set | n/a | pass |
| raw_is_file | `--raw` = a valid 20-line log file | 0 | 0 / 0 / 0 | warning only | **20** | fail (QA-CLI-02, silent loss) |
| spaces_quotes | `raw dir 'q' [x] %20 & ; $HOME` | 0 | 20 / 20 / 0 | - | 0 | pass |
| invalid_utf8_kv | 10 FGT, line 5 has `\xff\xfe\xc3` | 0 | 10 / 9 / 1 | decode_error | 0 | pass |
| from_stage_no_prior | `--from-stage 3`, no Parquet | 0 | - | warnings only; no ingest_accounting.json | n/a | fail (QA-CLI-07) |

No case left a traceback as the only stderr output. Every rc-0 case wrote run_metrics.json and
ingest_accounting.json, with rows_in = rows_ok + dropped and a reason for every drop.

## Product bugs (owner: backend-builder)
| Id | Sev | Location | Failing test | Scenario |
|---|---|---|---|---|
| QA-CLI-01 | medium | run.py:106 (`out_dir.mkdir` before `try`), run.py:181-182 (`except Exception: return 1` logs nothing) | `test_out_is_file_has_error_message` | `--out` names an existing file: rc 1, stderr completely empty. Any failure in load_config / mkdir / connect is equally silent |
| QA-CLI-02 | high | profile.py:210-212 (only `exists()` checked; `rglob` on a file yields nothing) | `test_raw_is_file_ingested_or_refused` | `--raw path/to/fw.log`: rc 0, "done", 0 rows, the file's 20 lines appear in no accounting row (silent loss) |
| QA-CLI-03 | medium | profile.py:51 (> 5 % NUL in the first 4 KiB makes the whole file "binary") | `test_nul_padding_small_keeps_valid_lines` | small log with a NUL-padded tail (crash / preallocation): all 10 valid lines dropped as unrecognized_format |
| QA-CLI-04 | medium | profile.py:51 (UTF-16 treated as binary), ingest.py:264 (`physical_lines` counts raw bytes) | `test_utf16le_bom_rows_in_matches_lines`, `TestSlowCases::test_utf16le_lf_rows_in` | Windows UTF-16 LE export is never decoded (100 % dropped), and rows_in is 41 (CRLF) / 21 (LF) for 20 lines, so the accounting is wrong. Reason text says "empty or binary" |
| QA-CLI-05 | medium | profile.py:47 (`first_lines` has no decompression), ingest.py:264 | `test_gzip_ingested_or_counted_exactly` | `.gz` of 20 lines: unrecognized, rows_in 7 (newline bytes inside compressed data), 13 lines unaccounted |
| QA-CLI-06 | low | ingest.py:349 (warning only), run.py:183-184 (rc 0) | `test_empty_dir_nonzero_rc`, `test_unknown_format_nonzero_rc`, `TestSlowCases::test_empty_file_nonzero_rc`, `TestSlowCases::test_binary_only_nonzero_rc` | zero usable rows (empty dir / 0-byte file / random bytes / unknown format) gives rc 0 and a "done" line. The API marks the run "succeeded" with 0 incidents (api_runs.py:55) |
| QA-CLI-07 | low | run.py:62-68 (`_register` warns, run continues) | `TestSlowCases::test_from_stage_without_parquet_nonzero_rc` | `--from-stage 3` with no events Parquet: rc 0, 0 incidents, no ingest_accounting.json |

QA-CLI-06 and QA-CLI-07 are severity low because DEVELOPMENT.md §4 Stage 0 only requires "warning, never a crash"
per file. A whole run with no usable rows is not specified. The track expectation (clear non-zero rc) is what the
xfails encode. If the owner decides rc 0 is intended, change the expectation explicitly, not the test.

## Numbers (source)
- Per-case rc / rows / reasons: `reports/qa/qa_cli_blackbox_results.json` (copied from
  `data/tmp/qa_cli_full/results.json` and `data/tmp/qa_cli/results_fast.json`).
- Wall per tiny run, repo config, 2 parallel jobs, contended: 1.1-1.2 s for the pre-ingest failures, 6.1-16.3 s for
  full runs. The first probe run of 20 lines took 66.5 s (detect 47.1 s, `data/tmp/qa_cli/out_probe/run_metrics.json`),
  measured at 99 % CPU from the shared job.
- Peak RSS of full tiny runs: 85-169 MB (`metrics.peak_rss_mb` in the results files; hardlink case 168.7 MB).
  Re-run: 92.7-225.7 MB (the max is mixed_formats, 4 source types). Wall per case was 4.5-6.0 s for the pre-ingest
  failures and 15.1-39.4 s for full runs, all contended (`repo_config[].peak_rss_mb` / `wall_s`).
- Full fast suite, run once (`pytest backend -q -m "not stress"`, log `data/tmp/qa_cli_fastsuite.log`): 1 failed,
  1322 passed, 3 skipped, 12 deselected, 20 xfailed in 1466.63 s. That is heavily contended (CPU 100 %, 0.31 GB free at
  start) and far over the ~2 min budget. This module took about 50 s of it. The one failure is in another track's
  file (see open issues).
- Re-run of the full fast suite, once (log `data/tmp/qa_cli_fastsuite2.log`, load `data/tmp/qa_cli_fastsuite2_load.txt`):
  13 failed, 1646 passed, 3 skipped, 17 deselected, 33 xfailed in 3403.38 s, 01:59:47-02:56:40 IST. It started at CPU
  100 % with 0.78 GB free, so the timing is **contended**. None of the failures is in `backend/tests/qa/`, and the
  earlier `test_qa_unit_ingest` failure is gone. The 13 failures are in test_cloud_connectors.py (9),
  test_api_integrations.py (2), test_integrations.py (1) and test_mock_siem.py (1, socket timeout). Those test files
  and `attacklens/connectors/*` were modified during the run (02:06, 02:07, 02:30), so the failures most likely come
  from another owner's in-flight edits. They are not attributed to this track.

## Open issues
- The symlink case was not run: WinError 1314 (no SeCreateSymbolicLinkPrivilege / Developer Mode). It skips and does
  not fail.
- Windows forbids `"` in file names, so the quote case covers `'`, spaces, `[ ]`, `%`, `&`, `;` and `$` only.
- The read-only out dir uses an ACL deny (`icacls /deny WD,AD,WA,WEA`) because Windows ignores the directory read-only
  attribute. In that case run.py's `finally` cannot write run_metrics.json either. The ERROR line is logged first, so
  the message is still clear.
- future_ts: 2099 timestamps are accepted as ts_ok in batch mode with no warning. Live mode has a future-ts guard, and
  batch behaviour is unspecified. This is an observation, not filed as a bug.
- binary_only: random bytes are accounted as 533 "rows" of unrecognized_format (the count of newline-separated
  segments). The row number has no meaning, but nothing is lost.
- missing_raw / readonly_out print a full traceback after the ERROR line. That is acceptable under the track rule (not
  traceback-only), but noisy for a CLI user.
- Not this track: the fast suite re-run has 13 connector / integration failures (see Numbers). Their owner should
  re-run once the connector edits settle.
- Resolved by 1 Nov 02:56: the item below no longer fails in the fast suite re-run.
- Not this track: `backend/tests/qa/test_qa_unit_ingest.py::test_no_recognized_files_accounts_unrecognized_only` fails
  with `IOException: No files found` from `conftest.run_ingest` -> `db.register_events` (conftest.py:238). The helper
  registers the events view when no Parquet was written. This is the same zero-usable-rows path as QA-CLI-06; the
  CLI avoids it via run.py `_register`. Owner: whoever owns that test file / conftest.
- The fast tests use a config copy with Sigma disabled to stay at about 50 s. Sigma-on behaviour is covered by the
  repo-config matrix (`python tools/qa/cli_cases.py --base data/tmp/qa_cli_full --jobs 2`).
