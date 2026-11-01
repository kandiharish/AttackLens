# QA track qa_property: property-based tests (hypothesis)

File: `backend/tests/qa/test_qa_props.py`. Library: hypothesis 6.170.14 (MPL-2.0; pulls in sortedcontainers 2.4.0,
Apache-2.0), installed into `.venv` for this track. The module uses `pytest.importorskip("hypothesis")`, so a venv
without it skips with an install hint instead of a collection error. README disclosure and a `backend[dev]` entry
are owner follow-ups (doc-writer / backend-builder).

Settings: `derandomize=True`, `database=None`, `deadline=None`, so every run uses the same examples. Inputs are
generated only; no organiser log is read. Scratch files go to `data/tmp/qa_props/p<pid>/` (one root per pytest
process) and are deleted at module teardown.

Every property runs the product code path itself, not a re-implementation:
- kv / FortiGate: `ingest_sql.kv_select` + `normalize_sql` with the shipped `config/sources.yaml`, executed by DuckDB
  over a generated file. This is the exact SQL Stage 1 runs.
- timestamps: the same kv SQL, plus `ingest_sql.ts_expr` with the shipped `pipeline.ingest.ts_formats`.
- entities: `ingest_sql._user` (SQL), `siem_alerts.norm_user`, `sigma_compile._normalize_user`,
  `incident_gate.entities` / `allowlist_entities`.
- Sigma: `sigma_compile.Compiler.value` + `render`, evaluated on tiny DuckDB tables against a Python reference
  matcher (`*` any run, `?` exactly one code point, everything else literal).
- accounting: `profile.run` + `ingest.run` end to end.

Example budget:
| Settings | Examples | Used by |
|---|---|---|
| CHEAP | 200 | SQL-expression and Python properties (fast suite) |
| SQL_FAST | 10 | kv ingest SQL, each example one file of 1-12 lines (fast suite) |
| SQL_FULL | 200 | `@stress` copies of the 3 kv properties |
| ACC_FAST | 4 | ingest accounting runs (fast suite) |
| ACC_FULL | 100 | `@stress` copy of the accounting property |

## Test matrix
| Type | What | Result | Evidence |
|---|---|---|---|
| property | kv round trip: quoted / unquoted values with spaces, `=`, `key=` text, unicode, N/A, `-` map exactly into host, src/dst ip, ports, bytes, user, domain, url / file_ext, zones, app, signature, severity, action, outcome | pass (10 fast + 200 stress) | `test_kv_roundtrip_mapped_fields`, `_200` |
| property | a quoted value (`msg="... srcip=6.6.6.6 \" user=\"evil\""`) before, after or instead of the real key never changes a mapped column or the timestamp; an absent key stays NULL | pass (10 + 200) | `test_kv_quoted_value_never_spoofs_a_key`, `_200` |
| property | spoof guard with one token outside `[a-z_0-9-]+=value` on the line | **fail: QA-PROP-1** | `test_kv_spoof_guard_survives_one_nonconforming_token` (strict xfail) |
| property | escaped quote `\"` inside a quoted value round-trips | **fail: QA-PROP-2** | `test_kv_escaped_quote_roundtrip` (strict xfail) |
| property | kv values get the same §3.1 cleaning as other sources (trim; `''` and `-` become NULL) | **fail: QA-PROP-6** | `test_kv_values_get_the_same_cleaning_as_other_sources` (strict xfail) |
| property | an attacker-chosen VPN login name with `\` before `"` cannot inject or hide `remip=` | **fail: QA-PROP-7** | `test_kv_attacker_controlled_value_never_spoofs_a_key` (strict xfail) |
| property | eventtime in s / ms / us / ns, local-as-UTC or true UTC, no eventtime, any tz offset (`+hhmm` / `+hh:mm`, -12:00..+14:00): ts_ms = true UTC instant to the unit's precision, offset applied once, monotonic | pass (10 + 200) | `test_kv_eventtime_units_and_tz_offset_applied_once`, `_200` |
| unit near-miss | `eventtime_is_local=false` puts a local-as-UTC eventtime off by exactly +5:30, which proves the property exercises the local branch | pass | `test_kv_eventtime_is_local_false_trusts_eventtime` |
| property | `ts_expr`: ISO Z / ISO offset / space / apache `%z` / epoch ms / epoch s / second-precision ISO for one instant give the same ts_ms (sub-ms ISO fractions round half-up, as measured) | pass (200) | `test_ts_expr_same_instant_every_format` |
| property | a sub-millisecond instant gets the same ts_ms as ISO, as fractional epoch seconds and as kv eventtime (us) | **fail: QA-PROP-4** | `test_sub_ms_instant_same_ts_ms_in_every_format` (strict xfail) |
| unit | `db.connect` is UTC with `TZ=Asia/Kolkata` set in the process; a naive string is read as UTC | pass | `test_connect_is_utc_whatever_the_process_tz` |
| property | ingest `_user(x)` is NULL or trimmed, lower-case, NFC, without `DOMAIN\` / `@domain`, never `''` / `-`; `_user(_user(x)) == _user(x)` | pass (200) | `test_ingest_user_normalization_is_canonical_and_idempotent` |
| property | user parity: ingest SQL = `siem_alerts.norm_user` = Sigma literal `_normalize_user` (`CORP\Bob`, `bob@corp.local`, `BOB` all become `bob`) | pass (200) | `test_user_normalization_parity_ingest_siem_sigma` |
| property | Python entity ids (`incident_gate.entities`) = SQL ids (`'host:' \|\| v`), `type:value`, idempotent, split on the first `:` gives the value back | pass (200) | `test_python_entity_id_matches_sql_entity_id` |
| property | the allowlist (`hosts` / `users` / `ips` / `entities`) matches an entity in any case | pass (200) | `test_allowlist_matches_entity_any_case` |
| property | Python `str.lower` = DuckDB `lower` (Sigma literals are lowered in Python, columns in SQL) | **fail: QA-PROP-3** | `test_python_lower_equals_sql_lower` (strict xfail) |
| property | a Sigma value with `' % _ \ * ?` (escaped or not), unicode, emoji or injection text compiles, never injects (table count and row count unchanged after the query), and matches exactly the Sigma reference: `*`, `?` = one code point, `\|cased` vs case-insensitive, keyword = substring, empty keyword = `Unsupported` | pass (200) | `test_sigma_value_matches_exact_literal_and_wildcard_semantics` |
| property | `lit()` round-trips any text through DuckDB and rejects NUL / the `\x01` marker with `Unsupported` | pass (200) | `test_lit_roundtrips_or_rejects_control_marker` |
| property | accounting: random mix of good, URL, garbage, no-ts, bad-ts, invalid UTF-8, blank and space-only lines over 1-3 files, LF / CRLF: rows_in = rows_ok + dropped = non-blank lines written, rows_ok = ts_ok rows in Parquet, sum(drop_reasons) = dropped, each bad kind in its exact reason | pass (4 + 100) | `test_accounting_exact_for_random_good_bad_mix`, `_100` |
| property | a line of only Unicode whitespace (NBSP, U+3000, EM SPACE) is accounted without a false decode_error | **fail: QA-PROP-5** | `test_accounting_unicode_whitespace_line_reason` (strict xfail) |

## Product bugs (each one is a strict xfail with the minimal example pinned by `@example`)
| Id | Sev | File:line | Failing test | Scenario |
|---|---|---|---|---|
| QA-PROP-7 | medium | `backend/attacklens/ingest_sql.py:32` (`KV_VALUE` reads `\` + any char as an escape pair; FortiGate writes backslashes unescaped) | `test_kv_attacker_controlled_value_never_spoofs_a_key` | VPN login name `a\" remip=6.6.6.6 x="` (attacker-chosen, written as `user="a\\" remip=6.6.6.6 x=\""`) gives src_ip `6.6.6.6` instead of `203.0.113.9`. The name `CORP\` swallows the real remip: src_ip NULL, target_user `" remip=203.0.113.9 reason=`. |
| QA-PROP-1 | low | `ingest_sql.py:213` (spoof guard `tok` / `sus` regex) | `test_kv_spoof_guard_survives_one_nonconforming_token` | `... Foo=bar msg="x srcip=6.6.6.6" srcip=10.0.0.1` gives src_ip `6.6.6.6`. One token the guard's walk cannot parse (upper-case or dotted key, a token without `=`) switches the guard off for the whole line. |
| QA-PROP-2 | low | `ingest_sql.py:218` (`trim(r, '"')`, no unescape) | `test_kv_escaped_quote_roundtrip` | `user="a\"b"` gives src_user `"b` (the escape backslash is read as `DOMAIN\`). `user="ab\""` gives NULL. |
| QA-PROP-6 | low | `ingest_sql.py:237` (kv `vals` skip `_clean`) | `test_kv_values_get_the_same_cleaning_as_other_sources` | `srcip="-"` is stored as src_ip `'-'`, so a bogus `ip:-` entity appears (§3.1 says `-` becomes NULL). `devname=" "` stores host `' '`, and `devname=" fgt "` stores `' fgt '`. |
| QA-PROP-5 | low | `ingest.py:207` (`_BLANK` counts ASCII space only) vs `ingest_sql.py:33` (`trim` strips all Unicode Zs) | `test_accounting_unicode_whitespace_line_reason` | A valid UTF-8 file with one NBSP-only line reports `decode_error (invalid UTF-8): 1`. The totals still balance; the reason is false. |
| QA-PROP-4 | low | `ingest_sql.py:50` (`DOUBLE*1000`) and `:258` (`// 1000` truncation) vs DuckDB `epoch_ms` (rounds half-up) | `test_sub_ms_instant_same_ts_ms_in_every_format` | Instant `2026-10-19T23:34:07.480500Z`: ISO gives `...481`; fractional epoch and kv eventtime (us) give `...480`. The same instant differs by 1 ms between sources. |
| QA-PROP-3 | low | `sigma_compile.py:229` (Python `p.lower()`) vs SQL `lower(col)` | `test_python_lower_equals_sql_lower` | `İ` (U+0130): Python gives `i̇`, DuckDB gives `i`. Word-final `Σ` (`ΑΣ`): Python gives `ας`, DuckDB gives `ασ`. A case-insensitive Sigma literal with these characters never matches. |

Expectation decisions (test bug or product bug):
- Whitespace inside a quoted kv value is a test-model issue, now fixed. `config/sources.yaml` kv_sources only unquotes
  and maps `null_values`, so the round-trip reference is verbatim. The cross-source gap is reported as QA-PROP-6.
- `-` on src_ip / dst_ip / dst_domain is a product bug (QA-PROP-6), because DEVELOPMENT.md §3.1 states it explicitly.
- User sentinels: `siem_alerts.norm_user` maps `none` / `n/a` to NULL, while ingest keeps them as user names. This
  is not filed as a bug; the parity property excludes these two words.
- The "lost line" / KeyError failures seen during the track came from the harness, not the product. Two pytest
  processes (this session and a concurrent one) shared `data/tmp/qa_props/<name>/` and deleted each other's files at
  teardown; the log shows `No files found ... batch114.txt` and `... acc/run13/pq/events`. A DuckDB file-cache
  explanation was checked and ruled out: 50 rewrite-then-read cycles of one path on one connection gave 0 stale
  reads. The fix is one root per process (`p<pid>`), a fresh file per call, and an assert that raw_line equals the
  input line.

## Numbers
Source: the pytest runs below, pasted from this session. The box was contended: CPU load 100 % and 1.1-1.2 GB free
RAM, sampled with `Get-CimInstance` before each run; the real-log pipeline jobs and other QA tracks were running.
- Fast (`pytest backend/tests/qa/test_qa_props.py -m "not stress"`): 13 passed, 7 xfailed, 4 deselected in 151.35 s.
  This ran concurrently with this track's own stress run. The earlier solo run of the same file took 133.96 s with
  25 kv examples. Later solo runs with 10 kv examples gave the same 13 passed / 7 xfailed: 100.74 s (CPU 100 %),
  then 106.29 s on the final file content (mtime 01:00:20).
- A second stress check (`test_kv_roundtrip_mapped_fields_200` + `test_kv_quoted_value_never_spoofs_a_key_200`,
  200 examples each, run together): 2 passed in 439.00 s, contended.
- Stress (`-m stress`), all 4 pass:

  | Test | Examples | Time |
  |---|---|---|
  | `test_kv_quoted_value_never_spoofs_a_key_200` | 200 | 393.29 s |
  | `test_kv_eventtime_units_and_tz_offset_applied_once_200` | 200 | 221.69 s |
  | `test_kv_roundtrip_mapped_fields_200` | 200 | 280.03 s (re-run after the shared-path fix) |
  | `test_accounting_exact_for_random_good_bad_mix_100` | 100 | 241.44 s (re-run after the fix) |

  The first attempts of the last two failed only on `No files found` (the shared-path collision above). Logs:
  `data/tmp/qa_props_stress.log` and `data/tmp/qa_props_stress2.log` (gitignored).
- Per-query cost: one kv `normalize_sql(kv_select(...))` is about 28 KB of SQL. On a 2-line file it measured 0.41-0.48 s
  for kv_select alone and 0.49-0.61 s with normalize, contended. Regex compilation dominates: the line reader alone
  took 2-8 ms.

## Open issues
- Fast-suite cost: about 130-150 s for this file on a 100 %-loaded box. The kv SQL compile dominates. If the
  fast-suite budget is exceeded, move the three kv fast properties to `@stress` only. The cheap properties (200
  examples) take about 1-7 s each.
- hypothesis is not yet in `backend/pyproject.toml [dev]` (backend-builder) or in README disclosures (doc-writer).
- QA-PROP-7 / QA-PROP-2 depend on how FortiOS escapes `"` and `\` inside quoted values. The parser assumes `\"`
  escapes and raw backslashes (fixture `user="CORP\jdoe"`), and that combination is inherently ambiguous. The owner
  should confirm against a real device sample (counts only), then either unescape `\\` and `\"` or stop treating
  `\x` as an escape pair outside `\"`.
- Two sessions edited this track's test file and report at the same time; the file was briefly renamed to
  `wip_props.py`. The final content was verified by the runs above. This track should have one owner from now on.
