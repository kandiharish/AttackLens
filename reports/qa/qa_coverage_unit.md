# QA track: qa_coverage_unit (unit + white-box coverage), 1 Nov 2026

Owner: qa-tester. Scope: line + branch coverage (coverage.py, `--branch`) of `backend/attacklens`, then unit tests
in `backend/tests/qa/test_qa_unit_<module>.py` for the most important uncovered branches of the critical modules
(exact values, positive + near miss). No product code touched. No organiser logs were read; every fixture is tiny and
synthetic.

Tool added to the venv: **coverage 7.17.0** (Apache-2.0, https://github.com/coveragepy/coveragepy). Needs a
README disclosure line (dev / QA only, not a runtime dependency).

Machine state: CPU 100 % and 0.3-2.2 GB RAM free throughout (shared with the long n10/n30/n50 analysis). Every timing
below is **contended**.

## 1. Test matrix

| type | what | result | evidence |
|---|---|---|---|
| white-box | baseline: full fast suite under branch coverage (the one full-suite run of this track) | 989 passed, 2 skipped, 3 xfailed, 633 s (contended) | `data/tmp/qa_cov/pytest_before.txt`, `before.json`, `report_before.txt` |
| white-box | after = baseline data + a branch-coverage run of the 14 `test_qa_unit_*.py` files (`coverage combine`) | 244 passed, 3 xfailed (strict), 97 s (contended); critical lines 94.7 -> 99.2 %, branches 84.5 -> 97.1 % | `data/tmp/qa_cov/pytest_qa.txt`, `.coverage_qa`, `.coverage_after`, `after.json`, `qa_only.json`, `critical_before_after.md` |
| unit | ingest: scan_lines vs an independent reference splitter (exact cases, chunk boundaries, CRLF split, multi-file reset, seeded random corpus); `_chunks` / `plan_batches` / `build_units` exact shapes; COPY settings; CSV missing / extra columns; re-ingest removes stale partitions; profile reuse vs another raw dir; unrecognized-only set | pass + 1 strict xfail (QA-COV-01) | `backend/tests/qa/test_qa_unit_ingest.py` |
| unit | ingest_sql: `ts_expr` on 10 input shapes + strptime + session TZ; `json_raw_line` label stripping (none / top-level / nested, malformed cut); kv timestamps with eventtime_is_local true and false (s / ms / us / ns, tz offsets); syslog messages without process / action | pass | `test_qa_unit_ingest_sql.py` |
| unit | telemetry: rss of children incl. vanished / denied, per-stage peak, stage recorded on exception, rows_per_s branches, extra never overrides measured keys, start/stop idempotent | pass | `test_qa_unit_telemetry.py` |
| unit | detect validator: duplicate id, missing technique (primary / secondary), bad sub-technique in a signature, unknown template / kind, template filter that does not compile, bf_key guard, lateral_direction guard, signature direction guard, empty lateral_ports; detect_sql q / sql_list / labels_of / empty raw_alerts / empty events view | pass | `test_qa_unit_detect.py` |
| unit | sigma_compile: fieldref (mapped / unmapped / partial), numbers on VARCHAR (= and >), bool number, placeholders, 10 `_match` shapes incl. LIKE escaping, '' value, user normalisation, keyword edge cases + guard, assume_true (cased / wildcard / number), narrow policy, constant-rule rejection, folding, render with aliases, field_spec | pass | `test_qa_unit_sigma_compile.py` |
| unit | sigma_rules: rule-id collision ladder, path-hash fallback, labels() rejections and sub-technique preference, keyword_column guard shapes | pass | `test_qa_unit_sigma_rules.py` |
| unit | episodes: more seeds than the cap (seed spilled + warning) vs cap = seeds; spill_params normalisation | pass | `test_qa_unit_episodes.py` |
| unit | link: r1_ext_ip / r2_ext_ip_session / r3_match_target_user on vs off, internal-IP near miss; episode_select fallbacks for a narrow schema; link.run without episodes; `_dt_text` 9 boundaries; link_params merge | pass | `test_qa_unit_link.py` |
| unit | paths: seed with a tactic-regressing edge hung off its shown predecessor, standalone seed / branch rejection, floor-exempt and R1 near misses, branch ratio boundary (0.9 vs 0.95), max_branches 0, dangling / backward edges, trim_weak | pass | `test_qa_unit_paths.py` |
| unit | incidents / incident_gate: entities(), allowlist list / dict forms, allowlisted vs one-entity-missing, max_incidents_per_component 0 vs 1, "extracted path fails gate" + remainder re-gate vs forward edge, no episodes file, accounting detects loss + duplicates, clip boundaries, burst without subject, `_path_edge` | pass | `test_qa_unit_incidents.py` |
| unit | reach: domain-admin grant to every known DC vs local Administrators vs non-admin group vs machine account; prepare without events; BFS exact hops / via_user / order / touched last; max_hops 2 vs 1; max_results + evidence cap; crown jewel first match | pass + 1 strict xfail (QA-COV-02) | `test_qa_unit_reach.py` |
| unit | publish: fallback narrative exact text, summary hosts, dict / invalid narrative, sink failure never raises, disabled / enabled sinks | pass | `test_qa_unit_publish.py` |
| unit | api_upload: names that sanitize to empty, raw filename parsing, local_roots 403 vs inside, max_bytes 413 vs exactly the cap, copy-fallback failure cleanup (507), list with missing root / lost or corrupt .meta / foreign dirs, `_rel` outside repo, meta file content, from_pipeline | pass | `test_qa_unit_api_upload.py` |
| unit | api_runs: furthest stage, run_error precedence + stage suffix + 300-char cap, sanitize_error branches, confined / confined_raw every rejection, RunManager.start: missing raw dir, ground truth missing / dir / outside, exact cmd with ground truth (stub runner), protected out dir -> fresh `<set>-<run_id>` + `--parquet` | pass + 1 strict xfail (QA-COV-03) | `test_qa_unit_api_runs.py` |
| tool | `tools/qa/cov_summary.py`: per-module line / branch % before vs after, uncovered arcs, markdown table (read-only) | works | `tools/qa/cov_summary.py` |

My own files: 244 passed, 3 xfailed (strict) in 177 s, contended (CPU 100 %, 1.3 GB free). Command:
`.venv/Scripts/python -m pytest backend/tests/qa/test_qa_unit_*.py -q -m "not stress" -p no:cacheprovider`.
Final run of the same files under coverage: 244 passed, 1 deselected (stress), 3 xfailed in 97 s (`data/tmp/qa_cov/pytest_qa.txt`). Stress variant (`-m stress`): 200 000-case scan_lines corpus, 29 s.

## 2. Product bugs (strict xfail, for the owner: backend-builder)

| id | file:line | failing test | scenario |
|---|---|---|---|
| QA-COV-01 | `backend/attacklens/ingest.py:207` (`_BLANK`) vs `backend/attacklens/ingest_sql.py:32` (`NONEMPTY`) | `test_qa_unit_ingest.py::test_unicode_space_only_lines_are_not_decode_errors` | A JSONL line made only of U+00A0 / U+3000 (valid UTF-8) is skipped by the reader (`trim()` strips Unicode spaces) but counted as a line by `scan_lines` (ASCII space only), so the difference is reported as `decode_error (invalid UTF-8, line not readable)`: 2 rows of 4 "dropped" in a 4-line file with 2 real events. Wrong drop reason and a dropped-rows rate that is not real. |
| QA-COV-02 | `backend/attacklens/reach.py:104` | `test_qa_unit_reach.py::test_prepare_stats_keys_stable_without_events` | `reach.prepare` with no events returns `{admin_edges, flow_edges}`, otherwise `{admin_edges, flow_edges, ssh_edges}`; `incidents.run` copies it to `stats["reach"]` (run_metrics), so the key set depends on the data. Low severity. |
| QA-COV-03 | `backend/attacklens/api_runs.py:30,77` (`_STAGE_RE`, `_furthest_stage`) | `test_qa_unit_api_runs.py::test_furthest_stage_ignores_stage_words_in_file_names` | Stage progress matches any stage word anywhere in the log tail. A raw file named `eval-notes.txt` (logged by profile as unrecognized) makes `GET /api/runs/{id}` show stage `eval`, 96 %, while ingest is running. Reproduced on a real 2-file pipeline run (`data/tmp/qa_cov/stage_probe/run.log`, `partial.log` -> `eval`). `run_error` already matches only `stage <name> start` lines; the fix is the same for progress. |

Near-miss tests next to each bug pass today and must keep passing after the fix.

## 3. Coverage numbers

Source: `data/tmp/qa_cov/before.json` (full fast suite, coverage.py 7.17.0, `--branch --source=backend/attacklens`)
and `after.json` (= before + QA run, `coverage combine`). Line % = covered / statements; branch % = covered / total
branch arcs (coverage.py's own `Cover` column combines both: 86 % before).

Whole package before: lines 5462 / 6179 = 88.4 %, branches 1276 / 1662 = 76.8 %. A whole-package "after" is not
reported: `connect.py`, `connectors/*`, `httpc.py`, `integrations*.py`, `api.py` and three new modules were edited by
another session between the two runs, so their combined numbers mix two source versions.

Critical modules (21 files):

| module | stmts | line % before | branches | branch % before | line % after | branch % after |
|---|---|---|---|---|---|---|
| api_runs.py | 226 | 94.7 | 48 | 89.6 | 99.1 | 100.0 |
| api_upload.py | 239 | 94.6 | 62 | 91.9 | 100.0 | 100.0 |
| detect.py | 161 | 93.8 | 44 | 86.4 | 98.1 | 97.7 |
| detect_sql.py | 115 | 93.0 | 22 | 81.8 | 97.4 | 95.5 |
| detect_templates.py | 58 | 98.3 | 2 | 50.0 | 100.0 | 100.0 |
| detect_templates2.py | 23 | 100.0 | 0 | - | 100.0 | - |
| detect_templates3.py | 72 | 95.8 | 10 | 70.0 | 100.0 | 100.0 |
| detect_templates_net.py | 45 | 100.0 | 0 | - | 100.0 | - |
| episodes.py | 85 | 98.8 | 16 | 93.8 | 100.0 | 100.0 |
| incident_gate.py | 71 | 93.0 | 32 | 87.5 | 100.0 | 100.0 |
| incidents.py | 242 | 97.1 | 54 | 87.0 | 100.0 | 96.3 |
| ingest.py | 255 | 89.8 | 108 | 79.6 | 99.6 | 98.1 |
| ingest_sql.py | 202 | 98.5 | 56 | 76.8 | n/c * | n/c * |
| link.py | 129 | 93.8 | 32 | 75.0 | 100.0 | 100.0 |
| paths.py | 100 | 98.0 | 40 | 92.5 | 100.0 | 100.0 |
| publish.py | 61 | 95.1 | 8 | 100.0 | 100.0 | 100.0 |
| reach.py | 126 | 92.1 | 34 | 76.5 | 98.4 | 94.1 |
| sigma_compile.py | 234 | 88.0 | 122 | 80.3 | 99.1 | 98.4 |
| sigma_detect.py | 181 | 99.4 | 44 | 97.7 | 99.4 | 97.7 |
| sigma_rules.py | 276 | 95.7 | 70 | 88.6 | 97.1 | 95.7 |
| telemetry.py | 83 | 92.8 | 10 | 70.0 | 100.0 | 100.0 |

\* `ingest_sql.py` was edited at 01:11 (json_select now calls `ingest_maps.apply_source_maps`), after the baseline:
not comparable. The QA files alone cover the new version at 86.1 % lines / 67.9 % branches (`qa_only.json`).

Aggregate of the 20 unchanged critical modules: lines 2626 / 2782 = 94.4 % -> 2760 / 2782 = 99.2 %;
branches 645 / 758 = 85.1 % -> 744 / 758 = 98.2 %.

Branches that never ran in the fast suite before this track and matter most (now covered, exact values):
- `incident_gate.entities()` never executed: the allowlist check was always short-circuited by the empty shipped
  allowlist, so allowlist suppression had no test at all.
- `reach.load_graph` domain-admin grant (AdminTo every known DC) never executed.
- `incidents.run`: "more than N incidents per component" and "extracted path fails gate" + remainder re-gate.
- `paths.best_path`: seed hung off a shown predecessor when its own edge fails the tactic order; standalone seed.
- `ingest`: CSV reject accounting (`csv_missing_columns`), truncated-columns note, profile reuse from
  `source_profile.json` (and re-profile for another raw dir), stale partition removal on re-ingest, no recognized files.
- `link`: r1_ext_ip / r2_ext_ip_session / r3_match_target_user off; episode_select fallbacks for a narrow schema.
- `detect` validator: duplicate id, missing technique, unknown template / kind, template SQL compile failure;
  template guards (bf_key, lateral_direction, signature direction).
- `sigma_compile`: |fieldref, numbers on VARCHAR fields, keyword edge cases, assume_true near misses.

Still uncovered in critical modules (after): detect.py 190->191 (relabel without `secondary`), detect_sql.py 45->47
(db.sql_path missing fallback), incidents.py 55->58 (no edges.parquet), 234->238 (peel_tails off), ingest.py 305->293,
321->322 (physical lines < rows written: warning only), reach.py 72->74, 182->183, sigma_compile.py 155->163, 234->237,
sigma_detect.py 102->103 (group without keys), sigma_rules.py 117->123, 160->161, 164->165 (cache key miss, parse
errors, non-detection rules). Not chased (target was the important branches, not 100 %).

Measurement limits: coverage does not follow subprocesses, so `run.py` (63.8 % lines) is under-measured (the API and
CLI tests run the pipeline in a child process). All timings contended (CPU 100 %, 0.3-2.2 GB free RAM).

## 4. Open issues

- QA-COV-01 / 02 / 03 need fixes by backend-builder; the strict xfails will turn into XPASS failures when fixed
  (then drop the marker).
- README disclosure: add `coverage 7.17.0 (Apache-2.0)` as a dev / QA tool (not a runtime dependency; not added to
  `backend/pyproject.toml`, which this track does not own).
- The fast-suite budget (~2 min) is already exceeded under contention: the full suite took 633 s under coverage at
  CPU 100 %; the QA unit files add 177 s uncovered / 97 s in the final run on the same contended machine. Re-time on an
  idle machine before deciding what to move to `-m slow` / `-m stress`.
- `ingest_sql.py` changed mid-session; its "after" needs a re-measure (fast suite + QA files under coverage) on an idle
  machine. Same for the integration modules edited mid-session.
- Remaining uncovered arcs listed in section 3 (low value; mostly defensive fallbacks).
- `test_qa_unit_reach.py` / `test_qa_unit_incidents.py` import private helpers (`_new_ctx`, `_path_edge`) from conftest /
  product modules: renames there break these tests loudly (intended for white-box tests).
