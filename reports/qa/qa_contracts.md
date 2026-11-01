# QA track: qa_contracts (integration, stage contracts)

Date 2026-11-01, second pass (re-run after the 01:11 ingest_sql.py / sources.yaml changes). HEAD 6fbfe3c with an
uncommitted working tree. DuckDB 2.0.0, Python 3.12.10.
Tests: `backend/tests/qa/test_qa_contracts.py` + `test_qa_contracts_selfcheck.py`. Runner: `tools/qa/run_contract_sets.sh`.

## How the outputs were made
- Sets: `demo`, `f1` (with GT), `g50m` (with GT), `smoke_mixed` (no GT, see QA-C1). Small sets only; n10/n30/n50 were not touched.
- Command: `python -m attacklens.run --raw data/raw/<set> --out data/out/qa_<set> --parquet data/parquet/qa_<set> --config data/tmp/qa_config [--ground-truth ...]`.
- `data/tmp/qa_config` is now re-made from `config/` on every runner call and `cmp`-checked byte-identical, except
  `pipeline.yaml`: `memory_limit 1GB`, `threads 2`, `temp_directory data/tmp/qa_spill`. Rules, thresholds, sources and
  linking are unchanged. (The first pass used a copy that had gone stale: sources.yaml and integrations.yaml differed.)
- Timings are **contended**. The machine ran the n30 pipeline, an n50 injection job, a mutation run and about 6 other
  full pytest suites at the same time. Machine state at each start (`data/tmp/qa_contracts_runs2.log`):
  smoke_mixed 1305 MB free / CPU 100 %, g50m 472 MB / 100 %, demo 457 MB / 99 %, f1 967 MB / 84 %. All 4 runs rc=0.

## Test matrix
| Type | What | Result | Evidence |
|---|---|---|---|
| Integration | 7 work Parquets x 4 sets: §15.4 column names + DuckDB types | 28/28 pass | `data/out/qa_<set>/work/*.parquet` |
| Integration | events Parquet = §3.1 `CANONICAL_COLUMNS` exactly (no extras), hive dirs `source_type/ts_ok/event_day` | 4/4 pass | `data/parquet/qa_<set>/events` |
| Integration | raw_alerts values: v20 tactic + tactic_idx, ts <= last_ts, evidence <= 3 lines and <= 301 chars (§15.4), source_keys <= 50, severity 0-100 | 4/4 pass | raw_alerts.parquet |
| Integration | episodes + spilled: `episode_id` = md5 formula, bucket = ts_ms // 300000, user = coalesce, no dup ids, sum merged = sum raw_alert_count | 4/4 pass | episodes*.parquet |
| Integration | edges: R1-R4 only, endpoints are kept episodes, dt_ms = t_j - t_i >= 0, weight > 0, why_linked set, no dup (i,j,rule) | 4/4 pass | edges.parquet |
| Integration | host_ip_map: no loopback / `-`, first <= last | 4/4 pass | host_ip_map.parquet |
| Integration | ingest_accounting: rows_in = rows_ok + dropped, sum drop_reasons = dropped, totals = run_metrics | 4/4 pass | ingest_accounting.json |
| Integration | accounting re-counted from Parquet (rows_ok, quarantined per source) | 4/4 pass | events Parquet |
| Integration | sum rows_in = non-empty physical lines of the raw files (own byte counter, CSV minus header) | 4/4 pass | raw files + source_profile.json |
| Integration | episode_accounting: in_incidents + in_suppressed = episodes, 0 missing/dup, = Parquet counts, = sum incident.episode_count; suppressed.json totals | 4/4 pass | run_metrics.json `stage_stats.incidents` |
| Integration | run_metrics §15.6 keys + types, stages = run.STAGES (+eval), peak >= every stage peak, sum stage wall <= total | 4/4 pass | run_metrics.json |
| Integration | eval_scorecard §15.6 keys, pct in 0-100 or null | 3/3 pass, 1 skip (smoke_mixed has no GT) | eval_scorecard.json |
| Integration | every incidents/*.json validates against `models.Incident`; file name = id `inc-<8 hex>`; = work/incidents.json ids | 4/4 pass | out/incidents/ |
| Integration | incident consistency: backbone steps 0..n-1, entry step valid, ISO-Z times, steps inside [first,last], graph edges hit nodes, step evidence <= 300 chars (strict) | 4/4 pass | out/incidents/ |
| Integration | tactics: every step tactic in the 15 v20 tactics; `tactics` unique and in v20 order; gaps disjoint | 4/4 pass | out/incidents/ |
| Integration | incidents_index.json = files (ids, every summary field, hosts) and sorted risk desc | 4/4 pass | incidents_index.json |
| Static | attack_v20.json tactic list = schemas.TACTICS_V20 (15; Stealth, Defense Impairment at 7-8) | pass | config/attack_v20.json |
| Static | models.py <-> types.ts: 9 interfaces (every models.py class; Graph is checked inline in Incident), field names + order, nullability, literals, nested types | 9/9 pass | frontend/src/types.ts |
| Static | TS parser self-test + negative controls | pass | in-memory |
| Static | all 4 `mock/incident*.json` validate + round-trip; mock index.json validates | 5/5 pass | frontend/src/mock/ |
| Black-box | bare-list ground truth (`[]`) gives a clear error | **strict xfail (QA-C1)**; object-form control passes | data/tmp/qa_contracts_evidence/ |
| White-box (self-check) | positive control: an untampered copy of qa_g50m passes every check the tampers use | pass | tmp copy of data/out/qa_g50m |
| White-box (self-check) | 17 tampered copies, each must fail its check (accounting, raw bytes, deleted incident, old tactic name, tactic order, non-Z ts, index drift, extra field, run_metrics key/stage dropped, episode_id, lost episode, dt_ms type, dangling edge) | 17/17 caught | `test_qa_contracts_selfcheck.py::test_selfcheck_tamper_is_caught[*]` |
| White-box (self-check) | 6 types.ts mutants must show drift (rename, `| null` dropped, literal dropped, inline graph field dropped, nested type changed, order swapped) | 6/6 caught | `test_qa_contracts_selfcheck.py::test_selfcheck_ts_drift_is_caught[*]` |

Run: `cd backend && ../.venv/Scripts/python -m pytest tests/qa/test_qa_contracts.py tests/qa/test_qa_contracts_selfcheck.py -q`
-> **128 passed, 1 skipped, 1 xfailed in 51.57 s** (contended). Skip = smoke_mixed scorecard (no GT); xfail = QA-C1.

## Product bugs
| Id | File:line | Failing test | Scenario |
|---|---|---|---|
| QA-C1 (still open) | backend/eval/harness.py:46 (owner: test-engineer) | `test_qa_c1_ground_truth_bare_list_gives_clear_error` (strict xfail) | `data/raw/smoke_mixed/ground_truth/attacks.json` is `[]`. `doc.get` raises AttributeError, so the run ends with rc=1 after publish and writes no eval_scorecard.json. It should raise a ValueError that names the file, or score zero attacks. |

## Doc drift
- Resolved since pass 1: §15.4 now says raw_alerts / episodes evidence is <= evidence_max_chars + 1 = 301 chars, and
  incident step evidence is <= 300. Measured: every line over 300 is exactly 301 (demo 564, f1 4361, g50m 466,
  smoke_mixed 1 lines). Incident step evidence passes the strict 300 check on all 4 sets.
- `background_hubs` has an extra `median_peers DOUBLE` column that §15.4 does not list. Extra columns are allowed.

## Numbers (source: data/out/qa_<set>/run_metrics.json; contended, 1 GB / 2 threads)
| Set | rows_in | total s | peak MB | rows/s | episodes | incidents | profile | ingest | lookups | detect | episodes | link | incidents | publish | eval |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| demo | 255 244 | 80.11 | 510.1 | 3 186.0 | 183 | 5 | 4.97 | 15.59 | 0.63 | 34.95 | 0.72 | 0.94 | 0.68 | 0.55 | 2.71 |
| f1 | 2 036 104 | 418.93 | 669.1 | 4 860.3 | 1 457 | 3 | 14.02 | 305.60 | 5.93 | 75.47 | 1.30 | 0.74 | 2.73 | 1.61 | 1.93 |
| g50m | 64 176 | 50.06 | 210.0 | 1 281.9 | 75 | 5 | 6.37 | 4.16 | 0.41 | 30.31 | 0.30 | 0.76 | 0.86 | 0.54 | 0.73 |
| smoke_mixed | 23 | 41.13 | 158.8 | 0.6 | 9 | 2 | 0.15 | 1.60 | 0.33 | 22.63 | 0.59 | 0.47 | 1.08 | 0.65 | - |

- Stage times are wall seconds. Detect takes >= 22 s even on 23 rows, because Sigma loads and scans its rules.
- Peak stage (run_metrics `stages[].peak_rss_mb`): ingest on demo, f1 and g50m; detect on smoke_mixed.
- Pass 1 to pass 2: the counts are the same (rows, episodes, incidents, accounting, scorecards). The times are 1.4-2.9x
  slower, because pass 2 ran at 1 GB / 2 threads under heavier load (pass 1: 1.5 GB / 4 threads). f1 ingest went from 94.6 s to 305.6 s.
  Do not read this as a regression.
- Ingest accounting (ingest_accounting.json): demo, f1 and g50m drop 0 rows. smoke_mixed (in/ok/dropped): cef 3/2/1,
  ecs_json 7/6/1, syslog 5/4/1, firewall_csv 3/3/0, win_json 3/3/0, unrecognized 2/0/2. Every drop has a reason.
- Episode accounting (in_incidents + in_suppressed = episodes): demo 33 + 150 = 183, f1 13 + 1444 = 1457, g50m 37 + 38 = 75,
  smoke_mixed 5 + 4 = 9. 0 spilled.
- Scorecards (eval_scorecard.json): demo and g50m: detection / labels / rebuilt 100, strict and lenient FA 0, singleton
  recall 100. f1: 100 / 100 / 100, FA 0, singleton recall null (no noise GT). step_precision_pct / _all_pct: demo
  80.77 / 80.77, g50m 65.62 / 65.62, f1 100 / 100.

## Open issues
- All timings are contended: CPU was at 84-100 % and free RAM was 457-1305 MB. Do not use them as benchmark claims.
- QA-C1 is still open. It has two parts: the harness crash (harness.py:46), and run.py, which re-raises an eval error
  and so marks a run as failed (rc=1) even though all 8 stages finished. The smoke_mixed GT file is also not in the
  §3.3 object form.
- There is no run-progress / ETA field in models.py or run_metrics (searched backend/attacklens for eta / remaining /
  progress). The UI ask, "ingest time + approx time remaining", has no backend contract to test yet. When one is added,
  it needs a key in §15.6 and a test here.
- The tests read outputs that `tools/qa/run_contract_sets.sh` writes. On a clean checkout they skip with that command
  as the reason. The self-checks need data/out/qa_g50m.
- Full fast suite (`pytest backend -q -m "not stress"`, run once, log in `data/tmp/qa_contracts_fast_suite2.log`): it was
  **killed by the 25-minute timeout (rc=124) at about 75 %** (1305 of about 1771 tests), with 17 `F` before the kill.
  -q does not name the tests, so I matched the failure positions to a `--collect-only` list
  (`data/tmp/qa_contracts_collect.txt`). This is approximate, because other agents were adding test files during the run.
  The matches point at test_api_upload.py (9), test_api_integrations.py (3), test_ingest_fortigate.py (2), qa_api (1)
  and qa_ui (1). A targeted re-run of test_ingest_fortigate.py passed (32 passed, 1 xfailed), so at least those 2
  matches are wrong or flaky. The other failures are in API files outside this track and were not re-run here. The
  < 2 min budget cannot be judged under this load.
