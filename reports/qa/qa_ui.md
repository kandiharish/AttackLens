# QA track qa_ui: frontend static checks, read-only UI smoke, run-time / ETA display

Date: 2026-11-01, 01:48 to 03:04 IST. Second pass, after the header/footer cleanup and the new ingestion-time / ETA UI.
The machine was busy: a heavy real-log job was running, other QA tracks were running pytest, and the frontend and
backend builders were still editing files during this session (see "Concurrent edits"). Every timing below is
**contended**. CPU and free RAM come from `Get-CimInstance`: 100 % / 1.03 GB at the first smoke, 100 % / 1.97 GB at
the final smoke (03:03).

## How it was run
- Static checks in `frontend/`: `npm run build`, `npx tsc --noEmit -p tsconfig.app.json`, `npx oxlint src`.
- UI smoke: `tools/qa/ui_smoke.mjs` runs headless Chrome over the DevTools protocol (Node 22, no npm deps).
  Playwright MCP tools are not available to this agent, so the task's fallback was used.
  - **Read-only:** the browser's Fetch domain fails every non-GET `/api/*` request and records it. Every run had
    `blocked_writes: []`. Nothing was uploaded, no run was started and the served data was never switched.
  - Expected values come from `GET /api/incidents`, `/api/incidents/{top}`, `/api/metrics` and `/api/health` on the
    same base URL. The script then compares the UI against them exactly.
  - New in this pass:
    - header audit: exactly the brand, 3 nav pills and 1 status dot, with 4 focusable controls;
    - footer audit: the exact text built from `run_metrics.json`, with 0 focusable controls;
    - the dev-only RunStepper harness (`/?harness=run-stepper`, no API calls), checking ETA headlines, the ingest
      line, the progress bar and the smoothing table against hand-computed values;
    - keyboard reaches Connections and the status dot;
    - Chrome robustness: a fresh profile per run, a CDP fallback to `[::1]`, and the whole process tree killed.
- Targets:
  - `shared5173`: http://127.0.0.1:5173 (proxies to :8000, which serves g1x). GETs only.
  - `demo`, `qa_demo`: a private stack, so QA-UI-1/2/3 could be checked on sets that show them without touching the
    shared server. It was the API on 127.0.0.1:8037 (`ATTACKLENS_OUT=data/out/<set>`) plus Vite on 127.0.0.1:8038
    (`tools/qa/ui_vite_private.mjs`, cacheDir under data/tmp), with CDP on 8032–8036. Both private servers were
    stopped afterwards.
- Unit and contract tests:
  - `backend/tests/qa/test_qa_ui_timing.py` (new): calls the real `lib/addData.ts`, `lib/metrics.ts` and
    `lib/format.ts` through `node --experimental-strip-types`, plus `attacklens.progress_eta.status_fields` and
    `RunManager.status`.
  - `backend/tests/qa/test_qa_ui.py` (unchanged).

## Static checks (pasted outputs, final run at 02:20)
```
$ npm run build
> tsc -b && vite build
✓ 60 modules transformed.
dist/index.html                     0.47 kB │ gzip:   0.30 kB
dist/assets/index-CZjVBhn_.css     44.04 kB │ gzip:   9.03 kB
dist/assets/index-Y_xgEDwJ.js     845.75 kB │ gzip: 263.76 kB
✓ built in 1.57s                                  rc=0
$ npx tsc --noEmit -p tsconfig.app.json           (no output) rc=0
$ npx oxlint src                                  (no diagnostics) rc=0
```
Earlier runs in this session failed while the builders were mid-edit:
- 01:48: tsc found a TopBar/StatusBar props mismatch (`dataset`, `incidentCount`) and a missing `baseName` export.
- 01:58: tsc and oxlint found an unclosed JSX tag in `components/integrations/ConnectionForm.tsx:410`.

Both were fixed by their owners within minutes. Neither is reported as a bug.

## Test matrix
| Type | What | Result | Evidence |
|---|---|---|---|
| integration | `npm run build` | pass | output above; JS 845.75 kB (263.76 kB gzip) |
| integration | `tsc --noEmit -p tsconfig.app.json` | pass (final) | rc=0 |
| integration | `oxlint src` | pass (final) | rc=0, no diagnostics |
| integration (UI) | Page loads; no console errors, no uncaught exceptions, no HTTP >= 400 | pass | reports/qa/ui/{shared5173,demo,qa_demo}_result.json `console_errors`, `http_errors` = [] |
| integration (UI) | Header: only "AttackLens" + Incidents / Add data / Connections + one status dot (4 focusables, 65 px) | pass | shared5173_result.json `header`; shared5173_01_list_1920.png |
| integration (UI) | Footer text == `Connected <set> <rows> events · ingested in <ingest wall_s> · analysed in <total_wall_s> AttackLens v0.4.0` from run_metrics.json; no controls | pass | g1x: "1.3 M events · ingested in 14.2 s · analysed in 28.6 s" (rows_in 1305412, ingest 14.193 s, total 28.561 s); demo: "255.2 k events · ingested in 10.4 s · analysed in 1m 4s" |
| integration (UI) | Incident list row count == GET /api/incidents; first row == riskiest | pass | g1x 5==5, demo 5==5, qa_demo 5==5 |
| integration (UI) | Open top incident: 6 tabs (Overview, Step by step, Graph, Evidence, Reach next, Report) all render | pass | shared5173_02_tab_*.png, demo_02_tab_*.png |
| integration (UI) | Graph: aria entity/edge counts == incident.graph; canvas painted | pass | g1x 7/4 == API, 8352 ink samples; demo 11/8 == API, 11009 |
| integration (UI) | Kill-chain bar: observed set == incident tactics; gaps == incident.gaps | pass | g1x 7 == 7, 5 gaps; demo 7 == 7, 5 gaps |
| integration (UI) | Evidence rows == sum(step.evidence); reach rows == reach_next | pass | g1x 13==13, 2==2; demo 12==12, 1==1 |
| integration (UI) | Kill-chain segment click opens the Inspector | pass | shared5173_03_inspector_1920.png |
| integration (UI) | Header "N steps across M machines" uses one step set | **fail (QA-UI-3)** on demo; pass on g1x (no branches) | demo_result.json `header_counts`: UI [5,7], backbone [5,2], all [10,7] |
| integration (UI) | Footer data path (tooltip) == /api/health served_out_dir | **fail (QA-UI-2)** on demo; pass on g1x | demo_result.json `status_bar_data`: `/app/data/out/demo` vs `C:\cyberforge\data\out\demo` |
| integration (UI) | Add data: both options (drop zone + Browse files + file input; path form) | pass | *_04_add_data_1920.png |
| integration (UI) | Add data: path submit disabled when empty; Analyse disabled with no source | pass | *_result.json `add_data` |
| integration (UI) | Coverage card visibility == readSigma() logic | pass | all runs |
| integration (UI) | Coverage card shown when stage_stats.detect has Sigma keys | **fail (QA-UI-1)** | qa_demo_result.json: hidden, stage_stats.detect total 3779 / applicable 1570 |
| integration (UI) | Keyboard: Tab reaches Incidents, Add data, Connections, status dot, search, sort, incident row, incident tab; ArrowRight (tabs), ArrowDown (list) | pass | shared5173_result.json `keyboard.tab_order` |
| integration (UI) | Focus indicator on every focused control | pass (weak, see open issues) | same |
| integration (UI) | 1366x768 + 1920x1080: no horizontal scroll (6 tabs + Add data + harness); tab strip not clipped | pass | 27 viewport checks per run; *_05_*.png, shared5173_06_harness_run_stepper_1366.png |
| integration (UI) | RunStepper harness: headlines exact (old backend: none; 371 s: "About 6 min remaining"; null: "Estimating time…"; 6 s: "Finishing…"; "Finished in 9m 8s"; "Stopped after 6m 42s") | pass | shared5173_result.json `harness`; shared5173_06_harness_run_stepper_1366.png |
| integration (UI) | Harness: ingest line "Ingestion: 3.20 GB of 6.50 GB · 31 MB/s"; progressbar 49 at fraction 0.49; no bar when fraction is null | pass | same |
| integration (UI) | Harness: ETA smoothing table == hand-computed EMA (null, 420.0, 404.7, 485.6 capped, 419.4, 414.8, 583.3 uncapped after stage change, 678.9, 440.0) | pass | same |
| integration (UI) | Read-only: no non-GET /api request attempted | pass | `blocked_writes: []` in all result files |
| unit | fmtEta: 18 exact values across every band and edge (null, NaN, < 10 s, 5 s steps, minutes, 3569 vs 3570 s, hours) | pass | test_qa_ui_timing.py::test_fmt_eta_exact_bands |
| unit | smoothEta: exact 9-poll sequence (20 % cap hit, cap lifted on stage change, negative raw -> 0), +3 s floor | pass | test_smooth_eta_exact_sequence, test_smooth_eta_growth_floor_three_seconds |
| unit | smoothEta near misses: new run id, clock backwards, same poll twice, null mid-run | pass | test_smooth_eta_resets_near_misses |
| unit | ingestLine exact (rate >= 10 / < 10, no done, clamp, rate 0) + near misses (total 0, missing, null) | pass | test_ingest_line_exact |
| unit | stepTimes groups backend stages (negative clamp, unknown stage, null wall, case) | pass | test_step_times_groups_backend_stages |
| unit | readRunTiming exact + 3 fallbacks; fmtCount / fmtSeconds / baseName exact | pass | test_read_run_timing_exact_and_fallbacks, test_footer_formatters_exact |
| integration (contract) | RunStatus progress keys in frontend/src/api.ts == keys of backend status_fields() (10 keys) | pass | test_run_progress_keys_match_frontend_contract |
| integration (contract) | status_fields during ingest, fixed clock: exact dict (fraction clamp, junk stages_done dropped, 10.0 MB/s) | pass | test_run_progress_fields_exact_while_ingesting |
| integration (contract) | Running, no progress.json: nulls -> UI "Estimating time…", no ingest line | pass | test_run_progress_fields_near_miss_no_progress_file |
| integration (contract) | Real RunManager.status() on a running stub process in stage ingest: base keys + all progress keys | pass | test_run_status_running_job_has_progress_keys |
| unit (bug) | QA-UI-1 / QA-UI-2 / QA-UI-3 strict xfail | xfail (3) | backend/tests/qa/test_qa_ui.py |

Smoke totals (pass/total):
- shared5173 (g1x): 73/73 at 02:1x. The rerun at 02:25, during the full fast suite, gave 71/73. Both failures were
  wait timeouts under load (page load > 20 s; harness lazy chunk > 10 s); the values themselves were correct. The
  timeouts are now 60 s / 45 s, and the load time is recorded as `load_ms`.
- shared5173 final rerun at 03:03 (CPU 100 %, 1.97 GB free): **73/73**, load_ms 7997, opened in 173 ms. No
  frontend file changed after 02:13.
- demo: 66/68 (QA-UI-2, QA-UI-3).
- qa_demo: 67/68 (QA-UI-1).

## Product bugs (owner: frontend-builder)
| Id | Severity | file:line | Failing test | Scenario |
|---|---|---|---|---|
| QA-UI-1 | medium | frontend/src/lib/addData.ts:120 | test_qa_ui.py::test_read_sigma_documented_location_shows_card | readSigma reads `run_metrics.sigma_rules_*` at the top level. The backend writes them under `run_metrics.stage_stats.detect` (DEVELOPMENT.md 15.6), so the "Detection coverage" card on Add data never shows. Note: the new `lib/metrics.ts readRunCounts` already reads `stage_stats.detect` correctly, so the two readers disagree. |
| QA-UI-2 | low | frontend/src/App.tsx:219 | test_qa_ui.py::test_status_bar_data_dir_is_served_out_dir | The footer data name comes from `run_metrics.out_dir`, not `/api/health served_out_dir`. The visible text is now only the basename ("demo"), which hides the bug when the names match, but the tooltip still shows `/app/data/out/demo` (Docker path) while the API serves `C:\cyberforge\data\out\demo`. |
| QA-UI-3 | low | frontend/src/components/Workspace.tsx:104 | test_qa_ui.py::test_header_step_and_machine_counts_use_one_step_set | The header shows "5 steps across 7 machines": 5 = backbone steps (they touch 2 machines), 7 = machines over all 10 steps. The "Step by step" badge on the same screen says 10. |

Steps to reproduce:
- **QA-UI-1:** serve `data/out/qa_demo` (its run_metrics has `stage_stats.detect.sigma_rules_total` 3779), open
  `#add-data`, and see no "Detection coverage" section.
- **QA-UI-2:** serve `data/out/demo` and hover the footer set name. The tooltip shows `/app/data/out/demo`, while
  `GET /api/health` shows `served_out_dir` `C:\cyberforge\data\out\demo`.
- **QA-UI-3:** serve `data/out/demo` and open inc-853d956b. The header says "5 steps across 7 machines", while the
  tab badge says 10.

The earlier candidate "backend sends no ETA keys" was closed while I was testing. A strict-xfail test of mine
XPASSed at 02:02, because `progress.py` / `progress_eta.py` and the `api_runs.status()` progress keys landed at
02:00–02:02. It was replaced by the four passing contract tests above.

## Numbers (source)
| Number | Value | Source |
|---|---|---|
| Open-incident render (click -> rendered, UI badge) | g1x 86 ms and 173 ms (final); demo 166 ms; qa_demo 217 ms (all contended) | *_result.json `opened_in`; target Great < 500 ms (lib/targets.ts) |
| Footer timing, served g1x run | 1,305,412 rows; ingest 14.193 s; total 28.561 s | data/out/g1x/run_metrics.json (`rows_in`, `stages[ingest].wall_s`, `total_wall_s`) |
| Page load to list rendered (final shared run) | 7997 ms at CPU 100 % | shared5173_result.json `load_ms` |
| Smoke wall time | shared5173 44.4–58.6 s, 47.8 s final (141.1 s while the full suite ran); demo 79.2 s; qa_demo 60.1 s | *_result.json `wall_s` |
| JS bundle | 845.75 kB / 263.76 kB gzip (was 822.12 / 256.51) | npm run build output |
| qa_ui pytest | 19 passed, 3 xfailed in 17.30 s | `pytest backend/tests/qa/test_qa_ui_timing.py backend/tests/qa/test_qa_ui.py -q -rxX` |

## Screenshots (reports/qa/ui/)
- `shared5173_01_list_1920.png`, `shared5173_02_tab_{overview,steps,graph,evidence,reach,report}_1920.png`,
  `shared5173_03_inspector_1920.png`, `shared5173_04_add_data_1920.png`,
  `shared5173_05_{1366x768,1920x1080}_{overview,graph,add_data}.png`, `shared5173_06_harness_run_stepper_1366.png`
- `demo_*` and `qa_demo_*`: the same set from the private stack (no harness).
- `demo2_result.json`: one demo run where the footer was checked 800 ms after the list loaded, before
  `/api/metrics` had arrived. It read "Connected — AttackLens v0.4.0". The check now waits up to 10 s; the next
  run waited 5 ms.

## Full fast suite (one run, contended)
- I ran `pytest backend -q -m "not stress"` once, from 02:20 under `timeout 2400`. It was **killed by the timeout at
  66 %** (rc=124, 03:01). CPU was at 100 %; at 03:04, 22 python processes matching pytest|attacklens were running on the machine.
- Up to the kill point there were **0 failures and 0 errors**: only `.`, `x` (expected xfails) and one `s`.
- I have no summary line or counts because the run did not finish. The output is in
  `data/tmp/qa_ui/full_fast.out` (gitignored).
- The targeted qa_ui files pass (19 passed, 3 xfailed).

## Open issues
- **Two different "ingestion" times.**
  - The footer "ingested in" is the `ingest` stage wall only: 14.2 s on g1x.
  - The RunStepper "Reading" step sums profile + ingest + lookups: 4.551 + 14.193 + 0.857 = 19.6 s for the same run.
  - Both read raw files. The labels should say what each one counts (frontend-builder).
- **Mixed units on the ingest line.** `ingest_mb_s` is decimal (bytes / 1e6, progress_eta.py), while `fmtBytes`
  shows binary GB/MB (1024^n) on the same line. That is a 4.9 % mismatch at the MB scale.
- **ETA in a real run not checked end to end.** The task forbids starting runs through the UI. The ETA path is
  covered by:
  - the harness (fake RunStatus objects);
  - unit tests of the real TS helpers;
  - backend contract tests (status_fields and RunManager.status on a stub process).

  A live run on a small set via a private API (POST on a private port) would close this gap. That run needs a
  pipeline job, which this track avoided on the shared machine.
- **Old backend shows no headline.** With no `eta_s` key at all, RunStepper now shows no remaining-time headline,
  not "Estimating time…". This is a design choice (02:12 change); the harness expectation was updated.
- **Footer shows "—" until `/api/metrics` answers.** This is harmless, but the footer is momentarily blank on a cold
  API.
- **Focus-indicator check is weak.** It accepts any outline or box-shadow; it is not a contrast audit.
- **Chrome leftovers.** After a smoke, netstat sometimes still lists a CDP port (8032–8035, 8039) owned by a Chrome
  PID that has already exited. taskkill reports "no running instance", and the sockets clear later. The smoke now
  uses a fresh profile per run and takes `--cdp` from 8031–8039.
- **Not smoke-tested:** mock mode (`VITE_USE_MOCK=true`) and the "API offline" state.
- **Concurrent edits.** The builders kept editing during this session: TopBar, StatusBar, format, api, addData,
  RunStepper, AddDataPage, App, main and dev harness between 01:48 and 02:13; integrations/* until 01:56; backend
  progress at 02:00–02:02. The results describe the tree as of 02:13.
