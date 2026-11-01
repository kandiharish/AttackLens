# QA track: qa_injection (black-box attack injection into real FortiGate backgrounds)

Date: 2026-11-01 (UTC 2026-10-31 evening). Owner: QA (qa-tester). Product code was not changed.
Organiser logs are confidential. This file holds only counts, ids, percentages and timings. It has no line content,
no device names and no entity values from the real logs.
The attack entities shown below (RFC 5737 / RFC 1918 addresses, `qa_*` users, `FGT-QAINJ-*` devnames) are synthetic.

## What was built
- `tools/qa/inject_scan.py`: one bounded DuckDB pass per background (memory_limit 1GB, threads 2, TimeZone UTC,
  temp under `data/tmp/qa_inj`, optional `--max-rows` cap). It returns only aggregates:
  - the header key order and quoting;
  - eventtime digits, the eventtime local-vs-UTC class, tz values;
  - an hourly histogram of the timestamp that AttackLens computes (a mirror of `ingest_sql.kv_select`; a test
    checks it against the product SQL);
  - collision counts for the attack's IPs and users.
- `tools/qa/inject.py`: builds `data/raw/<key>_inj/` for n10, n30 and n50, plus slices (`--slice-of`). Each set has:
  - a hard link to the real log (`os.link`, checked with `samefile` and `st_nlink >= 2`; if linking fails the build
    stops, it never falls back to a copy);
  - `attack_inject.log`;
  - `ground_truth/attacks.json` (harness format);
  - `manifest.json` (seed, scenario ids, window, counts, collision counts, sha256 of the attack file and generators).
- How the attacks are made: `tools/fortigate_scenarios.scenario_lines(start, [F1..F4], seed=7, days=7)`, re-timed
  into the busiest 12 h window of the background:
  - F1 at +20 min, F2 at +3 h, F3 at +5 h 30 m;
  - F4 decoy once, 7 h 45 m after F1 (the same gap as in f1);
  - the 7 daily context instances spread across the window.
  - Every line is then re-headed in the background's convention: key order, quoting, 19-digit eventtime written as
    local time, the background's tz, LF.
  - Each line is re-parsed with the product convention and must give its intended ms, or the build fails.
- `--entities isolated` (default) maps the internal addresses to a 10.x/16 that the scan found unused, and the users
  to `qa_fwadm` / `qa_vpnusr`. `--entities generator` keeps the generator's values.

## Test matrix
| type | what | result | evidence |
|---|---|---|---|
| unit | product-ts mirror == `kv_select` SQL on 6 hand lines (local ns, UTC ns, ms + colon tz, s + west tz, no eventtime, us + no tz) + near-miss (`eventtime_is_local` off) | pass | `backend/tests/qa/test_qa_inject.py::test_product_ts_mirror_matches_kv_select_exact` |
| unit | scan aggregates on a 151-line hand background: rows, conventions, digits, tz, header order/quoting, span, collisions (3 / 0 / 2 / 0, net 10.77 = 1) | pass | `::test_scan_exact_aggregates` |
| unit | busiest window: exact w0 = T0 + 1 h, 132 rows; short-span branch `fits=false`; empty histogram refused | pass | `::test_choose_window_exact_and_short_span` |
| black-box | background is a hard link (samefile, nlink 2), set has exactly 4 files | pass | `::test_background_is_a_hard_link_not_a_copy` |
| black-box | `os.link` failure aborts the build, no copy appears | pass | `::test_link_failure_aborts_without_copy` |
| black-box | refuses non-`*_inj` dir and an existing dir without `--force` | pass | `::test_prepare_refuses_non_inj_and_existing` |
| integration | GT loads in `eval.harness.load_ground_truth`: 3 attacks, 13 steps, exact techniques, exact anchors (F1 w0+20m, F2 w0+3h, F3 w0+5h40m), synthetic host / user / WAN | pass | `::test_ground_truth_schema_and_exact_anchors` |
| integration | all 129 attack lines, parsed by the product SQL, fall inside [w0, w0 + 11 h] and inside the background span; every GT ts is a real line ts | pass | `::test_attack_timestamps_inside_window_by_product_parse` |
| black-box | attack lines copy the background header order, quoting and local eventtime class (LF); no generator devname / WAN / users / 10.10 / 10.212 | pass | `::test_attack_lines_copy_background_style_and_hide_generator_values` |
| unit | same seed gives a byte-identical attack file; generator mode keeps `admin` / 10.10.20.15 (near-miss of isolated) | pass | `::test_same_seed_is_byte_identical_and_generator_mode_keeps_values` |
| unit (product) | QAINJ-1 precondition: F1 incident built and starts with F1 brute force -> login | pass | `::test_qainj1_precondition_f1_incident_exists` |
| unit (product) | QAINJ-1: unrelated brute-force bursts on `admin` stay out of F1's path; all 6 F1 episodes shown | **xfail (strict)** | `::test_qainj1_unrelated_bruteforce_bursts_stay_out_of_the_attack_path` |
| black-box E2E | n10 300 MiB head slice + injection (isolated), strict harness | pass: 100 / 100 / 100, FA 0, step precision 100 | `data/out/qa_n10slice_inj/eval_scorecard.json` |
| black-box E2E | same slice, generator entities (attack shares IP / user with the real network) | partial: 100 / 100 / 100, FA 0, **step precision 24.53** | `data/out/qa_n10slicegen_inj/eval_scorecard.json` |
| unit | /24 fallback when every /16 is used: exact map into 10.77, shared target for 10.212.134.x; near-miss busy 10.77.20 -> 10.78; auto still prefers a free /16 (172.31, 192.168); all /24s busy -> refused | pass | `::test_map_nets_falls_back_to_free_24s_when_every_16_is_used` |
| unit | `busy24` mode picks a used /16 first; near-miss busy /24 -> next used /16 | pass | `::test_map_nets_busy24_prefers_used_16s` |
| unit | busy RFC 5737 IP swapped for the first unused stand-in; near-misses: stand-in busy, IP not in background, pool not probed | pass | `::test_map_external_swaps_busy_rfc5737_ips` |
| integration | scan /24 SQL end-to-end on the tiny background: `private_24_seen == [10.10.20, 10.20.0]`, busy24 maps into 10.77 (which has 10.77.5.5) and no mapped IP occurs in the background | pass | `::test_scan_exact_aggregates`, `::test_busy24_end_to_end_on_tiny_background` |
| black-box E2E | n10 slice rebuilt with the fixed injector: attack file byte-identical to v3 | pass | `data/raw/n10slice_inj/manifest.json` sha256 vs `data/tmp/qa_inj/n10slice_manifest_v3.json` |
| black-box E2E | same slice, `--nets busy24` (attack hosts inside the real network's busy /16) | pass: 100 / 100 / 100, FA 0, step precision 100 | `data/out/qa_n10slice24_inj/eval_scorecard.json` |
| black-box | n10 set built (scan + hard link + attack + GT), pipeline NOT run (a later stage runs it) | pass | `data/raw/n10_inj/manifest.json` |
| black-box | n30 / n50 sets built | **not done**: n30 had no free /16 (fixed in the injector, rebuild pending); n50 orphan build still running | see "Full-key builds" |

## n10 slice validation (`data/raw/n10slice_inj`, 300 MiB head of n10 copied, gitignored)
- Background scan:
  - 595,934 lines, all valid key=value with a valid ts;
  - 100 % `local` eventtime class, 19-digit eventtime, LF;
  - span 22.6 h, 23 hours with rows;
  - busiest 12 h window holds 437,086 lines; `fits=true`.
- Collisions between the generator's own entities and this real slice:
  - generator app server IP: 560 lines;
  - generator admin-network IP: 272 lines;
  - user `admin`: 35,717 lines;
  - every other attack IP and every candidate 10.x/16: 0.
- Pipeline command, shipped config (Sigma on):
  `python -m attacklens.run --raw data/raw/n10slice_inj --out data/out/qa_n10slice_inj --ground-truth data/raw/n10slice_inj/ground_truth/attacks.json`
- Accounting: rows_in 596,063 = 595,934 background + 129 attack lines; dropped 0 (`ingest_accounting.json`).
- Run cost (`run_metrics.json`): total_wall_s 76.925, peak_rss_mb 728.4. Contended: CPU load 93-100 %,
  1.4-2.3 GB free RAM, and another heavy real-log job running.

| run (same slice) | detection | labels | rebuilt | FA strict | step precision | source |
|---|---|---|---|---|---|---|
| v1: 6 h window, F4 80 min after F1, context once, generator entities | 84.62 | 100.0 | 66.67 | 0.0 | 21.57 | run log of this session (output dir overwritten) |
| v2: isolated entities, context once | 92.31 | 100.0 | 66.67 | 0.0 | 92.31 | run log of this session (output dir overwritten) |
| **v3 final: isolated, context x7, F4 at +7 h 45 m** | **100.0** | **100.0** | **100.0** | **0.0** | **100.0** | `data/out/qa_n10slice_inj/eval_scorecard.json` |
| v3 with generator entities | 100.0 | 100.0 | 100.0 | 0.0 | **24.53** | `data/out/qa_n10slicegen_inj/eval_scorecard.json` |

How each miss was diagnosed. Timestamps and format were correct in every run: every missed step was in
`raw_alerts` at dt 0.
- v1 F1 steps 5-6 missed. The generator's app server IP is a busy real host and a background hub in this slice.
  Also, user `admin` linked F1 to real brute-force noise (QAINJ-1).
  - Fixed in the injection: entities are isolated by default.
- v1 decoy problem: F4 fell 80 min after F1, inside the 2 h `cfg_after_login_window_ms`. Its config edit was then
  attributed to F1's IP. In f1 the gap is 7 h 45 m.
  - Fixed in the injection: F4 now keeps the f1 gap.
- v2 F2 step 3 (port scan) missed. One context instance alone is a rare internal SMB pair, so it became an
  `internal_lateral` alert and pulled the scan off the path. In f1 the context repeats 7 times and stays routine
  (`lateral_max_triple_seen: 2`).
  - Fixed in the injection: 7 context instances.
- v3 with generator entities: the attacked account `admin` is the same one that real internet bots brute-force.
  - Result: 36 unrelated real brute-force episodes were chained into F1's backbone (38 steps, 173 R3 edges), and
    F1's RDP / SMB / exfil steps were moved into branches. Product bug QAINJ-1.
  - The harness still counts this as rebuilt, because all steps are in the incident and the backbone is in order.
    Step precision (24.53) is the metric that exposes it.

## Product bugs
| id | file:line | failing test | scenario |
|---|---|---|---|
| QAINJ-1 (high) | `backend/attacklens/link.py:207-208` (R3 `i.tu = j.tu`), `:195-196` (R2 user session keyed on devname + user), path DP in `paths.best_path` | `backend/tests/qa/test_qa_inject.py::test_qainj1_unrelated_bruteforce_bursts_stay_out_of_the_attack_path` (strict xfail) | Internet brute-force bursts against `admin` from 8 unrelated IPs on another device are linked into F1's path. Links: R3 "account admin used" (a failed-login burst is not use of the account), and R2 "same session admin on <device>" across different source IPs. The DP then prefers this 10-episode noise chain as the backbone. The exfil step is suppressed on its own and the SMB step is hidden. On the real n10 slice this pulled in 36 real brute-force episodes. |

## Full-key builds (scan + hard link + attack + GT; pipeline not run)
| set | state | evidence |
|---|---|---|
| n10_inj | built: hard link (nlink 2), 12,398,551 rows scanned (100 % valid ts, 100 % `local`, 19-digit), span 168 h, busiest window 8,738,126 rows, `fits=true`, 129 attack lines, 13 GT steps, attack inside span; /16 level map (free /16s exist) | `data/raw/n10_inj/manifest.json`, `data/tmp/qa_inj/build_full2.log` |
| n30_inj | **not built**: first two builds aborted (`need 2 unused private /16 nets, found 0`); only the hard link and an empty `ground_truth/` are left | `data/tmp/qa_inj/build_full*.log`, scan cache `data/tmp/qa_inj/scan_cache/f9f7a71bcb1a46ebfac0.json` |
| n50_inj | **not built**: an orphan build from the crashed session (old injector code, PID 472) is still scanning after more than 75 min on the contended machine; not killed and not duplicated, as instructed | process list in this session |

Why n30 failed, from the n30 scan aggregates (37,183,090 rows, 100 % valid ts, 100 % `local`, 19-digit, span 168 h,
scan 670 s):
- Every 10.x /16 and every 172.16-31 /16 occurs in the background (272 of 272 probed /16s), so a whole unused /16
  does not exist.
- The synthetic WAN stand-in 198.51.100.1 occurs on 1 background line.

Fix, in the injection only (`tools/qa/inject.py`, `tools/qa/inject_scan.py`):
- The scan now also probes 192.168/16 and a /24 occupancy mask for the exact /24s the remap writes
  (thirds 0, 2, 20, 30, 40, 99, 134). Measured cost on the 300 MiB slice: 18.9 s vs 17.6 s / 14.7 s without
  (back-to-back, contended).
- `map_nets`: level 16 (a wholly unused /16, as before) when one exists; otherwise level 24: a used /16 in which
  none of the remapped /24s occurs. Both generator /16s may share one target when their /24s differ.
  The level per net is in `manifest.net_level`.
- `map_external`: an RFC 5737 attack IP that occurs in the background is swapped for an unused stand-in
  (`EXT_POOL`, 18 probed addresses). The effective WAN is in `manifest.synthetic.wan_ip`.
- No-regression proof: the rebuilt n10 slice gives a byte-identical `attack_inject.log` (same sha256 as v3), so the
  v3 scorecard above still applies.
- Fallback proof (`--nets busy24`, the worst case: map into a /16 the real network uses; the slice picked one of its
  busy /16s): `data/raw/n10slice24_inj`, accounting 596,063 in / 596,063 ok / 0 dropped,
  scorecard 100 / 100 / 100, FA strict 0, FA lenient 0, step precision 100 (13 / 13 steps, 3 / 3 incidents matched,
  0 unmatched). Run cost 84.3 s, peak RSS 877 MB, contended (CPU 100 %, 0.4-0.5 GB free RAM).
  Source: `data/out/qa_n10slice24_inj/eval_scorecard.json`, `run_metrics.json`, `ingest_accounting.json`.

Build commands for the later stage (one at a time, after PID 472 exits):
`python tools/qa/inject.py --keys n30 --force`, then `--keys n50 --force` (n10 optional: the new code gives the same
attack bytes when a free /16 exists).

## Open issues
- The pipeline was not run on n10_inj, n30_inj or n50_inj (as instructed). Command for the later stage:
  `python -m attacklens.run --raw data/raw/<key>_inj --out data/out/qa_<key>_inj --ground-truth data/raw/<key>_inj/ground_truth/attacks.json`.
- FA strict on real backgrounds counts any real-log incident as a false alarm. The harness cannot tell a real attack
  in the organiser's log from a false alarm, so on real data FA strict is an upper bound.
- The injected attack is a separate file with its own synthetic devname. A real attacker would hit the real device.
  - Firewall steps (F1 1-3, F2 1-2) therefore never share a host with the background.
  - A "same device" variant would need the real devname in the attack lines. Its value would then appear in data/
    only (gitignored), never in a report.
- One F4 decoy instance (f1 has 7). Six generator decoy instances are dropped (recorded in `manifest.dropped_groups`).
- QAINJ-1 is reported here but not fixed (owner: backend-builder). The strict xfail turns red when it is fixed.
- n30_inj and n50_inj are not built yet (see "Full-key builds"). The orphan n50 build runs the old injector. If it
  finishes, it will either abort like n30 (no free /16) or write a set without the external-IP check. Rebuild n50 with
  the fixed injector either way.
- On n30 / n50 the remapped hosts share a /16 with real hosts (level 24). The busy24 slice run shows this does not
  change the slice score. Any subnet-level product logic would still see them as neighbours of real hosts.
- The full fast suite was not run in this session (the task forbids it on the overloaded machine).
  Only `backend/tests/qa/test_qa_inject.py` was run: 16 passed, 1 xfailed (QAINJ-1), 42 s.
