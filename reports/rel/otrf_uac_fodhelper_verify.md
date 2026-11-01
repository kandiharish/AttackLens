# Verify: rel_otrf_uac_fodhelper (independent check)

**Verdict: CONFIRMED.** The official run 1 numbers reproduce exactly. Both main miss causes are correct. The second one is now confirmed, where the claim only said "very likely".

## 1. Ground truth
- I downloaded the metadata myself from raw.githubusercontent.com. Its sha256 is c58c34fd…d484d9, the same as `.dl/`. The zip I downloaded has sha256 b8cc7aae…c504, the same as `src/`. So the data is byte-for-byte as published.
- The metadata's attack_mappings contain only T1548 / sub 002 / TA0004. The GT has one step: T1548.002, Privilege Escalation. That is justified.
- adversary_view shows host WORKSTATION5 and user THESHIRE\pgustavo. The elevated agent F2X6GE4R checks in at 07:30:34. Host and user are justified.
- Time 07:30:13.801Z: I checked it against the raw zip. It is the earliest `@timestamp` of any line containing "fodhelper" (PowerShell 800, 290 matching lines). The registry hijack has Sysmon UtcTime 07:30:13.135/.151 and `@timestamp` 07:30:13.833. Both are well inside the 10-minute tolerance.
- Missing documented steps: none from attack_mappings. T1112, T1546.001 (Sigma tags) and the `shell whoami` (T1033) after elevation appear in the docs or tags but are not mapped. Leaving them out is consistent with the stated GT policy.
- sha256 of attacks.json is d52b2ca2…0390134, which matches the claim. attacks.json mtime is 10:59:40. The first run_metrics.json was written at 11:04:26. So the GT was fixed before the run.

## 2. Reproduction
- I ran the same snapshot command (159f2c2c6abf) into `data/out/rel_otrf_uac_fodhelper_verify`. Exit code 0, 15.6 s, peak RSS 95 MB. I waited until free RAM was about 1 GB.
- eval_scorecard.json is identical apart from the GT path field: detection 0, rebuilt 0, labels/FA/step precision null.
- ingest_accounting, source_profile, suppressed and incidents_index are identical after replacing the set name.
- Integrity verdict: SUSPECT, score 78. Deterministic.

## 3. Miss causes
- **ingest_format: CONFIRMED.**
  - The snapshot's profile.py has no zip handling. It returns "first line matches no known format" at line 118.
  - Accounting: unrecognized 5550/5550 dropped, `unrecognized_format`.
  - The working tree calls `cloud_unpack.raw_files` in profile.run (backend/attacklens/profile.py:306-309). That code was not tested here.
- **missing_rule (registry): CONFIRMED.**
  - The compiled Sigma cache (data/snap/rel/data/cache/sigma/*.json) lists `registry_event_shell_open_keys_manipulation.yml` (152f3630, level high) as skipped with reason `unmapped_field:Details`. `registry_set_susp_shell_open_keys_modification_patterns.yml` is skipped for the same reason.
  - The raw Sysmon 13 events exist (DelegateExecute with Details "(Empty)", and (Default) with the powershell -enc launcher).
  - Detail: even with Details mapped, the DelegateExecute event would be removed by the rule's `filter_main_empty`. Only the (Default) SetValue would match.
  - Native run_key_persistence and com_hijack do not match this path, as claimed.
- Diagnostic run 2 matches the claim:
  - det/labels/rebuilt 100, FA 0, step precision 33.33 (3 predicted steps).
  - inc-12cab9ee, dt 199 ms. pred T1548 is the parent technique, accepted under the parent rule.
  - suppressed: 2 components, both "fewer than 2 tactics".
  - Alerts: sigma_3268b746 and sigma_7f741dcf (2 each), encoded_powershell 7, sigma_93ff0ceb 9, discovery_system 6, sigma_1f21ec3f 1.

## 4. As published?
- Yes for run 1. The zip is unchanged and has the upstream sha256.
- Run 2 unpacked the zip with the product's own cloud_unpack CLI. It is labelled diagnostic, so it is not the official score.
