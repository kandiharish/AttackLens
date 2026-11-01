# Reliability run: rel_otrf_uac_fodhelper

- **Dataset:** OTRF Security-Datasets SDWIN-200904032946, "Invoke BypassUAC FodHelper" (Empire `privesc/bypassuac_fodhelper`)
- **URL:** https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/privilege_escalation/host/empire_uac_shellapi_fodhelper.zip (712,457 bytes, sha256 b8cc7aae…c3504)
- **Licence:** MIT (OTRF/Security-Datasets)
- **Code:** frozen snapshot `data/snap/rel` (SNAPSHOT_HASH 159f2c2c6abf), memory_limit 1GB, threads 2
- **Ground truth:** `data/raw/rel_otrf_uac_fodhelper/ground_truth/attacks.json`, sha256 `d52b2ca233a0a637b8535fa3f888c9cefbae907fe0a9237f792f1c9616390134`. Recorded before any run and unchanged after.
- **Free RAM before run 1:** 434 MB at first. Polled every 30 s and reached 1085 MB after about 3.5 min, then ran.

## Ground truth (from the metadata only)
| step | technique | tactic | host | user | ts (UTC) |
|---|---|---|---|---|---|
| 1 | T1548.002 Bypass UAC | Privilege Escalation | WORKSTATION5.theshire.local | pgustavo | 2020-09-04 07:30:13.801 |

- The technique and tactic come from `attack_mappings` (T1548 / 002, TA0004). The user and host come from `adversary_view` (THESHIRE\pgustavo on WORKSTATION5).
- The docs give no exact time. I took the time and host from ONE raw event: the earliest line containing the docs-quoted string "FodHelper", which is a PowerShell EventID 800.
- T1112 (Modify Registry) is not in `attack_mappings`, so it is not a GT step.

## Run 1: AS PUBLISHED (official result)
`--raw data/raw/rel_otrf_uac_fodhelper`. `src/` holds the zip exactly as downloaded.

| metric | value |
|---|---|
| detection_pct | 0.0 |
| labels_pct | null |
| rebuilt_pct | 0.0 |
| false_alarms_strict_pct | null |
| step_precision_pct | null |
| incidents | 0 |
| total_wall_s | 22.033 |
| peak_rss_mb | 100.4 |

| source_type | files | rows_in | rows_ok | dropped | drop_reasons |
|---|---|---:|---:|---:|---|
| unrecognized | src/empire_uac_shellapi_fodhelper.zip | 5550 | 0 | 5550 | unrecognized_format: 5550 |

- source_profile: the zip is `unrecognized`, with reason "first line matches no known format". Skipped: `.dl/` (hidden_dir), `ground_truth/`, `SOURCE.md`.
- The drop is accounted for, not silent. The 5550 "rows" are newline-split binary zip bytes, not records; the archive holds 4139 JSON records. The integrity stage flagged the file SUSPECT (score 78: malformed lines, no trailing newline).

### Diagnosis of the miss (step 1)
**Cause: ingest_format.**
- In the frozen snapshot, the batch pipeline (`attacklens.run`) never opens archives.
- `profile.py` sniffs the first text line of the zip and returns `unrecognized` (snapshot `backend/attacklens/profile.py:118`).
- Stage 0 unwrap (`cloud_unpack.py`) exists in the snapshot, but only as a separate CLI (`python -m attacklens.cloud_unpack`). In the snapshot, only `ingest.py:343` touches it, to read accounting; nothing calls it during profiling.
- The current working tree has wired it in (`backend/attacklens/profile.py:306-309` calls `cloud_unpack.raw_files`), so newer code may handle this. I did not test that here; the snapshot is what was run.

## Run 2: DIAGNOSTIC (not the official score)
This run checks whether detection works once the container is opened. I unpacked the zip with the product's own published Stage 0 CLI, from the snapshot:
`python -m attacklens.cloud_unpack --raw data/raw/rel_otrf_uac_fodhelper --out data/out/rel_otrf_uac_fodhelper/diag_unpacked_raw`
- Result: 1 file unpacked, 4139 records out, 0 failed. The copied GT file has the same sha256.
- I then ran the same pipeline command with `--raw` set to that directory, writing to `--out data/out/rel_otrf_uac_fodhelper/diag_run2`.

| metric | value |
|---|---|
| detection_pct | 100.0 |
| labels_pct | 100.0 |
| rebuilt_pct | 100.0 |
| false_alarms_strict_pct | 0.0 |
| step_precision_pct | 33.33 |
| incidents | 1 (inc-12cab9ee, risk 23) |
| total_wall_s | 42.826 |
| peak_rss_mb | 267.4 |

| source_type | rows_in | rows_ok | dropped | drop_reasons |
|---|---:|---:|---:|---|
| win_json | 4139 | 4139 | 0 | {} |

- **Matched step:** episode e228ae2abc5, rule `sigma_3268b746` ("HackTool - Empire PowerShell UAC Bypass", T1548.002). It is at 07:30:14.087 on workstation5.theshire.local / pgustavo, dt_ms 199, label OK.
- A second episode, ea3cbaa0a1a (`sigma_7f741dcf`, "Bypass UAC via Fodhelper.exe", fodhelper.exe -> powershell.exe), comes from the same events. R2 links the two.
- **Why step_precision is 33.33:** the incident has 3 steps:
  - 2 x T1548.002 (two Sigma rules on the same process-create events, not merged into one step);
  - 1 x T1059.001, from `encoded_powershell` (`config/rules.yaml:186`). This is real Empire stager activity, but it is not a GT step.
- **Suppressed (suppressed.json):** 2 components, both with reason "fewer than 2 tactics":
  - `encoded_powershell` episode ef211f4a535, conf 75, user NULL, so it could not R2-link;
  - `sigma_93ff0ceb` "Scheduled Task Created - Registry", T1053.005, conf 35, a threat-hunting rule. Both are outside the GT.

### Registry signal (does the registry detection carry over from Run keys?) — NO
- The `ms-settings` hijack is in the parquet. On host workstation5, at 07:30:13.135 and 07:30:13.151, `powershell.exe` writes these values (Sysmon 12 / 13, `action=reg_set`):
  - `HKU\<SID>_Classes\ms-settings\Shell\Open\command\DelegateExecute`
  - `HKU\<SID>_Classes\ms-settings\Shell\Open\command\(Default)`
- `TargetObject -> registry_path` parsing works.
- No rule fired on it:
  - Native rules: `run_key_persistence` (`config/rules.yaml:205`) only matches `\CurrentVersion\Run`. `com_hijack` (`config/rules.yaml:405`) only matches `clsid`. No native rule covers `ms-settings` / `exefile\shell\open\command`.
  - Sigma rule `registry_event_shell_open_keys_manipulation` (id 152f3630) is the one built for this, and it did not run. The snapshot's `config/sigma_map.yaml` has no mapping for the Sigma field `Details`, and `work/sigma_coverage.json` shows 183 rules skipped as `unmapped_field:Details`. This rule uses `Details` in selection_1 and in both filters, so it is very likely one of them; the coverage file does not list the skipped ids.
- So the UAC bypass was caught only through process creation (fodhelper spawning PowerShell, plus Empire's command line). The registry write itself was not detected. If the attacker had used a different auto-elevate binary (computerdefaults.exe, sdclt.exe), only the registry signal would remain.

## Findings
1. **ingest_format (blocking, as published):** the snapshot's `attacklens.run` does not unwrap `.zip` inputs. The whole set is dropped as `unrecognized_format` (accounted for, not silent). The fix appears to exist in the working-tree `profile.py:306-309`; it needs a rerun on a new snapshot to confirm.
2. **missing_rule / unmapped field:** no detection fires on the `ms-settings\shell\open\command` registry write. Sigma `Details` is unmapped, so 183 registry rules are skipped, and no native rule covers it. Registry detection does not carry over beyond Run keys and CLSID.
3. **step dedupe:** two Sigma rules that hit the same events with the same technique become two backbone steps. This halves step precision.
4. **entity gap:** one `encoded_powershell` episode has a NULL user, so it was not linked and was suppressed.
