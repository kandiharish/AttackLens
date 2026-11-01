# Reliability run: rel_otrf_empire_dcsync (OTRF Empire DCSync, unseen)

**Bottom line:** 0 % detection. The as-published zip was **never opened**: 100 % of the bytes were dropped as
`unrecognized_format`, and that drop was accounted for, not silent. A second, diagnostic run on the extracted JSON member could not
read the file because **Windows Defender quarantined it** (Empire/Mimikatz PowerShell inside the logs). Even with both
blockers out of the way, the frozen snapshot has **no DCSync rule that can fire**: the Sigma rule is skipped because
the `Properties` field isn't mapped.

## Dataset
| Item | Value |
|---|---|
| Source | OTRF Security-Datasets atomic SDWIN-190301174830 "Empire DCSync" |
| URL | https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip |
| Licence | MIT (OTRF/Security-Datasets) |
| Download | 655,112 B, sha256 `fe1fcc96c0ff0cbae8fd4ffaadf85f51e28475441774f6fda3d963d4e2962800` |
| Archive listing (checked first) | 1 member, `empire_dcsync_dcerpc_drsuapi_DsGetNCChanges_2020-09-21185829.json`, 38,828,677 B, no path parts |
| Raw layout used | `data/raw/rel_otrf_empire_dcsync/src/empire_dcsync.zip` (as published, no converter) |

## Ground truth (written before any run)
- File: `data/raw/rel_otrf_empire_dcsync/ground_truth/attacks.json`
- sha256 **before** the first pipeline run: `565cb644e2e493ca51c893d4bf2f6a32ed4c9a33f31ae1a7766492c987ce9ba0` (not edited afterwards)

| Step | ts_ms (UTC) | Technique | Tactic | Host | User | src_ip |
|---|---|---|---|---|---|---|
| 1 | 1600729163579 (2020-09-21T22:59:23.579Z) | T1003.006 | Credential Access | MORDORDC.theshire.local | pgustavo | 172.18.39.5 |

Where each value comes from:
- Technique, tactic: metadata `attack_mappings` (T1003 / 006, TA0006).
- Host (the DC that answers replication), user, IP: metadata `adversary_view` (agent on WORKSTATION5 172.18.39.5
  as `THESHIRE\pgustavo`, `set dc MORDORDC.theshire.local`).
- Time: the docs give no exact time. I located ONE raw event by the docs-quoted module string `dcsync` (line 6817,
  PowerShell 4103 on WORKSTATION5, AccountName pgustavo) and read only its `@timestamp`. The playbook link in the
  metadata returns 404, so it was not used.

## Runs (frozen snapshot `data/snap/rel`, SNAPSHOT_HASH 159f2c2c6abf, memory_limit 1GB, threads 2)
Free RAM before run 1 was 519 MB, which reached 802 MB after a 30 s poll, so run 1 started without waiting further.

| Run | Raw | Exit | wall_s | peak RSS MB | incidents |
|---|---|---|---|---|---|
| 1, as published (scored) | `rel_otrf_empire_dcsync/` (zip) | 0 | 19.818 | 99.7 | 0 |
| 2, diagnostic (extracted member) | `rel_otrf_empire_dcsync/unzipped/` | 1 (OSError 22) | 0.3 | 53 | n/a |

### Run 1 scorecard (`data/out/rel_otrf_empire_dcsync/eval_scorecard.json`, verbatim)
| Metric | Value |
|---|---|
| detection_pct | 0.0 |
| labels_pct | null |
| rebuilt_pct | 0.0 |
| false_alarms_strict_pct | null |
| step_precision_pct | null |
| gt_steps / predicted_steps / incidents | 1 / 0 / 0 |

### Run 1 ingest accounting (`ingest_accounting.json`)
| source_type | rows_in | rows_ok | dropped | drop_reasons | files |
|---|---|---|---|---|---|
| unrecognized | 6772 | 0 | 6772 | unrecognized_format: 6772 | src/empire_dcsync.zip |

`source_profile.json`: `src/empire_dcsync.zip` has format `unrecognized`, reason `delimited header matches no csv
source: ['PK\x03\x04...']`. `ground_truth/attacks.json` and `SOURCE.md` were skipped correctly.
`integrity_report.json`: verdict `suspect`, `ingest_drops` fail (high: 6772 of 6772 lines dropped), `truncated_tail` warn.
`suppressed.json`: total 0, because nothing reached the gate.

## Diagnosis of the missed step
**Step 1 (T1003.006 DCSync), cause: ingest_format, plus a second blocker (missing_rule).**

1. **Zip not unpacked by the snapshot (primary).** The unpack code is present
   (snapshot `cloud_unpack.py` `classify()` returns `"zip"` at lines 44-45, and `raw_files()` exists), but the
   snapshot's profile stage never calls it. Snapshot `backend/attacklens/profile.py:295` does
   `for path in sorted(root.rglob("*"))` straight over the raw files, so the zip bytes go to the CSV/text sniffer and
   all 6,772 "lines" are dropped. In the live repo, `backend/attacklens/profile.py:299` already routes files through
   `cloud_unpack.raw_files(...)`, so the snapshot is behind the working tree. Once the snapshot is refreshed, the live
   code should open this zip. That isn't verified here.
2. **Antivirus (environment).** The extracted 38.8 MB JSON was quarantined by Microsoft Defender on open ("file
   contains a virus or potentially unwanted software", ThreatID family seen on other Empire sets 2147895685; my own
   command lines containing the mimikatz command string were blocked too, ThreatID 2147741009). Per the run rules, the
   file was deleted and AV was not bypassed. With the live unpack wired in, the member would be written to
   `data/out/<set>/work/unwrapped/` and would most likely be quarantined there as well. **Any Empire / Mimikatz
   dataset will fail this way on a Defender-protected demo machine unless the user decides on an exclusion for
   `data/`.** That decision is the user's, not the pipeline's.
3. **No DCSync detection that can fire (missing_rule), even if the data were ingested.**
   - `config/rules.yaml` has no native 4662 / replication-GUID rule (no match for `4662`, `1131f6a`, `DS-Replication`).
   - The bundled Sigma rule `win_security_ad_replication_non_machine_account.yml` (id 17d619c1, T1003.006, needs
     `EventID 4662` + `Properties|contains` the 1131f6aa / 1131f6ad GUIDs) cannot compile. `config/sigma_map.yaml:31`
     sets `unmapped_field_policy: skip`, and `Properties` is not in the field map (only `SubjectUserName` at line 45 and
     `EventID` at line 65 are), so the rule falls into the `unmapped_field` bucket (783 rules skipped for that reason in
     this run's `work/sigma_coverage.json`). `config/sources.yaml` has no win_json alias for `Properties` either.
   - If a detection existed, the gate would not block it. `config/linking.yaml:115-121` `single_step_critical` lists
     T1003 (min_confidence 80), so a lone DCSync alert at confidence 80 or above would become an incident.

What was **not** observed: whether this dataset's 4662 events actually carry the replication GUIDs. I didn't read
that, because the file is AV-blocked once extracted.

## Recommended fixes (for the owners; nothing edited here)
- Refresh `data/snap/rel` from the live tree, which has profile.py routing through `cloud_unpack.raw_files`, and re-run
  this set as published.
- backend-builder: map Sigma `Properties` (and `AccessMask`, `ObjectType`, `SubjectDomainName`) for win_json /
  ecs_json in `config/sigma_map.yaml`, or add a native 4662 replication-GUID rule (non-`$` subject) in
  `config/rules.yaml`, with a positive and near-miss fixture.
- Orchestrator: choose a replacement unseen dataset that Defender doesn't quarantine, or have the user decide on an
  AV exclusion for `data/`.
