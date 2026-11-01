# Verify: rel_otrf_empire_dcsync (independent check)

**Verdict: confirmed, with one correction to miss cause 2.** The scorecard reproduces exactly (0 % detection, 0 incidents).
Both claimed miss causes are real. But fixing the field mapping alone would **not** produce an incident.

## 1. Ground truth
- Metadata SDWIN-190301174830 (fetched myself): `attack_mappings` T1003 / 006, TA0006. `adversary_view`: agent on
  WORKSTATION5 172.18.39.5 as `THESHIRE\pgustavo`, `set dc MORDORDC.theshire.local`. The GT step matches it.
- Host, user and time are backed by the raw data (read in memory from the zip, nothing extracted):
  - 3 Security 4662 events on `MORDORDC.theshire.local`, SubjectUserName `pgustavo`, domain `THESHIRE`.
  - They carry the replication GUIDs (`1131f6aa` x2, `1131f6ad` x1), @timestamp `2020-09-21T22:59:14.904Z`.
  - That is 8.7 s before the GT `ts_ms` (`22:59:23.579Z`), well inside the 600 s tolerance.
- GT time event reproduced: line 6817 is PowerShell 4103 on WORKSTATION5, user pgustavo, `22:59:23.579Z`.
- No documented step is missing. The docs map one technique only. The Empire agent is context, not a mapped step.
- sha256 `565cb644...ba0` matches the file. attacks.json mtime is 11:01:35 IST and the run started 11:02:36 IST
  (05:32:36Z, progress.json), so the GT was written before the run and has not changed since.
- Small note: the GT time comes from the workstation PowerShell event, but the host is the DC. The 4662 event on the
  DC would be the more direct anchor. Both are inside tolerance, so the score is not affected.

## 2. Reproduction (same command, snapshot 159f2c2c6abf, free RAM 806 MB)
- Exit 0, 13.4 s, peak RSS 99 MB (original: 19.8 s, 99.7 MB).
- These files are identical to the original run: `eval_scorecard.json` (except the gt path key), `ingest_accounting.json`,
  `suppressed.json`, `incidents_index.json`, `source_profile.json` files and skipped entries. The run is deterministic.
- Integrity verdict: `suspect`, ingest_drops fail.

## 3. Miss causes
- **ingest_format: confirmed.**
  - Snapshot `profile.py:295` rglobs the raw files and never calls `cloud_unpack.raw_files`.
  - Snapshot `cloud_unpack.classify` returns `zip` for this file (lines 44-45).
  - The live tree does call it: HEAD `profile.py:299`, which is line 309 in the current working tree.
- **missing_rule: confirmed, but the gate claim was wrong.**
  - Compiling just the two DCSync Sigma rules with the snapshot config skips both (17d619c1, 611eab06) with
    `unmapped_field:Properties`.
  - `rules.yaml` has no 4662 or replication rule.
  - **Correction:** both rules are `level: medium`, and `sigma_map.yaml` level_severity gives medium = 55.
    - Confidence = severity x rarity, so it can be at most 55.
    - That is below `single_step_critical.min_confidence` 80, and below seed_confidence 65.
    - So mapping `Properties` alone would give an alert but no incident.
    - The fix also needs a `level_override` to critical (90), or a native 4662 rule with severity 80 or more.
  - A second detection path is also missing. The ps_module / ps_script logsources are unmapped (34 + 181 rules
    skipped), so the PowerShell 4103/800 events on WORKSTATION5 cannot fire Sigma rules either.
- **Defender: confirmed.** `Get-MpThreatDetection` shows ThreatID 2147895685 on the extracted member at 10:59:22, and
  2147741009 on the command lines. Reading the member in memory straight from the zip was not blocked.
  - Extracting it to disk is what triggers the quarantine.
  - The live unpack writes to `work/unwrapped/` on disk, so it would likely be blocked too. Not verified.

## 4. As published
- The upstream zip sha256 (streamed, not saved) is `fe1fcc96...2800`, the same as `src/empire_dcsync.zip`.
- One member, 38,828,677 B, 8,465 JSON lines.
- No converter or reshaping was used. The run used the zip as downloaded.
- Only the Host file was used. The metadata's separate Network zip was not.
