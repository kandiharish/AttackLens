# Verify: rel_splunk_aws_kms_ransom (independent check)

Verdict: **CONFIRMED.** The scorecard reproduces exactly, and both main miss causes check out against the outputs and the code.

## 1. Ground truth
- Descriptor `T1486/aws_kms_key/aws_kms_key.yml` (fetched raw from GitHub) says: "creation of a kms key with a policy that all
  people can use the key for encryption, common for S3 ransomware". mitre_technique is T1486. No time is given.
- GT has 1 step: T1486 / Impact at 2021-01-11T09:56:31Z (ts_ms 1610358991000, which is the same second). Host is account 111111111111,
  user is the okta_adm_role/pbareiss ARN, IP is 95.90.199.65. It matches the only CreateKey event (eventID f09518ac...).
  Its policy has `{"AWS":"*"}` -> `kms:Encrypt`. **Justified.**
- Possibly missing (minor, not documented as steps): PutKeyPolicy at 10:22:02Z and 11:04:39Z re-grant `kms:Encrypt` to `*`.
  The one at 10:21:54Z grants `kms:Decrypt` to `*`. The descriptor names only the "creation", so a 1-step GT is defensible.
  DisableKey and ScheduleKeyDeletion at 11:18 are not in the descriptor.
- Timing: GT mtime is 10:59:05. The first run output (source_profile) is 10:59:26, so the GT existed before the run. The sha256 is still
  2c8b39ba...43b7. The file's own mtime cannot prove *when* the hash was recorded, only that the GT predates the run and did not change.

## 2. Reproduction (data/out/rel_splunk_aws_kms_ransom_verify)
- I waited until free RAM was 722 MB (it was 482 MB at first), then ran the same snapshot command. Exit 0. 100.5 s, peak 162 MB (the original run took 138.5 s and 190 MB, so timing varies).
- eval_scorecard.json (minus the ground_truth path), ingest_accounting.json, suppressed.json and incidents_index.json are **identical**.
  Detection is 0 %, there are 0 incidents, 674/674 rows, 0 dropped, integrity TRUSTED.

## 3. Miss causes
- **missing_rule + escaped-JSON regex bug: CONFIRMED.** I ran the exact YAML predicate of the cl_storage_public_or_external
  PutKeyPolicy branch (rules_cloud.yaml:1353-1357, T1537 Exfiltration) in DuckDB on the ingested parquet. It is FALSE on all 4
  CreateKey/PutKeyPolicy events, and the stripped text reads `"principal":{n"aws":"*"n}`. The same regex on `json_extract_string(ct_rp,'$.policy')`
  is TRUE on all 4. CreateKey is not in that branch's api list. No rule maps this behaviour to T1486. cl_kms_key_destroy's PutKeyPolicy
  branch (line 1421) needs the root ARN to be gone, and the root ARN is present in all 4 policies.
- **gate: CONFIRMED.** suppressed.json shows 1 component with 11 episodes, tactics [Impact], max conf 75, and the reason "fewer than 2 tactics and max confidence 75 < 90".
  The episodes are 10 at conf 30 (T1078 x3 rules, T1535) and 1 cl_kms_key_destroy T1485 at conf 75 (11:18:17, 2 raw alerts).
  min_tactic_confidence is 40, T1485 is single_step_critical at min 80, and burst needs 3 techniques at conf >= 40. No Sigma rule fired.
- Extra: T1486 is deliberately **not** in single_step_critical (linking.yaml:146). A new T1486 KMS rule alone (1 tactic) would
  still be suppressed unless its conf is >= 90 with >= 5 merged alerts, or a second tactic is counted. The proposed fix needs a gate decision too.

## 4. As published
- I downloaded the published file again. Content-Length is 984076 and the sha256 is 8c686947...4b7, which is **byte-identical** to src/. 674 records and 674 distinct eventIDs were ingested.
  The parser is cloudtrail_json (any:eventSource). Nothing was reshaped. The OCSF sibling file was not used, as disclosed.
