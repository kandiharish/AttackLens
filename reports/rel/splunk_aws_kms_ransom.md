# rel_splunk_aws_kms_ransom — reliability run on an unseen public dataset

- Dataset: splunk/attack_data `T1486/aws_kms_key/aws_cloudtrail_events.json` (Apache-2.0), 984 076 bytes,
  sha256 `8c6869476565588356d30a0c20d3767b2d64de8f871af2e97b2b0d57c4cc64b7`. OCSF sibling file not downloaded (unsupported format).
- Descriptor `aws_kms_key.yml`: T1486. "creation of a kms key with a policy that all people can use the key for
  encryption, which is common for S3 ransomware attacks". No time given.
- Ground truth: 1 attack, 1 step, written before the run. sha256 `2c8b39baaa9d1ba54e9c1ee091c4d02e612c6a315958f315488a115768ff43b7`
  (the same after the run). The time comes from the one raw `CreateKey` event (only its time, account, ARN and IP were read):
  T1486 / Impact, 2021-01-11T09:56:31Z, host `111111111111`, user `...assumed-role/okta_adm_role/pbareiss@splunk.local`, ip 95.90.199.65.
- Run: frozen snapshot `data/snap/rel` (memory_limit 1GB, threads 2), run as published, no converters. Free RAM at start: 712 MB.

## Scorecard (verbatim, `data/out/rel_splunk_aws_kms_ransom/eval_scorecard.json`)
| metric | value |
|---|---|
| detection_pct | 0.0 |
| labels_pct | null |
| rebuilt_pct | 0.0 |
| false_alarms_strict_pct | null (0 incidents) |
| step_precision_pct | null |
| gt_steps / predicted_steps / incidents | 1 / 0 / 0 |

## Run metrics (`run_metrics.json`)
| total_wall_s | peak_rss_mb | incidents | rows/s |
|---|---|---|---|
| 138.5 | 189.7 | 0 | 4.9 |
Most of the wall time (102.4 s) was the Sigma rule load (1712 rules, cold cache). The scan itself took 1.1 s.

## Ingest (`ingest_accounting.json`, `source_profile.json`)
| file | source_type (detected_by) | rows_in | rows_ok | dropped | drop_reasons |
|---|---|---|---|---|---|
| src/aws_cloudtrail_events.json | cloudtrail_json (`any:eventSource`) | 674 | 674 | 0 | {} |
Integrity report: TRUSTED (score 100). Timestamps are correct: alerts land on the exact UTC second of the raw events.

## What the pipeline saw
- 18 raw alerts became 11 episodes. All 11 are on host `111111111111` / user `pbareiss` / ip 95.90.199.65, and R2 links them into one component.
  - Conf 30 baseline anomalies: `cl_first_seen_api`, `cl_rare_api_account`, `cl_first_seen_geo` (T1078 Initial Access) and `cl_unused_region` (T1535 Stealth).
    They fire on CreateAlias at 09:56:31, PutKeyPolicy at 10:21:54, DisableKey at 11:18:17 and CancelKeyDeletion at 12:40:27.
  - `cl_kms_key_destroy` (T1485 Impact, conf 75, seed): DisableKey at 11:18:17 and ScheduleKeyDeletion at 11:18:59.
- No alerts on the ~660 background KMS calls (Decrypt, DescribeKey, ListAliases, ...). There was no false-positive noise.
- Gate (`suppressed.json`): the single component was suppressed with "fewer than 2 tactics and max confidence 75 < 90".

## Diagnosis of the missed step (step 1, T1486 Impact, CreateKey 09:56:31)
1. **Missing rule / regex bug (main cause).** No rule turns "KMS key policy grants kms:Encrypt to Principal *" into a T1486 alert.
   - `config/rules_cloud.yaml:1353-1357` (`cl_storage_public_or_external`, T1537 Exfiltration) has a `PutKeyPolicy` + `"principal":"*"` branch. It does not fire, for 2 reasons:
     - The policy sits in `requestParameters.policy` as a JSON-encoded string, so newlines are stored as the 2-character escape `\n`.
       `regexp_replace(lower(ct_rp), '\s|\\', '', 'g')` removes the backslash but keeps the `n`, which leaves `"principal":{n"aws":"*"n}`.
       That text never matches `\{"aws":"\*"\}`.
     - Reproduced with DuckDB on the ingested parquet: the rule expression is false on all 4 events (CreateKey plus 3 PutKeyPolicy).
       The same regex on `json_extract_string(ct_rp, '$.policy')` (unescaped) is true on all 4.
   - That branch also does not list `CreateKey` in its api list, and the GT step is the CreateKey call. Even if it fired, it would label T1537 / Exfiltration, not T1486 / Impact.
   - `cl_kms_key_destroy`'s PutKeyPolicy branch (`rules_cloud.yaml:1421`) only fires when the account root is *removed* from the policy. Here the root stays and `{"AWS":"*"}` is *added*, so it is correctly silent.
   - Sigma: 1712 rules, 0 fired. No loaded Sigma rule covers this pattern.
2. **Gate suppression (secondary cause).**
   - `config/linking.yaml:74-76`: `min_tactics: 2`, `min_tactic_confidence: 40`. The conf-30 Initial Access and Stealth anomalies do not count, so the component has one counted tactic (Impact).
   - Max confidence is 75, below the critical value of 90.
   - `single_step_critical` lists T1485 but needs confidence >= 80 (`linking.yaml:115-117`). `cl_kms_key_destroy` gives 75: DisableKey and ScheduleKeyDeletion fall through `severity_sql` to the default 75 (`rules_cloud.yaml:1426-1427`).
     The distinct_burst branch (90) needs 3 distinct keys, and there is only 1.
   - `incident_gate.py:92-97` (`counted_tactics`) and `incidents.py:226-233` (`_gate_ids`).
3. **Not the cause:**
   - Ingest and format: 674/674 rows, 0 dropped.
   - Timestamp: exact UTC.
   - Entity: host, user and ip all agree with the GT. Conf-30 episodes sit on the GT second (09:56:31). The harness rule is dt <= 10 min AND host AND (user OR ip), so a kept incident containing them would have counted as detected.
     It would still have been mislabelled: T1078 Initial Access instead of T1486 Impact.

## Proposed fixes (not applied; owner: backend-builder, `config/rules_cloud.yaml`)
- Add a KMS branch to `cl_storage_ransom_encrypt` (T1486 Impact):
  - `app='kms.amazonaws.com' AND api IN ('CreateKey','PutKeyPolicy')`
  - the regex runs on `json_extract_string(ct_rp,'$.policy')` with whitespace stripped
  - match a statement with `"principal":("*"|{"aws":"*"})` whose action includes `kms:encrypt` or `kms:*`
  - severity >= 80
- Fix the escaped-JSON bug in the `cl_storage_public_or_external` principal-`*` branch (line 1355): strip `\\n|\\t|\\r` before `\s|\\`, or match on the unescaped policy.
  The same pattern probably affects SetTopicAttributes, SetQueueAttributes and SetRepositoryPolicy policies.
- Optional: give DisableKey and ScheduleKeyDeletion of a key created in the same session severity >= 80, so the T1485 single-step-critical path can keep it.
- Re-measure on this set and on the six Splunk CloudTrail sets plus g1/f1. Watch FA, because `Principal *` with conditions is a legitimate pattern.
