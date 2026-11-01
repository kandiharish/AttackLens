# Reliability run: rel_splunk_azuread_spray (real Entra ID / Azure AD password spray)

- **Dataset:** splunk/attack_data `T1110.003/password_spraying_azuread/azuread_signin.log` (Apache-2.0).
  This is real Entra ID SignInLogs diagnostic-settings export data, tenant details anonymised by Splunk. It is the first real Azure test.
- **Docs:** `password_spraying_azuread.yml` says: "Used Invoke-MSOLSpray to perform a password spraying attack against an Azure AD tenant using 30 users accounts", technique T1110.003, dated 2023-06-16.
- **Raw file:** 113,331 bytes, 31 JSON lines, LF line endings, no BOM. sha256 `14b4ded5...36c0f6`.
- **Ground truth:** `data/raw/rel_splunk_azuread_spray/ground_truth/attacks.json`, sha256
  `47b8195a97ba35a942f5167e8931a582ed53a576e3095ddf4ce1065402c7d191`. I recorded the hash before the pipeline ran and did not edit the file after.
  - The docs give no time, host, user or IP. I found ONE raw event by the doc-quoted string `aad` (from `azure:monitor:aad`); it was the first such line in the file. From it I read only `time`, `resourceId`, `identity` and `callerIpAddress`.
  - Disclosure: src_ip was also read, because the spray origin is the attacker entity.
  - One attack with one step: T1110.003, Credential Access, 2023-06-16T18:13:08.952Z.
  - Host = `/tenants/fc69e276-.../providers/Microsoft.aadiam`, user = `Sebastian.Lee`, src_ip = `82.1.1.35`.
  - That event turned out to be the last one in time. The spray runs from 18:11:35.348Z to 18:13:08.953Z, which is 93.6 s and well inside the 10-minute tolerance.
- **Run:** frozen snapshot `data/snap/rel` (SNAPSHOT_HASH `159f2c2c6abf`, memory_limit 1GB, threads 2), run as published with no converters.
  - Free RAM was 481 MB at the first check. I polled every 30 s and it reached 745 MB after about 5 min, so the run started then.

## Scorecard (verbatim, `data/out/rel_splunk_azuread_spray/eval_scorecard.json`)
| metric | value |
|---|---|
| detection_pct | 0.0 |
| labels_pct | null |
| rebuilt_pct | 0.0 |
| false_alarms_strict_pct | null |
| step_precision_pct | null |
| gt_steps / predicted_steps / incidents | 1 / 0 / 0 |
| per_rule_alerts | password_spray 1 (raw_alert_count 31), cl_password_spray 1 (raw_alert_count 29) |

## Run metrics (`run_metrics.json`)
| total_wall_s | peak_rss_mb | incidents |
|---|---|---|
| 37.687 | 172.3 | 0 |

Detect took 29.15 s of the total. Most of that is loading the 171 cloud rules plus about 1,700 Sigma rules, a fixed cost that does not depend on the 31 rows.

## Ingest accounting (`ingest_accounting.json`) and source profile
| source_type | rows_in | rows_ok | dropped | drop_reasons | quarantined |
|---|---|---|---|---|---|
| azure_signin_json | 31 | 31 | 0 | {} | 0 |

- `source_profile.json`: `src/azuread_signin.log` was read as format json and given `azure_signin_json`, detected by `any:properties.conditionalAccessStatus`.
- Field mapping on real data was checked in the events parquet. All of it is correct:
  - All 31 rows came out as action `login_failed`, outcome `failure`. resultType 50126 is a failure through `outcome_map.present`, and `Sign-in activity` maps to `login_failed`.
  - 31 distinct target users, taken from `properties.userPrincipalName`.
  - One src_ip, `82.1.1.35`.
  - host = resourceId on all rows.
  - ts_ms runs from 1686939095348 to 1686939188953, which is the exact UTC of the raw `time` values.
- The cloud layer counts 29 rows, not 31. The raw file has only 29 distinct `properties.id` / `correlationId` values: 2 sign-in ids repeat with different user names (probably from Splunk's anonymisation). `cloud.yaml` `dedupe: true` (`dedup_id`) removes them as duplicate deliveries. That still leaves 29 distinct users, well above `spray_min_users` 15, so it does not matter here.

## What the pipeline found (`work/episodes.parquet`, `work/edges.parquet`)
| episode | rule | technique / sub | tactic | conf | first ts (UTC) | host | user | src_ip | alerts |
|---|---|---|---|---|---|---|---|---|---|
| edf93a53775 | password_spray (config/rules.yaml:121) | T1110 / T1110.003 | Credential Access | 75 | 2023-06-16 18:11:35.348 | /tenants/fc69e276-.../microsoft.aadiam | – | 82.1.1.35 | 31 |
| ed37a532015 | cl_password_spray (config/rules_cloud.yaml:97, distinct_burst branch) | T1110 / T1110.003 | Credential Access | 75 | 2023-06-16 18:11:35.348 | same | abigail.clark | 82.1.1.35 | 29 |

- The two episodes are linked by R2 ("Same session: 82.1.1.35 on /tenants/..., 0s apart").
- Neither spray alert would match without the other: both have the right technique (T1110.003), the right tactic, the GT host, the GT IP and dt = 93.6 s.
- So they meet the harness step-match rule (dt <= 10 min AND host AND (user OR ip)), and the labels would count as correct.
- The follow-on `sequence` branch (spray, then success, T1078 Initial Access at severity 85) did not fire, correctly: every row is 50126, so no sprayed password worked.

## Diagnosis of the missed step
| GT step | cause | detail |
|---|---|---|
| AZSPRAY1 step 1, T1110.003 Credential Access | gate (suppression) | Detected and labelled correctly but suppressed at the incident gate, see below. |

- **Gate result:** the component {ed37a532015, edf93a53775} is listed in `suppressed.json` with reason "fewer than 2 tactics and max confidence 75 < 90". That reason comes from `backend/attacklens/incident_gate.py:209`.
- **Why the gate drops it:**
  - It has only one tactic, Credential Access, and `gate.min_tactics` is 2 (`config/linking.yaml:74`).
  - Its max confidence is 75, below the 90 needed for the critical path.
  - T1110 is not in `gate.single_step_critical.techniques` (`config/linking.yaml:115-150`).
  - The burst path needs >= 3 distinct parent techniques (`min_distinct_techniques: 3`, `config/linking.yaml:89`), and here there is only T1110.
- **So 0 % here is a gate result, not a parsing or detection failure.** A failed spray with no follow-on success is shown only as a suppressed component and never becomes an incident.
  - That fits the documented design (a single-tactic, sub-critical component is noise until it chains), but it means a pure failed spray is never surfaced.
  - The harness has no singleton or alert-level recall for T1110 (harness.py line 30: "T1110 singletons are not [detectable]"). So `singleton_recall_pct` is null and the correct raw alerts get no credit in the scorecard.
- **Possible tuning (not done; for the backend owner to measure against the eval sets):** let `cl_password_spray` reach the gate on its own when it has many distinct users from one external IP, for example >= 25. Two ways:
  - Add T1110.003 to `single_step_critical` with a min_confidence that only a high-distinct-user spray reaches.
  - Scale its confidence with the distinct-user count.

  The false-alarm effect of either has to be measured on g1-noisy / n30 first.

## Verdict
- **Ingest:** worked on real Azure data. 31/31 rows, 0 dropped, correct source type, correct UTC times.
- **Field mapping:** `azure_signin_json` is correct. resultType 50126 maps to login_failed, `properties.userPrincipalName` to the user, `callerIpAddress` / `properties.ipAddress` to src_ip, and resourceId to the host.
- **Detection:** both spray rules fired on the right IP, tenant, technique and time.
- **End result:** 0 incidents and detection_pct 0.0, because the incident gate suppresses single-tactic components below confidence 90. No step was lost to ingest, timestamps, mislabelling or entity mismatch.
