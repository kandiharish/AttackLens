# AttackLens on real public cloud attack logs (CloudTrail)

Author: ext-eval Cloud agent, 1 Nov 2026 (orchestrator session cyberforge-6e). No product code, config, harness or tests
were changed. Every number below is copied from that run's `eval_scorecard.json`, `run_metrics.json` or
`ingest_accounting.json`. The one exception is the "step diagnosis" columns, which are this agent's own analysis
(`tools/ext/cloud_collect.py`) and are labelled as such.

## 0. Summary

- **Ingest:** the published CloudTrail shapes cannot be ingested as-is. The `.tar`, the `.json.gz` and a plain
  `{"Records":[...]}` file were all dropped whole, as `unrecognized_format`. After a structure-only unwrap to JSON
  lines (and for the Splunk sets, which are already JSON lines), every row is ingested: 0 dropped out of 53,365 + 105.
- **Detection itself is mostly fine.** In the Splunk sets, an alert from the right rule fired for 39 of 40
  ground-truth steps, mostly with the right technique. The documented-behaviour rule covered 3 of 4 steps in
  loginfail and every step in the other five sets (createkey 28 of 28). The
  **incident gate** then threw 35 of those 39 away: "fewer than 2 tactics", or a single tactic with fewer than 5
  merged alerts.
- **Incident-level harness scores are low:** 4 of the 6 Splunk sets score detection 0–7 %, and flaws.cloud scores
  6.9 %. The Splunk sets produced 4 incidents. The 2 in
  stoptrail and snapexfil passed only because their second tactic came from `cl_attack_tool_user_agent` matching the
  `stratus-red-team_…` user agent, which is an artefact of the test tool.
- **Labelling gap on flaws.cloud discovery:** almost none of the documented L3–L6 steps gets the documented technique (4 of 809 steps have a label-correct episode)
  (T1078.004 key use, T1580 snapshot hunt, T1069.003 policy enumeration, T1526 Lambda/API GW discovery). Episodes
  carry T1059 (tool UA), T1550 (multi-ASN session), T1496 (RunInstances) or T1078 (first-seen) instead. Labels: 3.6 %.
- **False alarms are low:** strict false alarms are 0 % on every Splunk set that produced incidents, and 10.5 %
  (2 of 19) on flaws. A manual review of those 2 found that both are real attacker activity outside the partial
  ground truth.
- **Time and RAM:** peak RSS is 112–121 MB for the Splunk sets and 466 MB for 53k events. Wall time is 36–193 s,
  and 66–95 % of it is in `detect` (182 of 193 s for 2 rows). That is a fixed per-run cost, measured on a CPU-saturated
  machine (threads 2).

## 1. Setup

| Item | Value |
|---|---|
| Code/config | Frozen snapshot `data/snap/ext_cloud` (backend/attacklens + config + data/cache/sigma), taken 2026-11-01T02:56:24Z. md5 over `backend/attacklens/*.py` + `config/*.yaml`: `7cfaae58d89e4c87000d0148d503b993` as copied. |
| **Deviation from production config** | Orchestrator instruction, because the machine had 0.6–0.9 GB free: in the snapshot only, `config/pipeline.yaml` was changed to `memory_limit: "1GB"` (was 5GB) and `threads: 2` (was null = 12). md5 after the change: `174012a290ba6ac2a5dba65d5b0be3f0`. Runs were launched directly, one at a time, not through jobq. The jobq attempt had waited 38 min without starting. |
| Sigma | `COMPILER_VERSION = "6"`, 1792 compiled rules from cache. `config/sigma_map.yaml` sha256 `db1a0ef0eb20b7405b34b7d5b64d51202ab03ffd1aef214b77d0ff7ce4db2068`. `rules_cloud.yaml` sha256 `4638780e…12bfe`. `sources.yaml` sha256 `2431bfba…22fb`. |
| Harness | `backend/eval/harness.py` v1.0 (imported from the repo; sha256 `d2105083…4c0b`), `match.py` `d7c078d4…2d73`. Tolerance 10 min; a step needs host AND (user OR IP). |
| Command | `cd $S/backend && PYTHONPATH=$S/backend python.exe -m attacklens.run --raw C:/cyberforge/data/raw/<set> --out C:/cyberforge/data/out/<set> --parquet C:/cyberforge/data/parquet/<set> --ground-truth <attacks.json>` |
| Not run | `ext_cloud_flawsconv` (full 1.94M-event flaws set, 2.3 GB JSONL, already converted on disk). It was skipped on orchestrator instruction because of the RAM shortage. |

## 2. Datasets, licences, tools (for README disclosure)

| Set | Source | Licence | Size / rows | Ground truth |
|---|---|---|---|---|
| `ext_cloud_flaws*` | flaws.cloud CloudTrail logs, Scott Piper / Summit Route, released 2020-10-09. Data: https://summitroute.com/downloads/flaws_cloudtrail_logs.tar. Post: https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/ | **No licence stated.** Released "to advance research into AWS security". Use for research with attribution; do not redistribute. | 251,688,960 B tar, sha256 `f26c2b8d…96aa`; 20 × .json.gz; 1,939,207 records, 2017-02-12..2020-10-07, 1 account (anonymised) | Partial: the documented flaws.cloud L3–L6 path (level hint pages) |
| `ext_cloud_splunk_{sfa,loginfail,stoptrail,snapexfil,s3public,createkey}` | Splunk `attack_data` (github.com/splunk/attack_data, commit f08d681, 2026-10-29), git-lfs media URLs | Apache-2.0 | 2,272–89,943 B; 2/7/3/9/9/75 rows | From each dataset's `.yml` (description + `mitre_technique`) |
| Reference only | flaws.cloud level pages (level3–6 hints); Stratus Red Team technique names cited in the Splunk ymls/user agents | flaws: no licence stated; Stratus: Apache-2.0 | – | – |

Tools written (all under `tools/ext/`, all read-only on downloaded data, all run with `python -I`):
- `cloud_stream.py`: streaming reader for tar / gzip / `{"Records":[…]}` / JSON lines. Uses `raw_decode` and never extracts.
- `cloud_inventory.py`: row counts and event listings.
- `cloud_unwrap.py`: structure-only converter. It writes each record's exact source text, one per line, with an
  optional eventTime slice.
- `cloud_gt_build.py` / `cloud_flaws_gt.py`: ground-truth builders. The criteria are written from the documentation.
- `cloud_collect.py`: collects harness numbers and runs the per-step diagnosis.

Per-dataset `SOURCE.md` files (URL, licence, fetch date, sha256 of every file, sizes, row counts, GT hashes) are in
`data/raw/ext_cloud_*/SOURCE.md`. The total download was about 252 MB. All downloads went into fresh empty folders;
the tar was listed first (no absolute paths, no `..`, no links). No credential found in the data or on the hint pages
was used, no AWS endpoint was contacted, and no IP was scanned.

## 3. Ground truth: how it was built (before any run)

- **Splunk sets.** Each set has one documented criterion, taken from its yml:
  - sfa: ConsoleLogin Success with MFAUsed=No.
  - loginfail: ConsoleLogin Failure.
  - stoptrail: StopLogging/DeleteTrail.
  - snapexfil: ModifySnapshotAttribute adding createVolumePermission for `all` or another account.
  - s3public: PutBucketAcl granting AllUsers/AuthenticatedUsers.
  - createkey: successful CreateAccessKey for a user other than the caller.

  Instance rule: one attack per (account, caller, IP, UTC day), and one step per run of positive events with gaps of
  10 min or less. Technique and tactic come from the yml. T1562.008 was mapped to its ATT&CK v20 id T1685.002.
  createkey's T1078 was given the tactic "Privilege Escalation", from the yml text.
- **flaws.cloud** (partial, behaviour patterns only). One attack per (source IP, UTC day). There is one step per
  documented stage, placed at that stage's first event:
  - L3: leaked IAM user `backup` key used → T1078.004
  - L4: DescribeSnapshots with that key → T1580
  - L5: role `flaws` instance credentials used off-host → T1552.005
  - L6a: `Level6` IAM policy enumeration → T1069.003
  - L6b: `Level6` Lambda / API Gateway discovery → T1526

  The ground truth does **not** include other attacker activity the release post describes: GetBucketAcl /
  AssumeRole brute force, RunInstances spam, backdoor attempts, Kali user agents. Strict false alarms are therefore
  an upper bound.
- **Correction (v2).** The flaws builder never emitted L5. It matched `/assumed-role/flaws/`, but the ARN is
  `…:assumed-role/flaws/…`. This was found after the first scored run, while reviewing an unmatched incident. The v1
  files are kept unchanged and are the primary score. A v2 slice file was added, and both hashes are listed below.

| GT file | sha256 | attacks / steps |
|---|---|---|
| ext_cloud_splunk_sfa | `dd30d07189b524af33c70b67430c0eb3b52f92c44369f9f47424f12831b6dbaf` | 1 / 1 |
| ext_cloud_splunk_loginfail | `174a37fbc8d9693c2ddc46a9fe14bf4ae4e0ca11b7db5aea49e381a0c10ead54` | 4 / 4 |
| ext_cloud_splunk_stoptrail | `5c6c4cfc7bf91c8851146c5a129242fa1f127f83835d1952cc8514adaf7fa212` | 2 / 2 |
| ext_cloud_splunk_snapexfil | `79db1f019abb46fe146b340b5149ce402f504b963ae6c959e424c98fd6161636` | 2 / 2 |
| ext_cloud_splunk_s3public | `5c3d9e64ad5b75c748fcf882403ce49fb8c5efed8e20299fc68b928a5f405b72` | 2 / 3 |
| ext_cloud_splunk_createkey | `30d751430d55971231a3eca6d01dd61d22640be98c95b1ff6980105740c015ee` | 20 / 28 |
| flaws attacks.json (all time, v1) | `f0821da18230cb9240a1498ee4348b892cba1ad4766af49ad791f202cdd6b3cd` | 7,587 / 14,004 |
| flaws attacks_slice_2020-09.json (v1, **primary**) | `8902fb973cf9cb5d47d8d12434528728eaba996621a521b0a29c69bbbf55e04c` | 608 / 809 |
| flaws attacks_slice_2020-09_v2.json (L5 fix) | `c06ccda30b69d99ed1c6a62b87cea5a7fc9a027136b8a166f1dad7589ba8cc94` | 615 / 842 |

(Full hashes for every file are in each `SOURCE.md`.)

## 4. Results per dataset

### 4.1 Ingest: as-is versus converted (finding F1)

| Set | Published shape | rows_in | rows_ok | dropped | Reason | Wall s | Peak RSS MB |
|---|---|---|---|---|---|---|---|
| ext_cloud_flaws | `.tar` exactly as downloaded | 1,795,667 * | 0 | 1,795,667 | unrecognized_format | 46.0 | 145 |
| ext_cloud_flawsgz | 20 × `.json.gz` (CloudTrail S3 shape) | 1,795,686 * | 0 | 1,795,686 | unrecognized_format | 35.8 | 149 |
| ext_cloud_flawsrec | 1 plain `{"Records":[…]}` file (gunzipped member 19, 39,207 records) | **1** | 0 | **1** | unrecognized_format ("JSON with no known source fields") | 18.4 | 150 |
| ext_cloud_flawsslice | unwrapped to JSON lines, 2020-09-01..2020-10-07 | 53,365 | 53,365 | 0 | – | 45.3 | 466 |
| Splunk ×6 | JSON lines (Splunk export) | 105 | 105 | 0 | – | 36–193 | 112–121 |

\* These counts are lines of compressed bytes, not records. The real record count is 1,939,207. The drop is
logged, so it is not silent, but its size is wrong. In the plain Records file, 39,207 lost events are counted as
**1** dropped row.

### 4.2 Scorecards (harness, verbatim)

| Metric | sfa | loginfail | stoptrail | snapexfil | s3public | createkey | flawsslice (v1) | flawsslice (v2 GT) |
|---|---|---|---|---|---|---|---|---|
| GT technique | T1078.004 | T1110.001 | T1685.002 | T1537 | T1530 | T1078 | mixed | mixed |
| rows in / ok / dropped | 2/2/0 | 7/7/0 | 3/3/0 | 9/9/0 | 9/9/0 | 75/75/0 | 53,365/53,365/0 | same run |
| wall s (detect s) | 192.8 (182.1) | 60.0 (46.8) | 46.1 (42.8) | 36.3 (24.0) | 65.0 (61.9) | 120.4 (109.4) | 45.3 (31.0) | – |
| peak RSS MB | 118 | 117 | 114 | 117 | 113 | 121 | 466 | – |
| episodes / incidents | 7 / 0 | 3 / 0 | 13 / 1 | 18 / 1 | 9 / 0 | 98 / 2 | 425 / 19 | – |
| GT attacks / steps | 1 / 1 | 4 / 4 | 2 / 2 | 2 / 2 | 2 / 3 | 20 / 28 | 608 / 809 | 615 / 842 |
| **detection %** | 0.0 | 0.0 | 50.0 | 50.0 | 0.0 | 7.14 | 6.92 | 7.01 |
| **labels %** | null | null | 100.0 | 100.0 | null | 0.0 | 3.57 | 3.39 |
| labels (technique only) % | null | null | 100.0 | 100.0 | null | 50.0 | 3.57 | 3.39 |
| **rebuilt %** | 0.0 | 0.0 | 50.0 | 50.0 | 0.0 | 10.0 | 1.32 | 1.14 |
| **false alarms strict %** | null (0 inc.) | null | 0.0 | 0.0 | null | 0.0 | 10.53 | 10.53 |
| false alarms lenient % | null | null | 0.0 | 0.0 | null | 0.0 | 10.53 | 10.53 |
| step precision % | null | null | 20.0 | 20.0 | null | 16.67 | 31.18 | 31.18 |
| step precision (all) % | null | null | 20.0 | 20.0 | null | 16.67 | 56.57 | 59.60 |
| singleton recall | null | null | null | null | null | null | null | null |

Notes: `null` means the denominator is 0. No incidents means there is no false-alarm or label denominator.
`ext_cloud_flaws`, `ext_cloud_flawsgz` and `ext_cloud_flawsrec` all score detection 0.0 % because no rows were
ingested.

### 4.3 Per ground-truth step (Splunk). The "rule that fired" and "fate" columns are our own diagnosis.

| GT step | Detected (harness) | Rule that fired (best episode) / technique / conf | In an incident? | Why not |
|---|---|---|---|---|
| SFA1 root console login, no MFA | no | `aws_console_login_no_mfa`, `aws_root_usage`, `sigma_77caf516`, `sigma_8ad1600d` / T1078.004 / 70 | no | gate: fewer than 2 tactics and max confidence 70 < 90 |
| LOGINFAIL1 kshelton | no | `sigma_6393e346` / T1110 / 35 (**no tactic** on the episode) | no | gate: fewer than 2 tactics, conf 35 |
| LOGINFAIL2 4 failures in 3 min, "No username found…" | no | **none**. Sigma 6393e346 needs errorMessage "Failed authentication"; `cl_signin_bruteforce` needs ≥ 10 failures in 30 min | – | missing rule |
| LOGINFAIL3 xlin, LOGINFAIL4 gowthamaraj_cli | no | `sigma_6393e346` / T1110 / 35 | no | gate |
| STOPTRAIL1 StopLogging (Stratus) | **yes** (inc-51a852da, label ok) | `aws_logging_tamper` / T1685.002 / 90 | yes | – (2nd tactic from `cl_attack_tool_user_agent`, i.e. the Stratus UA) |
| STOPTRAIL2 2 × DeleteTrail (aws-cli) | no | `aws_logging_tamper`, `seq_logging_off_then_write` / T1685.002 / 90 | no | gate: critical single-tactic component, top episode has 2 merged alerts < 5 |
| SNAPEXFIL1 snapshot shared with `all` (aws-cli) | no | `cl_snapshot_image_share_external`, `sigma_abae8fec` / T1537 / 90 | no | gate: critical single-tactic, 1 merged alert < 5 |
| SNAPEXFIL2 snapshot shared to another account (Stratus) | **yes** (inc-f2b268c1, label ok) | `cl_snapshot_image_share_external` / T1537 / 85 | yes | – (2nd tactic from the Stratus UA) |
| S3PUBLIC1/2 (3 steps) PutBucketAcl AllUsers/AuthenticatedUsers | no | `cl_storage_public_or_external` / **T1537** / 80 | no | gate (fewer than 2 tactics, 80 < 90), **and** the label differs from the dataset's T1530 |
| CREATEKEY1–20 (28 steps) CreateAccessKey for another user | 2 of 28 (CREATEKEY11 via `cl_dormant_identity_reactivated`, CREATEKEY16) | `aws_credential_for_other_user` / **T1098.001** / 75 covers 28 of 28 steps | 2 incidents | gate: fewer than 2 tactics, max conf 75 < 90. The label differs from the dataset's T1078 (tactic Privilege Escalation) |

### 4.4 Per ground-truth stage (flaws slice, v1 GT, 809 steps)

| Stage (doc technique) | Steps | Harness-matched | Any episode covering the step | Label-correct episode | Main rules on these steps | Main fate (our diagnosis) |
|---|---|---|---|---|---|---|
| L3 leaked `backup` key (T1078.004) | 577 | 23 | 482 | 1 | `cl_compute_hijack` T1496.001 (384), `cl_attack_tool_user_agent` T1059.009 (66), `cl_session_multi_asn` T1550.001 (26) | 384 suppressed "max confidence 60 < 65" (RunInstances-spam component); 95 with no episode |
| L4 DescribeSnapshots (T1580) | 123 | 11 | 68 | 3 (`cl_discovery_burst`) | `cl_attack_tool_user_agent` (44), `cl_session_multi_asn` (18) | 55 with no episode; 33 suppressed "fewer than 2 tactics" |
| L6a Level6 IAM policy enum (T1069.003) | 59 | 13 | 36 | 0 | `cl_attack_tool_user_agent`, `cl_first_seen_geo` T1078.004, `cl_discovery_burst` T1580 | 23 with no episode; 16 suppressed |
| L6b Level6 Lambda/API GW discovery (T1526) | 50 | 9 | 41 | 0 | `cl_first_seen_geo`, `cl_attack_tool_user_agent`, `cl_discovery_burst` | 21 suppressed; 9 with no episode |
| L5 role `flaws` creds off-host (T1552.005) (v2 only) | 33 | 4 (v2 scorecard) | – | – | `cl_instance_creds_offhost` T1552.005 fired 1× (6 raw alerts), `sigma_352a918a` (T1078.002) on the `aws:ec2-instance` session | see F6 |

Incidents: 19. 17 are matched to a ground-truth attack. The harness rebuilt 8 attacks (v1). Two incidents are
unmatched, and both are real attacker activity on manual review:
- `inc-72ab90e6`: `cl_instance_creds_offhost` + `cl_session_multi_asn` on session `i-aa2d3b42e5c6e801a`. This is
  the documented L5 behaviour (role creds used from several external IPs in one session, 06:39Z). It stays unmatched even with the v2 ground
  truth. The ground-truth user is the raw ARN while the incident user is the session name, and the alert carries a
  different IP of the same session (`251.2.248.254` versus the step's `252.243.3.35`).
- `inc-00a72dd0`: `backup` + tool UA + discovery burst from `219.208.8.129`, 10:56–11:14Z. This is the same actor as
  ground-truth FL264, about 5 h after FL264's first-event-per-stage timestamps, and it uses a Kali UA (a pattern the
  release post names).

By our manual review, false alarms are therefore 0 of 19. The harness number stays 10.53 %.

## 5. Top misses, grouped by cause

1. **Linking / gate suppression (the largest cause by far).** In the Splunk sets, 39 of 40 steps had a correctly
   firing rule, but 35 of those were suppressed by `config/linking.yaml` `gate`:
   - `min_tactics: 2`, and the critical path needs `critical_confidence: 90`. The cloud single-API rules top out
     at 70–85.
   - `critical_min_merged_alerts: 5`. A single StopLogging or a public snapshot share is 1–2 alerts.

   In flaws, 385 steps were suppressed for "max confidence 60 < 65" (`seed_confidence`), because the
   `cl_compute_hijack` component sits at confidence 60.

   These suppressed alerts cover a single, decisive cloud control-plane action: logging stopped, a snapshot made
   public, a bucket ACL opened to AllUsers, a root console login without MFA, or keys created for another user.
   Such an action is a complete attack step on its own, and real attackers rarely add a second tactic in the same
   window.
2. **Test-tool artefact passes the gate.** The 2 Splunk incidents that did pass (stoptrail and snapexfil) passed
   only because `cl_attack_tool_user_agent` (T1059.009) matched the `stratus-red-team_<uuid>` user agent and added
   the Execution tactic. The same actions with an `aws-cli` user agent were suppressed. Do not count these 50 %
   scores as evidence that real attacks are detected.
3. **Wrong or missing label (flaws discovery).** No rule labels:
   - IAM policy enumeration as T1069.003. `aws_iam_policy_bruteforce` covers only MalformedPolicyDocument /
     UpdateAssumeRolePolicy failures. There is no rule for a GetPolicy/GetPolicyVersion/ListAttachedUserPolicies
     burst.
   - Lambda / API Gateway enumeration as T1526. The only T1526 rule is `aws_ses_recon`.
   - DescribeSnapshots-with-owner / public snapshot hunting as T1580. `cl_discovery_burst` needs ≥ 20 distinct APIs
     across ≥ 4 services in 10 min.
   - A leaked IAM key used from a new IP, as T1078.004 for an IAM user with key auth. `cl_first_seen_geo` fires
     only on some L6 steps.

   As a result, the matched steps carry T1059 (tool UA), T1550 (multi-ASN session), T1496 or T1078, and labels are
   3.6 %.
4. **Label differs from the dataset's own label.** These may be our ATT&CK choice rather than a bug, and need a
   decision:
   - `cl_storage_public_or_external` emits T1537 (Exfiltration) for a PutBucketAcl to AllUsers. Splunk labels this
     T1530; Sigma/Stratus use T1537/T1530 inconsistently.
   - `aws_credential_for_other_user` emits T1098.001 (Persistence). Splunk labels it T1078 (privilege escalation).
     T1098.001 is the more precise ATT&CK fit; Stratus `aws.persistence.iam-backdoor-user` agrees.
   - `sigma_352a918a` ("Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure") emits **T1078.002**
     (Domain Accounts), which is wrong for cloud. It should be T1552.005 or T1078.004.
   - `sigma_6393e346` ("AWS ConsoleLogin Failed Authentication") episodes have **no tactic** (`tactics: []` in
     `suppressed.json`), so they can never count toward `min_tactics`. Relevant to cyberforge-0c's `sigma_map.yaml`
     work.
5. **Missing rule / format gap.**
   - ConsoleLogin failures with errorMessage "No username found in supplied account" are not alerted by anything.
     This is username enumeration / failed login with an unknown user, T1110 / T1589.
   - No ingest of `.gz`, `.tar` or `{"Records":[…]}`. This is the standard CloudTrail S3 delivery format (F1).
     `sources.yaml` says that "{"Records": […]} files are unpacked by the aws_cloudtrail connector", but file ingest
     does not unpack them.
6. **Entity normalisation (harness ↔ ingest).** For assumed-role callers, the ground truth holds the ARN (as in the
   log) while AttackLens reports the session name (`i-aa2d…`, `jhernandez`). `eval/match.norm_user` does not reduce
   ARNs, so these steps match only through the IP. Multi-network session alerts can also carry another IP of the
   session. This is why inc-72ab90e6 (a true L5) scores as a false alarm.
7. **Alert caps hit.** `max_alerts_per_rule: 1000` was reached by `cl_compute_hijack` and `sigma_352a918a` on 53k
   events. Sigma logged 123 capped alerts. Overflow is counted, not silent, but it means on the full 1.94M set most
   of these alerts would be cut.

## 6. Recommendations (for the owners; nothing was changed)

1. **Ingest (backend-builder): accept CloudTrail as delivered.** Support `.gz` (and optionally `.tar`) and
   `{"Records":[…]}` documents in file ingest. Unwrap with `read_json(..., format='auto')` plus `unnest(Records)`,
   or reuse the aws_cloudtrail connector's unpacking. Until then, count dropped **records**, not byte-lines, in
   `ingest_accounting.json`. The plain Records file currently reports "1 row" for 39,207 events, which hides the size
   of the loss.
2. **Gate (linking.yaml), measured change needed.** Add a cloud "decisive control-plane action" path. A component
   should pass with one tactic when its top episode comes from a high-impact native cloud rule:
   `aws_logging_tamper` (StopLogging/DeleteTrail), `cl_snapshot_image_share_external`,
   `cl_storage_public_or_external`, `aws_root_usage` (console), `aws_credential_for_other_user` when the target is
   not self, `aws_security_service_off`, and `cl_kms_key_destroy`. Alternatively, raise those rules' confidence
   to ≥ 90 and exempt them from `critical_min_merged_alerts`. Either change must be re-measured on g1/f1 for false
   alarms first.
3. **Do not let `cl_attack_tool_user_agent` be the only second tactic.** Stratus and pacu UAs make test data look
   detected. Either exclude T1059.009 from the tactic count for `min_tactics`, or keep it as context only.
4. **New discovery rules (rules_cloud.yaml):**
   - (a) an IAM permission-enumeration burst (GetPolicy, GetPolicyVersion, ListAttachedUserPolicies,
     ListUserPolicies, ListEntitiesForPolicy, GetAccountAuthorizationDetails ≥ N distinct in 10 min) → T1069.003;
   - (b) a serverless/API discovery burst (lambda ListFunctions*/GetPolicy*, apigateway GetRestApis/GetStages)
     → T1526;
   - (c) DescribeSnapshots / DescribeSnapshotAttribute with an owner filter, or a large count by a non-admin
     identity → T1580;
   - (d) a ConsoleLogin failure with "No username found in supplied account" → T1110 (enumeration).

   The flaws slice is a ready regression set for (a)–(c).
5. **Sigma map (cyberforge-0c):**
   - give `sigma_6393e346` its tactic (Credential Access);
   - re-label `sigma_352a918a` to T1552.005;
   - review the `aws:ec2-instance` hits of `sigma_352a918a`: 938 of its 1000 alerts are from one IP.
6. **Harness (test-engineer, only via probes):** consider normalising AWS ARNs in `norm_user`
   (`assumed-role/<role>/<session>` → session) so that both sides use the same entity convention. Do this only with
   a new probe, never to raise one run's score.
7. **Performance:** detect has a fixed cost of about 25–180 s per run even for 2–75 rows (threads 2, CPU-saturated
   machine). It is worth one `perf-fixer` pass on the cloud rule group and on `cl_first_seen_*` / baseline templates
   for tiny inputs.
8. **Next measurement:** run `ext_cloud_flawsconv` (1.94M events, already converted, 2.3 GB) when about 6 GB of RAM
   is free. Build the v2 full-period ground truth first, with `tools/ext/cloud_flaws_gt.py` (fixed).

## 7. Files

- Raw + SOURCE.md + ground truth: `data/raw/ext_cloud_{flaws,flawsgz,flawsrec,flawsslice,flawsconv,splunk_*}/`
- Outputs: `data/out/ext_cloud_*/` (eval_scorecard.json, run_metrics.json, ingest_accounting.json, suppressed.json,
  `ext_summary.json` = our per-step diagnosis, `ext_cloud_flawsslice/eval_scorecard_gt_v2.json`)
- Parquet: `data/parquet/ext_cloud_*/`
- Snapshot: `data/snap/ext_cloud/`
