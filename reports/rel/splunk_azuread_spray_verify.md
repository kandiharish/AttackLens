# Verify: rel_splunk_azuread_spray (independent check)

Verdict: **confirmed** (detection 0 %, caused by the gate). Two small wording corrections are listed below.

## 1. Ground truth
- Docs (password_spraying_azuread.yml, fetched raw) say: Invoke-MSOLSpray against an Azure AD tenant using 30 user accounts, mitre_technique T1110.003, sourcetype azure:monitor:aad, date 2023-06-16. The docs give no host, user, IP or time.
- attacks.json has 1 attack and 1 step: T1110.003 / Credential Access. The docs support this. No documented step is missing.
- The host, user, src_ip and ts come from one raw event, and the GT notes say so. The values check out against the raw file: resourceId `/tenants/fc69e276-.../Microsoft.aadiam`, src_ip 82.1.1.35, user Sebastian.Lee, ts 18:13:08.952Z.
- Caveat: almost every line matches the string "aad" (resourceId contains `aadiam`), so "first line containing aad" just means line 0. That line is the latest event in time; the spray runs 18:11:35 to 18:13:08Z. The 93.6 s gap is well inside the 600 s tolerance, so the score does not change.
- The raw file has 31 distinct users, but the docs say 30. This is cosmetic.
- sha256 47b8195a… matches. attacks.json mtime is 11:00:02 +0530. The run started at 05:35:14Z (11:05:14 +0530), so the GT was written before the run.

## 2. Reproduction (snapshot data/snap/rel, out data/out/rel_splunk_azuread_spray_verify)
- I waited for free RAM ≥ 700 MB (852 MB at start). The run exited 0 in 45.9 s with peak RSS 130 MB.
- eval_scorecard.json is identical to the original, apart from the ground_truth path key. Both have detection 0.0, rebuilt 0.0 and labels/FA null.
- Accounting is identical: 31 in, 31 ok, 0 dropped, 0 quarantined. Episodes ed37a532015 and edf93a53775 are the same, the single R2 edge is the same, and suppressed.json is the same.

## 3. Miss causes (checked against outputs and code)
- Correct: the step was detected and then suppressed by the gate. Both episodes have T1110/T1110.003, Credential Access, conf 75, host `.../microsoft.aadiam`, src_ip 82.1.1.35, start ts 18:11:35.348Z.
- Correct: the suppression reason is "fewer than 2 tactics and max confidence 75 < 90" (incident_gate.py:209). Also correct: min_tactics 2 (linking.yaml:74), burst needs ≥ 3 techniques (:89), and T1110 is not in single_step_critical (:115-150).
- Correct: all 31 rows are resultType 50126 (failed sign-in), so there is no success sign-in and no T1078 follow-on.
- Wording fix: "31 alerts / 29 alerts" are raw_alert_count. Each rule emitted 1 aggregated alert (alerts_per_rule = 1). The 29 is 29 distinct properties.id/correlationId values, which I confirmed in the raw data.
- Wording fix: harness.py:30-31 (DETECTABLE_NOISE) applies only to noise-singleton recall and does not affect GT-step credit. The step scores 0 only because there are 0 incidents.

## 4. As published
- I downloaded the file again from the media.githubusercontent URL. sha256 14b4ded5… and 113,331 bytes / 31 lines are identical to src/azuread_signin.log. Nothing was reshaped. The profiler auto-detected it as azure_signin_json.
