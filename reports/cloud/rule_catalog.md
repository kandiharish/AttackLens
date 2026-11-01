# AttackLens cloud rule catalog: AWS CloudTrail, Azure (Entra sign-ins, Entra audit, Activity Log), GCP Cloud Audit Logs

Research report, 2026-11-01. Nothing in the code or config was changed. This file is the input for a `backend-builder`
delegation: `config/rules.yaml`, the proposed `config/cloud.yaml`, `config/sigma_map.yaml`, and new templates.

Contents
- §0 Summary (counts, top sources, licences)
- §1 Sources surveyed and licence rules
- §2 How to implement: our columns, JSON paths, macros, data prerequisites
- §3 Coverage table: Stratus Red Team / ATT&CK → source rules → our rule id
- §4 Native rules (69 rule ids, by tactic)
- §5 Behavioural / anomaly rules for novel attacks (18)
- §6 Sigma cloud rules: what to enable, what to skip, field mappings
- §7 Noise controls
- §8 Gaps and next steps

---

## 0. Summary

- **Native rules: 69 ids** (several ids have 2–4 branches; each branch is one `match` entry or one template call).
  By tactic: Initial Access 9 · Execution 6 · Persistence 11 · Privilege Escalation 9 · Stealth 2 ·
  Defense Impairment 10 · Credential Access 6 · Discovery 3 · Lateral Movement 3 · Exfiltration 4 · Impact 6.
  Collection is covered by the behavioural rules B10 and B14 (T1530).
  By cloud (an id counts once per cloud it covers): AWS 41 · Azure 35 · GCP 23.
- **Behavioural rules: 18** (B1–B18). They cover all three clouds through shared templates. Every window and threshold
  is a `config/cloud.yaml` key.
- **Stratus Red Team coverage:** all 93 cloud techniques (46 AWS, 15 Azure, 7 Entra ID, 25 GCP) are mapped to at
  least one rule. 82 can be detected from the logs our connectors pull by default. 11 need log settings that are off
  by default (CloudTrail S3 data events, GCP Data Access logs, Azure StorageBlobLogs); §3 marks them. The 10
  EKS/Kubernetes techniques are out of scope because we do not ingest Kubernetes audit logs.
- **Sigma:** 226 cloud rules are vendored (AWS 58, Azure 123, GCP 26, M365 19). None compile today because
  `sigma_map.yaml` has no cloud logsource. §6 lists **73 to enable** (34 at their own level, 39 forced down to
  `low` as context), **16 to disable as noisy or broken**, and **137 to skip** (logsource not ingested, placeholder
  values, list fields, or replaced by a better native rule).
- **Top sources by rules reused:** Stratus Red Team (Apache-2.0) for test plan and event names; SigmaHQ (DRL 1.1);
  Elastic detection-rules (ELv2, logic ideas only); Splunk security_content (Apache-2.0); Azure-Sentinel (MIT);
  Panther (Apache-2.0).
- **Licence notes:** Panther **is Apache-2.0**, not AGPL (GitHub licence API and `LICENSE.txt`, checked 2026-11-01), so
  its logic may be copied with attribution. **Elastic is Elastic License 2.0.** Every Elastic-derived entry below is
  re-expressed in our own SQL. No Elastic query text is copied. Keep it that way, or disclose any copied text in
  `README.md`.

---

## 1. Sources surveyed

| Source | Licence | What we used | Rule |
|---|---|---|---|
| SigmaHQ `rules/cloud/{aws,azure,gcp}`, vendored at `config/sigma/rules/cloud` (commit 05d1031) | DRL 1.1 | 226 rules read and classified (§6). Logic is re-used in native rules with attribution. | Keep author, id and reference when we show a Sigma-based alert. Already handled by `sigma_<id8>` ids. |
| DataDog Stratus Red Team `docs/attack-techniques/*` (main, 2026-11) | Apache-2.0 | Technique list = coverage target and test plan. "Detection" sections give exact event names. | Copying is fine. Add a NOTICE line in README. |
| Splunk `security_content/detections/cloud` (develop, 120 aws/azure/gcp/cloud files) | Apache-2.0 | Thresholds for AccessDenied recon, concurrent sessions, GetObject anomaly, previously-unseen patterns. | Copying is fine with attribution. |
| Azure-Sentinel `Solutions/Microsoft Entra ID` + `Solutions/Azure Activity` analytic rules (the `Detections/` copies are migration stubs) | MIT | Entra operation names, ResultType codes, spray/MFA/rare-operation thresholds. | Copying is fine. Keep the MIT notice. |
| Elastic `detection-rules/rules/integrations/{aws,azure,gcp}` (480 files) | Elastic License 2.0 | Ideas only: new-terms windows (10 d), role chaining, self-created key used, SSE-C threshold (20), unusual ASN API list. | Do not paste query text. Our SQL is original. Disclose "logic inspired by" in README. |
| Panther `panther-analysis/rules/aws_cloudtrail_rules` | Apache-2.0 (verified) | Ideas and lists: IMDS credential exfil, unused region, short lifecycle, SSE-C copy, cross-account KMS copy. | Copying is fine with attribution. |
| Falco `falcosecurity/plugins` cloudtrail rules | Apache-2.0 | Cross-check only. Nothing unique was found beyond the above. | — |
| MITRE ATT&CK Cloud matrix (IaaS, Identity Provider, Office Suite) via `config/attack_v20.json` | ATT&CK terms of use (attribution) | All technique ids below exist in our v20 file. Note the v20 renumbering: Impair Defenses tools = **T1685**, cloud logs = **T1685.002**, cloud firewall = **T1686.001**, T1562.007/.008 are gone. | Already disclosed. |
| iptoasn.com `ip2asn-combined.tsv.gz` (range_start, range_end, AS_number, country_code, AS_description) | PDDL 1.0 (public domain) | Offline IP → ASN + country for AWS/GCP/Azure Activity (only SigninLogs carries geo itself). | Disclose in README. |
| DB-IP "IP to ASN / Country Lite" (CSV/MMDB) | CC BY 4.0 | Alternative to iptoasn. | Attribution + link to db-ip.com on pages that show results. |
| AWS `ip-ranges.json`, Google `cloud.json` / `goog.json` | Public feeds | "Is the caller inside the cloud provider?" tests (instance credentials used off-host). | Disclose as data sources. Snapshot them into `config/geo/`. |

URLs (base paths; each rule entry gives its file name):
- Sigma: `https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/`
- Stratus: `https://stratus-red-team.cloud/attack-techniques/<PLATFORM>/<technique-id>/`
- Splunk: `https://github.com/splunk/security_content/blob/develop/detections/cloud/<name>.yml`
- Sentinel: `https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/<name>.yaml`
  and `.../Solutions/Azure%20Activity/Analytic%20Rules/<name>.yaml`
- Elastic: `https://github.com/elastic/detection-rules/blob/main/rules/integrations/<cloud>/<name>.toml`
- Panther: `https://github.com/panther-labs/panther-analysis/tree/develop/rules/aws_cloudtrail_rules/<name>.py`

---

## 2. How to implement against our formats

### 2.1 What ingest already gives us (from `config/sources.yaml` + `ingest_maps.py`)

| Canonical column | cloudtrail_json | azure_signin_json | azure_activity_json (Activity Log **and** Entra AuditLogs) | gcp_audit_json |
|---|---|---|---|---|
| `signature` (= API) | `eventName` | `OperationName` ("Sign-in activity") | `OperationNameValue` (e.g. `MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE`), else AuditLogs `OperationName` (e.g. `Add member to role`) | `protoPayload.methodName` |
| `app` (= service) | `eventSource` | `AppDisplayName` | `ResourceProviderValue` / `LoggedByService` | `protoPayload.serviceName` |
| `host` (= account scope) | `recipientAccountId` | `_ResourceId` (tenant) or app name | full `_ResourceId`, lower-case (resource level) | `resource.labels.project_id` |
| user | `userIdentity.userName` → `sessionIssuer.userName` (**role name, session name lost**) → arn → principalId | UPN, `@domain` stripped | `Caller` / `InitiatedBy.user.userPrincipalName` / `InitiatedBy.app.displayName`, `@domain` stripped | `principalEmail`, `@domain` stripped |
| `src_ip` | `sourceIPAddress` **only if it is an IP** (`AWS Internal`, `*.amazonaws.com` → NULL) | `IPAddress` | `CallerIpAddress` / `InitiatedBy.user.ipAddress` | `requestMetadata.callerIp` |
| `outcome` | ConsoleLogin result; else `errorCode` present → failure | ResultType 0 → success; MFA interrupts (50058/50072/50074/50076/50125/50140/50158) → NULL; other → failure | Succeeded → success, Failed → failure, Start/Accept → NULL | no `status` or code 0 → success, else failure |
| `action` | `consolelogin` → login_success/failed, `createuser` → user_created, `addusertogroup` → group_member_added, else the API name | `sign-in activity` → login_success/failed | `add user` → user_created, `add member to group` → group_member_added | API name |
| `target_user` | `requestParameters.userName` (also the login user for ConsoleLogin) | the UPN (login action) | `TargetResources[0].userPrincipalName` | — |
| `raw_line` | full JSON line (label keys `threat/rule/labels/labels_extra` and `event.kind/...` removed; note GCP's **top-level `labels`** is removed by this, `resource.labels` stays) | same | same | same |

Facts the rules depend on:
- **Actor.** For login actions the user is in `target_user`. For every other call it is in `src_user`. Use the macro
  `actor` below.
- **Upper-case.** Azure operation names come in mixed case. Always compare `upper(signature)`.
- **Azure double rows.** Azure Activity emits several rows per operation (Start, Accept, Succeeded). Count
  `DISTINCT az_corr` in burst templates, and match `outcome = 'success'`, or `outcome IS NULL AND J('$.ActivityStatusValue') IN ('Accept','Accepted')` for async creates.
- **Ingest alias gaps (backend-builder):**
  1. The Activity Log **REST/Event-Grid** shape has `operationName: {value, localizedValue}` and `status: {value}`.
     Add aliases `'$.operationName.value'` before `'$.operationName'` and `'$.status.value'` to `azure_activity_json`.
  2. The connector table list should add `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs` and
     `AADManagedIdentitySignInLogs`. They already route to `azure_signin_json` by content. Token replay and service
     principal abuse show up mostly there.

### 2.2 Macros used in every rule below

`J(p)` means `json_extract_string(raw_line, p)`. It returns VARCHAR; for an object or array it returns the JSON text.
A `[*]` path returns `VARCHAR[]`. Use `list_contains` / `list_has_any` on it.

```
-- source gates
CT   := source_type = 'cloudtrail_json'
AZS  := source_type = 'azure_signin_json'
AZA  := source_type = 'azure_activity_json' AND (J('$.OperationNameValue') IS NOT NULL
        OR upper(signature) LIKE 'MICROSOFT.%')                                     -- Activity Log (ARM)
AZD  := source_type = 'azure_activity_json' AND coalesce(J('$.LoggedByService'), J('$.loggedByService'),
        J('$.properties.loggedByService')) IS NOT NULL                              -- Entra AuditLogs
GCP  := source_type = 'gcp_audit_json'

-- shared
actor  := CASE WHEN action IN ('login_success','login_failed') THEN target_user ELSE src_user END
api    := signature        api_u := upper(signature)        svc := app
acct   := CASE WHEN CT OR GCP THEN host
               WHEN AZA THEN coalesce(regexp_extract(host, '^/subscriptions/([^/]+)', 1), J('$.SubscriptionId'))
               ELSE coalesce(J('$.TenantId'), J('$.AADTenantId'), J('$.tenantId')) END

-- AWS
ct_type  := J('$.userIdentity.type')     -- Root | IAMUser | AssumedRole | FederatedUser | AWSService | AWSAccount | IdentityCenterUser
ct_arn   := J('$.userIdentity.arn')      -- assumed-role/<role>/<session>: keeps the session name src_user loses
ct_iss   := J('$.userIdentity.sessionContext.sessionIssuer.arn')
ct_akid  := J('$.userIdentity.accessKeyId')   -- AKIA… long-term, ASIA… temporary
ct_mfa   := J('$.userIdentity.sessionContext.attributes.mfaAuthenticated')
ct_ua    := J('$.userAgent')        ct_err := J('$.errorCode')      ct_msg := J('$.errorMessage')
ct_ip    := J('$.sourceIPAddress')  -- raw: also 'AWS Internal' / service DNS names
ct_rp    := J('$.requestParameters')   ct_re := J('$.responseElements')   ct_add := J('$.additionalEventData')
ct_ro    := J('$.readOnly')         ct_region := J('$.awsRegion')     ct_id := J('$.eventID')
ct_svc   := ct_type = 'AWSService' OR J('$.userIdentity.invokedBy') IS NOT NULL OR ct_ip LIKE '%.amazonaws.com'
ct_write := ct_ro = 'false' OR (ct_ro IS NULL AND regexp_matches(api,
            '^(Create|Delete|Put|Update|Modify|Attach|Detach|Add|Remove|Set|Start|Stop|Terminate|Run|Authorize|Revoke|Enable|Disable|Associate|Disassociate|Import|Schedule|Send|Restore|Register|Deregister|Replace|Reset|Change)'))
ct_instance_role := regexp_matches(ct_arn, ':assumed-role/[^/]+/i-[0-9a-f]{8,17}$')

-- Azure Activity Log
az_caller := coalesce(J('$.Caller'), J('$.caller'))      -- raw; contains '@' for humans, a GUID for service principals
az_human  := az_caller LIKE '%@%'
az_req    := coalesce(J('$.Properties_d.requestbody'), json_extract_string(J('$.Properties'), '$.requestbody'),
                      J('$.properties.requestbody'))
az_resp   := coalesce(J('$.Properties_d.responseBody'), json_extract_string(J('$.Properties'), '$.responseBody'),
                      J('$.properties.responseBody'))
az_status_code := coalesce(J('$.Properties_d.statusCode'), json_extract_string(J('$.Properties'), '$.statusCode'),
                           J('$.properties.statusCode'), J('$.ActivitySubstatusValue'))
az_corr   := coalesce(J('$.CorrelationId'), J('$.correlationId'))

-- Entra AuditLogs
au_cat  := coalesce(J('$.Category'), J('$.category'), J('$.properties.category'))
au_name := coalesce(J('$.ActivityDisplayName'), J('$.activityDisplayName'), J('$.properties.activityDisplayName'), signature)
au_by_upn := coalesce(J('$.InitiatedBy.user.userPrincipalName'), J('$.properties.initiatedBy.user.userPrincipalName'))
au_by_app := coalesce(J('$.InitiatedBy.app.displayName'), J('$.properties.initiatedBy.app.displayName'))
tr_json := CAST(coalesce(json_extract(raw_line, '$.TargetResources'), json_extract(raw_line, '$.targetResources'),
                         json_extract(raw_line, '$.properties.targetResources')) AS VARCHAR)   -- includes modifiedProperties
au_add  := CAST(coalesce(json_extract(raw_line, '$.AdditionalDetails'), json_extract(raw_line, '$.properties.additionalDetails')) AS VARCHAR)

-- Entra SigninLogs (Log Analytics column, else diagnostic export properties.*)
si(Col, col) := coalesce(J('$.Col'), J('$.properties.col'))
si_code  := si(ResultType, status.errorCode)            si_ua := si(UserAgent, userAgent)
si_client:= si(ClientAppUsed, clientAppUsed)            si_req := si(AuthenticationRequirement, authenticationRequirement)
si_proto := si(AuthenticationProtocol, authenticationProtocol)     -- deviceCode | ropc | saml20 | wsFederation | none
si_risk  := si(RiskLevelDuringSignIn, riskLevelDuringSignIn)       si_rstate := si(RiskState, riskState)
si_asn   := si(AutonomousSystemNumber, autonomousSystemNumber)
si_cc    := coalesce(J('$.LocationDetails.countryOrRegion'), J('$.properties.location.countryOrRegion'), J('$.Location'))
si_lat   := coalesce(J('$.LocationDetails.geoCoordinates.latitude'), J('$.properties.location.geoCoordinates.latitude'))
si_lon   := coalesce(J('$.LocationDetails.geoCoordinates.longitude'), J('$.properties.location.geoCoordinates.longitude'))
si_sess  := coalesce(si(SessionId, sessionId), si(UniqueTokenIdentifier, uniqueTokenIdentifier))
si_home  := si(HomeTenantId, homeTenantId)  si_res_tenant := si(ResourceTenantId, resourceTenantId)
si_appid := si(AppId, appId)                si_authdet := CAST(json_extract(raw_line, '$.AuthenticationDetails') AS VARCHAR)

-- GCP
g_code  := J('$.protoPayload.status.code')        -- '7' PERMISSION_DENIED, '16' UNAUTHENTICATED
g_ua    := J('$.protoPayload.requestMetadata.callerSuppliedUserAgent')
g_res   := J('$.protoPayload.resourceName')       g_rtype := J('$.resource.type')     g_log := J('$.logName')
g_req   := J('$.protoPayload.request')            g_resp  := J('$.protoPayload.response')
g_md    := J('$.protoPayload.metadata')           g_sd    := J('$.protoPayload.serviceData')
g_delta := coalesce(J('$.protoPayload.serviceData.policyDelta.bindingDeltas'), J('$.protoPayload.metadata.datasetChange.bindingDeltas'))
g_audit_delta := J('$.protoPayload.serviceData.policyDelta.auditConfigDeltas')
g_deleg := J('$.protoPayload.authenticationInfo.serviceAccountDelegationInfo')   -- impersonation chain
g_zone  := J('$.resource.labels.zone')            g_id := J('$.insertId')

-- denied (recon / probing)
denied := (CT AND ct_err IN ('AccessDenied','AccessDeniedException','UnauthorizedOperation','Client.UnauthorizedOperation',
                              'UnauthorizedAccess','AuthorizationError','Forbidden','InvalidClientTokenId'))
       OR (GCP AND g_code IN ('7','16'))
       OR (AZA AND outcome = 'failure' AND (az_status_code ILIKE '%forbidden%' OR az_status_code ILIKE '%authorizationfailed%'))
```

**Performance recommendation (important at 50 GB):** do not let 69 rules each parse `raw_line`. At the start of
Stage 2, run one `CREATE TEMP TABLE cloud_ev AS SELECT source_seq, ts_ms, event_day, source_type, action, outcome, host,
src_user, target_user, src_ip, signature, app, <every macro above as a column> FROM events WHERE source_type IN
(cloud types)`. That is one JSON pass with bounded memory. All cloud rules then read `cloud_ev`. Promote the most used
macros (`user_agent`, `principal_type`, `session_id`, `access_key_id`, `error_code`, `read_only`, `region`,
`country`, `asn`) to canonical columns later if the schema owner agrees.

### 2.3 Data prerequisites (some rules need logs that are off by default)

| Tag | Needs | Default |
|---|---|---|
| `[mgmt]` | CloudTrail management events, Azure Activity Log, Entra SigninLogs/AuditLogs, GCP Admin Activity | on (what our connectors pull) |
| `[ct-data]` | CloudTrail **data events** (S3 Get/Put/DeleteObject, Lambda Invoke) | off; must be enabled per trail |
| `[gcp-da]` | GCP **Data Access** audit logs (secretmanager, storage objects, iamcredentials, compute get/list, testIamPermissions) | off except BigQuery |
| `[az-res]` | Azure resource logs (`StorageBlobLogs`, `AzureDiagnostics` / `AZKVAuditLogs`) | off; tables are not in our connector list |
| `[geo]` | Offline IP → ASN / country table (§1). SigninLogs needs none: it carries country and ASN. | must be shipped in `config/geo/` |
| `[ranges]` | AWS / Google published IP-range snapshot | must be shipped |

---

## 3. Coverage table

Columns: Stratus technique → ATT&CK v20 technique (tactic) → public rules that cover it → **our rule id(s)** →
data tag. "B#" is a behavioural rule from §5.

### 3.1 AWS (Stratus `aws.*`)

| Stratus technique | ATT&CK v20 | Public source rules | Ours | Data |
|---|---|---|---|---|
| credential-access.ec2-get-password-data | T1552 (CA) | Splunk aws_credential_access_getpassworddata · Panther aws_ec2_many_passwors_read_attempts | aws_ec2_password_data | mgmt |
| credential-access.ec2-steal-instance-credentials | T1552.005 (CA) + T1078.004 | Panther aws_imds_credential_exfiltration · GuardDuty InstanceCredentialExfiltration (concept) | cl_instance_creds_offhost, B12 | mgmt, ranges |
| credential-access.secretsmanager-batch-retrieve-secrets | T1555.006 (CA) | Splunk aws_anomalous_secrets_manager_batch_retrieval · Panther ..._batch | cl_secrets_mass_read | mgmt |
| credential-access.secretsmanager-retrieve-secrets | T1555.006 | Elastic credential_access_rapid_secret_retrieval_attempts_from_secretsmanager · Panther | cl_secrets_mass_read, B1 | mgmt |
| credential-access.ssm-retrieve-securestring-parameters | T1555.006 | Elastic credential_access_retrieve_secure_string_parameters_via_ssm · Panther aws_ssm_decrypt_ssm_params | cl_secrets_mass_read | mgmt |
| defense-evasion.cloudtrail-delete / -stop / -event-selectors | T1685.002 (DI) | Sigma 4db60cc0 · Elastic cloudtrail_logging_{deleted,suspended}, management_events_disabled_via_eventselectors · Splunk | aws_logging_tamper, B11 | mgmt |
| defense-evasion.cloudtrail-lifecycle-rule | T1685.002 | Splunk aws_defense_evasion_putbucketlifecycle · Elastic s3_bucket_lifecycle_expiration_added · Panther aws_cloudtrail_short_lifecycle | aws_logging_tamper (b) | mgmt |
| defense-evasion.dns-delete-logs | T1685.002 | Elastic route53_dns_query_resolver_config_deletion · Panther aws_dns_logs_deleted | aws_security_service_off | mgmt |
| defense-evasion.organizations-leave | T1666 (DI) | Elastic organizations_leave_organization · Panther aws_cloudtrail_attempt_to_leave_org | cl_leave_hierarchy | mgmt |
| defense-evasion.vpc-remove-flow-logs | T1685.002 | Sigma e386b9b5 · Elastic ec2_flow_log_deletion | aws_security_service_off | mgmt |
| discovery.ec2-enumerate-from-instance | T1580 (DS) | Stratus note (arn ends `i-*`) · Elastic discovery_multiple_discovery_api_calls_via_cli | B4 (instance-role variant), B1 | mgmt |
| discovery.ec2-download-user-data | T1552.005 / T1580 | Elastic discovery_ec2_userdata_request_for_ec2_instance · Panther aws_ec2_download_instance_user_data | cl_instance_metadata_read | mgmt |
| discovery.ses-enumerate | T1526 (DS) | Panther aws_cloudtrail_ses_* (4) · Elastic discovery_ses_enumeration_via_long_term_access_key | aws_ses_recon | mgmt |
| execution.ec2-launch-unusual-instances | T1496.001 (IM) | Panther aws_ec2_launch_unusual_ec2_instances · Splunk cloud_compute_instance_created_with_previously_unseen_instance_type | cl_compute_hijack | mgmt |
| execution.ec2-user-data | T1059.009 (EX) | Sigma 1ab3c5ed · Splunk aws_ec2_startup_script_modified_on_stopped_instance · Elastic execution_ec2_stop_start_with_user_data_modification | aws_ec2_userdata_modified | mgmt |
| execution.sagemaker-update-lifecycle-config | T1651 (EX) | Elastic persistence_sagemaker_lifecycle_config_suspicious_script_content | aws_serverless_code_change (b) | mgmt |
| execution.ssm-send-command | T1651 | Sigma 38e7f511 · Elastic execution_ssm_sendcommand_by_rare_user · Panther aws_ssm_distributed_command | aws_ssm_command | mgmt |
| execution.ssm-start-session | T1021.008 (LM) | Elastic lateral_movement_aws_ssm_start_session_to_ec2_instance | aws_remote_access_multi | mgmt |
| exfiltration.ec2-security-group-open-port-22-ingress | T1686.001 (DI) | Elastic vpc_security_group_ingress_rule_added_for_remote_connections · Sigma 6fb77778 (context) | cl_firewall_open_world | mgmt |
| exfiltration.ec2-share-ami | T1537 (EF) | Elastic exfiltration_ec2_ami_shared_with_separate_account · Splunk aws_ami_attribute_modification_for_exfiltration · Panther | cl_snapshot_image_share_external | mgmt |
| exfiltration.ec2-share-ebs-snapshot | T1537 | Sigma abae8fec · Splunk aws_ec2_snapshot_shared_externally · Elastic | cl_snapshot_image_share_external | mgmt |
| exfiltration.ec2-share-ebs-volume (RAM) | T1537 | Stratus (ram AssociateResourceShare) | cl_snapshot_image_share_external (c) | mgmt |
| exfiltration.rds-share-snapshot | T1537 | Elastic rds_snapshot_shared_with_another_account · Panther aws_rds_snapshot_shared | cl_snapshot_image_share_external | mgmt |
| exfiltration.s3-backdoor-bucket-policy | T1537 / T1530 | Elastic exfiltration_s3_bucket_policy_added_for_external_account_access · Panther aws_s3_bucket_policy_modified | cl_storage_public_or_external | mgmt |
| impact.bedrock-invoke-model | T1496.004 (IM) | Splunk aws_bedrock_* · Sigma 59b70e4d/1c722651 (guardrail) | aws_service_hijack | mgmt |
| impact.ec2-deregister-ami | T1485 (IM) | Panther aws_modify_cloud_compute_infrastructure | cl_backup_destruction | mgmt |
| impact.s3-ransomware-batch-deletion / -individual-deletion | T1485 | Splunk detect_spike_in_s3_bucket_deletion · Panther aws_s3_delete_objects | B13 | ct-data |
| impact.s3-ransomware-client-side-encryption | T1486 | Elastic impact_s3_excessive_object_encryption_with_sse_c · Panther aws_s3_copy_object_with_client_side_encryption | cl_storage_ransom_encrypt, B13 | ct-data |
| initial-access.console-login-without-mfa | T1078.004 (IA) | Sigma 77caf516 · Elastic iam_user_console_login_without_mfa · Panther | aws_console_login_no_mfa | mgmt |
| lateral-movement.ec2-instance-connect / -serial-console-send-ssh-public-key | T1021.008 | Elastic lateral_movement_ec2_instance_connect_ssh_public_key_uploaded · Splunk aws_ec2_multiple_ssh_public_keys_uploaded_by_a_single_identity | aws_remote_access_multi | mgmt |
| persistence.ec2-create-suspicious-keypair | T1098.004 (PE) | Elastic persistence_new_terms_ec2_create_keypair_unusual_source_as · Sigma 92f84194 | aws_keypair_new | mgmt |
| persistence.iam-backdoor-role / -create-backdoor-role | T1098.003 (PE/PR) | Elastic iam_update_assume_role_policy · Splunk aws_iam_role_created_with_external_trust · Panther aws_iam_backdoor_role | aws_role_trust_backdoor | mgmt |
| persistence.iam-backdoor-user | T1098.001 | Sigma 0a5177f4 · Elastic iam_user_created_access_keys_for_another_user | aws_credential_for_other_user, B8 | mgmt |
| persistence.iam-create-admin-user | T1136.003 + T1098.003 | Elastic administratoraccess_policy_attached_to_user · Panther aws_iam_attach_admin_user_policy | aws_admin_policy_attached, existing `account_created_then_elevated`, B7 | mgmt |
| persistence.iam-create-user-login-profile | T1098 | Elastic iam_login_profile_created_or_modified · Splunk aws_createloginprofile | aws_credential_for_other_user (b) | mgmt |
| persistence.lambda-backdoor-function | T1546 (PE) | Elastic lambda_backdoor_invoke_function_for_any_principal · Panther aws_backdoor_lambda_function | aws_lambda_backdoor (a) | mgmt |
| persistence.lambda-layer-extension | T1525 (PE) | Elastic execution_lambda_external_layer_added_to_function · Panther aws_add_malicious_lambda_extension · Sigma 97fbabf8 | aws_lambda_backdoor (b) | mgmt |
| persistence.lambda-overwrite-code | T1648 (EX) | Splunk aws_lambda_updatefunctioncode · Panther aws_overwrite_lambda_code | aws_serverless_code_change (a) | mgmt |
| persistence.rolesanywhere-create-trust-anchor | T1484.002 (PR/DI) | Elastic roles_anywhere_trusted_anchor_created_with_external_ca | aws_federation_trust_change | mgmt |
| persistence.sts-federation-token | T1550.001 (LM) | Elastic defense_evasion_sts_get_federation_token · sts_get_federation_token_administrator_access | aws_federation_token | mgmt |
| privilege-escalation.iam-update-user-login-profile | T1098 | Sigma 055fb148 · Splunk aws_updateloginprofile | aws_credential_for_other_user (b) | mgmt |

### 3.2 Azure and Entra ID (Stratus `azure.*`, `entra-id.*`)

| Stratus technique | ATT&CK v20 | Public source rules | Ours | Data |
|---|---|---|---|---|
| azure.credential-access.app-service-publishing-credentials | T1552 (CA) | Stratus (`MICROSOFT.WEB/SITES/PUBLISHXML/ACTION`) | az_key_listing | mgmt |
| azure.execution.vm-custom-script-extension | T1651 (EX) | Elastic execution_azure_vm_extension_unusual_for_host | az_remote_exec | mgmt |
| azure.execution.vm-run-command | T1651 | Elastic execution_azure_vm_managed_run_command_unusual_identity · Sentinel RareRunCommandPowerShellScript | az_remote_exec | mgmt |
| azure.exfiltration.disk-export | T1537 (EF) | Stratus (`DISKS/BEGINGETACCESS/ACTION`) | az_disk_sas_export | mgmt |
| azure.exfiltration.storage-public-access | T1530 (CO) | Elastic collection_azure_storage_account_blob_public_access_enabled | cl_storage_public_or_external (d) | mgmt |
| azure.exfiltration.storage-sas-export | T1552 / T1537 | Elastic credential_access_azure_storage_account_keys_accessed · Sentinel RareOperations | az_key_listing, B14 | mgmt |
| azure.impact.blob-ransomware-client-encryption-scope | T1486 | Stratus | cl_storage_ransom_encrypt (c) | mgmt (+az-res for blob ops) |
| azure.impact.blob-ransomware-cpek | T1486 | Stratus | B13 (only with StorageBlobLogs) | az-res |
| azure.impact.blob-ransomware-individual-file-deletion | T1485 | Stratus | B13 (only with StorageBlobLogs) | az-res |
| azure.impact.blob-ransomware-service-storage-cmk | T1486 | Stratus | cl_storage_ransom_encrypt (c), cl_kms_key_destroy | mgmt |
| azure.impact.resource-lock | T1685 (DI) | Stratus | az_lock_deleted | mgmt |
| azure.persistence.backdoor-managed-identity-fic | T1098.001 (PE) | Elastic persistence_entra_id_federated_identity_credential_modified | az_app_or_identity_credential (c) | mgmt |
| azure.persistence.create-bastion-shareable-link | T1021.008 (LM) | Stratus | az_remote_access | mgmt |
| azure.persistence.exfiltrate-foundry-key | T1552 + T1556 | Elastic credential_access_azure_ai_foundry_keys_or_connection_secrets_accessed | az_key_listing (+seq) | mgmt |
| azure.privilege-escalation.root-user-access-administrator | T1098.003 (PR) | Sigma 09438caa / ca9bf243 · Elastic elevate_to_user_administrator_access | az_elevate_access | mgmt |
| entra-id.persistence.backdoor-application(-sp, -fic) | T1098.001 | Sigma cbb67ecc · Sentinel NewAppOrServicePrincipalCredential · Splunk azure_ad_service_principal_new_client_credentials | az_app_or_identity_credential | mgmt |
| entra-id.persistence.guest-user | T1136.003 / T1078.004 | Splunk azure_ad_external_guest_user_invited · Elastic entra_id_external_guest_user_invite | az_guest_external | mgmt |
| entra-id.persistence.hidden-au / restricted-au | T1098.003 + T1564 | Stratus | az_hidden_au | mgmt |
| entra-id.persistence.new-application | T1098.001 | Splunk azure_ad_service_principal_created · Sigma 0ddcff6d | az_app_or_identity_credential (a), B1 | mgmt |

### 3.3 GCP (Stratus `gcp.*`)

| Stratus technique | ATT&CK v20 | Public source rules | Ours | Data |
|---|---|---|---|---|
| credential-access.secretmanager-retrieve-secrets | T1555.006 | Elastic (gke variants only) | cl_secrets_mass_read (c) | gcp-da |
| defense-evasion.delete-dns-logs | T1685.002 | Stratus | gcp_logging_tamper (d) | mgmt |
| defense-evasion.delete-logging-sink / disable-logging-sink | T1685.002 | Elastic defense_evasion_gcp_logging_sink_deletion · exfiltration_gcp_logging_sink_modification | gcp_logging_tamper (a) | mgmt |
| defense-evasion.disable-audit-logs | T1685.002 | Stratus (auditConfigs removed) | gcp_logging_tamper (b) | mgmt |
| defense-evasion.reduce-sink-log-retention | T1685.002 | Elastic defense_evasion_gcp_storage_bucket_configuration_modified | gcp_logging_tamper (c) | mgmt (+gcp-da) |
| defense-evasion.remove-project-from-organization | T1666 (DI) | Stratus | cl_leave_hierarchy (b) | mgmt |
| defense-evasion.remove-vpc-flow-logs | T1685.002 | Stratus | gcp_logging_tamper (d) | mgmt |
| discovery.download-instance-metadata | T1552.005 / T1580 | Stratus | cl_instance_metadata_read (b), B1 | gcp-da |
| discovery.enumerate-permissions | T1069.003 (DS) | Stratus | gcp_testiam_burst | gcp-da |
| execution.modify-vertex-notebook-startup | T1059.009 | Stratus | gcp_startup_script (b) | mgmt |
| exfiltration.share-compute-disk / -image / -snapshot | T1537 | Stratus | cl_snapshot_image_share_external (d) | mgmt |
| impact.create-gpu-vm / create-instances-in-multiple-zones | T1496.001 | Stratus | cl_compute_hijack (c) | mgmt |
| impact.gcs-ransomware-client-side-encryption | T1486 | Stratus | cl_storage_ransom_encrypt (b), B13 | gcp-da |
| impact.gcs-ransomware-individual-deletion | T1485 | Splunk (none for GCS) | B13 | gcp-da |
| initial-access.use-compute-sa-outside-gcp | T1078.004 + T1552.005 | Stratus | cl_instance_creds_offhost (b) | mgmt, ranges |
| lateral-movement.add-sshkey-instance-metadata | T1098.004 | Stratus | gcp_ssh_key_metadata | mgmt |
| persistence.backdoor-service-account-policy | T1098.003 | Elastic persistence_gcp_service_account_impersonation_role_grant | gcp_sensitive_grant (b) | mgmt |
| persistence.create-admin-service-account | T1136.003 + T1098.003 | Elastic persistence_gcp_service_account_created | gcp_sensitive_grant (a), B7 | mgmt |
| persistence.create-service-account-key | T1098.001 | Elastic persistence_gcp_key_created_for_service_account | gcp_sa_key_created | mgmt |
| persistence.invite-external-user | T1098.003 | Stratus | gcp_sensitive_grant (c) | mgmt |
| privilege-escalation.impersonate-service-accounts | T1548.005 (PR) | Stratus | gcp_sa_impersonation_use, B9 | gcp-da |

### 3.4 ATT&CK cloud techniques with no Stratus technique (covered anyway)

| ATT&CK | Ours |
|---|---|
| T1110.001 / T1110.003 brute force and spray (console, Entra) | cl_signin_bruteforce, cl_password_spray |
| T1621 MFA request generation | az_mfa_fatigue |
| T1528 consent phishing / T1098.003 Graph app roles | az_oauth_consent_privileged |
| T1484.002 trust modification (federation, SAML/OIDC providers) | az_federation_change, aws_federation_trust_change |
| T1556.009 conditional access / T1556.006 MFA | az_ca_policy_change, az_mfa_disabled, az_auth_method_added |
| T1535 unused regions | cl_unused_region |
| T1580 / T1526 / T1087.004 / T1069.003 discovery | B4, B5, aws_ses_recon, gcp_testiam_burst |
| T1078.004 valid cloud accounts (anomalous) | B2, B6, B12, az_valid_password_new_country, az_risky_signin_success |
| T1531 account access removal | cl_access_removal |
| T1040-like traffic mirroring | cl_traffic_mirroring |
| T1530 data from cloud storage (volume) | B14 |

---

## 4. Native rules

Format: **id** · clouds · technique (tactic) · severity (0–100, same scale as `rules.yaml`). Then:
**Logic** (SQL over the macros in §2.2), **FP** (false positives and how to suppress them), **Src** (source).
`cfg.<key>` means a key in the proposed `config/cloud.yaml`. All lists are config, not code.
Every rule is `outcome = 'success'` unless it says otherwise.

Severity tiers (they match the scoring in `sigma_map.yaml`): **≤35 context** (never seeds, never a tactic) ·
**45–60 signal** (counts only when rare or chained) · **65–80 strong** · **85–95 critical**.

### 4.1 Initial Access (TA0001)

**aws_console_login_no_mfa** · AWS · T1078.004 (Initial Access) · 55
- Logic: `CT AND api='ConsoleLogin' AND action='login_success' AND J('$.additionalEventData.MFAUsed')='No' AND ct_type IN ('IAMUser','Root')`.
- FP: accounts without MFA by design; SSO users (type AssumedRole) are excluded already. Suppress with `cfg.no_mfa_allow_users`. Raise to 75 when B2 (new country/ASN) fires for the same actor within 1 h.
- Src: Sigma `aws_cloudtrail_console_login_success_without_mfa` 77caf516 (DRL) · Stratus aws.initial-access.console-login-without-mfa (Apache-2.0).

**aws_root_usage** · AWS · T1078.004 (Initial Access) · 70 login / 60 API
- Logic: (a) `CT AND api='ConsoleLogin' AND action='login_success' AND ct_type='Root'` → 70. (b) `CT AND ct_type='Root' AND J('$.eventType') <> 'AwsServiceEvent' AND J('$.userIdentity.invokedBy') IS NULL AND api <> 'ConsoleLogin'` → 60, and 80 if `api IN ('CreateAccessKey','CreateLoginProfile','UpdateLoginProfile','DeactivateMFADevice','DeleteVirtualMFADevice')`.
- FP: break-glass procedures and billing tasks. Use `cfg.root_allow_ips` and a change-window list.
- Src: Sigma `aws_root_account_usage` 8ad1600d · Elastic initial_access_console_login_root · Panther aws_root_activity, aws_root_access_key_created.

**aws_console_pw_ok_mfa_fail** · AWS · T1078.004 (Initial Access) · 65
- Logic: `CT AND api='ConsoleLogin' AND action='login_failed' AND J('$.additionalEventData.MFAUsed')='Yes'`. The password was right and the MFA step failed, so the password is compromised. ≥ `cfg.mfa_fail_min` (3) per actor in 30 min → 75.
- FP: a mistyped TOTP code once. A threshold of 1 → 45, ≥ 3 → 75.
- Src: Splunk `aws_console_login_failed_during_mfa_challenge` (Apache-2.0).

**cl_signin_bruteforce** · AWS, Azure · T1110.001 (Credential Access) + secondary T1078 (Initial Access) · 75 / 85
- Logic: existing template `brute_force_then_success` with `filter: source_type IN ('cloudtrail_json','azure_signin_json')`, `params: {bf_min_failures: cfg.bf_min_failures (10), bf_key: [target_user]}`. Azure failure rows are limited to password failures: `si_code IN ('50126','50053','50056','50055')`. A success within `bf_success_window_ms` emits T1078.
- FP: user lockout loops and stale mobile mail clients (same src_ip, ClientAppUsed Exchange ActiveSync). Exclude `si_client IN cfg.legacy_noisy_clients` from the failure count.
- Why a new instance: today's rule needs 50 failures per (user, host), and Azure `host` changes per app.
- Src: Sentinel `SigninBruteForce-AzurePortal` (MIT) · Splunk `aws_high_number_of_failed_authentications_for_user`, `azure_ad_high_number_of_failed_authentications_for_user` · Elastic credential_access_entra_id_brute_force_activity (idea).

**cl_password_spray** · AWS, Azure · T1110.003 (Credential Access) · 75 / 85
- Logic: existing template `password_spray` with `filter: source_type IN ('cloudtrail_json','azure_signin_json')`, `params: {spray_min_users: cfg.spray_min_users (10), spray_window_ms: 1200000}`. Azure failures: `si_code IN ('50126','50053','50055')`. Also emit when one src_ip/ASN fails for ≥ 10 users and ≥ 1 of those users then succeeds (`si_code IN ('0','50074','50076','50158')`, because an MFA interrupt means the password was right).
- FP: NAT egress of a large office. Allowlist `cfg.corp_egress_cidrs`.
- Src: Sentinel `SigninPasswordSpray` (thresholds: 20 min window, failure codes 50053/50126/50055) · Splunk `azure_ad_multiple_users_failing_to_authenticate_from_ip`, `aws_multiple_users_failing_to_authenticate_from_ip` · Panther aws_cloudtrail_password_spraying.

**az_valid_password_new_country** · Azure · T1078.004 (Initial Access) · 70
- Logic: `AZS AND (si_code IN ('50074','50076','500121','50158') OR si_authdet ILIKE '%Correct Password%')`, and the `(actor, si_cc)` pair was not seen with `si_code='0'` in the previous `cfg.geo_baseline_days` (7).
- FP: travel. Suppress when the user later succeeds from the same country with MFA (it was the user). That lowers it to 35.
- Src: Sentinel `NewCountryValidCreds` (MIT).

**az_risky_auth_protocol** · Azure · T1078.004 / T1528 (Initial Access / Credential Access) · 60–75
- Logic: (a) Device code: `AZS AND si_proto='deviceCode' AND si_code='0'`. Severity 75 if the `(actor)` never used deviceCode in the baseline (30 d), else 35. (b) ROPC or legacy auth success: `AZS AND si_code='0' AND (si_proto='ropc' OR si_ua ILIKE '%BAV2ROPC%' OR si_client IN ('Exchange ActiveSync','IMAP4','POP3','Authenticated SMTP','Other clients','MAPI Over HTTP','Exchange Web Services','AutoDiscover','Offline Address Book','Exchange Online PowerShell'))` → 60.
- FP: kiosk/IoT device-code apps and scanners/printers using SMTP. Use `cfg.device_code_allow_apps` (si_appid) and `cfg.legacy_auth_allow_users`.
- Src: Sigma 248649b7, 55695bc0, 53bb4f7f · Elastic initial_access_entra_id_first_time_seen_device_code_auth, unusual_ropc_login_attempt · Splunk azure_ad_device_code_authentication.

**az_risky_signin_success** · Azure · T1078.004 (Initial Access) · 70
- Logic: `AZS AND si_code='0' AND (si_risk IN ('high','medium') OR si_rstate IN ('atRisk','confirmedCompromised'))`. `high` → 80.
- FP: the vendor (Identity Protection) risk score is a raw field, not a label, so it is allowed. It is noisy for `medium`, so `medium` with `si_req='multiFactorAuthentication'` → 45.
- Src: Elastic initial_access_entra_id_high_risk_signin (idea) · Splunk azure_active_directory_high_risk_sign_in · Sigma 572b12d4.

**cl_instance_creds_offhost** · AWS, GCP · T1552.005 (Credential Access) + T1078.004 · 85
- Logic: (a) AWS: `CT AND ct_instance_role AND src_ip IS NOT NULL AND NOT al_ip_in_ranges(src_ip, 'aws') AND J('$.vpcEndpointId') IS NULL`. Fallback without a ranges table: the `(ct_arn session)` is first seen from this /16 after being seen from another /16 within 6 h. (b) GCP: `GCP AND J('$.protoPayload.authenticationInfo.principalEmail') LIKE '%-compute@developer.gserviceaccount.com' AND NOT al_ip_in_ranges(src_ip, 'gcp') AND coalesce(g_ua,'') NOT ILIKE '%GCE%'`.
- FP: instances behind a NAT gateway (their egress IP *is* in AWS ranges, so no FP), and on-prem proxies of hybrid setups. Use `cfg.instance_role_allow_cidrs`.
- Src: Panther `aws_imds_credential_exfiltration` (Apache-2.0) · Stratus aws.credential-access.ec2-steal-instance-credentials, gcp.initial-access.use-compute-sa-outside-gcp · Sigma 352a918a (different heuristic, kept as context).

### 4.2 Execution (TA0002)

**cl_attack_tool_user_agent** · AWS, Azure, GCP · T1059.009 (Execution) · 75
- Logic: `ua := coalesce(ct_ua, si_ua, J('$.HTTPRequest.clientRequestId') /*no UA in AzureActivity*/, g_ua)`. Match `regexp_matches(lower(ua), cfg.attack_ua_regex)`, default `pacu|trufflehog|s3 browser|azurehound|roadtools|roadrecon|aadinternals|teamfiltration|graphrunner|tokentactics|kali|parrot|pentoo|blackarch|cloudfox|stratus-red-team|cloudsploit|weirdaal|cliam|gcploit`. Detection-tool UAs (`prowler|scoutsuite|steampipe|cloudquery|cartography`) → 30 (context).
- FP: sanctioned red-team runs. Use `cfg.redteam_principals` and windows. For the demo, Stratus UA (`stratus-red-team_<uuid>`) proves the rule works.
- Src: Sigma a840e606, 9b1b8e9b, db014773, 35b781cc · Elastic initial_access_suspicious_user_agent_detected_in_cloudtrail, initial_access_entra_id_kali365_user_agent (ideas) · Splunk azure_ad_azurehound_useragent_detected.

**aws_ssm_command** · AWS · T1651 (Execution) · 55 / 75
- Logic: `CT AND svc='ssm.amazonaws.com' AND api IN ('SendCommand','StartAutomationExecution','CreateAssociation')`. Targets: `json_array_length(J('$.requestParameters.instanceIds'))`, or the `targets` text. 75 if ≥ `cfg.ssm_min_targets` (3) distinct instances by one actor in 10 min, or if `(actor, api)` is first-seen (B1), else 55.
- FP: patch managers (AWS-RunPatchBaseline document). Exclude `J('$.requestParameters.documentName') IN cfg.ssm_allow_documents` and `ct_svc`.
- Src: Sigma 38e7f511 · Stratus aws.execution.ssm-send-command · Elastic execution_ssm_sendcommand_by_rare_user · Panther aws_ssm_distributed_command.

**aws_ec2_userdata_modified** · AWS · T1059.009 (Execution) · 75 / 85
- Logic: `CT AND api='ModifyInstanceAttribute' AND (J('$.requestParameters.attribute')='userData' OR J('$.requestParameters.userData') IS NOT NULL)`. 85 when the same instance (`J('$.requestParameters.instanceId')`) had `StopInstances` within the previous 1 h and `StartInstances` within 1 h after (Stratus pattern).
- FP: golden-image pipelines. Use `cfg.iac_principals`.
- Src: Sigma 1ab3c5ed · Splunk aws_ec2_startup_script_modified_on_stopped_instance · Stratus aws.execution.ec2-user-data.

**aws_serverless_code_change** · AWS · T1648 (Execution) · 50 / 70
- Logic: (a) `CT AND svc='lambda.amazonaws.com' AND api LIKE 'UpdateFunctionCode%'`. (b) `CT AND svc='sagemaker.amazonaws.com' AND api IN ('CreateNotebookInstanceLifecycleConfig','UpdateNotebookInstanceLifecycleConfig','UpdateNotebookInstance') AND ct_rp ILIKE '%LifecycleConfig%'`. 70 if the actor is first-seen for that API (B1) or `ct_ua` is not a CI/IaC UA (`cfg.iac_ua_regex`: terraform|pulumi|cloudformation|cdk|serverless|sam-cli|github-actions|codebuild).
- FP: deployments. That is why the base is 50 and the rule needs rarity to seed.
- Src: Splunk aws_lambda_updatefunctioncode · Panther aws_overwrite_lambda_code · Stratus aws.persistence.lambda-overwrite-code, aws.execution.sagemaker-update-lifecycle-config.

**az_remote_exec** · Azure · T1651 (Execution) · 55–80
- Logic: `AZA AND api_u IN ('MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION','MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE','MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/VIRTUALMACHINES/RUNCOMMAND/ACTION','MICROSOFT.HYBRIDCOMPUTE/MACHINES/RUNCOMMANDS/WRITE','MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE','MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE','MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE','MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE')`. Extensions only when `az_req ILIKE '%CustomScript%' OR az_req ILIKE '%commandToExecute%'`. Severity: runCommand by `az_human` 70. First-seen `(az_caller, api_u)` → 80. Extension or runbook 55.
- FP: Azure Policy/Defender agents (caller is a GUID service principal; extension type MDE/AMA). Exclude `az_req ILIKE ANY cfg.az_allow_extensions` and non-human callers unless first-seen.
- Src: Stratus azure.execution.vm-run-command, vm-custom-script-extension · Elastic execution_azure_vm_managed_run_command_unusual_identity, execution_automation_runbook_created_or_modified · Splunk azure_automation_runbook_created, azure_runbook_webhook_created.

**gcp_startup_script** · GCP · T1059.009 (Execution) · 70
- Logic: (a) `GCP AND api IN ('v1.compute.instances.setMetadata','beta.compute.instances.setMetadata','v1.compute.projects.setCommonInstanceMetadata') AND regexp_matches(coalesce(g_md,'')||coalesce(g_req,''), '(startup-script|shutdown-script|startup-script-url)')`. (b) `GCP AND api ILIKE '%notebooks.v%.NotebookService.UpdateInstance' AND g_req ILIKE '%startup-script%'` (covers post-startup-script).
- FP: config management. Use `cfg.iac_principals`.
- Src: Stratus gcp.execution.modify-vertex-notebook-startup, gcp.lateral-movement.add-sshkey-instance-metadata (same API).

### 4.3 Persistence (TA0003)

**aws_credential_for_other_user** · AWS · T1098.001 (Persistence) · 75; self = context 35
- Logic: (a) `CT AND api='CreateAccessKey' AND J('$.requestParameters.userName') IS NOT NULL AND lower(J('$.requestParameters.userName')) <> lower(coalesce(J('$.userIdentity.userName'), regexp_extract(ct_arn, '[^/]+$')))` → 75. Self-created → 35 (feeds B8). (b) `CT AND api IN ('CreateLoginProfile','UpdateLoginProfile') AND <same "other user" test>` → 75. 85 if the target user had no console login in the baseline.
- FP: IAM admins rotating keys for users. Use `cfg.iam_admin_principals` (still emitted, at 45).
- Src: Sigma 0a5177f4 (uses `fieldref|contains`, which our compiler cannot do, hence native), 055fb148 · Elastic persistence_iam_user_created_access_keys_for_another_user · Stratus aws.persistence.iam-backdoor-user, iam-create-user-login-profile, aws.privilege-escalation.iam-update-user-login-profile.

**aws_role_trust_backdoor** · AWS · T1098.003 (Persistence / Privilege Escalation) · 80; internal 50
- Logic: `CT AND api IN ('UpdateAssumeRolePolicy','CreateRole')`. `doc := lower(coalesce(J('$.requestParameters.policyDocument'), J('$.requestParameters.assumeRolePolicyDocument')))`. External if `regexp_matches(doc, '"aws"\s*:\s*"\*"|"principal"\s*:\s*"\*"')` or any `regexp_extract_all(doc, 'arn:aws:iam::(\d{12}):', 1)` element is not in `[host] + cfg.trusted_aws_accounts`. External → 80, else 50.
- FP: cross-account roles for vendors (Datadog, Wiz, etc.). List their accounts in `cfg.trusted_aws_accounts`.
- Src: Elastic privilege_escalation_iam_update_assume_role_policy, discovery_iam_principal_enumeration_via_update_assume_role_policy · Splunk aws_iam_role_created_with_external_trust · Panther aws_iam_backdoor_role · Stratus iam-backdoor-role, iam-create-backdoor-role.

**aws_federation_trust_change** · AWS · T1484.002 (Privilege Escalation / Defense Impairment) · 80
- Logic: `CT AND api IN ('CreateSAMLProvider','UpdateSAMLProvider','DeleteSAMLProvider','CreateOpenIDConnectProvider','UpdateOpenIDConnectProviderThumbprint','AddClientIDToOpenIDConnectProvider','CreateTrustAnchor','UpdateTrustAnchor','CreateProfile' /*rolesanywhere*/,'EnableExternalIdPConfigurationForDirectory','DisableExternalIdPConfigurationForDirectory','AssociateDirectory','DisassociateDirectory','CreateInstanceAccessControlAttributeConfiguration')`. `CreateProfile` only for `svc='rolesanywhere.amazonaws.com'`.
- FP: initial IdP setup. Use change windows and `cfg.iac_principals` (→ 45).
- Src: Sigma ccd6a6c8, f43f5d2f, d3adb3ef · Elastic persistence_iam_saml_provider_created, persistence_iam_oidc_provider_created, persistence_iam_roles_anywhere_trusted_anchor_created_with_external_ca · Splunk aws_saml_update_identity_provider.

**aws_lambda_backdoor** · AWS · T1546 (Persistence) / T1525 · 80
- Logic: (a) `CT AND api LIKE 'AddPermission%' AND (J('$.requestParameters.principal') = '*' OR regexp_extract(J('$.requestParameters.principal'), '(\d{12})', 1) NOT IN ([host] + cfg.trusted_aws_accounts))`. Also `api LIKE 'CreateFunctionUrlConfig%' AND J('$.requestParameters.authType')='NONE'` → 70. (b) `CT AND api LIKE 'UpdateFunctionConfiguration%' AND ct_rp ILIKE '%layers%'` where any layer ARN account (`regexp_extract_all(ct_rp, 'arn:aws:lambda:[^:]+:(\d{12}):layer', 1)`) is not in `[host] + cfg.trusted_aws_accounts` → 80, own account → 40.
- FP: public webhook functions. Use `cfg.public_lambda_allow` (function names).
- Src: Elastic persistence_lambda_backdoor_invoke_function_for_any_principal, execution_lambda_external_layer_added_to_function, persistence_lambda_function_url_public_access · Panther aws_backdoor_lambda_function, aws_add_malicious_lambda_extension · Sigma ec541962, 97fbabf8.

**aws_keypair_new** · AWS · T1098.004 (Persistence) · 45; suspicious name 70
- Logic: `CT AND svc='ec2.amazonaws.com' AND api IN ('CreateKeyPair','ImportKeyPair')`. 70 when the actor is first-seen for the API (B1) and `ct_akid LIKE 'AKIA%'` (long-term key, as in Stratus), or the key name matches `cfg.suspicious_name_regex` (`(?i)^(test|temp|tmp|backdoor|key|pwn|hack|a|x)\d*$`).
- FP: developers creating key pairs. That is why the base is 45.
- Src: Sigma 92f84194 · Elastic persistence_new_terms_ec2_create_keypair_unusual_source_as · Stratus aws.persistence.ec2-create-suspicious-keypair.

**az_app_or_identity_credential** · Azure · T1098.001 (Persistence) · 75 / 85
- Logic: (a) `AZD AND (au_name ILIKE 'Update application%Certificates and secrets management' OR au_name IN ('Add service principal credentials','Update service principal') OR (au_name='Update application' AND tr_json ILIKE '%KeyDescription%'))` → 75. If the app has a privileged Graph app role (seen in az_oauth_consent_privileged) or a privileged directory role → 85. (b) `AZD AND au_name IN ('Add application','Add service principal')` → 35 context (feeds B7). (c) Federated credential: `(AZD AND au_name ILIKE 'Update application%' AND tr_json ILIKE '%FederatedIdentityCredentials%') OR (AZA AND api_u = 'MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/FEDERATEDIDENTITYCREDENTIALS/WRITE')` → 85, or 90 if the issuer (`regexp_extract(coalesce(tr_json, az_req), '"?Issuer"?\\?"?\s*:\s*\\?"(https?://[^"\\]+)', 1)`) is not in `cfg.trusted_oidc_issuers`.
- Note: the real activity name uses an en dash ("Update application – Certificates…"). Match with `ILIKE '%Certificates and secrets management'`, not the Sigma hyphen string.
- FP: app owners rotating secrets. Exclude `au_by_upn IN cfg.app_owner_allow` (→ 45). GitHub-Actions OIDC FICs go in `cfg.trusted_oidc_issuers`.
- Src: Sentinel NewAppOrServicePrincipalCredential, FirstAppOrServicePrincipalCredential, CredentialAddedAfterAdminConsent (MIT) · Sigma cbb67ecc · Stratus entra-id backdoor-application, -sp, -fic, azure.persistence.backdoor-managed-identity-fic · Elastic persistence_entra_id_federated_identity_credential_modified (idea).

**az_guest_external** · Azure · T1136.003 (Persistence) / T1078.004 · 50 invite / 75 promotion
- Logic: (a) `AZD AND au_name IN ('Invite external user','Add user sponsor') OR (au_name='Add user' AND tr_json ILIKE '%#EXT#%')` → 50. Raise to 70 if the inviter is first-seen as an inviter (Sentinel GuestUsersInvitedtoTenantbyNewInviters). (b) `AZD AND au_name='Update user' AND tr_json ILIKE '%UserType%' AND tr_json ILIKE '%Guest%' AND tr_json ILIKE '%Member%'` (Guest→Member) → 75. (c) A guest added to a privileged role or group within 24 h → 85 (sequence with az_entra_privileged_role).
- FP: B2B collaboration. Use `cfg.trusted_guest_domains` and `cfg.guest_inviters`.
- Src: Splunk azure_ad_external_guest_user_invited · Sigma 8dee7a0d, 0b4b72e3 · Sentinel UserStatechangedfromGuesttoMember, NewExtUserGrantedAdmin · Stratus entra-id.persistence.guest-user.

**az_auth_method_added** · Azure · T1556.006 (Persistence / Credential Access) · 50 / 80
- Logic: `AZD AND (au_name IN ('User registered security info','Admin registered security info','User registered all required security info','Update user') AND (au_name <> 'Update user' OR tr_json ILIKE '%StrongAuthenticationMethod%'))`. TAP: `au_add ILIKE '%temporary access pass%' OR J('$.ResultReason') ILIKE '%temporary access pass%'` → 75. Admin registering a method for *another* user → 70. Self-registration within 6 h after a risky or new-country sign-in of the same user (B17) → 80, else 35.
- FP: onboarding waves. Use `cfg.onboarding_principals` and the bulk-registration days list.
- Src: Sigma 4d78a000, fa84aaf5 · Sentinel AdditionofaTemporaryAccessPasstoaPrivilegedAccount, SuspiciousSignInFollowedByMFAModification · Splunk azure_ad_new_mfa_method_registered_for_user · Elastic initial_access_entra_id_temporary_access_pass_created.

**az_hidden_au** · Azure · T1098.003 (Persistence) + T1564 (Stealth) · 70
- Logic: `AZD AND (au_name IN ('Add member to restricted management administrative unit','Add scoped member to role') OR (au_name='Add administrative unit' AND tr_json ILIKE ANY ('%HiddenMembership%','%isMemberManagementRestricted%true%')))`.
- FP: tenant admins building AU structures. Use `cfg.iac_principals`.
- Src: Stratus entra-id.persistence.hidden-au, restricted-au.

**gcp_sa_key_created** · GCP · T1098.001 (Persistence) · 60 / 80
- Logic: `GCP AND api = 'google.iam.admin.v1.CreateServiceAccountKey'`. The target SA is `regexp_extract(coalesce(J('$.protoPayload.request.name'), g_res), 'serviceAccounts/([^/]+)', 1)`. 80 if the actor is a user (not `*.gserviceaccount.com`) creating a key for an SA with roles/owner/editor, or the actor is first-seen for the API (B1). Also `google.iam.admin.v1.UploadServiceAccountKey` → 80.
- FP: CI bootstrapping. Use `cfg.iac_principals`. Org policy `iam.disableServiceAccountKeyCreation` makes any success notable.
- Src: Elastic persistence_gcp_key_created_for_service_account (idea) · Stratus gcp.persistence.create-service-account-key.

**gcp_ssh_key_metadata** · GCP · T1098.004 (Persistence / Privilege Escalation) · 65
- Logic: `GCP AND api IN ('v1.compute.instances.setMetadata','beta.compute.instances.setMetadata','v1.compute.projects.setCommonInstanceMetadata') AND (coalesce(J('$.protoPayload.metadata.instanceMetadataDelta.addedMetadataKeys'),'')||coalesce(J('$.protoPayload.metadata.instanceMetadataDelta.modifiedMetadataKeys'),'')||coalesce(J('$.protoPayload.metadata.projectMetadataDelta.addedMetadataKeys'),'')) ILIKE '%ssh-keys%'`. Project-wide → 75.
- FP: OS Login is off and `gcloud compute ssh` adds keys routinely (UA `google-cloud-sdk gcloud/... command/gcloud.compute.ssh`). Those → 35 unless the actor is first-seen on that instance.
- Src: Stratus gcp.lateral-movement.add-sshkey-instance-metadata.

### 4.4 Privilege Escalation (TA0004)

**aws_admin_policy_attached** · AWS · T1098.003 (Privilege Escalation) · 75
- Logic: `CT AND ((api IN ('AttachUserPolicy','AttachRolePolicy','AttachGroupPolicy') AND regexp_matches(J('$.requestParameters.policyArn'), cfg.admin_policy_regex /* ':policy/(AdministratorAccess|IAMFullAccess|PowerUserAccess|AWSOrganizationsFullAccess)$' */)) OR (api IN ('PutUserPolicy','PutRolePolicy','PutGroupPolicy','CreatePolicyVersion','CreatePolicy') AND regexp_matches(regexp_replace(lower(ct_rp), '\\s', '', 'g'), '"action":"\*"|"action":\["\*"\]|"action":"iam:\*"') AND regexp_matches(lower(ct_rp), '"resource":"\*"|"resource":\["\*"\]')))`. Target is self → 85 (self-escalation).
- FP: account bootstrap by IaC. Use `cfg.iac_principals` (→ 45).
- Src: Elastic privilege_escalation_iam_administratoraccess_policy_attached_to_{user,role,group} · Panther aws_iam_attach_admin_user_policy, aws_iam_attach_admin_role_policy · Splunk aws_create_policy_version_to_allow_all_resources · Stratus iam-create-admin-user.

**aws_iam_privesc_primitives** · AWS · T1098.003 / T1548 (Privilege Escalation) · 60 / 80
- Logic: `CT AND api IN ('SetDefaultPolicyVersion','DeleteUserPermissionsBoundary','DeleteRolePermissionsBoundary','PutUserPermissionsBoundary','PutRolePermissionsBoundary','AssociateIamInstanceProfile','ReplaceIamInstanceProfileAssociation','AddUserToGroup','UpdateAccessKey','CreatePolicyVersion')`. `CreatePolicyVersion` only with `J('$.requestParameters.setAsDefault')='true'`. `AddUserToGroup` only when `group_name ILIKE ANY cfg.admin_group_patterns`. 80 when the target principal equals the actor (self) or the actor is first-seen for the API (B1). Also PassRole abuse: `api IN ('CreateFunction20150331','RunInstances','CreateNotebookInstance','CreateDevEndpoint','CreateJob','CreateStack')` with a role param whose role has an admin policy attached in the data set → 75.
- FP: IAM automation. `cfg.iac_principals`.
- Src: Elastic iam_customer_managed_policy_version_created_or_set_default, iam_permissions_boundary_modified, ec2_instance_profile_associated_with_running_instance · Splunk aws_setdefaultpolicyversion · Rhino Security "AWS IAM privilege escalation methods" (public research, idea only).

**aws_federation_token** · AWS · T1550.001 (Lateral Movement) · 55 / 80
- Logic: `CT AND svc='sts.amazonaws.com' AND api='GetFederationToken'`. 80 when `ct_rp ILIKE '%AdministratorAccess%'` or `J('$.requestParameters.policyArns')` contains an admin policy, or a `signin.amazonaws.com` `ConsoleLogin` with `ct_type='FederatedUser'` follows within 1 h (Elastic chain).
- FP: legacy federation brokers. `cfg.federation_brokers`.
- Src: Elastic defense_evasion_sts_get_federation_token, privilege_escalation_sts_get_federation_token_administrator_access, credential_access_get_federation_token_followed_by_console_login_via_federation_exchange (ideas) · Stratus aws.persistence.sts-federation-token.

**az_entra_privileged_role** · Azure · T1098.003 (Privilege Escalation / Persistence) · 80; to service principal 85
- Logic: `AZD AND au_name IN ('Add member to role','Add eligible member to role','Add scoped member to role','Add member to role completed (PIM activation)','Add member to role outside of PIM (permanent)','Add eligible member (permanent)','Add eligible member (eligible)') AND (regexp_matches(lower(tr_json), cfg.entra_priv_role_regex) OR list_has_any(regexp_extract_all(lower(tr_json), '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), cfg.entra_priv_role_ids))`. Defaults: role names Global/Privileged Role/Privileged Authentication/Application/Cloud Application/User/Hybrid Identity/Security/Conditional Access/Exchange/Intune Administrator. Template ids: 62e90394-69f5-4237-9190-012177145e10, e8611ab8-c189-46e8-94e1-60213ab1f814, 7be44c8a-adaf-4e2a-84d6-ab2649e08a13, 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3, 158c047a-c907-4556-b7ef-446551a6b5f7, fe930be7-5e62-47db-91af-98c3a49a38b1, 8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2, 194ae4cb-b126-40b2-bd5b-6091b380977d, b1be1c3e-b65d-4f19-8427-f6fa0d97feb9, 29232cdf-9323-42fd-ade2-1d097af3e4de, 3a2c62db-5318-420d-8d74-23affee5d9d5, 7698a772-787b-4ac8-901f-60d6b08affd2. Verify the ids against the Microsoft "built-in roles" page when building. Target type Service Principal (`tr_json ILIKE '%"type":"ServicePrincipal"%'`) → 85. Self-assignment by an app → 90.
- FP: PIM activations by eligible admins (`completed (PIM activation)`) → 35 context unless off-hours by actor profile (B18).
- Src: Sentinel UserAssignedPrivilegedRole, ServicePrincipalAssignedPrivilegedRole, PrivlegedRoleAssignedOutsidePIM · Sigma 49a268a4, 11c767ae, ebbeb024 · Splunk azure_ad_global_administrator_role_assigned, azure_ad_privileged_role_assigned_to_service_principal · Elastic entra_id_application_self_assigned_privileged_role (idea).

**az_rbac_privileged_assignment** · Azure · T1098.003 (Privilege Escalation) · 75; other roles 35
- Logic: `AZA AND api_u='MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' AND list_has_any(regexp_extract_all(lower(coalesce(az_req,'')||coalesce(az_resp,'')), 'roledefinitions/([0-9a-f-]{36})', 1), cfg.az_priv_role_def_ids)`. Defaults: Owner 8e3af657-a8ff-443c-a75c-2fe8c4bcb635, Contributor b24988ac-6180-42a0-ab88-20f7382dd24c, User Access Administrator 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9, RBAC Administrator f58310d9-a9f6-439a-9e8d-f62e7b41a168. Scope at subscription or management group (`host` has no `/resourcegroups/`) → +10. Assignee not seen as a principal in the data set (external or new) → 85.
- FP: landing-zone automation. `cfg.iac_principals`.
- Src: Sigma a622fcd2 (keywords; kept as context) · Elastic privilege_escalation_azure_rbac_administrator_roles_assigned (idea) · Sentinel Granting_Permissions_To_Account_detection.

**az_elevate_access** · Azure · T1098.003 (Privilege Escalation) · 90
- Logic: `(AZA AND api_u='MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION') OR (AZD AND (au_cat='AzureRBACRoleManagementElevateAccess' OR au_name ILIKE 'User has elevated their access to User Access Administrator%'))`.
- FP: break-glass procedure. Allow-window only.
- Src: Sigma 09438caa, ca9bf243 · Stratus azure.privilege-escalation.root-user-access-administrator · Elastic privilege_escalation_entra_id_elevate_to_user_administrator_access.

**az_oauth_consent_privileged** · Azure · T1528 (Credential Access) / T1098.003 · 75 / 85
- Logic: (a) User consent: `AZD AND au_name='Consent to application' AND tr_json ILIKE '%IsAdminConsent%False%' AND regexp_matches(lower(tr_json), cfg.risky_scopes_regex /* mail\.read|mail\.readwrite|mail\.send|files\.read(write)?\.all|sites\.read(write)?\.all|offline_access|user\.readwrite\.all|directory\.readwrite\.all */)` → 75, or 85 if the app id (B3) is rare in the tenant. (b) Tenant-wide or app roles: `au_name IN ('Add delegated permission grant','Add app role assignment to service principal') AND (tr_json ILIKE '%AllPrincipals%' OR list_has_any(regexp_extract_all(lower(tr_json), '[0-9a-f-]{36}'), cfg.graph_priv_app_role_ids))` → 85. Default Graph app-role ids: RoleManagement.ReadWrite.Directory 9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8, AppRoleAssignment.ReadWrite.All 06b708a9-e830-4db3-a914-8e69da51d44f, Application.ReadWrite.All 1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9, Directory.ReadWrite.All 19dbc75e-c2e2-444c-a770-ec69d8559fc7, Mail.ReadWrite e2a3a72e-5f79-4c64-b1b1-878b674786c9, Mail.Read 810c84a8-4a9e-49e6-bf7d-12d183f40d01, Files.ReadWrite.All 75359482-378d-4052-8f01-80520e7db3cd, full_access_as_app dc890d15-9560-4a4c-9b7f-a736ec74ec40.
- FP: sanctioned SaaS onboarding. `cfg.trusted_app_ids`.
- Src: Sentinel RareApplicationConsent, ServicePrincipalAssignedAppRoleWithSensitiveAccess, MailPermissionsAddedToApplication · Sigma a6355fbe, 5aecf3d5, c1d147ae · Splunk azure_ad_privileged_graph_api_permission_assigned, azure_ad_fullaccessasapp_permission_assigned · Elastic initial_access_entra_id_illicit_consent_grant_via_registered_application (idea).

**gcp_sensitive_grant** · GCP · T1098.003 (Privilege Escalation / Persistence) · 70–85
- Logic: `GCP AND (api ILIKE '%SetIamPolicy' OR api='storage.setIamPermissions') AND g_delta ILIKE '%"action":"ADD"%'`. Parse the delta list `json_extract(raw_line, '$.protoPayload.serviceData.policyDelta.bindingDeltas[*]')`, one row per element (role, member). Three branches. (a) Role in `cfg.gcp_admin_roles` (roles/owner, roles/editor, roles/iam.securityAdmin, roles/iam.roleAdmin, roles/resourcemanager.organizationAdmin, roles/resourcemanager.projectIamAdmin, roles/iam.serviceAccountAdmin) → 75. (b) Role in impersonation set (roles/iam.serviceAccountTokenCreator, roles/iam.serviceAccountUser, roles/iam.workloadIdentityUser, roles/iam.serviceAccountKeyAdmin, roles/iam.serviceAccountOpenIdTokenCreator) on a service account → 75. (c) Member domain (`regexp_extract(member, '@(.+)$', 1)`) not in `cfg.trusted_domains`, or member `allUsers`/`allAuthenticatedUsers` → 85. Combinations stack to max 90.
- FP: Terraform SAs. Use `cfg.iac_principals`. Google-managed service agents (`@gcp-sa-*.iam.gserviceaccount.com`, `@cloudservices.gserviceaccount.com`) are excluded as members.
- Src: Elastic persistence_gcp_service_account_impersonation_role_grant (10 d new-terms idea) · Stratus gcp.persistence.backdoor-service-account-policy, create-admin-service-account, invite-external-user.

**gcp_sa_impersonation_use** · GCP · T1548.005 (Privilege Escalation) · 60 / 80
- Logic: `GCP AND svc='iamcredentials.googleapis.com' AND api IN ('GenerateAccessToken','GenerateIdToken','SignBlob','SignJwt')`, or any event with `g_deleg IS NOT NULL`. Target SA is `regexp_extract(g_res, 'serviceAccounts/([^/]+)', 1)`. 80 when ≥ `cfg.impersonation_min_targets` (3) distinct SAs by one actor in 10 min, when the `(actor, target)` pair is first-seen (B1 key variant), or when the delegation chain length (`json_array_length(g_deleg)`) ≥ 2. Failures (`g_code='7'`) on ≥ 3 SAs → 70 (probing).
- FP: CI using workload identity. `cfg.iac_principals`.
- Src: Stratus gcp.privilege-escalation.impersonate-service-accounts (Data Access logs needed).

### 4.5 Stealth (TA0005)

**cl_unused_region** · AWS, Azure, GCP · T1535 (Stealth) · 60
- Logic: `region := coalesce(ct_region, lower(J('$.location')) /*Azure ARM location rarely present*/, regexp_extract(g_zone, '^([a-z]+-[a-z]+\d+)', 1))`. Fire on `ct_write` (or AZA/GCP writes) where the region is not in `cfg.allowed_regions[acct]`, or it is first-seen for the account (B1 key `(acct, region)`, 30 d baseline). Also `CT AND api='EnableRegion'` → 60 (Sigma a5ffb6ea).
- FP: global services log `us-east-1` (iam, sts, organizations, route53, cloudfront). Exclude `svc IN cfg.global_services`.
- Src: Panther aws_unused_region · Splunk cloud_compute_instance_created_in_previously_unused_region, cloud_provisioning_activity_from_previously_unseen_region · Sigma a5ffb6ea.

**cl_account_create_delete_short** · AWS, Azure, GCP · T1136.003 (Persistence) + T1070 (Defense Impairment) · 70
- Logic: (create, delete) of the same principal within `cfg.create_delete_window_ms` (24 h): AWS `CreateUser`→`DeleteUser` (`requestParameters.userName`), `CreateAccessKey`→`DeleteAccessKey` (key id); Azure AuditLogs `Add user`→`Delete user` (target UPN in tr_json); GCP `CreateServiceAccount`→`DeleteServiceAccount`. If the principal did anything in between → 80.
- FP: test automation. `cfg.iac_principals`.
- Src: Sentinel AccountCreatedandDeletedinShortTimeframe (MIT) · Sigma 6f583da0 (single event only, hence native).

### 4.6 Defense Impairment (TA0112)

**aws_logging_tamper** · AWS · T1685.002 (Defense Impairment) · 70–90
- Logic: (a) `CT AND svc='cloudtrail.amazonaws.com' AND api IN ('StopLogging','DeleteTrail','DeleteEventDataStore','StopEventDataStoreIngestion')` → 90. `api IN ('UpdateTrail','PutEventSelectors','PutInsightSelectors')` → 65, or 85 if `regexp_matches(lower(ct_rp), '"includemanagementevents":false|"readwritetype":"readonly"|"excludemanagementeventsources":\["kms|"field":"readonly","equals":\["true"\]')`. (b) Trail or log bucket tamper: `CT AND api IN ('PutBucketLifecycle','PutBucketLifecycleConfiguration') AND TRY_CAST(regexp_extract(ct_rp, '"Days"\s*:\s*(\d+)', 1) AS INT) <= cfg.short_retention_days (7)` → 75; `api IN ('PutBucketLogging') AND ct_rp NOT ILIKE '%LoggingEnabled%'` → 60; `api IN ('DeleteBucketPolicy','PutBucketPolicy','DeleteBucket') AND J('$.requestParameters.bucketName') IN <trail buckets seen in CreateTrail/UpdateTrail responseElements.s3BucketName>` → 80. (c) CloudWatch Logs: `api IN ('DeleteLogGroup','DeleteLogStream','PutRetentionPolicy','DeleteSubscriptionFilter')` → 45 context (75 if the group name contains `cloudtrail|flowlog|guardduty`).
- FP: trail re-creation by IaC → `cfg.iac_principals` (→ 45).
- Src: Sigma 4db60cc0 · Stratus cloudtrail-stop/delete/event-selectors/lifecycle-rule · Elastic defense_evasion_cloudtrail_logging_{deleted,suspended}, cloudtrail_management_events_disabled_via_eventselectors, s3_bucket_lifecycle_expiration_added, s3_bucket_server_access_logging_disabled, impact_cloudwatch_log_group_deletion · Splunk aws_defense_evasion_* (Apache-2.0) · Panther aws_cloudtrail_short_lifecycle.

**aws_security_service_off** · AWS · T1685 / T1685.002 (Defense Impairment) · 70–90
- Logic: `CT AND ((svc='guardduty.amazonaws.com' AND (api IN ('DeleteDetector','DisassociateFromMasterAccount','DisassociateFromAdministratorAccount','DeleteMembers','StopMonitoringMembers','DeletePublishingDestination','DeleteThreatIntelSet') OR (api='UpdateDetector' AND J('$.requestParameters.enable')='false') OR (api='CreateFilter' AND J('$.requestParameters.action')='ARCHIVE') OR api IN ('CreateIPSet','UpdateIPSet'))) OR (svc='securityhub.amazonaws.com' AND api IN ('DisableSecurityHub','DisableImportFindingsForProduct','DeleteInsight') ) OR (svc='config.amazonaws.com' AND api IN ('StopConfigurationRecorder','DeleteDeliveryChannel','DeleteConfigurationRecorder','DeleteConfigRule')) OR (svc='access-analyzer.amazonaws.com' AND api='DeleteAnalyzer') OR (svc='macie2.amazonaws.com' AND api IN ('DisableMacie','UpdateMacieSession')) OR (svc='inspector2.amazonaws.com' AND api='Disable') OR (svc='detective.amazonaws.com' AND api='DeleteGraph') OR (svc='ec2.amazonaws.com' AND api='DeleteFlowLogs') OR (svc='route53resolver.amazonaws.com' AND api IN ('DeleteResolverQueryLogConfig','DisassociateResolverQueryLogConfig')) OR (svc IN ('waf.amazonaws.com','wafv2.amazonaws.com','waf-regional.amazonaws.com') AND api IN ('DeleteWebACL','DisassociateWebACL')) OR (svc='bedrock.amazonaws.com' AND api IN ('DeleteModelInvocationLoggingConfiguration','DeleteGuardrail')) OR (svc='monitoring.amazonaws.com' AND api IN ('DeleteAlarms','DisableAlarmActions')))`. GuardDuty or Config or flow logs → 85. IPSet, alarms or WAF → 65. SecurityHub `BatchUpdateFindings` with `Workflow.Status = SUPPRESSED` in bulk (≥ 20 findings) → 70.
- FP: account decommissioning, cost cuts. Use change windows and `cfg.iac_principals`.
- Src: Sigma d2656e78, 6e61ee20, a607e1fe, 07330162, e386b9b5, 59b70e4d · Elastic defense_evasion_guardduty_*, securityhub_disabled, configuration_recorder_stopped, config_service_rule_deletion, detective_graph_deleted, waf_*, cloudwatch_alarm_deletion · Splunk aws_defense_evasion_impair_security_services, aws_bedrock_delete_model_invocation_logging_configuration · Stratus dns-delete-logs, vpc-remove-flow-logs.

**cl_leave_hierarchy** · AWS, GCP · T1666 (Defense Impairment) · 90
- Logic: (a) `CT AND svc='organizations.amazonaws.com' AND api IN ('LeaveOrganization','RemoveAccountFromOrganization','DeleteOrganization','CloseAccount')`. (b) `GCP AND (api ILIKE '%Projects.MoveProject' OR api='cloudresourcemanager.googleapis.com/projects.move' OR (api ILIKE '%Projects.UpdateProject' AND g_req ILIKE '%parent%'))`. Failures count too (outcome any) → 75. Attempts are the signal.
- FP: real reorganisations are rare and planned. Use a change window.
- Src: Stratus aws.defense-evasion.organizations-leave, gcp.defense-evasion.remove-project-from-organization · Elastic defense_evasion_organizations_leave_organization, impact_aws_account_closed · Panther aws_cloudtrail_attempt_to_leave_org.

**cl_firewall_open_world** · AWS, Azure, GCP · T1686.001 (Defense Impairment) · 70
- Logic: `world := '(0\.0\.0\.0/0|::/0|"\*"|internet|any)'`. `sens := cfg.sensitive_ports` (22,3389,445,5985,5986,1433,3306,5432,6379,9200,27017,2375,6443). (a) AWS: `CT AND api IN ('AuthorizeSecurityGroupIngress','ModifySecurityGroupRules','CreateNetworkAclEntry','ReplaceNetworkAclEntry') AND regexp_matches(ct_rp, '"cidrIp(v6)?"\s*:\s*"(0\.0\.0\.0/0|::/0)"|"cidrBlock"\s*:\s*"0\.0\.0\.0/0"')`. Ports from `regexp_extract_all(ct_rp, '"(fromPort|toPort)"\s*:\s*(-?\d+)', 2)`. Fire if `-1` (all), or a range covering any port in `sens`. NACL only when `"ruleAction":"allow"` and egress false. (b) Azure: `AZA AND api_u IN ('MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE','MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE') AND az_req ILIKE '%"access":"Allow"%' AND az_req ILIKE '%"direction":"Inbound"%' AND regexp_matches(lower(az_req), '"sourceaddressprefix(es)?":\s*\[?"(\*|0\.0\.0\.0/0|internet|any)"')` + port test on `destinationPortRange(s)`. (c) GCP: `GCP AND api ILIKE 'v%.compute.firewalls.%' AND regexp_matches(api, '(insert|patch|update)$') AND g_req ILIKE '%0.0.0.0/0%' AND coalesce(J('$.protoPayload.request.direction'),'INGRESS')='INGRESS'` + port test on `allowed[*].ports`.
- FP: public web ports 80/443 are not in `sens`. Bastion hosts go in `cfg.public_sg_allow` (group ids / NSG names).
- Src: Stratus aws.exfiltration.ec2-security-group-open-port-22-ingress · Elastic defense_evasion_vpc_security_group_ingress_rule_added_for_remote_connections, ec2_nacl_all_traffic_allowed_new_identity, defense_evasion_gcp_firewall_rule_created · Splunk aws_network_access_control_list_created_with_all_open_ports · Sigma 6fb77778, e1f7febb, fe513c69 (context versions).

**az_diag_or_defender_off** · Azure · T1685.002 / T1685 (Defense Impairment) · 80
- Logic: `AZA AND (api_u IN ('MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE','MICROSOFT.AADIAM/DIAGNOSTICSETTINGS/DELETE','MICROSOFT.INSIGHTS/LOGPROFILES/DELETE','MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE','MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DATASOURCES/DELETE','MICROSOFT.NETWORK/NETWORKWATCHERS/FLOWLOGS/DELETE','MICROSOFT.NETWORK/NETWORKWATCHERS/DELETE','MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE','MICROSOFT.SECURITYINSIGHTS/ALERTRULES/DELETE','MICROSOFT.SECURITYINSIGHTS/DATACONNECTORS/DELETE','MICROSOFT.EVENTHUB/NAMESPACES/EVENTHUBS/DELETE') OR (api_u='MICROSOFT.SECURITY/PRICINGS/WRITE' AND az_req ILIKE '%"pricingTier":"Free"%') OR (api_u='MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE' AND az_req ILIKE '%"enabled":false%'))`.
- FP (Sentinel's suppression): a diagnostic setting deleted because its parent resource was deleted. Drop the alert when the same `az_corr`, or a `…/DELETE` success on the parent resource id (`host` up to the provider segment), happens within 10 min.
- Src: Sentinel AzDiagSettingsDeleted (MIT; leftanti filter idea) · Sigma 92cc3e5d · Elastic defense_evasion_insights_diagnostic_settings_deletion, security_alert_suppression_rule_created, network_watcher_deletion, event_hub_deletion.

**az_lock_deleted** · Azure · T1685 (Defense Impairment; Stratus files it under Impact) · 60; 85 with destruction
- Logic: `AZA AND api_u='MICROSOFT.AUTHORIZATION/LOCKS/DELETE'`. 85 if the same caller deletes any resource under the lock scope within 2 h (precursor of B13).
- FP: maintenance. Use change windows.
- Src: Stratus azure.impact.resource-lock.

**az_ca_policy_change** · Azure · T1556.009 (Defense Impairment / Persistence) · 55–80
- Logic: `AZD AND au_name IN ('Delete conditional access policy','Update conditional access policy','Add conditional access policy','Delete named location','Update named location','Add named location', 'Update policy' /*legacy*/)`. Delete → 80. Update where `tr_json` shows `"state":"disabled"` or `enabledForReportingButNotEnforced`, or adds an exclusion (`excludeUsers|excludeGroups|excludeApplications` newValue longer than oldValue) → 75. Named location marked trusted → 70. Others → 45. Actor not in `cfg.ca_admins` → +10 (Sigma "non-approved actor" idea).
- FP: CA admins tuning policies. `cfg.ca_admins` keeps them at base severity.
- Src: Sigma 26e7c5e2, 50a3c7aa, 0922467f · Sentinel "Conditional Access - …" series (8 rules, MIT) · Elastic persistence_entra_id_conditional_access_policy_modified.

**az_mfa_disabled** · Azure · T1556.006 (Defense Impairment / Persistence) · 70
- Logic: `AZD AND (au_name IN ('Disable Strong Authentication','Delete authentication method','Admin deleted security info','User deleted security info') OR (au_name='Update user' AND tr_json ILIKE '%StrongAuthenticationRequirement%' AND regexp_matches(tr_json, 'State\\?"\s*:\s*0')) OR (au_name='Update User Risk and MFA Registration Policy') OR (au_name='Authentication Methods Policy Update' AND tr_json ILIKE '%"state":"disabled"%'))`. Target is privileged → 80.
- FP: helpdesk resets after a lost phone. `cfg.helpdesk_principals` → 45.
- Src: Sigma 7ea78478, b18454c8, d4c7758e, 4d78a000 · Splunk azure_ad_multi_factor_authentication_disabled · Elastic persistence_entra_id_mfa_disabled_for_user.

**az_federation_change** · Azure · T1484.002 (Privilege Escalation / Defense Impairment) · 85
- Logic: `AZD AND (au_name IN ('Set federation settings on domain','Set domain authentication','Add unverified domain','Verify domain','Add partner to cross-tenant access setting','Update a partner cross-tenant access setting','Update user' /*only when ImmutableId changes*/) )`. Gates: `Set domain authentication` only if `tr_json ILIKE '%Federated%'`. `Verify domain` → 55 unless followed by a federation change within 24 h (→ 90). `Update user` only if `tr_json ILIKE '%ImmutableId%'` (Splunk azure_ad_user_immutableid_attribute_updated).
- FP: planned ADFS/PingFederate rollout. Use a change window.
- Src: Sentinel ADFSDomainTrustMods, Cross-tenantAccessSettings* (MIT) · Sigma 352a54e1 · Splunk azure_ad_new_federated_domain_added, azure_ad_new_custom_domain_added · Elastic privilege_escalation_entra_id_tenant_domain_federation_via_audit_logs, resource_development_entra_id_custom_domain_added_and_verified.

**gcp_logging_tamper** · GCP · T1685.002 (Defense Impairment) · 70–90
- Logic: (a) Sinks: `GCP AND api ILIKE '%ConfigServiceV2.DeleteSink'` → 85. `api ILIKE '%ConfigServiceV2.UpdateSink' AND (g_req ILIKE '%"disabled":true%' OR J('$.protoPayload.request.updateMask') ILIKE '%filter%')` → 80. `api ILIKE '%ConfigServiceV2.CreateExclusion' OR api ILIKE '%ConfigServiceV2.UpdateExclusion'` → 75 (an exclusion drops logs). `api ILIKE '%ConfigServiceV2.DeleteBucket' OR (api ILIKE '%ConfigServiceV2.UpdateBucket' AND TRY_CAST(J('$.protoPayload.request.bucket.retentionDays') AS INT) < cfg.short_retention_days)` → 80. (b) Audit config removal: `api ILIKE '%SetIamPolicy' AND g_audit_delta ILIKE '%"action":"REMOVE"%'` → 90. (c) Sink bucket lifecycle: `api='storage.buckets.update' AND g_req ILIKE '%lifecycle%' AND TRY_CAST(regexp_extract(g_req, '"age"\s*:\s*(\d+)', 1) AS INT) <= cfg.short_retention_days AND bucket IN <sink destinations seen in CreateSink/UpdateSink>` → 80. (d) Network logs: `api='dns.policies.delete' OR (api IN ('dns.policies.patch','dns.policies.update') AND g_req ILIKE '%"enableLogging":false%') OR (api ILIKE 'v%.compute.subnetworks.patch' AND g_req ILIKE '%"enable":false%' AND g_req ILIKE '%logConfig%')` → 75.
- FP: log-routing redesign. `cfg.iac_principals`.
- Src: Stratus gcp.defense-evasion.* (6 techniques) · Elastic defense_evasion_gcp_logging_sink_deletion, gcp_logging_bucket_deletion, exfiltration_gcp_logging_sink_modification.

### 4.7 Credential Access (TA0006)

**cl_secrets_mass_read** · AWS, Azure(*), GCP · T1555.006 (Credential Access) · 75 / 85
- Logic: per actor, count distinct secrets in `cfg.secrets_window_ms` (10 min). (a) AWS: `CT AND ((svc='secretsmanager.amazonaws.com' AND api IN ('GetSecretValue','BatchGetSecretValue')) OR (svc='ssm.amazonaws.com' AND api IN ('GetParameter','GetParameters','GetParametersByPath') AND J('$.requestParameters.withDecryption')='true'))`. The key is `coalesce(J('$.requestParameters.secretId'), J('$.requestParameters.name'), J('$.requestParameters.path'))`. Any `BatchGetSecretValue` → counts as `json_array_length(secretIdList)` or as many if `filters` is used. Distinct ≥ `cfg.secrets_min_distinct` (10, Elastic uses 20) → 75. Also from more than 1 region (Panther multiregion) → 85. Denied attempts on ≥ 5 secrets → 65. (b) Azure: needs Key Vault data-plane logs `[az-res]`: `SecretGet/KeyGet/CertificateGet` (Elastic key_vault_excessive_retrieval). The management-plane proxy is `MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE` adding the caller itself → 70. (c) GCP: `GCP AND api ILIKE '%SecretManagerService.AccessSecretVersion'`. Distinct `regexp_extract(g_res, 'secrets/([^/]+)', 1)` ≥ 10 → 75 `[gcp-da]`.
- FP: apps loading config at boot (`ct_svc`, Lambda/ECS role sessions). Exclude `ct_svc` and `ct_ua ILIKE ANY cfg.secret_reader_uas` (browsers, per Elastic). Raise the threshold for principals whose p95 baseline is higher (B-style baseline `max(10, 3 × p95)`).
- Src: Stratus aws.credential-access.secretsmanager-*, ssm-retrieve-securestring-parameters, gcp.credential-access.secretmanager-retrieve-secrets · Elastic rapid_secret_retrieval_attempts_from_secretsmanager (threshold idea), key_vault_excessive_retrieval · Panther aws_secretsmanager_retrieve_secrets(_batch, _multiregion) · Splunk aws_anomalous_secrets_manager_batch_retrieval.

**aws_ec2_password_data** · AWS · T1552 (Credential Access) · 55 / 75
- Logic: `CT AND api='GetPasswordData'`, any outcome. Distinct instances (`J('$.requestParameters.instanceId')`) ≥ 3 in 1 h, or ≥ 3 failures → 75. First-seen actor (B1) → 65.
- FP: Windows admins after launch. One call by a known admin → 35.
- Src: Splunk aws_credential_access_getpassworddata · Panther aws_ec2_many_passwors_read_attempts · Elastic credential_access_aws_getpassword_for_ec2_instance · Stratus.

**az_mfa_fatigue** · Azure · T1621 (Credential Access) · 70 / 85
- Logic: per user in `cfg.mfa_window_ms` (10 min): count of `AZS AND (si_code IN ('500121','50074','50076') OR si_authdet ILIKE '%MFA denied%' OR si_authdet ILIKE '%user declined%' OR si_authdet ILIKE '%fraud%')` ≥ `cfg.mfa_min_prompts` (5) → 70. Followed by `si_code='0'` within 30 min → 85, plus secondary T1078.004 (Initial Access). "Fraud reported" (`si_authdet ILIKE '%fraud%'` or code 500121 with 'Fraud' text) → 85 alone.
- FP: users with broken authenticator apps (one source IP, own country). Lower to 45 when every prompt comes from the user's baseline ASN.
- Src: Sentinel MFASpammingfollowedbySuccessfullogin, MFARejectedbyUser, MFAPromptBurstFromSingleIP (MIT) · Splunk azure_ad_multiple_denied_mfa_requests_for_user, azure_ad_multiple_failed_mfa_requests_for_user · Sigma e40f4962, 5496ff55 (context).

**az_key_listing** · Azure · T1552 (Credential Access) · 45–80
- Logic: `AZA AND api_u IN ('MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION','MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION','MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTACCOUNTSAS/ACTION','MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTSERVICESAS/ACTION','MICROSOFT.WEB/SITES/PUBLISHXML/ACTION','MICROSOFT.WEB/SITES/CONFIG/LIST/ACTION','MICROSOFT.COGNITIVESERVICES/ACCOUNTS/LISTKEYS/ACTION','MICROSOFT.DOCUMENTDB/DATABASEACCOUNTS/LISTKEYS/ACTION','MICROSOFT.DOCUMENTDB/DATABASEACCOUNTS/LISTCONNECTIONSTRINGS/ACTION','MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/LISTCLUSTERADMINCREDENTIAL/ACTION','MICROSOFT.CONTAINERREGISTRY/REGISTRIES/LISTCREDENTIALS/ACTION','MICROSOFT.COMPUTE/VIRTUALMACHINES/RETRIEVEBOOTDIAGNOSTICSDATA/ACTION','MICROSOFT.HYBRIDCOMPUTE/MACHINES/EXTENSIONS/WRITE')`. Severity: `az_human` and first-seen `(az_caller, api_u)` (B1) → 70. ≥ 5 distinct resources in 1 h → 80 (Sentinel RareOperations: ≥ 5 per IP/caller). Service principal routine → 35. Sequence: `MICROSOFT.COGNITIVESERVICES/ACCOUNTS/WRITE` with `az_req ILIKE '%"disableLocalAuth":false%'` then `LISTKEYS` within 1 h → 85 (Stratus Foundry).
- FP: the portal lists keys when a human opens the "Access keys" blade. Hence first-seen or burst is required for ≥ 70.
- Src: Stratus azure.exfiltration.storage-sas-export, azure.credential-access.app-service-publishing-credentials, azure.persistence.exfiltrate-foundry-key · Sentinel RareOperations (MIT) · Elastic credential_access_azure_storage_account_keys_accessed, storage_account_key_regenerated, vm_boot_diagnostics_retrieved_unusual_principal · Sigma c1182e02 (keywords, context).

**cl_instance_metadata_read** · AWS, GCP · T1552.005 (Credential Access) / T1580 · 55 / 70
- Logic: (a) AWS: `CT AND api='DescribeInstanceAttribute' AND J('$.requestParameters.attribute')='userData'`. Distinct instances ≥ 5 per actor in 1 h, or first-seen actor → 70. (b) GCP: `GCP AND api IN ('v1.compute.instances.get','beta.compute.instances.get','v1.compute.projects.get')` by an actor that never did compute admin writes in the baseline (no `v1.compute.instances.(insert|delete|setMetadata|start|stop)`), ≥ 5 instances in 1 h → 65 `[gcp-da]`.
- FP: inventory tools (`cfg.inventory_principals`).
- Src: Stratus aws.discovery.ec2-download-user-data, gcp.discovery.download-instance-metadata · Elastic discovery_ec2_userdata_request_for_ec2_instance · Panther aws_ec2_download_instance_user_data.

**cl_traffic_mirroring** · AWS, Azure, GCP · T1040 Network Sniffing (Credential Access) · 70
- Logic: (a) `CT AND api IN ('CreateTrafficMirrorSession','CreateTrafficMirrorTarget','CreateTrafficMirrorFilter')`. (b) `AZA AND api_u IN ('MICROSOFT.NETWORK/NETWORKWATCHERS/PACKETCAPTURES/WRITE','MICROSOFT.NETWORK/NETWORKINTERFACES/TAPCONFIGURATIONS/WRITE','MICROSOFT.NETWORK/VIRTUALNETWORKTAPS/WRITE')`. (c) `GCP AND regexp_matches(api, '(?i)v\d+\.compute\.packetMirrorings\.(insert|patch)')`.
- FP: NDR/IDS deployments. `cfg.nsm_principals`.
- Src: Panther aws_ec2_traffic_mirroring · Elastic exfiltration_ec2_full_network_packet_capture_detected, credential_access_network_full_network_packet_capture_detected · Sigma 980a7598 (includes Get/List; context).

### 4.8 Discovery (TA0007)

**aws_ses_recon** · AWS · T1526 (Discovery) · 55
- Logic: `CT AND svc IN ('ses.amazonaws.com','sesv2.amazonaws.com' /*eventSource is email.amazonaws.com for v2*/,'email.amazonaws.com') AND api IN ('GetAccountSendingEnabled','GetSendQuota','ListIdentities','GetIdentityVerificationAttributes','ListEmailIdentities','GetAccount','ListVerifiedEmailAddresses')`. ≥ 3 distinct APIs per actor in 10 min, and the actor did not use SES in the baseline → 55. With `ct_akid LIKE 'AKIA%'` and a first-seen ASN → 70. This is the usual precursor of spam abuse (aws_service_hijack).
- FP: mail ops teams. `cfg.ses_admins`.
- Src: Stratus aws.discovery.ses-enumerate · Panther aws_cloudtrail_ses_check_* · Elastic discovery_ses_enumeration_via_long_term_access_key.

**gcp_testiam_burst** · GCP · T1069.003 (Discovery) · 55 / 70
- Logic: `GCP AND api ILIKE '%testIamPermissions'`. ≥ `cfg.testiam_min` (5) calls or ≥ 3 distinct resources per actor in 10 min → 55. Requested permission count (`json_array_length(J('$.protoPayload.request.permissions'))`) ≥ 50 in one call → 70 (permission brute-force tools).
- FP: the Cloud Console calls testIamPermissions on page load. Exclude `g_ua ILIKE '%Mozilla%'` (→ 30).
- Src: Stratus gcp.discovery.enumerate-permissions `[gcp-da]`.

**aws_iam_policy_bruteforce** · AWS · T1069.003 (Discovery) · 60
- Logic: `CT AND ct_err='MalformedPolicyDocumentException'`, ≥ 2 per actor in 1 h (Splunk threshold). Also `api='UpdateAssumeRolePolicy'` failures on ≥ 5 distinct principal ARNs (role-trust principal enumeration, Elastic) → 65.
- FP: developers editing policies. Mostly by console UA → 35.
- Src: Splunk aws_iam_assume_role_policy_brute_force (Apache-2.0) · Elastic discovery_iam_principal_enumeration_via_update_assume_role_policy.

### 4.9 Lateral Movement (TA0008)

**aws_remote_access_multi** · AWS · T1021.008 (Lateral Movement) · 55 / 75
- Logic: `CT AND ((svc='ec2-instance-connect.amazonaws.com' AND api IN ('SendSSHPublicKey','SendSerialConsoleSSHPublicKey')) OR (svc='ssm.amazonaws.com' AND api IN ('StartSession','ResumeSession')) OR (svc='ec2.amazonaws.com' AND api IN ('EnableSerialConsoleAccess','GetSerialConsoleAccessStatus')))`. Target is `coalesce(J('$.requestParameters.instanceId'), J('$.requestParameters.target'))`. ≥ `cfg.remote_min_targets` (3) distinct targets per actor in 10 min → 75. `EnableSerialConsoleAccess` → 70. A single session by a first-seen actor → 60.
- FP: ops engineers. Single sessions by known users → 35.
- Src: Stratus aws.lateral-movement.ec2-instance-connect, ec2-serial-console-send-ssh-public-key, aws.execution.ssm-start-session · Elastic lateral_movement_ec2_instance_connect_ssh_public_key_uploaded, defense_evasion_ec2_serial_console_access_enabled · Splunk aws_ec2_multiple_ssh_public_keys_uploaded_by_a_single_identity · Panther aws_ec2_multi_instance_connect.

**az_remote_access** · Azure · T1021.008 (Lateral Movement) · 65 / 75
- Logic: `AZA AND api_u IN ('MICROSOFT.NETWORK/BASTIONHOSTS/CREATESHAREABLELINKS/ACTION','MICROSOFT.NETWORK/BASTIONHOSTS/GETSHAREABLELINKS/ACTION','MICROSOFT.SERIALCONSOLE/SERIALPORTS/CONNECT/ACTION','MICROSOFT.COMPUTE/VIRTUALMACHINES/LOGIN/ACTION' /*rare in ARM*/)`. Shareable link creation → 75 (persistence too: a link works without Azure credentials). Serial console → 65.
- FP: support engineers. `cfg.vm_ops_principals`.
- Src: Stratus azure.persistence.create-bastion-shareable-link · Elastic lateral_movement_azure_vm_serial_console_connect.

**aws_console_from_keys** · AWS · T1550.001 (Lateral Movement) · 60
- Logic: `CT AND svc='signin.amazonaws.com' AND api='GetSigninToken' AND coalesce(ct_ua,'') NOT ILIKE '%Jersey/${project.version}%'` (an SSO portal UA is benign), or `ConsoleLogin` with `ct_type='FederatedUser'` within 1 h of `GetFederationToken` by an IAM user key. Keys are turned into a console session (aws_consoler / Pacu).
- FP: AWS SSO portal (filtered by UA). Tools like `granted`/`aws-vault login` → `cfg.console_broker_uas`.
- Src: Sigma f8103686 (DRL) · Elastic credential_access_get_federation_token_followed_by_console_login_via_federation_exchange (idea).

### 4.10 Exfiltration (TA0010)

**cl_snapshot_image_share_external** · AWS, GCP · T1537 (Exfiltration) · 85; public 90
- Logic: `own := [host] + cfg.trusted_aws_accounts`. (a) AWS EBS/AMI: `CT AND ((api='ModifySnapshotAttribute' AND ct_rp ILIKE '%createVolumePermission%' AND ct_rp ILIKE '%"add"%') OR (api='ModifyImageAttribute' AND ct_rp ILIKE '%launchPermission%' AND ct_rp ILIKE '%"add"%'))`. Accounts are `regexp_extract_all(J('$.requestParameters.createVolumePermission.add'), '"userId"\s*:\s*"(\d{12})"', 1)` (same for launchPermission). Fire if any account is not in `own` (85), or `"group":"all"` (90). (b) RDS: `api IN ('ModifyDBSnapshotAttribute','ModifyDBClusterSnapshotAttribute') AND J('$.requestParameters.attributeName')='restore'`, with `valuesToAdd` containing an account not in `own` or `all`. (c) RAM: `svc='ram.amazonaws.com' AND api IN ('CreateResourceShare','AssociateResourceShare')`, principals (`regexp_extract_all(ct_rp, '(\d{12})', 1)`) not in own/org, and `allowExternalPrincipals=true`; `ec2 CopyVolumes`/`CreateVolume` from a shared volume → 85 (Stratus ec2-share-ebs-volume). (d) GCP: `GCP AND regexp_matches(api, '(?i)v\d+\.compute\.(disks|images|snapshots|machineImages)\.setIamPolicy')`, member (`regexp_extract_all(g_req, '"(user|serviceAccount|group|domain):([^"]+)"', 2)`) domain not in `cfg.trusted_domains`, or `allUsers`/`allAuthenticatedUsers` (90).
- FP: DR copies to a backup account. Add it to `cfg.trusted_aws_accounts` / domains.
- Src: Stratus 7 techniques (ec2-share-ami, -ebs-snapshot, -ebs-volume, rds-share-snapshot, gcp share-compute-*) · Sigma abae8fec (context: any ModifySnapshotAttribute) · Elastic exfiltration_ec2_ami_shared_with_separate_account, ec2_ebs_snapshot_shared_with_another_account, rds_snapshot_shared_with_another_account · Splunk aws_ec2_snapshot_shared_externally, aws_ami_attribute_modification_for_exfiltration · Panther aws_snapshot_made_public, aws_ami_modified_for_public_access.

**cl_storage_public_or_external** · AWS, Azure, GCP · T1537 (Exfiltration) / T1530 · 75–85
- Logic: (a) S3 policy: `CT AND api='PutBucketPolicy' AND (regexp_matches(ct_rp, '"Principal"\s*:\s*("\*"|\{\s*"AWS"\s*:\s*"\*")') OR any regexp_extract_all(ct_rp, 'arn:aws:iam::(\d{12}):', 1) NOT IN own) AND ct_rp NOT ILIKE '%cloudfront%'` (Elastic's exclusions) → 85 external / 85 public. (b) ACL and Block Public Access: `api IN ('PutBucketAcl','PutObjectAcl') AND ct_rp ILIKE ANY ('%AllUsers%','%AuthenticatedUsers%','%"x-amz-acl":["public-read%')` → 80. `api='DeletePublicAccessBlock' OR (api='PutBucketPublicAccessBlock' AND ct_rp ILIKE '%":false%')` → 70 (Sigma ab18a523). `svc='s3.amazonaws.com' AND api='PutBucketReplication'` with a destination bucket ARN in an account not in own (`"Account":"\d{12}"` or a different `"Bucket":"arn:aws:s3:::"` owner) → 85. (c) Other AWS public grants → 75: `ecr SetRepositoryPolicy`, `lambda AddLayerVersionPermission` with principal `*`, `sns/sqs SetTopicAttributes/SetQueueAttributes` with Principal `*`, `kms PutKeyPolicy` with Principal `*`. (d) Azure: `AZA AND ((api_u='MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE' AND az_req ILIKE '%"allowBlobPublicAccess":true%') OR (api_u='MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE' AND regexp_matches(az_req, '"publicAccess"\s*:\s*"(Container|Blob)"')) OR (api_u='MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE' AND az_req ILIKE '%"defaultAction":"Allow"%'))` → 75. (e) GCS: `GCP AND api='storage.setIamPermissions' AND g_delta ILIKE ANY ('%allUsers%','%allAuthenticatedUsers%')` → 85; external domain member → 80.
- FP: static website buckets. `cfg.public_bucket_allow`.
- Src: Stratus aws.exfiltration.s3-backdoor-bucket-policy, azure.exfiltration.storage-public-access · Elastic exfiltration_s3_bucket_policy_added_for_{external_account,public}_access, s3_bucket_replicated_to_external_account, ecr_repository_policy_granted_public_access, lambda_layer_shared_externally · Splunk detect_new_open_s3_buckets, detect_new_open_gcp_storage_buckets, aws_exfiltration_via_bucket_replication · Panther aws_resource_made_public, aws_s3_delete_public_access_block · Sigma ab18a523.

**aws_data_export_task** · AWS · T1537 (Exfiltration) · 70 / 85
- Logic: `CT AND api IN ('CreateInstanceExportTask','ExportImage','StartExportTask' /*rds*/,'ExportTableToPointInTime' /*dynamodb*/,'CreateTask' /*datasync*/,'StartReplicationTask','SubmitJob' /*batch with exfil container*/)`. 85 when the destination bucket's owner account (`requestParameters.s3BucketOwner`, `ExportBucketOwner`) is not own, or the destination bucket was never seen in the account. Failures → 45 (Sigma 54b9a76a).
- FP: analytics exports. `cfg.export_allow_buckets`.
- Src: Elastic exfiltration_ec2_export_task, rds_snapshot_export, dynamodb_table_exported_to_s3 · Splunk aws_exfiltration_via_datasync_task, aws_exfiltration_via_batch_service, aws_exfiltration_via_ec2_snapshot · Panther aws_rds_snapshot_export · Sigma 54b9a76a.

**az_disk_sas_export** · Azure · T1537 (Exfiltration) · 70 / 85
- Logic: `AZA AND api_u IN ('MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION','MICROSOFT.COMPUTE/SNAPSHOTS/BEGINGETACCESS/ACTION')`. 85 if `MICROSOFT.COMPUTE/SNAPSHOTS/WRITE` happened for the same disk within the previous 2 h (snapshot then export), or the caller is first-seen for the op (B1). Export with `az_req ILIKE '%"durationInSeconds":%'` > 86400 → +10.
- FP: backup tools (Veeam, Commvault service principals). `cfg.backup_principals`.
- Src: Stratus azure.exfiltration.disk-export · Sentinel RareOperations (snapshots/write).

### 4.11 Impact (TA0040)

**cl_kms_key_destroy** · AWS, Azure, GCP · T1485 / T1486 (Impact) · 75 / 90
- Logic: (a) AWS: `CT AND svc='kms.amazonaws.com' AND api IN ('ScheduleKeyDeletion','DisableKey','DeleteImportedKeyMaterial','ImportKeyMaterial','PutKeyPolicy','CancelKeyDeletion' /*context*/)`. `PutKeyPolicy` only when the new policy lacks `arn:aws:iam::<host>:root` (account lock-out) → 85. `ImportKeyMaterial` → 75 (Sigma 1279262f: BYOK attacker key). (b) Azure: `AZA AND api_u IN ('MICROSOFT.KEYVAULT/VAULTS/DELETE','MICROSOFT.KEYVAULT/VAULTS/KEYS/DELETE' /*rarely ARM*/,'MICROSOFT.KEYVAULT/LOCATIONS/DELETEDVAULTS/PURGE/ACTION')` → 75; `PURGE` → 90. (c) GCP: `GCP AND api ILIKE '%KeyManagementService.DestroyCryptoKeyVersion'` or `UpdateCryptoKeyVersion` with state DISABLED → 80. Any ≥ 3 keys in 1 h → 90.
- FP: key rotation retirements. `cfg.kms_admins` → 45.
- Src: Elastic impact_kms_cmk_disabled_or_scheduled_for_deletion, impact_kms_imported_key_material_deleted, privilege_escalation_kms_key_policy_put · Panther aws_kms_cmk_loss · Sigma 1279262f · Stratus azure blob-ransomware-service-storage-cmk.

**cl_storage_ransom_encrypt** · AWS, Azure, GCP · T1486 (Impact) · 80 / 90
- Logic: (a) S3 `[ct-data]`: `CT AND api IN ('PutObject','CopyObject','UploadPart','CreateMultipartUpload') AND (ct_rp ILIKE '%x-amz-server-side-encryption-customer-algorithm%' OR (ct_rp ILIKE '%aws:kms%' AND regexp_extract(J('$.requestParameters.x-amz-server-side-encryption-aws-kms-key-id'), 'arn:aws:kms:[^:]+:(\d{12}):', 1) NOT IN own))`. ≥ `cfg.ransom_min_objects` (20, Elastic threshold) per actor per bucket in 10 min → 90; 1–19 → 60. Also `api='PutBucketEncryption'` with a key from an account not in own → 85. Also a ransom note: `api='PutObject' AND regexp_matches(lower(J('$.requestParameters.key')), cfg.ransom_note_regex /* readme|recover|decrypt|ransom|restore.*files|how_to */)` after deletes → 85. (b) GCS `[gcp-da]`: `GCP AND api='storage.objects.create' AND J('$.protoPayload.authorizationInfo') ILIKE '%storage.objects.delete%'` (rewrite in place, Stratus) ≥ 20 per actor in 10 min → 90. (c) Azure CMK/scope: `api_u='MICROSOFT.STORAGE/STORAGEACCOUNTS/ENCRYPTIONSCOPES/WRITE'` or `api_u='MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE' AND az_req ILIKE '%"keySource":"Microsoft.Keyvault"%'`, followed within 2 h by Key Vault delete or purge (cl_kms_key_destroy b) by the same caller → 90. Alone → 55.
- FP: SSE-C is rare in practice. Allowlist apps that use it (`cfg.ssec_allow_principals`).
- Src: Stratus aws.impact.s3-ransomware-client-side-encryption, gcp.impact.gcs-ransomware-client-side-encryption, azure.impact.blob-ransomware-client-encryption-scope / service-storage-cmk · Elastic impact_s3_excessive_object_encryption_with_sse_c, impact_s3_object_encryption_with_external_key, impact_s3_bucket_object_uploaded_with_ransom_keyword · Panther aws_s3_copy_object_with_client_side_encryption, aws_s3_copy_object_cross_account_kms, aws_s3_ransomware_note_upload · Splunk aws_detect_users_with_kms_keys_performing_encryption_s3.

**cl_backup_destruction** · AWS, Azure, GCP · T1490 (Impact) · 40 single / 85 burst
- Logic: `bk` events: AWS `api IN ('DeleteSnapshot','DeleteDBSnapshot','DeleteDBClusterSnapshot','DeleteRecoveryPoint','DeleteBackupVault','DeleteBackupVaultLockConfiguration','DeleteBackupPlan','DeregisterImage','DeleteDBInstanceAutomatedBackup','ModifyDBInstance' /*only BackupRetentionPeriod=0 or DeletionProtection=false*/,'PutBucketVersioning' /*only Status Suspended or MFADelete Disabled*/,'DeleteBucketReplication')`. Azure `api_u IN ('MICROSOFT.COMPUTE/SNAPSHOTS/DELETE','MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/DELETE','MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/RESTOREPOINTS/DELETE','MICROSOFT.RECOVERYSERVICES/VAULTS/DELETE','MICROSOFT.RECOVERYSERVICES/VAULTS/BACKUPFABRICS/PROTECTIONCONTAINERS/PROTECTEDITEMS/DELETE','MICROSOFT.DATAPROTECTION/BACKUPVAULTS/DELETE')` or `RECOVERYSERVICES/VAULTS/BACKUPCONFIG/WRITE` with soft delete disabled. GCP `regexp_matches(api, '(?i)v\d+\.compute\.snapshots\.delete|cloudsql\.backupRuns\.delete|BackupDR.*Delete')`. Single → 40 (context). ≥ `cfg.backup_burst_min` (5) distinct resources by one actor in 1 h → 85.
- FP: retention clean-up jobs (`cfg.backup_principals`, always service principals; a human doing a burst is the signal).
- Src: Stratus aws.impact.ec2-deregister-ami · Sigma a136ac98, 16124c2d (encryption off by default) · Elastic impact_backup_vault_deleted_or_lock_removed, impact_backup_recovery_point_deleted, impact_rds_snapshot_deleted, impact_s3_object_versioning_disabled, impact_s3_mfa_delete_disabled, impact_rds_instance_cluster_deletion_protection_disabled, impact_azure_compute_vm_snapshot_deletions, impact_azure_compute_restore_point_collections_deleted · Panther aws_rds_automated_backup_deleted.

**cl_compute_hijack** · AWS, Azure, GCP · T1496.001 (Impact) · 60–85
- Logic: (a) AWS: `CT AND api='RunInstances' AND (regexp_matches(lower(J('$.requestParameters.instanceType')), cfg.aws_gpu_regex /* ^(p\d|g\d|gr6|trn\d|inf\d|dl\d|x\d|u-|.*\.metal|.*\.(16|18|24|32|48)xlarge) */) OR TRY_CAST(J('$.requestParameters.instancesSet.items[0].maxCount') AS INT) >= cfg.mass_launch_min (10))`. Any outcome: `ct_err IN ('VcpuLimitExceeded','Client.UnauthorizedOperation','InsufficientInstanceCapacity')` on such types → 60 (probing). Success → 75. ≥ 3 regions in 1 h → 85. Also `servicequotas RequestServiceQuotaIncrease` by a first-seen actor → 55, and `ecs RegisterTaskDefinition` with `ct_rp` matching `xmrig|minerd|cpuminer|nicehash|stratum\+tcp` → 85. (b) Azure: `AZA AND api_u IN ('MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE','MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE','MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/WRITE') AND regexp_matches(lower(az_req), '"vmsize"\s*:\s*"[^"]*(nc|nd|nv|hb|hc|_m\d{3}|416|208|192|128|120|96|80|72|64|48|44|40)')` (Sentinel token list) → 70. ≥ 10 VMs per caller per day → 85. (c) GCP: `GCP AND api IN ('v1.compute.instances.insert','beta.compute.instances.insert')`. `g_req ILIKE '%guestAccelerators%'` or `machineType` matches `(a2|a3|g2|n1-.*-(highcpu|highmem)-(64|96))` → 75. ≥ `cfg.multizone_min` (5) distinct `g_zone` per actor in 5 min, excluding `g_ua ILIKE '%GCE Managed Instance Group%'` → 85.
- FP: ML teams. `cfg.ml_principals` and per-account allowed families.
- Src: Stratus aws.execution.ec2-launch-unusual-instances, gcp.impact.create-gpu-vm, create-instances-in-multiple-zones · Sentinel Creation_of_Expensive_Computes_in_Azure (MIT) · Splunk cloud_compute_instance_created_with_previously_unseen_instance_type · Elastic impact_ecs_cryptomining_task_definition_deployment, resource_development_service_quota_increase_by_rare_identity · Panther aws_ec2_launch_unusual_ec2_instances.

**aws_service_hijack** · AWS · T1496.004 (Impact) · 60–80
- Logic: (a) LLMjacking: `CT AND svc='bedrock.amazonaws.com' AND api IN ('InvokeModel','InvokeModelWithResponseStream','Converse','ConverseStream','PutUseCaseForModelAccess','CreateFoundationModelAgreement','PutFoundationModelEntitlement','GetFoundationModelAvailability','ListFoundationModelAgreementOffers')`. Agreement or use-case APIs by any actor → 70. Invoke by a first-seen actor (B1) or from a first-seen ASN (B2) → 75. ≥ 10 `AccessDenied`/`ValidationException` on Invoke or List across models in 10 min → 70 (Splunk). Followed by `DeleteModelInvocationLoggingConfiguration` → 85. (b) SES spam: `CT AND api IN ('UpdateAccountSendingEnabled','PutAccountSendingAttributes','VerifyEmailIdentity','VerifyDomainIdentity','CreateEmailIdentity','PutAccountDetails' /*production access request*/)` by a first-seen actor → 65. With aws_ses_recon by the same actor in 24 h → 80. Identity verified then deleted (Sigma 20f754db, `DeleteIdentity`) within 24 h → 75.
- FP: AI teams. `cfg.genai_principals`. Bedrock Invoke may be a data event in some regions. Verify on the demo trail.
- Src: Stratus aws.impact.bedrock-invoke-model · Splunk aws_bedrock_high_number_list_foundation_model_failures, aws_bedrock_invoke_model_access_denied · Elastic resource_development_ses_account_sending_enabled, resource_development_ses_identity_verified_then_deleted · Sigma 20f754db.

**cl_access_removal** · AWS, Azure, GCP · T1531 (Impact) · 45 / 80
- Logic: actions against *other* principals. AWS `api IN ('DeleteLoginProfile','DeleteAccessKey','DeactivateMFADevice','DeleteVirtualMFADevice','DetachUserPolicy','RemoveUserFromGroup','UpdateAccountPasswordPolicy','DeleteAccountPasswordPolicy')` with `requestParameters.userName <> actor`. Azure AuditLogs `au_name IN ('Delete user','Disable account','Reset user password','Remove member from role','Revoke sign-in sessions' /*Invalidate*/)`. GCP `regexp_matches(api, '(?i)serviceAccounts\.(disable|delete)$|DisableServiceAccount|DeleteServiceAccount')` and SetIamPolicy REMOVE of owner bindings. Single → 45. ≥ `cfg.removal_burst_min` (5) distinct targets by one actor in 30 min → 80. Removal of all other owners / Global Admins → 90.
- FP: off-boarding (HR-driven, by IAM automation). `cfg.iam_admin_principals` → 35.
- Src: Elastic impact_iam_deactivate_mfa_device, impact_iam_group_deletion, impact_gcp_service_account_disabled, impact_gcp_service_account_deleted · Splunk aws_iam_delete_policy, asl_aws_multi_factor_authentication_disabled · Sentinel MultipleAdmin_membership_removals_from_NewAdmin, BulkChangestoPrivilegedAccountPermissions · Sigma 13f81a90, 102e11e3.

---

## 5. Behavioural / anomaly rules for novel attacks

These rules find attacks that match no signature: a new API, a new place, a new tool, a new sequence. They need
**new templates** in `detect_templates*.py`. Each one is one DuckDB query over `cloud_ev` (§2.2), so memory stays
bounded. Proposed generic templates:

| Template | Parameters (all from `config/cloud.yaml`) | Used by |
|---|---|---|
| `first_seen` | `key` (list of macro exprs), `filter`, `baseline_days`, `min_history_days`, `min_actor_events`, `gap_ms` | B1, B2, B3, B15, B16, many native "first-seen" boosts |
| `distinct_burst` | `key`, `filter`, `distinct` expr, `window_ms`, `min_distinct`, `min_count`, `baseline_mult`, `baseline_days` | B4, B13, B14, native burst branches |
| `rate_spike` | `key`, `num_filter`, `den_filter`, `window_ms`, `min_num`, `min_ratio`, `z` | B5, B18 |
| `sequence` | `a_filter`, `b_filter`, `join` (expr pairs), `window_ms`, `order` (a_before_b), `emit` (a, b or both) | B7–B11, B17, native sequences |
| `geo_velocity` | `key`, `max_kmh`, `min_km`, `ignore_same_asn`, `ignore_ranges` | B6 |
| `multi_network_session` | `session_key`, `network` (asn or /16), `window_ms`, `min_networks` | B12 |

**Baseline rules (for all baselines below).**
- Baseline = events of the same key in `[t − baseline_days, t − gap_ms)` inside the data set (batch). In live mode it
  also reads a persisted table `data/state/cloud_baseline.parquet` (key, first_ts, last_ts, n), updated after each
  cycle by DuckDB `COPY`. This fixes the 72 h live look-back being too short.
- **Cold start.** If the actor (or account) has less than `min_history_days` of history or fewer than
  `min_actor_events` events before t, the alert is emitted at **context severity (30)**. This stops "everything is
  new" on day 1 of a data set.
- Exclusions: `ct_svc`, Azure service-agent GUID callers, Google `*@gcp-sa-*` agents, and `cfg.iac_principals` are
  excluded from first-seen keys unless the rule says otherwise.

**B1 cl_first_seen_api** · AWS, Azure, GCP · T1078.004 (Initial Access/Stealth) as default label; the tactic is taken from the API's class when known · 40 / 60
- Key `(acct, actor, api)`. For CloudTrail use `coalesce(ct_iss, ct_arn)` as the actor when `ct_type='AssumedRole'`, so that sessions of one role share a baseline.
- Filter: writes only (`ct_write`, Azure `api_u LIKE '%/WRITE' OR '%/DELETE' OR '%/ACTION'`, AuditLogs all, GCP `g_log LIKE '%activity'`) plus `cfg.sensitive_read_apis` (GetSecretValue, GetPasswordData, ListKeys, AccessSecretVersion, GenerateAccessToken, GetObject on sensitive buckets).
- Thresholds: `baseline_days: 14`, `min_history_days: 3`, `min_actor_events: 50`. Severity 40, or 60 if `api IN cfg.sensitive_apis` (IAM/RBAC writes, key or secret reads, logging changes).
- Noise: max `cfg.first_seen_max_per_actor_day` (20) alerts per actor per day. More than that means a new job, so emit one summary alert at 35.
- Src: Splunk cloud_api_calls_from_previously_unseen_user_roles · Elastic ml_cloudtrail_rare_method_by_user, new_terms rules (10-day history idea).

**B2 cl_first_seen_geo** · AWS, Azure, GCP · T1078.004 (Initial Access) · 45 / 60 / 70
- Key `(actor, country)`, `(actor, asn)`, `(actor, ip_prefix)`. `country`/`asn` come from SigninLogs (`si_cc`, `si_asn`) or the `[geo]` lookup on `src_ip`. Without geo, use `ip_prefix` = /24 for IPv4 or /48 for IPv6.
- Filter: successful logins + successful writes.
- Baseline: `baseline_days: 30` for country and ASN, `14` for prefix; `min_history_days: 5`.
- Severity: new prefix 30 (context), new ASN 45, new country 60. New country **and** ASN is a hosting/VPN provider (`asn IN cfg.hosting_asns` or AS description matches `cfg.hosting_asn_regex`: `amazon|google|microsoft|digitalocean|ovh|hetzner|linode|vultr|choopa|m247|datacamp|leaseweb|contabo|tor|mullvad|nord|proton|expressvpn`) → 70.
- Privileged actors (in `cfg.privileged_principals` or seen doing IAM/RBAC writes) +10.
- Src: Splunk detect_aws_console_login_by_user_from_new_country/region/city, cloud_provisioning_activity_from_previously_unseen_country/ip_address · Sentinel AuthenticationAttemptfromNewCountry, PrivilegedUserLogonfromnewASN (14 d ASN baseline) · Elastic initial_access_aws_api_unusual_asn (hosting-ASN + sensitive API idea).

**B3 cl_rare_api_account** · AWS, Azure, GCP · T1078.004 / per-API class · 45
- Key `(acct, api)`. Fire when the API was called ≤ `cfg.rare_api_max_calls` (2) times by ≤ 1 distinct actor in `baseline_days: 30`, and it is a write or sensitive read. Different from B1: B1 is new for this actor, B3 is rare for the whole account.
- Thresholds: `min_account_history_days: 7`. Caps as in B1.
- Src: Sentinel RareOperations (MIT) · Elastic ml_*_rare_method_by_* (idea).

**B4 cl_discovery_burst** · AWS, Azure, GCP · T1580 / T1526 / T1087.004 / T1069.003 (Discovery) · 60 / 75
- Recon API set: `regexp_matches(api, '^(List|Describe|Get|Search|Lookup|BatchGet|Scan)')` for AWS (excluding `GetObject`, `GetSecretValue`, `GetParameter*` which have own rules); Azure `api_u LIKE '%/READ'` (rare in Activity Log) and Graph is out of scope; GCP `regexp_matches(api, '\.(list|get|aggregatedList|search|testIamPermissions|getIamPolicy)$')`.
- Key `(actor, session)` with `session := coalesce(ct_akid, si_sess, actor)`. Window `window_ms: 600000` (10 min).
- Fire when distinct APIs ≥ `min_distinct: 20` **and** distinct services ≥ `min_services: 4` **and** distinct APIs ≥ `baseline_mult: 3` × the actor's p95 distinct-APIs-per-10-min over `baseline_days: 14`.
- Severity 60. 75 if the session is an instance role (`ct_instance_role`, Stratus ec2-enumerate-from-instance), a long-term key from a new ASN, or `GetCallerIdentity` was the first call of the session.
- Exclude `ct_ua` matching `cfg.inventory_ua_regex` (prowler, scoutsuite, steampipe, cloudquery, cartography, aws-config, Wiz/Orca connectors) and `ct_svc`.
- Src: Elastic discovery_multiple_discovery_api_calls_via_cli (10-second windows, ESQL idea), discovery_s3_rapid_bucket_posture_api_calls · Stratus aws.discovery.ec2-enumerate-from-instance · Panther aws_cloudtrail_account_discovery.

**B5 cl_denied_spike** · AWS, Azure, GCP · T1580 (Discovery); escalates to T1098 (Privilege Escalation) for IAM probing · 60 / 70
- `denied` macro (§2.2). Key `(actor, coalesce(src_ip, ct_ip))`. Window `3600000` (1 h).
- Fire when denied ≥ `min_num: 10` **and** distinct denied APIs ≥ `min_distinct: 5` **and** `denied / all calls ≥ min_ratio: 0.3` **and** count > baseline mean + `z: 3` × σ of the actor's hourly denied counts over `baseline_days: 14` (σ floor 1).
- 70 + label T1098 (Privilege Escalation) when ≥ 3 denied APIs are IAM, STS or RBAC writes (`svc IN ('iam.amazonaws.com','sts.amazonaws.com')`, `api_u LIKE 'MICROSOFT.AUTHORIZATION/%'`, `api ILIKE '%SetIamPolicy'`).
- Exclude `ct_type='AWSService'` and console read-only noise (`ct_ua ILIKE '%console.amazonaws.com%'` with only Describe/List denials → 30).
- Src: Splunk aws_iam_accessdenied_discovery_events (≥ 5 failures/h per src+user) · Panther aws_iam_user_recon_denied · Elastic ml_cloudtrail_error_message_spike, ml_cloudtrail_rare_error_code (idea).

**B6 cl_impossible_travel** · AWS, Azure, GCP · T1078.004 (Initial Access) · 65
- Consecutive successful auth or API events per actor (order by ts). Location: `(si_lat, si_lon)` from SigninLogs, or the `[geo]` country/city centroid for others.
- Fire when `distance_km ≥ min_km: 500` and `distance_km / max(Δt_h, 1/60) > max_kmh: 900`.
- Ignore when both IPs are in the same ASN, either IP is in `cfg.corp_egress_cidrs`, `cfg.vpn_asns` or cloud provider ranges (`[ranges]`), or a previous travel between the same two countries was seen for the actor in the baseline (`baseline_days: 30`).
- 80 when the second location also triggers B2 (new country) and a write follows within 1 h.
- Src: Elastic initial_access_entra_id_signin_impossible_travel (idea) · Splunk aws_successful_console_authentication_from_multiple_ips · Sigma b2572bf9 (Identity Protection; not ingested).

**B7 cl_new_principal_privileged** · AWS, Azure, GCP · T1136.003 (Persistence) + T1098.003 (Privilege Escalation) · 85
- Sequence A → B with `window_ms: 3600000` (N = 60 min, `cfg.new_principal_window_ms`).
- A (creation): AWS `CreateUser`, `CreateRole`, `CreateAccessKey`, `CreateLoginProfile`; Azure `Add user`, `Add service principal`, `Add application`, `Invite external user`; GCP `CreateServiceAccount`, `CreateServiceAccountKey`.
- B: the **new principal** (A's `target_user`, the role name, the new key id `J('$.responseElements.accessKey.accessKeyId')`, or the new SA email) performs a write in `cfg.privileged_apis` (IAM/RBAC/SetIamPolicy writes, key creation, logging changes, data reads from secrets/storage).
- Also emit when A is granted a privileged role within the window (`aws_admin_policy_attached`, `az_entra_privileged_role`, `az_rbac_privileged_assignment`, `gcp_sensitive_grant` with the new principal as target). This generalises the existing `account_created_then_elevated` template to cloud identifiers.
- Src: existing AttackLens template · Stratus iam-create-admin-user, create-admin-service-account · Sentinel AccountCreatedandDeletedinShortTimeframe, AdminPromoAfterRoleMgmtAppPermissionGrant (MIT) · Elastic persistence_iam_create_user_via_assumed_role_on_ec2_instance (idea).

**B8 seq_new_key_used_new_ip** · AWS (+GCP SA keys) · T1098.001 (Persistence) + T1078.004 · 80
- A: `CT AND api='CreateAccessKey' AND outcome='success'`, key `k := J('$.responseElements.accessKey.accessKeyId')`, creator IP `ip_a := src_ip`.
- B: any `CT` event with `ct_akid = k` within `window_ms: 86400000` (24 h) where `src_ip` ≠ `ip_a` **and** the /24 (or ASN with `[geo]`) was never used by the creating actor in the baseline (14 d).
- Severity 80; 90 if B's first API is in the recon set (GetCallerIdentity, ListBuckets, ListUsers) or a privileged API.
- GCP variant: `CreateServiceAccountKey` (key id `regexp_extract(g_resp, '"name":"[^"]*/keys/([0-9a-f]+)"', 1)`) → events whose `J('$.protoPayload.authenticationInfo.serviceAccountKeyName')` ends with that key, from a new prefix.
- Src: Elastic persistence_iam_user_self_created_access_key_subsequently_used, credential_access_iam_long_term_access_key_first_seen_from_source_ip (10-day new-terms idea) · Stratus iam-backdoor-user.

**B9 seq_role_chain** · AWS, GCP · T1548.005 (Privilege Escalation) / T1550.001 · 60 / 75
- AWS: `CT AND svc='sts.amazonaws.com' AND api IN ('AssumeRole','AssumeRoleWithWebIdentity','AssumeRoleWithSAML','AssumeRoot')`.
  - Edge `caller := coalesce(ct_iss, ct_arn) → target := J('$.requestParameters.roleArn')`. New session key `J('$.responseElements.credentials.accessKeyId')`.
  - Fire when the edge `(caller_role, target_role)` is first-seen in `baseline_days: 14` → 60.
  - 75 when the chain depth (A→B→C within `window_ms: 3600000`, joined by `ct_akid` of the next AssumeRole equals the previous response key) ≥ 2, the target account (`regexp_extract(target, '::(\d{12}):', 1)`) ≠ caller account and not in `cfg.trusted_aws_accounts`, or `AssumeRoot` by a rare user (Elastic).
- GCP: `g_deleg` chain length ≥ 2, or a first-seen `(actor, impersonated SA)` edge (shares logic with gcp_sa_impersonation_use).
- Src: Elastic privilege_escalation_sts_role_chaining (new_terms on issuer arn + target arn, 10 d), privilege_escalation_sts_assume_root_from_rare_user_and_member_account · Sigma 905d389b (too broad, disabled).

**B10 seq_grant_then_data_access** · AWS, Azure, GCP · T1098.003 (Privilege Escalation) → T1530 / T1555.006 (Collection / Credential Access) · 85
- A: a role or permission grant to principal P. Sources: aws_admin_policy_attached or `Put*Policy`/`Attach*Policy` (P = `requestParameters.userName|roleName`), aws_role_trust_backdoor (P = the role), az_rbac_privileged_assignment or any `ROLEASSIGNMENTS/WRITE` (P = `principalId` in az_req), gcp_sensitive_grant (P = member), az_oauth_consent_privileged (P = app).
- B: P performs a data read within `window_ms: 7200000` (2 h). Data reads: S3 `GetObject`/`ListObjects` `[ct-data]`, `GetSecretValue`, `GetParameter` with decrypt, Azure `LISTKEYS`/`LISTACCOUNTSAS`, Key Vault `SecretGet` `[az-res]`, GCP `storage.objects.get|list`, `AccessSecretVersion` `[gcp-da]`, `GetPasswordData`, `DescribeInstanceAttribute userData`.
- 90 when A's actor ≠ P and P is new (B7) or external.
- Src: original composite (AttackLens). Idea from Elastic privilege_escalation_sensitive_rbac_change_followed_by_workload_modification (k8s analogue) and Sentinel AdminPromoAfterRoleMgmtAppPermissionGrant.

**B11 seq_logging_off_then_write** · AWS, Azure, GCP · T1685.002 (Defense Impairment) → tactic of the write · 90
- A: any of aws_logging_tamper, aws_security_service_off, az_diag_or_defender_off, gcp_logging_tamper, az_lock_deleted at sev ≥ 70.
- B: any write in the same `acct` within `window_ms: 7200000`, by the same actor (90) or any non-allowlisted actor (75).
- Emit B as its own alert (labelled with B's technique when it has one, else T1078.004) and link A → B for the attack path. This makes the "blind then act" pattern one incident even when B is a normal-looking API.
- Src: original composite. Pattern from Stratus defense-evasion techniques + Unit42 cloud extortion write-ups referenced by Stratus.

**B12 cl_session_multi_asn** · AWS, Azure · T1550.001 (Lateral Movement) / T1539 (Credential Access) · 70 / 85
- Session key: AWS `ct_akid LIKE 'ASIA%'` (temporary credentials; one key = one session), and IAM-user long-term keys `AKIA%` with `window_ms: 300000` (Splunk's 5-min concurrency); Azure `si_sess` (SessionId / UniqueTokenIdentifier, incl. non-interactive sign-ins).
- Network: ASN from `[geo]` / `si_asn`, else /16.
- Fire when ≥ `min_networks: 2` networks within `window_ms: 3600000` (1 h), ignoring IPs in cloud-provider ranges when the session is an instance or Lambda role (calls via AWS services), `ct_ip='AWS Internal'`, and `J('$.vpcEndpointId') IS NOT NULL`.
- 85 when one network is a hosting ASN (B2 list) or a different country, or the second network's first call is sensitive. GCP has no session id; use `principal + serviceAccountKeyName`.
- Src: Elastic initial_access_iam_session_token_used_from_multiple_addresses, credential_access_entra_id_prt_cookie_replay_unusual_ip (ideas) · Splunk aws_concurrent_sessions_from_different_ips, azure_ad_concurrent_sessions_from_different_ips.

**B13 cl_mass_destruction** · AWS, Azure, GCP · T1485 / T1486 / T1490 (Impact) · 85 / 95
- Key `(actor, acct)` and also `(actor, bucket)` for object stores. Window `window_ms: 900000` (15 min) for objects, `3600000` for resources. `baseline_days: 14`.
- Destruction events and default thresholds (`min_distinct`, plus `baseline_mult: 10` × the actor's p95 per window):
  - S3 objects `[ct-data]`: `DeleteObject`, `DeleteObjects` (count `coalesce(json_array_length(J('$.requestParameters.delete.Object')), 1)`; verify the path on a real event, as some trails log only the bucket). ≥ 100 objects.
  - GCS `[gcp-da]`: `storage.objects.delete` ≥ 100.
  - Azure blob `[az-res]`: `DeleteBlob` ≥ 100.
  - Buckets and containers: `DeleteBucket`, `storage.buckets.delete`, `STORAGEACCOUNTS/DELETE` ≥ 3.
  - Generic resources: AWS `ct_write AND regexp_matches(api, '^(Delete|Terminate|Remove|Purge|Deregister|ScheduleKeyDeletion)')`, Azure `api_u LIKE '%/DELETE'` (count distinct `host`), GCP `regexp_matches(api, '\.(delete|destroy)$')` ≥ 25 (Sentinel's `TotalEventsThreshold = 25`).
  - Keys and backups: from cl_kms_key_destroy and cl_backup_destruction ≥ 3.
  - Azure storage key regeneration `REGENERATEKEY/ACTION` ≥ 3 accounts (locks out apps).
  - Encryption rewrites (SSE-C, GCS rewrite, CPEK `PutBlob` with encryption headers `[az-res]`) ≥ 20.
- Severity 85. 95 when combined with any B11 A-event or cl_backup_destruction in the prior 24 h (the ransomware pattern: blind, kill backups, destroy or encrypt).
- Src: Sentinel TimeSeriesAnomaly_Mass_Cloud_Resource_Deletions (MIT; 14 d series, threshold 25) · Splunk detect_spike_in_s3_bucket_deletion · Elastic impact_azure_storage_account_deletion_multiple, impact_azure_compute_vm_snapshot_deletions · Stratus s3/gcs/blob ransomware techniques.

**B14 cl_exfil_volume** · AWS, Azure, GCP · T1530 (Collection) / T1537 / T1567.002 (Exfiltration) · 75 / 85
- S3 `[ct-data]`: key `(actor, acct)`. Per `window_ms: 3600000`: `sum(TRY_CAST(J('$.additionalEventData.bytesTransferredOut') AS DOUBLE))` and `count(DISTINCT J('$.requestParameters.key'))` for `api='GetObject'`. Fire when bytes > `max(cfg.exfil_min_bytes (1 GB), baseline_mult (10) × p95 hourly bytes over 14 d)` or objects > `max(1000, 10 × p95)` → 75.
  - 85 when the caller IP is outside `cfg.corp_egress_cidrs` and cloud ranges, or the actor is new (B7) or keyed from a new IP (B8).
  - `ListObjects`/`ListObjectsV2` ≥ 50 prefixes before the burst → +5.
- GCS `[gcp-da]`: `storage.objects.get`, same thresholds (bytes not logged; count only).
- Azure `[az-res]`: `GetBlob` from StorageBlobLogs (bytes `ResponseBodySize`). Management-plane proxies (always available): ≥ 2 of `LISTACCOUNTSAS`, `LISTSERVICESAS`, `DISKS/BEGINGETACCESS`, `LISTKEYS` by one caller in 1 h → 75 (SAS generation spree).
- Sharing bursts: cl_snapshot_image_share_external or cl_storage_public_or_external ≥ 3 resources in 1 h → 90.
- Src: Splunk aws_exfiltration_via_anomalous_getobject_api_activity (10 min bins, anomalydetection), aws_s3_exfiltration_behavior_identified · Elastic exfiltration_s3_uncommon_client_user_agent, exfiltration_azure_storage_blob_download_azcopy_sas_token · Stratus storage-sas-export · existing AttackLens `exfil_volume` baseline logic (median × mult) is reused for the threshold shape.

**B15 cl_dormant_identity_reactivated** · AWS, Azure, GCP · T1078.004 (Initial Access / Persistence) · 60
- Key `actor`. Fire on the first successful event after a gap ≥ `cfg.dormant_days` (30), when the data set covers that gap (`min_history_days ≥ dormant_days`).
- 75 if the first actions are writes or sensitive reads, or come from a new country (B2).
- Src: original (common IR heuristic). Sigma azure_pim_account_stale (PIM report, not a log) inspired it.

**B16 cl_new_user_agent_family** · AWS, Azure, GCP · T1059.009 (Execution) · 45
- `ua_family := regexp_extract(lower(coalesce(ct_ua, si_ua, g_ua)), '^(aws-cli|boto3|botocore|aws-sdk-[a-z]+|terraform|pulumi|console|mozilla|python-requests|curl|go-http-client|powershell|azurecli|azure-sdk|google-cloud-sdk|gcloud|grpc-[a-z]+)', 1)`, or `'other'`.
- Key `(actor, ua_family)`, `baseline_days: 14`. Fire when a principal that used only console/IaC suddenly uses a scripting family (`python-requests`, `curl`, `go-http-client`, raw `boto3`) for writes → 45 alone, 70 with B2 or B4 in the same hour.
- Src: Elastic execution_forbidden_request_from_unsual_user_agent (k8s analogue), exfiltration_s3_uncommon_client_user_agent (ideas) · Splunk aws_ecr_container_upload_unknown_user (idea).

**B17 seq_risky_signin_then_persistence** · Azure (+AWS console) · T1078.004 → T1098.001/.003/.005 / T1556.006 · 85
- A: az_risky_signin_success, az_valid_password_new_country, az_mfa_fatigue (success branch), az_risky_auth_protocol (device code), B2 country/hosting ASN, B6, or for AWS a ConsoleLogin with B2.
- B (same user, `window_ms: 21600000` = 6 h): az_auth_method_added (self), az_app_or_identity_credential, az_oauth_consent_privileged, az_entra_privileged_role (as actor), inbox rules are out of scope (M365), AWS aws_credential_for_other_user / CreateAccessKey (self) / aws_keypair_new.
- Src: Sentinel SuspiciousSignInFollowedByMFAModification (MIT) · Elastic persistence_identity_protect_alert_followed_by_device_reg, persistence_entra_id_device_registration_to_prt_chain (ideas).

**B18 cl_volume_zscore** · AWS, Azure, GCP · per-tactic label from the dominant API class · 50
- Key `(actor)`, hourly counts of writes. Fire when `count > mean + z (4) × σ` over `baseline_days: 14` (σ floor 2) and count ≥ `min_num: 50`, or when a privileged write happens in an hour-of-week where the actor has < 1 % of their history (`cfg.offhours_min_share`: 0.01) and the actor has ≥ 200 baseline events.
- Context only by itself (50 without rarity cannot seed). It mainly adds a tactic to an incident that already has a seed.
- Src: Elastic ml_*_event_failures, Sentinel TimeSeriesAnomaly (series-decomposition idea simplified to z-score).

---

## 6. Sigma cloud rules: enable, downgrade, skip, and field mappings

### 6.1 Logsources to add to `sigma_map.yaml`

```yaml
logsources:
  - {name: aws_cloudtrail, product: aws, service: cloudtrail, gate: "source_type = 'cloudtrail_json'"}
  - {name: azure_activity, product: azure, service: activitylogs,
     gate: "source_type = 'azure_activity_json' AND (json_extract_string(raw_line, '$.OperationNameValue') IS NOT NULL OR upper(signature) LIKE 'MICROSOFT.%')",
     keywords: {expr: raw_line, source_types: [azure_activity_json]}}
  - {name: azure_audit, product: azure, service: auditlogs,
     gate: "source_type = 'azure_activity_json' AND coalesce(json_extract_string(raw_line, '$.LoggedByService'), json_extract_string(raw_line, '$.loggedByService'), json_extract_string(raw_line, '$.properties.loggedByService')) IS NOT NULL"}
  - {name: azure_signin, product: azure, service: signinlogs, gate: "source_type = 'azure_signin_json'"}
  - {name: gcp_audit, product: gcp, service: gcp.audit, gate: "source_type = 'gcp_audit_json'",
     keywords: {expr: raw_line, source_types: [gcp_audit_json]}}
  # NOT added (no data): azure riskdetection, azure pim, gcp google_workspace.admin, m365 *
```

Cloud raw lines are label-free (they are not generator ECS), so a `raw_line` keyword column is allowed for these source
types. The compiler's JSON/CEF exclusion regex must be **off** for these two entries, because every cloud line is
JSON. Otherwise keyword rules never match. Suggest a per-logsource `exclude_regex: null`.

### 6.2 Field mappings (Sigma field → expression)

`fields` is global today. Each expression is gated by `source_type` so the same Sigma name cannot match another
source. Values are compared case-insensitively by the compiler.

| Sigma field | Expression | Notes |
|---|---|---|
| eventName | `CASE WHEN source_type='cloudtrail_json' THEN signature END` | |
| eventSource | `CASE WHEN source_type='cloudtrail_json' THEN app END` | |
| errorCode | `CASE WHEN source_type='cloudtrail_json' THEN json_extract_string(raw_line,'$.errorCode') END` | Sigma's `errorCode: Success` never occurs; the `null` branch matches successes. Works as written. |
| errorMessage | `… '$.errorMessage'` (CT-gated) | |
| sourceIPAddress | `… '$.sourceIPAddress'` (CT-gated) | raw, so `'AWS Internal'` filters work (src_ip would be NULL) |
| userAgent | `coalesce(CT: '$.userAgent', AZS: '$.UserAgent' / '$.properties.userAgent')` | used by AWS and signin rules |
| userIdentity.type / .arn / .sessionContext.sessionIssuer.type | `… '$.userIdentity.type'` etc. (CT-gated) | |
| eventType | `… '$.eventType'` | |
| additionalEventData.MFAUsed | `… '$.additionalEventData.MFAUsed'` | |
| responseElements.ConsoleLogin / .publiclyAccessible / .pendingModifiedValues.masterUserPassword / .accessKey.userName | `… '$.responseElements.<path>'` | |
| responseElements | `… '$.responseElements'` (JSON text) | `contains` works on text |
| requestParameters | `… '$.requestParameters'` (JSON text) | |
| requestParameters.attribute / .enable / .layers / .containerDefinitions.command / .PublicAccessBlockConfiguration.* | `… '$.requestParameters.<path>'` | `containerDefinitions` is an array, so map to `'$.requestParameters.containerDefinitions'` JSON text (`contains` rule) |
| status (AWS rule ccd6a6c8) | `CASE WHEN source_type='cloudtrail_json' THEN outcome END` | Sigma means "success" |
| operationName (activity) | `CASE WHEN source_type='azure_activity_json' THEN upper(signature) END` | also used by some audit rules with activity names; plain `signature` matches both because the compare is case-insensitive |
| category | `CASE WHEN source_type='azure_activity_json' THEN coalesce(J('$.CategoryValue'), J('$.category.value'), J('$.Category'), J('$.category'), J('$.properties.category')) END` | `Administrative` / audit categories |
| resourceId | `CASE WHEN source_type='azure_activity_json' THEN host END` | |
| properties.message (audit) | `CASE WHEN source_type='azure_activity_json' THEN coalesce(J('$.properties.message'), J('$.ActivityDisplayName'), J('$.activityDisplayName'), J('$.properties.activityDisplayName'), signature) END` | do **not** map it for signinlogs (device code/ROPC rules: use native) |
| OperationName | `CASE WHEN source_type IN ('azure_activity_json','azure_signin_json') THEN signature END` | |
| ActivityDisplayName, activityType | same as properties.message | |
| Category | as `category` | |
| LoggedByService | `coalesce(J('$.LoggedByService'), J('$.loggedByService'), J('$.properties.loggedByService'))` | |
| Status, properties.result | `CASE WHEN source_type IN ('azure_activity_json','azure_signin_json') THEN outcome END` | values Success/failure match; rules using Status for text (e40f4962, fa84aaf5) are skipped |
| TargetResources, properties.targetResources, TargetResources.modifiedProperties, TargetResources.modifiedProperties.newValue | `tr_json` (§2.2) | only valid for `contains` rules; equality rules on these fields are skipped |
| additionalDetails.additionalInfo | `au_add` | contains only |
| ResultType | `{expr: "TRY_CAST(coalesce(J('$.ResultType'), J('$.resultType'), J('$.properties.status.errorCode')) AS INTEGER)", type: INTEGER}` (AZS-gated) | |
| ResultDescription | `coalesce(J('$.ResultDescription'), J('$.resultDescription'), J('$.Status.failureReason'), J('$.properties.status.failureReason'))` | |
| AuthenticationRequirement, conditionalAccessStatus, ResourceDisplayName, RiskState | `si(...)` macros | |
| DeviceDetail.isCompliant / .trusttype / .deviceId | `coalesce(J('$.DeviceDetail.isCompliant'), J('$.properties.deviceDetail.isCompliant'))`; trusttype → `.trustType` | |
| NetworkLocationDetails | `CAST(json_extract(raw_line,'$.NetworkLocationDetails') AS VARCHAR)` | |
| gcp.audit.method_name, data.protoPayload.methodName | `CASE WHEN source_type='gcp_audit_json' THEN signature END` | Sigma wildcards like `v*.Compute.Firewalls.Delete` match `v1.compute.firewalls.delete` case-insensitively |
| data.protoPayload.serviceName | GCP-gated `app` | |
| data.protoPayload.logName | GCP-gated `J('$.logName')` | the rule's path is wrong (logName is top-level); the mapping fixes it |
| data.protoPayload.resource.type | GCP-gated `J('$.resource.type')` | same |

Not mapped (rules that use them are skipped): `ConsentContext.IsAdminConsent`, `failure_status_reason`,
`targetResources.type` (list equality), `data.protoPayload.authorizationInfo.*` (list), `Initiatedby`/`Target`/
`Username` (placeholders "UPN"), `riskEventType` (riskdetection/PIM), `ActivityDetails`, `ClientApp`.

### 6.3 Rules to ENABLE at their own level (34)

Paths are relative to `config/sigma/rules/cloud/`.

AWS (`aws/cloudtrail/`), 20:
`aws_cloudtrail_disable_logging.yml` (4db60cc0) · `aws_cloudtrail_guardduty_detector_deleted_or_updated.yml` (d2656e78) ·
`aws_guardduty_disruption.yml` (6e61ee20) · `aws_cloudtrail_vpc_flow_logs_deleted.yml` (e386b9b5) ·
`aws_config_disable_recording.yml` (07330162) · `aws_cloudtrail_console_login_success_without_mfa.yml` (77caf516) ·
`aws_ec2_startup_script_change.yml` (1ab3c5ed) · `aws_kms_import_key_material.yml` (1279262f) ·
`aws_rds_public_db_restore.yml` (c3f265c7) · `aws_sso_idp_change.yml` (d3adb3ef) ·
`aws_cloudtrail_bucket_block_public_access_weakened.yml` (ab18a523) · `aws_disable_bucket_versioning.yml` (a136ac98) ·
`aws_ec2_disable_encryption.yml` (16124c2d) · `aws_cloudtrail_pua_trufflehog.yml` (a840e606) ·
`aws_sts_getcalleridentity_trufflehog.yml` (9b1b8e9b) · `aws_iam_s3browser_loginprofile_creation.yml` ·
`aws_iam_s3browser_user_or_accesskey_creation.yml` · `aws_ecs_task_definition_cred_endpoint_query.yml` (b94bf91e) ·
`aws_route_53_domain_transferred_to_another_account.yml` (b056de1a; raise to medium) · `aws_delete_saml_provider.yml` (ccd6a6c8).

Azure activity (`azure/activity_logs/`), 3:
`azure_subscription_permissions_elevation_via_activitylogs.yml` (09438caa) · `azure_suppression_rule_created.yml` (92cc3e5d) ·
`azure_aadhybridhealth_adfs_new_server.yml` (288a39fc).

Azure audit (`azure/audit_logs/`), 8:
`azure_subscription_permissions_elevation_via_auditlogs.yml` (ca9bf243) · `azure_federation_modified.yml` (352a54e1) ·
`azure_mfa_disabled.yml` (7ea78478) · `azure_ad_users_added_to_device_admin_roles.yml` (11c767ae) ·
`azure_ad_new_root_ca_added.yml` (4bb80281) · `azure_ad_certificate_based_authencation_enabled.yml` (c2496b41) ·
`azure_update_risk_and_mfa_registration_policy.yml` (d4c7758e) · `azure_pim_alerts_disabled.yml` (aeaef14c).

Azure sign-in (`azure/signin_logs/`), 2: `azure_ad_azurehound_discovery.yml` (35b781cc) ·
`azure_ad_suspicious_signin_bypassing_mfa.yml` (53bb4f7f).

GCP (`gcp/audit/`), 1: `gcp_breakglass_container_workload_deployed.yml` (76737c19).

### 6.4 Rules to ENABLE as context (39; force `level: low` = severity 35)

This needs a small compiler feature: `level_override: {<id or uuid>: low}` in `sigma_map.yaml`, next to `disable`.

- AWS: `aws_cloudtrail_new_acl_entries`, `aws_cloudtrail_new_route_added`, `aws_cloudtrail_security_group_change_{ingress_egress,loadbalancer,rds}`,
  `aws_snapshot_backup_exfiltration`, `aws_cloudtrail_ssm_malicious_usage` (any SendCommand), `aws_securityhub_finding_evasion`
  (BatchUpdateFindings is routine), `aws_rds_dbcluster_actions`, `aws_cloudtrail_bucket_deleted`, `aws_ec2_import_key_pair_activity`,
  `aws_cloudtrail_imds_malicious_usage`, `aws_root_account_usage`, `aws_cloudtrail_region_enabled`, `aws_console_getsignintoken`,
  `aws_susp_saml_activity`, `aws_rds_change_master_password`, `aws_cloudtrail_bedrock_guardrail_{deleted,updated}`,
  `aws_s3_data_management_tampering`, `aws_lambda_function_url`, `aws_new_lambda_layer_attached`,
  `aws_cloudtrail_console_login_failed_authentication`, `aws_ec2_vm_export_failure`, `aws_delete_identity`,
  `aws_route_53_domain_transferred_lock_disabled`. (26)
- Azure activity: `azure_granting_permission_detection` (keywords roleAssignments/write), `azure_rare_operations`
  (keywords listKeys etc.), `azure_keyvault_{modified_or_deleted,key_modified_or_deleted,secrets_modified_or_deleted}`,
  `azure_new_cloudshell_created`, `azure_firewall_modified_or_deleted`, `azure_network_security_modified_or_deleted`. (8)
- Azure audit: `azure_app_owner_added`, `azure_ad_bitlocker_key_retrieval`, `azure_auditlogs_laps_credential_dumping`. (3)
- GCP: `gcp_full_network_traffic_packet_capture`, `gcp_service_account_disabled_or_deleted`. (2)

### 6.5 Rules to DISABLE (16): noisy or broken against real data

| Rule | Reason |
|---|---|
| `aws_sts_assumerole_misuse` (905d389b) | matches every role session (userIdentity.type AssumedRole + issuer Role) |
| `aws_sts_getsessiontoken_misuse` (b45ab1d2) | every MFA CLI user; covered by B9/B12 |
| `aws_enum_buckets` (f305fd62) | every non-role ListBuckets; covered by B4 |
| `aws_update_login_profile` (055fb148) | `fieldref` compares the ARN with the userName, never equal, so it always fires; replaced by aws_credential_for_other_user |
| `aws_iam_backdoor_users_keys` (0a5177f4) | `fieldref|contains` is unsupported; native replacement |
| `aws_iam_s3browser_templated_s3_bucket_policy_creation` | placeholder `<YOUR-BUCKET-NAME>` |
| `aws_eks_cluster_created_or_deleted`, `aws_elasticache_security_group_{created,modified_or_deleted}`, `aws_efs_fileshare_{modified_or_deleted,mount_modified_or_deleted}`, `aws_passed_role_to_glue_development_endpoint` | admin noise with no attacker specificity (6 files; keep available if a demo needs them) |
| `azure_creating_number_of_resources_detection` (d2d901db) | keywords on every VM write; covered by cl_compute_hijack and B18 |
| `azure_ad_only_single_factor_auth_required` (28eea407) | every single-factor sign-in |
| `azure_ad_sign_ins_from_unknown_devices` (4d136857) | every unmanaged-device sign-in |
| `gcp_bucket_enumeration` (e2feb918) | every storage.buckets.list |

### 6.6 Rules SKIPPED (137): no data, unmappable, or replaced natively

Count per folder (total minus enabled, context and disabled): azure/activity_logs 23 · azure/audit_logs 33 ·
azure/signin_logs 14 · azure/identity_protection 19 · azure/privileged_identity_management 7 · gcp/audit 12 ·
gcp/gworkspace 10 · m365 19.

- **No logsource ingested (55):** `azure/identity_protection/*` (19, riskdetection), `azure/privileged_identity_management/*`
  (7, PIM reports), `gcp/gworkspace/*` (10), `m365/*` (19). Ingesting `AADUserRiskEvents` / `AADRiskyUsers` would
  enable the first 19.
- **AKS data-plane operations (10):** `azure/activity_logs/azure_kubernetes_*`. They need connected-cluster
  operations that rarely reach the Activity Log. Re-enable as context if a data set shows them.
- **Unmappable fields or placeholders:** `azure_user_password_change`, `azure_legacy_authentication_protocols` (UPN placeholder),
  `azure_app_end_user_consent`, `azure_app_end_user_consent_blocked`, `azure_app_role_added`, `gcp_access_policy_deleted`,
  `azure_app_device_code_authentication`, `azure_app_ropc_authentication`, `azure_mfa_denies`, `azure_tap_added`,
  `azure_guest_to_member`, `azure_user_account_mfa_disable`, `azure_privileged_account_creation` (`contains|all` of two
  different activity names on one field can never match), `azure_app_uri_modifications` (string "Sucess-" never logged),
  `azure_device_or_configuration_modified_or_deleted` (Intune).
- **Replaced by a native rule with better logic (the rest):** `azure_app_credential_added` (hyphen vs en dash),
  `azure_app_delegated_permissions_all_users`, `azure_app_privileged_permissions`, `azure_app_permissions_msft`,
  `azure_priviledged_role_assignment_add`, `azure_ad_user_added_to_admin_role`, `azure_aad_secops_ca_policy_*` (3),
  `azure_change_to_authentication_method`, `azure_account_lockout`, `azure_conditional_access_failure`,
  `azure_mfa_interrupted`, `azure_login_to_disabled_account`, `azure_blocked_account_attempt`, `azure_ad_account_created_deleted`,
  `azure_service_principal_created/removed`, `azure_application_deleted`, `azure_owner_removed_from_application_or_service_principal`,
  the remaining network/VPN/DNS/app-gateway/container-registry activity rules, and the remaining GCP audit rules
  (bucket modified, DNS, firewall, SQL, VPN, k8s ×4, DLP, SA modified). These can be switched to "context" later if
  the data set shows they help linking.

---

## 7. Noise controls

1. **Context-only by default (severity ≤ 35; never seeds, never adds a tactic alone).**
   aws_credential_for_other_user (self branch), az_app_or_identity_credential (b), cl_backup_destruction (single),
   aws_logging_tamper (c, generic log groups), cl_attack_tool_user_agent (scanner UAs), az_entra_privileged_role
   (PIM activations), az_key_listing (service principals), gcp_testiam_burst (console UA), all §6.4 Sigma rules, B1–B3
   in cold start, B2 new-prefix, B18 alone. They exist to **link** (the same actor or account) and to explain the path.
2. **Promotion needs a second signal.** Signal-tier rules (45–60) reach 65+ only with one of: first-seen (B1/B2/B3),
   burst threshold, external principal/account, or a sequence (B7–B11, B17). This is written into each rule's
   severity line above, not into global scoring.
3. **Allowlists in `config/cloud.yaml`** (proposed keys): `iac_principals`, `iam_admin_principals`,
   `trusted_aws_accounts`, `trusted_domains`, `trusted_guest_domains`, `trusted_app_ids`, `trusted_oidc_issuers`,
   `corp_egress_cidrs`, `vpn_asns`, `hosting_asns`, `allowed_regions`, `global_services`, `inventory_ua_regex`,
   `iac_ua_regex`, `attack_ua_regex`, `redteam_principals` + windows, `change_windows`, `backup_principals`,
   `ml_principals`, `genai_principals`, `ca_admins`, `helpdesk_principals`, `public_bucket_allow`, `public_sg_allow`.
   An allowlisted match is **downgraded** (to 35 or 45), never dropped. The evidence stays for the timeline and the
   accounting.
4. **Machine identities have their own track.** `ct_svc` (AWSService / invokedBy / `*.amazonaws.com`), Azure GUID
   callers, and Google service agents are excluded from first-seen, geo and travel rules. They still count for
   destruction and exfil bursts (B13/B14), because a stolen service identity is exactly how those happen.
5. **De-duplication before counting.** CloudTrail `eventID` (organization trail + account trail both deliver the same
   event), GCP `insertId`, Azure `(az_corr, api_u, ActivityStatusValue)`, SigninLogs `Id`. Burst templates count
   `DISTINCT` of these. Do it at template level: ingest must keep every row for the accounting.
6. **Caps.** Per rule `max_alerts_per_rule` (as Sigma), per actor per day for B1/B2 (`first_seen_max_per_actor_day: 20`,
   then one summary alert), and per account per hour for context rules.
7. **Cold start is explicit.** Baseline rules report `baseline_ok: false` in the alert evidence when history is short,
   and the UI can show it. "Measure, never assert" applies to anomalies too.
8. **Azure state rows.** Only `success` (or `Accept` for async creates) rows can fire. Start rows have outcome NULL
   and are ignored except for counting failures.
9. **Data-event volume guard.** `[ct-data]`/`[gcp-da]`/`[az-res]` rows can be 100× management volume. Pre-aggregate
   them per `(actor, bucket, 1-min)` in `cloud_ev` before B13/B14 run, so templates never scan raw object events twice.

---

## 8. Gaps and next steps

- **Kubernetes:** 10 Stratus EKS/k8s techniques and the AKS/GKE Sigma rules need Kubernetes audit logs (EKS control
  plane logs, AKS `kube-audit`, GKE `k8s.io` audit). GKE audit arrives in Cloud Audit Logs and is routed to
  `gcp_audit_json`, so k8s method names are matchable. A `k8s` rule pack is a follow-up.
- **Azure data plane:** blob ransomware (CPEK, individual deletion) and Key Vault secret reads need `StorageBlobLogs` and
  `AZKVAuditLogs`/`AzureDiagnostics`. Add them to `azure_monitor.events.tables` and add a source format.
- **Geo/ASN:** ship `config/geo/ip2asn-combined.tsv.gz` (PDDL) and the AWS/Google range snapshots. Load them as
  DuckDB tables with an `ip_to_int` range join. Without them B2/B6/B12 fall back to /24 and /16 prefixes and
  cl_instance_creds_offhost uses its fallback.
- **Ingest aliases:** `$.operationName.value` and `$.status.value` for Activity Log REST shape (§2.1). Consider keeping
  the AWS session name: `ct_arn` is only in raw_line today.
- **Test plan (`test-engineer`):** one fixture JSONL per Stratus technique, built from the "Detonation logs" and
  sample events in each Stratus page (event names listed in §3), plus benign baselines for first-seen rules.
  A probe test should assert that no rule reads label keys (unchanged rule from CLAUDE.md).
- **Licences to add to README:** Stratus (Apache-2.0), Splunk security_content (Apache-2.0), Azure-Sentinel (MIT),
  Panther (Apache-2.0), Elastic detection-rules (ELv2, "logic inspired by", no code copied), SigmaHQ (DRL 1.1,
  already listed), iptoasn (PDDL) or DB-IP Lite (CC BY 4.0), AWS/Google IP-range feeds.

---

## 9. Rules track: label decisions and new native rules (1 Nov 2026)

Label decisions (ATT&CK v20 text, not a dataset's label):

- **Bucket / blob made public (`cl_storage_public_or_external`): keep T1537.** T1537 Transfer Data to Cloud Account:
  "Adversaries may also use cloud-native mechanisms to share victim data with adversary-controlled cloud accounts,
  such as creating anonymous file sharing links". A PutBucketAcl to AllUsers is that sharing step. T1530 Data from
  Cloud Storage is the later read of the data (`aws_s3_anonymous_read`, `cl_storage_data_access`, `cl_exfil_volume`).
  Splunk's T1530 label on its s3public set is a dataset choice.
- **CreateAccessKey / CreateLoginProfile for another user (`aws_credential_for_other_user`): keep T1098.001
  (Persistence).** T1098.001 Additional Cloud Credentials: "Adversaries may also use the CreateAccessKey API in AWS
  ... to add access keys to an account ... CreateLoginProfile API ... If the target account has different
  permissions from the requesting account, the adversary may also be able to escalate their privileges". T1078
  (Valid Accounts) is the later use of that key (`seq_new_key_used_new_ip`). Privilege Escalation is a valid second
  tactic of T1098.001 but the primary intent named first is persistent access.
- **Sigma 6393e346 (ConsoleLogin "Failed authentication"): no override.** Its own tags already give T1110 /
  Credential Access (episodes carry it). "tactics: []" in `suppressed.json` means the episode is context (the rule is
  in `level_override` as low): a single failed login is not an intrusion. Bursts are `cl_signin_bruteforce` and the
  new `aws_console_unknown_user`.
- **KMS ScheduleKeyDeletion (`cl_kms_key_destroy`): stays T1485** (data made unrecoverable; nothing is encrypted by the
  actor). Imported key material then deleted is T1486 (new `cl_storage_ransom_encrypt` branch).
- **GetSecretValue bursts (`cl_secrets_mass_read`): stays T1555.006** Cloud Secrets Management Stores.

New / changed (tests: `backend/tests/test_detect_cloud_native_rules.py`, thresholds in `cloud.yaml` "native rule
quality track"):

| Rule | Technique | What |
|---|---|---|
| `aws_console_unknown_user` | T1110 (+ T1078.004 after a success) | ConsoleLogin "No username found in supplied account": 1 = context 35, >= 3 from one IP in 30 min = 65, then a success from that IP = 85 |
| `cl_discovery_burst` low tier | T1580 | >= 6 read APIs over >= 4 services in 10 min with >= 2 denied or >= 3 recon-first APIs, never console UA (55) |
| `cl_denied_spike` | T1580 | keyed on the identity, not (identity, IP): a new IP no longer cold-starts the stolen-key case |
| `cl_first_seen_geo` | T1078.004 (context) | recon-first reads (whoami, list buckets / users / roles, `storage.buckets.list`) count as activity |
| `seq_novel_network_then_action` | T1078.004 | first-seen network, then from the same IP within 1 h a discovery / credential / collection / exfil alert; hit at the access (70) |
| `cl_storage_enum_burst` | T1619 | GCS / Azure object listing over >= 5 buckets or containers in 10 min (50, external 60); S3 is `aws_s3_bucket_enum` |
| `cl_storage_write_new_bucket` | T1537 | >= 20 objects written in 1 h into a bucket with no activity in the account for 30 d (75) |
| `aws_sts_token_new_network` | T1550.001 | STS credentials issued to one network, used from another within 12 h (prefix only 50, ASN 75, hosting 85) |
| `aws_serverless_code_change` | T1648 | + CreateFunction (45, IaC 35); create / update code then event-source mapping / function URL / AddPermission by the same identity within 1 h (75) |
| `cl_storage_ransom_encrypt` | T1486 | + KMS ImportKeyMaterial then DeleteImportedKeyMaterial / ScheduleKeyDeletion / DisableKey on the same key (90) |
| `az_oauth_consent_privileged` | T1528 | + user-level delegated grant ('Add delegated permission grant' / 'Add OAuth2PermissionGrant') with risky scopes (75) |
| `cl_compute_snapshot_create` | T1578.001 | a person snapshotting / imaging >= 3 volumes, DBs or instances in 1 h (55; backup allowlist 35; automation downgrade) |
