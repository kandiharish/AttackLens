# Cloud log coverage, claims audit and gap plan

Date: 2026-11-01. Author: cyberforge-0c (cloud research + claims audit). Read-only audit: no code or config changed.

Inputs:
- Research on four providers: AWS, Azure + Entra + M365, GCP + Workspace, and cross-cloud / SaaS (Okta, Kubernetes, GitHub, Cloudflare and others).
- Read-only inventory of `config/sources.yaml`, `config/cloud.yaml`, `config/rules_cloud.yaml`, `config/sigma_map.yaml`, `connectors/**` and `tools/cloud_attacks/**`.
- Measured numbers from `data/out/cloud_small/eval_scorecard.json` and `run_metrics.json`.

Every number below is copied from those files or counted in the repo during this audit. Nothing is estimated.

## TL;DR

- **We ingest 5 cloud source types**: `cloudtrail_json`, `azure_signin_json`, `azure_activity_json`, `azure_storageblob_json`, `gcp_audit_json`. All are control-plane or identity logs, plus Azure blob data.
- **The researched logs cover about 130 log types**. Supported or partial: about 20. Missing: about 110, including all network logs (VPC / VNet / GCP flow), all vendor findings (GuardDuty, Security Hub, SCC), and all SaaS identity (Okta, M365, Workspace Reports).
- **The biggest single blocker is shape, not source.** File ingest reads only one JSON record per line. These native delivery formats all come out as `unrecognized`:
  - CloudTrail `{"Records":[...]}` files, `.json.gz` and `.tar`
  - Azure `{"records":[...]}` exports
  - GCP Pub/Sub envelopes
  - CloudWatch subscription payloads
  - EventBridge envelopes

  The ext-eval session had to write `tools/ext/cloud_stream.py` to read flaws.cloud for this reason.
- **Rules**: 87 native cloud rules (aws 59, azure 51, gcp 39, counted per cloud tag) plus 70 Sigma cloud rules that run. Only 15 of the 87 native rules have a positive unit test.
- **Measured quality** on our own synthetic set `cloud_small` (29 MB, 10 attacks):

  | Metric | Value |
  |---|---|
  | Detection | 76.74 % |
  | Labels | 78.79 % |
  | Rebuilt | 40 % |
  | False alarms | 36.36 % |
  | Step precision | 41.1 % |

  Stories A6 and A7 (both novel) and A9 score 0 steps.
- **10 claims are FALSE and 8 are UNTESTED.** Most of the FALSE ones are stale docs that undersell what we have (README "not measured yet", old "known limits"). Two overstate it: "behavioural rules detect novel attacks" and "Stratus 93 techniques mapped".
- **Plan for today (S/M)**:
  1. Stage 0 envelope unwrap
  2. Azure export-shape aliases
  3. Keep GCP `labels`
  4. AWS VPC Flow (header-driven)
  5. GuardDuty in alert-input mode
  6. Okta System Log plus its 23 Sigma rules
  7. Kubernetes audit (generic, EKS and AKS shapes, plus GKE rules)
  8. Key Vault
  9. Workspace Reports
  10. Tune the A6, A7 and A9 misses
  11. Fix the stale claims

---

## 1. Coverage matrix

Legend:
- **Status**: OK = supported and tested. PART = parses, but with a shape, rule or test gap. NO = not ingested (counted as "JSON with no known source fields" or unrecognized; no silent loss).
- **Shapes** lists the shapes handled today; anything after "not" is missing.
- **Native** = rules in `config/rules_cloud.yaml` that target this log. "shared" means only the 12 cross-cloud behavioural rules (`cl_first_seen_*`, `cl_impossible_travel`, `seq_*`) apply.
- **Sigma** = Sigma rules that run on this source after `cloud_disable`.
- **Gen** = rows in the `tools/cloud_attacks` generator (cloud_small).

### 1a. AWS

| Log type | Pri | Status | Shapes handled | Delivery (ours) | Native | Sigma | Gen | Tests |
|---|---|---|---|---|---|---|---|---|
| CloudTrail management events | P0 | PART | Raw record, one per line. Not: `{Records}` file, `.gz` or `.tar`, EventBridge `detail`, CloudWatch subscription envelope, LookupEvents string (the connector unpacks it), Sentinel `AWSCloudTrail`, ECS, OCSF 3005 | `aws_cloudtrail` LookupEvents + S3 (mock only); file JSONL | 47 + shared | 44 | 17,437 rows; A1, A2, A6, A8, A10 | `test_ingest_cloud`, `test_cloud_connectors` aws_* (5), e2e, `test_detect_cloud` (6 AWS rules) |
| CloudTrail sign-in (ConsoleLogin, Identity Center) | P0 | PART | `responseElements.ConsoleLogin` maps to outcome. Not: Identity Center `CredentialVerification` (serviceEventDetails), `AuthWorkflowID` | as above | in the 47 (`aws_console_login_no_mfa`, `aws_root_usage`, `aws_console_pw_ok_mfa_fail`, `cl_signin_bruteforce`) | in the 44 | ConsoleLogin rows | `test_detect_cloud` |
| KMS / Secrets Manager / SSM Parameter events | P0 | OK | Same record | as above | in the 47 (GetSecretValue 4 refs, BatchGetSecretValue 3, GetParameter 3, kms 12) | in the 44 | yes | rule positives for a subset |
| S3 data events (GetObject and similar) | P0 | PART | Parses as `cloudtrail_json` | as above | `cl_storage_data_access`, `cl_exfil_volume` (`bytesTransferred` is referenced once) | in the 44 | `s3_data()` | A9-style story missed: 0/3 |
| Lambda / DynamoDB data events | P1 | PART | Parses | as above | Invoke 1 ref, dynamodb 0 | — | no | none |
| Network activity events (VPC endpoint) | P2 | PART | Parses; untested | the connector skips them unless enabled | 0 (`VpceAccessDenied` 0 refs) | — | no | none |
| CloudTrail Insights | P2 | PART | Parses, but has no `userIdentity`, so actor is NULL | skipped unless enabled | 0 | — | no | none |
| CloudTrail Lake / org trail | P2 | PART | Org-trail prefix is config only. Lake: NO | S3 prefix template | — | — | no | none |
| VPC Flow Logs (v2–v11) | P0 | NO | — | — | 0 | 0 | no | none |
| Transit Gateway flow logs | P2 | NO | — | — | 0 | 0 | no | none |
| Route 53 Resolver query logs | P1 | NO | — | — | 0 | 0 | no | none |
| Route 53 public zone query logs | P3 | NO | — | — | 0 | 0 | no | none |
| GuardDuty findings | P0 | NO | — | — | (alert-input only) | — | no | none |
| Security Hub findings (ASFF / OCSF) | P1 | NO | — | — | alert-input | — | no | none |
| S3 server access logs | P1 | NO | — | — | 0 | 0 | no | none |
| ELB / ALB access logs | P1 | NO | — | — | 0 | 0 | no | none |
| CloudFront access logs | P2 | NO | — | — | 0 | 0 | no | none |
| WAF v2 logs | P1 | NO | (top-level `labels` collides with our strip list) | — | 0 | 0 | no | none |
| Network Firewall (alert / flow / tls) | P1 | NO | — | — | 0 | 0 | no | none |
| EKS audit (+ authenticator) | P1 | NO | — | — | 0 | 0 | no | none |
| Lambda function logs | P2 | NO | — | — | 0 | 0 | no | none |
| RDS / Aurora audit | P2 | NO | — | — | 0 | 0 | no | none |
| SSM Session Manager transcripts | P2 | NO | — | — | 0 | 0 | no | none |
| AWS Config items / compliance | P1 | NO | — | — | (reach-next context) | — | no | none |
| IAM Access Analyzer | P2 | NO | — | — | alert-input | — | no | none |
| Inspector v2 | P2 | NO | — | — | context | — | no | none |
| Macie | P2 | NO | — | — | alert-input | — | no | none |
| Detective | P3 | n/a | Not a log; competitor reference only | — | — | — | — | — |
| Security Lake (OCSF Parquet) | P1 | NO | — | — | 0 | 0 | no | none |

### 1b. Azure, Entra ID and Microsoft 365

| Log type | Pri | Status | Shapes handled | Delivery (ours) | Native | Sigma | Gen | Tests |
|---|---|---|---|---|---|---|---|---|
| Azure Activity Log | P0 | PART | Log Analytics `AzureActivity`, and the REST / Event Grid shape one per line. Not: `{"records":[]}` export, Event Hub batches. Bug: export user = `identity.claims.name`, which is the display name, not the UPN | `azure_monitor` (mock); file JSONL | 31 (`is_aza` 20 ∪ `is_azd` 13) | 9 | 646 rows (shared with AuditLogs) | `test_ingest_cloud`, `test_detect_cloud2` (REST shape) |
| Entra interactive sign-ins (`SigninLogs`) | P0 | PART | LA columns tested. `properties.*` export is aliased but has no fixture. Not mapped: risk, `AuthenticationProtocol`, `ClientAppUsed`, `UserAgent`, `UniqueTokenIdentifier`, `SessionId`, ASN | `azure_monitor` | 7 | 3 | 792 rows; A3, A4, A7 | `test_azure_signin_mapping` (3 rows), `cl_signin_bruteforce`, `az_mfa_fatigue`, `cl_impossible_travel` |
| Entra non-interactive sign-ins | P0 | PART | Claimed via the same columns. String-typed JSON columns are not parsed. No fixture | `azure_monitor` union | shared with sign-in | — | no | UNTESTED |
| Entra service-principal sign-ins | P0 | PART | Routes via `ServicePrincipalName`; no fixture | `azure_monitor` union | shared | — | no | UNTESTED |
| Entra managed-identity sign-ins | P1 | PART | As above | `azure_monitor` union | shared | — | no | UNTESTED |
| Entra AuditLogs | P0 | PART | LA `InitiatedBy` / `TargetResources`. Export: `properties.initiatedBy.*`, `properties.targetResources`, `properties.result` are not aliased in ingest, so user, target and outcome are NULL | `azure_monitor` | 13 | 11 | A3, A4 | `test_ingest_cloud` (1 row), `az_entra_privileged_role` |
| Microsoft Graph activity logs | P0 | NO | — | — | 0 | 0 | no | none |
| M365 UAL: Exchange | P0 | NO | — | — | 0 | 0 (m365 / exchange Sigma rules are unmapped) | no | none |
| M365 UAL: SharePoint / OneDrive | P0 | NO | — | — | 0 | 0 | no | none |
| M365 UAL: AzureActiveDirectory / General | P1 | NO | — | — | 0 | 0 | no | none |
| M365 UAL: Teams | P2 | NO | — | — | 0 | 0 | no | none |
| Key Vault `AuditEvent` | P0 | NO | — | — | 0 | 0 | no | none |
| Storage blob data plane | P0 | PART | LA and export; `ip:port` is stripped | `azure_monitor` optional table (off by default, untested) | 2 + shared | 0 | 603 rows; A3, A7 | `test_detect_cloud2` |
| Storage file / queue / table | P2 | PART | Same columns; probably matches the blob detector; untested | — | 0 | 0 | no | none |
| VNet flow logs | P1 | NO | (`records[]` → `flowTuples` CSV) | — | 0 | 0 | no | none |
| NSG flow logs (legacy) | P1 | NO | — | — | 0 | 0 | no | none |
| Azure Firewall (`AZFW*`, legacy `msg_s`) | P1 | NO | — | — | 0 | 0 | no | none |
| App Gateway access + WAF | P1 | NO | — | — | 0 | 0 | no | none |
| Front Door / CDN + WAF | P1 | NO | — | — | 0 | 0 | no | none |
| DNS resolver policy (`DNSQueryLogs`) | P1 | NO | — | — | 0 | 0 | no | none |
| SecurityAlert (Defender / Sentinel) | P1 | PART | Alert-input mode via `sentinel` (tested); `azure_monitor` alerts mode untested | alert-input | n/a | n/a | no | `test_mock_siem` (sentinel only) |
| Identity Protection risk tables | P1 | NO | — | — | 0 | 0 (19 riskdetection Sigma rules unmapped) | no | none |
| Provisioning logs | P2 | NO | — | — | 0 | 0 | no | none |
| AKS audit (`AKSAudit`, `AzureDiagnostics log_s`, Event Hub) | P1 | NO | — | — | 0 | 0 | no | none |
| Azure SQL audit | P1 | NO | — | — | 0 | 0 | no | none |
| App Service / Functions logs | P1 | NO | — | — | 0 | 0 | no | none |
| Defender XDR streaming (CloudAppEvents and others) | P1 | NO | — | — | 0 | 0 | no | none |
| Bastion, Cosmos DB, ACR, VPN, Azure OpenAI, Automation, Intune, AD FS | P2 | NO | — | — | 0 | 0 (PIM: 7 Sigma rules unmapped) | no | none |
| Posture (recommendations, policy, health) | P3 | NO | — | — | — | — | no | none |

### 1c. GCP and Google Workspace

| Log type | Pri | Status | Shapes handled | Delivery (ours) | Native | Sigma | Gen | Tests |
|---|---|---|---|---|---|---|---|---|
| Audit: Admin Activity | P0 | PART | Native LogEntry JSONL. Not: Pub/Sub base64, JSON array (`gcloud`), `entries[]` pages, BigQuery / Log Analytics snake_case, Sentinel `GCPAuditLogs`. Bug: top-level `labels` is stripped | `gcp_logging` entries.list (mock); file JSONL | 27 (gcp-tagged 39 incl. shared) | 3 | 5,916 rows; A5, A9 | `test_gcp_audit_mapping`, `gcp_logging_tamper`, `gcp_sensitive_grant` |
| Audit: Data Access | P0 | PART | Same | same | in the 27 (AccessSecretVersion 2, GenerateAccessToken 2) | in the 3 | `gcs()` | A9 missed: 0/3 |
| IAM / SA key / impersonation fields | P0 | OK | `serviceAccountKeyName` pairing (`g_keyname`), delegation chains | same | in the 27 | — | yes | `test_detect_cloud` |
| GKE audit (`k8s.io`) | P0 | PART | Routes as `gcp_audit_json`. No `io.k8s.*` rules (0 refs). `labels` (`authorization.k8s.io/decision`, `command.gke.io`) are stripped | same | 0 | 0 | no | none |
| VPC Flow Logs | P0 | NO | — | — | 0 | 0 | no | none |
| Firewall rules logging | P1 | NO | — | — | 0 | 0 | no | none |
| Cloud DNS query logs | P1 | NO | — | — | 0 | 0 | no | none |
| Load Balancing request logs | P1 | NO | — | — | 0 | 0 | no | none |
| Cloud Armor | P1 | NO | — | — | 0 | 0 | no | none |
| Cloud IDS / NGFW threat | P2 | NO | — | — | 0 | 0 | no | none |
| Cloud NAT | P2 | NO | — | — | 0 | 0 | no | none |
| SCC findings | P1 | NO | — | — | alert-input | — | no | none |
| Audit: System Event | P2 | PART | Parses; used only for context | same | 0 | — | no | none |
| Audit: Policy Denied (VPC-SC) | P1 | PART | Parses (status 7 means denied) | same | 0 specific | — | no | none |
| BigQuery audit (`metadataJson`) | P1 | PART | Parses; `metadata.jobChange` is unused | same | 0 (bigquery 0 refs) | — | no | none |
| Secret Manager / KMS audit | P1 | OK | Parses | same | yes (secrets mass read, KMS destroy) | — | yes | partial |
| Cloud Run / Functions audit + request logs | P1 | PART | Audit parses (0 rules); request logs (`httpRequest`): NO | same | 0 | — | no | none |
| Ops Agent guest logs, OS Login, IAP | P1 | NO | `textPayload` syslog is not routed to the syslog parser | — | 0 | — | no | none |
| Cloud SQL audit | P2 | PART | pgAudit parses as audit; 1 ref | same | 1 | — | no | none |
| GCS usage logs (CSV) | P2 | NO | — | — | 0 | — | no | none |
| Access Transparency (`jsonPayload`) | P3 | NO | — | — | 0 | — | no | none |
| Workspace Login (Reports API) | P0 | NO | Reports shape: NO. The Cloud Logging shape routes as `gcp_audit_json` but has no rules (`login.googleapis` 0 refs) | — | 0 | 0 (10 gworkspace Sigma rules unmapped) | no | none |
| Workspace Admin | P0 | NO | same | — | 0 | 0 | no | none |
| Workspace OAuth Token | P0 | NO | same | — | 0 | 0 | no | none |
| Workspace Drive | P1 | NO | Reports only | — | 0 | 0 | no | none |
| Workspace SAML | P1 | NO | same | — | 0 | 0 | no | none |
| Workspace other apps / Alert Center | P2 | NO | — | — | 0 | 0 | no | none |
| Cloud Asset Inventory | P2 | NO | — | — | (reach-next) | — | no | none |
| Secure Web Proxy, VPN, reCAPTCHA | P3 | NO | — | — | 0 | — | no | none |

### 1d. Cross-cloud, SaaS identity and normalisation standards

| Log type | Pri | Status | Notes |
|---|---|---|---|
| Okta System Log | P0 | NO | 23 Okta Sigma rules are vendored but skipped as `unmapped_logsource` |
| Kubernetes audit (generic, EKS, AKS, GKE) | P0 | NO | GKE parses via `gcp_audit_json` with no rules |
| GitHub audit (org / enterprise, git events) | P1 | NO | GitHub Sigma rules unmapped |
| GitLab audit events | P2 | NO | — |
| Cloudflare `http_requests` | P1 | NO | — |
| Cloudflare `firewall_events` | P1 | NO | — |
| Cloudflare audit logs v1 / v2 | P1 | NO | — |
| Cloudflare Zero Trust (Access, Gateway) | P2 | NO | — |
| Cloudflare DNS / Spectrum / Workers / NEL | P3 | NO | — |
| OCI Audit | P2 | NO | — |
| Alibaba ActionTrail | P2 | NO (misroute risk) | It has `eventSource`, and `cloudtrail_json` `detect_any` is any-of, so a raw ActionTrail record probably routes as `cloudtrail_json` (untested). Then `src_ip` is lost (`sourceIpAddress` vs `sourceIPAddress`) and AWS rules may fire on Alibaba API names. Add a guard (`acsRegion` present → not CloudTrail) |
| Auth0 tenant logs | P1 | NO | — |
| Cisco Duo authentication | P1 | NO | — |
| Cisco Duo admin / activity | P2 | NO | — |
| OneLogin events | P2 | NO | — |
| Salesforce Event Monitoring / Setup Audit Trail | P2 | NO | — |
| Slack audit logs | P2 | NO | — |
| HashiCorp Vault audit | P1 | NO | — |
| OCSF (Security Lake and vendors) | P1 | NO | — |
| ECS exports (Elastic) | P1 | PART | `ecs_json` routes them; vendor namespaces (`okta.*`, `aws.cloudtrail.*`, `github.*`) are not aliased. `event.kind` / `event.severity` are stripped by design |

---

## 2. How cloud logging is built: what an ingester must handle

### 2a. One event, many shapes (the main lesson)

| Provider | Native record | Wrappers we must unwrap | SIEM re-shapes |
|---|---|---|---|
| AWS CloudTrail | Raw record | (1) S3 `{"Records":[...]}` `.json.gz`; (2) CloudWatch subscription: gzip+base64 `{messageType, logEvents[{message:"<json string>"}]}`, skip `CONTROL_MESSAGE`; Firehose concatenated gzip members; (3) EventBridge `{detail-type, detail:{record}}`; (4) LookupEvents `Events[].CloudTrailEvent` = JSON string; (5) Lake SQL rows | Sentinel `AWSCloudTrail` PascalCase; ECS `aws.cloudtrail.*`; OCSF 3005 Parquet |
| AWS flow / ALB / S3 access | Positional text | Header line in S3 files only. CloudWatch flow lines have no header, so the `LogFormat` string is needed | Sentinel `AWSVPCFlow`; OCSF 4001 |
| AWS findings | GuardDuty finding JSON | EventBridge `detail`; S3 export `.jsonl.gz` | Sentinel `AWSGuardDuty` (the type is in `ActivityType`) |
| Azure | Resource-log record (`time`, `resourceId`, `operationName`, `properties{}`) | Event Hub `{"records":[...]}`; storage `PT1H.json` (JSON Lines, but flow logs are ONE `{"records":[]}` document); Event Hubs Capture Avro | LA PascalCase tables; `AzureDiagnostics` `_s/_d/_g/_t` suffixes; CSV export with dynamic columns as JSON strings; Graph REST camelCase; Activity REST `operationName.value` |
| M365 UAL | Management API JSON | Content blobs = JSON arrays | Sentinel `OfficeActivity`; Purview CSV with an `AuditData` JSON string; Defender `CloudAppEvents.RawEventData` |
| GCP | LogEntry (`protoPayload` / `jsonPayload` / `textPayload`) | Pub/Sub `message.data` base64; `gcloud` JSON array; GCS shard = list; API `{entries[]}` | BigQuery `protopayload_auditlog.*`, `requestJson` / `metadataJson` strings; Log Analytics snake_case; Sentinel `GCPAuditLogs` |
| Workspace | Reports `activities.list` item | `{items[]}` pages; one item holds many `events[]`; `parameters[]` name/value lists | Cloud Logging shape (`protoPayload.metadata.event[]`) |
| Okta / Auth0 | LogEvent / log object | EventBridge `detail`; Okta hook `data.events[]`; Auth0 stream `{log_id, data}` | Sentinel `Okta_CL` `_s` columns; ECS `okta.*` |
| Kubernetes | `audit.k8s.io/v1` Event | EKS: CloudWatch `message` string; AKS: `log_s` / `properties.log` string; GKE: `protoPayload` with `methodName io.k8s.*` | `AKSAudit` dynamic columns |

Rule for our code: **detect the variant by key presence, never by file name**, and alias each variant in `config/sources.yaml`. This is the same fix we already made for Azure `properties.requestbody` vs `Properties_d`.

### 2b. Time formats (normalise in DuckDB, never via a text round-trip)

| Format | Where |
|---|---|
| ISO-8601 Z | CloudTrail `eventTime`, GuardDuty, Config, Route 53, Okta `published`, OCI |
| ISO with no Z, but UTC | M365 `CreationTime` |
| Epoch seconds | VPC / TGW flow `start` / `end`, NSG flow v2 tuples, Network Firewall `event_timestamp` (string or int), Slack, Duo |
| Epoch ms | WAF, OCSF `time`, CloudWatch `logEvents[].timestamp`, VNet flow v4 tuples, GitHub `@timestamp` |
| Epoch µs | Aurora MySQL audit |
| Epoch ns or RFC3339 | Cloudflare (per Logpush job) |
| `[06/Feb/2019:00:00:38 +0000]` | S3 access logs |
| `+0000` with no colon | Network Firewall `event.timestamp` |
| Separate date and time columns | CloudFront |
| `yyyyMMddHHmmss.SSS` | Salesforce `TIMESTAMP` (use `TIMESTAMP_DERIVED`) |

### 2c. Skip, dedupe and accounting rules

| Case | Handling |
|---|---|
| CloudTrail-Digest files, CloudWatch `CONTROL_MESSAGE`, flow `NODATA` / `SKIPDATA` | Count as **skipped with a reason**, not dropped |
| Org trail + account trail | Dedupe on `eventID`. Keep `sharedEventID` pairs (different `recipientAccountId`) |
| GuardDuty updates | Same finding `id`; keep the latest `updatedAt` |
| K8s audit stages | Keep `stage = ResponseComplete` |
| GCP VPC flow | Each flow is reported by SRC and by DEST; dedupe on 5-tuple + `start_time` |
| Vault | Request + response lines; join on `request.id` |
| GitHub streaming | At-least-once delivery; dedupe on `_document_id` |
| Cloudflare `firewall_events` | Several rows per `RayID` (`MatchIndex`) |

### 2d. Correlation keys that link one cloud attack path

| Key | Connects |
|---|---|
| Identity: AWS `accessKeyId` | Links the AssumeRole `responseElements.credentials.accessKeyId` to later calls, EKS `user.extra.accessKeyId` and the GuardDuty `accessKeyDetails` |
| Identity: Entra token | `UniqueTokenIdentifier` (sign-in) = `UniqueTokenId` (Graph); `SessionId` |
| Identity: GCP | `serviceAccountKeyName`; `serviceAccountDelegationInfo` |
| Identity: Okta | `authenticationContext.externalSessionId` |
| Identity: SAML | Okta / Workspace user → AWS `AssumeRoleWithSAML` RoleSessionName |
| Network | CloudTrail `sourceIPAddress` = ALB client = WAF `clientIp` = flow `srcaddr` / `pkt-srcaddr` = GuardDuty `remoteIpDetails` = Cloudflare `ClientIP` |
| Host | AWS ENI / `instance-id` (flow, Route 53 `srcids.instance`, CloudTrail RunInstances, Config); GCP `src_instance.vm_name`; Azure MAC + NIC |
| Request | ALB `trace_id` = WAF `requestId`; Config `relatedEvents` = CloudTrail `eventID`; AppGW `transactionId` |

### 2e. Our two key-name traps

1. **`labels` strip.** `sources.yaml label_keys: [threat, rule, labels, labels_extra]` removes the top-level `labels` key.
   - AWS WAF: `labels` holds vendor labels.
   - GCP LogEntry and GKE: `labels` holds real evidence such as `authorization.k8s.io/decision` and `command.gke.io/command`. We currently lose it.
2. **ECS `event.kind` / `event.severity` strip.** This is correct for generator data. For real ECS exports, detection must use `event.dataset`, `event.action` and `event.outcome`, never `event.kind`.

---

## 3. Claims audit

Verdicts: FALSE = wrong today. UNTESTED = no test or run backs it. PARTIAL = true only in part. TRUE = verified in this audit.

### 3a. FALSE

| Claim | Where | Evidence | Fix |
|---|---|---|---|
| "Cloud accuracy, run time and RAM: not measured yet." | README.md:67 | `cloud_small` scorecard: detection 76.74 %, labels 78.79 %, rebuilt 40 %, FA 36.36 %, step precision 41.1 %. `run_metrics`: 25,394 rows in = ok, 16.16 s, 527.1 MB. A6, A7 and A9 score 0 steps | Quote the files, with the caveat "synthetic set from our own generator, 29 MB, 10 attacks; not a public dataset". Add the ext-eval numbers when `reports/ext/cloud*.md` lands |
| "Known limit: no overlap window; late-indexed data is not pulled." | README.md:124; DEVELOPMENT.md:442 | `base.py:18-20` overlap 10 min + dedupe; `test_azure_checkpoint_overlap_dedupes_and_late_row_is_written`, `test_audit_late_row_inside_overlap_is_pulled_next_cycle` pass | Replace with "rows indexed later than the 10 min overlap are missed (raise `overlap`)" |
| "Known limit: Sentinel can get stuck on a page where every row has the same timestamp." | README.md:125; DEVELOPMENT.md:393, 443 | Keyset paging on (`TimeGenerated`, `AlId`), `loganalytics.py:9-14`; two tests pass | Delete; describe keyset paging |
| "Known limit: a Splunk first pull is all-or-nothing." | README.md:126; DEVELOPMENT.md:444 | `commit_every_pages: 1`; `test_commit_every_page_keeps_committed_pages_after_a_failure` passes | "A failed chunk is re-pulled; committed chunks are kept." |
| "detect.py hook for native cloud detection (NOT applied)" | reports/cloud/detect_hook.md:1 | `detect.py:245-246` calls `detect_cloud.run_cloud`; `run_metrics` shows 763 cloud alerts, 87 rules | Retitle as applied. Keep the true note: `cloud_baseline.parquet` for live mode is not built |
| "Nothing in code changed; no Sigma cloud rule compiles today" | reports/cloud/rule_catalog.md:3, 32 | `sigma_map.yaml:187-307` `cloud_logsources`; 70 rules run (aws 44, audit 11, activity 9, signin 3, gcp 3), matches `run_metrics sigma_rules_applicable 70` | Add a dated status header and strike the done items in §8 |
| "Behavioural / anomaly rules detect novel attacks" | reports/cloud/rule_catalog.md:711 | The NOVEL stories score A6 0/3 and A7 0/3. Geo is prefix only (`asn_db false`) | Tune (gap P0-10). Until then: "designed for novel attacks; 0/2 novel stories detected in our own synthetic set" |
| "Sigma cloud patch: DRAFT, nothing applied; compiled aws 52, activity 26, audit 35, signin 15, gcp 6" | reports/cloud/sigma_patch.md:1-5, 200 | `sigma_rules.py:45 RUNTIME_KEYS` include `cloud_disable`; running counts 44/9/11/3/3; 37 forced to level low | Mark as applied; report compiled vs running vs context-only |
| "REST / Event Grid shape needs the `$.operationName.value` alias first" | config/sigma_map.yaml:226-227 | The alias exists at `sources.yaml:196, 204`; two tests pass | Delete the comment |
| "Bug 2: S3 mode ignores endpoint_url; boto3 not installed" | reports/integrations/live.md:96, 110-114 | `aws_cloudtrail.py:137-139` fallback; `test_aws_s3_endpoint_from_the_form_endpoint_url` passes; boto3 imports | Mark fixed. Live rows stay NOT RUN |

### 3b. UNTESTED

| Claim | Where | Evidence | Fix |
|---|---|---|---|
| "Stratus: all 93 cloud techniques mapped; 82 detectable from default logs" | rule_catalog.md:27-29 | No Stratus fixture or eval. 15 rules have unit positives. 3 of 10 synthetic attacks are fully missed | Say "mapped on paper", or build per-technique fixtures and report the hit rate |
| Azure Monitor default tables include the AAD non-interactive / SP / MI sign-in tables | azure_monitor.py:4-5; integrations.yaml:310-313 | KQL asserted for only the first 3 tables; no fixture, generator row or mock table | Add one row per table to `fixtures/cloud` and mock `la_query`; assert `source_type` + user |
| Azure Monitor alerts mode (SecurityAlert) | azure_monitor.py:12; integrations.yaml:323 | Only the `sentinel` SecurityAlert path is tested | Test `azure_monitor` alerts mode against the mock |
| StorageBlobLogs optional table | azure_monitor.py:6-7; integrations.yaml:314-315 | `optional_tables()` / `all_tables()` have no test | Unit test the template, plus rejection of invalid names |
| STS `role_arn` assume; org-trail prefix | aws_cloudtrail.py:11, 127-134 | No test references `role_arn` / `assume_role` | Fake-boto3 test asserting `RoleArn`, `ExternalId` and the derived session |
| Credentials JSON read in the browser, sent only on save | ConnectionForm.tsx:339; FieldInput.tsx:179 | No frontend test covers the integrations components | Component test: no fetch on file load |
| Mock seed hides cross-cloud story C1 | tools/mock_cloud_seed.py:3-15 | Tests only check that files are written. Every `cloud_small` attack is single-cloud | Pipeline test on `seed.write()`: one incident across 3 clouds. Add a cross-cloud story to `tools/cloud_attacks` |
| Connector events reach live mode and are detected | integrations.yaml:21-22; README.md:72 | The e2e test fakes the live spawn. Live lookback is 72 h, but the cloud baseline wants 14 d | Live test on the `cloud_small` spool; persist `data/state/cloud_baseline.parquet` |

### 3c. PARTIAL

| Claim | Where | Evidence | Fix |
|---|---|---|---|
| "Exported JSON files also work without any connector" | README.md:60 | One-per-line works. `{Records}`, `.gz`, arrays, pretty JSON, Azure `{records}` and GCP Pub/Sub all come out unrecognized | Gap P0-1 (unwrap). Until then: "JSON Lines only; CloudTrail S3 `.json.gz` goes through the S3 connector" |
| "Pull connectors for cloud logs: aws_cloudtrail, azure_monitor, sentinel, gcp_logging" | README.md:59 | The `sentinel` default query is SecurityEvent → ECS, not cloud | "For Entra / Activity in a Sentinel workspace use `azure_monitor`" |
| "Pull command `--source elastic\|splunk\|sentinel\|syslog`" | README.md:76; DEVELOPMENT.md:334, 355-356 | `choices=connectors.SOURCES` also includes the 3 cloud sources | List all 7; add cloud rows to the DEVELOPMENT.md connector table |
| "Cloud formats: cloudtrail_json (one per line), azure_* , gcp_audit_json" | README.md:56-58 | All 5 route with no drops. The Azure export shapes have no fixture, and AuditLogs export loses user, target and outcome | Gap P0-3 (aliases + fixtures) |
| Architecture diagram | README.md:367-371 | Omits the cloud connectors and formats | Add "Cloud (AWS CloudTrail, Azure Monitor/Entra, GCP Audit)" to the inbound box |
| "`{Records}` files are unpacked by the aws_cloudtrail connector" | sources.yaml:104 | S3 mode only | "connector S3 mode only", or implement P0-1 |
| "Digest always skipped; Insight / NetworkActivity when enabled" | integrations.yaml:285-286 | Key skipping is tested; record mapping is not | Add one Insight and one NetworkActivity record to `fixtures/cloud/cloudtrail.jsonl` |
| Geo: optional ASN DB / ranges / centroids, else /16 or /48 | cloud.yaml:28-36; README.md:63-64 | The prefix fallback is tested; loading the DB has no test. rule_catalog §8 says /24 + /16 | ip2asn TSV fixture test; fix rule_catalog to /16 and /48 |
| UI: "Connect the SIEM or cloud account you already use…" | ConnectionsPage.tsx:157 | Mock-verified only. AWS = LookupEvents (management events, 1 region, 90 d) | Add a sub-line per cloud tile: what is pulled, "tested against a local mock" |
| Mock catalog describes the cloud connectors | frontend/src/mock/integrations_catalog.json | Drifts from the backend CATALOG (AWS source select, Azure modes, GCP keys) | Regenerate from `GET /api/integrations/catalog`, plus a key/mode diff test |

### 3d. TRUE (keep)

| Claim | Where | Note |
|---|---|---|
| Integrations verified against the local mock only | README.md:36-37 | Extend the sentence to cover the AWS, Azure and GCP accounts |
| `backend[cloud]` extra needed for boto3 / cryptography | README.md:39-40 | Tested |
| 69 native + 18 behavioural = 87 rules | README.md:61 | Optional: add "70 Sigma cloud rules run; 15 / 87 have unit positives" |
| Azure / GCP token caching, refresh once on 401, no secrets in errors | cloud_auth.py | Tested |
| GCP entries.list paging, 60 req/min, id = `logName\|insertId` | gcp_logging.py:1-7 | Add "(mock only)" |
| AWS LookupEvents slices + S3 LastModified order | aws_cloudtrail.py:3-9 | Add "mock only; LocalStack not run" |
| Every connector and sink is disabled by default; secrets as env-var names | integrations.yaml:9-13 | — |
| `cloud.yaml` never references label paths | cloud.yaml:6-7 | Tested by grep |

---

## 4. Competitors vs AttackLens

| Product | What they claim (short) | AttackLens today |
|---|---|---|
| Elastic Security | AWS: CloudTrail, CloudFront, ELB, Network Firewall, Route 53, S3 access, VPC Flow, WAF, GuardDuty, Inspector, Config, Security Hub. Azure: Activity, Entra (all sign-in types, audit, risk, provisioning), Graph activity, Firewall, AppGW. GCP: audit, firewall, VPC flow, DNS, LB. Workspace (20+ apps), Okta, GitHub, Cloudflare (23 datasets), Duo, Auth0, Vault, K8s audit. ECS | 5 cloud source types; no network, findings or SaaS |
| Microsoft Sentinel | S3 connector: CloudTrail, VPC Flow, GuardDuty, CloudWatch. GCP Pub/Sub: audit, SCC, GKE. Full Entra / M365 / Defender; Okta, GitHub, Cloudflare, Auth0, Duo, Salesforce, Slack, OCI, Alibaba. ASIM | Pulls Activity / Entra / blob via LA; SecurityAlert as alerts |
| Splunk ES | `aws:cloudtrail`, vpcflow, s3 / elb / cloudfront access, GuardDuty, Security Hub, Inspector, Config, TGW flow, Security Lake (`aws:asl`); O365 UAL; Workspace; Okta; Duo; K8s; GitHub. CIM | Same 5 types |
| Panther | AWS: ALB, Aurora, Bedrock, CloudTrail, Config, EKS, GuardDuty, NLB, Security Hub, Security Lake, S3, TGW, VPC, WAF. GCP: audit, DNS, firewall, HTTP LB, Access Transparency; GSuite; Okta via API or EventBridge | Same |
| Datadog Cloud SIEM | Official AWS guide covers CloudTrail only; OOTB rules on CloudTrail, Entra sign-in, M365, GCP, Workspace, GitHub, Okta, Duo, Cloudflare | We match on CloudTrail / Entra depth; behind on SaaS |
| Google SecOps | Broadest GCP coverage: audit, DNS, firewall, LB, NAT, VPC flow, SWP, NGFW, IDS, SQL, GKE, Run, Workspace, SCC. Also CloudTrail, VPC Flow, GuardDuty, Azure AD / Activity, Okta, GitHub, Duo, Vault, Slack, Salesforce, OCI | Only GCP audit |
| AWS GuardDuty (native) | Reads CloudTrail, VPC flow and DNS without customer logging. AttackSequence findings = multi-stage path with MITRE tags | Our closest rival on "attack path". We should ingest its findings as a seed and validation source |
| SigmaHQ | `rules/cloud`: aws, azure, gcp, m365. Okta, GitHub and K8s live elsewhere | We run 70 cloud Sigma rules. Okta 23, riskdetection 19, m365 19, gworkspace 10 and PIM 7 are vendored but unmapped |

**Where we are ahead** (per the stated claims, not head-to-head tests):
- One attack path across clouds and hosts, ATT&CK v20 labels per step, and reach-next.
- Measured, reproducible scores from our own harness.
- Fully offline.
- None of the competitors above publishes a per-step detection / rebuild score.

**Where we are behind**: breadth.
- Every competitor ingests VPC flow and GuardDuty.
- Most ingest Okta, M365 UAL and K8s audit.
- All handle the native delivery wrappers: S3 `{Records}` gz, Event Hub `records[]`, Pub/Sub.

---

## 5. Prioritised gap plan

Order:
- P0 first.
- Inside a priority, gaps are sorted by attack value per unit of effort.
- Effort: S ≈ under 2 h, M ≈ half a day, L ≈ more than a day.
- **Today** = S or M, finishable in this session's remaining time if run in parallel on disjoint files.

Shared patterns, so each plan stays short:
- **New JSON source** = a `json_sources` entry in `config/sources.yaml`:
  - put it before any entry whose `detect_any` it would also hit
  - write `fields` with every shape variant's path
  - add `outcome_map`, `action_map`, `value_regex` and `ip_fields` as needed
  - add cloud-detection columns to `config/cloud.yaml columns` with `src: [<new type>]`, plus an `is_<x>` macro
  - add rules to `config/rules_cloud.yaml` (extend the `clouds` enum in `detect_cloud*.py` when the provider is new)
- **Network-shaped sources** (flow, firewall, DNS) map to the canonical columns `src_ip`, `dst_ip`, `src_port`, `dst_port`, `bytes`, `event_action` and `dst_domain`. The existing `config/rules.yaml` templates (`port_scan`, `beaconing`, exfil volume T1048) then apply with no new code.
- **Vendor findings** (GuardDuty, Security Hub, SCC, Defender) go ONLY through alert-input mode (`attacklens/siem_alerts.py` → `raw_alerts`). They never feed the scored raw-event detectors, under the "detect from raw fields only" rule.
- **Generator**: in `tools/cloud_attacks/formats.py`, add a feed function and an `entity()` branch, plus a `CONNECTOR` entry in `story.py`. Add benign baseline rows in `baseline.py`, and an attack `Story` in `stories.py` whose ground truth comes from the step's first event.
- **Tests**:
  - an ingest fixture per shape in `backend/tests/test_ingest_cloud.py`
  - a positive and a near-miss per rule in `test_detect_cloud*.py`
  - a generator schema test in `test_cloud_attacks_gen.py`
  - then a `cloud_small` re-run through `jobq`
- Probes and `backend/eval/**` are untouched.

### P0

| # | Gap | Kind | Effort | Today |
|---|---|---|---|---|
| P0-1 | Stage 0 envelope unwrap (all providers) | new_shape | M | yes |
| P0-2 | Fix FALSE / stale claims | claim_fix | S | yes |
| P0-3 | Azure export-shape aliases + AAD* fixtures | new_shape | S | yes |
| P0-4 | Keep GCP / GKE LogEntry `labels` | new_shape | S | yes |
| P0-5 | AWS VPC Flow Logs | new_source | M | yes |
| P0-6 | GuardDuty findings (alert-input) | new_source | M | yes |
| P0-7 | Okta System Log + 23 Sigma rules | new_source | M | yes |
| P0-8 | Kubernetes audit (generic / EKS / AKS) + GKE rules | new_source | M | yes |
| P0-9 | Azure Key Vault AuditEvent | new_source | S | yes |
| P0-10 | Tune the misses A6 / A7 / A9 | new_rules | M | yes |
| P0-11 | Workspace Reports (login / admin / token) | new_source | M | yes |
| P0-12 | M365 UAL (Exchange, SharePoint) file shapes | new_source | M | stretch |
| P0-13 | Microsoft Graph activity logs | new_source | M | stretch |
| P0-14 | GCP VPC flow | new_source | S | yes (after P0-5) |
| P0-15 | AWS S3 data-event rules completed | new_rules | S | yes |
| P0-16 | Connectors for Okta / M365 / Workspace | connector | L | later |

**P0-1 Stage 0 envelope unwrap** (M, today)
- What: a pre-step in `profile.py` / `ingest.py`, e.g. a new `attacklens/unwrap.py` under 400 lines.
- It writes per-record JSONL beside the source in `work/unwrapped/`.
- DuckDB does the heavy work: `read_json(..., format='auto')` + `unnest(Records)`. Never explode the records in Python.
- Shapes, chosen by key presence:

  | Shape | Unwrap step |
  |---|---|
  | `{"Records":[...]}` | unnest `Records` |
  | `{"records":[...]}` | unnest `records` (Azure Event Hub, NSG / VNet flow, Defender streaming) |
  | JSON array (`gcloud`, GCS shard, M365 content blob) | one record per element |
  | `{entries:[...]}` / `{items:[...]}` | unnest the page |
  | EventBridge `detail` | lift `detail` to the top level |
  | CloudWatch subscription `logEvents[].message` | gzip+base64 decode, then parse each `message` |
  | Pub/Sub `message.data` | base64 decode |
  | LookupEvents `Events[].CloudTrailEvent` | second `json()` parse of the string |
  | `.gz` and `.tar` | decompress / iterate members (stream them; never load everything into memory) |
  | Pretty-printed single document | parse as one document |

- Skip CloudTrail-Digest and `CONTROL_MESSAGE`, and count them as `skipped_reason` in `ingest_accounting.json` (both the container rows and the unwrapped rows).
- Config: `config/pipeline.yaml unwrap:` with the path, key and decoder list.
- Tests:
  - fixtures for each shape in `backend/tests/fixtures/cloud/wrapped/`
  - assert rows in = rows out and the same `source_type` as the JSONL version
  - flaws.cloud tar sample (10 records) end to end
- Retires `tools/ext/cloud_stream.py`. Coordinate with the ext-eval session.

**P0-2 Claim fixes** (S, today)
- Apply every FIX in §3a and §3c to `README.md`, `docs/DEVELOPMENT.md`, `reports/cloud/{detect_hook,rule_catalog,sigma_patch}.md`, `reports/integrations/live.md` and the `sigma_map.yaml:226` comment.
- Owner: `doc-writer` for README / docs. The config comment and `reports/cloud/**` belong to cyberforge-0c.
- Quote the `cloud_small` numbers with the synthetic-set caveat.

**P0-3 Azure export shapes** (S, today)
- `azure_activity_json` additions:

  | Field | Alias(es) to add |
  |---|---|
  | `user` | `$.properties.initiatedBy.user.userPrincipalName`, `$.properties.initiatedBy.app.displayName`, `$.identity.claims."http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"` (BEFORE `claims.name`), `$.identity.claims.appid` |
  | `target_name` | `$.properties.targetResources[0].userPrincipalName` |
  | `outcome` | `$.properties.result` |
  | `event_action` | `$.properties.activityDisplayName` |

- `azure_signin_json`: add `cloud.yaml` columns `si_ua` (`UserAgent`, `properties.userAgent`), `si_proto` (`AuthenticationProtocol`), `si_tokid` (`UniqueTokenIdentifier`), `si_sess` (`SessionId`), `si_risk` (`RiskLevelDuringSignIn`), `si_asn` (`AutonomousSystemNumber`).
- In the AAD* tables, `Status`, `LocationDetails` and `DeviceDetail` are strings: use `json(...)` before extract.
- Rules:
  - `az_device_code_signin`: T1528, Credential Access (`si_proto = 'deviceCode'`)
  - `az_token_replay_new_net`: T1550.001, Lateral Movement (same `si_sess` from 2 networks)
- Tests: one export row per type (signin, AuditLogs, Activity with the claims URI), plus one `AADServicePrincipalSignInLogs` and one `AADNonInteractiveUserSignInLogs` row, in `fixtures/cloud` and in mock `la_query`.
- Generator: a `signin(..., shape='export')` variant for 10 % of rows.

**P0-4 Keep GCP / GKE `labels`** (S, today)
- Problem: `label_keys` strips the top-level `labels`.
- Fix: add `label_keys_by_source: {gcp_audit_json: [threat, rule, labels_extra]}`. Rename the vendor `labels` to `log_labels` in `raw_line` before the generic strip.
- Accounting: count `labels_kept` per source.
- Guard test: the `tools/cloud_attacks` GCP rows never carry a ground-truth `labels` key. Add the assert in `test_cloud_attacks_gen.py`.
- Add `cloud.yaml` columns `g_k8s_decision` (`$.log_labels."authorization.k8s.io/decision"`) and `g_k8s_cmd`.
- Do the same scoping for a future WAF source (P1-9).

**P0-5 AWS VPC Flow Logs** (M, today)
- New text source `aws_vpcflow_txt` under `csv_sources` with `delimiter: ' '`.
- Detection: header names (`srcaddr`, `dstaddr`, `log-status`, `interface-id`) with `min_matches: 3`.
- Headerless CloudWatch lines: `config/cloud.yaml vpcflow.default_format` (v2 order), overridable by a configured `LogFormat` string. Never assume v2 positions when a header exists.
- Field mapping:

  | Canonical field | Flow-log field(s) |
  |---|---|
  | `ts` | `start` (epoch s, `ts_unit: s`) |
  | `src_ip` | `pkt-srcaddr`, else `srcaddr` (NAT) |
  | `dst_ip` | `pkt-dstaddr`, else `dstaddr` |
  | `src_port` | `srcport` |
  | `dst_port` | `dstport` |
  | `bytes` | `bytes` |
  | `event_action` | `action` (`ACCEPT` → allow, `REJECT` → deny) |
  | `host` | `instance-id`, else `interface-id` |
  | `app` | `protocol` |

- `-` maps to NULL. `NODATA` / `SKIPDATA` rows are counted as skipped.
- Also accept the Parquet shape (`pkt_srcaddr` underscore names) via `read_parquet`, and the OCSF 4001 fields after P1-1.
- Rules:
  - The existing `port_scan` (T1046), `beaconing` (T1071.001) and exfil (T1048) apply through the canonical columns.
  - New `cl_flow_mining_port`: T1496.001, Impact. Ports `{cfg.mining_ports}` = 3333, 4444, 14444, …
  - New `cl_flow_inbound_admin_accept`: T1133, Initial Access. ACCEPT to 22 / 3389 from a public IP after `AuthorizeSecurityGroupIngress` 0.0.0.0/0, via a `sequence` with `a_rules` on the SG rule (T1686.001).
- Linking: `host:i-…` matches the CloudTrail RunInstances `instanceId`.
- Generator: a `flow()` feed, 30 k benign rows per day, written as a header file in `aws_vpcflow/` plus a headerless CloudWatch variant.
  - Story A11: stolen instance-role key used off-host (CloudTrail) → instance scans 10.0.0.0/24 (flow REJECT burst) → large egress to a new IP.
  - Ground truth: T1552.005, T1046, T1048.
- Tests: header vs headerless vs custom-order fixture; NODATA accounting; port_scan positive on flow rows.

**P0-6 GuardDuty findings, alert-input only** (M, today)
- Mapping: in `config/integrations.yaml siem_alerts.sources.guardduty`.
- Shapes: bare finding (S3 export `.jsonl.gz`, via P0-1), EventBridge `detail`, API `Findings[]`.
- Field mapping:

  | Canonical field | GuardDuty field |
  |---|---|
  | `ts` | `service.eventFirstSeen`, else `createdAt` |
  | `signature` | `type` |
  | `severity` | `severity × 10` |
  | `user` | `resource.accessKeyDetails.userName` |
  | `key` | `accessKeyId` |
  | `src_ip` | `service.action.awsApiCallAction.remoteIpDetails.ipAddressV4`, or `networkConnectionAction.remoteIpDetails.ipAddressV4` |
  | `host` | `resource.instanceDetails.instanceId`, else `accountId` |

- Technique comes from `config/guardduty_map.yaml`:
  - ThreatPurpose prefix → tactic.
  - Known types → v20 ids: `InstanceCredentialExfiltration` → T1552.005, `Recon:EC2/Portscan` → T1046, `CloudTrailLoggingDisabled` → T1685.002, `DNSDataExfiltration` → T1071.004, `ContainerMountsHostDirectory` → T1611, `Exfiltration:S3/AnomalousBehavior` → T1530.
  - AttackSequence: read `service.detection.sequence.sequenceIndicators` (ATTACK_TECHNIQUE values).
- Dedupe: on `id`, keep the latest `updatedAt`.
- Generator: `tools/cloud_attacks` emits a GuardDuty finding for story A1 into `siem_alerts/guardduty/` (not scored as raw).
- Tests: three shapes → the same `raw_alerts` row; dedupe; never in `cloud_ev`.

**P0-7 Okta System Log** (M, today)
- New `okta_json`, with `detect_any: ["eventType", "legacyEventType", "authenticationContext"]`.
- Field mapping:

  | Canonical field | Okta field(s) |
  |---|---|
  | `ts` | `published` |
  | `event_action` / `signature` | `eventType` |
  | `outcome` | `outcome.result` (SUCCESS / ALLOW → success; FAILURE / DENY → failure; CHALLENGE / SKIPPED → NULL) |
  | `user` | `actor.alternateId` |
  | `target_name` | `target[0].alternateId` |
  | `src_ip` | `client.ipAddress`, else `request.ipChain[0].ip` |
  | `host` | `okta:<org>` from `debugContext` or the config `okta.org` |
  | `app` | `client.userAgent.rawUserAgent` |

- `cloud.yaml` columns: `ok_sess` (`authenticationContext.externalSessionId`), `ok_asn` (`securityContext.asNumber`), `ok_reason` (`outcome.reason`), `ok_cred` (`authenticationContext.credentialType`).
- Shapes: bare; EventBridge `detail` (P0-1); Event Hook `data.events[]` (P0-1); ECS `okta.*` aliases.
- Sigma: map logsource `product: okta, service: okta` → `okta_json` in `sigma_map.yaml cloud_logsources`. The fields are native Okta names, so this adds up to 23 rules.
- Native rules, `clouds: [okta]`:

  | Rule | Technique | Tactic | Logic |
  |---|---|---|---|
  | `okta_password_spray` | T1110.003 | Credential Access | `distinct_burst` users per IP |
  | `okta_mfa_push_fatigue` | T1621 | Credential Access | ≥ 5 `user.mfa.okta_verify.deny_push` / timeouts, then success |
  | `okta_session_hijack` | T1550.004 | Lateral Movement | `multi_network_session` on `ok_sess` |
  | `okta_admin_grant` | T1098.003 | Persistence | `user.account.privilege.grant` |
  | `okta_new_idp` | T1484.002 | Privilege Escalation | `system.idp.lifecycle.create` |
  | `okta_factor_reset` | T1556.006 | Persistence | factor deactivate / reset |
  | `okta_api_token` | T1098.001 | Persistence | `system.api_token.create` |

- Linking: the Okta user email → AWS `AssumeRoleWithSAML` session name (existing `value_regex`).
- Generator: an `okta()` feed with benign logins; story C2 (spray → MFA fatigue → session from a new ASN → SAML into AWS → CreateAccessKey). This is the first cross-source story.
- Tests: 3 shapes, 7 rules, plus a Sigma compile count.
- Connector `okta_logs` (`/api/v1/logs` Link-next) is part of P0-16.

**P0-8 Kubernetes audit** (M, today)
- New `k8s_audit_json`, with `detect_any: ["auditID", "objectRef", "requestReceivedTimestamp"]`.
- Field mapping:

  | Canonical field | Audit field |
  |---|---|
  | `ts` | `requestReceivedTimestamp` |
  | `event_action` | `verb` |
  | `signature` | `verb` + `objectRef.resource` + `/` + `objectRef.subresource` |
  | `user` | `impersonatedUser.username`, else `user.username` |
  | `src_ip` | `sourceIPs[0]` |
  | `host` | cluster from config or `_ResourceId`, else `k8s` |
  | `target_name` | `objectRef.namespace` + `/` + `objectRef.name` |
  | `outcome` | `responseStatus.code` (< 400 success) |

- Keep only `stage = ResponseComplete` (others counted as skipped).
- Shapes:
  - generic JSONL
  - EKS CloudWatch `message` string (P0-1)
  - AKS `AKSAudit` PascalCase: `Verb`, `User`, `SourceIps`, `ObjectRef`, `ResponseStatus`
  - AKS `AzureDiagnostics.log_s` / Event Hub `properties.log` (string → re-parse in P0-1)
- GKE needs no new source: add rules on `is_gcp AND g_svc = 'k8s.io'` over `methodName io.k8s.*` and the `log_labels` from P0-4.
- Rules, `clouds: [k8s, gcp]`:

  | Rule | Technique | Tactic | Logic |
  |---|---|---|---|
  | `k8s_exec` | T1609 | Execution | exec / attach create |
  | `k8s_privileged_pod` | T1610 + T1611 | Execution / Privilege Escalation | `requestObject.spec` privileged / hostPID / hostPath |
  | `k8s_cluster_admin_binding` | T1098.006 | Persistence | clusterrolebinding create to cluster-admin |
  | `k8s_secrets_sweep` | T1552.007 | Credential Access | `distinct_burst` namespaces on secrets get / list |
  | `k8s_sa_token_create` | T1528 | Credential Access | serviceaccounts/token create |
  | `k8s_anon_or_forbid_burst` | T1613 | Discovery | anonymous or forbidden burst |

- EKS `user.extra.accessKeyId` links to the CloudTrail key.
- Generator: `k8s()` feed; story A12 (CloudTrail AssumeRole → kubectl exec → secrets list → cluster-admin binding).
- Tests: 4 shapes → the same columns; 6 rules positive and near-miss.

**P0-9 Azure Key Vault** (S, today)
- New `azure_keyvault_json`, placed before `azure_activity_json`.
- `detect_any: ["properties.clientInfo", "ClientInfo", "clientInfo_s", "requestUri_s"]`.
- Field mapping:

  | Canonical field | Key Vault field(s) |
  |---|---|
  | `ts` | `time`, `TimeGenerated` |
  | `signature` | `operationName`, `OperationName` |
  | `outcome` | `resultSignature`, `ResultSignature`, `httpStatusCode_d` (OK → success) |
  | `user` | `identity.claim."http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"`, `identity_claim_http_schemas_xmlsoap_org_ws_2005_05_identity_claims_upn_s`, `identity.claim.appid` |
  | `src_ip` | `callerIpAddress`, `CallerIPAddress` |
  | `host` | `resourceId` |
  | `file_path` | `properties.id`, `id_s` |

- Rules:
  - `az_kv_secret_sweep`: T1555.006, Credential Access. `distinct_burst` secret ids per actor; promote first_seen.
  - `az_kv_forbidden_then_get`: T1555.006 (`sequence` from Forbidden to OK).
  - `az_kv_purge`: T1485, Impact (`SecretPurge` / `KeyPurge`).
  - `az_kv_cmk_delete`: T1486, Impact.
- Generator: `kv()` feed; add the KV steps to story A3.
- Tests: 3 shapes; 4 rules.

**P0-10 Tune the misses** (M, today)
- Run against `cloud_small`, using rules and thresholds only; the harness is never tuned.
- A6 (dormant identity + new ASN + 403 spike): add a `cl_dormant_identity_wakeup` branch (T1078.004) when the actor is idle for ≥ 30 d, then active from a new network. Feed `denied` rate_spike as the second signal.
- A7 (first-seen country + rare reads + blob spike): check `cl_storage_data_access` cold-start (`st_store_history_days`) and the geo prefix fallback; add a /16-first-seen branch.
- A9 (GCS enumeration → copy out): check that `objects.list` / `objects.get` bursts reach `cl_discovery_burst` and `cl_exfil_volume` (GCS `numResponseItems`, rewrite / copy to a foreign bucket → T1537).
- Exit gate: A6, A7 and A9 at ≥ 2/3 steps; FA not higher than 36.36 %; probes pass.

**P0-11 Google Workspace Reports** (M, today, needs P0-1 explode)
- New `gws_reports_json`, with `detect_any: ["id.applicationName", "id.uniqueQualifier"]`.
- Explode `events[]` (one row per event; count `events_exploded`).
- Pivot `parameters[]` to a map column `gw_params` via DuckDB `map_from_entries(list_transform(...))`. Read `value` / `boolValue` / `intValue` / `multiValue`.
- Field mapping:

  | Canonical field | Reports field |
  |---|---|
  | `ts` | `id.time` |
  | `signature` / `event_action` | `events.name` |
  | `app` | `id.applicationName` |
  | `user` | `actor.email` |
  | `src_ip` | `ipAddress` |
  | `host` | `gws:<customerId>` |
  | `outcome` | `login_failure` → failure, `login_success` → success |

- The Cloud Logging shape already routes as `gcp_audit_json`: add an `is_gws` macro on `g_svc IN ('login.googleapis.com', 'admin.googleapis.com', 'oauth2.googleapis.com')` so the same rules run.
- Rules:

  | Rule | Technique | Tactic | Logic |
  |---|---|---|---|
  | `gws_password_spray` | T1110.003 | Credential Access | — |
  | `gws_suspicious_login` | T1078.004 | Initial Access | `is_suspicious` |
  | `gws_super_admin_grant` | T1098.003 | Persistence | `ASSIGN_ROLE` `_SEED_ADMIN_ROLE` / `GRANT_ADMIN_PRIVILEGE` |
  | `gws_2sv_disable` | T1556.006 | Persistence | — |
  | `gws_oauth_broad_scope` | T1528 | Credential Access | `authorize` with `https://mail.google.com/` or `drive` scope from a new `client_id` |
  | `gws_dwd_grant` | T1550.001 | Lateral Movement | `AUTHORIZE_API_CLIENT_ACCESS` |

- Sigma: map `product: google_workspace` (Cloud Logging field names) → `gcp_audit_json` with `is_gws`, which adds up to 10 rules.
- Generator: `gws()` feed; story A13 (spray → success → OAuth mail scope → super-admin grant).
- Tests: both shapes; explode accounting.

**P0-12 M365 UAL, file shapes** (M, stretch; connector in P0-16)
- New `m365_ual_json`, with `detect_any: ["Workload", "RecordType", "OfficeWorkload"]` + `Operation`.
- Purview CSV: parse the `AuditData` JSON string (P0-1 decoder). `CloudAppEvents`: lift `RawEventData`.
- Field mapping:

  | Canonical field | UAL field(s) |
  |---|---|
  | `ts` | `CreationTime` (no Z = UTC), `TimeGenerated` |
  | `signature` | `Operation` |
  | `user` | `UserId` |
  | `src_ip` | `ClientIP`, `ClientIPAddress`, `ActorIpAddress` (strip `[::ffff:]` and `:port` with `value_regex`) |
  | `host` | `m365:<OrganizationId>` |
  | `app` | `Workload` |
  | `file_path` | `ObjectId` |
  | `outcome` | `ResultStatus` |

- `cloud.yaml`: `m3_params` (`Parameters`), `m3_logon_type`, `m3_client_app` (`AppId`).
- Rules:

  | Rule | Technique | Tactic | Logic |
  |---|---|---|---|
  | `m365_inbox_forward_rule` | T1114.003 | Collection | `New-InboxRule` / `Set-InboxRule` / `Set-Mailbox` `ForwardTo` / `RedirectTo` / `ForwardingSmtpAddress` |
  | `m365_hiding_rule` | T1564.008 | Stealth | MoveToFolder RSS / DeleteMessage |
  | `m365_mailbox_perm` | T1098.002 | Persistence | — |
  | `m365_mail_access_by_app` | T1114.002 | Collection | — |
  | `m365_mass_download` | T1213.002 | Collection | `distinct_burst` FileDownloaded |
  | `m365_anon_link` | T1567 | Exfiltration | AnonymousLinkCreated |
  | `m365_audit_disable` | T1685.002 | Defense Impairment | `Set-AdminAuditLogConfig` |

- Sigma: map m365 audit / threat_management logsources (19 rules).
- Generator: `ual()` feed; extend story A4 with the forwarding rule.

**P0-13 Microsoft Graph activity logs** (M, stretch)
- New `graph_activity_json`, with `detect_any: ["RequestUri", "properties.requestUri"]` + `SignInActivityId`.
- Field mapping:

  | Canonical field | Graph field |
  |---|---|
  | `ts` | `TimeGenerated` / `time` |
  | `signature` | `RequestMethod` + path template |
  | `user` | `UserId`, else `ServicePrincipalId` |
  | `src_ip` | `IPAddress` |
  | `app` | `UserAgent` |
  | `outcome` | `ResponseStatusCode` |

- Rules:
  - `graph_enum_burst`: T1087.004, Discovery. `distinct_burst` over `/users`, `/groups`, `/servicePrincipals`, `/directoryRoles`; AzureHound / ROADtools user agents raise severity.
  - `graph_mail_read`: T1114.002.
  - `graph_add_password`: T1098.001.
- Linking: `UniqueTokenId` = sign-in `UniqueTokenIdentifier` (P0-3 column).

**P0-14 GCP VPC flow** (S after P0-5)
- New `gcp_vpcflow_json`, with `detect_any: ["jsonPayload.connection.src_ip", "jsonPayload.reporter"]`.
- Field mapping:

  | Canonical field | GCP field |
  |---|---|
  | `ts` | `jsonPayload.start_time` |
  | `src_ip` / `dst_ip` | `connection.src_ip` / `connection.dest_ip` |
  | `src_port` / `dst_port` | `connection.src_port` / `connection.dest_port` |
  | `bytes` | `bytes_sent` (string → int) |
  | `host` | `src_instance.vm_name`, else `resource.labels.project_id` |
  | `event_action` | `disposition` (DROPPED → deny, else allow) |

- Dedupe the SRC / DEST reporters.
- Rules: the same network templates; `cl_flow_mining_port`.

**P0-15 S3 data-event rules completed** (S, today)
- These events already parse. Rules:
  - `aws_s3_mass_get`: T1530, Collection. `distinct_burst` keys per `actor_key`, plus a `sum(bytesTransferredOut)` branch over `ct_add`.
  - `aws_s3_ssec_ransom`: T1486, Impact. CopyObject / PutObject with `x-amz-server-side-encryption-customer-algorithm`, followed by DeleteObject.
  - `aws_s3_delete_burst`: T1485.
- Check for overlap with `cl_storage_data_access` / `cl_exfil_volume` first, and add branches rather than new ids where they overlap.
- Generator: story A9-aws.

**P0-16 Pull connectors for Okta, M365 and Workspace** (L, later)
- `connectors/okta.py` (`/api/v1/logs` Link-next, SSWS token env var).
- `connectors/m365_ual.py` (Management Activity API `subscriptions/start` + content blobs).
- `connectors/gws_reports.py` (`activities.list`, SA JWT reusing `cloud_auth`).
- Each with a mock in `tools/mock_cloud.py`, e2e tests and a catalog entry.

### P1

| # | Gap | Kind | Effort |
|---|---|---|---|
| P1-1 | OCSF / Security Lake (Parquet + JSON) | new_shape | M |
| P1-2 | Route 53 Resolver query logs | new_source | S |
| P1-3 | Security Hub + SCC + Defender findings (alert-input) | new_source | S |
| P1-4 | Identity Center sign-in mapping | new_rules | S |
| P1-5 | GCP firewall + DNS logs | new_source | S |
| P1-6 | Azure VNet / NSG flow logs | new_source | M |
| P1-7 | Azure Firewall `AZFW*` + legacy `msg_s` | new_source | M |
| P1-8 | AWS Network Firewall | new_source | S |
| P1-9 | AWS WAF + GCP Armor + Azure AppGW / Front Door WAF | new_source | M |
| P1-10 | ALB + S3 server access text logs | new_source | M |
| P1-11 | GCP audit rules: Policy Denied, BigQuery, Cloud Run, Workload Identity | new_rules | S |
| P1-12 | Entra Identity Protection risk | new_source | S |
| P1-13 | AWS Config / GCP Asset for reach-next | new_source | M |
| P1-14 | GitHub audit | new_source | M |
| P1-15 | Cloudflare http / firewall / audit | new_source | M |
| P1-16 | Auth0 + Duo auth | new_source | S |
| P1-17 | HashiCorp Vault audit | new_source | M |
| P1-18 | ECS vendor namespaces | new_shape | S |
| P1-19 | Azure SQL / App Service / DNSQueryLogs / Defender XDR | new_source | M |
| P1-20 | GCP Ops Agent guest / IAP | new_source | M |
| P1-21 | Untested-claim tests (connectors, live, cross-cloud) | claim_fix | M |

Short plans:
- **P1-1 OCSF.** `ocsf_json` with `detect_any: ["class_uid", "type_uid"]`, plus `read_parquet` for `.parquet` files.
  - Common mapping: `time` (ms) → `ts`; `api.operation` → `signature`; `actor.user.name` → `user`; `src_endpoint.ip` → `src_ip`; `cloud.account.uid` → `host`; `status` → `outcome`.
  - Class 3005 / 3002 is aliased into the CloudTrail columns (`ct_*` macros gain `src: [ocsf_json]` where the meaning is the same), so the AWS rules run on Security Lake.
  - 4001 → network columns. 4003 → `dst_domain`. 2004 → alert-input.
  - Tests per class.
- **P1-2 Route 53 Resolver.** `aws_r53_json`, `detect_any: ["query_name", "srcids"]`.
  - Mapping: `query_timestamp`, `query_name` → `dst_domain`, `srcaddr`, `srcids.instance` → host, `rcode` → outcome, `firewall_rule_action`.
  - Rules: `cl_dns_tunnel` (T1071.004, C2: long high-entropy labels, TXT / NULL types, many unique subdomains of one apex); `cl_dga_nxdomain` (T1568.002).
  - Share them with Azure `DNSQueryLogs` and GCP DNS (P1-5).
- **P1-3 Findings.** Alert-input maps for Security Hub ASFF (`detail.findings[]`, `Types` `TTPs/<Tactic>`), OCSF 2004 (`finding_info.attacks`), GCP SCC (`finding.mitreAttack`; the enum → v20 map is in `config/scc_map.yaml`; `access.principalEmail`, `access.callerIp`), and `azure_monitor` alerts mode (plus the missing test).
- **P1-4 Identity Center.**
  - `cloud.yaml` columns `ct_auth_wf` (`additionalEventData.AuthWorkflowID`) and `ct_sed` (`serviceEventDetails`).
  - Outcome alias for CredentialVerification.
  - Rule `aws_sso_mfa_fatigue`: T1621, repeated CredentialChallenge per `AuthWorkflowID`.
  - Rule `aws_sso_mfa_enroll_new_ip`: T1556.006.
- **P1-5 GCP firewall / DNS.**
  - `gcp_firewall_json`: `jsonPayload.rule_details`, `disposition`. For INGRESS, the attacker is `src_ip`.
  - `gcp_dns_json`: `jsonPayload.queryName`, `sourceIP`, `vmInstanceName`, with both naming conventions.
- **P1-6 Azure flow.** P0-1 unwraps the `records[]` document; DuckDB `unnest` explodes `flows → flowGroups → flowTuples`, and `string_split` splits each tuple.
  - v4 (epoch ms, 13 fields) vs NSG v2 (epoch s, T / U protocol, A / D) is chosen by `flowLogVersion` / `properties.Version`.
  - Map to network columns; the B (begin) state has empty byte counts.
- **P1-7 Azure Firewall.**
  - Structured tables: map `SourceIp`, `DestinationIp`, `DestinationPort`, `Action`, `Fqdn` → `dst_domain`, `ThreatDescription`.
  - Legacy `msg_s`: regex patterns in `sources.yaml`, e.g. `'^(\w+) request from ([\d.]+):(\d+) to ([^:]+):(\d+)\. Action: (\w+)'`.
  - TI / IDPS rows go to alert-input.
- **P1-8 Network Firewall.** `aws_nfw_json`, `detect_any: ["firewall_name", "event.event_type"]`.
  - Mapping: `event.src_ip` / `dest_ip` / `dest_port`, `alert.action`, `event_timestamp` (string or int → `TRY_CAST`), `event.timestamp` `+0000` with no colon.
  - netflow rows → network columns; alert rows → alert-input.
  - Same pattern as FortiGate.
- **P1-9 WAF.**
  - AWS: `aws_waf_json` (`webaclId`, `httpRequest.clientIp`, `action`, `terminatingRuleId`). The user agent comes from `list_filter(httpRequest.headers, h -> lower(h.name) = 'user-agent')`. Scope the `labels` strip as in P0-4.
  - GCP Armor: `jsonPayload.enforcedSecurityPolicy`.
  - AppGW / Front Door: `properties.clientIp`, `ruleId`, `action`.
  - Rules: `web_exploit_allowed_after_block` (T1190, Initial Access: count-mode or ALLOW match after a BLOCK from the same IP); `web_scanner_burst` (T1595.002, Reconnaissance).
- **P1-10 ALB / S3 access text.**
  - `line_regex` sources in the `syslog` style.
  - ALB: 36 positional fields, `client:port` split on the last colon, extra trailing fields tolerated.
  - S3 access: `[%d/%b/%Y:%H:%M:%S %z]`, Requester `-` means anonymous.
  - Rules: `web_scanner_burst`; `aws_s3_anon_get` (T1530).
- **P1-11 GCP audit rules.**
  - `gcp_vpcsc_violation`: T1537, Exfiltration (`g_log LIKE '%policy'` + VPC_SERVICE_CONTROLS).
  - `gcp_bq_bulk_read`: T1213 (`metadata.jobChange.job.jobStats.queryStats.totalBilledBytes` over a threshold, or EXTRACT to a foreign bucket → T1537).
  - `gcp_run_public_invoker`: T1648 / T1098.003 (`allUsers`).
  - `gcp_wif_provider_create`: T1484.002.
  - `setCommonInstanceMetadata` already exists (3 refs).
- **P1-12 Identity Protection.** `azure_risk_json`, `detect_any: ["RiskEventType", "properties.riskEventType", "riskEventType"]`. Vendor verdicts go to alert-input. Map `riskEventType` → technique (`passwordSpray` T1110.003, `anomalousToken` T1550.001, `unlikelyTravel` T1078.004, `mfaFraud` T1621). This unlocks the 19 Sigma riskdetection rules.
- **P1-13 Config / Asset.** Context only, not detection.
  - Load the Config `configurationItems` / EventBridge `detail.configurationItem` and the GCP Asset feed into `work/assets.parquet`.
  - `reach.py` uses `relationships` (instance → ENI → SG with 0.0.0.0/0) and IAM bindings to extend reach-next.
  - Detect T1686.001 from `configurationItemDiff`.
- **P1-14 GitHub.** `github_audit_json`, `detect_any: ["_document_id", "action"]` + `actor`.
  - Mapping: `@timestamp` / `created_at` (epoch ms), `action`, `actor`, `actor_ip`, `repo`, `hashed_token`.
  - Rules: `gh_mass_clone` (T1213.003); `gh_repo_public` (T1567.001); `gh_token_new_ip` (T1550.001); `gh_2fa_disabled` (T1556.006); `gh_owner_grant` (T1098.003).
  - Sigma github mapping.
- **P1-15 Cloudflare.** Three sources.
  - `timestamp_format` detection: an int over 1e17 means ns.
  - Use `ClientIP`, `RayID`, `SecurityAction`, `WAFAttackScore`; v1 / v2 audit aliases (`When` / `ActionTimestamp`, `ActorIP` / `ActorIPAddress`).
  - Rules: T1190 low-score allowed; `cf_logpush_deleted` (T1685.002); `cf_waf_rule_disabled` (T1686.001).
- **P1-16 Auth0 / Duo.**
  - Auth0: type codes → `outcome_map`; stream `{log_id, data}` lift.
  - Duo: `timestamp` epoch s, `result`, `reason`, `access_device.ip` vs `auth_device.ip`.
  - Rules: credential stuffing (T1110.004); `duo_push_fatigue` / `user_marked_fraud` (T1621).
- **P1-17 Vault.** `vault_audit_json`, `detect_any: ["request.mount_type", "auth.accessor"]`.
  - Join request and response on `request.id`; HMAC values are kept opaque.
  - Rules: `vault_secret_sweep` (T1555.006); `vault_audit_disable` (T1685.002, path `sys/audit/*` delete); `vault_root_token` (T1098.001).
- **P1-18 ECS namespaces.** In `ecs_json`, add aliases for `okta.*`, `aws.cloudtrail.*`, `github.*` and `gcp.audit.*`, plus `event.dataset` → `app`. Route rows with `event.dataset = 'aws.cloudtrail'` into the CloudTrail columns.
- **P1-19 Azure misc.**
  - SQL `AzureDiagnostics` (`action_id_s` LGIF burst → T1110; large `response_rows_d` → T1213).
  - App Service `AppServiceAuditLogs` FTP / Kudu login from a new IP (T1078.004), plus FileAudit new `.aspx` (T1505.003).
  - `DNSQueryLogs` → P1-2 rules.
  - Defender XDR `records[].properties` lift → `m365_ual_json` via `RawEventData`.
- **P1-20 GCP guest.** Route `logName .../syslog` `textPayload` lines to the existing syslog `messages` patterns (sshd), and `windows_event_log` `jsonPayload` to `win_json` aliases. IAP `AuthorizeUser` maps to T1021.004.
- **P1-21 Tests for the untested claims.**
  - AAD* rows, `azure_monitor` alerts mode, optional table, `role_arn` assume
  - Insight / NetworkActivity fixtures, ip2asn fixture
  - a live mode cloud test with a persisted baseline
  - a cross-cloud C1 pipeline test
  - a mock-vs-backend catalog diff, and the frontend credentials test

### P2

| # | Gap | Kind | Effort | Plan (short) |
|---|---|---|---|---|
| P2-1 | AWS Transit Gateway flow | new_source | S | Reuse the P0-5 header parser; `tgw-src-vpc-id` / `tgw-dst-vpc-id` → host; no action field |
| P2-2 | CloudFront logs | new_source | M | W3C `#Fields` header TSV + v2 JSON (keys with parentheses); join date + time; web rules from P1-9 |
| P2-3 | RDS / Aurora audit | new_source | M | Aurora CSV (epoch µs), pgaudit / `password authentication failed` regex; T1110, T1213, T1485 DROP |
| P2-4 | SSM Session Manager transcripts | new_source | S | CloudWatch streaming JSON `sessionData[]` → `command_line`; link `sessionId` to CloudTrail StartSession; existing command-line rules (IMDS curl T1552.005) |
| P2-5 | Lambda function logs | new_source | S | `platform.*` JSON; context only (new `Version` after UpdateFunctionCode, T1648) |
| P2-6 | CloudTrail Insights + NetworkActivity rules | new_rules | S | Actor from `insightDetails.insightContext.attributions`; `VpceAccessDenied` from a foreign account → T1567.002 |
| P2-7 | Access Analyzer / Inspector / Macie | new_source | S | Alert-input (Access Analyzer `ExternalAccess` confirms T1537) and reach-next context (Inspector `exploitAvailable` + `ipV4Addresses`) |
| P2-8 | Azure storage file / queue / table | new_rules | S | Extend `azure_storageblob_json` `detect_any` + smb fields; fixture |
| P2-9 | Azure Bastion / Cosmos / ACR / VPN / OpenAI / Automation / Intune / AD FS / provisioning | new_source | M | One alias block each (LA columns + `properties.*`); rules: Bastion new IP T1021.004, ACR push T1525, OpenAI key from foreign IP T1496.004, Intune script push T1072, AD FS spray T1110.003 |
| P2-10 | M365 Teams | new_rules | S | After P0-12: external `MemberAdded` guest T1534 / T1566 |
| P2-11 | GCP IDS / NGFW / NAT / Cloud SQL / GCS usage CSV / System Event | new_source | M | IDS + NGFW → alert-input (both naming conventions); NAT → network columns linking `nat_ip` → `src_ip` VM; GCS usage CSV via `csv_sources` (`c_ip`, `cs_operation`, `time_micros`); System Event suppresses T1485 / T1578.003 FPs |
| P2-12 | Workspace Drive / SAML / user_accounts / groups / Alert Center | new_rules | S | On `gws_reports_json`: Drive external share T1567.002, SAML into AWS T1021.007, recovery email change T1098 |
| P2-13 | GitLab, OCI Audit, Alibaba ActionTrail | new_source | M | OCI: CloudEvents 0.1 vs 1.0 (`eventId` / `eventID`, `response.status` string); Alibaba: CloudTrail-like plus the SLS `event.` prefix shape → reuse CloudTrail rules where the API names map |
| P2-14 | OneLogin, Salesforce, Slack, Duo admin, Cloudflare Zero Trust | new_source | M | One source each; Slack `anomaly` reasons → T1539; Salesforce EventLogFile CSV `TIMESTAMP_DERIVED`; Duo admin `description` parsed twice |
| P2-15 | CloudTrail Lake query results / org-trail test | new_shape | S | Tabular rows with dotted column names → aliases; test the org-trail prefix |

### P3

| # | Gap | Kind | Effort | Plan |
|---|---|---|---|---|
| P3-1 | Route 53 public zone logs | new_source | S | Space-delimited; T1595 / T1590 subdomain enumeration only |
| P3-2 | GCP Access Transparency | new_source | S | `jsonPayload @type TransparencyLog`; T1199 context |
| P3-3 | Azure posture (recommendations, policy, health) | new_source | M | Context for reach-next; Policy `deny` events as blocked attempts |
| P3-4 | GCP SWP / VPN / reCAPTCHA; Cloudflare DNS / Spectrum / Workers | new_source | M | Product-specific; low value for the demo |
| P3-5 | Amazon Detective | claim_fix | S | Not a log. Cite it as a competitor reference only |

### What is realistic today

Run in parallel on disjoint files. The owner is cyberforge-0c for `config/sources.yaml` cloud entries, `cloud.yaml`, `rules_cloud.yaml`, `tools/cloud_attacks/**` and tests.

| Lane | Gaps | Files |
|---|---|---|
| A (ingest) | P0-1, P0-4 | `attacklens/unwrap.py` (new), `profile.py` / `ingest.py` hook, `pipeline.yaml`, `sources.yaml` label scope |
| B (Azure) | P0-3, P0-9 | `sources.yaml` azure entries, `cloud.yaml` `si_*` / kv columns, `rules_cloud.yaml` azure block |
| C (network) | P0-5, P0-14, P0-15 | `sources.yaml` csv / flow entries, `rules_cloud.yaml` flow + S3 |
| D (identity) | P0-7, P0-11 | `okta_json`, `gws_reports_json`, `sigma_map.yaml` okta / gworkspace logsources |
| E (k8s + findings) | P0-8, P0-6 | `k8s_audit_json`, `integrations.yaml siem_alerts.guardduty`, `guardduty_map.yaml` |
| F (tuning + docs) | P0-10, P0-2 | `rules_cloud.yaml` behavioural block (coordinate with lane B), README / reports |

Gate for each lane:
1. Fast tests through `jobq` (only the touched test files).
2. Re-run `cloud_small` through `jobq` and compare the scorecard to 76.74 / 78.79 / 40 / 36.36 / 41.1.
3. `test_probes.py` must pass.

Later (L): P0-16 connectors, a full Security Lake Parquet path at scale, P1-13 asset graph in `reach.py`, and live-mode cloud baselines.
