# Sigma cloud mapping: compiler patch + apply steps (DRAFT)

Goal: run the SigmaHQ cloud rules (`config/sigma/rules/cloud/{aws,azure,gcp}`) with the mapping in
`reports/cloud/sigma_map_cloud.yaml` (rule_catalog.md §6). Nothing here is applied yet: `config/sigma_map.yaml` and
`backend/attacklens/sigma_*.py` were being edited by another session when this was written.

- Base: `backend/attacklens/sigma_rules.py` md5 `26ed818c573bb0be30da89c536f2494d` (398 lines, COMPILER_VERSION "5").
  `git apply --check` passed against it on 2026-11-01. `sigma_compile.py` needs **no** change.
- Test: `backend/tests/test_sigma_cloud_draft.py` (passes before AND after the patch; it detects the patch through
  `sigma_rules.RUNTIME_KEYS`).

## 1. What the patch adds (all in `sigma_rules.py`)

| Feature | Key in sigma_map.yaml | When | Why |
|---|---|---|---|
| Extra logsource list | `cloud_logsources:` (appended to `logsources`) | compile | The block is APPENDED. `yaml.safe_load` keeps only the LAST copy of a repeated top-level key, so a second `logsources:` / `disable:` would silently drop every existing entry. New key names avoid that. |
| Per-logsource fields | `fields:` inside a logsource entry | compile | When present, it REPLACES the global `fields` for that logsource only. Cloud names (`Status`, `category`, `userAgent`, `eventName` ...) cannot leak into windows / proxy rules (e.g. 4625 `Status: 0xC000006D` rules stay skipped), and windows names (`Image`, `User` ...) never compile into a cloud rule. |
| JSON exclusion switch | `keywords: {..., exclude_regex: false}` | compile | `RAW_LINE_EXCLUDE` (`\{\s*"` / CEF) hides every cloud line, because every cloud line is JSON. `false` turns it off for that entry only. It still needs `source_types` (the `source_type IN (...)` guard stays). null / '' keep the default, so the existing syslog entry does not change. |
| Technique for tactic-only rules | `technique_override: [{id, technique}]` | compile | 31 cloud rules carry tactic tags only and were skipped as `no_attack_technique_tag`. This includes 3 of the catalogue's "enable" rules (VPC flow logs deleted, Defender suppression rule, MFA registration policy). Used only when the rule has no technique tag of its own. |
| Extra disable list | `cloud_disable:` (merged with `disable`) | load (`_filter`) | Same reason as `cloud_logsources`. Runtime filter, no recompile. |
| Level override | `level_override: [{id, level, reason}]` | load (`_filter`) | Context rules run at `low` (= 35: never seeds, never adds a tactic alone). One rule is raised to `medium`. Severity comes from `level_severity`. The original level is kept as `level_from`, and `coverage.level_overridden` counts them. `live_min_level` filters on the overridden level, so context rules stay out of live cycles. A bad level raises `ValueError` (config error). |

`RUNTIME_KEYS = ("disable", "cloud_disable", "level_override")` are left out of the compile hash, the same way
`disable` was before, so editing them never recompiles. `COMPILER_VERSION` goes to "6" (one recompile).

## 2. The patch

Save the block below as `sigma_cloud.diff` and run `git apply sigma_cloud.diff` from the repo root. If the other
session changed `sigma_rules.py` and the diff no longer applies, make the same 8 hunks by hand. They are small and
independent.

```diff
--- a/backend/attacklens/sigma_rules.py
+++ b/backend/attacklens/sigma_rules.py
@@ -37,8 +37,10 @@
 
 log = logging.getLogger(__name__)
 
-COMPILER_VERSION = "5"   # 5: NOT parity, keyword substring + guard expression, assume_true values
+COMPILER_VERSION = "6"   # 6: per-logsource fields, cloud_logsources, technique_override, exclude_regex: false
 LEVELS = ("informational", "low", "medium", "high", "critical")
+# sigma_map.yaml keys applied at load time (_filter), never compiled: changing them never recompiles
+RUNTIME_KEYS = ("disable", "cloud_disable", "level_override")
 NEVER_STATUS = ("deprecated", "unsupported")
 DEFAULTS: dict[str, Any] = {"enabled": True, "dir": "config/sigma", "cache_dir": "data/cache/sigma",
                             "min_level": "low", "status": ["stable", "test", "experimental"],
@@ -58,15 +60,31 @@
 
 
 def settings(cfg: dict[str, Any]) -> dict[str, Any]:
-    """pipeline.yaml `sigma` over DEFAULTS, plus sigma_map.yaml `disable` (ids or SigmaHQ uuids, each with a reason)."""
+    """pipeline.yaml `sigma` over DEFAULTS, plus sigma_map.yaml `disable` + `cloud_disable` (ids or SigmaHQ uuids,
+    each with a reason) and `level_override` ({id, level}: the rule runs at that level / its severity)."""
     s = {**DEFAULTS, **((cfg.get("pipeline") or {}).get("sigma") or {})}
     if os.environ.get("ATTACKLENS_SIGMA", "").strip().lower() in ("0", "false", "off", "no"):
         s["enabled"] = False   # cheap global off switch (tests that do not concern Sigma)
-    dis = (cfg.get("sigma_map") or {}).get("disable") or []
+    smap = cfg.get("sigma_map") or {}
+    dis = list(smap.get("disable") or []) + list(smap.get("cloud_disable") or [])
     s["disable"] = [str(d["id"] if isinstance(d, dict) else d) for d in dis] + [str(x) for x in s.get("disable") or []]
+    s["level_override"] = level_overrides(smap)
+    s["level_severity"] = dict(smap.get("level_severity") or {})
     return s
 
 
+def level_overrides(smap: dict[str, Any]) -> dict[str, str]:
+    """sigma_map `level_override` [{id, level, reason}] -> {lower-case id or uuid: level}. A bad level is a config
+    error (raised), never silently ignored."""
+    out: dict[str, str] = {}
+    for d in smap.get("level_override") or []:
+        level = str(d.get("level") or "").lower()
+        if level not in LEVELS or level not in (smap.get("level_severity") or {}):
+            raise ValueError(f"sigma_map level_override {d.get('id')}: unknown level {d.get('level')!r}")
+        out[str(d["id"]).lower()] = level
+    return out
+
+
 def _resolve(p: str) -> Path:
     path = Path(p)
     return path if path.is_absolute() else REPO_ROOT / path
@@ -85,7 +103,7 @@
     s = settings(cfg)
     root = _resolve(str(s["dir"]))
     cache_dir = _resolve(str(s["cache_dir"]))
-    smap = {k: v for k, v in (cfg.get("sigma_map") or {}).items() if k != "disable"}   # runtime filter, not compiled
+    smap = {k: v for k, v in (cfg.get("sigma_map") or {}).items() if k not in RUNTIME_KEYS}   # runtime, not compiled
     smap_json, attack_json = json.dumps(smap, sort_keys=True, default=str), json.dumps(cfg.get("attack") or {})
     walk = sigma_cache.walk(root) if root.is_dir() else []
     t_walk = time.perf_counter()
@@ -143,7 +161,7 @@
     from sigma.rule import SigmaRule
 
     files = rule_files(root) if root.exists() else []
-    entries = list(smap.get("logsources") or [])
+    entries = list(smap.get("logsources") or []) + list(smap.get("cloud_logsources") or [])
     specs = {k: field_spec(v, CANONICAL_COLUMNS) for k, v in (smap.get("fields") or {}).items()}
     exprs: list[str] = []
     rules: list[dict[str, Any]] = []
@@ -208,6 +226,8 @@
     if entry is None:
         ls = r.logsource
         raise Unsupported(f"unmapped_logsource:{ls.product}/{ls.category}/{ls.service}")
+    if entry.get("fields"):   # a logsource with its own fields uses ONLY those: no global name leaks in or out
+        specs = {k: field_spec(v, CANONICAL_COLUMNS) for k, v in entry["fields"].items()}
     kw_expr, kw_guard = keyword_column(entry.get("keywords"))
     comp = Compiler(specs, exprs, assume_true_spec(entry.get("assume_true")), kw_expr, keyword_guard=kw_guard,
                     policy=str(smap.get("unmapped_field_policy", "skip")))
@@ -225,7 +245,8 @@
     sev_map = smap.get("level_severity") or {}
     if level not in sev_map:
         raise Unsupported(f"level:{level}")
-    tech, sub, tactic, de = labels(r, attack, smap.get("tactic_aliases") or {})
+    fallback = {str(d["id"]).lower(): str(d["technique"]) for d in smap.get("technique_override") or []}
+    tech, sub, tactic, de = labels(r, attack, smap.get("tactic_aliases") or {}, fallback.get(str(r.id).lower()))
     rid = _rule_id(r, rel, ids)
     out = {"id": rid, "kind": "match", "source": "sigma", "title": str(r.title or "")[:200],
            "sigma_id": str(r.id) if r.id else None, "path": rel, "logsource": entry.get("name"),
@@ -241,14 +262,16 @@
 def keyword_column(kw: Any) -> tuple[str | None, str | None]:
     """logsource `keywords` -> (column expression, guard predicate or None). Guard: source_type IN (source_types);
     for raw_line also NOT regexp_matches(raw_line, exclude_regex) (RAW_LINE_EXCLUDE by default) so a syslog frame that
-    wraps generator JSON / CEF (with its label fields) is never keyword-searched. Config text is quoted via lit()."""
+    wraps generator JSON / CEF (with its label fields) is never keyword-searched. Config text is quoted via lit().
+    exclude_regex: false switches that exclusion off (only with source_types): for label-stripped JSON sources whose
+    every line is JSON (cloud audit logs); null / '' keeps the default."""
     if not isinstance(kw, dict):
         return (str(kw) if kw else None), None
     expr = str(kw.get("expr") or "") or None
     conds = []
     if kw.get("source_types"):
         conds.append("source_type IN (" + ", ".join(lit(str(x)) for x in kw["source_types"]) + ")")
-    if conds and expr == "raw_line":
+    if conds and expr == "raw_line" and kw.get("exclude_regex") is not False:
         conds.append(f"NOT regexp_matches(raw_line, {lit(str(kw.get('exclude_regex') or RAW_LINE_EXCLUDE))})")
     return expr, (" AND ".join(conds) or None)
 
@@ -273,16 +296,18 @@
     return [t for t in TACTICS_V20 if t.lower() == norm]
 
 
-def labels(r: Any, attack: dict[str, Any], aliases: dict[str, Any]) -> tuple[str, str | None, str, str | None]:
+def labels(r: Any, attack: dict[str, Any], aliases: dict[str, Any], fallback: str | None = None
+           ) -> tuple[str, str | None, str, str | None]:
     """(technique, sub_technique, tactic, defense_evasion_to) from the rule's attack.* tags, mapped through
     attack_v20.json. Technique: the first tagged sub-technique known to v20, else the first known technique.
     Tactic (deterministic): among the rule's tagged tactics that the technique belongs to in v20, the EARLIEST in
     kill-chain order (TACTIC_IDX); a tag that names a pre-v20 tactic is translated by sigma_map tactic_aliases
     (Defense Evasion -> Stealth / Defense Impairment, decided by the technique's own v20 tactics). No usable tag ->
-    the technique's default v20 tactic. defense_evasion_to = the v20 tactic a defense-evasion tag resolved to."""
+    the technique's default v20 tactic. defense_evasion_to = the v20 tactic a defense-evasion tag resolved to.
+    fallback: sigma_map technique_override for a rule that carries tactic tags only (used only when it has none)."""
     techniques = attack.get("techniques") or {}
     tags = [t.name.lower() for t in (r.tags or []) if str(t.namespace).lower() == "attack"]
-    techs = [t.upper() for t in tags if _TECH_TAG.fullmatch(t)]
+    techs = [t.upper() for t in tags if _TECH_TAG.fullmatch(t)] or ([fallback.upper()] if fallback else [])
     if not techs:
         raise Unsupported("no_attack_technique_tag")
     known = [t for t in techs if t in techniques and t.split(".")[0] in techniques]
@@ -366,7 +391,13 @@
     status = {str(x).lower() for x in s.get("status") or []} - set(NEVER_STATUS)
     run, filtered = [], Counter()
     disabled = {str(x).lower() for x in s.get("disable") or []}
+    over, sev = s.get("level_override") or {}, s.get("level_severity") or {}
+    n_over = 0
     for r in full["rules"]:
+        lv = over.get(r["id"]) or over.get(str(r.get("sigma_id") or "").lower())
+        if lv and lv != r["level"]:   # context / raised rules: level and severity as configured, original kept
+            r = {**r, "level": lv, "severity": int(sev[lv]), "level_from": r["level"]}
+            n_over += 1
         if r["id"] in disabled or str(r.get("sigma_id") or "").lower() in disabled:
             filtered["disabled"] += 1
         elif r["status"] not in status:
@@ -375,7 +406,9 @@
             filtered[f"below_min_level:{r['level']}"] += 1
         else:
             run.append(r)
-    return SigmaSet(run, list(full["exprs"]), coverage(full, run, filtered, s))
+    cov = coverage(full, run, filtered, s)
+    cov["level_overridden"] = n_over
+    return SigmaSet(run, list(full["exprs"]), cov)
 
 
 def coverage(full: dict[str, Any], run: list[dict[str, Any]], filtered: Counter, s: dict[str, Any]
```

## 3. Measured with the patch (scratch copy, live files untouched)

How it was measured: config/ was copied to a temp dir and the block appended to the TEMP `sigma_map.yaml`. The
patched `sigma_rules.py` copy was loaded as `attacklens.sigma_rules`. `config/sigma/rules/cloud` was copied and
compiled.

- **Cloud folder (226 files):** 134 compile and 92 are skipped:
  - 55 `unmapped_logsource`: riskdetection 19, pim 7, google_workspace 10, m365 19. No ingested source.
  - 25 `no_attack_technique_tag`: tactic-only rules without an override.
  - 12 `unmapped_field`: ConsentContext.IsAdminConsent, failure_status_reason, targetResources.type,
    TargetResources.ModifiedProperties.DisplayName, Initiatedby, properties.message (2 sign-in rules, kept native on
    purpose), ActivityDetails, data.protoPayload.authorizationInfo.permission, requestParameters.userName (fieldref
    target), responseElements.accessKey.userName (fieldref), properties.message for the Intune activity rule.
  - 0 `sql_compile_error`.
- **Per logsource (compiled):** aws_cloudtrail 52, azure_activity 26, azure_audit 35, azure_signin 15, gcp_audit 6.
- **Running: 71.** That is 33 at their own level, plus 38 `level_override` (37 low, 1 medium; 34 actually change
  level, the others were already low).
  - Disabled: 63. These are 11 of the 16 §6.5 rules (the other 5 do not compile anyway) and 52 rules that compile
    but stay off under catalogue §6.6:
    - 9 AKS data-plane rules.
    - 5 with a dead mapping: Status text, `contains|all` of two activity names, the 'Sucess' typo, guest_to_member.
    - 38 the catalogue left to native rules or did not select.
  - The catalogue target was 34 + 39 = 73. The 2 missing are `aws_lambda_function_url` and
    `aws_new_lambda_layer_attached` (tactic-only, technique unclear, no override given).
- **Running by level:** low 37, medium 17, high 17.
- **Whole vendored pack (3800+ files):**
  - Merged map + patched code compiles 1792 rules; the live map + live code compiles 1657.
  - Added: 135. That is the 134 cloud rules plus
    `rules-threat-hunting/cloud/azure/signin_logs/azure_ad_signin_axios_user_agent.yml` (low, userAgent contains
    'axios').
  - Removed: 0. Changed `where` / severity: 0. No non-cloud rule changes.
- **test_sigma3 catalogue checks on the merged map:**
  - With `label_free` extended (see §4): 0 violations, and every label is ATT&CK v20.
  - Without the extension: 79 cloud rules fail the raw_line check.
  - `->>` keeps the column check valid: `raw_line->>'$.x'` leaves only `raw_line`, while `json_extract_string`
    would show up as a non-canonical identifier.
- **Gates:** every compiled cloud rule's gate starts with `source_type = '<cloud type>'`. Every JSON read is inside
  `CASE WHEN source_type = '<type>' AND action <> 'malformed' THEN ...`. Non-JSON lines of 6 other source types that
  carry the same API names and keywords, plus malformed cloud lines evaluated WITHOUT the OK filter: 0 matches and
  0 errors.

Hits. Each rule's `where` and the production grouped path (`sigma_detect._run_group`) agree everywhere. All rules
are evaluated here; the disable and level filters only change what runs.

| Data | Rows | Running rules that fired (alerts) |
|---|---|---|
| backend/tests/fixtures/cloud/*.jsonl | 14 | aws_cloudtrail_console_login_failed_authentication 1 (low, context), aws_cloudtrail_console_login_success_without_mfa 1 (medium). Disabled but would fire: azure_ad_account_created_deleted, aws_sts_assumerole_misuse (AssumedRole fixture row), azure_creating_number_of_resources_detection (VM write keyword). |
| positive lines (in the test) | 11 + 1 syslog | StopLogging -> aws_cloudtrail_disable_logging; DeleteDetector -> guardduty_detector_deleted_or_updated (the AccessDenied UpdateDetector does not fire); PutBucketPublicAccessBlock false -> bucket_block_public_access_weakened; ROLEASSIGNMENTS/WRITE -> azure_granting_permission_detection (keyword); ELEVATEACCESS -> elevation_via_activitylogs; 'Disable Strong Authentication' -> azure_mfa_disabled; BAV2ROPC sign-in -> suspicious_signin_bypassing_mfa; packetMirrorings.insert -> gcp_full_network_traffic_packet_capture; k8s pod + break-glass -> gcp_breakglass_container_workload_deployed. The syslog line with the same words: nothing. GCP SetIamPolicy: nothing (no SigmaHQ gcp.audit rule covers it; native rule). |
| data/raw/cloud_small (25 394 rows, generated by another agent, as found on 2026-11-01) | ct 17 437, gcp 5 916, az-act 646, az-signin 792, az-blob 603 | azure_network_security_modified_or_deleted 98 (low), azure_rare_operations 16 (low), azure_granting_permission_detection 4 (low), console_login_success_without_mfa 3, aws_cloudtrail_disable_logging 2, aws_snapshot_backup_exfiltration 2 (low), security_group_change_ingress_egress 1 (low), guardduty_detector_deleted_or_updated 1. gcp_audit: 0, azure_audit: 0, azure_signin: 0. Not compared with ground truth (not tuned). |

## 4. Apply steps (later, when the other session is done)

1. Append the block:
   `printf '\n' >> config/sigma_map.yaml && cat reports/cloud/sigma_map_cloud.yaml >> config/sigma_map.yaml`
   On its own this changes nothing: the current compiler ignores the four new keys. Only the Sigma cache key
   changes.
2. Apply the patch in §2 (`git apply`). Then check `wc -l backend/attacklens/sigma_rules.py`: it goes from 398 to 431
   lines, past the 400-line convention. Moving `keyword_column` + `level_overrides` into `sigma_compile.py` (337 lines)
   fixes that.
3. `backend/tests/test_sigma3.py`. This is **two one-line edits** for test-engineer (the task expected one; the
   second is needed because `cloud_disable` is a new key):
   - line 52: `cfg["sigma_map"]["disable"] = []` -> `cfg["sigma_map"]["disable"] = cfg["sigma_map"]["cloud_disable"] = []`
     (otherwise the catalogue fixture still filters 63 cloud rules, and `len(s.rules) == compiled` fails).
   - line 76: `label_free = {"syslog", "fortigate_kv"}` ->
     `label_free = {"syslog", "fortigate_kv", "cloudtrail_json", "azure_signin_json", "azure_activity_json", "gcp_audit_json"}`
     (cloud raw_line is ingest's label-stripped JSON, sources.yaml `label_keys` / `label_nested_keys`).
4. Run `pytest backend/tests/test_sigma_cloud_draft.py backend/tests/test_sigma3.py -q`. The draft test switches to
   patched mode by itself: compile 134, running 71, level / severity check active.
5. Optional: give `aws_lambda_function_url` / `aws_new_lambda_layer_attached` a `technique_override`, or move rules
   from the §6.6 part of `cloud_disable` to `level_override` once real data shows they help linking.

## 5. Known limits / follow-ups

- **Activity Log REST / Event Grid shape** (`operationName: {value}`): signature is then JSON text, so those rows
  fall to the `azure_audit` gate and match nothing. Fix it at ingest with the alias `$.operationName.value` first
  (rule_catalog.md §2.1 item 1).
- **Cost at 50 GB:** each JSON field is a separate `->>` parse of raw_line, about 25 per CloudTrail row in the
  aws_cloudtrail group. Tuples are close to rows there, because requestParameters / responseElements JSON text is
  in the DISTINCT tuple. The catalogue's §2.2 `cloud_ev` pre-materialization (one JSON pass) is the fix if Stage 2
  time grows.
- **gcp_service_account_disabled_or_deleted** expects `...serviceAccounts.delete` / `.disable`. Real Admin Activity
  logs say `google.iam.admin.v1.DeleteServiceAccount`, so the rule likely never fires on real data. It is kept as
  context (catalogue) and needs a native rule.
- **azure_network_security_modified_or_deleted** (context, via technique_override) fired 98 times on 646 activity
  rows of cloud_small. It is low (35), so it never seeds an incident, but it is the noisiest cloud rule. Consider
  `cloud_disable` if the cap (`max_alerts_per_rule`) is reached on big sets.
- `azure_storageblob_json` rows exist in cloud_small; no Sigma logsource maps to them (SigmaHQ has no blob rules).

## 6. label_override + cloud label audit + native-cloud dedupe (cyberforge-0c Fixer B, 2026-11-01)

### 6.1 label_override (compile-time, COMPILER_VERSION "7")

`sigma_map.yaml label_override: [{id, technique?, tactic?, reason}]` (`id` = SigmaHQ uuid or AttackLens id).

- `technique` **replaces** the rule's tagged techniques. `technique_override` only fills in when a rule has no
  technique tag.
- `tactic` must be one of the technique's v20 tactics in `config/attack_v20.json`. Without `tactic`, the rule's own
  tactic tags decide (earliest valid one), else the technique's default tactic.
- Any bad entry raises `ValueError`: unknown technique or tactic, a tactic outside the technique, neither key given,
  no reason, or a duplicate id. `sigma_rules.load` checks this before the cache, so a warm cache cannot hide it.
- The key is part of the Sigma cache key, so editing it recompiles once. Compiled rules carry `label_override:
  <reason>`, and `coverage.label_overridden` counts them.
- Code: `sigma_options.label_overrides` / `check_tactic`, and `sigma_rules.labels(..., override)`.
- Tests: `backend/tests/test_sigma5.py`.

### 6.2 Audit of the running cloud Sigma rules (70)

Each label was judged from the rule's own detection logic (the eventName / operationName it matches) against
ATT&CK v20. Ground truth was never used. Rules not listed here keep their tagged label, which fits.

| Rule (uuid8) | Detection | Was | Now (label_override) | Why |
|---|---|---|---|---|
| aws SG ingress/egress (6fb77778) | Authorize/Revoke SecurityGroup Ingress/Egress | T1190 / Initial Access | T1686.001 / Defense Impairment | firewall change, not an exploit of a public app |
| aws SG load balancer (7a4409fc) | ApplySecurityGroupsToLoadBalancer, SetSecurityGroups | T1190 / IA | T1686.001 / DI | same |
| aws SG RDS (14f3f1c8) | DB security group create / delete / authorize / revoke | T1190 / IA | T1686.001 / DI | same |
| aws ssm SendCommand (38e7f511) | ssm SendCommand ok | T1566.002 / IA | T1651 / Execution | runs commands on instances, not a spearphishing link |
| aws imds usage (352a918a) | assumed-role/aws:* identity outside SSM | T1078.002 / IA | T1078.004 / IA | a cloud identity, not a domain account |
| aws vm export (54b9a76a) | CreateInstanceExportTask ok | T1005 / Collection | T1537 / Exfiltration | VM image export (the rule also tags T1537) |
| aws delete SAML provider (ccd6a6c8) | DeleteSAMLProvider | T1078.004 / IA | T1531 / Impact | removes federated access (the rule also tags T1531) |
| aws userData change (1ab3c5ed) | ModifyInstanceAttribute userData | T1059.001 / Execution | T1059 / Execution | the interpreter is unknown; PowerShell was just the first tag |
| aws KMS key material (1279262f) | Import / DeleteImportedKeyMaterial | T1608.003 / Resource Dev | T1486 / Impact | KMS ransomware pattern (the rule also tags T1486) |
| aws RDS master password (8a63cdd4) | ModifyDBInstance masterUserPassword | T1020 / Exfiltration | T1098 / Persistence | a credential change, nothing exfiltrated |
| aws ImportKeyPair (92f84194) | ec2 ImportKeyPair | T1078 / IA | T1098.004 / Persistence | registers an SSH key, no account is used |
| az Key Vault secrets (b831353c) | SECRETS write / backup / restore / set | T1552.001 / CA | T1555.006 / CA | a cloud secrets store, not files |
| az Key Vault keys (80eeab92) | KEYS create / backup / delete ... | T1552.001 / CA | T1552 / CA | keeps the parent tag, drops the wrong "in files" sub |
| az Key Vault vault (459a2970) | VAULTS write / delete / accesspolicies | T1552.001 / CA | T1552 / CA | same |
| az elevateAccess activity (09438caa) | AUTHORIZATION/ELEVATEACCESS/ACTION | T1078.004 / IA | T1098.003 / Privilege Escalation | grants User Access Administrator: a role grant |
| az elevateAccess audit (ca9bf243) | "User has elevated their access ..." | T1078 / IA | T1098.003 / PE | same |
| az device admin roles (11c767ae) | "Add member to role" + device admin role ids | T1078.004 / IA | T1098.003 / PE | a role grant |
| az federation modified (352a54e1) | "Set federation settings on domain" | T1078 / IA | T1484.002 / PE | the ATT&CK Trust Modification procedure |
| az PIM alerts disabled (aeaef14c) | "Disable PIM Alert" | T1078 / IA | T1685 / DI | switches off a security alert |
| az BitLocker key read (a0413867) | "Read BitLocker key" | T1078.004 / IA | T1555 / CA | reads a stored recovery secret |
| az LAPS recovery (a4b25073) | "Recover device local administrator password" | T1098.005 / Persistence | T1555 / CA | reads a stored password |
| az app owner added (74298991) | "Add owner to application" | T1552 / CA | T1098 / Persistence | grants control of an app, no credential is read |
| gcp packet mirroring (980a7598) | Compute.PacketMirrorings.* | T1074 / Collection | T1040 / CA | ATT&CK T1040 names GCP Packet Mirroring |

These are mislabelled too, but left as they are because no single better label is clearly right:

| Rule (uuid8) | Detection | Label | Why not overridden |
|---|---|---|---|
| aws RDS cluster actions (457cc9ac) | ModifyDBCluster, DeleteDBCluster | T1020 / Exfiltration | "automated exfiltration" is wrong, but modify and delete need different labels (T1578-like vs T1485) |
| aws RDS public restore (c3f265c7) | RestoreDBInstanceFromDBSnapshot, publiclyAccessible | T1020 / Exfiltration | T1578.002 (create instance from snapshot) and T1537 both fit in part |
| aws EBS default encryption off (16124c2d) | DisableEbsEncryptionByDefault | T1486 / Impact | turning encryption off is not "encrypted for impact", and no technique fits cleanly |
| az ADFS new server (288a39fc) | ADHYBRIDHEALTHSERVICE servicemembers action | T1578 / DI | an AD FS server is not cloud compute; T1484.002 is plausible but not certain |
| aws route53 transfer / lock (b056de1a, 3940b5f1) | TransferDomainToAnotherAwsAccount, DisableDomainTransferLock | T1098 / Persistence | a domain hijack has no exact v20 technique (T1584.001 is resource development) |
| aws CreateRoute (c803b2ce) | ec2 CreateRoute | T1686.001 / DI | a route is not a firewall, but the tag is defensible as a network-control change |

`c1182e02` (azure_rare_operations, tagged T1003) **stays in `cloud_disable`**. Its main case (listKeys) is native
`az_key_listing` (T1552), and it also matches noisy NSG writes. The reason text there now says so.

### 6.3 Dedupe against native cloud alerts

The problem: `detect.py` used to insert native cloud alerts (`detect_cloud.run_cloud`) into al_raw *after* Sigma,
so `dedupe_against_native` never saw them. The same event then carried, for example, `sigma_a622fcd2` (T1098.003
Persistence) and `az_rbac_privileged_assignment` (T1098.003 Privilege Escalation). This happened 11 times on
cloud_small.

The fix:
- The cloud hook now runs **before** Sigma. It still runs after `relabel_without_context`, which reads only
  rules.yaml alerts.
- The native cloud rule ids (the distinct rule_id values of `raw_alerts_cloud.parquet`) go to
  `sigma_detect.run(native_cloud_ids=...)`.

The dedupe rules:
- **Native cloud alerts** cover a Sigma alert when all of these hold:
  - same event (source_seq in the native alert's source_keys)
  - same host
  - same parent technique
  - compatible sub-technique: equal, or one side has none (parent/child)
- When covered, the Sigma alert is dropped and the native label and severity stay.
- A sibling sub-technique (T1098.001 vs T1098.003) or another technique is never dropped.
- A native cloud alert never dedupes on tactic alone. Generic behaviour alerts such as `cl_first_seen_api` (T1078.004
  Initial Access) must not swallow a distinct Sigma technique.
- **rules.yaml natives** keep the old rule (technique OR tactic), so non-cloud sets do not change.
- `run_metrics` / `sigma_coverage.json` report this as `sigma_alerts_deduped_cloud`.
