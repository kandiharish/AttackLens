# Native cloud detection: operator notes

Rules: `config/rules_cloud.yaml` (69 native + 18 behavioural). Settings, thresholds, allowlists, column map:
`config/cloud.yaml`. Code: `backend/attacklens/detect_cloud*.py`. Catalog and sources: `rule_catalog.md`.
Hook into detect.py: `detect_hook.md`.

## Offline IP -> ASN / country (optional)

Nothing is downloaded at runtime. Without a database the "network" of an IP is its /16 (IPv4) or /48 (IPv6) prefix,
and rules that compare networks (B2 new network, B12 one session from several networks) treat prefix-only evidence
as weak (B12 prefix-only = severity 45; B2 new prefix = 30, context).

To enable ASNs (and hosting-provider detection through `params.hosting_asn_regex` / `hosting_asns`):

1. On a machine with internet access, download the iptoasn table (PDDL 1.0, public domain):
   `https://iptoasn.com/data/ip2asn-v4.tsv.gz` (IPv4 only; this is what is used), or `ip2asn-combined.tsv.gz`
   (IPv6 rows are ignored).
   ```
   curl -fLo config/geo/ip2asn-v4.tsv.gz https://iptoasn.com/data/ip2asn-v4.tsv.gz
   ```
   Format: tab-separated `range_start  range_end  AS_number  country_code  AS_description`, no header.
   DuckDB reads the `.gz` file directly; do not unpack it.
2. Set `geo.asn_db_path: config/geo/ip2asn-v4.tsv.gz` in `config/cloud.yaml` (a path relative to the working
   directory of the run, or absolute).
3. Optional: `geo.country_centroids_path` = CSV with header `cc,lat,lon` (one row per ISO country code) so that
   impossible travel (B6) also works for CloudTrail / GCP / Activity Log rows; Entra sign-ins carry coordinates.
4. Optional cloud-provider ranges (used by `cl_instance_creds_offhost` and to ignore provider IPs in travel /
   multi-network rules): any file that lists CIDRs, for example
   - AWS: `https://ip-ranges.amazonaws.com/ip-ranges.json` -> `geo.provider_ranges.aws`
   - Google Cloud: `https://www.gstatic.com/ipranges/cloud.json` -> `geo.provider_ranges.gcp`
   - Azure: the "Azure IP Ranges and Service Tags - Public Cloud" JSON from the Microsoft download center ->
     `geo.provider_ranges.azure`
   Without the AWS / GCP file, `cl_instance_creds_offhost` falls back to "one instance-role session from two
   networks within 6 h".

Check: the `geo` block of the run stats (`python -m attacklens.detect_cloud --work ...`) shows `asn_db: true`,
`ips_with_asn` and `provider_ranges` counts.

## Unverified values (check before production)

- Entra built-in role template ids (`params.entra_priv_role_ids`), Azure RBAC role definition ids
  (`params.az_priv_role_def_ids`) and Microsoft Graph app-role ids (`params.graph_priv_app_role_ids`) are copied
  from the catalog. They were not re-checked against the Microsoft "built-in roles" / Graph permissions pages.
  Role names are matched too (`params.entra_priv_role_regex`), so a wrong id only loses the id path.
- Entra error codes (50126 / 50053 / 50055 / 50056 password failures, 50074 / 50076 / 500121 / 50158 MFA steps) and
  the Activity Log operation names follow the catalog's sources; real tenant data may add variants.
- Several AWS request shapes (`BatchGetSecretValue.secretIdList`, `DeleteObjects` key lists, Bedrock `Invoke*`
  being management vs data events) were not checked against live trails.

## Disclosures for README.md (third-party sources of rule logic and data)

| Source | Licence | Use |
|---|---|---|
| DataDog Stratus Red Team (attack technique docs) | Apache-2.0 | technique list, event names, test plan |
| SigmaHQ rules (`rules/cloud`) | DRL 1.1 | logic re-expressed in native rules, with attribution |
| Splunk security_content (`detections/cloud`) | Apache-2.0 | thresholds and patterns |
| Azure-Sentinel (Entra ID / Azure Activity analytic rules) | MIT | operation names, result codes, thresholds |
| Panther panther-analysis (`aws_cloudtrail_rules`) | Apache-2.0 | lists and patterns |
| Elastic detection-rules | Elastic License 2.0 | logic inspired by; no query text copied, all SQL is original |
| iptoasn.com ip2asn tables (optional, not shipped) | PDDL 1.0 | offline IP -> ASN / country |
| AWS ip-ranges.json, Google cloud.json, Azure Service Tags (optional, not shipped) | public feeds | provider IP ranges |
| MITRE ATT&CK v20 | MITRE terms of use | technique / tactic ids (already disclosed) |
