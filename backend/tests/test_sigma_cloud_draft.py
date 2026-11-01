"""DRAFT cloud Sigma mapping (reports/cloud/sigma_map_cloud.yaml, rule_catalog.md §6, reports/cloud/sigma_patch.md).

The draft is appended to a TEMP copy of config/sigma_map.yaml (never the live file). Works before and after the patch:
each cloud logsource is compiled on its own rule folder with that entry as the only logsource and its own `fields`
as the field map, which is exactly what the patch's per-logsource `fields` does. Before the patch, technique_override
is ignored (fewer rules compile) and keywords.exclude_regex: false is emulated with monkeypatch (marked below).
"""

from __future__ import annotations

import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from attacklens import config, sigma_detect, sigma_rules
from attacklens.detect_sql import OK, RAW_ALERT_COLUMNS
from attacklens.schemas import CANONICAL_COLUMNS

from .conftest import FIXTURES, run_ingest
from .sigma_fx import LABEL_COLUMNS, events_con

pytestmark = pytest.mark.sigma

REPO = Path(__file__).resolve().parents[2]
DRAFT = REPO / "reports" / "cloud" / "sigma_map_cloud.yaml"
CLOUD = REPO / "config" / "sigma" / "rules" / "cloud"
FOLDERS = {"aws_cloudtrail": "aws/cloudtrail", "azure_activity": "azure/activity_logs",
           "azure_audit": "azure/audit_logs", "azure_signin": "azure/signin_logs", "gcp_audit": "gcp/audit"}
GATE_TYPE = {"aws_cloudtrail": "cloudtrail_json", "azure_activity": "azure_activity_json",
             "azure_audit": "azure_activity_json", "azure_signin": "azure_signin_json", "gcp_audit": "gcp_audit_json"}
CLOUD_TYPES = frozenset(GATE_TYPE.values())
DRAFT_KEYS = ("cloud_logsources", "technique_override", "cloud_disable", "level_override", "label_override")
PATCHED = hasattr(sigma_rules, "RUNTIME_KEYS")      # the patch adds RUNTIME_KEYS + the four draft keys
COMPILED = ({"aws_cloudtrail": 52, "azure_activity": 26, "azure_audit": 35, "azure_signin": 15, "gcp_audit": 6}
            if PATCHED else
            {"aws_cloudtrail": 49, "azure_activity": 24, "azure_audit": 34, "azure_signin": 15, "gcp_audit": 6})
RUNNING = 69 if PATCHED else 65      # compiled minus cloud_disable (patched: 33 own level + 36 level_override)
T0 = 1792814400000                   # 2026-10-24T04:00:00Z


# ---------------------------------------------------------------- fixtures
def _keyword_column_patched(kw: Any) -> tuple[str | None, str | None]:
    """EMULATION of the patch's keyword_column (exclude_regex: false = no JSON/CEF exclusion); used only when the
    live sigma_rules is not patched yet."""
    if isinstance(kw, dict) and kw.get("exclude_regex") is False:
        expr = str(kw.get("expr") or "") or None
        return expr, "source_type IN (" + ", ".join(sigma_rules.lit(str(x)) for x in kw["source_types"]) + ")"
    return _ORIG_KEYWORD_COLUMN(kw)


_ORIG_KEYWORD_COLUMN = sigma_rules.keyword_column


@pytest.fixture(scope="module")
def draft_cfg(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """config/ (without the sigma/ rule tree: deep paths, MAX_PATH) + the draft appended to the TEMP sigma_map, unless
    the live sigma_map already carries it (patch applied: appending again would duplicate its YAML anchors)."""
    d = tmp_path_factory.mktemp("cloudcfg") / "config"
    shutil.copytree(config.CONFIG_DIR, d, ignore=shutil.ignore_patterns("sigma"))
    live = yaml.safe_load((d / "sigma_map.yaml").read_text(encoding="utf-8")) or {}
    if "cloud_logsources" not in live:
        with open(d / "sigma_map.yaml", "a", encoding="utf-8") as fh:
            fh.write("\n" + DRAFT.read_text(encoding="utf-8"))
    return config.load_config(d)


@pytest.fixture(scope="module")
def compiled(draft_cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """{logsource name: compile_dir output} - each cloud entry on its own folder, its fields as the field map."""
    mp = pytest.MonkeyPatch()
    if not PATCHED:
        mp.setattr(sigma_rules, "keyword_column", _keyword_column_patched)
    try:
        sm = draft_cfg["sigma_map"]
        base = {k: v for k, v in sm.items() if k not in ("disable", "cloud_disable", "level_override",
                                                         "cloud_logsources")}
        out = {}
        for e in sm["cloud_logsources"]:
            smap = {**base, "logsources": [e], "fields": e["fields"]}
            out[e["name"]] = sigma_rules.compile_dir(CLOUD / FOLDERS[e["name"]], smap, draft_cfg["attack"])
        return out
    finally:
        mp.undo()


def _uuids() -> dict[str, str]:
    """SigmaHQ uuid -> rule file stem, for every cloud rule file."""
    out = {}
    for f in CLOUD.rglob("*.yml"):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        out[str(doc["id"]).lower()] = f.stem
    return out


# ---------------------------------------------------------------- the draft itself
def test_draft_appends_without_clobbering_live_keys(draft_cfg: dict[str, Any]) -> None:
    live = config.load_config()["sigma_map"]
    sm = draft_cfg["sigma_map"]
    for k in ("logsources", "fields", "disable", "level_severity", "product_gates", "tactic_aliases"):
        assert sm[k] == live[k], k                      # an appended duplicate key would have replaced these
    if set(DRAFT_KEYS) & set(live):   # already applied: the live block must be the draft (one source of truth)
        assert {k: live.get(k) for k in DRAFT_KEYS} == {k: sm[k] for k in DRAFT_KEYS}
        draft = yaml.safe_load(DRAFT.read_text(encoding="utf-8"))   # the fixture did not append it: compare the file
        assert {k: live.get(k) for k in DRAFT_KEYS} == {k: draft[k] for k in DRAFT_KEYS}
    assert [e["name"] for e in sm["cloud_logsources"]] == list(FOLDERS)
    assert (len(sm["technique_override"]), len(sm["cloud_disable"]), len(sm["level_override"]),
            len(sm["label_override"])) == (6, 70, 38, 23)


def test_draft_ids_are_cloud_rules_with_valid_levels_and_techniques(draft_cfg: dict[str, Any]) -> None:
    sm, uu = draft_cfg["sigma_map"], _uuids()
    ids = [str(d["id"]).lower() for k in ("cloud_disable", "level_override") for d in sm[k]]
    assert len(ids) == len(set(ids)), Counter(ids).most_common(3)   # one run decision per rule
    tech_ids = [str(d["id"]).lower() for k in ("technique_override", "label_override") for d in sm[k]]
    assert set(ids + tech_ids) <= set(uu), set(ids + tech_ids) - set(uu)
    assert all(d["reason"] for d in sm["cloud_disable"])
    assert Counter(d["level"] for d in sm["level_override"]) == {"low": 37, "medium": 1}
    tech = draft_cfg["attack"]["techniques"]
    assert all(d["technique"] in tech for d in sm["technique_override"])


# ---------------------------------------------------------------- compile
def test_compile_counts(compiled: dict[str, dict[str, Any]]) -> None:
    assert {k: len(v["rules"]) for k, v in compiled.items()} == COMPILED
    reasons = Counter(s["reason"].split(":")[0] for v in compiled.values() for s in v["skipped"])
    assert reasons == {"no_attack_technique_tag": 25 if PATCHED else 31, "unmapped_field": 12}, reasons
    for v in compiled.values():   # no SQL error, no unsupported value / modifier in the mapped folders
        assert not [s for s in v["skipped"] if s["reason"] == "sql_compile_error"]


def test_running_set_after_disable(compiled: dict[str, dict[str, Any]], draft_cfg: dict[str, Any]) -> None:
    sm = draft_cfg["sigma_map"]
    rules = [r for v in compiled.values() for r in v["rules"]]
    off = {str(d["id"]).lower() for d in sm["cloud_disable"]}
    assert len([r for r in rules if str(r["sigma_id"]).lower() not in off]) == RUNNING
    if not PATCHED:
        pytest.skip("level_override / cloud_disable are applied by the patch (sigma_rules._filter)")
    s = sigma_rules.settings(draft_cfg)
    full = {"rules": rules, "exprs": [], "skipped": [], "files": 0, "parsed": len(rules)}
    run = sigma_rules._filter(full, s)
    assert len(run.rules) == RUNNING
    lo = {str(d["id"]).lower(): d["level"] for d in sm["level_override"]}
    sev = sm["level_severity"]
    for r in run.rules:
        want = lo.get(str(r["sigma_id"]).lower())
        if want:
            assert (r["level"], r["severity"]) == (want, sev[want]), r["path"]


def test_every_gate_and_field_is_restricted_to_its_cloud_type(compiled: dict[str, dict[str, Any]]) -> None:
    for name, v in compiled.items():
        st = GATE_TYPE[name]
        for r in v["rules"]:
            assert r["gate"].startswith(f"source_type = '{st}'"), (r["path"], r["gate"])
            assert set(re.findall(r"source_type = '([a-z_]+)'", r["gate"])) == {st}
            cols = sigma_rules.referenced_columns(r, v["exprs"])
            assert cols <= set(CANONICAL_COLUMNS), (r["path"], cols - set(CANONICAL_COLUMNS))
            assert not cols & LABEL_COLUMNS
        for e in v["exprs"]:
            assert not re.search(r"\b(threat|labels|labels_extra|event\.kind|event\.severity)\b", e), e
            if "raw_line" in e:   # JSON read or keyword column: only under its own source type
                assert (e.startswith(f"CASE WHEN source_type = '{st}' AND action <> 'malformed' THEN ")
                        or e.startswith(f"TRY_CAST(CASE WHEN source_type = '{st}' AND action <> 'malformed' THEN ")
                        or e.startswith(f"coalesce(CASE WHEN source_type = '{st}' AND action <> 'malformed' THEN ")
                        or e.startswith(f"CASE WHEN source_type IN ('{st}') THEN (raw_line) END")), (name, e)


def test_cloud_rules_never_match_or_parse_other_sources(compiled: dict[str, dict[str, Any]]) -> None:
    """Non-JSON raw lines that carry cloud API names: a JSON read on them would raise (Malformed JSON), a keyword /
    signature match would be a false positive. Also a malformed cloud line (CASE guard, even without the OK filter)."""
    rows = [{"source_type": s, "action": "other", "signature": "StopLogging", "app": "cloudtrail.amazonaws.com",
             "outcome": "success", "host": "acct", "raw_line": "<13>x StopLogging Microsoft.Authorization/"
             "roleAssignments/write image-policy.k8s.io/break-glass {not json"}
            for s in ("syslog", "ecs_json", "win_json", "fortigate_kv", "cef", "firewall_csv")]
    rows += [{"source_type": st, "action": "malformed", "ts_ok": False, "raw_line": "{\"eventName\": \"Stop"}
             for st in sorted(CLOUD_TYPES)]
    con = events_con(rows)
    try:
        for v in compiled.values():
            for r in v["rules"]:
                assert con.execute(f"SELECT count(*) FROM events WHERE {r['where']}").fetchone()[0] == 0, r["path"]
    finally:
        con.close()


# ---------------------------------------------------------------- hits on ingested fixtures
POSITIVE = {
    "ct.log": [
        {"eventVersion": "1.09", "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/mallory",
         "accountId": "111122223333", "userName": "mallory"}, "eventTime": "2026-10-24T04:00:00Z",
         "eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging", "awsRegion": "us-east-1",
         "sourceIPAddress": "203.0.113.99", "userAgent": "aws-cli/2.15.0", "requestParameters": {"name": "trail-1"},
         "responseElements": None, "eventID": "p-1", "readOnly": False, "eventType": "AwsApiCall",
         "recipientAccountId": "111122223333"},
        {"userIdentity": {"type": "IAMUser", "accountId": "111122223333", "userName": "mallory"},
         "eventTime": "2026-10-24T04:00:01Z", "eventSource": "guardduty.amazonaws.com", "eventName": "DeleteDetector",
         "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.99", "requestParameters": {"detectorId": "d1"},
         "eventID": "p-2", "recipientAccountId": "111122223333"},
        # denied: the rule wants errorCode null / Success
        {"userIdentity": {"type": "IAMUser", "accountId": "111122223333", "userName": "mallory"},
         "eventTime": "2026-10-24T04:00:02Z", "eventSource": "guardduty.amazonaws.com", "eventName": "UpdateDetector",
         "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.99",
         "requestParameters": {"detectorId": "d1", "enable": False}, "errorCode": "AccessDenied", "eventID": "p-3",
         "recipientAccountId": "111122223333"},
        {"userIdentity": {"type": "IAMUser", "accountId": "111122223333", "userName": "mallory"},
         "eventTime": "2026-10-24T04:00:03Z", "eventSource": "s3.amazonaws.com",
         "eventName": "PutBucketPublicAccessBlock", "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.99",
         "requestParameters": {"bucketName": "payroll", "PublicAccessBlockConfiguration": {
             "BlockPublicAcls": False, "BlockPublicPolicy": True, "IgnorePublicAcls": True,
             "RestrictPublicBuckets": True}}, "eventID": "p-4", "recipientAccountId": "111122223333"},
    ],
    "aza.log": [
        {"TimeGenerated": "2026-10-24T04:00:04Z", "OperationNameValue": "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
         "ActivityStatusValue": "Success", "CategoryValue": "Administrative", "Caller": "mallory@contoso.com",
         "CallerIpAddress": "203.0.113.99", "ResourceProviderValue": "MICROSOFT.AUTHORIZATION",
         "_ResourceId": "/subscriptions/sub-1/providers/microsoft.authorization/roleassignments/ra-1"},
        {"TimeGenerated": "2026-10-24T04:00:05Z", "OperationNameValue": "MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION",
         "ActivityStatusValue": "Success", "CategoryValue": "Administrative", "Caller": "mallory@contoso.com",
         "CallerIpAddress": "203.0.113.99", "_ResourceId": "/providers/microsoft.authorization"},
        {"TimeGenerated": "2026-10-24T04:00:06Z", "OperationName": "Disable Strong Authentication",
         "Result": "success", "Category": "UserManagement", "LoggedByService": "Core Directory",
         "InitiatedBy": {"user": {"userPrincipalName": "mallory@contoso.com", "ipAddress": "203.0.113.99"}},
         "TargetResources": [{"userPrincipalName": "bob@contoso.com", "type": "User"}]},
    ],
    "azs.log": [
        {"TimeGenerated": "2026-10-24T04:00:07Z", "OperationName": "Sign-in activity", "ResultType": "0",
         "UserPrincipalName": "mallory@contoso.com", "IPAddress": "203.0.113.99", "AppDisplayName": "Azure Portal",
         "ConditionalAccessStatus": "notApplied", "AuthenticationRequirement": "singleFactorAuthentication",
         "UserAgent": "BAV2ROPC"},
    ],
    "gcp.log": [
        {"insertId": "pg-1", "logName": "projects/acme-prod/logs/cloudaudit.googleapis.com%2Factivity",
         "protoPayload": {"status": {}, "authenticationInfo": {"principalEmail": "mallory@evil.example"},
                          "requestMetadata": {"callerIp": "203.0.113.99"}, "serviceName": "compute.googleapis.com",
                          "methodName": "v1.compute.packetMirrorings.insert",
                          "resourceName": "projects/acme-prod/regions/us-central1/packetMirrorings/pm-1"},
         "resource": {"type": "gce_packet_mirroring"}, "timestamp": "2026-10-24T04:00:08Z"},
        {"insertId": "pg-2", "logName": "projects/acme-prod/logs/cloudaudit.googleapis.com%2Factivity",
         "protoPayload": {"status": {}, "authenticationInfo": {"principalEmail": "mallory@evil.example"},
                          "requestMetadata": {"callerIp": "203.0.113.99"}, "serviceName": "k8s.io",
                          "methodName": "io.k8s.core.v1.pods.create",
                          "metadata": {"note": "image-policy.k8s.io/break-glass"}},
         "resource": {"type": "k8s_cluster"}, "timestamp": "2026-10-24T04:00:09Z"},
        # SetIamPolicy: no SigmaHQ gcp.audit rule covers it (native rule territory, rule_catalog.md §4)
        {"insertId": "pg-3", "logName": "projects/acme-prod/logs/cloudaudit.googleapis.com%2Factivity",
         "protoPayload": {"status": {}, "authenticationInfo": {"principalEmail": "mallory@evil.example"},
                          "serviceName": "cloudresourcemanager.googleapis.com", "methodName": "SetIamPolicy"},
         "resource": {"type": "project"}, "timestamp": "2026-10-24T04:00:10Z"},
    ],
}
# a syslog line naming the same APIs / keywords must hit nothing
SYSLOG = ("Oct 24 04:00:11 ws-fin-010 sshd[100]: note StopLogging Microsoft.Authorization/roleAssignments/write "
          "image-policy.k8s.io/break-glass\n")
# SigmaHQ uuid prefix -> offsets (s) from T0 of the positive lines it must hit (and nothing else in the set)
EXPECTED = {
    "4db60cc0": [0],     # aws_cloudtrail_disable_logging: StopLogging
    "d2656e78": [1],     # guardduty detector deleted (the AccessDenied update at +2 s does not count)
    "ab18a523": [3],     # bucket block public access weakened (JSON boolean false)
    "a622fcd2": [4],     # azure_granting_permission_detection: keyword roleAssignments/write (raw_line)
    "09438caa": [5],     # azure subscription permissions elevation (operationName)
    "7ea78478": [6],     # azure_mfa_disabled (audit: operationName + properties.result)
    "53bb4f7f": [7],     # signin bypassing MFA (Status + userAgent)
    "980a7598": [8],     # gcp_full_network_traffic_packet_capture (method_name 'v*.Compute...' wildcard, any case)
    "76737c19": [9],     # gcp breakglass (resource.type + logName id + keyword)
}


@pytest.fixture(scope="module")
def ingested(tmp_path_factory: pytest.TempPathFactory):
    import json
    tmp = tmp_path_factory.mktemp("cloudhits")
    raw = tmp / "raw"
    raw.mkdir()
    for name, docs in POSITIVE.items():
        (raw / name).write_text("".join(json.dumps(d) + "\n" for d in docs), encoding="utf-8")
    (raw / "sys.log").write_text(SYSLOG, encoding="utf-8")
    for i, f in enumerate(sorted((FIXTURES / "cloud").glob("*.jsonl"))):
        shutil.copy(f, raw / f"fx-{i}.log")
    ctx = run_ingest(raw, tmp)
    yield ctx
    ctx.con.close()


def _hits(con: Any, compiled: dict[str, dict[str, Any]]) -> dict[str, list[int]]:
    """{sigma uuid: sorted ts offsets (s) from T0} through each rule's `where`, cross-checked against the
    production grouped path (sigma_detect._run_group)."""
    cols = ", ".join(f"{c} {RAW_ALERT_COLUMNS.get(c, 'VARCHAR')}" for c in sigma_detect.HIT_COLUMNS)
    direct: dict[str, list[int]] = {}
    grouped: dict[str, list[int]] = {}
    uuid = {}
    for v in compiled.values():
        con.execute(f"CREATE OR REPLACE TEMP TABLE al_sigma_hits ({cols}, raw_line VARCHAR, rule_ids VARCHAR[])")
        for r in v["rules"]:
            uuid[r["id"]] = str(r["sigma_id"]).lower()
            got = [int(x[0]) for x in con.execute(
                f"SELECT ts_ms FROM events WHERE {OK} AND ({r['where']}) ORDER BY 1").fetchall()]
            if got:
                direct[r["id"]] = got
        gates = {r["gate"] for r in v["rules"]}
        assert len(gates) == 1, gates                   # one gate per cloud logsource (no product gate)
        sigma_detect._run_group(con, gates.pop(), v["rules"], v["exprs"], 250, 301)
        for ts, ids in con.execute("SELECT ts_ms, rule_ids FROM al_sigma_hits").fetchall():
            for i in ids:
                grouped.setdefault(i, []).append(int(ts))
    assert direct == {k: sorted(v) for k, v in grouped.items()}
    return {uuid[k]: [(t - T0) // 1000 for t in v] for k, v in direct.items()}


def test_positive_fixture_hits_key_rules(ingested, compiled: dict[str, dict[str, Any]],
                                         draft_cfg: dict[str, Any]) -> None:
    con = ingested.con
    assert dict(con.execute("SELECT source_type, count(*) FROM events GROUP BY 1").fetchall()) == {
        "cloudtrail_json": 9, "azure_activity_json": 6, "azure_signin_json": 4, "gcp_audit_json": 6, "syslog": 1}
    hits = _hits(con, compiled)
    pos = {u: [t for t in ts if 0 <= t <= 11] for u, ts in hits.items()}
    pos = {u: ts for u, ts in pos.items() if ts}
    for prefix, want in EXPECTED.items():
        got = [ts for u, ts in pos.items() if u.startswith(prefix)]
        assert got == [want], (prefix, got, pos)
    # no other RUNNING rule fires on the positive set (SetIamPolicy at +10 s and the syslog line at +11 s included);
    # disabled ones may: azure_ad_only_single_factor_auth_required (28eea407, noisy) matches the +7 s sign-in
    off = {str(d["id"]).lower() for d in draft_cfg["sigma_map"]["cloud_disable"]}
    assert {u[:8] for u in pos if u not in off} == set(EXPECTED), pos
    assert {u[:8] for u in pos if u in off} == {"28eea407"}, pos
    # the shared fixtures (2026-10-24T02:00). Running: failed console login, console login without MFA. Disabled
    # (cloud_disable confirms why): Entra 'Add user' (catalog: native rule), AssumedRole session (every role session),
    # VM write keyword (every VM write)
    old = {u: ts for u, ts in hits.items() if any(t < 0 for t in ts)}
    assert sorted(u[:8] for u in old if u not in off) == ["6393e346", "77caf516"], old
    assert sorted(u[:8] for u in old if u in off) == ["6f583da0", "905d389b", "d2d901db"], old
