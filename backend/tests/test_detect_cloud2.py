"""detect_cloud contract: rule catalogue validity, no-op on non-cloud data, never raises, raw_alerts schema, no label
access, DuckDB memory_limit kept, CLI, and the StorageBlobLogs / Activity Log REST ingest shapes it relies on."""

from __future__ import annotations

import copy
import json
import re
import shutil
import time
from collections import Counter
from pathlib import Path

import pytest

from attacklens import detect_cloud
from attacklens.config import CONFIG_DIR, load_config

from .conftest import FIXTURES, make_events_parquet, query, run_ingest
from .test_detect_cloud import Ctx, history, run, subset, write_raw

BACKEND = Path(detect_cloud.__file__).resolve().parent
BEHAVIOURAL = {"cl_first_seen_api", "cl_first_seen_geo", "cl_rare_api_account", "cl_discovery_burst", "cl_denied_spike",
               "cl_impossible_travel", "cl_new_principal_privileged", "seq_new_key_used_new_ip", "seq_role_chain",
               "seq_grant_then_data_access", "seq_logging_off_then_write", "cl_session_multi_asn", "cl_mass_destruction",
               "cl_exfil_volume", "cl_dormant_identity_reactivated", "cl_new_user_agent_family",
               "seq_risky_signin_then_persistence", "cl_volume_zscore", "cl_storage_data_access"}
TEMPLATES = {"match", "first_seen", "distinct_burst", "rate_spike", "sequence", "geo_velocity", "multi_network_session",
             "new_source_burst"}
# generator label fields (CLAUDE.md): never read by detection, as a JSON path or a key name in SQL
LABEL_RX = re.compile(r"\$\.\"?(threat|rule|labels|labels_extra)\b|\$\.event\.(kind|severity|module|dataset)\b"
                      r"|['\"](threat|labels_extra)['\"]|label_keys|label_nested_keys|strip_keys")


@pytest.fixture(scope="module")
def cfg() -> dict:
    return load_config()


def test_catalogue_valid_counts_and_templates(cfg) -> None:
    rules, errs = detect_cloud.load_rules(cfg)
    assert errs == []
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)) and len(ids) >= 88       # 88 base rules; source tracks add prefixed ones
    assert BEHAVIOURAL <= set(ids) and len(set(ids) - BEHAVIOURAL) >= 69
    used = {b.get("template", "match") for r in rules for b in r["branches"]}
    assert used == TEMPLATES                                   # every template is exercised by a shipped rule
    clouds = Counter(c for r in rules if r["id"] not in BEHAVIOURAL for c in r["clouds"])
    assert {"aws", "azure", "gcp"} <= set(clouds) <= set(detect_cloud.CLOUDS)


def test_bad_rules_are_rejected(cfg) -> None:
    base = {"id": "x", "clouds": ["aws"], "technique": "T1098", "tactic": "Persistence", "severity": 50,
            "branches": [{"match": "true"}]}
    assert detect_cloud.check_rule(base, cfg["attack"]) == []
    assert detect_cloud.check_rule({**base, "technique": "T9999"}, cfg["attack"])
    assert detect_cloud.check_rule({**base, "tactic": "Impact"}, cfg["attack"])          # not a tactic of T1098
    assert detect_cloud.check_rule({**base, "clouds": ["oci"]}, cfg["attack"])
    assert detect_cloud.check_rule({**base, "branches": [{"template": "nope"}]}, cfg["attack"])
    assert detect_cloud.check_rule({**base, "branches": [{"match": "true", "label": "secondary"}]}, cfg["attack"])


def test_no_label_fields_referenced() -> None:
    files = [CONFIG_DIR / "rules_cloud.yaml", CONFIG_DIR / "cloud.yaml",
             *sorted(BACKEND.glob("detect_cloud*.py"))]
    for f in files:
        hits = [m.group(0) for m in LABEL_RX.finditer(f.read_text(encoding="utf-8"))]
        assert not hits, (f.name, hits)


def test_generated_sql_never_reads_label_fields(cfg, tmp_path) -> None:
    """Every branch's SQL, built against the shipped config, is free of label paths too."""
    ctx = make_events_parquet(tmp_path, [{"ts_ms": 1792807200000, "source_type": "cloudtrail_json",
                                          "raw_line": '{"eventName": "ListBuckets"}', "signature": "ListBuckets"}])
    from attacklens import detect_cloud_ev as cev
    from attacklens.detect_sql import prepare
    prepare(ctx.con, cfg)
    cc = cfg["cloud"]
    cev.build(ctx.con, cc, 301)
    detect_cloud.alert_tables(ctx.con)
    cols = tuple(c[0] for c in ctx.con.execute('DESCRIBE cloud_ev').fetchall())
    made: set[str] = set()
    rules, _ = detect_cloud.load_rules(cfg)
    th = cfg["rules"]["thresholds"]
    for r in rules:
        for i, b in enumerate(r["branches"]):
            sql = detect_cloud.branch_sql(r, i, b, cc, th, lambda c: cev.hist_table(ctx.con, c, made), cfg['attack'], cols)
            assert not LABEL_RX.search(sql), (r["id"], i)   # (every branch compiling: test_detect_cloud errors == 0)
    ctx.con.close()


def test_noop_on_non_cloud_data(cfg, tmp_path) -> None:
    rows = [{"ts_ms": 1792807200000 + i, "action": "proc_start", "host": "ws-1", "raw_line": "not json {"}
            for i in range(50)]
    ctx = make_events_parquet(tmp_path, rows)
    work = tmp_path / "work"
    work.mkdir()
    (work / detect_cloud.OUT_NAME).write_bytes(b"stale")       # a previous run's output must not survive
    t0 = time.perf_counter()
    st = detect_cloud.run_cloud(ctx.con, cfg, Ctx(work, ctx.events_glob))
    assert time.perf_counter() - t0 < 2.0
    assert st["skipped"] == "no cloud rows" and st["errors"] == 0 and st["alerts"] == 0
    assert not (work / detect_cloud.OUT_NAME).exists()
    tables = {r[0] for r in ctx.con.execute("SELECT table_name FROM duckdb_tables()").fetchall()}
    assert "cloud_ev" not in tables                             # no JSON pass was made
    ctx.con.close()


def test_never_raises(cfg, tmp_path) -> None:
    write_raw(tmp_path / "raw", [{"ct": history()["ct"][:30]}])
    ctx = run_ingest(tmp_path / "raw", tmp_path)
    bad = copy.deepcopy(cfg)
    bad["rules_cloud"]["rules"] = [
        {"id": "broken", "clouds": ["aws"], "technique": "T1098", "tactic": "Persistence", "severity": 50,
         "branches": [{"match": "no_such_column = 1"}]},
        {"id": "fine", "clouds": ["aws"], "technique": "T1580", "tactic": "Discovery", "severity": 50,
         "branches": [{"match": "is_ct AND api = 'DescribeInstances'"}]},
        {"id": "invalid", "clouds": ["aws"], "technique": "T0000", "tactic": "Discovery", "branches": [{"match": "true"}]}]
    st, alerts = run(ctx.con, bad, tmp_path / "w1", ctx.events_glob)
    assert st["errors"] == 2 and {a["rule_id"] for a in alerts} == {"fine"}
    broken = copy.deepcopy(cfg)
    broken["cloud"]["columns"] = {"bad name!": ["$.x"]}           # cloud_ev cannot even be built
    st2 = detect_cloud.run_cloud(ctx.con, broken, Ctx(tmp_path / "w2", ctx.events_glob))
    assert st2["errors"] == 1 and st2["alerts"] == 0 and st2["error_messages"]
    ctx.con.close()


def test_cli_end_to_end(cfg, tmp_path, monkeypatch) -> None:
    write_raw(tmp_path / "raw", [history()])
    ctx = run_ingest(tmp_path / "raw", tmp_path)
    ctx.con.close()
    small = subset(cfg, {"cl_first_seen_api", "cl_session_multi_asn"})
    monkeypatch.setattr("attacklens.config.load_config", lambda *a, **k: small)
    work = tmp_path / "out" / "work"
    assert detect_cloud.main(["--work", str(work), "--events", ctx.events_glob]) == 0
    assert (work / detect_cloud.OUT_NAME).exists()


def test_storageblob_ip_port_and_activity_rest_shape(tmp_path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    for f in ("storageblob.jsonl", "activity_rest.jsonl"):
        shutil.copy(FIXTURES / "cloud_detect" / f, raw / f"{f}.log")
    ctx = run_ingest(raw, tmp_path)
    blob = query(ctx, "SELECT * FROM events WHERE source_type = 'azure_storageblob_json' ORDER BY ts_ms")
    assert [(r["src_ip"], r["src_user"], r["app"], r["outcome"], r["signature"]) for r in blob] == [
        ("203.0.113.33", None, "accountkey", "success", "GetBlob"),          # "ip:port", no identity (AccountKey)
        ("2001:db8::7", "kiyer", "oauth", "success", "DeleteBlob"),          # "[v6]:port"
        ("10.1.0.22", "3a9e11f0-0000-4000-8000-00000000b0b0", "sas", "failure", "GetBlob")]
    assert blob[0]["bytes_out"] == 799434 and blob[0]["file_path"] == "/corpappassets/static/a.js"
    (rest,) = query(ctx, "SELECT * FROM events WHERE source_type = 'azure_activity_json'")
    assert (rest["signature"], rest["outcome"], rest["src_user"], rest["src_ip"]) == \
        ("Microsoft.Authorization/elevateAccess/action", "success", "mallory", "203.0.113.50")
    st, alerts = run(ctx.con, subset(ctx.cfg, {"az_elevate_access", "cl_exfil_volume", "cl_mass_destruction"}),
                     tmp_path / "work", ctx.events_glob)
    assert st["errors"] == 0
    assert [a["src_user"] for a in alerts if a["rule_id"] == "az_elevate_access"] == ["mallory"]
    ctx.con.close()


SUB = "9b0e6a51-0000-4000-8000-0000000000b2"
OWNER, CONTRIB, READER = ("8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "b24988ac-6180-42a0-ab88-20f7382dd24c",
                          "acdd72a7-3385-48ef-bd42-f606fba81ae7")


def _rbac_la(ts: str, role: str, principal: str, ra: str) -> dict:
    """Log Analytics AzureActivity: roleDefinitionId / principalId are top-level keys of Properties_d."""
    rid = f"/subscriptions/{SUB}/providers/microsoft.authorization/roleassignments/{ra}"
    return {"TenantId": "t-1", "TimeGenerated": ts, "CategoryValue": "Administrative",
            "OperationNameValue": "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", "ActivityStatusValue": "Success",
            "Caller": "kiyer@corp.example", "CallerIpAddress": "203.0.113.33", "CorrelationId": f"c-{ra}",
            "SubscriptionId": SUB, "_ResourceId": rid, "Type": "AzureActivity",
            "Properties_d": {"entity": rid, "principalId": principal, "principalType": "User",
                             "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/"
                                                 f"roleDefinitions/{role}"}}


def _rbac_rest(ts: str, role: str, principal: str, ra: str) -> dict:
    """Activity Log REST / Event Hub export: the request is a JSON string in properties.requestbody (PascalCase)."""
    rid = f"/subscriptions/{SUB}/resourceGroups/rg-data/providers/Microsoft.Authorization/roleAssignments/{ra}"
    body = {"Id": ra, "Properties": {"PrincipalId": principal, "Scope": rid.split("/providers/")[0],
                                     "RoleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/"
                                                         f"roleDefinitions/{role}"}}
    return {"authorization": {"action": "Microsoft.Authorization/roleAssignments/write", "scope": rid},
            "caller": "mallory@corp.example", "correlationId": f"r-{ra}", "eventDataId": f"e-{ra}",
            "eventTimestamp": ts, "httpRequest": {"clientIpAddress": "203.0.113.50", "method": "PUT"},
            "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"}, "resourceId": rid,
            "status": {"value": "Succeeded"}, "subscriptionId": SUB, "tenantId": "t-1",
            "properties": {"requestbody": json.dumps(body)}}


def test_rbac_privileged_assignment_both_activity_shapes(tmp_path) -> None:
    """Owner / Contributor role ids are read from Properties_d (Log Analytics) and from properties.requestbody
    (REST / Event Hub): 85 at subscription scope, 75 below it, base 35 for a non-privileged role. The alert's
    host is the resource acted on (the event's ingest host, as for Sigma), the principal is the target."""
    raw = tmp_path / "raw"
    raw.mkdir()
    p1, p2, p3 = (f"{i}249dcf7-517f-4c24-b062-d597e131898f" for i in (1, 2, 3))
    rows = [_rbac_la("2026-10-24T08:00:00Z", OWNER, p1, "a1"), _rbac_la("2026-10-24T08:05:00Z", READER, p3, "a3"),
            _rbac_rest("2026-10-24T08:10:00.0000000Z", CONTRIB, p2, "a2")]
    (raw / "activity.log").write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    ctx = run_ingest(raw, tmp_path)
    st, alerts = run(ctx.con, subset(ctx.cfg, {"az_rbac_privileged_assignment"}), tmp_path / "work", ctx.events_glob)
    assert st["errors"] == 0, st["error_messages"]
    got = sorted(((a["target_user"], a["severity"], a["host"], a["subject_host"]) for a in alerts), key=str)
    la, rd, rest = rows[0]["_ResourceId"], rows[1]["_ResourceId"], rows[2]["resourceId"].lower()   # ingest lower()
    assert got == [(p1, 85, la, la), (p2, 75, rest, rest), (p3, 35, rd, rd)]
    ctx.con.close()
