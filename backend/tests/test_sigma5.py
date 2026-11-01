"""Sigma label_override (compile-time relabel) and the native-cloud dedupe (sigma_rules / sigma_options /
sigma_detect / the detect.py cloud hook):
- label_override {id, technique?, tactic?, reason}: technique REPLACES the rule's tagged techniques (technique_override
  only fills in when there is none); tactic must be one of that technique's v20 tactics, else a config error
  (ValueError); untouched rules keep their labels; the compile hash (Sigma cache key) changes;
- the shipped cloud label_override entries are valid and name running cloud rules;
- dedupe against native CLOUD alerts (detect_cloud via the detect.py hook): same event + host + same or parent/child
  technique -> the Sigma alert is dropped (native label and severity kept); a sibling sub-technique or another
  technique is never dropped, and a native cloud alert never dedupes on tactic alone (rules.yaml natives still do);
- detect.run runs the cloud hook BEFORE Sigma and hands Sigma the native cloud rule ids.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import duckdb
import pytest

from attacklens import config, detect, detect_cloud, detect_sql, sigma_detect, sigma_rules
from attacklens.detect_sql import RAW_ALERT_COLUMNS
from attacklens.sigma_options import label_overrides

from .sigma_fx import (base_cfg, compile_docs, events_con, native_alert, rid, rule_doc, shipped_smap, sigma_cfg,
                       write_rules)

pytestmark = pytest.mark.sigma

PE = "Privilege Escalation"


def contains(token: str) -> dict:
    return {"sel": {"CommandLine|contains": token}, "condition": "sel"}


def uuid(n: int) -> str:
    return f"{n:08x}-0000-4000-8000-000000000000"


DOCS = [rule_doc(contains("tokA"), n=0xA, tags=["attack.execution", "attack.t1059.001"]),
        rule_doc(contains("tokB"), n=0xB, tags=["attack.persistence", "attack.privilege-escalation",
                                                 "attack.t1098.003"]),
        rule_doc(contains("tokC"), n=0xC, tags=["attack.initial-access", "attack.t1078.002"])]


def _smap(overrides: list[dict[str, Any]]) -> dict[str, Any]:
    return {**shipped_smap(), "label_override": overrides}


def _labels(out: dict[str, Any]) -> dict[str, tuple]:
    return {r["id"]: (r["technique"], r.get("sub_technique"), r["tactic"]) for r in out["rules"]}


# ================================================================ label_override
def test_label_override_replaces_technique_and_tactic(tmp_path: Path) -> None:
    base = _labels(compile_docs(tmp_path, DOCS, _smap([])))
    assert base == {rid(0xA): ("T1059", "T1059.001", "Execution"), rid(0xB): ("T1098", "T1098.003", "Persistence"),
                    rid(0xC): ("T1078", "T1078.002", "Initial Access")}
    ov = [{"id": uuid(0xA), "technique": "T1651", "reason": "fx: cloud admin command"},       # sub -> other tech
          {"id": uuid(0xB), "tactic": PE, "reason": "fx: tactic only"},                         # tactic only
          {"id": rid(0xC), "technique": "t1078.004", "tactic": PE, "reason": "fx: by AttackLens id"}]
    out = compile_docs(tmp_path, DOCS, _smap(ov))
    assert out["skipped"] == []
    assert _labels(out) == {rid(0xA): ("T1651", None, "Execution"), rid(0xB): ("T1098", "T1098.003", PE),
                            rid(0xC): ("T1078", "T1078.004", PE)}
    assert {r["id"]: r.get("label_override") for r in out["rules"]} == {
        rid(0xA): "fx: cloud admin command", rid(0xB): "fx: tactic only", rid(0xC): "fx: by AttackLens id"}


def test_label_override_without_tactic_uses_tagged_tactics(tmp_path: Path) -> None:
    # T1098.003 is Persistence + Privilege Escalation: the earliest TAGGED tactic of the new technique wins
    doc = rule_doc(contains("tokD"), n=0xD, tags=["attack.privilege-escalation", "attack.initial-access",
                                                  "attack.t1078.004"])
    out = compile_docs(tmp_path, [doc], _smap([{"id": uuid(0xD), "technique": "T1098.003", "reason": "fx"}]))
    assert _labels(out) == {rid(0xD): ("T1098", "T1098.003", PE)}
    # no usable tagged tactic -> the technique's default v20 tactic
    out = compile_docs(tmp_path, [doc], _smap([{"id": uuid(0xD), "technique": "T1485", "reason": "fx"}]))
    assert _labels(out) == {rid(0xD): ("T1485", None, "Impact")}


def test_untouched_rules_are_unchanged(tmp_path: Path) -> None:
    plain = compile_docs(tmp_path, DOCS, _smap([]))
    over = compile_docs(tmp_path, DOCS, _smap([{"id": uuid(0xA), "technique": "T1651", "reason": "fx"}]))
    a = {r["id"]: r for r in plain["rules"]}
    b = {r["id"]: r for r in over["rules"]}
    for k in (rid(0xB), rid(0xC)):
        assert a[k] == b[k]
    assert "label_override" not in a[rid(0xA)]


@pytest.mark.parametrize("entry, msg", [
    ({"technique": "T1651", "tactic": "Persistence"}, "not a v20 tactic of T1651"),   # tactic outside technique
    ({"technique": "T9999"}, "not in attack_v20"),
    ({"technique": "T1651", "tactic": "Evasion"}, "not a v20 tactic"),
    ({}, "technique and/or tactic"),
    ({"technique": "T1651", "reason": ""}, "reason"),
])
def test_invalid_label_override_raises(tmp_path: Path, entry: dict, msg: str) -> None:
    d = {"id": uuid(0xA), "reason": "fx", **entry}
    with pytest.raises(ValueError, match=msg):
        label_overrides({"label_override": [d]}, base_cfg()["attack"])
    with pytest.raises(ValueError, match=msg):
        compile_docs(tmp_path, DOCS, _smap([d]))


def test_tactic_only_override_outside_the_rules_technique_raises(tmp_path: Path) -> None:
    # valid v20 tactic, but T1059.001 (the rule's own technique) is Execution only: config error at compile
    with pytest.raises(ValueError, match="not a v20 tactic of T1059.001"):
        compile_docs(tmp_path, DOCS, _smap([{"id": uuid(0xA), "tactic": "Persistence", "reason": "fx"}]))


def test_duplicate_label_override_raises() -> None:
    d = {"id": uuid(0xA), "technique": "T1651", "reason": "fx"}
    with pytest.raises(ValueError, match="duplicate"):
        label_overrides({"label_override": [d, {**d, "id": uuid(0xA).upper()}]}, base_cfg()["attack"])


def test_compile_hash_changes_and_load_relabels(tmp_path: Path) -> None:
    assert sigma_rules.COMPILER_VERSION == "7"
    assert "label_override" not in sigma_rules.RUNTIME_KEYS             # compile-time: part of the cache key
    attack = base_cfg()["attack"]
    root = write_rules(tmp_path, DOCS)
    files = sigma_rules.rule_files(root)
    ov = [{"id": uuid(0xA), "technique": "T1651", "reason": "fx"}]
    assert sigma_rules.content_key(files, root, _smap([]), attack) != sigma_rules.content_key(files, root, _smap(ov),
                                                                                                attack)
    cfg = sigma_cfg(tmp_path, DOCS)
    cfg["sigma_map"]["label_override"] = []
    first = {r["id"]: r["technique"] for r in sigma_rules.load(cfg).rules}
    cfg2 = copy.deepcopy(cfg)
    cfg2["sigma_map"]["label_override"] = ov
    s = sigma_rules.load(cfg2)                                          # same cache dir: must not serve the old one
    assert first[rid(0xA)] == "T1059" and {r["id"]: r["technique"] for r in s.rules}[rid(0xA)] == "T1651"
    assert s.coverage["label_overridden"] == 1
    bad = copy.deepcopy(cfg)
    bad["sigma_map"]["label_override"] = [{"id": uuid(0xA), "technique": "T1651", "tactic": "Impact", "reason": "x"}]
    with pytest.raises(ValueError):                                     # raised even before the cache is consulted
        sigma_rules.load(bad)


def test_shipped_label_overrides_are_valid_running_cloud_rules() -> None:
    cfg = config.load_config()
    sm = cfg["sigma_map"]
    ov = label_overrides(sm, cfg["attack"])                             # raises on any bad entry
    assert ov and all(v["reason"] for v in ov.values())
    off = {str(d["id"]).lower() for d in (sm.get("cloud_disable") or []) + (sm.get("disable") or [])
           if isinstance(d, dict)}
    assert not set(ov) & off, set(ov) & off                             # a relabel of a disabled rule is dead config
    assert "c1182e02-49a3-481c-b3de-0fadc4091488" in off                # azure_rare_operations stays disabled
    run = {str(r["sigma_id"]).lower(): r for r in sigma_rules.load(cfg).rules}
    for k, v in ov.items():
        r = run[k]
        assert r["logsource"] in ("aws_cloudtrail", "azure_activity", "azure_audit", "azure_signin", "gcp_audit")
        if v.get("technique"):
            assert (r.get("sub_technique") or r["technique"]) == v["technique"], r["path"]
        if v.get("tactic"):
            assert r["tactic"] == v["tactic"], r["path"]


# ================================================================ dedupe against native cloud alerts
ROWS = [{"command_line": f"tok{c} seq{i}", "host": "acct-1"} for i, c in enumerate("PSOQP", start=1)]
DEDUPE_DOCS = [rule_doc(contains("tokP"), n=0x1, tags=["attack.persistence", "attack.t1098"]),         # rows 1, 5
               rule_doc(contains("tokS"), n=0x2, tags=["attack.persistence", "attack.t1098.001"]),     # row 2
               rule_doc(contains("tokO"), n=0x3, tags=["attack.initial-access", "attack.t1078.004"]),  # row 3
               rule_doc(contains("tokQ"), n=0x4, tags=["attack.persistence", "attack.t1098.003"])]     # row 4


def _native(seq: int, technique: str, sub: str | None, tactic: str, host: str, rule_id: str,
            severity: int = 90) -> dict[str, Any]:
    a = native_alert(seq, technique, tactic, host, rule_id)
    a.update({"sub_technique_id": sub, "severity": severity})
    return a


def _run(cfg: dict[str, Any], native: list[dict[str, Any]], cloud_ids: list[str]
         ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    con = events_con(ROWS)
    try:
        detect_sql.prepare(con, cfg)
        cols = list(RAW_ALERT_COLUMNS)
        con.execute("CREATE OR REPLACE TEMP TABLE al_raw (" + ", ".join(f"{c} {t}" for c, t in
                                                                       RAW_ALERT_COLUMNS.items()) + ")")
        for a in native:
            con.execute(f"INSERT INTO al_raw VALUES ({', '.join('?' for _ in cols)})", [a[c] for c in cols])
        stats = sigma_detect.run(con, cfg, dict(cfg["rules"]["thresholds"]), native_cloud_ids=cloud_ids)
        cur = con.execute("SELECT * FROM al_raw ORDER BY rule_id, source_seq")
        names = [d[0] for d in cur.description]
        return stats, [dict(zip(names, r)) for r in cur.fetchall()]
    finally:
        con.close()


NATIVE = [_native(1, "T1098", "T1098.003", PE, "acct-1", "az_rbac_fx"),        # child of sigma T1098 -> dedupe
          _native(2, "T1098", "T1098.003", PE, "acct-1", "az_rbac_fx"),        # sibling of T1098.001 -> keep both
          _native(3, "T1190", None, "Initial Access", "acct-1", "cl_tactic_fx"),  # same tactic only -> keep (cloud)
          _native(4, "T1098", None, PE, "acct-1", "az_parent_fx"),             # parent of sigma T1098.003 -> dedupe
          _native(5, "T1098", "T1098.003", PE, "other", "az_rbac_fx")]         # other host -> keep


def test_dedupe_against_native_cloud(tmp_path: Path) -> None:
    cfg = sigma_cfg(tmp_path, DEDUPE_DOCS)
    stats, alerts = _run(cfg, NATIVE, ["az_rbac_fx", "cl_tactic_fx", "az_parent_fx"])
    sig = sorted((a["rule_id"], a["source_seq"]) for a in alerts if a["rule_id"].startswith("sigma_"))
    # row 1: T1098 vs native child T1098.003 -> dropped; row 4: T1098.003 vs native parent T1098 -> dropped;
    # row 2: sibling sub-technique, row 3: same tactic only, row 5: other host -> kept
    assert sig == [(rid(1), 5), (rid(2), 2), (rid(3), 3)]
    assert (stats["sigma_alerts_deduped"], stats["sigma_alerts_deduped_cloud"], stats["sigma_alerts"]) == (2, 2, 3)
    nat = sorted((a["rule_id"], a["source_seq"], a["sub_technique_id"], a["tactic"], a["severity"])
                 for a in alerts if not a["rule_id"].startswith("sigma_"))
    assert nat == sorted((a["rule_id"], a["source_seq"], a["sub_technique_id"], a["tactic"], a["severity"])
                         for a in NATIVE)                               # native labels and severity untouched


def test_rules_yaml_native_keeps_technique_or_tactic_dedupe(tmp_path: Path) -> None:
    # near miss: the SAME native rows not marked as cloud -> the rules.yaml semantics (technique OR tactic): row 2
    # (same parent T1098) and row 3 (same tactic) are deduped as before, row 5 (other host) is not
    cfg = sigma_cfg(tmp_path, DEDUPE_DOCS)
    stats, alerts = _run(cfg, NATIVE, [])
    sig = sorted((a["rule_id"], a["source_seq"]) for a in alerts if a["rule_id"].startswith("sigma_"))
    assert sig == [(rid(1), 5)]
    assert (stats["sigma_alerts_deduped"], stats["sigma_alerts_deduped_cloud"]) == (4, 0)


def test_detect_runs_cloud_hook_before_sigma(events_ctx, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = events_ctx([{"source_type": "cloudtrail_json", "action": "other", "host": "acct-1", "signature": "x"}])
    seen: dict[str, Any] = {}

    def fake_cloud(con: duckdb.DuckDBPyConnection, cfg: dict[str, Any], c: Any) -> dict[str, Any]:
        p = Path(c.work_dir) / "raw_alerts_cloud.parquet"
        a = _native(1, "T1098", "T1098.003", PE, "acct-1", "az_rbac_fx")
        con.execute("CREATE OR REPLACE TEMP TABLE fx_cloud (" + ", ".join(f"{k} {t}" for k, t in
                                                                         RAW_ALERT_COLUMNS.items()) + ")")
        con.execute(f"INSERT INTO fx_cloud VALUES ({', '.join('?' for _ in RAW_ALERT_COLUMNS)})",
                    [a[k] for k in RAW_ALERT_COLUMNS])
        con.execute(f"COPY fx_cloud TO {detect_sql.sql_path(p)} (FORMAT PARQUET)")
        return {"parquet": str(p), "wall_s": 0.0}

    def fake_sigma(con: duckdb.DuckDBPyConnection, *a: Any, native_cloud_ids: Any = (), **k: Any) -> dict[str, Any]:
        seen["al_raw"] = [r[0] for r in con.execute("SELECT DISTINCT rule_id FROM al_raw").fetchall()]
        seen["ids"] = sorted(native_cloud_ids)
        return {"enabled": False}

    monkeypatch.setattr(detect_cloud, "run_cloud", fake_cloud)
    monkeypatch.setattr(sigma_detect, "run", fake_sigma)
    res = detect.run(ctx)
    assert "az_rbac_fx" in seen["al_raw"] and seen["ids"] == ["az_rbac_fx"]
    assert res["alerts_per_rule"]["az_rbac_fx"] == 1
