"""Sigma: the burst-gate technique-confidence floor (incident_gate.burst) and two whole-catalogue static checks over
the vendored config/sigma rules (compiled once per content hash; the on-disk cache keeps these ~1 s): no running
rule reads a generator label column, and every running rule carries a valid ATT&CK v20 technique + tactic.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from attacklens import incident_gate, sigma_rules
from attacklens.schemas import CANONICAL_COLUMNS, TACTICS_V20

from .sigma_fx import LABEL_COLUMNS, T0, base_cfg, compile_docs, rule_doc, rid, shipped_smap

pytestmark = pytest.mark.sigma


def sel(field: str, value) -> dict:
    return {"sel": {field: value}, "condition": "sel"}


# ================================================================ gate: burst technique-confidence floor
def _eps(confs: list[float]) -> list[dict]:
    return [{"episode_id": f"e{i}", "subject_host": "ws-1", "ts_ms": T0 + i * 60_000, "technique_id": t,
             "rule_id": f"r{i}", "confidence": c} for i, (t, c) in enumerate(zip(("T1059.001", "T1027", "T1105"),
                                                                               confs))]


def test_burst_excludes_low_confidence_episodes_from_technique_count() -> None:
    p = {**incident_gate._params(base_cfg()), "burst_techniques": 3, "burst_rules": 2, "burst_window": 7_200_000,
         "burst_conf": 60, "burst_seeds": 0, "burst_tech_conf": 40}
    assert incident_gate.burst(_eps([70, 70, 40]), p) is True
    assert incident_gate.burst(_eps([70, 70, 39.9]), p) is False         # third technique below the floor
    assert incident_gate.burst(_eps([70, 70, 39.9]), {**p, "burst_tech_conf": 0}) is True   # 0 = literal
    assert incident_gate._params(base_cfg())["burst_tech_conf"] == float(
        base_cfg()["linking"]["gate"]["multi_technique_min_technique_conf"])


# ================================================================ whole catalogue (vendored config/sigma)
@pytest.fixture(scope="module")
def catalogue() -> sigma_rules.SigmaSet:
    """Every COMPILED rule, not only today's running subset: min_level / status / disable are runtime filters, so a
    config change could run any of them. Disk cache keyed by content hash: ~1 s cold, ~0.2 s warm."""
    cfg = base_cfg()
    cfg["pipeline"]["sigma"] = {**cfg["pipeline"]["sigma"], "min_level": "informational",
                                "status": ["stable", "test", "experimental"], "disable": []}
    cfg["sigma_map"]["disable"] = cfg["sigma_map"]["cloud_disable"] = []
    s = sigma_rules.load(cfg)
    assert len(s.rules) == s.coverage["compiled"] > 1000, s.coverage
    return s


def test_referenced_columns_catches_a_label_column(tmp_path: Path) -> None:
    smap = shipped_smap()
    smap["fields"] = {**smap["fields"], "Leak": "labels_extra"}
    out = compile_docs(tmp_path, [rule_doc(sel("Leak", "x"), n=1), rule_doc(sel("Image|endswith", "\\a.exe"), n=2)],
                       smap, check_batch=1)
    # labels_extra is not a column of events, so the EXPLAIN check drops that rule ...
    assert [(s["path"], s["reason"]) for s in out["skipped"]] == [("r000.yml", "sql_compile_error")]
    # ... and referenced_columns sees such an expression anyway (gate columns included, literals stripped)
    leak = {"gate": "action = 'proc_start'", "scan": "\x01L0\x01"}
    assert sigma_rules.referenced_columns(leak, ["labels_extra"]) == {"action", "labels_extra"}
    assert sigma_rules.referenced_columns(leak, ['"event.kind"']) == {"action", "event.kind"}
    assert sigma_rules.referenced_columns(leak, ["json_extract_string(raw_line, '$.threat')"]) == \
        {"action", "json_extract_string", "raw_line"}       # not a canonical column -> the catalogue check fails
    ok = next(r for r in out["rules"] if r["id"] == rid(2))
    assert sigma_rules.referenced_columns(ok, out["exprs"]) <= set(CANONICAL_COLUMNS)


def test_catalogue_never_reads_label_columns(catalogue: sigma_rules.SigmaSet) -> None:
    label_free = {"syslog", "fortigate_kv",   # cloud raw_line = ingest's label-stripped JSON (sources.yaml label_keys)
                  "cloudtrail_json", "azure_signin_json", "azure_activity_json", "gcp_audit_json"}
    for r in catalogue.rules:
        cols = sigma_rules.referenced_columns(r, catalogue.exprs)
        assert not cols & LABEL_COLUMNS, (r["id"], r["path"], cols & LABEL_COLUMNS)
        assert cols <= set(CANONICAL_COLUMNS), (r["id"], r["path"], cols - set(CANONICAL_COLUMNS))
        if "raw_line" in cols:   # raw lines of JSON / CEF sources may carry ground-truth labels
            srcs = set(re.findall(r"source_type = '([a-z_]+)'", r["gate"]))
            assert srcs and srcs <= label_free, (r["id"], r["path"], r["gate"])
    for i, e in enumerate(catalogue.exprs):
        assert not re.search(r"\b(threat|labels|labels_extra|event\.kind|event\.severity|event_kind|"
                             r"event_severity)\b", e), (i, e)


def test_catalogue_labels_are_v20(catalogue: sigma_rules.SigmaSet) -> None:
    tech = base_cfg()["attack"]["techniques"]
    assert len(TACTICS_V20) == 15
    seen = set()
    for r in catalogue.rules:
        assert r["id"] not in seen, r["id"]
        seen.add(r["id"])
        assert re.fullmatch(r"T\d{4}", r["technique"]) and r["technique"] in tech, (r["id"], r["technique"])
        sub = r.get("sub_technique")
        if sub:
            assert sub in tech and sub.split(".")[0] == r["technique"], (r["id"], sub)
        assert r["tactic"] in TACTICS_V20, (r["id"], r["tactic"])
        assert r["tactic"] in (tech[sub or r["technique"]].get("tactics") or []), (r["id"], r["tactic"])
        assert r["tactic"] != "Defense Evasion"
        assert r["level"] in sigma_rules.LEVELS and r["status"] not in sigma_rules.NEVER_STATUS


REPO = Path(__file__).resolve().parents[2]
OWN_CHANNEL = {"win_security": "security", "win_system": "system"}


def _detection_fields(det: Any) -> list[tuple[str, Any]]:
    """(field name without modifiers, value) for every field condition in a Sigma detection block."""
    out: list[tuple[str, Any]] = []
    for name, block in (det or {}).items():
        if name == "condition":
            continue
        for item in (block if isinstance(block, list) else [block]):
            if isinstance(item, dict):
                out += [(str(k).split("|")[0], v) for k, v in item.items()]
    return out


def test_catalogue_never_assumes_provider_or_foreign_channel(catalogue: sigma_rules.SigmaSet) -> None:
    """No compiled win_security / win_system rule may depend on Provider_Name (no canonical column), and a Channel
    constraint must be exactly the logsource's own channel (Security / System) - anything else would fire for every
    provider / channel sharing the EventID."""
    root = REPO / str(base_cfg()["pipeline"]["sigma"].get("dir") or "config/sigma")
    checked = 0
    for r in catalogue.rules:
        if r["logsource"] not in OWN_CHANNEL:
            continue
        doc = yaml.safe_load((root / r["path"]).read_text(encoding="utf-8"))
        for fname, value in _detection_fields(doc.get("detection")):
            assert fname != "Provider_Name", (r["id"], r["path"])
            if fname == "Channel":
                vals = value if isinstance(value, list) else [value]
                assert [str(v).lower() for v in vals] == [OWN_CHANNEL[r["logsource"]]], (r["id"], r["path"], value)
        checked += 1
    assert checked >= 1


# ================================================================ conftest switch (the fast suite depends on it)
def test_marked_tests_run_sigma() -> None:
    import os
    from attacklens import sigma_detect
    assert "ATTACKLENS_SIGMA" not in os.environ
    assert sigma_detect.enabled(base_cfg()) is True
