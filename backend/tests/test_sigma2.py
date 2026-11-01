"""Sigma loader / runner (sigma_rules.py, sigma_detect.py): skip reasons, ATT&CK v20 labels, compile cache, run
controls (disable list, per-rule cap, native dedupe, on/off switches, live level). Burst gate + whole-catalogue
checks: test_sigma3.py.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from attacklens import sigma_detect, sigma_rules
from attacklens.schemas import TACTIC_IDX

from .sigma_fx import (SEC_WIN, T0, base_cfg, compile_docs, compile_one, direct_matches, matches,
                       native_alert, rid, rule_doc, run_sigma, shipped_smap, sigma_cfg, skip_reason)

pytestmark = pytest.mark.sigma


def sel(field: str, value) -> dict:
    return {"sel": {field: value}, "condition": "sel"}


def contains(token: str) -> dict:
    return sel("CommandLine|contains", token)


# ================================================================ skip reasons
@pytest.mark.parametrize("doc, reason", [
    (rule_doc(sel("Hashes|contains", "abc")), "unmapped_field:Hashes"),
    (rule_doc(contains("x"), logsource={"category": "driver_load", "product": "windows"}),
     "unmapped_logsource:windows/driver_load/None"),
    (rule_doc(contains("x"), logsource={"category": "process_creation", "product": "aix"}),
     "unmapped_logsource:aix/process_creation/None"),
    (rule_doc(contains("x"), tags=["attack.execution"]), "no_attack_technique_tag"),
    (rule_doc(contains("x"), tags=[]), "no_attack_technique_tag"),
    (rule_doc(contains("x"), tags=["attack.execution", "attack.t9999"]), "technique_not_in_v20"),
    (rule_doc(contains("x"), status="deprecated"), "status:deprecated"),
    (rule_doc(contains("x"), status="unsupported"), "status:unsupported"),
    (rule_doc({"keywords": ["mimikatz"], "condition": "keywords"}), "keyword_search_unmapped"),
    (rule_doc(sel("Channel", "Security"), logsource=SEC_WIN), "matches_every_gated_row"),
    (rule_doc(contains("x"), level=None), "level:None"),
])
def test_skip_reason(tmp_path: Path, doc: dict, reason: str) -> None:
    assert skip_reason(tmp_path, doc) == reason


def test_near_miss_of_each_skip_compiles(tmp_path: Path) -> None:
    docs = [rule_doc(sel("Image|endswith", "\\x.exe"), n=1),                         # mapped field
            rule_doc(contains("x"), n=2, tags=["attack.t1059"]),                     # technique tag only
            rule_doc(contains("x"), n=3, status="stable"),
            rule_doc({"sel": {"Channel": "Security", "EventID": 1102}, "condition": "sel"}, n=4, logsource=SEC_WIN,
                     tags=["attack.defense-evasion", "attack.t1070.001"])]           # assume_true + a real field
    out = compile_docs(tmp_path, docs)
    assert out["skipped"] == []
    assert [r["id"] for r in out["rules"]] == [rid(1), rid(2), rid(3), rid(4)]
    assert matches(out, [{"event_id": 1102, "action": "log_cleared"}, {"event_id": 4624}])[rid(4)] == [1]


def test_unparseable_yaml_is_skipped_not_fatal(tmp_path: Path) -> None:
    d = tmp_path / "bad"
    d.mkdir()
    (d / "a.yml").write_text("title: [unclosed\n  detection: {", encoding="utf-8")
    out = sigma_rules.compile_dir(d, shipped_smap(), base_cfg()["attack"])
    assert out["rules"] == [] and out["files"] == 1
    assert [s["path"] for s in out["skipped"]] == ["a.yml"]
    assert out["skipped"][0]["reason"].startswith("parse_error:")


def test_re2_invalid_regex_is_a_parse_error(tmp_path: Path) -> None:
    assert skip_reason(tmp_path, rule_doc(sel("CommandLine|re", "(a)\\1"))) == "parse_error:SigmaRegularExpressionError"


def test_duckdb_rejected_regex_is_isolated_by_bisect(tmp_path: Path) -> None:
    # (?<n>a) passes pySigma's RE2 but DuckDB's RE2 refuses it at bind time: only EXPLAIN can catch it
    docs = [rule_doc(contains(f"tok{i}"), n=i + 1) for i in range(5)]
    docs[2] = rule_doc(sel("CommandLine|re", "(?<n>a)"), n=3)
    out = compile_docs(tmp_path, docs, check_batch=2)
    assert [r["id"] for r in out["rules"]] == [rid(1), rid(2), rid(4), rid(5)]
    assert out["skipped"] == [{"path": "r002.yml", "reason": "sql_compile_error", "level": "high",
                               "status": "test"}]


def test_bad_mapped_expression_is_isolated_by_bisect(tmp_path: Path) -> None:
    smap = shipped_smap()
    smap["fields"] = {**smap["fields"], "Broken": "no_such_column"}
    docs = [rule_doc(contains("a"), n=1), rule_doc(sel("Broken", "x"), n=2), rule_doc(contains("b"), n=3)]
    out = compile_docs(tmp_path, docs, smap, check_batch=400)
    assert [r["id"] for r in out["rules"]] == [rid(1), rid(3)]
    assert [(s["path"], s["reason"]) for s in out["skipped"]] == [("r001.yml", "sql_compile_error")]


def _smap_with(entry: dict, policy: str = "skip") -> dict:
    smap = copy.deepcopy(shipped_smap())
    smap["logsources"] = [entry] + list(smap["logsources"])
    smap["unmapped_field_policy"] = policy
    return smap


KW = {"category": "kwtest"}


def test_unguarded_raw_line_keyword_column_is_refused(tmp_path: Path) -> None:
    smap = _smap_with({"name": "kw", "category": "kwtest", "gate": "action = 'other'", "keywords": "raw_line"})
    doc = rule_doc({"keywords": ["accepted password"], "condition": "keywords"}, logsource=KW)
    assert skip_reason(tmp_path, doc, smap) == "keyword_raw_line_unguarded"


KW_ROWS = [{"action": "other", "source_type": "syslog", "raw_line": "sshd[1]: ACCEPTED PASSWORD for root"},
           {"action": "other", "source_type": "ecs_json", "raw_line": "sshd[1]: ACCEPTED PASSWORD for root"},
           {"action": "other", "source_type": "cef", "raw_line": "sshd[1]: ACCEPTED PASSWORD for root"},
           {"action": "other", "source_type": "syslog", "raw_line": "sshd[1]: Failed password for root"}]


def test_guarded_raw_line_keyword_where_matches_only_listed_sources(tmp_path: Path) -> None:
    smap = _smap_with({"name": "kw", "category": "kwtest", "gate": "action = 'other'",
                       "keywords": {"expr": "raw_line", "source_types": ["syslog"]}})
    out = compile_docs(tmp_path, [rule_doc({"keywords": ["*Accepted password*"], "condition": "keywords"},
                                           logsource=KW)], smap)
    assert out["skipped"] == []
    # label-carrying sources (ecs_json, cef) are never keyword-searched, even with the same raw line
    assert direct_matches(out, KW_ROWS) == {rid(1): [1]}


# regression (was strict xfail): the keyword guard was raw SQL inside rule['scan'] and the grouped DISTINCT-tuple path
# had no source_type column -> Binder Error, the whole linux_syslog batch was dropped (0 alerts, uncounted).
def test_keyword_rule_runs_in_the_production_group(tmp_path: Path) -> None:
    ls = {"product": "linux", "service": "sshd"}
    tags = ["attack.initial-access", "attack.t1078"]
    docs = [rule_doc({"keywords": ["*Accepted password*"], "condition": "keywords"}, n=1, logsource=ls, tags=tags),
            rule_doc(sel("CommandLine|contains", "id -u"), n=2, logsource=ls, tags=tags)]
    rows = [{**KW_ROWS[0], "host": "srv-web-01"}, {**KW_ROWS[3], "host": "srv-web-01", "command_line": "id -u"}]
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs), rows)
    assert [(a["rule_id"], a["source_seq"]) for a in alerts] == [(rid(1), 1), (rid(2), 2)]
    assert (stats["sigma_batches_failed"], stats["sigma_rules_failed"], stats["sigma_failed_rule_ids"]) == (0, 0, [])


# regression (was strict xfail): a plain keyword compiled to whole-raw_line equality and could never match a line
def test_plain_keyword_is_a_substring_search(tmp_path: Path) -> None:
    smap = _smap_with({"name": "kw", "category": "kwtest", "gate": "action = 'other'",
                       "keywords": {"expr": "raw_line", "source_types": ["syslog"]}})
    out = compile_docs(tmp_path, [rule_doc({"keywords": ["Accepted password"], "condition": "keywords"},
                                           logsource=KW)], smap)
    assert direct_matches(out, KW_ROWS) == {rid(1): [1]}
    # near miss: the substring search must not become a fuzzy one ('accepted  password' / 'accepted' alone)
    near = [{"action": "other", "source_type": "syslog", "raw_line": r} for r in
            ("sshd[1]: Accepted  password for root", "sshd[1]: Accepted publickey for root",
             "x accepted password", "accepted passwor")]
    assert direct_matches(out, near) == {rid(1): [3]}


def test_narrow_policy_only_removes_matches(tmp_path: Path) -> None:
    smap = _smap_with({"name": "x", "category": "never"}, policy="narrow")
    a, h = {"CommandLine|contains": "aaa"}, {"Hashes|contains": "ff"}
    assert skip_reason(tmp_path, rule_doc({"h": h, "condition": "h"}), smap) == "unsatisfiable_without_unmapped"
    # unknown under NOT resolves to TRUE inside the NOT, so the rule can only lose matches -> constant FALSE
    assert skip_reason(tmp_path, rule_doc({"a": a, "h": h, "condition": "a and not h"}), smap) == \
        "unsatisfiable_without_unmapped"
    out = compile_one(tmp_path, {"a": a, "h": h, "condition": "a or h"}, smap)
    assert matches(out, [{"command_line": c} for c in ("aaa", "ff", None)]) == {rid(1): [1]}
    assert skip_reason(tmp_path, rule_doc({"a": a, "h": h, "condition": "a or h"})) == "unmapped_field:Hashes"


# ================================================================ ATT&CK v20 labels
def _labels(tmp_path: Path, tags: list[str]) -> tuple:
    r = compile_one(tmp_path, contains("x"), tags=tags)["rules"][0]
    return r["technique"], r.get("sub_technique"), r["tactic"], r["defense_evasion_to"]


@pytest.mark.parametrize("tags, want", [
    (["attack.defense-evasion", "attack.t1027"], ("T1027", None, "Stealth", "Stealth")),
    (["attack.defense-evasion", "attack.t1562.001"], ("T1562", "T1562.001", "Defense Impairment",
                                                      "Defense Impairment")),
    (["attack.defense_evasion", "attack.t1070.001"], ("T1070", "T1070.001", "Defense Impairment",
                                                      "Defense Impairment")),
    # T1055 is Privilege Escalation + Stealth in v20: the earliest tagged tactic wins, DE still recorded
    (["attack.defense-evasion", "attack.privilege-escalation", "attack.t1055"],
     ("T1055", None, "Privilege Escalation", "Stealth")),
    # sub-technique: parent + sub, even when the parent tag comes first
    (["attack.execution", "attack.t1059", "attack.t1059.001"], ("T1059", "T1059.001", "Execution", None)),
    (["attack.privilege-escalation", "attack.persistence", "attack.t1547.001"],
     ("T1547", "T1547.001", "Persistence", None)),
    (["attack.persistence", "attack.privilege-escalation", "attack.execution", "attack.t1053.005"],
     ("T1053", "T1053.005", "Execution", None)),
    # a tagged tactic the technique does not belong to is ignored -> the technique's default v20 tactic
    (["attack.persistence", "attack.t1059.001"], ("T1059", "T1059.001", "Execution", None)),
    (["attack.t1003.001"], ("T1003", "T1003.001", "Credential Access", None)),
    # unknown first technique, known second -> the known one
    (["attack.t9999", "attack.t1027"], ("T1027", None, "Stealth", None)),
])
def test_labels(tmp_path: Path, tags: list[str], want: tuple) -> None:
    assert _labels(tmp_path, tags) == want


# ================================================================ end to end: alert row, controls
ROWS = [{"command_line": c, "host": "ws-1", "src_user": "pmehta", "raw_line": f"raw {i}"}
        for i, c in enumerate(["benign", "run mimikatz now", "tokA tokB tokC", "tokA", "tokA"], start=1)]


def test_alert_row_exact_values(tmp_path: Path) -> None:
    cfg = sigma_cfg(tmp_path, [rule_doc(contains("mimikatz"), n=1)])
    stats, alerts = run_sigma(cfg, ROWS, work_dir=tmp_path / "work")
    assert len(alerts) == 1
    a = alerts[0]
    assert {k: a[k] for k in ("rule_id", "technique_id", "sub_technique_id", "technique_name", "tactic", "tactic_idx",
                              "severity", "ts_ms", "last_ts_ms", "source_seq", "host", "src_user", "target_user",
                              "raw_alert_count", "evidence_lines", "source_keys")} == {
        "rule_id": rid(1), "technique_id": "T1059", "sub_technique_id": "T1059.001", "technique_name": "PowerShell",
        "tactic": "Execution", "tactic_idx": TACTIC_IDX["Execution"], "severity": 75, "ts_ms": T0 + 1000,
        "last_ts_ms": T0 + 1000, "source_seq": 2, "host": "ws-1", "src_user": "pmehta", "target_user": None,
        "raw_alert_count": 1, "evidence_lines": ["raw 2"], "source_keys": [2]}
    assert (stats["enabled"], stats["sigma_rules_running"], stats["sigma_rules_fired"], stats["sigma_alerts"],
            stats["rows_matched"], stats["sigma_alerts_deduped"], stats["sigma_alerts_capped_by_rule"]) == \
        (True, 1, 1, 1, 1, 0, {})
    cov = json.loads((tmp_path / "work" / "sigma_coverage.json").read_text(encoding="utf-8"))
    assert cov["alerts_per_rule"] == {rid(1): 1} and cov["titles"] == {rid(1): "fx rule 1"}


def test_level_maps_to_configured_severity(tmp_path: Path) -> None:
    sev = base_cfg()["sigma_map"]["level_severity"]
    docs = [rule_doc(contains("mimikatz"), n=i + 1, level=lv) for i, lv in enumerate(("low", "medium", "critical"))]
    _, alerts = run_sigma(sigma_cfg(tmp_path, docs), ROWS)
    assert [(a["rule_id"], a["severity"]) for a in alerts] == [(rid(1), sev["low"]), (rid(2), sev["medium"]),
                                                               (rid(3), sev["critical"])]


def test_max_alerts_per_rule_keeps_earliest_and_counts_overflow(tmp_path: Path) -> None:
    rows = [{"command_line": "tokA", "host": "ws-1", "ts_ms": T0 + (10 - i) * 1000} for i in range(5)]
    rows.append({"command_line": "tokB", "host": "ws-1"})
    docs = [rule_doc(contains("tokA"), n=0xA), rule_doc(contains("tokB"), n=0xB)]
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs, max_alerts_per_rule=2), rows)
    assert stats["sigma_alerts_capped_by_rule"] == {rid(0xA): 3}
    assert stats["sigma_alerts"] == 3 and stats["rows_matched"] == 6
    # earliest by ts_ms (rows were written newest first): seq 5 (T0+6 s), seq 4 (T0+7 s)
    assert [(a["rule_id"], a["source_seq"]) for a in alerts] == [(rid(0xA), 5), (rid(0xA), 4), (rid(0xB), 6)]
    stats0, alerts0 = run_sigma(sigma_cfg(tmp_path, docs, max_alerts_per_rule=0), rows)
    assert stats0["sigma_alerts_capped_by_rule"] == {} and len(alerts0) == 6


@pytest.mark.parametrize("where", ["pipeline_id", "pipeline_uuid", "map_uuid"])
def test_disable_list(tmp_path: Path, where: str) -> None:
    docs = [rule_doc(contains("tokA"), n=0xA), rule_doc(contains("tokB"), n=0xB)]
    if where == "pipeline_id":
        cfg = sigma_cfg(tmp_path, docs, disable=[rid(0xB)])
    elif where == "pipeline_uuid":
        cfg = sigma_cfg(tmp_path, docs, disable=["0000000B-0000-4000-8000-000000000000"])
    else:
        cfg = sigma_cfg(tmp_path, docs)
        cfg["sigma_map"]["disable"] = [{"id": "0000000b-0000-4000-8000-000000000000", "reason": "fx"}]
    stats, alerts = run_sigma(cfg, ROWS)
    assert {a["rule_id"] for a in alerts} == {rid(0xA)}
    assert stats["sigma_rules_running"] == 1 and stats["sigma_rules_skipped_by_reason"] == {"disabled": 1}
    stats_all, alerts_all = run_sigma(sigma_cfg(tmp_path, docs), ROWS)                 # near miss: not disabled
    assert {a["rule_id"] for a in alerts_all} == {rid(0xA), rid(0xB)}


def test_dedupe_against_native(tmp_path: Path) -> None:
    docs = [rule_doc(contains("tokA"), n=0xA, tags=["attack.execution", "attack.t1059.001"]),   # same technique
            rule_doc(contains("tokB"), n=0xB, tags=["attack.defense-evasion", "attack.t1027"]),  # other tactic
            rule_doc(contains("tokC"), n=0xC, tags=["attack.execution", "attack.t1047"])]        # same tactic
    native = [native_alert(3, "T1059", "Execution", "ws-1"),          # covers row 3 on ws-1
              native_alert(4, "T1059", "Execution", "other-host")]    # row 4, but another host
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs), ROWS, native=native)
    sig = sorted((a["rule_id"], a["source_seq"]) for a in alerts if a["rule_id"].startswith("sigma_"))
    assert sig == [(rid(0xA), 4), (rid(0xA), 5), (rid(0xB), 3)]
    assert stats["sigma_alerts_deduped"] == 2 and stats["sigma_alerts"] == 3
    assert sorted(a["rule_id"] for a in alerts if not a["rule_id"].startswith("sigma_")) == ["native_fx"] * 2


@pytest.mark.parametrize("value", ["0", "false", "OFF", " no "])
def test_env_switch_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("ATTACKLENS_SIGMA", value)
    stats, alerts = run_sigma(sigma_cfg(tmp_path, [rule_doc(contains("mimikatz"))]), ROWS)
    assert stats == {"enabled": False, "live": False, "sigma_alerts": 0, "sigma_wall_s": 0.0} and alerts == []
    assert sigma_detect.enabled(sigma_cfg(tmp_path, [])) is False


def test_env_switch_on_and_config_switch_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATTACKLENS_SIGMA", "1")
    stats, alerts = run_sigma(sigma_cfg(tmp_path, [rule_doc(contains("mimikatz"))]), ROWS)
    assert stats["enabled"] is True and len(alerts) == 1
    stats, alerts = run_sigma(sigma_cfg(tmp_path, [rule_doc(contains("mimikatz"))], enabled=False), ROWS)
    assert stats["enabled"] is False and alerts == []


def test_live_runs_only_live_min_level(tmp_path: Path) -> None:
    docs = [rule_doc(contains("mimikatz"), n=1, level="medium"), rule_doc(contains("mimikatz"), n=2, level="high")]
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs, live_min_level="high"), ROWS, live=True)
    assert [a["rule_id"] for a in alerts] == [rid(2)] and stats["sigma_rules_running"] == 1
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs, live=False), ROWS, live=True)
    assert stats["enabled"] is False and alerts == []
    _, alerts = run_sigma(sigma_cfg(tmp_path, docs, live_min_level="high"), ROWS, live=False)  # batch: both
    assert [a["rule_id"] for a in alerts] == [rid(1), rid(2)]


def test_missing_rule_dir_runs_nothing(tmp_path: Path) -> None:
    cfg = sigma_cfg(tmp_path, [])
    cfg["pipeline"]["sigma"]["dir"] = str(tmp_path / "nope")
    stats, alerts = run_sigma(cfg, ROWS)
    assert (stats["sigma_rules_running"], stats["sigma_alerts"], alerts) == (0, 0, [])


# ================================================================ compile cache
def test_cache_filters_without_recompile_and_recompiles_on_change(tmp_path: Path,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    real = sigma_rules.compile_dir
    monkeypatch.setattr(sigma_rules, "compile_dir", lambda *a, **k: calls.append(1) or real(*a, **k))
    cfg = sigma_cfg(tmp_path, [rule_doc(contains("aaa"), n=1, level="high"),
                               rule_doc(contains("bbb"), n=2, level="medium", status="stable")])
    cache = Path(cfg["pipeline"]["sigma"]["cache_dir"])
    ids = lambda s: [r["id"] for r in s.rules]  # noqa: E731

    assert ids(sigma_rules.load(cfg)) == [rid(1), rid(2)] and len(calls) == 1
    assert len(list(cache.glob("sigma_*.json"))) == 1
    hi = copy.deepcopy(cfg)
    hi["pipeline"]["sigma"]["min_level"] = "high"
    s = sigma_rules.load(hi)
    assert ids(s) == [rid(1)] and s.coverage["filtered_out"] == {"below_min_level:medium": 1} and len(calls) == 1
    st = copy.deepcopy(cfg)
    st["pipeline"]["sigma"]["status"] = ["stable"]
    s = sigma_rules.load(st)
    assert ids(s) == [rid(2)] and s.coverage["filtered_out"] == {"status:test": 1} and len(calls) == 1
    sigma_rules._compiled.cache_clear()          # a new process: the on-disk cache serves it
    assert ids(sigma_rules.load(hi)) == [rid(1)] and len(calls) == 1

    rule = Path(cfg["pipeline"]["sigma"]["dir"]) / "r000.yml"
    rule.write_text(rule.read_text(encoding="utf-8").replace("aaa", "aaaa-changed"), encoding="utf-8")
    s = sigma_rules.load(cfg)
    assert len(calls) == 2 and "aaaa-changed" in s.rules[0]["where"]
    assert len(list(cache.glob("sigma_*.json"))) == 2

    smap_changed = copy.deepcopy(cfg)
    del smap_changed["sigma_map"]["fields"]["CommandLine"]
    s = sigma_rules.load(smap_changed)
    assert len(calls) == 3 and s.rules == [] and s.coverage["skipped_by_reason"] == {"unmapped_field": 2}


def test_corrupt_cache_file_recompiles(tmp_path: Path) -> None:
    cfg = sigma_cfg(tmp_path, [rule_doc(contains("aaa"))])
    sigma_rules.load(cfg)
    (f,) = Path(cfg["pipeline"]["sigma"]["cache_dir"]).glob("sigma_*.json")
    f.write_text("{not json", encoding="utf-8")
    sigma_rules._compiled.cache_clear()
    assert [r["id"] for r in sigma_rules.load(cfg).rules] == [rid(1)]
    assert json.loads(f.read_text(encoding="utf-8"))["rules"][0]["id"] == rid(1)

