"""QA unit / white-box tests for the Stage 2 config validator and template parameter guards (track qa_coverage_unit).

Baseline coverage showed these RuleError / ValueError branches never ran: duplicate rule id, missing technique,
unknown template, unsupported kind, template SQL that does not compile, bad bf_key, bad lateral_direction, bad
signature direction, empty lateral_ports (default T1021). Each case gets the shipped rule as the near miss.
detect._validate_uncached is called directly so the content cache cannot hide a failure.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from attacklens import config, detect, detect_sql


@pytest.fixture(scope="module")
def cfg() -> dict[str, Any]:
    return config.load_config()


def _rule(cfg: dict[str, Any], rid: str) -> dict[str, Any]:
    return copy.deepcopy(next(r for r in cfg["rules"]["rules"] if r["id"] == rid))


def _with(cfg: dict[str, Any], rules: list[dict[str, Any]]) -> dict[str, Any]:
    out = copy.deepcopy(cfg)
    out["rules"]["rules"] = rules
    return out


MATCH = {"id": "zz_m", "kind": "match", "where": "action = 'log_cleared'", "technique": "T1070",
         "tactic": "Defense Impairment", "severity": 10}


def test_minimal_valid_config_passes(cfg) -> None:
    detect._validate_uncached(_with(cfg, [dict(MATCH), _rule(cfg, "brute_force_then_success")]))


def test_duplicate_rule_id(cfg) -> None:
    with pytest.raises(detect.RuleError, match=r"^zz_m: duplicate rule id$"):
        detect._validate_uncached(_with(cfg, [dict(MATCH), dict(MATCH)]))


def test_missing_technique_primary_and_secondary(cfg) -> None:
    bad = {k: v for k, v in MATCH.items() if k != "technique"}
    with pytest.raises(detect.RuleError, match=r"^zz_m: missing technique$"):
        detect._validate_uncached(_with(cfg, [bad]))
    sec = {**MATCH, "secondary": {"tactic": "Initial Access", "severity": 50}}   # secondary without technique
    with pytest.raises(detect.RuleError, match=r"^zz_m: missing technique$"):
        detect._validate_uncached(_with(cfg, [sec]))


def test_bad_sub_technique_in_signature(cfg) -> None:
    sig = {**MATCH, "signatures": [{"pattern": "x", "technique": "T1070", "sub_technique": "T1070.999",
                                    "tactic": "Defense Impairment"}]}
    with pytest.raises(detect.RuleError, match=r"^zz_m: technique T1070\.999 not in attack_v20\.json$"):
        detect._validate_uncached(_with(cfg, [sig]))


def test_unknown_template_and_kind(cfg) -> None:
    tpl = {**_rule(cfg, "brute_force_then_success"), "template": "no_such_template"}
    with pytest.raises(detect.RuleError, match=r"^brute_force_then_success: unknown template 'no_such_template'$"):
        detect._validate_uncached(_with(cfg, [tpl]))
    kind = {**MATCH, "kind": "magic"}
    with pytest.raises(detect.RuleError, match=r"^zz_m: unsupported kind 'magic'$"):
        detect._validate_uncached(_with(cfg, [kind]))


def test_template_filter_that_does_not_compile(cfg) -> None:
    tpl = {**_rule(cfg, "brute_force_then_success"), "filter": "no_such_column = 1"}
    with pytest.raises(detect.RuleError, match=r"^brute_force_then_success: SQL does not compile"):
        detect._validate_uncached(_with(cfg, [tpl]))


@pytest.mark.parametrize("key, ok", [(["target_user", "host"], True), (["target_user", "host", "src_ip"], True),
                                     (["host"], False), (["target_user", "host", "process_name"], False)])
def test_bf_key_guard(cfg, key: list[str], ok: bool) -> None:
    tpl = {**_rule(cfg, "brute_force_then_success"), "params": {"bf_key": key}}
    if ok:
        detect._validate_uncached(_with(cfg, [tpl]))
    else:
        with pytest.raises(ValueError, match=r"^bf_key .*must contain host and target_user"):
            detect._validate_uncached(_with(cfg, [tpl]))


def test_lateral_direction_guard_and_default_ports(cfg) -> None:
    base = _rule(cfg, "internal_lateral")
    with pytest.raises(ValueError, match=r"^lateral_direction 'sideways': expected internal or inbound$"):
        detect._validate_uncached(_with(cfg, [{**base, "params": {"lateral_direction": "sideways"}}]))
    detect._validate_uncached(_with(cfg, [{**base, "params": {"lateral_direction": "inbound"}}]))   # near miss
    # empty lateral_ports -> {0: T1021}: the template still compiles (no IN () parse error)
    detect._validate_uncached(_with(cfg, [{**base, "params": {"lateral_ports": {}}}]))


def test_signature_direction_guard(cfg) -> None:
    base = _rule(cfg, "ips_signatures")
    sigs = copy.deepcopy(base["signatures"])
    sigs[0]["direction"] = "upward"
    with pytest.raises(ValueError, match=r"^signature direction 'upward': expected inbound, outbound or internal$"):
        detect._validate_uncached(_with(cfg, [{**base, "signatures": sigs}]))
    sigs[0]["direction"] = "outbound"                                                  # near miss
    detect._validate_uncached(_with(cfg, [{**base, "signatures": sigs}]))


# ---- detect_sql literal helpers ---------------------------------------------------------------------------------
@pytest.mark.parametrize("value, sql", [(None, "NULL"), (True, "TRUE"), (False, "FALSE"), (3, "3"), (2.5, "2.5"),
                                        ("O'Brien", "'O''Brien'"), ("", "''")])
def test_q_literals(value: Any, sql: str) -> None:
    assert detect_sql.q(value) == sql


def test_sql_list_never_empty() -> None:
    assert detect_sql.sql_list([]) == "(NULL)"
    assert detect_sql.sql_list(["a", 1, None]) == "('a', 1, NULL)"


def test_labels_of_primary_secondary_signatures() -> None:
    rule = {"technique": "T1110", "sub_technique": "T1110.001", "tactic": "Credential Access", "severity": 75,
            "secondary": {"technique": "T1078", "tactic": "Initial Access", "severity": 85},
            "signatures": [{"technique": "T1190", "tactic": "Initial Access"}]}
    assert detect_sql.labels_of(rule) == [("primary", "T1110", "T1110.001", "Credential Access", 9, 75),
                                          ("secondary", "T1078", None, "Initial Access", 3, 85),
                                          ("sig0", "T1190", None, "Initial Access", 3, 75)]  # inherits rule severity


def test_empty_raw_alerts_sql_has_contract_columns() -> None:
    import duckdb
    con = duckdb.connect()
    try:
        cols = [d[0] for d in con.execute(detect_sql.empty_raw_alerts_sql()).description]
        n = con.execute(f"SELECT count(*) FROM ({detect_sql.empty_raw_alerts_sql()})").fetchone()[0]
    finally:
        con.close()
    # DEVELOPMENT.md §15.4 raw_alerts columns (binding)
    assert cols[:5] == ["rule_id", "technique_id", "sub_technique_id", "technique_name", "tactic"]
    assert {"evidence_lines", "source_keys", "raw_alert_count", "subject_host", "src_host", "dst_host"} <= set(cols)
    assert n == 0


def test_ensure_events_creates_empty_view_without_parquet(tmp_path) -> None:
    import duckdb
    con = duckdb.connect()
    try:
        detect_sql.ensure_events(con, (tmp_path / "events" / "**" / "*.parquet").as_posix())
        assert con.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        have = {r[0] for r in con.execute("DESCRIBE SELECT * FROM events").fetchall()}
    finally:
        con.close()
    assert {"ts_ms", "ts_ok", "action", "host", "raw_line", "source_seq"} <= have
