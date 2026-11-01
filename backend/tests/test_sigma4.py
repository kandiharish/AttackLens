"""Sigma regressions for the BB-detect fixes of 31 Oct (sigma_detect / sigma_compile / sigma_rules / sigma_map.yaml):
- the per-rule cap runs AFTER the native dedupe (covered hits never consume the cap; later distinct hits survive);
- a failing batch is retried rule by rule and every failure is counted (sigma_batches_failed / _rules_failed / ids);
- Provider_Name and any Channel other than the logsource's own are never assumed true (skipped, unmapped_field);
- a syslog-framed JSON / CEF payload (the generator's syslog sink wraps label-carrying ECS JSON) is never
  keyword-searched, so label text cannot create a match;
- al_sigma_labels (columnar unnest insert) holds exactly one typed row per rule.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from attacklens import sigma_detect, sigma_rules

from .sigma_fx import (SEC_WIN, compile_one, events_con, matches, native_alert, rid, rule_doc, run_sigma,
                       sigma_cfg, skip_reason)

pytestmark = pytest.mark.sigma

WIN_SYS = {"product": "windows", "service": "system"}
LINUX_SSHD = {"product": "linux", "service": "sshd"}
T1078 = ["attack.initial-access", "attack.t1078"]


def contains(token: str) -> dict:
    return {"sel": {"CommandLine|contains": token}, "condition": "sel"}


def sigma_pairs(alerts: list[dict]) -> list[tuple[str, int]]:
    return [(a["rule_id"], a["source_seq"]) for a in alerts if a["rule_id"].startswith("sigma_")]


# ================================================================ cap after dedupe
CAP_ROWS = [{"command_line": "tokA", "host": "ws-1"} for _ in range(5)]          # seq 1..5, ts T0 + 0..4 s


def test_cap_applies_after_native_dedupe(tmp_path: Path) -> None:
    docs = [rule_doc(contains("tokA"), n=0xA)]                                    # T1059.001 / Execution
    native = [native_alert(1, "T1059", "Execution", "ws-1"), native_alert(2, "T1059", "Execution", "ws-1")]
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs, max_alerts_per_rule=2), CAP_ROWS, native=native)
    # the two earliest hits are covered by native alerts -> deduped; the cap then keeps the next two (3, 4).
    # cap-before-dedupe would keep 1, 2 and then delete both: 0 Sigma alerts.
    assert sigma_pairs(alerts) == [(rid(0xA), 3), (rid(0xA), 4)]
    assert (stats["sigma_alerts_deduped"], stats["sigma_alerts_capped_by_rule"], stats["sigma_alerts"],
            stats["rows_matched"]) == (2, {rid(0xA): 1}, 2, 5)


def test_cap_without_covering_native_keeps_earliest(tmp_path: Path) -> None:
    # near miss: the native alerts are on another host -> nothing deduped, the cap keeps 1, 2 and counts 3 over
    docs = [rule_doc(contains("tokA"), n=0xA)]
    native = [native_alert(1, "T1059", "Execution", "other"), native_alert(2, "T1059", "Execution", "other")]
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs, max_alerts_per_rule=2), CAP_ROWS, native=native)
    assert sigma_pairs(alerts) == [(rid(0xA), 1), (rid(0xA), 2)]
    assert (stats["sigma_alerts_deduped"], stats["sigma_alerts_capped_by_rule"], stats["sigma_alerts"]) == \
        (0, {rid(0xA): 3}, 2)


# ================================================================ batch / group failures are counted
FAIL_ROWS = [{"command_line": c, "host": "ws-1"} for c in ("tokA", "tokB", "tokC")]
BAD_REGEX = " AND regexp_matches('x', '(?<n>a)')"          # DuckDB's RE2 refuses this at bind time


def _inject(monkeypatch: pytest.MonkeyPatch, n: int, how: str) -> None:
    """Break rule rid(n) after compile (past the EXPLAIN check), like a predicate that only fails at run time."""
    real = sigma_rules.load

    def fake(cfg: dict[str, Any]) -> sigma_rules.SigmaSet:
        s = real(cfg)
        rules = copy.deepcopy(s.rules)
        for r in rules:
            if r["id"] == rid(n):
                if how == "scan":
                    r["scan"] = f"({r['scan']}){BAD_REGEX}"
                else:
                    r["gate"] = f"({r['gate']}) AND no_such_column = 1"
        return sigma_rules.SigmaSet(rules, s.exprs, s.coverage)
    monkeypatch.setattr(sigma_rules, "load", fake)


@pytest.mark.parametrize("bs", [250, 1])
def test_failing_rule_is_isolated_and_counted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bs: int) -> None:
    docs = [rule_doc(contains(t), n=i + 1) for i, t in enumerate(("tokA", "tokB", "tokC"))]
    _inject(monkeypatch, 2, "scan")
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs, batch_size=bs), FAIL_ROWS)
    # the batch holding rule 2 fails once, is retried rule by rule: 1 and 3 still alert, 2 is counted
    assert sigma_pairs(alerts) == [(rid(1), 1), (rid(3), 3)]
    assert (stats["sigma_batches_failed"], stats["sigma_rules_failed"], stats["sigma_failed_rule_ids"]) == \
        (1, 1, [rid(2)])
    assert stats["sigma_rules_running"] == 3 and stats["sigma_alerts"] == 2


def test_failing_gate_counts_every_rule_of_its_group(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    docs = [rule_doc(contains(t), n=i + 1) for i, t in enumerate(("tokA", "tokB", "tokC"))]
    _inject(monkeypatch, 2, "gate")              # rule 2 now has its own (broken) gate -> its own group fails
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs), FAIL_ROWS)
    assert sigma_pairs(alerts) == [(rid(1), 1), (rid(3), 3)]
    assert (stats["sigma_batches_failed"], stats["sigma_rules_failed"], stats["sigma_failed_rule_ids"]) == \
        (1, 1, [rid(2)])


def test_no_failure_counts_zero(tmp_path: Path) -> None:
    docs = [rule_doc(contains(t), n=i + 1) for i, t in enumerate(("tokA", "tokB", "tokC"))]
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs, batch_size=1), FAIL_ROWS)
    assert sigma_pairs(alerts) == [(rid(1), 1), (rid(2), 2), (rid(3), 3)]
    assert (stats["sigma_batches_failed"], stats["sigma_rules_failed"], stats["sigma_failed_rule_ids"]) == (0, 0, [])


# ================================================================ assume_true: only the logsource's own Channel
@pytest.mark.parametrize("det, logsource, reason", [
    ({"Provider_Name": "Service Control Manager", "EventID": 7045}, WIN_SYS, "unmapped_field:Provider_Name"),
    ({"Provider_Name": "Microsoft-Windows-Eventlog", "EventID": 1102}, SEC_WIN, "unmapped_field:Provider_Name"),
    ({"Channel": "System", "EventID": 1102}, SEC_WIN, "unmapped_field:Channel"),
    ({"Channel": "Security", "EventID": 7045}, WIN_SYS, "unmapped_field:Channel"),
    ({"Channel|contains": "Secur", "EventID": 1102}, SEC_WIN, "unmapped_field:Channel"),
    ({"Channel": "Sec*", "EventID": 1102}, SEC_WIN, "unmapped_field:Channel"),
    ({"Channel": ["Security", "System"], "EventID": 1102}, SEC_WIN, "unmapped_field:Channel"),
    ({"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}, SEC_WIN, "unmapped_field:Channel"),
])
def test_provider_and_foreign_channel_never_assumed(tmp_path: Path, det: dict, logsource: dict,
                                                    reason: str) -> None:
    doc = rule_doc({"sel": det, "condition": "sel"}, logsource=logsource,
                   tags=["attack.persistence", "attack.t1543.003"])
    assert skip_reason(tmp_path, doc) == reason


@pytest.mark.parametrize("channel, logsource, event_id", [("System", WIN_SYS, 7045), ("security", SEC_WIN, 1102)])
def test_own_channel_is_implied(tmp_path: Path, channel: str, logsource: dict, event_id: int) -> None:
    # near miss: the logsource's own channel (any case) is implied by the gate and only EventID is tested
    out = compile_one(tmp_path, {"sel": {"Channel": channel, "EventID": event_id}, "condition": "sel"},
                      logsource=logsource, tags=["attack.persistence", "attack.t1543.003"])
    rows = [{"event_id": event_id, "action": "other"}, {"event_id": 4624, "action": "login_success"},
            {"event_id": event_id, "action": "other", "source_type": "syslog"}]   # outside the gate's sources
    assert matches(out, rows) == {out["rules"][0]["id"]: [1]}
    assert out["rules"][0]["fields"] == ["EventID"]


# ================================================================ keyword search never reads label payloads
LABEL_JSON = ('{"@timestamp":"2026-10-24T02:00:00.000Z","event":{"action":"user_logon"},'
              '"rule":{"name":"Accepted password"},"threat":{"technique":{"id":["T1078"]}}}')
LABEL_CEF = ("CEF:0|Mitigata|SimEDR|1.0|R-1078|Accepted password|8|rt=2026-10-24T02:00:00Z dvchost=srv-web-01")
KW_LINES = [
    ("syslog", "sshd[1]: Accepted password for root from 10.0.0.1 port 2222 ssh2"),     # 1 plain syslog: match
    ("syslog", f"<134>Oct 24 02:00:00 collector SimEDR: {LABEL_JSON}"),                 # 2 generator syslog sink
    ("syslog", '<134>Oct 24 02:00:00 collector SimEDR: { "rule": {"name": "Accepted password"}}'),  # 3 spaced
    ("syslog", f"<134>Oct 24 02:00:00 collector SimEDR: {LABEL_CEF}"),                  # 4 CEF in a frame
    ("syslog", "<134>Oct 24 02:00:00 fw CEF: 0|V|P|1|1|Accepted password|5|"),          # 5 CEF with a space
    ("syslog", "sshd[1]: Accepted password for user {admin} from 10.0.0.1"),            # 6 brace, not JSON: match
    ("ecs_json", "sshd[1]: Accepted password for root"),                                # 7 label-carrying source
    ("syslog", "sshd[1]: Accepted password for svc CEF:abc"),                           # 8 'CEF:' not a header
]


def test_keyword_never_matches_syslog_wrapped_json_or_cef(tmp_path: Path) -> None:
    rows = [{"source_type": s, "raw_line": line, "host": "srv-web-01"} for s, line in KW_LINES]
    for kw in ("Accepted password", "*accepted password*"):
        out = compile_one(tmp_path, {"keywords": [kw], "condition": "keywords"}, logsource=LINUX_SSHD, tags=T1078)
        assert matches(out, rows) == {rid(1): [1, 6, 8]}, kw


def test_label_only_keyword_never_matches(tmp_path: Path) -> None:
    # 'T1078' and 'R-1078' exist only inside the generator's label fields: no line may match
    rows = [{"source_type": s, "raw_line": line, "host": "srv-web-01"} for s, line in KW_LINES]
    out = compile_one(tmp_path, {"keywords": ["T1078", "R-1078"], "condition": "keywords"}, logsource=LINUX_SSHD,
                      tags=T1078)
    assert matches(out, rows) == {rid(1): []}


def test_keyword_rule_end_to_end_ignores_wrapped_payloads(tmp_path: Path) -> None:
    rows = [{"source_type": s, "raw_line": line, "host": "srv-web-01"} for s, line in KW_LINES]
    docs = [rule_doc({"keywords": ["Accepted password"], "condition": "keywords"}, logsource=LINUX_SSHD, tags=T1078)]
    stats, alerts = run_sigma(sigma_cfg(tmp_path, docs), rows)
    assert sigma_pairs(alerts) == [(rid(1), 1), (rid(1), 6), (rid(1), 8)]
    assert stats["sigma_rules_failed"] == 0
    assert all("threat" not in line and "CEF:0" not in line for a in alerts for line in a["evidence_lines"])


# ================================================================ columnar label insert
def test_labels_table_exact_rows_and_types() -> None:
    rules = [{"id": "sigma_b", "technique": "T1027", "tactic": "Stealth", "severity": 55},
             {"id": "sigma_a", "technique": "T1059", "sub_technique": "T1059.001", "tactic": "Execution",
              "severity": 75},
             {"id": "sigma_c'q", "technique": "T1070", "sub_technique": "T1070.001", "tactic": "Defense Impairment",
              "severity": 90}]
    from attacklens.schemas import TACTIC_IDX
    con = events_con([])
    try:
        sigma_detect._labels_table(con, rules)
        got = con.execute("SELECT * FROM al_sigma_labels").fetchall()          # insertion order kept
        types = [(r[0], r[1]) for r in con.execute("DESCRIBE al_sigma_labels").fetchall()]
        sigma_detect._labels_table(con, [])
        empty = con.execute("SELECT count(*) FROM al_sigma_labels").fetchone()[0]
    finally:
        con.close()
    assert got == [("sigma_b", "T1027", None, "Stealth", TACTIC_IDX["Stealth"], 55),
                   ("sigma_a", "T1059", "T1059.001", "Execution", TACTIC_IDX["Execution"], 75),
                   ("sigma_c'q", "T1070", "T1070.001", "Defense Impairment", TACTIC_IDX["Defense Impairment"], 90)]
    assert types == [("rule_id", "VARCHAR"), ("technique_id", "VARCHAR"), ("sub_technique_id", "VARCHAR"),
                     ("tactic", "VARCHAR"), ("tactic_idx", "INTEGER"), ("severity", "INTEGER")]
    assert empty == 0
