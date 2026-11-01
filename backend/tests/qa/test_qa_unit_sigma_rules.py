"""QA unit / white-box tests for attacklens.sigma_rules helpers (track qa_coverage_unit).

Baseline coverage left unexecuted: the rule-id collision ladder (8 -> 12 -> 32 hex chars -> sha1 of the path),
labels() rejecting a technique whose only tactic is not a v20 tactic, and keyword_column() guard shapes.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from attacklens import sigma_rules as sr
from attacklens.sigma_compile import Unsupported


def test_rule_id_collision_ladder() -> None:
    rule = SimpleNamespace(id="ABCDEF12-3456-7890-abcd-ef1234567890")
    ids: set[str] = set()
    got = [sr._rule_id(rule, f"r{k}.yml", ids) for k in range(4)]
    assert got == ["sigma_abcdef12", "sigma_abcdef123456", "sigma_abcdef1234567890abcdef1234567890",
                   "sigma_" + hashlib.sha1(b"r3.yml").hexdigest()[:12]]
    assert len(ids) == 4


def test_rule_id_without_usable_id_uses_path_hash() -> None:
    sha = hashlib.sha1(b"dir/x.yml").hexdigest()
    assert sr._rule_id(SimpleNamespace(id=None), "dir/x.yml", set()) == f"sigma_{sha[:8]}"
    assert sr._rule_id(SimpleNamespace(id="zzz-yyy"), "dir/x.yml", set()) == f"sigma_{sha[:8]}"   # no hex chars


def test_rule_id_short_id_collision_falls_to_path_hash() -> None:
    ids: set[str] = set()
    a = sr._rule_id(SimpleNamespace(id="abc"), "a.yml", ids)
    b = sr._rule_id(SimpleNamespace(id="abc"), "b.yml", ids)     # 8/12/32 prefixes of 'abc' are all 'abc'
    assert a == "sigma_abc" and b == "sigma_" + hashlib.sha1(b"b.yml").hexdigest()[:12]


def _tag(name: str, ns: str = "attack") -> SimpleNamespace:
    return SimpleNamespace(namespace=ns, name=name)


ATTACK = {"techniques": {"T1000": {"tactic": "Defense Evasion", "tactics": ["Defense Evasion"]},
                         "T1059": {"tactic": "Execution", "tactics": ["Execution"]},
                         "T1059.001": {"tactic": "Execution", "tactics": ["Execution"]}}}


def test_labels_rejects_pre_v20_only_tactic() -> None:
    with pytest.raises(Unsupported, match="^tactic_not_v20$"):
        sr.labels(SimpleNamespace(tags=[_tag("t1000")]), ATTACK, {})


def test_labels_sub_technique_preferred_and_namespace_filtered() -> None:
    r = SimpleNamespace(tags=[_tag("t1059"), _tag("t1059.001"), _tag("t9999", "cve"), _tag("execution")])
    assert sr.labels(r, ATTACK, {}) == ("T1059", "T1059.001", "Execution", None)
    with pytest.raises(Unsupported, match="^no_attack_technique_tag$"):
        sr.labels(SimpleNamespace(tags=[_tag("t1059", "car")]), ATTACK, {})      # not the attack namespace
    with pytest.raises(Unsupported, match="^technique_not_in_v20$"):
        sr.labels(SimpleNamespace(tags=[_tag("t4242")]), ATTACK, {})


@pytest.mark.parametrize("kw, expected", [
    (None, (None, None)),
    ("", (None, None)),
    ("command_line", ("command_line", None)),
    ({"expr": "command_line"}, ("command_line", None)),
    ({"expr": "raw_line"}, ("raw_line", None)),                                    # unguarded: compile refuses it
    ({"expr": "command_line", "source_types": ["syslog"]}, ("command_line", "source_type IN ('syslog')")),
    ({"expr": "raw_line", "source_types": ["syslog", "o'q"], "exclude_regex": "CEF:"},
     ("raw_line", "source_type IN ('syslog', 'o''q') AND NOT regexp_matches(raw_line, 'CEF:')")),
])
def test_keyword_column_shapes(kw, expected) -> None:
    assert sr.keyword_column(kw) == expected


def test_keyword_column_raw_line_default_exclude() -> None:
    expr, guard = sr.keyword_column({"expr": "raw_line", "source_types": ["syslog"]})
    assert expr == "raw_line"
    assert guard.startswith("source_type IN ('syslog') AND NOT regexp_matches(raw_line, '")
    assert sr.RAW_LINE_EXCLUDE.replace("'", "''") in guard
