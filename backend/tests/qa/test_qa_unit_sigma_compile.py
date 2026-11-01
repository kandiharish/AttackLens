"""QA unit / white-box tests for attacklens.sigma_compile helpers (track qa_coverage_unit).

Baseline coverage (88.0 % lines / 80.3 % branches) left these paths unexecuted: |fieldref (mapped, unmapped,
partial), numbers on a VARCHAR field (= and comparisons), bool numbers, placeholder strings, keyword-only edge cases
(no keyword column, unguarded raw_line, '*' keyword, number keyword), assume_true with a cased / wildcard value,
assume_true_spec validation, user normalisation of multi-part values, '' and '*' patterns, render() with aliases and
field_spec(). Each SQL string is asserted exactly and, where it matters, evaluated in DuckDB (positive + near miss).
"""

from __future__ import annotations

import duckdb
import pytest
from sigma import conditions as sc
from sigma import types as st

from attacklens import sigma_compile as sg
from attacklens.sigma_compile import Compiler, FieldSpec, Unsupported

W, Q = st.SpecialChars.WILDCARD_MULTI, st.SpecialChars.WILDCARD_SINGLE


def comp(**kw) -> Compiler:
    fields = {"CommandLine": FieldSpec("command_line"), "EventID": FieldSpec("event_id", "INTEGER"),
              "Port": FieldSpec("dst_port_txt"), "Other": FieldSpec("parent_cmd"),
              "User": FieldSpec("src_user", user=True)}
    return Compiler(fields=fields, exprs=[], **kw)


def sql(c: Compiler, text: str) -> str:
    return sg.render(text, c.exprs)


def evaluate(c: Compiler, text: str, row: dict) -> bool | None:
    con = duckdb.connect()
    try:
        cols = ", ".join(f"{v!r}::{'INTEGER' if isinstance(v, int) else 'VARCHAR'} AS {k}" if v is not None
                         else f"NULL::VARCHAR AS {k}" for k, v in row.items())
        return con.execute(f"SELECT {sql(c, text)} FROM (SELECT {cols})").fetchone()[0]
    finally:
        con.close()


# ---- |fieldref -------------------------------------------------------------------------------------------------------
def test_fieldref_mapped_equality_case_insensitive() -> None:
    c = comp()
    out = c.leaf("CommandLine", st.SigmaFieldReference("Other"), False)
    assert sql(c, out) == "(lower(command_line) = lower(parent_cmd))"
    assert c.used == {"CommandLine", "Other"}
    assert evaluate(c, out, {"command_line": "A.EXE", "parent_cmd": "a.exe"}) is True
    assert evaluate(c, out, {"command_line": "A.EXE", "parent_cmd": "b.exe"}) is False


def test_fieldref_unmapped_and_partial_unsupported() -> None:
    with pytest.raises(Unsupported, match="^unmapped_field:Nope$"):
        comp().leaf("CommandLine", st.SigmaFieldReference("Nope"), False)
    with pytest.raises(Unsupported, match="^modifier:fieldref_partial$"):
        comp().leaf("CommandLine", st.SigmaFieldReference("Other", starts_with=True), False)


# ---- numbers --------------------------------------------------------------------------------------------------------
def test_number_on_varchar_field_equality_is_text() -> None:
    c = comp()
    out = c.leaf("Port", st.SigmaNumber(445), False)
    assert sql(c, out) == "(lower(dst_port_txt) = '445')"
    assert evaluate(c, out, {"dst_port_txt": "445"}) is True
    assert evaluate(c, out, {"dst_port_txt": "4450"}) is False


def test_compare_on_varchar_field_uses_try_cast() -> None:
    c = comp()
    gt = st.SigmaCompareExpression(st.SigmaNumber(1000), st.SigmaCompareExpression.CompareOperators.GT)
    out = c.leaf("Port", gt, False)
    assert sql(c, out) == "(TRY_CAST((dst_port_txt) AS DOUBLE) > 1000)"
    assert evaluate(c, out, {"dst_port_txt": "1001"}) is True
    assert evaluate(c, out, {"dst_port_txt": "1000"}) is False             # strict
    assert evaluate(c, out, {"dst_port_txt": "n/a"}) is None              # not a number -> NULL, never TRUE


def test_number_on_integer_field_and_bool_rejected() -> None:
    c = comp()
    assert sql(c, c.leaf("EventID", st.SigmaNumber(4625), False)) == "((event_id) = 4625)"
    with pytest.raises(Unsupported, match="^value_type:number$"):
        comp().number(FieldSpec("event_id", "INTEGER"), True, "=")


# ---- strings ---------------------------------------------------------------------------------------------------------
def test_placeholder_string_unsupported() -> None:
    s = st.SigmaString("%admins%").insert_placeholders()
    with pytest.raises(Unsupported, match="^modifier:expand_placeholder$"):
        comp().leaf("CommandLine", s, False)


@pytest.mark.parametrize("parts, expected", [
    ([], "(coalesce(c, '') = '')"),
    ([W], "(c IS NOT NULL)"),
    (["a"], "(c = 'a')"),
    ([W, "a"], "ends_with(c, 'a')"),
    (["a", W], "starts_with(c, 'a')"),
    ([W, "a", W], "contains(c, 'a')"),
    (["a", W, "b"], "(c LIKE 'a%b' ESCAPE '\\')"),
    (["a", Q], "(c LIKE 'a_' ESCAPE '\\')"),
    (["50%_x", W], "starts_with(c, '50%_x')"),                            # no LIKE: specials stay literal
    ([W, "50%_x", Q], "(c LIKE '%50\\%\\_x_' ESCAPE '\\')"),               # LIKE: specials escaped
])
def test_match_shapes(parts: list, expected: str) -> None:
    assert sg._match("c", parts) == expected


def test_empty_value_matches_null_and_empty_only() -> None:
    c = comp()
    out = c.leaf("CommandLine", st.SigmaString(""), False)
    assert evaluate(c, out, {"command_line": None}) is True
    assert evaluate(c, out, {"command_line": ""}) is True
    assert evaluate(c, out, {"command_line": " "}) is False


@pytest.mark.parametrize("parts, expected", [
    (["nt authority\\system"], ["system"]), (["bob@corp.local"], ["bob"]), (["@handle"], ["@handle"]),
    (["corp\\bob@x"], ["bob"]), ([W, "bob"], [W, "bob"]),                 # wildcard values are left alone
])
def test_normalize_user(parts: list, expected: list) -> None:
    assert sg._normalize_user(parts) == expected


# ---- keywords --------------------------------------------------------------------------------------------------------
def test_keyword_without_column_or_guard_unsupported() -> None:
    with pytest.raises(Unsupported, match="^keyword_search_unmapped$"):
        comp().keyword(st.SigmaString("mimikatz"))
    with pytest.raises(Unsupported, match="^keyword_raw_line_unguarded$"):
        comp(keywords="raw_line").keyword(st.SigmaString("mimikatz"))


def test_keyword_star_only_is_empty_and_number_is_text() -> None:
    c = comp(keywords="command_line")
    with pytest.raises(Unsupported, match="^keyword_empty$"):
        c.keyword(st.SigmaString("*"))
    out = c.keyword(st.SigmaNumber(4625))                                  # keyword 4625 -> substring '4625'
    assert sql(c, out) == "contains(lower(command_line), '4625')"
    assert evaluate(c, out, {"command_line": "event 4625 failed"}) is True
    assert evaluate(c, out, {"command_line": "event 4624"}) is False


def test_keyword_guard_nulls_unguarded_rows() -> None:
    c = comp(keywords="raw_line", keyword_guard="source_type = 'syslog'")
    out = c.keyword(st.SigmaString("sudo"))
    assert sql(c, out) == "contains(lower(CASE WHEN source_type = 'syslog' THEN (raw_line) END), 'sudo')"
    assert evaluate(c, out, {"source_type": "syslog", "raw_line": "x sudo y"}) is True
    assert evaluate(c, out, {"source_type": "ecs_json", "raw_line": "x sudo y"}) is None   # guard: never a match


def test_keyword_value_type_rejected() -> None:
    with pytest.raises(Unsupported, match="^keyword_value_type:SigmaNull$"):
        comp(keywords="command_line").value(FieldSpec("command_line"), st.SigmaNull(), substring=True)


def test_leaf_without_field_is_keyword() -> None:
    c = comp(keywords="command_line")
    assert c.leaf(None, st.SigmaString("evil"), False) == c.keyword(st.SigmaString("evil"))


# ---- assume_true / policy ------------------------------------------------------------------------------------------
def test_assume_true_only_plain_equal_values() -> None:
    c = comp(assume_true={"Channel": frozenset({"security"})})
    assert c.leaf("Channel", st.SigmaString("Security"), False) == "TRUE"
    with pytest.raises(Unsupported, match="^unmapped_field:Channel$"):
        c.leaf("Channel", st.SigmaString("Secur*"), False)               # wildcard: not implied
    cased = st.SigmaCasedString.from_sigma_string(st.SigmaString("security"))
    with pytest.raises(Unsupported, match="^unmapped_field:Channel$"):
        c.leaf("Channel", cased, False)                                    # |cased: not implied
    with pytest.raises(Unsupported, match="^unmapped_field:Channel$"):
        c.leaf("Channel", st.SigmaNumber(4), False)                        # not a string


def test_narrow_policy_constants_by_parity() -> None:
    c = comp(policy="narrow")
    assert c.leaf("Unmapped", st.SigmaString("x"), False) == "FALSE"
    assert c.leaf("Unmapped", st.SigmaString("x"), True) == "TRUE"


def test_assume_true_spec_validation() -> None:
    assert sg.assume_true_spec(None) == {}
    assert sg.assume_true_spec({"Channel": "Security", "Provider": ["A", "b"]}) == {
        "Channel": frozenset({"security"}), "Provider": frozenset({"a", "b"})}
    with pytest.raises(ValueError, match="must be a mapping"):
        sg.assume_true_spec(["Channel"])


def test_unknown_condition_node_unsupported() -> None:
    class Weird:
        pass
    with pytest.raises(Unsupported, match="^condition_node:Weird$"):
        comp().node(Weird(), False)


def test_condition_parse_error_unsupported() -> None:
    class Bad:
        def parse(self):
            raise KeyError("x")
    with pytest.raises(Unsupported, match="^condition_error:KeyError$"):
        comp().compile_rule([Bad()])


def test_compile_rule_constant_results_rejected() -> None:
    class Const:
        def __init__(self, node):
            self.n = node

        def parse(self):
            return self.n
    c = comp(assume_true={"Channel": frozenset({"security"})})
    true_leaf = sc.ConditionFieldEqualsValueExpression("Channel", st.SigmaString("security"))
    with pytest.raises(Unsupported, match="^matches_every_gated_row$"):
        c.compile_rule([Const(true_leaf)])
    false_leaf = sc.ConditionNOT([true_leaf])
    with pytest.raises(Unsupported, match="^unsatisfiable_without_unmapped$"):
        c.compile_rule([Const(false_leaf)])


# ---- folding / render / field_spec -----------------------------------------------------------------------------------
def test_and_or_folding() -> None:
    assert sg._and(["a", "TRUE", "b"]) == "(a AND b)"
    assert sg._and(["a", "FALSE"]) == "FALSE" and sg._and(["TRUE"]) == "TRUE" and sg._and(["x"]) == "x"
    assert sg._or(["a", "FALSE", "b"]) == "(a OR b)"
    assert sg._or(["a", "TRUE"]) == "TRUE" and sg._or(["FALSE"]) == "FALSE" and sg._or([]) == "FALSE"


def test_render_default_and_aliases() -> None:
    text = f"({sg.MARK}L0{sg.MARK} = 'a') AND {sg.MARK}R1{sg.MARK} IS NULL"
    assert sg.render(text, ["command_line", "image"]) == "(lower(command_line) = 'a') AND (image) IS NULL"
    assert sg.render(text, ["command_line", "image"], {0: "cmd", 1: "img"}) == "(l_cmd = 'a') AND r_img IS NULL"
    assert sg.marker_indices(text) == {0, 1}


def test_field_spec_forms() -> None:
    types = {"event_id": "INTEGER"}
    assert sg.field_spec("event_id", types) == FieldSpec("event_id", "INTEGER")
    assert sg.field_spec("command_line", types) == FieldSpec("command_line", "VARCHAR")
    assert sg.field_spec({"expr": "process_path", "name": "process_name", "user": 1}, types) == FieldSpec(
        "process_path", "VARCHAR", "process_name", True)
    assert sg.field_spec({"expr": "event_id"}, types).type == "INTEGER"
    assert sg.field_spec({"expr": "x", "type": "BIGINT"}, types).type == "BIGINT"


def test_parts_merges_adjacent_strings() -> None:
    s = st.SigmaString("ab")
    s.s = ("a", "B", W, "c")                       # pySigma may hand over split plain parts
    assert sg._parts(s, lower=True) == ["ab", W, "c"]
    assert sg._parts(s, lower=False) == ["aB", W, "c"]
