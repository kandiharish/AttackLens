"""Sigma compiler semantics (sigma_compile.py via sigma_rules.compile_dir): every modifier gets a positive and a
near-miss negative over a tiny hand-checked events table; NOT over absent fields; literal escaping / no SQL
injection; name-only (ECS parent.name) data. Each case is evaluated through the rendered `where` AND the production
grouped path (sigma_fx.matches asserts they agree). Skip reasons, labels, cache, run controls: test_sigma2.py.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from attacklens import sigma_compile
from attacklens.sigma_compile import Unsupported, lit

from .sigma_fx import NET_WIN, SEC_WIN, compile_docs, compile_one, matches, rid, rule_doc, seqs, skip_reason

pytestmark = pytest.mark.sigma
BS = "\\"   # one backslash, spelled once so no literal below depends on Python escape rules


def cmd(*lines: str | None) -> list[dict]:
    """Process-creation rows, one per command line (source_seq 1, 2, ...)."""
    return [{"command_line": c, "process_name": "x.exe", "host": "ws-1"} for c in lines]


def sel(field: str, value) -> dict:
    return {"sel": {field: value}, "condition": "sel"}


# ================================================================ contains / startswith / endswith
def test_contains_is_case_insensitive_substring(tmp_path: Path) -> None:
    rows = cmd("powershell Invoke-Mimikatz -x", "POWERSHELL INVOKE-MIMIKATZ", "powershell Invoke-Mimi", None)
    assert seqs(tmp_path, sel("CommandLine|contains", "invoke-mimikatz"), rows) == [1, 2]


def test_startswith_anchors_at_start(tmp_path: Path) -> None:
    rows = cmd("CMD /c whoami", "x cmd /c whoami", "cmd /cwhoami")
    assert seqs(tmp_path, sel("CommandLine|startswith", "cmd /c "), rows) == [1]


def test_endswith_anchors_at_end(tmp_path: Path) -> None:
    rows = cmd("run a.PS1", "run a.ps1 -x", "a.ps")
    assert seqs(tmp_path, sel("CommandLine|endswith", ".ps1"), rows) == [1]


def test_plain_value_is_whole_string_equality(tmp_path: Path) -> None:
    rows = cmd("whoami", "WHOAMI", "whoami /all", "xwhoami")
    assert seqs(tmp_path, sel("CommandLine", "whoami"), rows) == [1, 2]


# ================================================================ inner * and ? wildcards
def test_inner_star_wildcard(tmp_path: Path) -> None:
    rows = cmd("net group /domain", "NET user x /DOMAIN", "net group /domainx", "xnet group /domain", "net/domain")
    assert seqs(tmp_path, sel("CommandLine", "net * /domain"), rows) == [1, 2]


def test_single_char_wildcard_needs_exactly_one_char(tmp_path: Path) -> None:
    rows = cmd("reg.exe", "REG_EXE", "regexe", "reg..exe")
    assert seqs(tmp_path, sel("CommandLine", "reg?exe"), rows) == [1, 2]


def test_escaped_star_is_literal(tmp_path: Path) -> None:
    rows = cmd("a*b", "axb", "a**b")
    assert seqs(tmp_path, sel("CommandLine", "a" + BS + "*b"), rows) == [1]


# ================================================================ |all
def test_contains_all_needs_every_value(tmp_path: Path) -> None:
    rows = cmd("ps -nop -w hidden", "ps -w hidden -nop", "ps -nop", "ps -w hidden")
    assert seqs(tmp_path, sel("CommandLine|contains|all", ["-nop", "-w hidden"]), rows) == [1, 2]


def test_contains_list_without_all_is_any(tmp_path: Path) -> None:
    rows = cmd("ps -nop", "ps -w hidden", "ps -enc")
    assert seqs(tmp_path, sel("CommandLine|contains", ["-nop", "-w hidden"]), rows) == [1, 2]


# ================================================================ |re, |re|i
def test_re_is_case_sensitive_unanchored_search(tmp_path: Path) -> None:
    rows = cmd("xx Invoke-ABC yy", "invoke-abc", "Invoke-123")
    assert seqs(tmp_path, sel("CommandLine|re", "Invoke-[A-Z]+"), rows) == [1]


def test_re_i_ignores_case(tmp_path: Path) -> None:
    rows = cmd("xx Invoke-ABC yy", "invoke-abc", "Invoke-123")
    assert seqs(tmp_path, sel("CommandLine|re|i", "Invoke-[A-Z]+"), rows) == [1, 2]


def test_re_with_quote_is_literal(tmp_path: Path) -> None:
    rows = cmd("it's here", "its here")
    assert seqs(tmp_path, sel("CommandLine|re", "it's"), rows) == [1]


# ================================================================ |cidr (also inside NOT)
def net(*ips: str | None) -> list[dict]:
    return [{"action": "conn_out", "dst_ip": ip, "host": "ws-1"} for ip in ips]


def test_cidr_octet_boundary(tmp_path: Path) -> None:
    rows = net("10.1.2.3", "10.10.2.3", "110.1.2.3", "10.2.0.1", None)
    assert seqs(tmp_path, sel("DestinationIp|cidr", "10.1.0.0/16"), rows, logsource=NET_WIN) == [1]


def test_cidr_non_octet_prefix(tmp_path: Path) -> None:
    rows = net("10.1.16.0", "10.1.31.255", "10.1.15.9", "10.1.32.1", "10.1.160.1")
    assert seqs(tmp_path, sel("DestinationIp|cidr", "10.1.16.0/20"), rows, logsource=NET_WIN) == [1, 2]


def test_cidr_inside_not_and_absent_ip(tmp_path: Path) -> None:
    det = {"sel": {"Initiated": "true"}, "filter": {"DestinationIp|cidr": "10.0.0.0/8"},
           "condition": "sel and not filter"}
    rows = net("203.0.113.5", "10.2.3.4", None, "100.0.0.1")
    # external -> match; internal -> filtered; absent dst_ip under NOT -> no match (missing data never alerts)
    assert seqs(tmp_path, det, rows, logsource=NET_WIN) == [1, 4]


# ================================================================ |windash
def test_windash_expands_dash_variants(tmp_path: Path) -> None:
    rows = cmd("ps -enc x", "ps /enc x", "ps \u2013enc x", "ps \u2014enc x", "ps enc x", "ps +enc x")
    assert seqs(tmp_path, sel("CommandLine|windash|contains", "-enc"), rows) == [1, 2, 3, 4]


# ================================================================ |base64offset
def test_base64offset_matches_every_alignment(tmp_path: Path) -> None:
    b64 = [base64.b64encode(p).decode() for p in (b"IEX (New-Object Net.WebClient)", b"xIEX (a)", b"xyIEX (a)",
                                                  b"iex (new-object)", b"Write-Host hi")]
    rows = cmd(*(f"powershell -enc {b}" for b in b64))
    assert seqs(tmp_path, sel("CommandLine|base64offset|contains", "IEX"), rows) == [1, 2, 3]


# ================================================================ |cased
def test_cased_is_case_sensitive(tmp_path: Path) -> None:
    rows = cmd("xAbCx", "xabcx", "XABCX")
    assert seqs(tmp_path, sel("CommandLine|cased|contains", "AbC"), rows) == [1]


# ================================================================ null / |exists
def test_null_matches_absent_only(tmp_path: Path) -> None:
    rows = cmd(None, "x", "null")
    assert seqs(tmp_path, {"sel": {"CommandLine|contains": "x"}, "n": {"CommandLine": None},
                           "condition": "sel or n"}, rows) == [1, 2]
    assert seqs(tmp_path, {"sel": {"Image|endswith": "\\x.exe"}, "n": {"CommandLine": None},
                           "condition": "sel and n"}, [{**r, "process_path": "C:\\x.exe"} for r in rows]) == [1]


def test_exists(tmp_path: Path) -> None:
    rows = [{"process_path": "C:\\x.exe", "command_line": c} for c in ("x", None)]
    base = {"sel": {"Image|endswith": "\\x.exe"}}
    assert seqs(tmp_path, {**base, "e": {"CommandLine|exists": True}, "condition": "sel and e"}, rows) == [1]
    assert seqs(tmp_path, {**base, "e": {"CommandLine|exists": False}, "condition": "sel and e"}, rows) == [2]


# ================================================================ numbers, |gt, numeric strings
def logons(*types: int | None) -> list[dict]:
    return [{"action": "login_success", "event_id": 4624, "logon_type": t, "host": "srv-1"} for t in types]


def test_numeric_equality(tmp_path: Path) -> None:
    rows = logons(3, 10, None, 33)
    assert seqs(tmp_path, {"sel": {"EventID": 4624, "LogonType": 3}, "condition": "sel"}, rows,
                logsource=SEC_WIN) == [1]


def test_numeric_string_value_on_integer_column(tmp_path: Path) -> None:
    rows = logons(3, 10, 33)
    assert seqs(tmp_path, {"sel": {"EventID": 4624, "LogonType": "3"}, "condition": "sel"}, rows,
                logsource=SEC_WIN) == [1]


def test_gt_is_strict(tmp_path: Path) -> None:
    rows = logons(3, 4, 10, None)
    assert seqs(tmp_path, {"sel": {"EventID": 4624, "LogonType|gt": 3}, "condition": "sel"}, rows,
                logsource=SEC_WIN) == [2, 3]
    assert seqs(tmp_path, {"sel": {"EventID": 4624, "LogonType|gte": 4}, "condition": "sel"}, rows,
                logsource=SEC_WIN) == [2, 3]


def test_event_id_list_is_any(tmp_path: Path) -> None:
    rows = [{"action": a, "event_id": e, "host": "srv-1"} for a, e in
            (("login_success", 4624), ("login_failed", 4625), ("priv_assigned", 4672))]
    assert seqs(tmp_path, sel("EventID", [4624, 4625]), rows, logsource=SEC_WIN) == [1, 2]


# ================================================================ 1 of sel* / all of sel*
def test_one_of_and_all_of_pattern(tmp_path: Path) -> None:
    det = {"sel_a": {"CommandLine|contains": "aaa"}, "sel_b": {"CommandLine|contains": "bbb"},
           "other": {"CommandLine|contains": "ccc"}}
    out = compile_docs(tmp_path, [rule_doc({**det, "condition": "1 of sel_*"}, n=1),
                                  rule_doc({**det, "condition": "all of sel_*"}, n=2)])
    assert out["skipped"] == []
    rows = cmd("aaa", "bbb", "ccc", "aaa bbb", "zzz")
    assert matches(out, rows) == {rid(1): [1, 2, 4], rid(2): [4]}


# ================================================================ NOT and missing fields
def test_not_filter_on_absent_field_gives_no_match(tmp_path: Path) -> None:
    det = {"sel": {"CommandLine|contains": "whoami"}, "filter": {"ParentImage|endswith": "\\explorer.exe"},
           "condition": "sel and not filter"}
    rows = [{"command_line": "whoami", "parent_process": p} for p in
            ("cmd.exe", "explorer.exe", None, "C:\\Windows\\explorer.exe", "C:\\Windows\\cmd.exe")]
    assert seqs(tmp_path, det, rows) == [1, 5]
    out = compile_one(tmp_path, det)
    assert "coalesce(NOT (" in out["rules"][0]["where"]


def test_not_alone_on_absent_field_gives_no_match(tmp_path: Path) -> None:
    det = {"sel": {"Image|endswith": "\\x.exe"}, "filter": {"CommandLine|contains": "safe"},
           "condition": "sel and not filter"}
    rows = [{"process_path": "C:\\x.exe", "command_line": c} for c in ("run", "run safe", None)]
    assert seqs(tmp_path, det, rows) == [1]


def test_double_negation_on_present_values(tmp_path: Path) -> None:
    det = {"sel": {"CommandLine|contains": "a"}, "condition": "not (not sel)"}
    assert seqs(tmp_path, det, cmd("a", "b")) == [1]


# regression (was strict xfail): a NOT nested under another NOT resolved an absent field to coalesce(NOT x, FALSE),
# which the outer NOT turned into TRUE - missing data created a match. The inner constant now follows parity.
def test_double_negation_on_absent_field_gives_no_match(tmp_path: Path) -> None:
    det = {"sel": {"CommandLine|contains": "a"}, "condition": "not (not sel)"}
    assert seqs(tmp_path, det, cmd("a", "b", None)) == [1]
    where = compile_one(tmp_path, det)["rules"][0]["where"]
    assert "coalesce(NOT (coalesce(NOT (" in where and where.count(", TRUE)") == 1, where


def test_triple_negation_on_absent_field_gives_no_match(tmp_path: Path) -> None:
    # odd depth: not not not sel == not sel; absent field -> unknown -> no match; 'b' -> match; 'a' -> no match
    det = {"sel": {"CommandLine|contains": "a"}, "condition": "not (not (not sel))"}
    assert seqs(tmp_path, det, cmd("a", "b", None)) == [2]


def test_nested_filter_exception_on_absent_field_gives_no_match(tmp_path: Path) -> None:
    # common SigmaHQ shape: selection and not (filter_main and not filter_exception)
    det = {"sel": {"Image|endswith": "\\x.exe"}, "filter_main": {"ParentImage|endswith": "\\svc.exe"},
           "filter_exc": {"CommandLine|contains": "evil"},
           "condition": "sel and not (filter_main and not filter_exc)"}
    rows = [{"process_path": "C:\\x.exe", "parent_process": "C:\\w\\svc.exe", "command_line": c}
            for c in ("ok", "evil", None)]
    # 'ok': filtered out; 'evil': the exception re-opens it -> match; absent command line -> unknown -> no match
    assert seqs(tmp_path, det, rows) == [2]


# ================================================================ escaping and injection
def test_quote_percent_underscore_backslash_match_literally(tmp_path: Path) -> None:
    value = "it's 100%_done" + BS + "x"
    rows = cmd("run it's 100%_done" + BS + "x now",   # literal -> match
               "run it's 100XXdone" + BS + "x now",   # % and _ are not LIKE wildcards
               "run it's 100%Xdone" + BS + "x now",   # _ is not a single-char wildcard
               "run it's 100%_donex now",             # the backslash is required
               "run its 100%_done" + BS + "x now")    # the quote is required
    assert seqs(tmp_path, sel("CommandLine|contains", value), rows) == [1]


def test_like_path_escapes_specials_next_to_wildcards(tmp_path: Path) -> None:
    value = "a'b*c%d_e" + BS + "f"          # '*' forces the LIKE path; % _ \ must stay literal there
    rows = cmd("a'bXYZc%d_e" + BS + "f",
               "a'bXc" + "ZZZd_e" + BS + "f",
               "a'bXc%dXe" + BS + "f",
               "a'bXc%d_ef",
               "a'bXc%d_e" + BS + BS + "f")
    out = compile_one(tmp_path, sel("CommandLine", value))
    assert "LIKE" in out["rules"][0]["where"]
    assert matches(out, rows)[out["rules"][0]["id"]] == [1]


@pytest.mark.parametrize("payload", ["x' OR TRUE OR 'x", "'); DROP TABLE events; --", "a' OR 1=1 --",
                                     "\\'; SELECT 1; --"])
def test_injection_payload_is_a_literal(tmp_path: Path, payload: str) -> None:
    rows = cmd("benign", "pre " + payload + " post", payload.swapcase(), payload)
    contains = compile_one(tmp_path, sel("CommandLine|contains", payload))
    assert matches(contains, rows)[rid(1)] == [2, 3, 4]       # case-insensitive literal substring, nothing else
    ends = compile_one(tmp_path, sel("CommandLine|endswith", payload))
    assert matches(ends, rows)[rid(1)] == [3, 4]
    exact = compile_one(tmp_path, sel("CommandLine|cased", payload))
    assert matches(exact, rows)[rid(1)] == [4]


def test_regex_value_with_quote_cannot_escape_the_literal(tmp_path: Path) -> None:
    payload = "x') OR TRUE OR regexp_matches('a"
    rows = cmd("benign", "x') OR TRUE OR regexp_matches('a")
    assert seqs(tmp_path, sel("CommandLine|re", payload.replace("(", "\\(").replace(")", "\\)")), rows) == [2]


def test_lit_doubles_quotes_and_rejects_control_chars() -> None:
    assert lit("a'b") == "'a''b'"
    assert lit("") == "''"
    assert lit("x\\y") == "'x\\y'"
    for bad in ("a\x00b", "a" + sigma_compile.MARK + "b"):
        with pytest.raises(Unsupported, match="^value_control_char$"):
            lit(bad)


def test_marker_byte_in_rule_value_is_skipped(tmp_path: Path) -> None:
    doc = rule_doc(sel("CommandLine|contains", "a\x01L0\x01b"))
    assert skip_reason(tmp_path, doc) == "value_control_char"


def test_user_fields_are_normalized_like_ingest(tmp_path: Path) -> None:
    rows = [{"src_user": u, "process_path": "C:\\x.exe"} for u in ("jdoe", "jdoe2", None)]
    for v in ("CORP\\JDoe", "jdoe@corp.local", "jdoe"):
        assert seqs(tmp_path, sel("User", v), rows) == [1], v


# ================================================================ name-only data (ECS parent.name)
def test_parentimage_endswith_matches_bare_name(tmp_path: Path) -> None:
    rows = [{"parent_process": p, "command_line": "x"} for p in
            ("winword.exe", "WINWORD.EXE", "notwinword.exe", "C:\\Office\\WINWORD.EXE", "C:\\x\\notwinword.exe",
             None)]
    assert seqs(tmp_path, sel("ParentImage|endswith", "\\winword.exe"), rows) == [1, 2, 4]


def test_path_pattern_never_matches_bare_name(tmp_path: Path) -> None:
    rows = [{"parent_process": p, "command_line": "x"} for p in
            ("winword.exe", "C:\\Office\\winword.exe", "office", None)]
    assert seqs(tmp_path, sel("ParentImage|contains", "\\Office\\"), rows) == [2]
    assert seqs(tmp_path, sel("ParentImage|startswith", "C:\\Windows\\"),
                [{"parent_process": p} for p in ("cmd.exe", "C:\\Windows\\cmd.exe", "c:\\windowsx\\cmd.exe")]) == [2]


def test_path_pattern_on_bare_name_under_not_gives_no_match(tmp_path: Path) -> None:
    det = {"sel": {"CommandLine|contains": "whoami"}, "filter": {"ParentImage|contains": "\\Office\\"},
           "condition": "sel and not filter"}
    rows = [{"command_line": "whoami", "parent_process": p} for p in
            ("winword.exe", "C:\\Office\\winword.exe", "C:\\Windows\\cmd.exe")]
    # bare name: unknown whether it lives under \Office\ -> no match; full path outside \Office\ -> match
    assert seqs(tmp_path, det, rows) == [3]
