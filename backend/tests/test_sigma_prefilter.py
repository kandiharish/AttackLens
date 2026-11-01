"""Sigma group prefilter (attacklens.sigma_prefilter): the weakening parser, and exactness of the prefiltered
DISTINCT-tuple path against each rule's rendered `where` (direct) and against the unfiltered path.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import pytest

from attacklens import sigma_detect, sigma_prefilter
from attacklens.sigma_compile import MARK

from .sigma_fx import NET_WIN, _direct, _hits_table, compile_docs, events_con, rid, rule_doc, run_sigma, sigma_cfg

pytestmark = pytest.mark.sigma

L3, R3, L6, R8 = (f"{MARK}L3{MARK}", f"{MARK}R3{MARK}", f"{MARK}L6{MARK}", f"{MARK}R8{MARK}")


# ================================================================ parser / weakening
def test_negation_and_else_true_guard_are_dropped() -> None:
    scan = (f"((ends_with({L3}, '\\cmd.exe') OR {L3} = 'cmd.exe') AND coalesce(NOT (({R8} = 443)), FALSE) "
            f"AND (CASE WHEN contains(coalesce({R3}, ''), '\\') THEN ({L3} = 'x') ELSE TRUE END))")
    assert sigma_prefilter.necessary(scan) == f"((ends_with({L3}, '\\cmd.exe')) OR ({L3} = 'cmd.exe'))"


def test_or_with_an_unconstrained_branch_requires_nothing() -> None:
    assert sigma_prefilter.parse(f"(({L6} = 'a') OR coalesce(NOT (({R8} = 1)), FALSE))") is None


@pytest.mark.parametrize("lit", ["a' OR 'b", "x AND y", "CASE", "END", "(", ")", "it''s"])
def test_literals_never_split_or_unbalance(lit: str) -> None:
    v = lit.replace("'", "''") if lit != "it''s" else lit
    scan = f"(contains({L6}, '{v}') AND ({R8} = 22))"
    t = sigma_prefilter.parse(scan)
    assert t is not None and t[0] == "and"
    assert [x[1] for x in sigma_prefilter.leaves(t)] == [f"(contains({L6}, '{v}'))", f"({R8} = 22)"]


def test_case_when_or_is_one_leaf() -> None:
    leaf = (f"CASE WHEN contains(coalesce({R3}, ''), '\\') OR contains(coalesce({R3}, ''), '/') "
            f"THEN ends_with({L3}, '\\a.exe') ELSE FALSE END")
    t = sigma_prefilter.parse(f"(({leaf}) AND ({L6} = 'b'))")
    assert [x[1] for x in sigma_prefilter.leaves(t)] == [f"({leaf})", f"({L6} = 'b')"]
    assert [x[2] for x in sigma_prefilter.leaves(t)] == [3, 6]


@pytest.mark.parametrize("scan", [f"({R8} BETWEEN 1 AND 5)", f"(({L6} = 'a') = TRUE", "((x)"])
def test_unparseable_text_stays_one_opaque_leaf(scan: str) -> None:
    t = sigma_prefilter.parse(scan)
    assert t is not None and t[0] == "leaf" and t[1] == f"({scan})"


def test_choose_keeps_cheapest_conjunct() -> None:
    t = sigma_prefilter.parse(f"(({L6} = 'a') AND ({R8} = 22))")
    rows = {(6, f"({L6} = 'a')"): 50, (8, f"({R8} = 22)"): 3}
    assert sigma_prefilter.choose(t, rows) == [(8, f"({R8} = 22)")]


# ================================================================ exactness on data
DOCS = [
    rule_doc({"sel": {"DestinationHostname|endswith": [".ngrok.io", ".evil.test"], "Initiated": "true"},
              "condition": "sel"}, n=1, logsource=NET_WIN),
    rule_doc({"sel": {"Image|endswith": "\\certutil.exe", "DestinationPort": [80, 443]},
              "filter": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "sel and not filter"}, n=2,
             logsource=NET_WIN),
    rule_doc({"sel": {"DestinationPort": [4444, 8888], "Initiated": "true"},
              "filter": {"DestinationIp|startswith": "127."}, "condition": "sel and not filter"}, n=3,
             logsource=NET_WIN),
    rule_doc({"sel": {"Image": None, "DestinationPort": 31337}, "condition": "sel"}, n=4, logsource=NET_WIN),
    rule_doc({"sel": {"DestinationHostname|contains": "a' OR 'b"}, "condition": "sel"}, n=5, logsource=NET_WIN),
]


def _rows(n: int, seed: int) -> list[dict[str, Any]]:
    rnd = random.Random(seed)
    doms = [None, "x.ngrok.io", "a.evil.test", "good.example", "a' or 'b.test", "EVIL.TEST.ngrok.io"]
    imgs = [None, "C:\\Windows\\System32\\certutil.exe", "C:\\a\\b.exe", "certutil.exe"]
    ips = [None, "10.1.2.3", "127.0.0.1", "203.0.113.9"]
    return [{"action": rnd.choice(["conn_out", "conn_allowed"]), "host": "ws-1", "dst_domain": rnd.choice(doms),
             "process_path": rnd.choice(imgs), "dst_port": rnd.choice([None, 80, 443, 4444, 8888, 31337, 53]),
             "dst_ip": rnd.choice(ips), "src_port": rnd.randint(1024, 65535)} for _ in range(n)]


ON = {"max_terms": 2000, "min_rows": 0}                       # production defaults, forced on for tiny fixtures
VALUE_ONLY = {**ON, "direct_max_leaves": 0}
DIRECT_ONLY = {**ON, "direct_max_leaves": 100_000}
OFF = {"max_terms": 0}
SIGMA_ON = {"prefilter_min_rows": 0}


def _grouped(con: Any, out: dict[str, Any], **kw: int) -> tuple[dict[str, list[int]], list[dict[str, Any]]]:
    _hits_table(con)
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in out["rules"]:
        groups.setdefault(r["gate"], []).append(r)
    stats = [sigma_detect._run_group(con, g, rs, out["exprs"], 250, 301, **kw) for g, rs in groups.items()]
    got: dict[str, list[int]] = {r["id"]: [] for r in out["rules"]}
    for seq, ids in con.execute("SELECT source_seq, rule_ids FROM al_sigma_hits").fetchall():
        for i in ids:
            got[i].append(int(seq))
    return {k: sorted(v) for k, v in got.items()}, stats


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_prefiltered_path_equals_direct_and_unfiltered(tmp_path: Path, seed: int) -> None:
    out = compile_docs(tmp_path, DOCS)
    assert out["skipped"] == [] and len(out["rules"]) == len(DOCS)
    rows = _rows(400, seed)
    con = events_con(rows)
    try:
        direct = _direct(con, out)
        runs = {name: _grouped(con, out, **kw) for name, kw in
                (("on", ON), ("value", VALUE_ONLY), ("direct", DIRECT_ONLY), ("off", OFF))}
    finally:
        con.close()
    for name, (got, _) in runs.items():
        assert got == direct, name
    assert all(v for v in direct.values())                      # every rule fires on the fixture
    st_off = runs["off"][1]
    assert not any(s.get("prefilter") for s in st_off)
    for name in ("on", "value", "direct"):
        st = runs[name][1]
        assert any(s.get("prefilter") for s in st), name
        assert sum(s["tuples"] for s in st) < sum(s["tuples"] for s in st_off), name


@pytest.mark.parametrize("kw", [VALUE_ONLY, DIRECT_ONLY], ids=["value", "direct"])
def test_null_satisfying_leaf_keeps_null_rows(tmp_path: Path, kw: dict[str, int]) -> None:
    out = compile_docs(tmp_path, [DOCS[3]])
    rows = [{"action": "conn_out", "host": "ws-1", "dst_port": 31337},
            {"action": "conn_out", "host": "ws-1", "dst_port": 31337, "process_path": "C:\a.exe"}]
    con = events_con(rows)
    try:
        got, st = _grouped(con, out, **kw)
    finally:
        con.close()
    assert got == {rid(4): [1]} and st[0].get("prefilter")


def _build(con: Any, out: dict[str, Any], direct_max_leaves: int, min_rows: int = 0) -> tuple[str | None, int | None]:
    g = out["rules"][0]["gate"]
    assert all(r["gate"] == g for r in out["rules"])
    where = f"CAST(ts_ok AS BOOLEAN) AND ts_ms IS NOT NULL AND ({g})"
    return sigma_prefilter.build(con, out["rules"], out["exprs"], where, 2000, 250, min_rows, direct_max_leaves)


def test_direct_fields_are_inlined_value_fields_use_candidate_tables(tmp_path: Path) -> None:
    out = compile_docs(tmp_path, [DOCS[0], DOCS[2]])
    port = out["exprs"].index("dst_port")
    rows = _rows(200, 5)
    con = events_con(rows)
    try:
        flt_v, gated = _build(con, out, 0)
        sigma_prefilter.cleanup(con, flt_v)
        flt_d, _ = _build(con, out, 100_000)
        n_tables = con.execute("SELECT count(*) FROM duckdb_tables() WHERE starts_with(table_name, 'al_sg_')"
                               ).fetchone()[0]
    finally:
        con.close()
    assert gated == len(rows)
    assert flt_v and "al_sg_c" in flt_v and f"r_{port} = 4444" not in flt_v        # value fields: candidate tables
    assert flt_d and "al_sg_c" not in flt_d and f"(r_{port} = 4444)" in flt_d      # direct fields: inlined leaves
    assert n_tables == 0                                                             # no temp table left behind


def test_min_rows_gate_runs_small_groups_unfiltered(tmp_path: Path) -> None:
    out = compile_docs(tmp_path, DOCS)
    rows = _rows(120, 9)
    con = events_con(rows)
    try:
        direct = _direct(con, out)
        gated = int(con.execute("SELECT count(*) FROM events WHERE action IN ('conn_out', 'conn_allowed')"
                                ).fetchone()[0])
        small, st_small = _grouped(con, out, **{**ON, "min_rows": gated + 1})
        big, st_big = _grouped(con, out, **{**ON, "min_rows": gated})
    finally:
        con.close()
    assert small == big == direct
    assert not any(s.get("prefilter") for s in st_small) and any(s.get("prefilter") for s in st_big)


def test_no_candidate_value_skips_group_but_counts_it_applicable(tmp_path: Path) -> None:
    docs = [DOCS[0], DOCS[2]]
    rows = [{"action": "conn_out", "host": "ws-1", "dst_domain": "good.example", "dst_port": 53,
             "src_port": 1000 + i} for i in range(20)]
    s_on, a_on = run_sigma(sigma_cfg(tmp_path / "on", docs, **SIGMA_ON), rows)
    s_off, a_off = run_sigma(sigma_cfg(tmp_path / "off", docs, prefilter_max_terms=0), rows)
    assert a_on == a_off == []
    assert s_on["sigma_rules_applicable"] == s_off["sigma_rules_applicable"] == 2
    g = next(v for v in s_on["group_tuples"].values() if v.get("prefilter"))
    assert g["tuples"] == 0 and g.get("gated") is True


def test_end_to_end_alerts_identical_with_and_without_prefilter(tmp_path: Path) -> None:
    rows = _rows(300, 7)
    s_on, a_on = run_sigma(sigma_cfg(tmp_path / "on", DOCS, **SIGMA_ON), rows)
    s_off, a_off = run_sigma(sigma_cfg(tmp_path / "off", DOCS, prefilter_max_terms=0), rows)
    s_def, a_def = run_sigma(sigma_cfg(tmp_path / "def", DOCS), rows)    # defaults: 300 rows < min_rows
    assert a_on == a_off == a_def and a_on
    keep = ("sigma_alerts", "sigma_rules_fired", "sigma_rules_applicable", "sigma_rules_failed", "rows_matched")
    assert {k: s_on[k] for k in keep} == {k: s_off[k] for k in keep} == {k: s_def[k] for k in keep}
    assert any(v.get("prefilter") for v in s_on["group_tuples"].values())
    assert not any(v.get("prefilter") for v in s_def["group_tuples"].values())


def test_prefilter_settings_read_pipeline_keys() -> None:
    assert sigma_detect.prefilter_settings({}) == {
        "max_terms": sigma_detect.PREFILTER_MAX_TERMS, "min_rows": sigma_detect.PREFILTER_MIN_ROWS,
        "direct_max_leaves": sigma_detect.PREFILTER_DIRECT_MAX_LEAVES}
    assert sigma_detect.prefilter_settings({"prefilter_max_terms": 0, "prefilter_min_rows": 5,
                                            "prefilter_direct_max_leaves": 3}) == {
        "max_terms": 0, "min_rows": 5, "direct_max_leaves": 3}


@pytest.mark.parametrize("kw", [VALUE_ONLY, DIRECT_ONLY], ids=["value", "direct"])
def test_prefilter_sql_error_falls_back_to_unfiltered(tmp_path: Path, kw: dict[str, int]) -> None:
    out = compile_docs(tmp_path, [DOCS[0]])
    r = out["rules"][0]
    i = int(sigma_prefilter.leaves(sigma_prefilter.parse(r["scan"]))[0][2])
    bad = dict(r, scan=f"({r['scan']} AND regexp_matches({MARK}R{i}{MARK}, '(?<n>a)'))")
    rows = _rows(50, 3)
    con = events_con(rows)
    try:
        _hits_table(con)
        st = sigma_detect._run_group(con, bad["gate"], [bad], out["exprs"], 250, 301, **kw)
    finally:
        con.close()
    # the prefilter's leaf query hits the broken regex -> group runs unfiltered -> the rule fails and is counted
    assert not st.get("prefilter") and st["rules_failed"] == 1 and st["failed_rule_ids"] == [r["id"]]
