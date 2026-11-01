"""QA track qa_cli_blackbox: `python -m attacklens.run` as a black box on hostile raw directories.

Inputs are built by tools/qa/cli_cases.py from our own synthetic lines (never organiser logs) under tmp_path.
Every case runs the real CLI in a subprocess with a copy of config/ where only Sigma is disabled (Sigma compile
dominates a 20-line run; ingest / accounting / rc behaviour do not depend on it). The matrix with the unmodified
repo config is tools/qa/cli_cases.py without --fast-config (reports/qa/qa_cli_blackbox.md).

Expected values are what the case wrote (line counts, epoch ms), never read back from the product.
Product bugs are strict xfails with the bug id (reports/qa/qa_cli_blackbox.md): they turn into failures when fixed
so the marker gets removed.
"""

from __future__ import annotations

import importlib.util
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import duckdb
import pytest

REPO = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("qa_cli_cases", REPO / "tools" / "qa" / "cli_cases.py")
assert _spec and _spec.loader
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)

FAST = ("missing_raw", "out_is_file", "readonly_out", "raw_is_file", "empty_dir", "unknown_format",
        "nul_padding_small", "utf16le_bom", "gzip", "crlf", "utf8_bom", "mixed_formats", "spaces_quotes")
SLOW = ("empty_file", "binary_only", "nul_padding_large", "utf16le_bom_lf", "huge_line", "same_ts", "future_ts",
        "hardlink", "symlink", "invalid_utf8_kv", "from_stage_no_prior")
EXPECTED_TS_MS = [(cc.BASE_EPOCH + i) * 1000 for i in range(20)]


def bug(reason: str) -> pytest.MarkDecorator:
    """Known product bug: strict xfail that only accepts an AssertionError (a broken test is not 'expected')."""
    return pytest.mark.xfail(strict=True, raises=AssertionError, reason=reason)


def _run_all(base: Path, names: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    cfg = cc.fast_config(base / "_config_fast")
    with ThreadPoolExecutor(max_workers=5) as pool:
        res = list(pool.map(lambda n: cc.run_case(n, base, cfg, timeout=600), names))
    return {r["case"]: r for r in res}


@pytest.fixture(scope="module")
def fast_runs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    return _run_all(tmp_path_factory.mktemp("qa cli 'fast'"), FAST)


@pytest.fixture(scope="module")
def slow_runs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    return _run_all(tmp_path_factory.mktemp("qa_cli_slow"), SLOW)


def _events(r: dict[str, Any]) -> list[tuple]:
    """(ts_ms, ts_ok, source_seq, raw_line length, raw_line startswith 'date=', raw_line has CR) from the run."""
    tmp = REPO / "data" / "tmp" / "qa_cli_duck"
    tmp.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    try:
        for s in ("SET TimeZone='UTC'", "SET memory_limit='1GB'", "SET threads=2",
                  f"SET temp_directory='{tmp.as_posix()}'"):
            con.execute(s)
        glob = (Path(r["parquet_dir"]) / "events" / "**" / "*.parquet").as_posix().replace("'", "''")
        return con.execute(
            f"SELECT ts_ms, ts_ok, source_seq, length(raw_line), starts_with(raw_line, 'date='), "
            f"contains(raw_line, chr(13)) FROM read_parquet('{glob}', hive_partitioning=true) ORDER BY ts_ms"
        ).fetchall()
    finally:
        con.close()


def _acc(r: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {a["source_type"]: a for a in r.get("accounting") or []}


def _clear_failure(r: dict[str, Any], *needles: str) -> None:
    assert r["rc"] != 0, r["stderr_tail"]
    errs = " ".join(r["stderr"]["error_messages"] + r["stderr"]["argparse"])
    assert errs, f"rc {r['rc']} with no ERROR message; stderr tail: {r['stderr_tail']}"
    for n in needles:
        assert n.lower() in errs.lower(), errs
    assert not r["stderr"]["traceback_only"]


# ------------------------------------------------------------------ fast: unusable input, clear failures
def test_missing_raw_dir_clear_rc1_and_metrics_error(fast_runs: dict) -> None:
    r = fast_runs["missing_raw"]
    _clear_failure(r, "raw dir not found")
    assert r["files"]["run_metrics.json"] is True
    assert r["metrics"]["error"].startswith("FileNotFoundError: raw dir not found")


def test_readonly_out_dir_clear_rc1(fast_runs: dict) -> None:
    r = fast_runs["readonly_out"]
    if r["result"] == "not_run":
        pytest.skip(r["why"][0])
    _clear_failure(r, "PermissionError")


@bug("QA-CLI-01: --out is an existing file -> rc 1 with empty stderr "
                                       "(run.py:106 mkdir outside try, run.py:181 except swallows)")
def test_out_is_file_has_error_message(fast_runs: dict) -> None:
    _clear_failure(fast_runs["out_is_file"])


@bug("QA-CLI-02: --raw is a file -> rc 0, 0 rows, its 20 lines in no "
                                       "accounting row (profile.py:210-212)")
def test_raw_is_file_ingested_or_refused(fast_runs: dict) -> None:
    r = fast_runs["raw_is_file"]
    if r["rc"] == 0:
        assert r["rows_in"] == 20 and r["rows_ok"] == 20
    else:
        _clear_failure(r)


@bug("QA-CLI-06: no usable rows (empty dir) -> rc 0 'done' with warnings only")
def test_empty_dir_nonzero_rc(fast_runs: dict) -> None:
    _clear_failure(fast_runs["empty_dir"])


def test_unknown_format_fully_accounted(fast_runs: dict) -> None:
    r = fast_runs["unknown_format"]
    assert _acc(r) == {"unrecognized": {"source_type": "unrecognized", "rows_in": 15, "rows_ok": 0,
                                        "dropped": 15, "drop_reasons": {"unrecognized_format": 15}}}


@bug("QA-CLI-06: only unrecognized input (0 usable rows) -> rc 0")
def test_unknown_format_nonzero_rc(fast_runs: dict) -> None:
    _clear_failure(fast_runs["unknown_format"])


# ------------------------------------------------------------------ fast: encodings and padding
@bug("QA-CLI-03: 10 valid lines + NUL tail -> whole file 'binary', 10 valid "
                                       "rows dropped as unrecognized_format (profile.py:51)")
def test_nul_padding_small_keeps_valid_lines(fast_runs: dict) -> None:
    r = fast_runs["nul_padding_small"]
    assert _acc(r).get("fortigate_kv", {}).get("rows_ok") == 10


def test_nul_padding_small_still_counted(fast_runs: dict) -> None:
    r = fast_runs["nul_padding_small"]  # data lost but not silently: 10 lines + 1 NUL run, all with a reason
    assert (r["rows_in"], r["rows_ok"], r["unaccounted"]) == (11, 0, 0)
    assert all(a["drop_reasons"] for a in r["accounting"])


@bug("QA-CLI-04: UTF-16 LE (BOM+CRLF) not decoded; rows_in counts bytes: 41 "
                                       "for 20 lines (profile.py:51, ingest.py:264)")
def test_utf16le_bom_rows_in_matches_lines(fast_runs: dict) -> None:
    assert fast_runs["utf16le_bom"]["rows_in"] == 20


def test_utf16le_bom_does_not_crash(fast_runs: dict) -> None:
    r = fast_runs["utf16le_bom"]
    assert r["rc"] == 0 and r["files"]["ingest_accounting.json"] and r["rows_ok"] == 0


@bug("QA-CLI-05: gzip of 20 lines -> unrecognized, rows_in 7 (newline bytes in compressed data); "
     "13 lines unaccounted (profile.py:47 no decompression, ingest.py:264)")
def test_gzip_ingested_or_counted_exactly(fast_runs: dict) -> None:
    r = fast_runs["gzip"]
    reasons = " ".join(k for a in r["accounting"] for k in a["drop_reasons"])
    assert r["rows_ok"] == 20 or (r["rows_in"] == 20 and ("gzip" in reasons or "compress" in reasons))


def test_crlf_exact_ts_and_no_cr(fast_runs: dict) -> None:
    r = fast_runs["crlf"]
    assert (r["rc"], r["rows_in"], r["rows_ok"]) == (0, 20, 20)
    ev = _events(r)
    assert [e[0] for e in ev] == EXPECTED_TS_MS
    assert all(e[1] for e in ev) and not any(e[5] for e in ev)
    assert len({e[2] for e in ev}) == 20


def test_utf8_bom_exact_ts_and_bom_stripped(fast_runs: dict) -> None:
    r = fast_runs["utf8_bom"]
    assert (r["rc"], r["rows_in"], r["rows_ok"]) == (0, 20, 20)
    ev = _events(r)
    assert [e[0] for e in ev] == EXPECTED_TS_MS
    assert all(e[4] for e in ev)  # first line's raw_line starts with 'date=' (no U+FEFF)


def test_mixed_formats_routed_and_counted(fast_runs: dict) -> None:
    r = fast_runs["mixed_formats"]
    assert r["rc"] == 0
    assert {st: (a["rows_in"], a["rows_ok"], a["dropped"]) for st, a in _acc(r).items()} == {
        "cef": (10, 10, 0), "ecs_json": (10, 10, 0), "fortigate_kv": (10, 10, 0), "syslog": (10, 10, 0)}


def test_spaces_quotes_in_paths(fast_runs: dict) -> None:
    r = fast_runs["spaces_quotes"]
    assert (r["rc"], r["rows_in"], r["rows_ok"]) == (0, 20, 20)
    assert r["files"]["incidents_index.json"] and r["files"]["run_metrics.json"]


@pytest.mark.parametrize("case", [c for c in FAST if c != "out_is_file"])
def test_never_traceback_only_or_silent_rc(fast_runs: dict, case: str) -> None:
    r = fast_runs[case]
    if r["result"] == "not_run":
        pytest.skip(r["why"][0])
    assert not r["stderr"]["traceback_only"], r["stderr_tail"]
    if r["rc"] != 0:
        assert r["stderr"]["error_messages"], r["stderr_tail"]
    else:
        assert r["files"]["run_metrics.json"] and r["files"]["ingest_accounting.json"]
        assert r["invariant_ok"] and r["reasons_ok"]


# ------------------------------------------------------------------ slower remainder (stress-marked)
@pytest.mark.stress
class TestSlowCases:
    def test_nul_padding_large_tail_counted(self, slow_runs: dict) -> None:
        r = slow_runs["nul_padding_large"]
        a = _acc(r)["fortigate_kv"]
        assert (a["rows_in"], a["rows_ok"], a["dropped"]) == (401, 400, 1)
        assert list(a["drop_reasons"]) == ["unparseable_line (kept in ts_ok=false, action=malformed)"]

    @bug("QA-CLI-04: UTF-16 LE (BOM+LF) rows_in 21 for 20 lines")
    def test_utf16le_lf_rows_in(self, slow_runs: dict) -> None:
        assert slow_runs["utf16le_bom_lf"]["rows_in"] == 20

    def test_huge_line_ingested_whole(self, slow_runs: dict) -> None:
        r = slow_runs["huge_line"]
        assert (r["rc"], r["rows_in"], r["rows_ok"]) == (0, 11, 11)
        assert max(e[3] for e in _events(r)) > 2 * 1024 * 1024

    def test_same_ts_distinct_source_seq(self, slow_runs: dict) -> None:
        r = slow_runs["same_ts"]
        ev = _events(r)
        assert (r["rows_ok"], len(ev), len({e[2] for e in ev})) == (50, 50, 50)
        assert {e[0] for e in ev} == {cc.BASE_EPOCH * 1000}

    def test_future_ts_exact_values(self, slow_runs: dict) -> None:
        r = slow_runs["future_ts"]
        assert (r["rc"], r["rows_in"], r["rows_ok"]) == (0, 20, 20)  # observed: 2099 accepted as ts_ok
        assert [e[0] for e in _events(r)] == [(4070908800 + i) * 1000 for i in range(20)]

    def test_hardlink_duplicates_counted(self, slow_runs: dict) -> None:
        r = slow_runs["hardlink"]
        assert (r["rc"], r["rows_in"], r["rows_ok"]) == (0, 40, 40)
        assert len({e[2] for e in _events(r)}) == 40

    def test_symlink_followed(self, slow_runs: dict) -> None:
        r = slow_runs["symlink"]
        if r["result"] == "not_run":
            pytest.skip(r["why"][0])
        assert (r["rc"], r["rows_in"], r["rows_ok"]) == (0, 20, 20)

    def test_invalid_utf8_line_counted_with_reason(self, slow_runs: dict) -> None:
        a = _acc(slow_runs["invalid_utf8_kv"])["fortigate_kv"]
        assert (a["rows_in"], a["rows_ok"], a["dropped"]) == (10, 9, 1)
        assert a["drop_reasons"] == {"decode_error (invalid UTF-8, line not readable)": 1}

    def test_binary_only_accounted(self, slow_runs: dict) -> None:
        r = slow_runs["binary_only"]
        assert r["rc"] == 0 and r["rows_ok"] == 0 and r["rows_in"] == r["dropped"] > 0
        assert list(_acc(r)) == ["unrecognized"]

    @bug("QA-CLI-06: zero-byte file only -> rc 0")
    def test_empty_file_nonzero_rc(self, slow_runs: dict) -> None:
        _clear_failure(slow_runs["empty_file"])

    @bug("QA-CLI-06: random-bytes file only -> rc 0")
    def test_binary_only_nonzero_rc(self, slow_runs: dict) -> None:
        _clear_failure(slow_runs["binary_only"])

    @bug("QA-CLI-07: --from-stage 3 without events Parquet -> rc 0, "
                                           "0 incidents, warnings only (run.py:62-68)")
    def test_from_stage_without_parquet_nonzero_rc(self, slow_runs: dict) -> None:
        _clear_failure(slow_runs["from_stage_no_prior"])
