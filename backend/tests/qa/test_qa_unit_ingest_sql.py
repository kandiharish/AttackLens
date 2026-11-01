"""QA unit / white-box tests for attacklens.ingest_sql (track qa_coverage_unit): the SQL builders are evaluated in
DuckDB on single hand-checked values, so every timestamp / label-stripping branch is pinned to an exact result.

Baseline coverage left unexecuted: json_raw_line without label config, json_raw_line with top-level labels only,
kv_select with eventtime_is_local false (shipped config has true), syslog messages without a process filter / action
/ outcome, the kv outcome_from_action map without an `action` key. Also pinned: ts_expr on every accepted input
shape (ISO Z, offset, naive-as-UTC, 13-digit ms, 10-digit s, fractional s, strptime formats) and rejections.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from attacklens import ingest_sql as q

UTC_0100 = 1793322000000          # 2026-10-30T01:00:00Z


@pytest.fixture
def con():
    c = duckdb.connect()
    c.execute("SET TimeZone='UTC'")
    yield c
    c.close()


@pytest.mark.parametrize("text, expected", [
    ("2026-10-30T01:00:00Z", UTC_0100),
    ("2026-10-30T06:30:00+05:30", UTC_0100),
    ("2026-10-30 01:00:00", UTC_0100),                 # naive = UTC on a UTC session
    ("2026-10-30T01:00:00.123Z", UTC_0100 + 123),
    ("1793322000123", UTC_0100 + 123),                 # 13 digits = ms
    ("1793322000", UTC_0100),                          # 10 digits = s
    ("1793322000.5", UTC_0100 + 500),                  # fractional seconds
    ("17933220001234", None),                          # 14 digits: neither ms nor s
    ("abc", None),
    ("", None),
])
def test_ts_expr_exact(con, text: str, expected: int | None) -> None:
    assert con.execute(f"SELECT {q.ts_expr('x', [])} FROM (SELECT ? AS x)", [text]).fetchone()[0] == expected


def test_ts_expr_strptime_formats(con) -> None:
    sql = q.ts_expr("x", ["%d/%b/%Y:%H:%M:%S %z"])
    assert con.execute(f"SELECT {sql} FROM (SELECT ? AS x)", ["30/Oct/2026:06:30:00 +0530"]).fetchone()[0] == UTC_0100
    no_fmt = q.ts_expr("x", [])                                      # near miss: same text without the format
    assert con.execute(f"SELECT {no_fmt} FROM (SELECT ? AS x)", ["30/Oct/2026:06:30:00 +0530"]).fetchone()[0] is None


def test_ts_expr_naive_follows_session_timezone() -> None:
    """Why CLAUDE.md pins TimeZone='UTC' on every connection: the naive branch is session-relative."""
    from attacklens import db
    c = duckdb.connect()
    try:
        c.execute("SET TimeZone='Asia/Kolkata'")
        ist = c.execute(f"SELECT {q.ts_expr('x', [])} FROM (SELECT '2026-10-30 06:30:00' AS x)").fetchone()[0]
    finally:
        c.close()
    assert ist == UTC_0100                                           # 06:30 IST = 01:00 UTC
    c2 = db.connect(memory_limit="256MB", threads=1)
    try:
        assert c2.execute("SELECT current_setting('TimeZone')").fetchone()[0] == "UTC"
    finally:
        c2.close()


# ---- json_raw_line -----------------------------------------------------------------------------------------------
def _raw(con, expr: str, line: str, valid: bool = True) -> str:
    return con.execute(f"SELECT {expr} FROM (SELECT ? AS line, ? AS v)", [line, 1 if valid else None]).fetchone()[0]


def test_json_raw_line_no_labels_is_identity() -> None:
    assert q.json_raw_line({}, {}) == "line"


def test_json_raw_line_top_labels_only(con) -> None:
    e = q.json_raw_line({"threat": None, "labels": None}, {})
    assert _raw(con, e, '{"a":1,"threat":"x"}') == '{"a":1}'
    assert _raw(con, e, '{"labels":[1],"a":2}') == '{"a":2}'
    assert _raw(con, e, '{"a":1}') == '{"a":1}'                                   # near miss: nothing to strip
    assert _raw(con, e, '{"a":1,"threat":"x', valid=False) == '{"a":1'          # malformed: cut at the label
    assert _raw(con, e, '{"a":"no label', valid=False) == '{"a":"no label'      # malformed, no label: kept


def test_json_raw_line_nested_hints_only(con) -> None:
    e = q.json_raw_line({}, {"event": {"kind": None, "severity": None}})
    assert _raw(con, e, '{"event":{"kind":"alert","action":"x","severity":3}}') == '{"event":{"action":"x"}}'
    assert _raw(con, e, '{"event":{"action":"x"}}') == '{"event":{"action":"x"}}'


# ---- kv timestamps ------------------------------------------------------------------------------------------------
KV_LINES = [
    'date=2026-10-30 time=06:30:00 tz="+0530" eventtime=1793322000 action=x',        # eventtime true UTC
    'date=2026-10-30 time=06:30:00 tz="+0530" eventtime=1793341800 action=x',        # eventtime = local as UTC
    'date=2026-10-30 time=06:30:00 tz="+0530" eventtime=1793341801 action=x',        # 1 s off local: not local
    'date=2026-10-30 time=06:30:00 tz="+0530" eventtime=1793341800123456789 action=x',  # ns, local + 123 ms
    'date=2026-10-30 time=06:30:00 tz="+05:30" action=x',                            # no eventtime: date+time+tz
    'date=2026-10-30 time=01:00:00 tz="-0400" action=x',
    'eventtime=1793322000123456 action=x',                                           # 16 digits = us
    'not a kv line',
]


def _kv_ts(tmp: Path, local: bool) -> list[tuple[int | None, bool]]:
    p = tmp / "fw.log"
    p.write_text("\n".join(KV_LINES) + "\n", encoding="utf-8", newline="\n")
    kcfg = {"line_regex": "=", "fields": {}, "ts": {"epoch_key": "eventtime", "date_key": "date", "time_key": "time",
                                                    "tz_key": "tz", "eventtime_is_local": local}}
    sql = q.kv_select("fortigate_kv", [p.as_posix()], tmp.as_posix(), kcfg)
    c = duckdb.connect()
    try:
        c.execute("SET TimeZone='UTC'")
        return c.execute(f"SELECT ts_ms, malformed FROM ({sql})").fetchall()
    finally:
        c.close()


H = 3_600_000


def test_kv_eventtime_is_local(tmp_path: Path) -> None:
    got = _kv_ts(tmp_path, True)
    assert got == [(UTC_0100, False), (UTC_0100, False), (UTC_0100 + 5 * H + 30 * 60_000 + 1000, False),
                   (UTC_0100 + 123, False), (UTC_0100, False), (UTC_0100 + 4 * H, False), (UTC_0100 + 123, False),
                   (None, True)]


def test_kv_eventtime_trusted_as_utc(tmp_path: Path) -> None:
    got = _kv_ts(tmp_path, False)
    local_as_utc = UTC_0100 + 5 * H + 30 * 60_000
    assert got == [(UTC_0100, False), (local_as_utc, False), (local_as_utc + 1000, False),
                   (local_as_utc + 123, False), (UTC_0100, False), (UTC_0100 + 4 * H, False),
                   (UTC_0100 + 123, False), (None, True)]


# ---- syslog without per-message process / action / outcome --------------------------------------------------------
def test_syslog_message_without_process_or_action(tmp_path: Path) -> None:
    from attacklens import config
    scfg = dict(config.load_config()["sources"]["syslog"])
    scfg["messages"] = [{"regex": "Accepted password for (\\S+)", "fields": {"user": 1}}]   # no process / action
    p = tmp_path / "auth.log"
    p.write_text("Oct 30 01:00:00 web-01 sshd[1]: Accepted password for bob from 1.2.3.4\n"
                 "Oct 30 01:00:01 web-01 cron[2]: Accepted password for alice\n"
                 "Oct 30 01:00:02 web-01 sshd[3]: Connection closed\n", encoding="utf-8", newline="\n")
    sql = q.syslog_select([p.as_posix()], tmp_path.as_posix(), scfg, 2026, "%Y %b %d %H:%M:%S", [])
    c = duckdb.connect()
    try:
        c.execute("SET TimeZone='UTC'")
        rows = c.execute(f"SELECT ts_ms, f_host, f_process_name, f_user, f_event_action FROM ({sql}) "
                         "ORDER BY ts_ms").fetchall()
    finally:
        c.close()
    assert rows == [(UTC_0100, "web-01", "sshd", "bob", None),
                    (UTC_0100 + 1000, "web-01", "cron", "alice", None),       # no process filter: any process
                    (UTC_0100 + 2000, "web-01", "sshd", None, None)]
