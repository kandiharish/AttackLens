"""L1 ingest fixture tests (TESTING.md §4.2). Exact values from hand-checked fixtures in fixtures/ingest/.

All six fixture formats are ingested together once (module scope), the way run.py calls Stage 0 + 1.
Expected epoch ms were computed by hand and cross-checked with datetime.fromisoformat (UTC).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from .conftest import FIXTURES, accounting, make_events_parquet, query, run_ingest

FX = FIXTURES / "ingest"

# (source_type) -> (rows_in, rows_ok, dropped)
EXPECTED_ACCOUNTING = {
    "ecs_json": (5, 4, 1),     # 1 malformed JSON line
    "win_json": (5, 5, 0),     # 3 EVTX-style + 2 Sysmon (.txt)
    "firewall_csv": (2, 2, 0),  # header is not a row
    "syslog": (4, 3, 1),       # 1 line without a timestamp (kept with ts_ok=false)
    "cef": (1, 1, 0),
}
LABEL_KEYS = ("threat", "rule", "labels", "labels_extra")


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("ingest_fx")
    raw = tmp / "raw"
    shutil.copytree(FX, raw)
    c = run_ingest(raw, tmp)
    yield c
    c.con.close()


def one(ctx, where: str, params: list | None = None) -> dict:
    rows = query(ctx, f"SELECT * FROM events WHERE {where}", params)
    assert len(rows) == 1, f"expected exactly 1 row for {where} {params}, got {len(rows)}"
    return rows[0]


# ---------------------------------------------------------------- fixture integrity
def test_fixture_bytes_have_bom_and_crlf() -> None:
    b = (FX / "ecs" / "edr_part.jsonl").read_bytes()
    assert b.startswith(b"\xef\xbb\xbf") and b.count(b"\r\n") == 5 and b.count(b"\n") == 5


# ---------------------------------------------------------------- accounting
def test_accounting_exact(ctx) -> None:
    acc = accounting(ctx)
    got = {k: (v["rows_in"], v["rows_ok"], v["dropped"]) for k, v in acc.items() if v["rows_in"]}
    assert got == EXPECTED_ACCOUNTING


def test_rows_in_equals_lines_and_parquet_holds_everything_parsable(ctx) -> None:
    n = query(ctx, "SELECT source_type, count(*) n, count(*) FILTER (WHERE ts_ok) ok FROM events GROUP BY 1")
    by = {r["source_type"]: (r["n"], r["ok"]) for r in n}
    for st, (rin, rok, _) in EXPECTED_ACCOUNTING.items():
        assert by[st][1] == rok, st
    # the syslog line without a timestamp is quarantined, never lost
    assert by["syslog"] == (4, 3)


def test_source_seq_unique_and_not_null(ctx) -> None:
    r = query(ctx, "SELECT count(*) n, count(DISTINCT source_seq) d, count(source_seq) nn FROM events")[0]
    assert r["n"] == r["d"] == r["nn"]


def test_ts_ok_partition_consistent(ctx) -> None:
    bad = query(ctx, "SELECT count(*) n FROM events WHERE ts_ok <> (ts_ms IS NOT NULL)")[0]["n"]
    assert bad == 0
    days = {str(r["event_day"]) for r in query(ctx, "SELECT DISTINCT event_day FROM events WHERE ts_ok")}
    assert days == {"2026-10-24"}


# ---------------------------------------------------------------- ECS JSON (generator)
def test_ecs_4625_domain_user_and_labels_stripped(ctx) -> None:
    r = one(ctx, "source_type='ecs_json' AND event_id=4625")
    assert r["ts_ms"] == 1792807203120  # 2026-10-24T02:00:03.120Z, first line after the BOM
    assert (r["action"], r["outcome"], r["logon_type"]) == ("login_failed", "failure", 3)
    assert (r["host"], r["host_ip"], r["target_user"], r["src_ip"]) == ("srv-dc-01", "10.10.0.10", "jdoe",
                                                                        "203.0.113.57")
    assert r["is_machine"] is False
    raw = json.loads(r["raw_line"])
    for k in LABEL_KEYS:
        assert k not in raw, f"label field {k!r} leaked into raw_line"
    assert raw["user"]["name"] == "CORP\\jdoe"  # raw evidence is the original value


def test_ecs_4624_network_logon_upn_user(ctx) -> None:
    r = one(ctx, "source_type='ecs_json' AND event_id=4624")
    assert r["ts_ms"] == 1792807491004
    assert (r["action"], r["outcome"], r["logon_type"], r["logon_id"]) == ("login_success", "success", 3, "0x8a3f21")
    assert r["target_user"] == "jdoe"  # jdoe@corp.local


def test_ecs_process_offset_timestamp_and_lower_name(ctx) -> None:
    r = one(ctx, "source_type='ecs_json' AND action='proc_start'")
    assert r["ts_ms"] == 1792808100000  # 07:45+05:30 == 02:15Z
    assert (r["process_name"], r["parent_process"]) == ("powershell.exe", "winword.exe")
    assert r["process_path"] == "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    assert r["command_line"] == "powershell.exe -enc SQBFAFgA"
    assert (r["src_user"], r["host"]) == ("pmehta", "ws-fin-010")


def test_ecs_network_bytes_and_empty_domain_null(ctx) -> None:
    r = one(ctx, "source_type='ecs_json' AND action='conn_out'")
    assert r["ts_ms"] == 1792808400000
    assert (r["dst_ip"], r["dst_port"], r["bytes_out"]) == ("198.51.100.23", 443, 26214400)
    assert r["dst_domain"] is None  # "" -> NULL
    assert r["src_ip"] is None and r["src_port"] is None and r["file_path"] is None


def test_raw_line_kept_for_every_row_including_quarantined(ctx) -> None:
    # DEVELOPMENT.md §3.1: raw_line = original line. A quarantined/malformed row without it is silent data loss.
    missing = query(ctx, "SELECT source_type, action FROM events WHERE raw_line IS NULL")
    assert missing == [], f"rows without raw_line: {missing}"
    r = one(ctx, "source_type='ecs_json' AND NOT ts_ok")
    assert r["raw_line"] == '{"@timestamp":"2026-10-24T02:10:00.000Z","event":{"action":"user_lo'


def test_raw_lines_have_no_bom_or_cr(ctx) -> None:
    for r in query(ctx, "SELECT raw_line FROM events WHERE raw_line IS NOT NULL"):
        assert "\r" not in r["raw_line"] and "\ufeff" not in r["raw_line"]


# ---------------------------------------------------------------- Windows EVTX-style JSON
def test_win_4624(ctx) -> None:
    r = one(ctx, "source_type='win_json' AND event_id=4624")
    assert r["ts_ms"] == 1792808400123  # 7 fractional digits truncated to ms
    assert (r["action"], r["host"], r["target_user"], r["src_ip"]) == ("login_success", "srv-file-01", "svc_sql",
                                                                       "10.10.3.15")
    assert (r["logon_type"], r["logon_id"]) == (3, "0x3e7a1")


def test_win_4625_dash_ip_is_null(ctx) -> None:
    r = one(ctx, "source_type='win_json' AND event_id=4625")
    assert r["ts_ms"] == 1792808460000
    assert (r["action"], r["target_user"], r["logon_type"]) == ("login_failed", "jdoe", 3)
    assert r["src_ip"] is None  # "-" -> NULL


def test_win_4720_actor_and_new_account(ctx) -> None:
    r = one(ctx, "source_type='win_json' AND event_id=4720")
    assert r["ts_ms"] == 1792808520000
    assert (r["action"], r["host"], r["src_user"], r["target_user"]) == ("user_created", "srv-dc-01", "asharma",
                                                                         "helpdesk_tmp")


# ---------------------------------------------------------------- Sysmon JSON saved as .txt
def test_sysmon_txt_routed_by_content(ctx) -> None:
    rows = query(ctx, "SELECT * FROM events WHERE source_type='win_json' AND event_id=1 ORDER BY ts_ms")
    assert [r["ts_ms"] for r in rows] == [1792809000000, 1792809060500]
    a, b = rows
    assert (a["action"], a["host"], a["process_name"], a["parent_process"]) == ("proc_start", "ws-hr-012",
                                                                                 "cmd.exe", "winword.exe")
    assert a["process_path"] == "C:\\Windows\\System32\\cmd.exe" and a["command_line"] == "cmd.exe /c whoami"
    assert a["src_user"] == "pmehta"
    assert (b["process_name"], b["parent_process"]) == ("powershell.exe", "cmd.exe")


# ---------------------------------------------------------------- firewall CSV saved as .log
def test_firewall_csv(ctx) -> None:
    rows = query(ctx, "SELECT * FROM events WHERE source_type='firewall_csv' ORDER BY ts_ms")
    assert [r["ts_ms"] for r in rows] == [1792809600000, 1792809660000]  # naive time read as UTC
    a, b = rows
    assert (a["action"], a["host"], a["src_ip"], a["dst_ip"], a["dst_port"], a["bytes_out"]) == (
        "conn_allowed", "fw-edge-01", "10.10.3.15", "198.51.100.23", 443, 26214400)
    assert (b["action"], b["dst_ip"], b["dst_port"], b["bytes_out"]) == ("conn_denied", "203.0.113.57", 22, None)
    for r in rows:
        assert r["src_user"] is None and r["target_user"] is None  # no user column


# ---------------------------------------------------------------- syslog auth.log
def test_syslog_sshd_accepted(ctx) -> None:
    r = one(ctx, "source_type='syslog' AND action='login_success'")
    assert r["ts_ms"] == 1792879511000  # Oct 24 22:05:11 + baseline_year 2026
    assert (r["host"], r["process_name"], r["target_user"], r["src_ip"]) == ("srv-web-01", "sshd", "vreddy",
                                                                             "192.0.2.88")
    assert (r["src_port"], r["dst_port"], r["outcome"]) == (50522, 22, "success")


def test_syslog_sshd_failed_invalid_user(ctx) -> None:
    r = one(ctx, "source_type='syslog' AND action='login_failed'")
    assert r["ts_ms"] == 1792879499000
    assert (r["target_user"], r["src_port"], r["dst_port"], r["process_name"]) == ("admin", 50510, 22, "sshd")


def test_syslog_sudo(ctx) -> None:
    r = one(ctx, "source_type='syslog' AND process_name='sudo'")
    assert r["ts_ms"] == 1792879560000
    assert (r["action"], r["src_user"], r["target_user"], r["command_line"]) == ("proc_start", "vreddy", "root",
                                                                                 "/bin/bash")


def test_syslog_line_without_timestamp_quarantined(ctx) -> None:
    r = one(ctx, "source_type='syslog' AND NOT ts_ok")
    assert r["ts_ms"] is None
    assert (r["host"], r["process_name"]) == ("srv-web-01", "sshd")  # anchored after host, never "04"
    assert r["raw_line"] == "srv-web-01 sshd[2300]: Connection closed by 192.0.2.88 port 50530"


def test_syslog_process_never_from_time(ctx) -> None:
    procs = {r["process_name"] for r in query(ctx, "SELECT process_name FROM events WHERE source_type='syslog'")}
    assert procs == {"sshd", "sudo"}


# ---------------------------------------------------------------- CEF
def test_cef(ctx) -> None:
    r = one(ctx, "source_type='cef'")
    assert r["ts_ms"] == 1792810200000
    assert (r["action"], r["host"], r["src_user"], r["process_name"]) == ("reg_set", "ws-hr-012", "pmehta",
                                                                          "powershell.exe")


# ---------------------------------------------------------------- normalization across sources
def test_users_normalized_everywhere(ctx) -> None:
    users = {u for r in query(ctx, "SELECT src_user, target_user FROM events") for u in r.values() if u}
    assert users == {"jdoe", "pmehta", "svc_sql", "asharma", "helpdesk_tmp", "vreddy", "admin", "root"}
    for u in users:
        assert u == u.lower() and "\\" not in u and "@" not in u


def test_hosts_lower_case(ctx) -> None:
    hosts = {r["host"] for r in query(ctx, "SELECT DISTINCT host FROM events WHERE host IS NOT NULL")}
    # only the malformed JSON line has no host
    assert query(ctx, "SELECT count(*) n FROM events WHERE host IS NULL")[0]["n"] == 1
    assert hosts == {"srv-dc-01", "ws-fin-010", "srv-file-01", "ws-hr-012", "fw-edge-01", "srv-web-01"}


def test_empty_strings_never_stored(ctx) -> None:
    cols = [r["column_name"] for r in query(ctx, "DESCRIBE events") if r["column_type"] == "VARCHAR"]
    for c in cols:
        n = query(ctx, f'SELECT count(*) n FROM events WHERE "{c}" = \'\'')[0]["n"]
        assert n == 0, f"column {c} holds empty strings (must be NULL)"


def test_canonical_columns_present(ctx) -> None:
    from attacklens.schemas import CANONICAL_COLUMNS
    got = {r["column_name"]: r["column_type"] for r in query(ctx, "DESCRIBE events")}
    for c, t in CANONICAL_COLUMNS.items():
        assert c in got, c
        if c not in ("ts_ok", "event_day", "source_type"):  # hive partition columns are re-inferred
            assert got[c] == t, (c, got[c], t)


# ---------------------------------------------------------------- time zone independence
_TZ_SCRIPT = r"""
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from tests.conftest import run_ingest, query
ctx = run_ingest(Path(sys.argv[1]), Path(sys.argv[2]))
rows = query(ctx, "SELECT * EXCLUDE (event_day) , CAST(event_day AS VARCHAR) d FROM events "
                  "ORDER BY source_type, ts_ms NULLS LAST, raw_line")
print(json.dumps(rows, default=str, sort_keys=True))
"""


@pytest.mark.parametrize("tz", ["Asia/Kolkata", "America/New_York"])
def test_timezone_independent(tmp_path: Path, tz: str) -> None:
    outs = {}
    for name in ("UTC", tz):
        work = tmp_path / name.replace("/", "_")
        shutil.copytree(FX, work / "raw")
        env = {**os.environ, "TZ": name}
        p = subprocess.run([sys.executable, "-c", _TZ_SCRIPT, str(work / "raw"), str(work),
                            str(Path(__file__).resolve().parents[1])],
                           capture_output=True, text=True, env=env, timeout=120)
        assert p.returncode == 0, p.stderr[-2000:]
        outs[name] = json.loads(p.stdout.strip().splitlines()[-1])
    a, b = outs["UTC"], outs[tz]
    assert sum(1 for r in a if r["ts_ok"]) == 15  # 4 + 5 + 2 + 3 + 1
    # source_seq may hash the absolute filename; everything else must be identical
    strip = lambda rows: [{k: v for k, v in r.items() if k != "source_seq"} for r in rows]
    assert strip(a) == strip(b)
    assert {r["ts_ms"] for r in a if r["source_type"] == "ecs_json"} >= {1792807203120, 1792808100000}


# ---------------------------------------------------------------- shared helper (used by detection/link tests)
def test_make_events_parquet_helper(tmp_path: Path) -> None:
    rows = [
        {"ts_ms": 1792807203120, "action": "login_failed", "host": "srv-dc-01", "target_user": "jdoe",
         "logon_type": 3, "bytes_out": None},
        {"ts_ms": 1792893603120, "action": "conn_out", "host": "ws-fin-010", "bytes_out": 26214400,
         "source_type": "firewall_csv"},
        {"ts_ms": None, "action": "other", "host": "srv-web-01", "source_type": "syslog"},
    ]
    ctx = make_events_parquet(tmp_path, rows)
    try:
        got = query(ctx, "SELECT ts_ms, ts_ok, CAST(event_day AS VARCHAR) d, source_type, action, host, target_user, "
                         "logon_type, bytes_out, src_ip FROM events ORDER BY ts_ms NULLS LAST")
        assert got == [
            {"ts_ms": 1792807203120, "ts_ok": True, "d": "2026-10-24", "source_type": "ecs_json",
             "action": "login_failed", "host": "srv-dc-01", "target_user": "jdoe", "logon_type": 3,
             "bytes_out": None, "src_ip": None},
            {"ts_ms": 1792893603120, "ts_ok": True, "d": "2026-10-25", "source_type": "firewall_csv",
             "action": "conn_out", "host": "ws-fin-010", "target_user": None, "logon_type": None,
             "bytes_out": 26214400, "src_ip": None},
            {"ts_ms": None, "ts_ok": False, "d": "1970-01-01", "source_type": "syslog", "action": "other",
             "host": "srv-web-01", "target_user": None, "logon_type": None, "bytes_out": None, "src_ip": None},
        ]
        assert (ctx.parquet_dir / "events" / "source_type=ecs_json" / "ts_ok=true" / "event_day=2026-10-24"
                / "data.parquet").exists()
        r = query(ctx, "SELECT count(DISTINCT source_seq) n, typeof(any_value(source_seq)) t FROM events")[0]
        assert r == {"n": 3, "t": "UBIGINT"}
        with pytest.raises(KeyError):
            make_events_parquet(tmp_path / "bad", [{"threat": "T1110"}])
    finally:
        ctx.con.close()
