"""FortiGate key=value ingest, exact values (DEVELOPMENT.md §15.9, config/sources.yaml kv_sources.fortigate_kv).
Fixtures are made up (fixtures/ingest_fortigate/*.txt). Real files under logs/ are confidential and never read.

Clock: every line is local 07:30:SS +0530 = 02:00:SS UTC. fw.txt writes eventtime as the LOCAL time "as if UTC"
(what the real tiers do), fw_utc.txt writes eventtime as true UTC; both must give the same instant.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from .conftest import FIXTURES, accounting, query, run_ingest

FX = FIXTURES / "ingest_fortigate"
T0 = 1792807200000  # 2026-10-24T02:00:00Z = 07:30:00 +0530
UNPARSEABLE = "unparseable_line (kept in ts_ok=false, action=malformed)"
DECODE = "decode_error (invalid UTF-8, line not readable)"


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("fgt")
    (tmp / "raw").mkdir()
    for name in ("fw.txt", "fw_utc.txt"):  # .txt on purpose: routed by content, not extension
        shutil.copy(FX / name, tmp / "raw" / name)
    c = run_ingest(tmp / "raw", tmp)
    yield c
    c.con.close()


def row(ctx, ts: int) -> dict:
    rows = query(ctx, "SELECT * FROM events WHERE ts_ms = ?", [ts])
    assert len(rows) == 1, (ts, rows)
    return rows[0]


def acc_entry(ctx) -> dict:
    import json
    rows = json.loads((ctx.out_dir / "ingest_accounting.json").read_text(encoding="utf-8"))
    return next(r for r in rows if r["source_type"] == "fortigate_kv")


# ---------------------------------------------------------------- routing + accounting
def test_routed_by_content_as_fortigate(ctx) -> None:
    acc = {k: v for k, v in accounting(ctx).items() if v["rows_in"]}
    assert list(acc) == ["fortigate_kv"]
    assert {r["source_type"] for r in query(ctx, "SELECT DISTINCT source_type FROM events")} == {"fortigate_kv"}


def test_accounting_exact(ctx) -> None:
    e = acc_entry(ctx)
    # fw.txt 16 lines (1 URL + 14 log lines + 1 invalid UTF-8) + fw_utc.txt 2 lines
    assert (e["rows_in"], e["rows_ok"], e["dropped"]) == (18, 16, 2)
    assert e["drop_reasons"] == {UNPARSEABLE: 1, DECODE: 1}


def test_url_header_line_kept_as_unparseable(ctx) -> None:
    r = query(ctx, "SELECT * FROM events WHERE NOT ts_ok")
    assert len(r) == 1
    assert (r[0]["raw_line"], r[0]["action"], r[0]["ts_ms"]) == ("http://192.0.2.1:8000/", "malformed", None)


def test_ts_ok_rows_and_unique_source_seq(ctx) -> None:
    r = query(ctx, "SELECT count(*) n, count(DISTINCT source_seq) d FROM events WHERE ts_ok")[0]
    assert r == {"n": 16, "d": 16}


# ---------------------------------------------------------------- time
def test_eventtime_19_digits_local_as_utc_minus_offset_plus_ms(ctx) -> None:
    assert row(ctx, T0 + 123)["dst_ip"] == "198.51.100.7"  # 07:30:00.123456789 local -> 02:00:00.123Z


def test_eventtime_16_digits(ctx) -> None:
    assert row(ctx, T0 + 11_654)["dst_ip"] == "198.51.100.11"  # microseconds, sub-ms truncated


def test_eventtime_10_digits(ctx) -> None:
    assert row(ctx, T0 + 12_000)["dst_ip"] == "198.51.100.12"


def test_eventtime_true_utc_is_trusted(ctx) -> None:
    assert row(ctx, T0 + 20_000)["dst_ip"] == "198.51.100.20"
    assert row(ctx, T0 + 21_500)["dst_ip"] == "198.51.100.21"


def test_every_ok_row_on_the_expected_instant(ctx) -> None:
    got = sorted(r["ts_ms"] - T0 for r in query(ctx, "SELECT ts_ms FROM events WHERE ts_ok"))
    assert got == [123, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000, 11654, 12000, 13000,
                   20000, 21500]
    assert {str(r["event_day"]) for r in query(ctx, "SELECT DISTINCT event_day FROM events WHERE ts_ok")} == {
        "2026-10-24"}


# ---------------------------------------------------------------- per record type
def test_traffic_accept_all_columns(ctx) -> None:
    r = row(ctx, T0 + 123)
    want = {"action": "conn_allowed", "outcome": "success", "host": "fgt-sim-01", "src_ip": "10.0.0.5",
            "src_port": 50000, "dst_ip": "198.51.100.7", "dst_port": 443, "bytes_out": 1200, "bytes_in": 3400,
            "service_name": "https", "app": "example",  # lower-cased ids "src_zone": "lan", "dst_zone": "wan",
            "vendor_severity": "notice", "signature": None, "src_user": None, "target_user": None,
            "dst_domain": None, "logon_type": None}
    assert {k: r[k] for k in want} == want
    assert r["raw_line"].startswith("date=2026-10-24 time=07:30:00 devname=")


def test_traffic_deny(ctx) -> None:
    r = row(ctx, T0 + 1000)
    assert (r["action"], r["outcome"], r["src_ip"], r["dst_ip"], r["dst_port"], r["src_zone"], r["dst_zone"]) == (
        "conn_denied", "failure", "203.0.113.9", "10.0.0.5", 3389, "wan", "lan")
    assert (r["bytes_out"], r["bytes_in"], r["service_name"]) == (0, 0, "rdp")


def test_admin_login_failed_src_ip_from_ui(ctx) -> None:
    r = row(ctx, T0 + 2000)
    assert (r["action"], r["outcome"], r["target_user"], r["src_user"], r["src_ip"], r["host"]) == (
        "login_failed", "failure", "admin", None, "203.0.113.9", "fgt-sim-01")
    assert r["vendor_severity"] == "alert"


def test_vpn_login_success(ctx) -> None:
    r = row(ctx, T0 + 3000)
    assert (r["action"], r["outcome"], r["logon_type"], r["target_user"]) == (
        "login_success", "success", 10, "jdoe")


@pytest.mark.xfail(strict=True, reason="BUG (BB-ingest): FortiGate VPN login remip (the client's public IP) is not "
                   "mapped to src_ip, so the attacker IP of a VPN logon is lost (fields.src_ip = [srcip, ui])")
def test_vpn_login_keeps_remote_ip(ctx) -> None:
    assert row(ctx, T0 + 3000)["src_ip"] == "203.0.113.20"


def test_ips_dropped(ctx) -> None:
    r = row(ctx, T0 + 4000)
    assert (r["action"], r["outcome"], r["signature"], r["vendor_severity"], r["src_ip"], r["dst_ip"],
            r["dst_port"]) == ("ips_alert", "blocked", "Example.Exploit", "high", "203.0.113.9", "10.0.0.20", 443)


def test_ips_detected_is_allowed(ctx) -> None:
    r = row(ctx, T0 + 5000)
    assert (r["action"], r["outcome"], r["signature"], r["vendor_severity"]) == (
        "ips_alert", "allowed", "Example.Probe", "medium")


def test_webfilter_blocked_and_passthrough(ctx) -> None:
    b, p = row(ctx, T0 + 6000), row(ctx, T0 + 7000)
    assert (b["action"], b["outcome"], b["signature"], b["dst_domain"], b["file_path"]) == (
        "web_blocked", "blocked", "Malicious Websites", "bad.example.test", "/x")
    assert (p["action"], p["outcome"], p["signature"], p["dst_domain"]) == (
        "web_access", "allowed", "Business", "ok.example.test")


def test_virus_blocked(ctx) -> None:
    r = row(ctx, T0 + 8000)
    assert (r["action"], r["outcome"], r["signature"], r["dst_domain"], r["file_path"], r["src_ip"]) == (
        "av_alert", "blocked", "Example.Virus", "dl.example.test", "/f.exe", "10.0.0.5")


def test_dns_query(ctx) -> None:
    r = row(ctx, T0 + 9000)
    assert (r["action"], r["dst_domain"], r["src_ip"], r["dst_ip"], r["dst_port"]) == (
        "dns_query", "example.test", "10.0.0.5", "10.0.0.2", 53)


def test_config_change(ctx) -> None:
    r = row(ctx, T0 + 10_000)
    assert (r["action"], r["src_user"], r["target_user"], r["src_ip"], r["host"]) == (
        "config_change", "admin", None, "10.0.99.10", "fgt-sim-01")


def test_na_values_are_null(ctx) -> None:
    r = row(ctx, T0 + 13_000)
    assert (r["app"], r["src_port"], r["dst_port"], r["bytes_out"]) == (None, None, 443, 12)


def test_no_empty_strings_stored(ctx) -> None:
    cols = [r["column_name"] for r in query(ctx, "DESCRIBE events") if r["column_type"] == "VARCHAR"]
    for c in cols:
        assert query(ctx, f'SELECT count(*) n FROM events WHERE "{c}" = \'\'')[0]["n"] == 0, c


# ---------------------------------------------------------------- lone CR inside a line (own file)
@pytest.mark.xfail(strict=True, reason="BUG (BB-ingest): a lone CR (0x0D) inside a FortiGate line is treated as a "
                   "line break - rows_in 3 for a 2-line file (same bug as test_robustness)")
def test_lone_cr_inside_line(tmp_path: Path) -> None:
    (tmp_path / "raw").mkdir()
    shutil.copy(FX / "fw_cr.txt", tmp_path / "raw" / "fw_cr.txt")
    c = run_ingest(tmp_path / "raw", tmp_path)
    try:
        a = accounting(c)["fortigate_kv"]
        ts = sorted(r["ts_ms"] - T0 for r in query(c, "SELECT ts_ms FROM events WHERE ts_ok"))
    finally:
        c.con.close()
    assert a["rows_in"] == 2 and a["rows_ok"] + a["dropped"] == 2
    assert ts[-1] == 31_000 and a["rows_ok"] == 2  # \n is the only line terminator
