"""L1 detection tests (TESTING.md §4.3): every template gets a positive and a near-miss; match rules fire on their
signal and only on it; raw_alerts schema (§15.4); evidence bounds; CEF label fields never used; episodes (§4 Stage
2.5, §15.4).

Template tests pin the §4.3 threshold values explicitly (SPEC_TH) so they test template semantics, not tuning.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Any

import duckdb
import pytest

from attacklens import config, detect, detect_sql, episodes, lookups
from attacklens import detect_templates as T

from .conftest import make_events_parquet, query, run_ingest

T0 = 1792807200000  # 2026-10-24T02:00:00Z (outside business hours; bucket-aligned: T0 % 300000 == 0)
S, MIN, H, DAY = 1000, 60_000, 3_600_000, 86_400_000
MB = 1_000_000

SPEC_TH = {  # TESTING.md §4.3 / DEVELOPMENT.md §5.1 values
    "bf_min_failures": 50, "bf_gap_ms": 10 * MIN, "bf_success_window_ms": 15 * MIN, "bf_require_success": False,
    "emit_t1078_on_bruteforce": True, "spray_min_users": 15, "spray_window_ms": 10 * MIN,
    "create_elevate_window_ms": 24 * H, "exfil_min_bytes": 50 * MB, "exfil_window_ms": 15 * MIN,
    "exfil_baseline_mult": 5.0, "mass_rename_min": 100, "mass_rename_window_ms": 60 * S, "beacon_min_conns": 6,
    "beacon_max_cv": 0.2, "beacon_session_gap_ms": H, "new_admin_max_pair_seen": 2,
    "evidence_max_lines": 3, "evidence_max_chars": 300, "source_keys_max": 50,
}

RAW_ALERTS_SCHEMA = [  # DEVELOPMENT.md §15.4, binding order and types
    ("rule_id", "VARCHAR"), ("technique_id", "VARCHAR"), ("sub_technique_id", "VARCHAR"),
    ("technique_name", "VARCHAR"), ("tactic", "VARCHAR"), ("tactic_idx", "INTEGER"), ("severity", "INTEGER"),
    ("ts_ms", "BIGINT"), ("last_ts_ms", "BIGINT"), ("source_seq", "UBIGINT"), ("host", "VARCHAR"),
    ("subject_host", "VARCHAR"), ("src_host", "VARCHAR"), ("dst_host", "VARCHAR"), ("src_user", "VARCHAR"),
    ("target_user", "VARCHAR"), ("src_ip", "VARCHAR"), ("dst_ip", "VARCHAR"), ("raw_alert_count", "BIGINT"),
    ("evidence_lines", "VARCHAR[]"), ("source_keys", "UBIGINT[]"),
]


# ---------------------------------------------------------------- event builders (canonical rows)
def fail(ts: int, user: str = "jdoe", host: str = "srv-dc-01", ip: str = "203.0.113.57") -> dict:
    return {"ts_ms": ts, "action": "login_failed", "outcome": "failure", "event_id": 4625, "logon_type": 3,
            "host": host, "host_ip": "10.10.0.10", "target_user": user, "src_ip": ip}


def success(ts: int, user: str = "jdoe", host: str = "srv-dc-01", ip: str | None = "203.0.113.57",
            logon_type: int | None = 3, logon_id: str | None = None, **kw) -> dict:
    return {"ts_ms": ts, "action": "login_success", "outcome": "success", "event_id": 4624,
            "logon_type": logon_type, "logon_id": logon_id, "host": host, "host_ip": "10.10.0.10",
            "target_user": user, "src_ip": ip, **kw}


def priv(ts: int, user: str, host: str, logon_id: str) -> dict:
    return {"ts_ms": ts, "action": "priv_assigned", "event_id": 4672, "host": host, "target_user": user,
            "logon_id": logon_id}


def conn(ts: int, dst: str, nbytes: int | None = None, host: str = "ws-fin-010", src: str = "10.10.3.10",
         **kw) -> dict:
    return {"ts_ms": ts, "action": "conn_out", "host": host, "host_ip": src, "src_ip": src, "dst_ip": dst,
            "dst_port": 443, "bytes_out": nbytes, "src_user": "pmehta", **kw}


def proc(ts: int, name: str, cmd: str, parent: str = "explorer.exe", host: str = "ws-hr-012") -> dict:
    return {"ts_ms": ts, "action": "proc_start", "event_id": 4688, "host": host, "src_user": "pmehta",
            "process_name": name, "parent_process": parent, "command_line": cmd}


# ---------------------------------------------------------------- runners
@pytest.fixture
def ev(tmp_path: Path):
    made: list = []

    def _make(rows: list[dict]):
        ctx = make_events_parquet(tmp_path / f"c{len(made)}", rows)
        made.append(ctx)
        detect_sql.prepare(ctx.con, ctx.cfg)
        return ctx

    yield _make
    for c in made:
        c.con.close()


def rule_of(cfg: dict, rule_id: str) -> dict:
    rules, _ = detect.rules_and_thresholds(cfg)
    return next(r for r in rules if r["id"] == rule_id)


def th_of(cfg: dict, **over: Any) -> dict:
    _, th = detect.rules_and_thresholds(cfg)
    return {**th, **SPEC_TH, **over}


def run_template(ctx, rule_id: str, **over: Any) -> list[dict]:
    rule = rule_of(ctx.cfg, rule_id)
    sql = T.TEMPLATES[rule["template"]](ctx.con, rule, th_of(ctx.cfg, **over))
    cur = ctx.con.execute(sql + " ORDER BY ts_ms, technique_id")
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def labels(rows: list[dict]) -> list[tuple]:
    return [(r["technique_id"], r["sub_technique_id"], r["tactic"]) for r in rows]


# ================================================================ brute force (T1110 + T1078)
def bf_rows(n: int, start: int = T0, step: int = S, **kw) -> list[dict]:
    return [fail(start + i * step, **kw) for i in range(n)]


def test_bf_50_failures_fires(ev) -> None:
    rows = run_template(ev(bf_rows(50)), "brute_force_then_success")
    assert labels(rows) == [("T1110", "T1110.001", "Credential Access")]
    r = rows[0]
    assert (r["ts_ms"], r["last_ts_ms"], r["raw_alert_count"]) == (T0, T0 + 49 * S, 50)
    assert (r["host"], r["subject_host"], r["target_user"], r["src_ip"]) == ("srv-dc-01", "srv-dc-01", "jdoe",
                                                                             "203.0.113.57")


def test_bf_49_failures_silent(ev) -> None:
    assert run_template(ev(bf_rows(49)), "brute_force_then_success") == []


def test_bf_50_failures_split_over_two_users_silent(ev) -> None:
    rows = bf_rows(25, user="jdoe") + bf_rows(25, start=T0 + 30 * S, user="asharma")
    assert run_template(ev(rows), "brute_force_then_success") == []


def test_bf_burst_split_on_11_min_gap(ev) -> None:
    a = bf_rows(25)
    b = bf_rows(25, start=a[-1]["ts_ms"] + 11 * MIN)
    assert run_template(ev(a + b), "brute_force_then_success") == []


def test_bf_9_min_gap_stays_one_burst(ev) -> None:
    a = bf_rows(25)
    b = bf_rows(25, start=a[-1]["ts_ms"] + 9 * MIN)
    rows = run_template(ev(a + b), "brute_force_then_success")
    assert [(r["ts_ms"], r["raw_alert_count"]) for r in rows] == [(T0, 50)]


def test_bf_two_full_bursts_two_alerts(ev) -> None:
    a = bf_rows(50)
    b = bf_rows(50, start=a[-1]["ts_ms"] + 11 * MIN)
    rows = run_template(ev(a + b), "brute_force_then_success")
    assert [(r["ts_ms"], r["raw_alert_count"]) for r in rows] == [(T0, 50), (b[0]["ts_ms"], 50)]


def test_bf_success_at_14_min_emits_t1078(ev) -> None:
    f = bf_rows(50)
    s_ts = f[-1]["ts_ms"] + 14 * MIN
    rows = run_template(ev(f + [success(s_ts)]), "brute_force_then_success")
    assert labels(rows) == [("T1110", "T1110.001", "Credential Access"), ("T1078", None, "Initial Access")]
    t1078 = rows[1]
    assert (t1078["ts_ms"], t1078["target_user"], t1078["host"], t1078["raw_alert_count"]) == (
        s_ts, "jdoe", "srv-dc-01", 1)
    assert t1078["severity"] == rule_of(config.load_config(), "brute_force_then_success")["secondary"]["severity"]


def test_bf_success_at_16_min_t1110_only(ev) -> None:
    f = bf_rows(50)
    rows = run_template(ev(f + [success(f[-1]["ts_ms"] + 16 * MIN)]), "brute_force_then_success")
    assert labels(rows) == [("T1110", "T1110.001", "Credential Access")]  # brute force stays, no T1078


def test_bf_require_success_true_needs_success(ev) -> None:
    f = bf_rows(50)
    ctx = ev(f + [success(f[-1]["ts_ms"] + 16 * MIN)])
    assert run_template(ctx, "brute_force_then_success", bf_require_success=True) == []


def test_bf_success_before_burst_ignored(ev) -> None:
    rows = run_template(ev([success(T0 - MIN)] + bf_rows(50)), "brute_force_then_success")
    assert labels(rows) == [("T1110", "T1110.001", "Credential Access")]


# ================================================================ password spray (T1110.003)
SPRAY_USERS = [f"user{i:02d}" for i in range(20)]


def spray(n_users: int, spacing: int = 30 * S, ip: str = "192.0.2.88") -> list[dict]:
    return [fail(T0 + i * spacing, user=SPRAY_USERS[i], host="srv-web-01", ip=ip) for i in range(n_users)]


def test_spray_15_users_fires(ev) -> None:
    rows = run_template(ev(spray(15)), "password_spray")
    assert labels(rows) == [("T1110", "T1110.003", "Credential Access")]
    r = rows[0]
    assert (r["ts_ms"], r["last_ts_ms"], r["raw_alert_count"], r["src_ip"], r["host"]) == (
        T0, T0 + 14 * 30 * S, 15, "192.0.2.88", "srv-web-01")
    assert r["target_user"] is None  # no success followed


def test_spray_14_users_silent(ev) -> None:
    assert run_template(ev(spray(14)), "password_spray") == []


def test_spray_15_users_over_14_min_silent(ev) -> None:
    assert run_template(ev(spray(15, spacing=MIN)), "password_spray") == []  # no 10-min window holds 15


def test_spray_then_success_emits_t1078_for_that_account(ev) -> None:
    f = spray(15)
    s_ts = f[-1]["ts_ms"] + 2 * MIN
    rows = run_template(ev(f + [success(s_ts, user="vreddy", host="srv-web-01", ip="192.0.2.88")]),
                        "password_spray")
    assert labels(rows) == [("T1110", "T1110.003", "Credential Access"), ("T1078", None, "Initial Access")]
    assert rows[0]["target_user"] == "vreddy" and rows[1]["ts_ms"] == s_ts


# ================================================================ account created then elevated (T1136 + T1098)
def created(ts: int) -> dict:
    return {"ts_ms": ts, "action": "user_created", "event_id": 4720, "host": "srv-dc-01", "src_user": "asharma",
            "target_user": "helpdesk_tmp"}


def added(ts: int) -> dict:
    return {"ts_ms": ts, "action": "group_member_added", "event_id": 4732, "host": "srv-dc-01",
            "src_user": "asharma", "target_user": "helpdesk_tmp", "group_name": "administrators"}


def test_create_then_elevate_23h_fires_both(ev) -> None:
    rows = run_template(ev([created(T0), added(T0 + 23 * H)]), "account_created_then_elevated")
    assert labels(rows) == [("T1136", None, "Persistence"), ("T1098", None, "Privilege Escalation")]
    assert [r["ts_ms"] for r in rows] == [T0, T0 + 23 * H]
    assert all((r["src_user"], r["target_user"]) == ("asharma", "helpdesk_tmp") for r in rows)


def test_create_then_elevate_25h_silent(ev) -> None:
    assert run_template(ev([created(T0), added(T0 + 25 * H)]), "account_created_then_elevated") == []


def test_group_add_alone_silent(ev) -> None:
    assert run_template(ev([added(T0)]), "account_created_then_elevated") == []


# ================================================================ exfiltration (T1048)
def exfil_rows(total: int, dst: str = "198.51.100.23", baseline: int = MB) -> list[dict]:
    """5 quiet days of `baseline` bytes/day to one external dst, then `total` bytes in 3 conns within 10 min."""
    days = [conn(T0 - (d + 1) * DAY, "203.0.113.99", baseline) for d in range(5)]
    burst = [conn(T0 + i * 5 * MIN, dst, total // 3 + (total % 3 if i == 0 else 0)) for i in range(3)]
    return days + burst


def test_exfil_51mb_external_fires(ev) -> None:
    rows = run_template(ev(exfil_rows(51 * MB)), "exfil_volume")
    assert labels(rows) == [("T1048", None, "Exfiltration")]
    r = rows[0]
    assert (r["ts_ms"], r["last_ts_ms"], r["raw_alert_count"], r["dst_ip"], r["subject_host"]) == (
        T0, T0 + 10 * MIN, 3, "198.51.100.23", "ws-fin-010")


def test_exfil_49mb_silent(ev) -> None:
    assert run_template(ev(exfil_rows(49 * MB)), "exfil_volume") == []


def test_exfil_51mb_internal_silent(ev) -> None:
    assert run_template(ev(exfil_rows(51 * MB, dst="10.10.0.20")), "exfil_volume") == []


def test_exfil_51mb_spread_beyond_window_silent(ev) -> None:
    rows = [conn(T0 + i * 20 * MIN, "198.51.100.23", 17 * MB) for i in range(3)]  # 17 MB per 15-min window
    rows += [conn(T0 - (d + 1) * DAY, "203.0.113.99", MB) for d in range(5)]
    assert run_template(ev(rows), "exfil_volume") == []


@pytest.mark.xfail(strict=True, reason="BUG (BB-detect): exfil baseline includes the window under test, so a host "
                   "with no other external traffic has threshold 5 x its own exfil and can never fire (300 MB -> 0 "
                   "alerts). Remove this marker when fixed.")
def test_exfil_without_history_fires(ev) -> None:
    rows = [conn(T0 + i * 5 * MIN, "198.51.100.23", 100 * MB) for i in range(3)]  # 300 MB, first external traffic
    rows = run_template(ev(rows), "exfil_volume")
    assert [(r["raw_alert_count"], r["dst_ip"]) for r in rows] == [(3, "198.51.100.23")]


def test_exfil_below_host_baseline_multiple_silent(ev) -> None:
    # host routinely sends 20 MB/day to one external dst -> threshold 5 x 20 MB = 100 MB > 51 MB
    assert run_template(ev(exfil_rows(51 * MB, baseline=20 * MB)), "exfil_volume") == []


# ================================================================ beaconing (T1071.001)
def beacon(gaps_s: list[int], dst: str = "198.51.100.77") -> list[dict]:
    rows, t = [conn(T0, dst, 500, host="ws-hr-012", src="10.10.4.12")], T0
    for g in gaps_s:
        t += g * S
        rows.append(conn(t, dst, 500, host="ws-hr-012", src="10.10.4.12"))
    return rows


def test_beacon_cv_01_fires(ev) -> None:
    rows = run_template(ev(beacon([54, 66] * 5)), "beaconing")  # 11 conns, mean 60 s, sd 6 s -> CV 0.1
    assert labels(rows) == [("T1071", "T1071.001", "Command and Control")]
    r = rows[0]
    assert (r["raw_alert_count"], r["dst_ip"], r["subject_host"], r["ts_ms"]) == (11, "198.51.100.77",
                                                                                 "ws-hr-012", T0)


def test_beacon_cv_05_silent(ev) -> None:
    assert run_template(ev(beacon([30, 90] * 5)), "beaconing") == []  # mean 60 s, sd 30 s -> CV 0.5


def test_beacon_five_regular_conns_silent(ev) -> None:
    assert run_template(ev(beacon([60] * 4)), "beaconing") == []  # 5 < beacon_min_conns 6


# ================================================================ ransomware rename (T1486)
def renames(n: int, spacing_ms: int = 500) -> list[dict]:
    return [{"ts_ms": T0 + i * spacing_ms, "action": "file_rename", "host": "srv-file-01", "src_user": "svc_sql",
             "file_path": f"D:\\share\\f{i}.docx.locked", "file_ext": "locked"} for i in range(n)]


def test_rename_100_in_60s_fires(ev) -> None:
    rows = run_template(ev(renames(100)), "ransom_rename")
    assert labels(rows) == [("T1486", None, "Impact")]
    assert (rows[0]["raw_alert_count"], rows[0]["host"], rows[0]["src_user"]) == (100, "srv-file-01", "svc_sql")


def test_rename_99_silent(ev) -> None:
    assert run_template(ev(renames(99)), "ransom_rename") == []


def test_rename_100_over_120s_silent(ev) -> None:
    assert run_template(ev(renames(100, spacing_ms=1200)), "ransom_rename") == []  # <= 50 per 60 s


# ================================================================ new admin logon (T1021 / T1078)
def admin_logon(ts: int, lid: str, user: str = "svc_backup", host: str = "ws-fin-010", ip: str = "10.10.0.10",
                logon_type: int = 3) -> list[dict]:
    return [success(ts, user=user, host=host, ip=ip, logon_type=logon_type, logon_id=lid),
            priv(ts + 10, user, host, lid)]


def test_new_admin_first_seen_fires_t1021_002(ev) -> None:
    rows = run_template(ev(admin_logon(T0, "0x8a3f21")), "new_admin_logon")
    assert labels(rows) == [("T1021", "T1021.002", "Lateral Movement")]
    r = rows[0]
    assert (r["ts_ms"], r["host"], r["target_user"], r["src_ip"]) == (T0, "ws-fin-010", "svc_backup", "10.10.0.10")
    assert len(r["evidence_lines"]) == 2 and len(r["source_keys"]) == 2  # logon + 4672


def test_new_admin_routine_pair_silent(ev) -> None:
    rows = [x for d in range(3) for x in admin_logon(T0 + d * DAY, f"0x8a3f2{d}")]  # 3 privileged logons > 2
    assert run_template(ev(rows), "new_admin_logon") == []


def test_new_admin_rdp_is_t1021_001(ev) -> None:
    rows = run_template(ev(admin_logon(T0, "0x1111", logon_type=10)), "new_admin_logon")
    assert labels(rows) == [("T1021", "T1021.001", "Lateral Movement")]


def test_new_admin_external_source_is_t1078(ev) -> None:
    rows = run_template(ev(admin_logon(T0, "0x2222", ip="203.0.113.57")), "new_admin_logon")
    assert labels(rows) == [("T1078", None, "Initial Access")]


def test_new_admin_ssh_is_t1021_004(ev) -> None:
    rows = run_template(ev([success(T0, user="vreddy", host="srv-db-01", ip="10.10.0.30", logon_type=None,
                                    process_name="sshd", dst_port=22)]), "new_admin_logon")
    assert labels(rows) == [("T1021", "T1021.004", "Lateral Movement")]


@pytest.mark.parametrize("case", ["no_priv", "system_logon_id", "machine_account", "interactive"])
def test_new_admin_near_misses_silent(ev, case: str) -> None:
    if case == "no_priv":
        rows = [success(T0, user="svc_backup", host="ws-fin-010", ip="10.10.0.10", logon_id="0x8a3f21")]
    elif case == "system_logon_id":
        rows = admin_logon(T0, "0x3e7")
    elif case == "machine_account":
        rows = admin_logon(T0, "0x8a3f21", user="ws-fin-010$")
    else:
        rows = admin_logon(T0, "0x8a3f21", logon_type=2)
    assert run_template(ev(rows), "new_admin_logon") == []


def test_new_admin_business_hours_routine_suppressed(ev) -> None:
    cfg_th = detect.rules_and_thresholds(config.load_config())[1]
    if "new_admin_routine_min_logons" not in cfg_th:
        pytest.skip("routine suppression not configured")
    n = int(cfg_th["new_admin_routine_min_logons"])
    h0 = int(cfg_th["new_admin_business_hours_utc"][0])
    day = T0 - 2 * H  # 00:00Z
    plain = [success(day - (i + 1) * DAY + 9 * H, user="asharma", host="srv-dc-01", ip="10.10.1.5",
                     logon_type=3, logon_id=f"0x9{i}") for i in range(n)]
    inside = admin_logon(day + h0 * H + 30 * MIN, "0xabc1", user="asharma", host="srv-dc-01", ip="10.10.1.5")
    assert run_template(ev(plain + inside), "new_admin_logon") == []
    outside = admin_logon(day + 2 * H, "0xabc2", user="asharma", host="srv-dc-01", ip="10.10.1.5")
    rows = run_template(ev(plain + outside), "new_admin_logon")
    assert [r["ts_ms"] for r in rows] == [day + 2 * H]  # same routine pair, 02:00 UTC -> alert


# ================================================================ match rules
MATCH_CASES = [
    # (description, row, expected match rule ids)
    ("office spawns powershell", proc(T0, "powershell.exe", "powershell.exe -enc SQBFAFgA", "winword.exe"),
     {"office_spawns_script"}),
    ("encoded powershell", proc(T0, "powershell.exe", "powershell.exe -nop -enc SQBFAFgA"), {"encoded_powershell"}),
    ("plain powershell", proc(T0, "powershell.exe", "powershell.exe -nop Get-Date"), set()),
    ("office spawns printer helper", proc(T0, "splwow64.exe", "splwow64.exe 8192", "winword.exe"), set()),
    ("run key by powershell", {"ts_ms": T0, "action": "reg_set", "host": "ws-hr-012", "process_name": "powershell.exe",
                               "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"},
     {"run_key_persistence"}),
    ("run key by explorer", {"ts_ms": T0, "action": "reg_set", "host": "ws-hr-012", "process_name": "explorer.exe",
                             "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"}, set()),
    ("other key by powershell", {"ts_ms": T0, "action": "reg_set", "host": "ws-hr-012",
                                 "process_name": "powershell.exe",
                                 "registry_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\x"},
     set()),
    ("ioc ip", conn(T0, "198.51.100.23", 100), {"ioc_destination"}),
    ("ioc domain upper-case", {"ts_ms": T0, "action": "dns_query", "host": "ws-hr-012",
                               "dst_domain": "SUSPICIOUS-EXAMPLE-C2.INVALID"}, {"ioc_destination"}),
    ("benign ip", conn(T0, "52.1.2.3", 100), set()),
    ("ransom ext", {"ts_ms": T0, "action": "file_rename", "host": "srv-file-01", "file_ext": "locked"},
     {"ransom_extension"}),
    ("docx rename", {"ts_ms": T0, "action": "file_rename", "host": "srv-file-01", "file_ext": "docx"}, set()),
    ("net group", proc(T0, "net.exe", 'net group "domain admins" /domain'), {"discovery_commands"}),
    ("whoami", proc(T0, "whoami.exe", "whoami /all"), {"discovery_system"}),
    ("netstat", proc(T0, "netstat.exe", "netstat -ano"), set()),
    ("service", {"ts_ms": T0, "action": "service_installed", "event_id": 7045, "host": "srv-file-01"},
     {"service_or_task"}),
    ("task", {"ts_ms": T0, "action": "scheduled_task", "event_id": 4698, "host": "srv-file-01"},
     {"scheduled_task"}),
    ("log cleared", {"ts_ms": T0, "action": "log_cleared", "event_id": 1102, "host": "srv-dc-01"}, {"log_cleared"}),
    ("7z archive", proc(T0, "7z.exe", "7z a C:\\temp\\q3.7z C:\\finance"), {"archive_staging"}),
    ("7z extract", proc(T0, "7z.exe", "7z x C:\\temp\\setup.7z"), set()),
]


@pytest.mark.parametrize("desc,row,expected", MATCH_CASES, ids=[c[0] for c in MATCH_CASES])
def test_match_rule_fires_only_on_signal(ev, desc: str, row: dict, expected: set[str]) -> None:
    ctx = ev([row])
    cfg = ctx.cfg
    rules, th = detect.rules_and_thresholds(cfg)
    detect.build_match_hits(ctx.con, rules, cfg["ioc"], th)
    fired = set()
    for r in rules:
        if r["kind"] != "match":
            continue
        out = ctx.con.execute(detect.rule_sql(ctx.con, r, th)).fetchall()
        if out:
            assert len(out) == 1, (r["id"], out)
            fired.add(r["id"])
    assert fired == expected


def test_every_match_rule_has_a_positive_case() -> None:
    rules, _ = detect.rules_and_thresholds(config.load_config())
    covered = set().union(*(c[2] for c in MATCH_CASES))
    missing = {r["id"] for r in rules if r["kind"] == "match"} - covered
    assert not missing, f"match rules without a positive fixture: {sorted(missing)}"


def test_every_template_rule_has_tests() -> None:
    rules, _ = detect.rules_and_thresholds(config.load_config())
    tested = {"brute_force_then_success", "password_spray", "account_created_then_elevated", "exfil_volume",
              "beaconing", "ransom_rename", "new_admin_logon"}
    assert {r["template"] for r in rules if r["kind"] == "template"} <= tested


# ================================================================ full Stage 2: schema + evidence bounds
def run_stage2(ctx) -> list[dict]:
    lookups.run(ctx)
    detect.run(ctx)
    return query(ctx, f"SELECT * FROM read_parquet('{(ctx.work_dir / 'raw_alerts.parquet').as_posix()}') "
                      "ORDER BY rule_id, ts_ms, technique_id")


def test_raw_alerts_schema_and_evidence_bounds(tmp_path: Path) -> None:
    pad = "x" * 1000
    rows = [{**fail(T0 + i * S), "raw_line": f'{{"i":{i},"pad":"{pad}"}}'} for i in range(60)]
    rows += [{**proc(T0, "powershell.exe", "powershell.exe -enc " + "A" * 2000, "winword.exe"),
              "raw_line": "y" * 5000}]
    ctx = make_events_parquet(tmp_path, rows)
    try:
        alerts = run_stage2(ctx)
        desc = query(ctx, f"DESCRIBE SELECT * FROM read_parquet('"
                          f"{(ctx.work_dir / 'raw_alerts.parquet').as_posix()}')")
        assert [(d["column_name"], d["column_type"]) for d in desc] == RAW_ALERTS_SCHEMA
        assert {a["rule_id"] for a in alerts} == {"brute_force_then_success", "office_spawns_script"}
        for a in alerts:
            assert 1 <= len(a["evidence_lines"]) <= 3, a["rule_id"]
            assert all(len(x) <= 300 for x in a["evidence_lines"]), a["rule_id"]
            assert 1 <= len(a["source_keys"]) <= 50
            assert a["technique_name"], a["rule_id"]
        bf = next(a for a in alerts if a["rule_id"] == "brute_force_then_success")
        assert bf["raw_alert_count"] == 60 and len(bf["evidence_lines"]) == 3 and len(bf["source_keys"]) == 50
        assert bf["tactic_idx"] == 9  # Credential Access
    finally:
        ctx.con.close()


def test_detect_validate_names_bad_rule() -> None:
    cfg = config.load_config()
    detect.validate(cfg)  # the shipped config is valid
    bad = {**cfg, "rules": {**cfg["rules"], "rules": cfg["rules"]["rules"] + [
        {"id": "zz_bad", "kind": "match", "where": "no_such_column = 1", "technique": "T1082",
         "tactic": "Discovery", "severity": 10}]}}
    with pytest.raises(detect.RuleError, match="^zz_bad"):
        detect.validate(bad)


# ================================================================ CEF generator labels are never used
CEF_EVENT = ("rt=2026-10-24T02:50:00.000Z dvchost=WS-HR-012 suser=pmehta cat=process act=process_created "
             "externalId=8f0c0e3a-0000-4000-8000-0000000000{n:02d} dproc=powershell.exe "
             "cs1Label=cmdline cs1=powershell.exe -nop -enc SQBFAFgA")
CEF_BENIGN = ("rt=2026-10-24T02:51:00.000Z dvchost=SRV-DC-01 suser=rkumar cat=authentication act=user_logon "
              "externalId=8f0c0e3a-0000-4000-8000-0000000001{n:02d} src=203.0.113.57")


def _cef(labelled: bool) -> bytes:
    lines = []
    for n, (ext, tid, name) in enumerate([(CEF_EVENT, "T1059.001", "Office spawned script"),
                                          (CEF_BENIGN, "T1110", "High rate of failed logons")]):
        body = ext.format(n=n)
        if labelled:  # generator to_cef(): rule id/name/severity in the header, cs2=mitre technique
            hdr = f"CEF:0|Mitigata|SimEDR|1.0|{hashlib.md5(name.encode()).hexdigest()[:8]}|{name}|8|"
            body += f" cs2Label=mitre cs2={tid}"
        else:
            hdr = "CEF:0|Mitigata|SimEDR|1.0|event|event|0|"
        lines.append(hdr + body)
    return ("\n".join(lines) + "\n").encode()


def test_cef_label_fields_never_used(tmp_path: Path) -> None:
    out = {}
    for labelled in (True, False):
        tmp = tmp_path / ("lab" if labelled else "plain")
        (tmp / "raw").mkdir(parents=True)
        (tmp / "raw" / "edr.cef").write_bytes(_cef(labelled))
        ctx = run_ingest(tmp / "raw", tmp)
        try:
            alerts = run_stage2(ctx)
        finally:
            ctx.con.close()
        out[labelled] = [(a["rule_id"], a["technique_id"], a["sub_technique_id"], a["tactic"], a["ts_ms"],
                          a["host"], a["src_user"], a["target_user"]) for a in alerts]
    assert out[True] == out[False]
    assert out[False] == [("encoded_powershell", "T1059", "T1059.001", "Execution", 1792810200000, "ws-hr-012",
                           "pmehta", None)]


# ================================================================ episodes (Stage 2.5)
def _alert(ts: int, rule: str = "office_spawns_script", host: str = "ws-hr-012", src_user: str | None = "pmehta",
           target_user: str | None = None, n: int = 1, severity: int = 80, seq: int = 1,
           technique: str = "T1059", tactic: str = "Execution", src_ip: str | None = None) -> dict:
    return {"rule_id": rule, "technique_id": technique, "sub_technique_id": None, "technique_name": "x",
            "tactic": tactic, "tactic_idx": 4, "severity": severity, "ts_ms": ts, "last_ts_ms": ts + 100,
            "source_seq": seq, "host": host, "subject_host": host, "src_host": None, "dst_host": None,
            "src_user": src_user, "target_user": target_user, "src_ip": src_ip, "dst_ip": None,
            "raw_alert_count": n, "evidence_lines": [f"line{seq}a", f"line{seq}b"], "source_keys": [seq]}


def _write_alerts(ctx, alerts: list[dict]) -> None:
    con = ctx.con
    con.execute("CREATE OR REPLACE TEMP TABLE _ra (" + ", ".join(f"{c} {t}" for c, t in RAW_ALERTS_SCHEMA) + ")")
    con.executemany(f"INSERT INTO _ra VALUES ({', '.join('?' for _ in RAW_ALERTS_SCHEMA)})",
                    [[a[c] for c, _ in RAW_ALERTS_SCHEMA] for a in alerts])
    con.execute(f"COPY _ra TO '{(ctx.work_dir / 'raw_alerts.parquet').as_posix()}' (FORMAT PARQUET)")


def _episodes(ctx) -> list[dict]:
    return query(ctx, f"SELECT * FROM read_parquet('{(ctx.work_dir / 'episodes.parquet').as_posix()}') "
                      "ORDER BY ts_ms, episode_id")


def expected_episode_id(rule: str, sh: str, su: str | None, tu: str | None, dh: str | None, bucket: int,
                        tech: str) -> str:
    key = "|".join([rule, sh or "", su or "", tu or "", dh or "", str(bucket), tech])
    return "e" + hashlib.md5(key.encode()).hexdigest()[:10]


EPISODE_ALERTS = [
    _alert(T0 + 10 * S, n=1, seq=11), _alert(T0 + 1 * MIN, n=2, seq=12), _alert(T0 + 5 * MIN - 1, n=4, seq=13),
    _alert(T0 + 5 * MIN, n=1, seq=14),                              # next 5-min bucket
    _alert(T0 + 2 * MIN, src_user=None, target_user="jdoe", seq=15),  # other user, same bucket
]


def _episode_ctx(tmp: Path, alerts: list[dict]):
    ctx = make_events_parquet(tmp, [proc(T0, "a.exe", "a", host=f"h{i}") for i in range(4)])
    _write_alerts(ctx, alerts)
    return ctx


def test_episodes_bucket_merge_and_ids(tmp_path: Path) -> None:
    ctx = _episode_ctx(tmp_path, EPISODE_ALERTS)
    try:
        stats = episodes.run(ctx)
        eps = _episodes(ctx)
    finally:
        ctx.con.close()
    b0 = T0 // 300000
    assert stats["episodes"] == 3 and stats["spilled"] == 0
    got = [(e["episode_id"], e["ts_ms"], e["last_ts_ms"], e["merged_alert_count"], e["user"]) for e in eps]
    assert got == sorted([
        (expected_episode_id("office_spawns_script", "ws-hr-012", "pmehta", None, None, b0, "T1059"),
         T0 + 10 * S, T0 + 5 * MIN - 1 + 100, 7, "pmehta"),
        (expected_episode_id("office_spawns_script", "ws-hr-012", None, "jdoe", None, b0, "T1059"),
         T0 + 2 * MIN, T0 + 2 * MIN + 100, 1, "jdoe"),
        (expected_episode_id("office_spawns_script", "ws-hr-012", "pmehta", None, None, b0 + 1, "T1059"),
         T0 + 5 * MIN, T0 + 5 * MIN + 100, 1, "pmehta"),
    ], key=lambda x: (x[1], x[0]))
    first = eps[0]
    assert first["evidence_lines"] == ["line11a", "line11b", "line12a"]  # ordered by time, capped at 3
    assert first["source_seq"] == 11 and first["source_keys"] == [11, 12, 13]


def test_episode_ids_deterministic_across_runs(tmp_path: Path) -> None:
    ids = []
    for k in range(2):
        ctx = _episode_ctx(tmp_path / f"r{k}", list(reversed(EPISODE_ALERTS)) if k else EPISODE_ALERTS)
        try:
            episodes.run(ctx)
            ids.append([(e["episode_id"], e["merged_alert_count"]) for e in _episodes(ctx)])
        finally:
            ctx.con.close()
    assert ids[0] == ids[1] and len(ids[0]) == 3


def test_episode_spill_keeps_seed_neighbourhood(tmp_path: Path) -> None:
    alerts = [
        _alert(T0, severity=90, src_user="svc_backup", host="srv-dc-01", seq=1),                 # seed
        _alert(T0 + H, rule="discovery_system", severity=40, src_user="svc_backup", host="ws-fin-010",
               technique="T1082", tactic="Discovery", seq=2),                                    # 1 hop (user)
        _alert(T0 + 2 * H, rule="discovery_system", severity=40, src_user="kiyer", host="ws-it-003",
               technique="T1082", tactic="Discovery", seq=3),                                    # unrelated
    ]
    ctx = _episode_ctx(tmp_path, alerts)
    ctx.cfg["rules"]["thresholds"]["episode_cap"] = 2
    try:
        stats = episodes.run(ctx)
        kept = {e["src_user"] for e in _episodes(ctx)}
        spilled = query(ctx, f"SELECT src_user, is_seed FROM read_parquet('"
                             f"{(ctx.work_dir / 'episodes_spilled.parquet').as_posix()}')")
    finally:
        ctx.con.close()
    assert (stats["episodes"], stats["spilled"], stats["episodes_total"], stats["seeds"]) == (2, 1, 3, 1)
    assert kept == {"svc_backup"} and spilled == [{"src_user": "kiyer", "is_seed": False}]
