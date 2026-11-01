"""Windows endpoint round W (reports/ext/win_eval.md gaps): WMI child execution (T1047), EventLog service disabled
(T1685.001), COM hijacking (T1546.015), SDelete (T1070.004), PsExec-style remote service execution (T1569.002 +
T1021.002). One positive and near-miss negatives per rule; fixtures are hand-written canonical rows built from
ATT&CK / tool semantics, not copied from any dataset.

WIN_EXT_MATCH_RULES / WIN_EXT_TEMPLATES list the rules whose positive fixtures live here (for the coverage
meta-tests in test_detect.py)."""

from __future__ import annotations

import pytest

from attacklens import detect, detect_sql
from attacklens import detect_templates as T

from .conftest import make_events_parquet
from .test_detect import MIN, T0, ev, labels, proc, rule_of, run_stage2, th_of  # noqa: F401 (ev = fixture)

WIN_EXT_MATCH_RULES = {"eventlog_service_disabled", "com_hijack", "wmi_exec", "indicator_removal_files"}
WIN_EXT_TEMPLATES = {"remote_service_exec"}

CLSID = "{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}"
SID = "S-1-5-21-1111111111-2222222222-3333333333-1104"
EVTLOG_START = r"HKLM\System\CurrentControlSet\Services\EventLog\Start"


def reg(ts: int, path: str, name: str = "powershell.exe", event_id: int = 13, action: str = "reg_set") -> dict:
    return {"ts_ms": ts, "action": action, "event_id": event_id, "host": "ws-hr-012", "process_name": name,
            "registry_path": path}


def block(ts: int, text: str, event_id: int = 4104) -> dict:
    """PowerShell/Operational script block: action stays 'other', the text is in command_line."""
    return {"ts_ms": ts, "action": "other", "event_id": event_id, "host": "ws-hr-012", "src_user": "pmehta",
            "command_line": text}


def wmi_child(name: str, user: str | None = "pmehta", is_machine: bool | None = None,
              parent: str = "wmiprvse.exe") -> dict:
    return {**proc(T0, name, rf"C:\Users\Public\{name}", parent), "src_user": user, "is_machine": is_machine}


# ================================================================ match rules
WIN_CASES = [
    # wmi_exec (T1047): any non-provider child of wmiprvse.exe
    ("implant under wmiprvse", wmi_child("grunthttp.exe"), {"wmi_exec"}),
    ("pwsh under wmiprvse", wmi_child("pwsh.exe"), {"wmi_exec"}),
    ("werfault under wmiprvse", wmi_child("werfault.exe"), set()),
    ("mofcomp under wmiprvse", wmi_child("mofcomp.exe"), set()),
    ("child as system", wmi_child("grunthttp.exe", user="system"), set()),
    ("child as network service", wmi_child("grunthttp.exe", user="network service"), set()),
    ("child as machine account", wmi_child("grunthttp.exe", user="ws-hr-012$", is_machine=True), set()),
    ("implant under explorer", wmi_child("grunthttp.exe", parent="explorer.exe"), set()),
    ("wmiprvse child no image", {**wmi_child("x.exe"), "process_name": None}, set()),
    # eventlog_service_disabled (T1685.001)
    ("reg EventLog Start", reg(T0, EVTLOG_START, "services.exe"), {"eventlog_service_disabled"}),
    ("reg EventLog Start ControlSet001", reg(T0, r"HKLM\SYSTEM\ControlSet001\Services\EventLog\Start"),
     {"eventlog_service_disabled"}),
    ("sc config eventlog disabled", proc(T0, "sc.exe", "sc config eventlog start= disabled", "cmd.exe"),
     {"eventlog_service_disabled"}),
    ("sc.exe config remote", proc(T0, "sc.exe", r'"C:\Windows\System32\sc.exe" \\ws-fin-010 config EventLog '
                                                r"start=disabled", "cmd.exe"), {"eventlog_service_disabled"}),
    ("net stop eventlog", proc(T0, "net.exe", "net stop eventlog /y", "cmd.exe"), {"eventlog_service_disabled"}),
    ("ps set-service disabled", proc(T0, "powershell.exe",
                                     "powershell.exe -c Set-Service -Name EventLog -StartupType Disabled"),
     {"eventlog_service_disabled"}),
    ("script block set-service", block(T0, "Set-Service -StartupType Disabled -Name 'EventLog'"),
     {"eventlog_service_disabled"}),
    ("script block stop-service", block(T0, "Stop-Service -Name eventlog -Force", 4103),
     {"eventlog_service_disabled"}),
    ("reg add start 4", proc(T0, "reg.exe", r"reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog /v Start "
                                           r"/t REG_DWORD /d 4 /f", "cmd.exe"), {"eventlog_service_disabled"}),
    ("set-itemproperty start 4", block(T0, r"Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\EventLog"
                                           r" -Name Start -Value 4"), {"eventlog_service_disabled"}),
    ("reg EventLog source key", reg(T0, r"HKLM\System\CurrentControlSet\Services\EventLog\Application\MyApp"
                                        r"\EventMessageFile"), set()),
    ("reg Spooler Start", reg(T0, r"HKLM\System\CurrentControlSet\Services\Spooler\Start"), set()),
    ("sc query eventlog", proc(T0, "sc.exe", "sc query eventlog", "cmd.exe"), set()),
    ("sc config spooler disabled", proc(T0, "sc.exe", "sc config spooler start= disabled", "cmd.exe"), set()),
    ("set-service eventlog automatic", block(T0, "Set-Service -Name EventLog -StartupType Automatic"), set()),
    ("get-eventlog block", block(T0, "Get-EventLog -LogName Security -Newest 5; Stop-Service spooler"), set()),
    ("reg add eventlog start 2", proc(T0, "reg.exe", r"reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog "
                                                    r"/v Start /t REG_DWORD /d 2 /f", "cmd.exe"), set()),
    ("eventlog text on other row", {**block(T0, "sc config eventlog start= disabled"), "event_id": 4100}, set()),
    # com_hijack (T1546.015)
    ("hku classes inproc", reg(T0, rf"HKU\{SID}_Classes\CLSID\{CLSID}\InprocServer32\(Default)"), {"com_hijack"}),
    ("hkcu localserver by reg", reg(T0, rf"HKCU\Software\Classes\CLSID\{CLSID}\LocalServer32", "reg.exe"),
     {"com_hijack"}),
    ("sysmon 12 create key", reg(T0, rf"HKU\{SID}\Software\Classes\CLSID\{CLSID}\InprocServer32", "rundll32.exe",
                                 event_id=12, action="other"), {"com_hijack"}),
    ("hklm machine-wide clsid", reg(T0, rf"HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32\(Default)"), set()),
    ("hkcu clsid defaulticon", reg(T0, rf"HKCU\Software\Classes\CLSID\{CLSID}\DefaultIcon\(Default)"), set()),
    ("onedrive per-user com", reg(T0, rf"HKU\{SID}_Classes\CLSID\{CLSID}\InprocServer32\(Default)", "OneDrive.exe"),
     set()),
    ("event 12 not other", reg(T0, rf"HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32", event_id=12,
                               action="proc_start"), set()),
    # indicator_removal_files + SDelete (T1070.004)
    ("sdelete64 image", proc(T0, "sdelete64.exe", r"sdelete64.exe -accepteula C:\Users\x\Draft.zip", "cmd.exe"),
     {"indicator_removal_files"}),
    ("sdelete in command line", proc(T0, "cmd.exe", r'cmd.exe /c "C:\tools\sdelete.exe" -q C:\temp\a.rar'),
     {"indicator_removal_files"}),
    ("renamed sdelete", proc(T0, "svcupd.exe", r"svcupd.exe -accepteula -p 3 -s C:\Users\x\Downloads", "cmd.exe"),
     {"indicator_removal_files"}),
    ("psexec accepteula s", proc(T0, "psexec.exe", r"psexec.exe -accepteula -s \\ws-fin-010 cmd.exe", "cmd.exe"),
     set()),
    ("renamed psexec with password", proc(T0, "x.exe", r"x.exe \\ws-fin-010 -accepteula -u corp\adm -p 12 cmd.exe",
                                          "cmd.exe"), set()),
    ("sdelete notes file", proc(T0, "notepad.exe", r"notepad.exe C:\docs\sdelete_notes.txt"), set()),
]


@pytest.fixture(scope="module")
def fired(tmp_path_factory: pytest.TempPathFactory) -> dict[str, set[str]]:
    """All cases in ONE events set (distinct source_seq); every match rule's real rule_sql() is run once and its hits
    are attributed back to the case by source_seq (match rules are row-local)."""
    assert len({c[0] for c in WIN_CASES}) == len(WIN_CASES), "case names must be unique"
    rows = [{**row, "source_seq": 5000 + k} for k, (_, row, _) in enumerate(WIN_CASES)]
    ctx = make_events_parquet(tmp_path_factory.mktemp("wx"), rows)
    try:
        detect_sql.prepare(ctx.con, ctx.cfg)
        rules, th = detect.rules_and_thresholds(ctx.cfg)
        detect.build_match_hits(ctx.con, rules, ctx.cfg["ioc"], th)
        out: dict[str, set[str]] = {c[0]: set() for c in WIN_CASES}
        for r in rules:
            if r["kind"] != "match":
                continue
            seqs = [x[0] for x in ctx.con.execute(f"SELECT source_seq FROM ({detect.rule_sql(ctx.con, r, th)})")
                    .fetchall()]
            assert len(seqs) == len(set(seqs)), (r["id"], seqs)
            for s in seqs:
                out[WIN_CASES[int(s) - 5000][0]].add(r["id"])
    finally:
        ctx.con.close()
    return out


@pytest.mark.parametrize("desc,row,expected", WIN_CASES, ids=[c[0] for c in WIN_CASES])
def test_win_match_rule_fires_only_on_signal(fired, desc: str, row: dict, expected: set[str]) -> None:
    assert fired[desc] == expected


def test_win_rule_labels(ev) -> None:
    ctx = ev([proc(T0, "x", "x")])
    want = {"eventlog_service_disabled": ("T1685", "T1685.001", "Defense Impairment", 80),
            "com_hijack": ("T1546", "T1546.015", "Persistence", 75),
            "wmi_exec": ("T1047", None, "Execution", 70),
            "indicator_removal_files": ("T1070", "T1070.004", "Defense Impairment", 70),
            "remote_service_exec": ("T1569", "T1569.002", "Execution", 75)}
    for rid, (tech, sub, tactic, sev) in want.items():
        r = rule_of(ctx.cfg, rid)
        assert (r["technique"], r.get("sub_technique"), r["tactic"], r["severity"]) == (tech, sub, tactic, sev), rid
    sec = rule_of(ctx.cfg, "remote_service_exec")["secondary"]
    assert (sec["technique"], sec["sub_technique"], sec["tactic"]) == ("T1021", "T1021.002", "Lateral Movement")


# ================================================================ remote_service_exec (template)
HOST, SRC = "ws-fin-010", "10.10.3.15"


def svc(ts: int, name: str, image: str | None, event_id: int = 7045, host: str = HOST) -> dict:
    return {"ts_ms": ts, "action": "service_installed", "event_id": event_id, "host": host, "service_name": name,
            "process_path": image}


def svc_child(ts: int, path: str, parent: str = "services.exe") -> dict:
    name = path.rsplit("\\", 1)[-1].lower()
    return {"ts_ms": ts, "action": "proc_start", "event_id": 1, "host": HOST, "src_user": "system",
            "process_name": name, "process_path": path, "parent_process": parent, "command_line": path}


def logon(ts: int, user: str = "jdoe", ip: str = SRC, host: str = HOST, logon_type: int = 3,
          is_machine: bool = False) -> dict:
    return {"ts_ms": ts, "action": "login_success", "outcome": "success", "event_id": 4624, "logon_type": logon_type,
            "host": host, "target_user": user, "src_ip": ip, "is_machine": is_machine}


def run_rse(ctx) -> list[dict]:
    rule = rule_of(ctx.cfg, "remote_service_exec")
    sql = T.TEMPLATES[rule["template"]](ctx.con, rule, th_of(ctx.cfg))
    cur = ctx.con.execute(sql + " ORDER BY ts_ms, technique_id")
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


PRIMARY = ("T1569", "T1569.002", "Execution")
SECONDARY = ("T1021", "T1021.002", "Lateral Movement")


def test_rse_psexesvc_after_network_logon_emits_both(ev) -> None:
    rows = run_rse(ev([logon(T0 - 2000), svc(T0, "PSEXESVC", r"%SystemRoot%\PSEXESVC.exe")]))
    assert labels(rows) == [SECONDARY, PRIMARY]
    for r in rows:
        assert (r["ts_ms"], r["host"], r["subject_host"], r["target_user"], r["src_ip"]) == (T0, HOST, HOST, "jdoe",
                                                                                              SRC)
        assert len(r["evidence_lines"]) == 2 and len(r["source_keys"]) == 2 and r["raw_alert_count"] == 1
        assert all(len(x) <= 301 for x in r["evidence_lines"])


@pytest.mark.parametrize("image", [r"%SystemRoot%\kXbQmTzA.exe", r"C:\Windows\a1b2c3d4.exe",
                                   r"\\10.10.3.15\ADMIN$\beacon.exe",
                                   r"%COMSPEC% /Q /c echo whoami ^> \\127.0.0.1\C$\__output 2^>^&1 > x.bat",
                                   r"C:\Windows\System32\cmd.exe /c start /b powershell -noP -sta -w 1 -enc SQBFAFgA"])
def test_rse_remote_exec_service_images(ev, image: str) -> None:
    rows = run_rse(ev([svc(T0, "Updater", image)]))
    assert labels(rows) == [PRIMARY]
    assert rows[0]["target_user"] is None and len(rows[0]["evidence_lines"]) == 1


def test_rse_4697_name_only(ev) -> None:
    assert labels(run_rse(ev([svc(T0, "psexesvc", None, event_id=4697)]))) == [PRIMARY]


@pytest.mark.parametrize("path", [r"C:\Windows\PSEXESVC.exe", r"C:\Windows\x7Gq2.exe",
                                  r"C:\Windows\System32\cmd.exe"])
def test_rse_services_child(ev, path: str) -> None:
    assert labels(run_rse(ev([svc_child(T0, path)]))) == [PRIMARY]


@pytest.mark.parametrize("row", [
    svc(T0, "javamtsup", r"C:\Windows\System32\javamtsup.exe"),           # ordinary service (service_or_task)
    svc(T0, "FooSvc", r'"C:\Program Files\Foo\foo.exe" -service'),
    svc(T0, "upd_helper", r"C:\Windows\Temp\upd.exe"),                     # not the ADMIN$ root
    svc_child(T0, r"C:\Windows\System32\svchost.exe"),
    svc_child(T0, r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"),
    svc_child(T0, r"C:\Windows\PSEXESVC.exe", parent="explorer.exe"),
], ids=["system32 service", "program files", "windows temp", "svchost", "msmpeng", "not under services"])
def test_rse_near_misses(ev, row: dict) -> None:
    assert run_rse(ev([row])) == []


@pytest.mark.parametrize("lg", [logon(T0 - 6 * MIN), logon(T0 - 2000, ip="127.0.0.1"),
                                logon(T0 - 2000, user="ws-dc-01$", is_machine=True),
                                logon(T0 - 2000, user="anonymous logon"),
                                logon(T0 - 2000, host="ws-hr-012"), logon(T0 - 2000, logon_type=10),
                                logon(T0 + 2000)],
                         ids=["6 min before", "loopback", "machine account", "anonymous", "other host", "rdp type 10",
                              "after"])
def test_rse_logon_near_misses_primary_only(ev, lg: dict) -> None:
    rows = run_rse(ev([lg, svc(T0, "PSEXESVC", r"%SystemRoot%\PSEXESVC.exe")]))
    assert labels(rows) == [PRIMARY] and rows[0]["target_user"] is None


def test_rse_latest_logon_in_window_wins(ev) -> None:
    rows = run_rse(ev([logon(T0 - 4 * MIN, user="asharma", ip="10.10.3.16"), logon(T0 - MIN),
                       svc(T0, "PSEXESVC", r"%SystemRoot%\PSEXESVC.exe")]))
    assert [(r["target_user"], r["src_ip"]) for r in rows] == [("jdoe", SRC)] * 2


def test_rse_runs_in_stage2(tmp_path) -> None:
    """The real detect.run path (validate + every rule) with the new rules, and per-rule counts."""
    rows = [logon(T0 - 2000), svc(T0, "PSEXESVC", r"%SystemRoot%\PSEXESVC.exe"),
            reg(T0 + MIN, EVTLOG_START), reg(T0 + MIN, rf"HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32")]
    ctx = make_events_parquet(tmp_path, rows)
    try:
        alerts = run_stage2(ctx)
    finally:
        ctx.con.close()
    got = sorted((a["rule_id"], a["technique_id"]) for a in alerts
                 if a["rule_id"] in WIN_EXT_MATCH_RULES | WIN_EXT_TEMPLATES)
    assert got == [("com_hijack", "T1546"), ("eventlog_service_disabled", "T1685"),
                   ("remote_service_exec", "T1021"), ("remote_service_exec", "T1569")]
