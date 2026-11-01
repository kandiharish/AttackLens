"""JSON source pack (reports/robust/SUMMARY.md items 8, 12, 21): EDR / IDS / journal JSON sources, Windows JSON
alias shapes (evtx_dump, Velociraptor, Get-WinEvent, UserData, ::ffff:) and the ECS action vocabulary.

One hand-written line per source / shape (invented values: example hosts, documentation IPs). Expected epoch ms are
computed from ISO strings in UTC.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from attacklens import db, ingest, profile
from attacklens.ingest_maps import ts_value_sql

from .conftest import _new_ctx, accounting, query


def ms(iso: str) -> int:
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp() * 1000)


T0 = "2026-10-30T10:15:02.123Z"
E0 = ms(T0)

LINES: dict[str, dict[str, Any]] = {
    "mde_stream.json": {"time": "2026-10-30T10:15:05.1230000Z", "category": "AdvancedHunting-DeviceProcessEvents",
                        "properties": {"Timestamp": "2026-10-30T10:15:02.1230000Z", "DeviceId": "00c3",
                                       "DeviceName": "ws-fin-010.corp.example.com", "ActionType": "ProcessCreated",
                                       "FileName": "powershell.exe",
                                       "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                       "ProcessCommandLine": "powershell.exe -nop -enc SQBFAFgA",
                                       "AccountName": "alice", "InitiatingProcessFileName": "WINWORD.EXE"}},
    "mde_flat.json": {"Timestamp": "2026-10-30T10:15:03.123Z", "DeviceId": "00c3", "DeviceName": "ws-fin-010",
                      "ActionType": "ConnectionSuccess", "RemoteIP": "203.0.113.57", "RemotePort": 443,
                      "LocalIP": "192.0.2.10", "LocalPort": 50112, "RemoteUrl": "evil.example.net",
                      "InitiatingProcessFileName": "powershell.exe", "InitiatingProcessAccountName": "alice"},
    "fdr.json": {"aid": "4f2c9e1a", "aip": "198.51.100.20", "cid": "c0ff", "event_simpleName": "ProcessRollup2",
                 "timestamp": "1793355309999", "ContextTimeStamp": "1793355302.123", "ComputerName": "WS-FIN-010",
                 "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
                 "CommandLine": "cmd.exe /c whoami /all", "ParentBaseFileName": "powershell.exe", "UserName": "alice"},
    "s1_dv.json": {"agentName": "WS-FIN-010", "agentUuid": "b7a9", "eventTime": T0, "createdAt": "2026-10-30T10:15:11Z",
                   "eventType": "Process Creation", "srcProcName": "winword.exe", "srcProcUser": "CORP\\alice",
                   "tgtProcName": "powershell.exe", "tgtProcImagePath": "C:\\Windows\\powershell.exe",
                   "tgtProcCmdLine": "powershell.exe -nop", "tgtProcUser": "CORP\\alice"},
    "s1_cf.json": {"event.time": E0 + 1000, "endpoint.name": "WS-FIN-010", "agent.uuid": "b7a9",
                   "event.type": "IP Connect", "src.process.name": "powershell.exe",
                   "src.process.user": "CORP\\alice", "dst.ip.address": "203.0.113.57", "dst.port.number": 443,
                   "src.ip.address": "192.0.2.10"},
    "eve.json": {"timestamp": "2026-10-31T15:30:00.123456+0530", "flow_id": 18765, "event_type": "alert",
                 "src_ip": "203.0.113.66", "src_port": 51520, "dest_ip": "192.0.2.20", "dest_port": 80, "proto": "TCP",
                 "alert": {"action": "blocked", "signature_id": 2034647, "signature": "ET EXPLOIT log4j", "severity": 1},
                 "http": {"hostname": "www.example.com", "url": "/index.php"}, "app_proto": "http", "host": "sensor01"},
    "eve_dns.json": {"timestamp": "2026-10-31T10:01:00.000000+0000", "flow_id": 2, "event_type": "dns",
                     "src_ip": "192.0.2.10", "src_port": 53001, "dest_ip": "198.51.100.53", "dest_port": 53,
                     "dns": {"version": 3, "type": "request", "queries": [{"rrname": "x.exfil.example.net"}]}},
    "zeek_conn.log": {"ts": 1793440800.123456, "uid": "CHhAv", "id.orig_h": "192.0.2.10", "id.orig_p": 51000,
                      "id.resp_h": "203.0.113.50", "id.resp_p": 443, "proto": "tcp", "service": "ssl",
                      "orig_bytes": 5120, "resp_bytes": 3920, "conn_state": "SF"},
    "zeek_dns.log": {"ts": 1793440860.0, "uid": "C4J4T", "id.orig_h": "192.0.2.10", "id.orig_p": 53000,
                     "id.resp_h": "198.51.100.53", "id.resp_p": 53, "proto": "udp", "query": "www.example.com",
                     "qtype_name": "A", "rcode_name": "NOERROR"},
    "zeek_http.log": {"ts": "2026-10-31T10:00:00.123456Z", "uid": "CHhAx", "id.orig_h": "192.0.2.10",
                      "id.orig_p": 51001, "id.resp_h": "203.0.113.51", "id.resp_p": 80, "method": "GET",
                      "host": "www.example.com", "uri": "/a.exe", "request_body_len": 0, "response_body_len": 5120},
    "journal.json": {"__CURSOR": "s=0f1e", "__REALTIME_TIMESTAMP": "1793348102003000", "_HOSTNAME": "web01",
                     "SYSLOG_IDENTIFIER": "sshd", "_COMM": "sshd", "_EXE": "/usr/sbin/sshd",
                     "_SOURCE_REALTIME_TIMESTAMP": "1793348102002880",
                     "MESSAGE": "Failed password for root from 203.0.113.57 port 50122 ssh2"},
    "rsyslog.json": {"msg": "Accepted password for alice", "timereported": "2026-10-30T08:16:00.000+00:00",
                     "hostname": "web01", "syslogtag": "sshd[2220]:", "programname": "sshd"},
    "rsyslog_elk.json": {"@timestamp": "2026-10-30T08:15:02.003+00:00", "@version": "1", "message": " Failed",
                         "sysloghost": "web01", "host": {"ip": "10.0.0.5"}, "programname": "sshd"},
    # ---- item 12: Windows JSON shapes ----
    "evtx_dump.json": {"Event": {"#attributes": {"xmlns": "x"}, "System": {
        "Provider": {"#attributes": {"Name": "Service Control Manager"}},
        "EventID": {"#attributes": {"Qualifiers": 16384}, "#text": 7045},
        "TimeCreated": {"#attributes": {"SystemTime": "2026-10-31T09:15:01.123456Z"}},
        "Channel": "System", "Computer": "SRV-DB-02.corp.example.com"},
        "EventData": {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe"}}},
    "velo.json": {"System": {"Provider": {"Name": "Microsoft-Windows-Security-Auditing"}, "EventID": {"Value": 4688},
                             "TimeCreated": {"SystemTime": 1793438103.123456}, "Channel": "Security",
                             "Computer": "WS-FIN-010.corp.example.com"},
                  "EventData": {"SubjectUserName": "alice", "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                                "ParentProcessName": "C:\\Windows\\explorer.exe", "CommandLine": "cmd.exe /c ver"}},
    "getwinevent.json": {"Id": 4624, "ProviderName": "Microsoft-Windows-Security-Auditing", "LogName": "Security",
                         "MachineName": "WS-FIN-010.corp.example.com", "TimeCreated": "/Date(1793438101123)/",
                         "Properties": [{"Value": v} for v in [
                             "S-1-5-18", "WS-FIN-010$", "CORP", "0x3e7", "S-1-5-21-1", "alice", "CORP", "0x8a3f21",
                             "3", "NtLmSsp ", "NTLM", "ATTACKER1", "{0}", "-", "NTLM V2", "128", "0x0", "-",
                             "203.0.113.57", "49712"]]},
    "win_1102.json": {"Event": {"System": {"EventID": 1102, "Channel": "Security", "Computer": "DC01.corp.example.com",
                                           "TimeCreated": {"SystemTime": "2026-10-31T09:20:00Z"}},
                                "UserData": {"LogFileCleared": {"SubjectUserName": "mallory"}}}},
    "win_4769.json": {"EventID": 4769, "Channel": "Security", "Computer": "DC01.corp.example.com",
                      "TimeCreated": "2026-10-31T09:21:00Z", "TargetUserName": "alice@CORP.EXAMPLE.COM",
                      "ServiceName": "MSSQLSvc", "TicketEncryptionType": "0x17", "IpAddress": "::ffff:198.51.100.23"},
    # ---- item 21: ECS action vocabulary ----
    "elastic_defend.ndjson": {"@timestamp": "2026-10-30T10:16:00.000Z", "ecs": {"version": "8.11.0"},
                              "agent": {"type": "endpoint"}, "host": {"name": "ws-fin-011"}, "user": {"name": "bob"},
                              "event": {"category": ["process"], "type": ["start"], "action": "start"},
                              "process": {"name": "rundll32.exe", "executable": "C:\\Windows\\System32\\rundll32.exe",
                                          "command_line": "rundll32.exe comsvcs.dll, MiniDump 624 l.dmp full",
                                          "parent": {"name": "cmd.exe"}}},
    "elastic_dns.ndjson": {"@timestamp": "2026-10-30T10:16:05.000Z", "ecs": {"version": "8.11.0"},
                           "host": {"name": "ws-fin-011"}, "user": {"name": "bob"},
                           "event": {"category": ["network"], "type": ["protocol", "info"],
                                     "action": "lookup_requested"},
                           "dns": {"question": {"name": "update.evil-cdn.example.net"}}},
    "auditbeat.ndjson": {"@timestamp": "2026-10-30T08:17:12.003Z", "ecs": {"version": "8.0.0"},
                         "event": {"category": ["process"], "action": "executed", "outcome": "success"},
                         "host": {"name": "web02"}, "user": {"name": "root", "audit": {"name": "carol"}},
                         "process": {"name": "cat", "executable": "/usr/bin/cat", "args": ["cat", "/etc/shadow"],
                                     "title": "cat /etc/shadow"}},
    "auditbeat_login.ndjson": {"@timestamp": "2026-10-30T08:15:03.100Z", "ecs": {"version": "8.0.0"},
                               "event": {"category": ["authentication"], "action": "logged-in", "outcome": "failure"},
                               "host": {"name": "web02"}, "user": {"name": "root"}, "source": {"ip": "203.0.113.58"},
                               "process": {"executable": "/usr/sbin/sshd"}},
    "auditbeat_sys.ndjson": {"@timestamp": "2026-10-30T08:15:04.000Z", "ecs": {"version": "8.0.0"},
                             "event": {"module": "system", "action": "user_login", "outcome": "failure"},
                             "host": {"name": "web03"}, "user": {"name": "admin"}, "source": {"ip": "203.0.113.59"}},
}


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("jsonpack")
    raw = tmp / "raw"
    raw.mkdir()
    for name, obj in LINES.items():
        (raw / name).write_text(json.dumps(obj) + "\n", encoding="utf-8")
    c = _new_ctx(tmp, raw_dir=raw)
    profile.run(c)
    ingest.run(c)
    db.register_events(c.con, c.events_glob)
    yield c
    c.con.close()


def one(ctx, where: str) -> dict[str, Any]:
    rows = query(ctx, f"SELECT * FROM events WHERE {where}")
    assert len(rows) == 1, f"expected 1 row for {where}, got {len(rows)}"
    return rows[0]


def _src(ctx, rel: str) -> str | None:
    prof = json.loads((Path(ctx.out_dir) / "source_profile.json").read_text(encoding="utf-8"))
    return next(f.get("source_type") for f in prof["files"] if f["rel"] == rel)


@pytest.mark.parametrize("rel,stype", [
    ("mde_stream.json", "mde_json"), ("mde_flat.json", "mde_json"), ("fdr.json", "crowdstrike_fdr_json"),
    ("s1_dv.json", "sentinelone_json"), ("s1_cf.json", "sentinelone_json"), ("eve.json", "suricata_eve_json"),
    ("eve_dns.json", "suricata_eve_json"), ("zeek_conn.log", "zeek_json"), ("zeek_dns.log", "zeek_json"),
    ("zeek_http.log", "zeek_json"), ("journal.json", "journald_json"), ("rsyslog.json", "rsyslog_json"),
    ("rsyslog_elk.json", "rsyslog_json"), ("evtx_dump.json", "win_json"), ("velo.json", "win_json"),
    ("getwinevent.json", "win_json"), ("win_1102.json", "win_json"), ("win_4769.json", "win_json"),
    ("elastic_defend.ndjson", "ecs_json"), ("auditbeat.ndjson", "ecs_json"), ("auditbeat_sys.ndjson", "ecs_json"),
])
def test_routing(ctx, rel: str, stype: str) -> None:
    assert _src(ctx, rel) == stype


def test_accounting_no_loss(ctx) -> None:
    acc = accounting(ctx)
    assert "unrecognized" not in acc or acc["unrecognized"]["rows_in"] == 0
    assert sum(a["rows_in"] for a in acc.values()) == len(LINES)
    assert sum(a["dropped"] for a in acc.values()) == 0
    assert query(ctx, "SELECT count(*) n FROM events WHERE NOT ts_ok")[0]["n"] == 0


def test_mde_streaming(ctx) -> None:
    r = one(ctx, "source_type = 'mde_json' AND action = 'proc_start'")
    assert r["ts_ms"] == ms("2026-10-30T10:15:02.123Z")
    assert (r["host"], r["src_user"], r["process_name"], r["parent_process"]) == (
        "ws-fin-010.corp.example.com", "alice", "powershell.exe", "winword.exe")
    assert r["command_line"] == "powershell.exe -nop -enc SQBFAFgA"


def test_mde_flat_network(ctx) -> None:
    r = one(ctx, "source_type = 'mde_json' AND action = 'conn_out'")
    assert r["ts_ms"] == ms("2026-10-30T10:15:03.123Z")
    assert (r["dst_ip"], r["dst_port"], r["src_ip"], r["dst_domain"]) == ("203.0.113.57", 443, "192.0.2.10",
                                                                          "evil.example.net")
    assert (r["process_name"], r["src_user"]) == ("powershell.exe", "alice")


def test_crowdstrike_fdr(ctx) -> None:
    r = one(ctx, "source_type = 'crowdstrike_fdr_json'")
    assert r["ts_ms"] == 1793355302123            # ContextTimeStamp (endpoint), not the receipt `timestamp`
    assert (r["action"], r["host"], r["host_ip"], r["src_user"]) == ("proc_start", "ws-fin-010", "198.51.100.20",
                                                                     "alice")
    assert (r["process_name"], r["parent_process"], r["command_line"]) == ("cmd.exe", "powershell.exe",
                                                                           "cmd.exe /c whoami /all")


def test_sentinelone_dv_and_cloud_funnel(ctx) -> None:
    r = one(ctx, "source_type = 'sentinelone_json' AND action = 'proc_start'")
    assert r["ts_ms"] == E0
    assert (r["host"], r["src_user"], r["process_name"], r["parent_process"], r["command_line"]) == (
        "ws-fin-010", "alice", "powershell.exe", "winword.exe", "powershell.exe -nop")
    c = one(ctx, "source_type = 'sentinelone_json' AND action = 'conn_out'")
    assert c["ts_ms"] == E0 + 1000
    assert (c["dst_ip"], c["dst_port"], c["process_name"], c["src_user"]) == ("203.0.113.57", 443, "powershell.exe",
                                                                              "alice")


def test_suricata_alert_and_dns(ctx) -> None:
    a = one(ctx, "source_type = 'suricata_eve_json' AND action = 'ips_alert'")
    assert a["ts_ms"] == ms("2026-10-31T10:00:00.123Z")    # +0530 offset honoured
    assert (a["src_ip"], a["dst_ip"], a["dst_port"], a["outcome"], a["signature"], a["vendor_severity"]) == (
        "203.0.113.66", "192.0.2.20", 80, "blocked", "ET EXPLOIT log4j", "1")
    assert (a["host"], a["dst_domain"], a["file_path"], a["app"]) == ("sensor01", "www.example.com", "/index.php",
                                                                      "http")
    d = one(ctx, "source_type = 'suricata_eve_json' AND action = 'dns_query'")
    assert (d["ts_ms"], d["dst_domain"]) == (ms("2026-10-31T10:01:00Z"), "x.exfil.example.net")


def test_zeek(ctx) -> None:
    c = one(ctx, "source_type = 'zeek_json' AND action = 'conn_out'")
    assert c["ts_ms"] == 1793440800123
    assert (c["src_ip"], c["src_port"], c["dst_ip"], c["dst_port"], c["bytes_out"], c["bytes_in"], c["app"]) == (
        "192.0.2.10", 51000, "203.0.113.50", 443, 5120, 3920, "ssl")
    d = one(ctx, "source_type = 'zeek_json' AND action = 'dns_query'")
    assert (d["ts_ms"], d["dst_domain"], d["outcome"]) == (1793440860000, "www.example.com", None)
    h = one(ctx, "source_type = 'zeek_json' AND action = 'web_access'")
    assert (h["ts_ms"], h["dst_domain"], h["file_path"], h["dst_port"]) == (ms("2026-10-31T10:00:00.123Z"),
                                                                            "www.example.com", "/a.exe", 80)


def test_journald_epoch_us(ctx) -> None:
    r = one(ctx, "source_type = 'journald_json'")
    assert r["ts_ms"] == 1793348102002                     # _SOURCE_REALTIME_TIMESTAMP us -> ms
    assert (r["host"], r["process_name"], r["process_path"], r["action"]) == ("web01", "sshd", "/usr/sbin/sshd",
                                                                              "other")


def test_rsyslog_json(ctx) -> None:
    r = one(ctx, "source_type = 'rsyslog_json' AND host = 'web01' AND ts_ms = %d" % ms("2026-10-30T08:16:00Z"))
    assert r["process_name"] == "sshd"
    e = one(ctx, "source_type = 'rsyslog_json' AND ts_ms = %d" % ms("2026-10-30T08:15:02.003Z"))
    assert (e["host"], e["process_name"]) == ("web01", "sshd")   # sysloghost; the host object is never the host


def test_evtx_dump_attributes(ctx) -> None:
    r = one(ctx, "event_id = 7045")
    assert r["ts_ms"] == ms("2026-10-31T09:15:01.123Z")
    assert (r["action"], r["host"], r["service_name"], r["process_path"]) == (
        "service_installed", "srv-db-02.corp.example.com", "psexesvc", "%SystemRoot%\\PSEXESVC.exe")


def test_velociraptor_value(ctx) -> None:
    r = one(ctx, "event_id = 4688")
    assert r["ts_ms"] == 1793438103123
    assert (r["action"], r["src_user"], r["process_name"], r["parent_process"], r["command_line"]) == (
        "proc_start", "alice", "cmd.exe", "explorer.exe", "cmd.exe /c ver")


def test_getwinevent_properties(ctx) -> None:
    r = one(ctx, "event_id = 4624")
    assert r["ts_ms"] == 1793438101123
    assert (r["action"], r["host"], r["target_user"], r["logon_type"], r["src_ip"], r["src_port"]) == (
        "login_success", "ws-fin-010.corp.example.com", "alice", 3, "203.0.113.57", 49712)
    assert (r["src_user"], r["logon_id"], r["auth_package"]) == ("ws-fin-010$", "0x8a3f21", "ntlm")


def test_1102_userdata_and_ffff(ctx) -> None:
    r = one(ctx, "event_id = 1102")
    assert (r["action"], r["src_user"], r["ts_ms"]) == ("log_cleared", "mallory", ms("2026-10-31T09:20:00Z"))
    k = one(ctx, "event_id = 4769")
    assert (k["action"], k["src_ip"], k["src_user"], k["service_name"]) == ("kerberos_tgs", "198.51.100.23", "alice",
                                                                            "mssqlsvc")


def test_ecs_category_fallback(ctx) -> None:
    p = one(ctx, "source_type = 'ecs_json' AND host = 'ws-fin-011' AND process_name = 'rundll32.exe'")
    assert (p["action"], p["parent_process"], p["src_user"]) == ("proc_start", "cmd.exe", "bob")
    d = one(ctx, "source_type = 'ecs_json' AND dst_domain = 'update.evil-cdn.example.net'")
    assert d["action"] == "dns_query"


def test_auditbeat_actions(ctx) -> None:
    e = one(ctx, "source_type = 'ecs_json' AND host = 'web02' AND process_name = 'cat'")
    assert (e["action"], e["command_line"], e["src_user"]) == ("proc_start", "cat /etc/shadow", "carol")
    f = one(ctx, "source_type = 'ecs_json' AND host = 'web02' AND src_ip = '203.0.113.58'")
    assert (f["action"], f["outcome"], f["target_user"]) == ("login_failed", "failure", "root")
    s = one(ctx, "source_type = 'ecs_json' AND host = 'web03'")
    assert (s["action"], s["target_user"], s["src_ip"]) == ("login_failed", "admin", "203.0.113.59")


@pytest.mark.parametrize("val,expect", [
    ("1793348102", 1793348102000), ("1793348102003", 1793348102003), ("1793348102003000", 1793348102003),
    ("1793348102003000123", 1793348102003), ("1793348102.5", 1793348102500),
])
def test_epoch_widths(val: str, expect: int, tmp_path: Path) -> None:
    from attacklens.ingest_sql import ts_expr
    con = db.connect(memory_limit="256MB", threads=1, temp_directory=tmp_path / "spill")
    try:
        pol = {"zones": {}, "naive_tz": None, "naive_formats": [], "skew_warn_s": 300}
        sql = ts_expr(ts_value_sql("x", "explicit", pol), [])
        assert con.execute(f"SELECT {sql} FROM (SELECT ? AS x)", [val]).fetchone()[0] == expect
    finally:
        con.close()
