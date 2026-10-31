"""Planted multi-step scenarios S1-S5 + one decoy each (TESTING.md §3.2, DEVELOPMENT.md §15.5).

Every event is an inert ECS JSON log record built with the provided generator's base_event()/proc_block(),
so its schema matches benign traffic. Command lines are short descriptive placeholders in the generator's
own style. IPs: RFC 5737 + the generator's 10.10.x.x hosts; domains: .invalid only. Attacker addresses
are IOC-free by default (not in config/ioc.yaml); ioc_free=False restores the legacy IOC addresses.
Offsets are from --start (d1 = the start date when --start is midnight).

Decoys (must NOT become incidents):
  S1  rkumar network logon + 4672 on SRV-DC-01, d1 10:15, from a workstation (business hours)
  S2  asharma adds existing jdsouza to "Backup Operators" on SRV-DC-01, d2 11:00 (no 4720 before it)
  S3  winword.exe spawns splwow64.exe (printing) on WS-HR-013, d3 11:00
  S4  30 benign 4625 for kiyer on SRV-FILE-01 spread over d4
  S5  svc_backup 40 MB upload from SRV-FILE-01 to internal 10.10.0.40, d5 01:00
"""
from __future__ import annotations

import random
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_dataset as gd  # noqa: E402

MIN = 60_000
HOUR = 3_600_000
DAY = 86_400_000
MB = 1 << 20
SCENARIO_NAMES = {
    "S1": "vendor brute force -> exfil",
    "S2": "account backdoor",
    "S3": "phishing -> C2",
    "S4": "spray -> SSH pivot",
    "S5": "ransomware",
}
ENC_PS = "powershell.exe -nop -w hidden -enc <REDACTED_BASE64>"
PS_PATH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
RUN_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\<SUSPECT_ENTRY>"
# Attacker infrastructure. Two variants (both RFC 5737 / reserved TLDs):
#  "ioc_free" (default): addresses and domain that are NOT in config/ioc.yaml, so ioc_destination cannot help link
#                        the planted chains (honest numbers; code review finding 6).
#  "ioc" (legacy):       the generator's SUSPECT_IPS / SUSPECT_DOMAINS, which are exactly config/ioc.yaml's lists.
ADDRS: dict[str, dict[str, str]] = {
    "ioc": {"C2_DOMAIN": "suspicious-example-c2.invalid", "C2_IP": "198.51.100.77",
            "S1_BRUTE_IP": "203.0.113.57", "S1_EXFIL_IP": "198.51.100.23",
            "S4_SPRAY_IP": "192.0.2.88", "S4_EXFIL_IP": "203.0.113.57"},
    "ioc_free": {"C2_DOMAIN": "cdn-telemetry-sync.invalid", "C2_IP": "198.51.100.77",
                 "S1_BRUTE_IP": "203.0.113.141", "S1_EXFIL_IP": "198.51.100.142",
                 "S4_SPRAY_IP": "192.0.2.143", "S4_EXFIL_IP": "203.0.113.144"},
}
C2_DOMAIN, C2_IP = ADDRS["ioc"]["C2_DOMAIN"], ADDRS["ioc"]["C2_IP"]          # legacy names (ioc variant)
S1_BRUTE_IP, S1_EXFIL_IP = ADDRS["ioc"]["S1_BRUTE_IP"], ADDRS["ioc"]["S1_EXFIL_IP"]
S4_SPRAY_IP, S4_EXFIL_IP = ADDRS["ioc"]["S4_SPRAY_IP"], ADDRS["ioc"]["S4_EXFIL_IP"]
S5_SRC_IP = "10.10.4.13"           # WS-SALES-013
# generic account names a spray tries besides the real directory users (USERS has only 12)
SPRAY_EXTRA = ["root", "admin", "test", "guest", "ubuntu", "oracle", "deploy", "backup"]


class _Builder:
    """Wraps one generator module instance with a settable clock and seeded ids."""

    def __init__(self, gen: Any, seed: int) -> None:
        self.gen = gen
        self.clock = gd.SimClock(0, 1 << 62)
        self.rng = random.Random(f"scenarios:{seed}")
        gd.install_patches(gen, self.clock, self.rng)
        self.hosts = {h["name"]: h for h in gen.HOSTS}
        self.events: list[tuple[int, int, dict]] = []
        self.ip: dict[str, str] = ADDRS["ioc_free"]  # set per call by scenario_events

    def logon_id(self) -> str:
        return f"0x{self.rng.randrange(0x100000, 0xFFFFFF):x}"

    def _base(self, ts: int, host: str, user: str, category: str, etype: str, action: str) -> dict:
        self.clock.ms = ts
        ev = self.gen.base_event(self.hosts[host], user, category, etype, action)
        self.events.append((ts, len(self.events), ev))
        return ev

    # ---- authentication / iam (DEVELOPMENT.md §15.5)
    def logon(self, ts: int, host: str, user: str, ok: bool, ltype: str, src_ip: str,
              lid: str | None = None) -> dict:
        ev = self._base(ts, host, user, "authentication", "start", "user_logon")
        ev["event"]["outcome"] = "success" if ok else "failure"
        logon: dict[str, Any] = {"type": ltype}
        if lid:
            logon["id"] = lid
        ev["winlog"] = {"event_id": 4624 if ok else 4625, "logon": logon}
        ev["source"] = {"ip": src_ip}
        return ev

    def privileges(self, ts: int, host: str, user: str, lid: str) -> dict:
        ev = self._base(ts, host, user, "iam", "admin", "special_privileges_assigned")
        ev["winlog"] = {"event_id": 4672, "logon": {"id": lid}}
        return ev

    def admin_logon(self, ts: int, host: str, user: str, src_ip: str, ltype: str = "Network") -> None:
        lid = self.logon_id()
        self.logon(ts, host, user, True, ltype, src_ip, lid)
        self.privileges(ts + 150, host, user, lid)

    def user_created(self, ts: int, host: str, actor: str, new_user: str) -> dict:
        ev = self._base(ts, host, actor, "iam", "creation", "user_created")
        ev["winlog"] = {"event_id": 4720}
        ev["user"]["target"] = {"name": new_user}
        return ev

    def group_add(self, ts: int, host: str, actor: str, member: str, group: str) -> dict:
        ev = self._base(ts, host, actor, "iam", "group", "group_member_added")
        ev["winlog"] = {"event_id": 4732}
        ev["user"]["target"] = {"name": member}
        ev["group"] = {"name": group}
        return ev

    def service(self, ts: int, host: str, user: str, name: str, exe: str) -> dict:
        ev = self._base(ts, host, user, "configuration", "installation", "service_installed")
        ev["winlog"] = {"event_id": 7045}
        ev["service"] = {"name": name}
        ev["process"] = {"executable": exe}
        return ev

    def log_cleared(self, ts: int, host: str, user: str) -> dict:
        ev = self._base(ts, host, user, "configuration", "deletion", "log_cleared")
        ev["winlog"] = {"event_id": 1102}
        return ev

    def ssh_logon(self, ts: int, host: str, user: str, ok: bool, src_ip: str) -> dict:
        ev = self._base(ts, host, user, "authentication", "start", "user_logon")
        ev["event"]["outcome"] = "success" if ok else "failure"
        ev["process"] = {"name": "sshd"}
        ev["source"] = {"ip": src_ip}
        ev["destination"] = {"port": 22}
        return ev

    # ---- process / network / file / registry (generator style)
    def proc(self, ts: int, host: str, user: str, name: str, path: str, cmd: str, parent: str) -> dict:
        ev = self._base(ts, host, user, "process", "start", "process_created")
        ev["process"] = self.gen.proc_block(name, path, cmd, parent)
        return ev

    def conn(self, ts: int, host: str, user: str, proc: str, dst_ip: str, port: int, nbytes: int,
             domain: str | None = None) -> dict:
        ev = self._base(ts, host, user, "network", "connection", "network_connection")
        ev["process"] = {"pid": self.gen.rand_pid(), "name": proc}
        ev["source"] = {"ip": self.hosts[host]["ip"], "port": self.rng.randint(49152, 65535)}
        ev["destination"] = {"ip": dst_ip, "port": port}
        if domain:
            ev["destination"]["domain"] = domain
        ev["network"] = {"transport": "tcp", "direction": "outbound", "bytes": nbytes}
        return ev

    def reg_set(self, ts: int, host: str, user: str, path: str, data: str, proc: str) -> dict:
        ev = self._base(ts, host, user, "registry", "change", "registry_value_set")
        ev["registry"] = {"path": path, "data": {"strings": [data]}}
        ev["process"] = {"pid": self.gen.rand_pid(), "name": proc}
        return ev

    def rename(self, ts: int, host: str, user: str, path: str, ext: str, proc: str) -> dict:
        ev = self._base(ts, host, user, "file", "change", "file_rename")
        ev["file"] = {"path": path, "name": path.split("\\")[-1], "extension": ext}
        ev["process"] = {"pid": self.gen.rand_pid(), "name": proc}
        return ev


def _step(n: int, ts: int, tid: str, tactic: str, host: str, user: str | None,
          src_ip: str | None = None, dst_ip: str | None = None) -> dict:
    return {"step": n, "ts_ms": ts, "technique_id": tid, "tactic": tactic, "host": host.lower(),
            "user": user, "src_ip": src_ip, "dst_ip": dst_ip}


# ----------------------------------------------------------------------------- scenarios
def _s1(b: _Builder, t: int) -> list[dict]:
    dc, ws, u = "SRV-DC-01", "WS-FIN-010", "svc_backup"
    for i in range(60):                                    # 60 x 4625 within 5 min
        b.logon(t + i * 4900 + (b.rng.randint(0, 400) if i else 0), dc, u, False, "Network", b.ip["S1_BRUTE_IP"])
    t2 = t + 6 * MIN
    b.logon(t2, dc, u, True, "Network", b.ip["S1_BRUTE_IP"], b.logon_id())
    t3 = t + 20 * MIN
    b.admin_logon(t3, ws, u, b.hosts[dc]["ip"])
    t4 = t + 25 * MIN
    b.proc(t4, ws, u, "powershell.exe", PS_PATH, ENC_PS, "wmiprvse.exe")
    t5 = t + 28 * MIN
    b.proc(t5, ws, u, "net.exe", r"C:\Windows\System32\net.exe", 'net group "domain admins" /domain',
           "powershell.exe")
    t6 = t + 35 * MIN
    b.proc(t6, ws, u, "7z.exe", r"C:\Program Files\7-Zip\7z.exe", "7z a <archive>.7z <folder>",
           "powershell.exe")
    t7 = t + 45 * MIN
    for i in range(4):                                     # 4 x 25 MB within 10 min
        b.conn(t7 + i * 3 * MIN, ws, u, "powershell.exe", b.ip["S1_EXFIL_IP"], 443, 25 * MB)
    # decoy: legitimate admin logon on the DC in business hours
    b.admin_logon(t - 2 * HOUR + 10 * HOUR + 15 * MIN, dc, "rkumar", b.hosts["WS-ENG-010"]["ip"])
    _s1_history(b, t)
    return [
        _step(1, t, "T1110", "Credential Access", dc, u, b.ip["S1_BRUTE_IP"]),
        _step(2, t2, "T1078", "Initial Access", dc, u, b.ip["S1_BRUTE_IP"]),
        _step(3, t3, "T1021", "Lateral Movement", ws, u, b.hosts[dc]["ip"]),
        _step(4, t4, "T1059.001", "Execution", ws, u),
        _step(5, t5, "T1087", "Discovery", ws, u),
        _step(6, t6, "T1560.001", "Collection", ws, u),
        _step(7, t7, "T1048", "Exfiltration", ws, u, b.hosts[ws]["ip"], b.ip["S1_EXFIL_IP"]),
    ]


def _s1_history(b: _Builder, t: int) -> None:
    """Benign context 2-3 days before S1 (not ground truth): svc_backup is a backup job with admin rights on
    SRV-FILE-01, which talks SSH to SRV-DB-01 -> reach-next shows srv-file-01 (hop 1) and srv-db-01 (hop 2).
    Must not trigger any rule: the pair is routine (>= new_admin_routine_min_logons non-privileged logons) and both
    privileged logons are in business hours, 2 flows < beacon_min_conns, internal destination (no exfil)."""
    fs, db, u, src = "SRV-FILE-01", "SRV-DB-01", "svc_backup", b.hosts["SRV-DC-01"]["ip"]   # 10.10.0.10
    day0 = t - 2 * HOUR                                     # midnight of S1's day
    for d, hh, mm in ((3, 9, 40), (3, 13, 5), (2, 9, 35)):   # routine non-privileged job logons (no 4672)
        b.logon(day0 - d * DAY + hh * HOUR + mm * MIN, fs, u, True, "Network", src, b.logon_id())
    for d, hh, mm in ((3, 10, 5), (2, 14, 20)):               # 4624 type 3 + 4672 (same logon id), twice
        b.admin_logon(day0 - d * DAY + hh * HOUR + mm * MIN, fs, u, src)
    for d, hh, mm in ((3, 10, 12), (2, 14, 31)):              # allowed SSH flows file server -> DB server
        b.conn(day0 - d * DAY + hh * HOUR + mm * MIN, fs, u, "ssh", b.hosts[db]["ip"], 22, 18_000)


def _s2(b: _Builder, t: int) -> list[dict]:
    dc, fs, actor, new = "SRV-DC-01", "SRV-FILE-01", "asharma", "helpdesk_tmp"
    b.user_created(t, dc, actor, new)
    t2 = t + 2 * MIN
    b.group_add(t2, dc, actor, new, "Administrators")
    t3 = t + 15 * MIN
    b.admin_logon(t3, fs, new, b.hosts[dc]["ip"])
    t4 = t + 20 * MIN
    b.service(t4, fs, new, "upd_helper", r"C:\Windows\Temp\<redacted>.exe")
    t5 = t + 25 * MIN
    b.log_cleared(t5, fs, new)
    # decoy: existing user added to a group, no account creation before it
    b.group_add(t - 3 * HOUR - 30 * MIN, dc, actor, "jdsouza", "Backup Operators")
    return [
        _step(1, t, "T1136", "Persistence", dc, new),
        _step(2, t2, "T1098", "Privilege Escalation", dc, new),
        _step(3, t3, "T1021", "Lateral Movement", fs, new, b.hosts[dc]["ip"]),
        _step(4, t4, "T1543.003", "Persistence", fs, new),
        _step(5, t5, "T1070.001", "Defense Impairment", fs, new),
    ]


def _s3(b: _Builder, t: int) -> list[dict]:
    ws, u = "WS-HR-012", "pmehta"
    word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    b.proc(t - 2 * MIN, ws, u, "winword.exe", word, f'"{word}"', "explorer.exe")   # context
    b.proc(t, ws, u, "powershell.exe", PS_PATH, ENC_PS, "winword.exe")
    t2 = t + 2 * MIN
    b.reg_set(t2, ws, u, RUN_KEY, r"%AppData%\<redacted>.exe", "powershell.exe")
    t3 = t + 5 * MIN
    for i in range(10):                                    # every 60 s +/- 3 s
        jitter = b.rng.randint(-3000, 3000) if i else 0
        b.conn(t3 + i * MIN + jitter, ws, u, "powershell.exe", b.ip["C2_IP"], 443, b.rng.randint(1000, 5000),
               b.ip["C2_DOMAIN"])
    # decoy: Office spawning a non-script helper (printing)
    b.proc(t + 1 * HOUR + 50 * MIN, "WS-HR-013", "kiyer", "splwow64.exe",
           r"C:\Windows\splwow64.exe", r"C:\Windows\splwow64.exe 12288", "winword.exe")
    return [
        _step(1, t, "T1059.001", "Execution", ws, u),
        _step(2, t2, "T1547.001", "Persistence", ws, u),
        _step(3, t3, "T1071.001", "Command and Control", ws, u, b.hosts[ws]["ip"], b.ip["C2_IP"]),
    ]


def _s4(b: _Builder, t: int, users: list[str]) -> list[dict]:
    web, db, u = "SRV-WEB-01", "SRV-DB-01", "vreddy"
    sprayed = users[:10] + SPRAY_EXTRA + ["svc_sql", "svc_backup"]
    assert len(set(sprayed)) == 20 and u in sprayed
    for i, name in enumerate(sprayed):                     # 20 users within 10 min
        b.ssh_logon(t + i * 25_000, web, name, False, b.ip["S4_SPRAY_IP"])
    t2 = t + 10 * MIN
    b.ssh_logon(t2, web, u, True, b.ip["S4_SPRAY_IP"])
    t3 = t + 18 * MIN
    b.conn(t3 - 400, web, u, "ssh", b.hosts[db]["ip"], 22, 4200)                    # context
    b.ssh_logon(t3, db, u, True, b.hosts[web]["ip"])
    t4 = t + 30 * MIN
    b.conn(t4, db, u, "curl", b.ip["S4_EXFIL_IP"], 443, 60 * MB)
    # decoy: 30 benign failures for one user spread over the day
    day0 = t - 22 * HOUR
    for i in range(30):
        b.logon(day0 + i * 47 * MIN + b.rng.randint(0, 60_000), "SRV-FILE-01", "kiyer", False,
                "Network", b.hosts["WS-HR-011"]["ip"])
    return [
        _step(1, t, "T1110.003", "Credential Access", web, None, b.ip["S4_SPRAY_IP"]),
        _step(2, t2, "T1078", "Initial Access", web, u, b.ip["S4_SPRAY_IP"]),
        _step(3, t3, "T1021.004", "Lateral Movement", db, u, b.hosts[web]["ip"]),
        _step(4, t4, "T1048", "Exfiltration", db, u, b.hosts[db]["ip"], b.ip["S4_EXFIL_IP"]),
    ]


def _s5(b: _Builder, t: int) -> list[dict]:
    fs, u = "SRV-FILE-01", "svc_sql"
    b.admin_logon(t, fs, u, S5_SRC_IP)
    t2 = t + 5 * MIN
    for i in range(300):                                   # 300 renames within 60 s
        b.rename(t2 + i * 200, fs, u, rf"C:\Shares\Finance\doc_{i:04d}.xlsx.locked", "locked", "unknown.exe")
    # decoy: nightly backup upload to an internal server
    b.conn(t - 2 * HOUR, fs, "svc_backup", "svchost.exe", b.hosts["SRV-DB-01"]["ip"], 445, 40 * MB)
    return [
        _step(1, t, "T1078", "Initial Access", fs, u, S5_SRC_IP),
        _step(2, t2, "T1486", "Impact", fs, u),
    ]


OFFSETS = {"S1": 2 * HOUR, "S2": DAY + 14 * HOUR + 30 * MIN, "S3": 2 * DAY + 9 * HOUR + 10 * MIN,
           "S4": 3 * DAY + 22 * HOUR, "S5": 4 * DAY + 3 * HOUR}


def scenario_events(start_ms: int, ids: list[str] | None = None, generator: str | Path | None = None,
                    seed: int = 42, ioc_free: bool = True) -> tuple[list[dict], dict]:
    """Return (events sorted by time, attacks.json dict) for the requested scenario ids (default all).

    ioc_free=True (default) plants attacker addresses that are not in config/ioc.yaml; False = legacy addresses."""
    ids = list(SCENARIO_NAMES) if ids is None else [i.upper() for i in ids]
    gen = gd.load_generator(generator or gd.DEFAULT_GENERATOR, "edr_log_generator_scenarios")
    saved = random.getstate()                              # proc_block/rand_pid use the global random
    random.seed(f"scenarios-pids:{seed}")
    try:
        b = _Builder(gen, seed)
        b.ip = ADDRS["ioc_free" if ioc_free else "ioc"]
        attacks = []
        for sid in SCENARIO_NAMES:
            if sid not in ids:
                continue
            t = start_ms + OFFSETS[sid]
            steps = _s4(b, t, list(gen.USERS)) if sid == "S4" else globals()[f"_{sid.lower()}"](b, t)
            attacks.append({"id": sid, "name": SCENARIO_NAMES[sid], "steps": steps})
    finally:
        random.setstate(saved)
    events = [ev for _, _, ev in sorted(b.events, key=lambda x: (x[0], x[1]))]
    return events, {"attack_version": "v20", "attacks": attacks}
