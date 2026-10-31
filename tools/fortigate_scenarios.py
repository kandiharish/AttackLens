"""Planted FortiGate scenarios F1-F3 + decoy F4 + reach-next context (DEVELOPMENT.md §15.9).

Inert records only (placeholders where a payload would be). Attackers use RFC 5737 addresses. Ground truth
(TESTING.md §3.3): host = the internal endpoint IP of the step, or the firewall devname for steps on the firewall
itself (admin login / config / VPN portal); ts_ms = the step's first record. Offsets are from --start (UTC).

F1 (d1 01:30 UTC = 07:00 IST)  admin brute force -> login -> policy edit -> inbound RDP -> SMB -> 200 MB upload
F2 (d2 19:00 UTC)              IPS SSLVPN path-traversal hit let through -> VPN login vpnuser -> port scan -> WinRM to DC
F3 (d3 06:10 UTC)              AV download (monitored) -> 60 s +/- 3 s beacon x12 -> Tor app-ctrl
F4 decoy, every day 09:15-10:40 UTC (business hours IST and UTC): admin login success from the admin network
   10.10.99.10 + two routine config edits. Must NOT become an incident; not in ground truth.
Context (not ground truth, business hours daily): app server -> DB MS-SQL, file server -> DC SMB (reach-next edges).
"""
from __future__ import annotations

import random

from fortigate_gen import DEVNAME, IPS_PASS_ACTION, SERVERS, WAN_IP, Fmt

MIN, HOUR, DAY, MB = 60_000, 3_600_000, 86_400_000, 1 << 20
NAMES = {"F1": "firewall admin brute force -> RDP -> SMB -> exfil",
         "F2": "SSL VPN exploit -> VPN login -> scan -> WinRM",
         "F3": "malware download -> beacon -> Tor"}
OFFSETS = {"F1": 1 * HOUR + 30 * MIN, "F2": DAY + 19 * HOUR, "F3": 2 * DAY + 6 * HOUR + 10 * MIN}
F1_IP, F1_EXFIL = "203.0.113.66", "198.51.100.150"
F2_IP, F2_TUNNEL = "192.0.2.77", "10.212.134.200"
F3_HOST, F3_DL, F3_C2, F3_TOR = "10.10.2.37", "203.0.113.200", "198.51.100.210", "192.0.2.150"
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 464, 636, 993, 995, 1433, 1521,
              2049, 3268, 3306, 3389, 5432, 5900, 5985, 8080, 8443, 9200]
OPEN_SCAN_PORTS = {135, 445, 3389}


def _step(n: int, ts: int, tid: str, tactic: str, host: str, user: str | None = None, src: str | None = None,
          dst: str | None = None) -> dict:
    return {"step": n, "ts_ms": ts, "technique_id": tid, "tactic": tactic, "host": host, "user": user,
            "src_ip": src, "dst_ip": dst}


def _f1(f: Fmt, r: random.Random, t: int, out: list) -> list[dict]:
    for i in range(60):                                         # ~60 failures in 5 min on the admin GUI
        ts = t + i * 5000 + (r.randint(0, 600) if i else 0)
        out.append((ts, f.admin_login(ts, "admin", F1_IP, False, "passwd_invalid")))
    t2 = t + 6 * MIN
    out.append((t2, f.admin_login(t2, "admin", F1_IP, True)))
    t3 = t + 10 * MIN
    out.append((t3, f.config_change(t3, "admin", F1_IP, "firewall.policy", "17",
                                    "srcaddr[lan-servers->all]action[deny->accept]")))
    t4 = t + 14 * MIN
    out.append((t4, f.traffic(t4, F1_IP, SERVERS["app"], "RDP", "accept", sent=2_400_000, rcvd=18_000_000,
                              duration=1800, policyid=17)))
    t5 = t + 30 * MIN
    out.append((t5, f.traffic(t5, SERVERS["app"], SERVERS["file"], "SMB", "accept", sent=900_000,
                              rcvd=220 * MB, duration=420, policyid=3)))
    t6 = t + 50 * MIN
    out.append((t6, f.traffic(t6, SERVERS["app"], F1_EXFIL, "HTTPS", "accept", sent=200 * MB, rcvd=60_000,
                              duration=900, policyid=1)))
    return [_step(1, t, "T1110", "Credential Access", DEVNAME, "admin", F1_IP, WAN_IP),
            _step(2, t2, "T1078", "Initial Access", DEVNAME, "admin", F1_IP, WAN_IP),
            _step(3, t3, "T1562.004", "Defense Impairment", DEVNAME, "admin", F1_IP),
            _step(4, t4, "T1021.001", "Lateral Movement", SERVERS["app"], None, F1_IP, SERVERS["app"]),
            _step(5, t5, "T1021.002", "Lateral Movement", SERVERS["app"], None, SERVERS["app"], SERVERS["file"]),
            _step(6, t6, "T1048", "Exfiltration", SERVERS["app"], None, SERVERS["app"], F1_EXFIL)]


def _f2(f: Fmt, r: random.Random, t: int, out: list) -> list[dict]:
    out.append((t, f.ips(t, F2_IP, WAN_IP, "Sim.SSLVPN.Portal.Path.Traversal", "critical", IPS_PASS_ACTION, 443,
                         "/remote/<PLACEHOLDER_PATH>")))
    t2 = t + 3 * MIN
    out.append((t2, f.vpn(t2, "vpnuser", F2_IP, F2_TUNNEL, up=True)))
    t3 = t + 8 * MIN
    for i, port in enumerate(SCAN_PORTS):                       # 30 ports on one host in 45 s
        ts = t3 + i * 1500
        act = "accept" if port in OPEN_SCAN_PORTS else "deny"
        svc = {135: "DCE-RPC", 445: "SMB", 3389: "RDP"}.get(port, f"tcp/{port}")
        out.append((ts, f.traffic(ts, F2_TUNNEL, SERVERS["file"], svc, act, dport=port, sent=60 if act == "accept"
                                  else 0, rcvd=40 if act == "accept" else 0, duration=0, policyid=9)))
    t4 = t + 20 * MIN
    out.append((t4, f.traffic(t4, F2_TUNNEL, SERVERS["dc"], "tcp/5985", "accept", dport=5985, sent=48_000,
                              rcvd=210_000, duration=240, policyid=9)))
    return [_step(1, t, "T1190", "Initial Access", DEVNAME, None, F2_IP, WAN_IP),
            _step(2, t2, "T1133", "Initial Access", DEVNAME, "vpnuser", F2_IP),
            _step(3, t3, "T1046", "Discovery", F2_TUNNEL, None, F2_TUNNEL, SERVERS["file"]),
            _step(4, t4, "T1021.006", "Lateral Movement", F2_TUNNEL, None, F2_TUNNEL, SERVERS["dc"])]


def _f3(f: Fmt, r: random.Random, t: int, out: list) -> list[dict]:
    out.append((t, f.virus(t, F3_HOST, F3_DL, "W32/Sim.Test!tr", "monitored", "files.sim-download.invalid",
                           "/<PLACEHOLDER_FILE>")))
    t2 = t + 5 * MIN
    for i in range(12):                                         # every 60 s +/- 3 s
        ts = t2 + i * MIN + (r.randint(-3000, 3000) if i else 0)
        out.append((ts, f.traffic(ts, F3_HOST, F3_C2, "HTTPS", "accept", sent=r.randint(400, 900),
                                  rcvd=r.randint(300, 700), duration=1, policyid=1)))
    t3 = t + 25 * MIN
    out.append((t3, f.appctrl(t3, F3_HOST, F3_TOR, "Tor", "Proxy", "critical", "pass", 9001)))
    return [_step(1, t, "T1105", "Command and Control", F3_HOST, None, F3_HOST, F3_DL),
            _step(2, t2, "T1071.001", "Command and Control", F3_HOST, None, F3_HOST, F3_C2),
            _step(3, t3, "T1090.003", "Command and Control", F3_HOST, None, F3_HOST, F3_TOR)]


def _f4_and_context(f: Fmt, r: random.Random, start_ms: int, days: int, out: list, decoy: bool) -> None:
    for d in range(days):
        base = start_ms + d * DAY
        if decoy:                                               # routine admin work from the admin network
            t = base + 9 * HOUR + 15 * MIN + r.randint(0, 600_000)
            out.append((t, f.admin_login(t, "admin", SERVERS["admin"], True)))
            for k, (path, obj) in enumerate((("firewall.address", "srv-new"), ("system.interface", "internal"))):
                ts = t + (15 + 70 * k) * MIN
                out.append((ts, f.config_change(ts, "admin", SERVERS["admin"], path, obj, "comment[]")))
        for src, dst, svc in ((SERVERS["app"], SERVERS["db"], "MS-SQL"), (SERVERS["file"], SERVERS["dc"], "SMB")):
            ts = base + 11 * HOUR + r.randint(0, 3_600_000)
            out.append((ts, f.traffic(ts, src, dst, svc, "accept", sent=r.randint(20_000, 90_000),
                                      rcvd=r.randint(50_000, 400_000), duration=r.randint(5, 60), policyid=3)))


def scenario_lines(start_ms: int, ids: list[str], seed: int, days: int = 7) -> tuple[list[tuple[int, str]], dict]:
    """(sorted (ts_ms, line) list, attacks.json dict) for the requested ids. Deterministic in (start, ids, seed)."""
    r = random.Random(f"fortigate-scenarios:{seed}")
    f = Fmt(r, session_base=900_000_000)
    out: list[tuple[int, str]] = []
    attacks = []
    for sid, fn in (("F1", _f1), ("F2", _f2), ("F3", _f3)):
        if sid in ids:
            attacks.append({"id": sid, "name": NAMES[sid], "steps": fn(f, r, start_ms + OFFSETS[sid], out)})
    if ids:
        _f4_and_context(f, r, start_ms, max(1, days), out, decoy="F4" in ids)
    out.sort(key=lambda x: x[0])
    return out, {"attack_version": "v20", "attacks": attacks}
