"""Synthetic FortiGate key=value log generator with planted scenarios F1-F4 (DEVELOPMENT.md §15.9, TESTING.md §3).

    python tools/fortigate_gen.py --size 1G --out data/raw/f1 --workers 6 --seed 42 --force

The record mix is modelled on the type/subtype distribution of the real tiers (counts only, no real lines):
traffic/forward 64 %, event/system 16 % (mostly "Admin login failed"), utm webfilter 4.5 %, ips 3 %, app-ctrl 3 %,
dns 3 %, virus 1.5 %, event vpn 1.5 %, ha / connector / dhcp / sdwan ~1 % each. One device (FGT60FTK-SIM).
`date`/`time` are device-local (+05:30) and `eventtime` is UTC epoch nanoseconds; both always describe the same instant.
Records only describe events: signature / virus names are plain placeholder strings, URLs are <PLACEHOLDER> paths.
Output (same conventions as gen_dataset.py): part-<k>.log (noise, LF, size target), scenarios.log (F1-F4 + context),
ground_truth/attacks.json (§3.3), manifest.json. Same --seed -> byte-identical parts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import multiprocessing as mp
import random
import sys
import time
from bisect import bisect
from itertools import accumulate
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_dataset as gd  # noqa: E402

log = logging.getLogger("fortigate_gen")

DEVNAME, DEVID, VD = "FGT60FTK-SIM", "FGT60FTK00000001", "root"
TZ_OFFSET_S = 19_800                     # +05:30
WAN_IP = "49.36.200.10"                  # the firewall's own public address (VPN portal, admin GUI)
ALL_SCENARIOS = ("F1", "F2", "F3", "F4")
IPS_PASS_ACTION = "pass_session"         # FortiGate IPS "let it through" action (F2 path-traversal hit)

LOGID = {"traffic": "0000000013", "login_failed": "0100032002", "login_ok": "0100032001", "config": "0100044547",
         "perf": "0100040704", "vpn": "0101039947", "ips": "0419016384", "webfilter": "0316013056",
         "app-ctrl": "1059028704", "dns": "1501054802", "virus": "0211008192", "ha": "0108037893",
         "connector": "0100053200", "dhcp": "0100026001", "sdwan": "0113022925"}
# service -> (proto, dstport, app, appcat, internal destination?)
SERVICES = {
    "HTTPS": (6, 443, "HTTPS.BROWSER", "Web.Client", False), "DNS": (17, 53, "DNS", "Network.Service", True),
    "HTTP": (6, 80, "HTTP.BROWSER", "Web.Client", False), "SIP": (17, 5060, "SIP", "VoIP", False),
    "RDP": (6, 3389, "RDP", "Remote.Access", True), "RTP": (17, 0, "RTP", "VoIP", False),
    "SNMP": (17, 161, "SNMP", "Network.Service", True), "SSH": (6, 22, "SSH", "Remote.Access", True),
    "SMTP": (6, 25, "SMTP", "Email", False), "KERBEROS": (6, 88, "Kerberos", "Network.Service", True),
    "IMAPS": (6, 993, "IMAPS", "Email", False), "NTP": (17, 123, "NTP", "Network.Service", False),
    "SMB": (6, 445, "SMB", "Network.Service", True), "ICMP_ANY": (1, 0, "ICMP", "Network.Service", False),
    "LDAP": (6, 389, "LDAP", "Network.Service", True), "MS-SQL": (6, 1433, "MS.SQL", "Business", True),
}
SERVICE_W = {"HTTPS": 45, "DNS": 20, "HTTP": 8, "SIP": 3, "RDP": 1, "RTP": 3, "SNMP": 2, "SSH": 1, "SMTP": 2,
             "KERBEROS": 3, "IMAPS": 2, "NTP": 3, "SMB": 3, "ICMP_ANY": 2, "LDAP": 3, "MS-SQL": 1}
MIX = [("traffic", 64.0), ("system", 16.0), ("webfilter", 4.5), ("ips", 3.0), ("app-ctrl", 3.0), ("dns", 3.0),
       ("virus", 1.5), ("vpn", 1.5), ("ha", 1.0), ("connector", 1.0), ("dhcp", 1.0), ("sdwan", 0.5)]
TRAFFIC_ACTIONS = [("accept", 88), ("deny", 5), ("close", 4), ("timeout", 3)]
SERVERS = {"dc": "10.10.0.10", "dc2": "10.10.0.11", "app": "10.10.20.15", "web": "10.10.20.20",
           "file": "10.10.30.5", "db": "10.10.40.5", "admin": "10.10.99.10"}
EMPLOYEES = ["rkumar", "asharma", "pmehta", "sgupta", "nverma", "kiyer", "dnair", "jdsouza", "vreddy", "mjoshi"]
BOT_USERS = ["root", "test", "user", "guest", "support", "administrator", "ftp", "oracle", "pi", "ubnt", "manager",
             "operator", "service", "default", "fortinet", "sysadmin"]
COUNTRIES = ["United States", "India", "Germany", "Singapore", "Netherlands", "Ireland", "Japan", "France",
             "United Kingdom", "Brazil"]
IPS_NOISE = ["Sim.HTTP.URI.Path.Traversal", "Sim.Web.Server.RCE.Probe", "Sim.SMB.Login.Bruteforce",
             "Sim.PHP.CGI.Argument.Injection", "Sim.Telnet.Login.Bruteforce", "Sim.IoT.Botnet.Scanner",
             "Sim.SQL.Injection.Probe"]
WEB_HOSTS = ["login.microsoftonline.com", "outlook.office365.com", "www.google.com", "teams.microsoft.com",
             "github.com", "update.microsoft.com", "slack.com", "zoom.us", "news.example.com"]
CATDESC = ["Information Technology", "Search Engines and Portals", "Business", "News and Media",
           "Streaming Media and Download", "Social Networking"]
APPS = [("Microsoft.Office.365", "Collaboration", "low"), ("Google.Services", "General.Interest", "low"),
        ("YouTube", "Video/Audio", "medium"), ("Zoom", "Collaboration", "low"), ("Slack", "Collaboration", "low"),
        ("Microsoft.Teams", "Collaboration", "low"), ("WhatsApp", "Social.Media", "medium")]
_PUBLIC_FIRST = [13, 20, 23, 31, 40, 45, 52, 64, 77, 88, 91, 104, 142, 151, 185]


def is_internal(ip: str) -> bool:
    return ip.startswith("10.")


class Fmt:
    """Formats FortiGate key=value records. Every record starts with the same header fields."""

    def __init__(self, rng: random.Random, session_base: int) -> None:
        self.rng = rng
        self.sid = session_base
        self._sec = -1
        self._dt = ""

    def head(self, ms: int, logid: str, typ: str, sub: str, level: str) -> str:
        sec = ms // 1000
        if sec != self._sec:
            self._sec = sec
            self._dt = time.strftime("date=%Y-%m-%d time=%H:%M:%S", time.gmtime(sec + TZ_OFFSET_S))
        ns = ms * 1_000_000 + self.rng.randrange(1_000_000)
        return (f'{self._dt} devname="{DEVNAME}" devid="{DEVID}" eventtime={ns} tz="+0530" logid="{logid}" '
                f'type="{typ}" subtype="{sub}" level="{level}" vd="{VD}"')

    @staticmethod
    def _intf(ip: str) -> tuple[str, str]:
        if ip.startswith("10.212."):
            return "ssl.root", "undefined"
        if ip.startswith("10.10.20."):
            return "dmz", "dmz"
        if is_internal(ip):
            return "internal", "lan"
        return "wan1", "wan"

    def traffic(self, ms: int, src: str, dst: str, service: str, action: str = "accept", sport: int | None = None,
                dport: int | None = None, sent: int | None = None, rcvd: int | None = None, duration: int | None = None,
                policyid: int = 1) -> str:
        r = self.rng
        proto, port, app, appcat, _ = SERVICES.get(service, (6, dport or 0, "unknown-TCP", "unscanned", True))
        dport = dport if dport is not None else (r.randint(16384, 32767) if service == "RTP" else port)
        sport = sport if sport is not None else (0 if proto == 1 else r.randint(1024, 65535))
        sent = sent if sent is not None else (0 if action == "deny" else int(r.lognormvariate(7.5, 1.6)))
        rcvd = rcvd if rcvd is not None else (0 if action == "deny" else int(r.lognormvariate(8.5, 1.8)))
        duration = duration if duration is not None else (0 if action == "deny" else r.randint(1, 180))
        si, sr = self._intf(src)
        di, dr = self._intf(dst)
        sc = "Reserved" if is_internal(src) else r.choice(COUNTRIES)
        dc = "Reserved" if is_internal(dst) else r.choice(COUNTRIES)
        self.sid += 1
        spk, rpk = (0, 0) if action == "deny" else (max(1, sent // 900), max(1, rcvd // 1200))
        risk = "elevated" if service in ("RDP", "SSH", "SMB") else "low"
        return (f'{self.head(ms, LOGID["traffic"], "traffic", "forward", "notice")} srcip={src} srcport={sport} '
                f'srcintf="{si}" srcintfrole="{sr}" dstip={dst} dstport={dport} dstintf="{di}" dstintfrole="{dr}" '
                f'srccountry="{sc}" dstcountry="{dc}" sessionid={self.sid} proto={proto} action="{action}" '
                f'policyid={policyid} policytype="policy" service="{service}" trandisp="snat" duration={duration} '
                f'sentbyte={sent} rcvdbyte={rcvd} sentpkt={spk} rcvdpkt={rpk} appcat="{appcat}" app="{app}" '
                f'apprisk="{risk}"')

    def admin_login(self, ms: int, user: str, src: str, ok: bool, reason: str = "name_invalid") -> str:
        if ok:
            return (f'{self.head(ms, LOGID["login_ok"], "event", "system", "information")} '
                    f'logdesc="Admin login successful" sn="0" user="{user}" ui="https({src})" method="https" '
                    f'srcip={src} dstip={WAN_IP} action="login" status="success" reason="none" profile="super_admin" '
                    f'msg="Administrator {user} logged in successfully from https({src})"')
        why = "invalid user name" if reason == "name_invalid" else "invalid password"
        return (f'{self.head(ms, LOGID["login_failed"], "event", "system", "alert")} logdesc="Admin login failed" '
                f'sn="0" user="{user}" ui="https({src})" method="https" srcip={src} dstip={WAN_IP} action="login" '
                f'status="failed" reason="{reason}" msg="Administrator {user} login failed from https({src}) '
                f'because of {why}"')

    def config_change(self, ms: int, user: str, src: str, path: str, obj: str, attr: str) -> str:
        return (f'{self.head(ms, LOGID["config"], "event", "system", "information")} '
                f'logdesc="Object attribute configured" user="{user}" ui="GUI({src})" action="Edit" '
                f'cfgtid={self.rng.randint(1000, 999999)} cfgpath="{path}" cfgobj="{obj}" cfgattr="{attr}" '
                f'msg="Edit {path} {obj}"')

    def ips(self, ms: int, src: str, dst: str, attack: str, severity: str, action: str, dport: int = 443,
            url: str = "/") -> str:
        si, sr = self._intf(src)
        di, dr = self._intf(dst)
        self.sid += 1
        return (f'{self.head(ms, LOGID["ips"], "utm", "ips", "alert")} eventtype="signature" severity="{severity}" '
                f'srcip={src} srcport={self.rng.randint(1024, 65535)} srcintf="{si}" srcintfrole="{sr}" '
                f'dstip={dst} dstport={dport} dstintf="{di}" dstintfrole="{dr}" sessionid={self.sid} proto=6 '
                f'action="{action}" policyid=1 service="HTTPS" direction="incoming" attack="{attack}" '
                f'attackid={int(hashlib.md5(attack.encode()).hexdigest()[:6], 16)} url="{url}" msg="{attack}"')

    def webfilter(self, ms: int, src: str, dst: str, hostname: str, catdesc: str, action: str) -> str:
        return (f'{self.head(ms, LOGID["webfilter"], "utm", "webfilter", "notice")} eventtype="ftgd_allow" '
                f'srcip={src} dstip={dst} dstport=443 service="HTTPS" hostname="{hostname}" url="/" '
                f'catdesc="{catdesc}" action="{action}" msg="URL belongs to an allowed category in policy"')

    def appctrl(self, ms: int, src: str, dst: str, app: str, appcat: str, apprisk: str, action: str = "pass",
                dport: int = 443) -> str:
        return (f'{self.head(ms, LOGID["app-ctrl"], "utm", "app-ctrl", "information")} eventtype="signature" '
                f'srcip={src} dstip={dst} dstport={dport} service="tcp/{dport}" action="{action}" app="{app}" '
                f'appcat="{appcat}" apprisk="{apprisk}" msg="{appcat}: {app}"')

    def dns(self, ms: int, src: str, dst: str, qname: str) -> str:
        return (f'{self.head(ms, LOGID["dns"], "utm", "dns", "information")} eventtype="dns-response" '
                f'srcip={src} dstip={dst} dstport=53 proto=17 qname="{qname}" qtype="A" action="pass"')

    def virus(self, ms: int, src: str, dst: str, name: str, action: str, hostname: str, url: str) -> str:
        return (f'{self.head(ms, LOGID["virus"], "utm", "virus", "warning")} eventtype="infected" srcip={src} '
                f'dstip={dst} dstport=80 service="HTTP" direction="incoming" action="{action}" virus="{name}" '
                f'hostname="{hostname}" url="{url}" msg="File is infected."')

    def vpn(self, ms: int, user: str, remip: str, tunnelip: str, up: bool = True) -> str:
        what, act = ("SSL VPN tunnel up", "tunnel-up") if up else ("SSL VPN tunnel down", "tunnel-down")
        return (f'{self.head(ms, LOGID["vpn"], "event", "vpn", "information")} logdesc="{what}" action="{act}" '
                f'tunneltype="ssl-tunnel" user="{user}" remip={remip} tunnelip={tunnelip} status="success" '
                f'reason="N/A" msg="{what}"')

    def misc(self, ms: int, sub: str) -> str:
        r = self.rng
        body = {"ha": 'logdesc="HA statistics" msg="HA heartbeat statistics"',
                "connector": 'logdesc="SDN connector updated" msg="Dynamic address updated"',
                "dhcp": f'logdesc="DHCP Ack log" ip=10.10.{r.randint(1, 4)}.{r.randint(10, 250)} '
                        f'mac="00:0c:29:{r.randint(16, 255):02x}:{r.randint(16, 255):02x}:{r.randint(16, 255):02x}" '
                        'msg="DHCP server sends a DHCPACK"',
                "sdwan": 'logdesc="SD-WAN status" member="wan1" msg="SD-WAN member is up"',
                "perf": f'logdesc="System performance statistics" cpu={r.randint(1, 60)} mem={r.randint(20, 70)}'}[sub]
        typ = "event"
        sub_name = "system" if sub == "perf" else sub
        return f'{self.head(ms, LOGID[sub], typ, sub_name, "information")} {body}'


class Noise:
    """Background records with the real tiers' mix. All randomness comes from one seeded stream."""

    def __init__(self, rng: random.Random, fmt: Fmt) -> None:
        self.r, self.f = rng, fmt
        self.cum_mix = list(accumulate(w for _, w in MIX))
        self.kinds = [k for k, _ in MIX]
        self.cum_svc = list(accumulate(SERVICE_W.values()))
        self.svcs = list(SERVICE_W)
        self.cum_act = list(accumulate(w for _, w in TRAFFIC_ACTIONS))
        self.acts = [a for a, _ in TRAFFIC_ACTIONS]
        self.bots = [self.public_ip() for _ in range(4000)]   # internet hosts that hammer the admin login
        self.workstations = [f"10.10.{a}.{b}" for a in range(1, 5) for b in range(10, 60)]

    def public_ip(self) -> str:
        r = self.r
        return f"{r.choice(_PUBLIC_FIRST)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"

    def pick(self, cum: list[float], items: list[str]) -> str:
        return items[bisect(cum, self.r.random() * cum[-1])]

    def line(self, ms: int) -> str:
        r, f = self.r, self.f
        kind = self.pick(self.cum_mix, self.kinds)
        ws = r.choice(self.workstations)
        if kind == "traffic":
            svc = self.pick(self.cum_svc, self.svcs)
            internal = SERVICES[svc][4]
            dst = r.choice(list(SERVERS.values())[:6]) if internal else self.public_ip()
            act = self.pick(self.cum_act, self.acts)
            if act == "deny" and r.random() < 0.5:              # inbound internet noise hitting the WAN
                return f.traffic(ms, self.public_ip(), WAN_IP, r.choice(["SSH", "RDP", "HTTP", "SMB"]), "deny")
            return f.traffic(ms, ws, dst, svc, act, policyid=r.choice([1, 2, 3, 5]))
        if kind == "system":
            x = r.random()
            if x < 0.80:
                return f.admin_login(ms, r.choice(BOT_USERS), r.choice(self.bots), False, "name_invalid")
            if x < 0.88:
                return f.admin_login(ms, "admin", r.choice(self.bots), False, "passwd_invalid")
            return f.misc(ms, "perf")
        if kind == "webfilter":
            return f.webfilter(ms, ws, self.public_ip(), r.choice(WEB_HOSTS), r.choice(CATDESC),
                               "blocked" if r.random() < 0.1 else "passthrough")
        if kind == "ips":
            sev = r.choice(["low", "medium", "high", "critical"])
            return f.ips(ms, self.public_ip(), r.choice([WAN_IP, SERVERS["web"]]), r.choice(IPS_NOISE), sev,
                         "dropped" if r.random() < 0.95 else "reset", r.choice([80, 443]))
        if kind == "app-ctrl":
            app, cat, risk = r.choice(APPS)
            return f.appctrl(ms, ws, self.public_ip(), app, cat, risk, "block" if r.random() < 0.05 else "pass")
        if kind == "dns":
            return f.dns(ms, ws, SERVERS["dc"], r.choice(WEB_HOSTS))
        if kind == "virus":
            return f.virus(ms, ws, self.public_ip(), r.choice(["EICAR_TEST_FILE", "W32/Sim.Noise!tr",
                                                               "JS/Sim.Adware!tr"]), "blocked",
                           "cdn.example.com", "/download/<PLACEHOLDER_FILE>")
        if kind == "vpn":
            return f.vpn(ms, r.choice(EMPLOYEES), self.public_ip(), f"10.212.134.{r.randint(10, 99)}",
                         up=r.random() < 0.6)
        return f.misc(ms, kind)


def run_worker(job: dict) -> dict:
    """One part file of noise, exactly like gen_dataset.run_worker (slice of the clock, byte target)."""
    k, seed = job["k"], job["seed"]
    lo, hi = gd.slice_bounds(job["start_ms"], job["span_ms"], job["workers"], k)
    rng = random.Random(f"fortigate:{seed}:{k}")
    fmt = Fmt(rng, session_base=(k + 1) * 1_000_000_000)
    noise = Noise(rng, fmt)
    part = Path(job["out"]) / f"part-{k}.log"
    target = job["target_bytes"]
    written = events = 0
    step = (hi - lo) / max(1.0, target / 420.0)
    ms, first_ms, last_ms = lo, None, None
    buf, h = bytearray(), hashlib.sha256()
    t0 = time.perf_counter()
    with open(part, "wb", buffering=0) as fh:
        while written < target:
            if events:
                ms = min(hi - 1, ms + int(round(step * rng.uniform(1 - gd.JITTER, 1 + gd.JITTER))))
            line = noise.line(ms).encode("utf-8") + b"\n"
            buf += line
            written += len(line)
            events += 1
            first_ms = ms if first_ms is None else first_ms
            last_ms = ms
            if len(buf) >= gd.BUF_BYTES:
                fh.write(buf)
                h.update(buf)
                buf.clear()
            if events % gd.RECAL == 0:
                remaining = (target - written) / (written / events)
                if remaining >= gd.RECAL:
                    step = max(0.0, (hi - ms) / (remaining + gd.TAIL_MARGIN))
        if buf:
            fh.write(buf)
            h.update(buf)
    return {"k": k, "file": part.name, "bytes": written, "events": events, "sha256": h.hexdigest(),
            "first_ts_ms": first_ms, "last_ts_ms": last_ms, "slice_ms": [lo, hi],
            "wall_s": round(time.perf_counter() - t0, 3)}


def _ids(text: str) -> list[str]:
    t = text.strip().lower()
    if t == "all":
        return list(ALL_SCENARIOS)
    if t == "none":
        return []
    ids = [x.strip().upper() for x in text.split(",") if x.strip()]
    bad = [i for i in ids if i not in ALL_SCENARIOS]
    if bad:
        raise SystemExit(f"unknown scenario ids {bad}")
    return ids


def build(args: argparse.Namespace) -> dict:
    import fortigate_scenarios as fs  # noqa: PLC0415  (tools/fortigate_scenarios.py)

    t0 = time.perf_counter()
    out = Path(args.out)
    target, start_ms = gd.parse_size(args.size), gd.parse_start(args.start)
    span_ms, workers = int(args.days * 86_400_000), max(1, int(args.workers))
    ids = _ids(args.scenarios)
    gd._check_out(out, args.force)
    (out / "ground_truth").mkdir(exist_ok=True)
    per = -(-target // workers)
    jobs = [{"k": k, "workers": workers, "seed": args.seed, "start_ms": start_ms, "span_ms": span_ms,
             "target_bytes": per, "out": str(out)} for k in range(workers)]
    if workers == 1:
        parts = [run_worker(jobs[0])]
    else:
        with mp.get_context("spawn").Pool(workers) as pool:
            parts = pool.map(run_worker, jobs)
    parts.sort(key=lambda p: p["k"])
    lines, attacks = fs.scenario_lines(start_ms, ids, args.seed, int(args.days))
    with open(out / "scenarios.log", "wb") as fh:
        fh.write(b"".join(ln.encode("utf-8") + b"\n" for _, ln in lines))
    with open(out / "ground_truth" / "attacks.json", "w", encoding="utf-8", newline="\n") as fh:
        json.dump(attacks, fh, indent=1)
    wall = time.perf_counter() - t0
    total = sum(p["bytes"] for p in parts)
    manifest = {
        "format": "fortigate_kv",
        "args": {"size": args.size, "out": str(args.out), "seed": args.seed, "workers": workers,
                 "start": args.start, "days": args.days, "scenarios": args.scenarios},
        "devname": DEVNAME, "tz": "+0530", "target_bytes": target, "start_ms": start_ms,
        "end_ms": start_ms + span_ms, "generator_sha256": gd.sha256_file(Path(__file__)),
        "scenarios_sha256": gd.sha256_file(Path(fs.__file__)), "parts": parts, "bytes": total,
        "events": sum(p["events"] for p in parts), "scenario_ids": ids, "scenario_events": len(lines),
        "wall_s": round(wall, 3), "mb_per_s": round(total / (1 << 20) / wall, 2) if wall > 0 else None,
    }
    with open(out / "manifest.json", "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=1)
    return manifest


def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Synthetic FortiGate key=value dataset (DEVELOPMENT.md §15.9).")
    p.add_argument("--size", required=True, help="total part bytes, e.g. 50M, 1G (base 1024)")
    p.add_argument("--out", required=True)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--start", default="2026-10-24T00:00:00Z")
    p.add_argument("--days", type=float, default=7.0)
    p.add_argument("--scenarios", default="all", help="all | none | F1,F3,...")
    p.add_argument("--force", action="store_true", help="delete a non-empty --out first")
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    m = build(make_parser().parse_args(argv))
    log.info("wrote %d bytes, %d events, scenarios=%s (%d lines) in %.1fs (%.1f MB/s)", m["bytes"], m["events"],
             m["scenario_ids"], m["scenario_events"], m["wall_s"], m["mb_per_s"] or 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
