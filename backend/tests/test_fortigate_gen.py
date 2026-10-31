"""tools/fortigate_gen.py + tools/fortigate_scenarios.py (DEVELOPMENT.md §15.9): format, clock, size target,
reproducibility, distribution, noise realism, planted steps vs ground truth, label hygiene."""

from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import fortigate_gen as fg  # noqa: E402
import fortigate_scenarios as fsc  # noqa: E402

KV = re.compile(r'(\w+)=("[^"]*"|\S+)')
HEAD = ["date", "time", "devname", "devid", "eventtime", "tz", "logid", "type", "subtype", "level", "vd"]
ALLOWED = set(HEAD) | {
    "srcip", "srcport", "srcintf", "srcintfrole", "dstip", "dstport", "dstintf", "dstintfrole", "srccountry",
    "dstcountry", "sessionid", "proto", "action", "policyid", "policytype", "service", "trandisp", "duration",
    "sentbyte", "rcvdbyte", "sentpkt", "rcvdpkt", "appcat", "app", "apprisk", "logdesc", "sn", "user", "ui",
    "method", "status", "reason", "profile", "msg", "cfgtid", "cfgpath", "cfgobj", "cfgattr", "eventtype",
    "severity", "direction", "attack", "attackid", "url", "hostname", "catdesc", "qname", "qtype", "virus",
    "tunneltype", "remip", "tunnelip", "ip", "mac", "member", "cpu", "mem"}
START_MS = 1_792_800_000_000  # 2026-10-24T00:00:00Z
MIN, DAY = 60_000, 86_400_000


def parse(line: str) -> dict[str, str]:
    return {k: v.strip('"') for k, v in KV.findall(line)}


def gen(out: Path, size: str = "2M", workers: int = 2, seed: int = 42, extra: list[str] | None = None) -> dict:
    return fg.build(fg.make_parser().parse_args(["--size", size, "--out", str(out), "--workers", str(workers),
                                                 "--seed", str(seed), *(extra or [])]))


def records(path: Path) -> list[dict[str, str]]:
    return [parse(ln) for ln in path.read_text(encoding="utf-8").splitlines()]


def ms(r: dict[str, str]) -> int:
    return int(r["eventtime"]) // 1_000_000


@pytest.fixture(scope="module")
def ds(tmp_path_factory: pytest.TempPathFactory) -> dict:
    out = tmp_path_factory.mktemp("fg") / "set"
    m = gen(out)
    noise = [r for p in m["parts"] for r in records(out / p["file"])]
    scen = records(out / "scenarios.log")
    gt = json.loads((out / "ground_truth" / "attacks.json").read_text(encoding="utf-8"))
    return {"out": out, "m": m, "noise": noise, "scen": scen, "gt": gt}


# ---------------------------------------------------------------- format + clock
def test_size_target_and_manifest(ds) -> None:
    m = ds["m"]
    assert m["bytes"] >= 2 * (1 << 20) and m["format"] == "fortigate_kv"
    assert m["bytes"] == sum(p["bytes"] for p in m["parts"]) == sum(
        (ds["out"] / p["file"]).stat().st_size for p in m["parts"])
    assert m["events"] == len(ds["noise"]) and m["scenario_events"] == len(ds["scen"])
    assert m["scenario_ids"] == ["F1", "F2", "F3", "F4"] and m["mb_per_s"] > 0


def test_lf_only_and_every_line_parses(ds) -> None:
    for f in [*(ds["out"] / p["file"] for p in ds["m"]["parts"]), ds["out"] / "scenarios.log"]:
        b = f.read_bytes()
        assert b"\r" not in b and b.endswith(b"\n")
        for ln in b.decode("utf-8").splitlines():
            assert [k for k, _ in KV.findall(ln)][:len(HEAD)] == HEAD, ln[:120]
            assert KV.sub("", ln).strip() == "", ln[:200]  # nothing outside key=value pairs


def test_only_known_keys_and_constant_device(ds) -> None:
    keys = {k for r in ds["noise"] + ds["scen"] for k in r}
    assert keys <= ALLOWED, sorted(keys - ALLOWED)
    for r in ds["noise"] + ds["scen"]:
        assert (r["devname"], r["devid"], r["tz"], r["vd"]) == ("FGT60FTK-SIM", "FGT60FTK00000001", "+0530", "root")


def test_local_date_time_equals_eventtime_plus_0530(ds) -> None:
    for r in ds["noise"][:3000] + ds["scen"]:
        sec = int(r["eventtime"]) // 1_000_000_000
        assert time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(sec + 19_800)) == f'{r["date"]} {r["time"]}'


def test_noise_clock_monotonic_per_part_and_covers_slice(tmp_path: Path) -> None:
    m = gen(tmp_path / "s", size="512K", workers=2)
    for p in m["parts"]:
        t = [ms(r) for r in records(tmp_path / "s" / p["file"])]
        assert t == sorted(t) and p["slice_ms"][0] <= t[0] and t[-1] < p["slice_ms"][1]
        assert t[-1] - t[0] > 0.9 * (p["slice_ms"][1] - p["slice_ms"][0])


def test_same_seed_identical_bytes_other_seed_differs(tmp_path: Path) -> None:
    a, b = gen(tmp_path / "a", "256K"), gen(tmp_path / "b", "256K")
    c = gen(tmp_path / "c", "256K", seed=7)
    assert [p["sha256"] for p in a["parts"]] == [p["sha256"] for p in b["parts"]]
    assert [p["sha256"] for p in a["parts"]] != [p["sha256"] for p in c["parts"]]
    for f in ("scenarios.log", "ground_truth/attacks.json"):
        assert (tmp_path / "a" / f).read_bytes() == (tmp_path / "b" / f).read_bytes()


def test_force_required_for_non_empty_out(tmp_path: Path) -> None:
    gen(tmp_path / "x", "64K", workers=1)
    with pytest.raises(SystemExit):
        gen(tmp_path / "x", "64K", workers=1)
    assert gen(tmp_path / "x", "64K", workers=1, extra=["--force"])["bytes"] >= 64 * 1024


# ---------------------------------------------------------------- distribution + noise realism
def test_type_subtype_mix_matches_profile(ds) -> None:
    n = len(ds["noise"])
    share = {k: 100 * v / n for k, v in Counter((r["type"], r["subtype"]) for r in ds["noise"]).items()}
    assert abs(share[("traffic", "forward")] - 64) < 4
    assert abs(share[("event", "system")] - 16) < 3
    for k, want in ((("utm", "webfilter"), 4.5), (("utm", "ips"), 3), (("utm", "app-ctrl"), 3), (("utm", "dns"), 3),
                    (("utm", "virus"), 1.5), (("event", "vpn"), 1.5), (("event", "ha"), 1),
                    (("event", "connector"), 1), (("event", "dhcp"), 1), (("event", "sdwan"), 0.5)):
        assert 0.3 * want < share.get(k, 0) < 2.0 * want, (k, share.get(k))


def test_traffic_actions_and_services(ds) -> None:
    tr = [r for r in ds["noise"] if r["type"] == "traffic"]
    act = Counter(r["action"] for r in tr)
    assert act.most_common(1)[0][0] == "accept" and 3 < 100 * act["deny"] / len(tr) < 12
    assert {"close", "timeout"} <= set(act)
    assert set(fg.SERVICE_W) <= {r["service"] for r in tr}
    assert len({r["sessionid"] for r in tr}) == len(tr)


def test_admin_login_failed_noise_from_many_ips(ds) -> None:
    fails = [r for r in ds["noise"] if r.get("logdesc") == "Admin login failed"]
    sysrows = [r for r in ds["noise"] if r["subtype"] == "system"]
    assert len(fails) > 0.8 * len(sysrows)
    assert Counter(r["reason"] for r in fails).most_common(1)[0][0] == "name_invalid"
    assert len({r["srcip"] for r in fails}) > 0.5 * len(fails)  # internet background: many sources, few tries each
    per_ip = defaultdict(list)
    for r in fails:
        per_ip[r["srcip"]].append(ms(r))
    for ip, ts in per_ip.items():  # no noise IP looks like the planted 60-in-5-min brute force
        ts.sort()
        assert all(ts[i + 9] - ts[i] > 10 * MIN for i in range(len(ts) - 9)), ip


def test_ips_noise_is_blocked(ds) -> None:
    ips = [r for r in ds["noise"] if r["subtype"] == "ips"]
    assert ips and {r["action"] for r in ips} <= {"dropped", "reset"}
    assert Counter(r["action"] for r in ips)["dropped"] > 0.8 * len(ips)


def test_noise_never_uses_planted_attacker_space(ds) -> None:
    doc = ("192.0.2.", "198.51.100.", "203.0.113.")
    for r in ds["noise"]:
        for k in ("srcip", "dstip", "remip"):
            assert not r.get(k, "").startswith(doc), r


# ---------------------------------------------------------------- scenarios vs ground truth
def test_ground_truth_step_counts_and_order(ds) -> None:
    at = {a["id"]: a for a in ds["gt"]["attacks"]}
    assert ds["gt"]["attack_version"] == "v20" and list(at) == ["F1", "F2", "F3"]  # F4 is a decoy
    assert [len(at[i]["steps"]) for i in at] == [6, 4, 3]
    scen_ts = {ms(r) for r in ds["scen"]}
    for a in at.values():
        ts = [s["ts_ms"] for s in a["steps"]]
        assert ts == sorted(ts) and set(ts) <= scen_ts  # every step time is a planted record's time
        assert [s["step"] for s in a["steps"]] == list(range(1, len(ts) + 1))


def _steps(ds, sid: str) -> list[dict]:
    return next(a for a in ds["gt"]["attacks"] if a["id"] == sid)["steps"]


def test_f1_records(ds) -> None:
    s = _steps(ds, "F1")
    sc = ds["scen"]
    fails = sorted(ms(r) for r in sc if r.get("logdesc") == "Admin login failed" and r["srcip"] == fsc.F1_IP)
    assert len(fails) == 60 and fails[0] == s[0]["ts_ms"] and fails[-1] - fails[0] <= 5 * MIN
    ok = [r for r in sc if r.get("logdesc") == "Admin login successful" and r["srcip"] == fsc.F1_IP]
    assert [ms(r) for r in ok] == [s[1]["ts_ms"]] and ok[0]["user"] == "admin"
    cfg = [r for r in sc if r.get("cfgpath") == "firewall.policy" and fsc.F1_IP in r["ui"]]
    assert [ms(r) for r in cfg] == [s[2]["ts_ms"]]
    rdp = [r for r in sc if r.get("service") == "RDP" and r["srcip"] == fsc.F1_IP]
    assert [ms(r) for r in rdp] == [s[3]["ts_ms"]] and rdp[0]["action"] == "accept" and rdp[0]["srcintfrole"] == "wan"
    smb = [r for r in sc if r.get("service") == "SMB" and r["srcip"] == fg.SERVERS["app"]]
    assert [ms(r) for r in smb] == [s[4]["ts_ms"]] and smb[0]["dstip"] == fg.SERVERS["file"]
    up = [r for r in sc if r.get("dstip") == fsc.F1_EXFIL]
    assert [ms(r) for r in up] == [s[5]["ts_ms"]] and int(up[0]["sentbyte"]) >= 200 * (1 << 20)
    assert s[0]["host"] == s[1]["host"] == s[2]["host"] == "FGT60FTK-SIM" and s[3]["host"] == fg.SERVERS["app"]


def test_f2_records(ds) -> None:
    s = _steps(ds, "F2")
    sc = ds["scen"]
    hit = [r for r in sc if r.get("subtype") == "ips" and r["srcip"] == fsc.F2_IP]
    assert [ms(r) for r in hit] == [s[0]["ts_ms"]] and hit[0]["action"] == fg.IPS_PASS_ACTION
    assert "<PLACEHOLDER" in hit[0]["url"]
    vpn = [r for r in sc if r.get("subtype") == "vpn" and r["remip"] == fsc.F2_IP]
    assert [ms(r) for r in vpn] == [s[1]["ts_ms"]] and vpn[0]["user"] == "vpnuser"
    assert vpn[0]["tunnelip"] == fsc.F2_TUNNEL
    scan = [r for r in sc if r.get("srcip") == fsc.F2_TUNNEL and r.get("dstip") == fg.SERVERS["file"]]
    t = sorted(ms(r) for r in scan)
    assert len({r["dstport"] for r in scan}) == 30 and t[-1] - t[0] < 60_000 and t[0] == s[2]["ts_ms"]
    winrm = [r for r in sc if r.get("dstport") == "5985" and r.get("srcip") == fsc.F2_TUNNEL
             and r["dstip"] == fg.SERVERS["dc"]]
    assert [ms(r) for r in winrm] == [s[3]["ts_ms"]] and winrm[0]["action"] == "accept"


def test_f3_records(ds) -> None:
    s = _steps(ds, "F3")
    sc = ds["scen"]
    av = [r for r in sc if r.get("subtype") == "virus" and r["srcip"] == fsc.F3_HOST]
    assert [ms(r) for r in av] == [s[0]["ts_ms"]] and av[0]["virus"] == "W32/Sim.Test!tr"
    bc = sorted(ms(r) for r in sc if r.get("dstip") == fsc.F3_C2)
    gaps = [b - a for a, b in zip(bc, bc[1:])]
    assert len(bc) >= 10 and bc[0] == s[1]["ts_ms"] and all(54_000 <= g <= 66_000 for g in gaps)
    tor = [r for r in sc if r.get("app") == "Tor"]
    assert [ms(r) for r in tor] == [s[2]["ts_ms"]] and tor[0]["srcip"] == fsc.F3_HOST


def test_f4_decoy_and_context_not_in_ground_truth(ds) -> None:
    sc = ds["scen"]
    adm = [r for r in sc if r.get("logdesc") == "Admin login successful" and r["srcip"] == fg.SERVERS["admin"]]
    days = {(ms(r) - START_MS) // DAY for r in adm}
    assert days == set(range(7)) and all(9 <= (ms(r) % DAY) // 3_600_000 < 12 for r in adm)
    edits = [r for r in sc if r.get("logdesc") == "Object attribute configured" and fg.SERVERS["admin"] in r["ui"]]
    assert len(edits) == 14 and all(9 <= (ms(r) % DAY) // 3_600_000 < 12 for r in edits)
    gt_ips = {x for a in ds["gt"]["attacks"] for s in a["steps"] for x in (s["src_ip"], s["dst_ip"]) if x}
    assert fg.SERVERS["admin"] not in gt_ips


def test_scenarios_filterable(tmp_path: Path) -> None:
    lines, at = fsc.scenario_lines(START_MS, ["F3"], 42)
    assert [a["id"] for a in at["attacks"]] == ["F3"]
    assert not any("Admin login successful" in ln and "10.10.99.10" in ln for _, ln in lines)  # no F4 decoy
    assert fsc.scenario_lines(START_MS, [], 42) == ([], {"attack_version": "v20", "attacks": []})


# ---------------------------------------------------------------- hygiene
def test_no_label_fields_or_technique_ids_in_logs(ds) -> None:
    for r in ds["noise"] + ds["scen"]:
        assert not ({"threat", "labels", "labels_extra", "rule", "technique", "tactic", "mitre"} & set(r))
    for f in [*(ds["out"] / p["file"] for p in ds["m"]["parts"]), ds["out"] / "scenarios.log"]:
        assert not re.search(r"\bT1\d{3}\b|TA00\d\d", f.read_text(encoding="utf-8")), f.name


def test_content_is_inert(ds) -> None:
    for r in ds["noise"] + ds["scen"]:
        if "virus" in r:
            assert "Sim" in r["virus"] or r["virus"] == "EICAR_TEST_FILE"
        if "attack" in r:
            assert r["attack"].startswith("Sim.")
        if "url" in r:
            assert r["url"] == "/" or "<PLACEHOLDER" in r["url"]
