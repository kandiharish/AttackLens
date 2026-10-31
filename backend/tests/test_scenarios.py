"""tools/scenarios.py — TESTING.md §3.2/§3.3, DEVELOPMENT.md §15.5 (exact values on the planted events)."""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import gen_dataset as gd  # noqa: E402
import scenarios as sc  # noqa: E402

START_MS = 1_792_800_000_000          # 2026-10-24T00:00:00Z
MIN, HOUR, DAY, MB = 60_000, 3_600_000, 86_400_000, 1 << 20
LABEL_KEYS = {"threat", "rule", "labels", "labels_extra"}
HEX_ID = re.compile(r"^0x[0-9a-f]{6}$")
EXPECTED = {
    "S1": [("T1110", "Credential Access"), ("T1078", "Initial Access"), ("T1021", "Lateral Movement"),
           ("T1059.001", "Execution"), ("T1087", "Discovery"), ("T1560.001", "Collection"),
           ("T1048", "Exfiltration")],
    "S2": [("T1136", "Persistence"), ("T1098", "Privilege Escalation"), ("T1021", "Lateral Movement"),
           ("T1543.003", "Persistence"), ("T1070.001", "Defense Impairment")],
    "S3": [("T1059.001", "Execution"), ("T1547.001", "Persistence"), ("T1071.001", "Command and Control")],
    "S4": [("T1110.003", "Credential Access"), ("T1078", "Initial Access"), ("T1021.004", "Lateral Movement"),
           ("T1048", "Exfiltration")],
    "S5": [("T1078", "Initial Access"), ("T1486", "Impact")],
}


@pytest.fixture(scope="module")
def built() -> tuple[list[dict], dict]:
    return sc.scenario_events(START_MS)


@pytest.fixture(scope="module")
def gen():
    return gd.load_generator(gd.DEFAULT_GENERATOR, "edr_gen_scen_test")


def ts(e: dict) -> int:
    return gd.parse_start(e["@timestamp"])


def sel(events: list[dict], **kw) -> list[dict]:
    """Filter by dotted ECS paths, e.g. sel(ev, **{"host.name": "SRV-DC-01"})."""
    out = []
    for e in events:
        ok = True
        for path, want in kw.items():
            v = e
            for p in path.split("."):
                v = v.get(p) if isinstance(v, dict) else None
            if v != want:
                ok = False
                break
        if ok:
            out.append(e)
    return out


def steps(attacks: dict, sid: str) -> list[dict]:
    return next(a for a in attacks["attacks"] if a["id"] == sid)["steps"]


def _walk_keys(obj, acc: set) -> set:
    if isinstance(obj, dict):
        for k, v in obj.items():
            acc.add(k)
            _walk_keys(v, acc)
    elif isinstance(obj, list):
        for v in obj:
            _walk_keys(v, acc)
    return acc


# ----------------------------------------------------------------------------- ground truth shape
def test_ground_truth_steps_exact(built) -> None:
    _, at = built
    assert at["attack_version"] == "v20"
    assert [a["id"] for a in at["attacks"]] == ["S1", "S2", "S3", "S4", "S5"]
    assert [len(a["steps"]) for a in at["attacks"]] == [7, 5, 3, 4, 2]
    for a in at["attacks"]:
        assert [(s["technique_id"], s["tactic"]) for s in a["steps"]] == EXPECTED[a["id"]]
        assert [s["step"] for s in a["steps"]] == list(range(1, len(a["steps"]) + 1))
        for s in a["steps"]:
            assert set(s) == {"step", "ts_ms", "technique_id", "tactic", "host", "user", "src_ip", "dst_ip"}
            assert s["host"] == s["host"].lower()
        assert [s["ts_ms"] for s in a["steps"]] == sorted(s["ts_ms"] for s in a["steps"])


def test_scenario_start_times(built) -> None:
    _, at = built
    first = {a["id"]: a["steps"][0]["ts_ms"] for a in at["attacks"]}
    assert first == {"S1": START_MS + 2 * HOUR, "S2": START_MS + DAY + 14 * HOUR + 30 * MIN,
                     "S3": START_MS + 2 * DAY + 9 * HOUR + 10 * MIN, "S4": START_MS + 3 * DAY + 22 * HOUR,
                     "S5": START_MS + 4 * DAY + 3 * HOUR}
    assert first["S1"] == 1_792_807_200_000                 # TESTING.md §3.3 example


def test_gt_ts_is_first_event_of_each_step(built) -> None:
    ev, at = built
    s1, s2, s3, s4, s5 = (steps(at, f"S{i}") for i in range(1, 6))
    first = lambda xs: min(ts(e) for e in xs)  # noqa: E731
    assert s1[0]["ts_ms"] == first(sel(ev, **{"host.name": "SRV-DC-01", "user.name": "svc_backup",
                                              "winlog.event_id": 4625}))
    assert s1[6]["ts_ms"] == first(sel(ev, **{"destination.ip": "198.51.100.23"}))
    assert s2[0]["ts_ms"] == first(sel(ev, **{"winlog.event_id": 4720}))
    assert s3[2]["ts_ms"] == first(sel(ev, **{"destination.domain": "suspicious-example-c2.invalid"}))
    assert s4[0]["ts_ms"] == first(sel(ev, **{"source.ip": "192.0.2.88", "event.outcome": "failure"}))
    assert s5[1]["ts_ms"] == first(sel(ev, **{"event.action": "file_rename"}))


# ----------------------------------------------------------------------------- S1
def test_s1_bruteforce_success_and_lateral(built) -> None:
    ev, at = built
    s = steps(at, "S1")
    fails = sel(ev, **{"host.name": "SRV-DC-01", "winlog.event_id": 4625, "source.ip": "203.0.113.57"})
    assert len(fails) == 60
    assert {f["user"]["name"] for f in fails} == {"svc_backup"}
    assert {f["winlog"]["logon"]["type"] for f in fails} == {"Network"}
    assert max(map(ts, fails)) - min(map(ts, fails)) < 5 * MIN
    ok = sel(ev, **{"host.name": "SRV-DC-01", "winlog.event_id": 4624, "source.ip": "203.0.113.57"})
    assert len(ok) == 1 and ts(ok[0]) == s[1]["ts_ms"] and ts(ok[0]) > max(map(ts, fails))
    assert ok[0]["event"]["outcome"] == "success" and HEX_ID.match(ok[0]["winlog"]["logon"]["id"])
    lat = sel(ev, **{"host.name": "WS-FIN-010", "winlog.event_id": 4624})
    assert len(lat) == 1
    lid = lat[0]["winlog"]["logon"]["id"]
    assert HEX_ID.match(lid) and lat[0]["source"]["ip"] == "10.10.0.10"
    assert lat[0]["winlog"]["logon"]["type"] == "Network" and lat[0]["user"]["name"] == "svc_backup"
    priv = sel(ev, **{"host.name": "WS-FIN-010", "winlog.event_id": 4672})
    assert len(priv) == 1 and priv[0]["winlog"]["logon"]["id"] == lid
    assert priv[0]["event"]["action"] == "special_privileges_assigned"
    assert 0 <= ts(priv[0]) - ts(lat[0]) < 1000


def test_s1_execution_discovery_collection_exfil(built) -> None:
    ev, at = built
    s = steps(at, "S1")
    procs = sel(ev, **{"host.name": "WS-FIN-010", "event.action": "process_created"})
    assert [(p["process"]["name"], p["process"]["parent"]["name"]) for p in procs] == [
        ("powershell.exe", "wmiprvse.exe"), ("net.exe", "powershell.exe"), ("7z.exe", "powershell.exe")]
    assert "-enc" in procs[0]["process"]["command_line"]
    assert 'net group "domain admins"' in procs[1]["process"]["command_line"]
    assert procs[2]["process"]["command_line"].startswith("7z a ")
    assert [ts(p) for p in procs] == [s[3]["ts_ms"], s[4]["ts_ms"], s[5]["ts_ms"]]
    ex = sel(ev, **{"destination.ip": "198.51.100.23"})
    assert len(ex) == 4 and [e["network"]["bytes"] for e in ex] == [25 * MB] * 4
    assert {e["network"]["direction"] for e in ex} == {"outbound"}
    assert {e["host"]["name"] for e in ex} == {"WS-FIN-010"}
    assert max(map(ts, ex)) - min(map(ts, ex)) <= 10 * MIN


# ----------------------------------------------------------------------------- S2
def test_s2_backdoor_chain(built) -> None:
    ev, at = built
    s = steps(at, "S2")
    (c,) = sel(ev, **{"winlog.event_id": 4720})
    assert c["event"]["action"] == "user_created" and c["host"]["name"] == "SRV-DC-01"
    assert c["user"]["name"] == "asharma" and c["user"]["target"]["name"] == "helpdesk_tmp"
    (g,) = sel(ev, **{"winlog.event_id": 4732, "user.target.name": "helpdesk_tmp"})
    assert g["group"]["name"] == "Administrators" and g["user"]["name"] == "asharma"
    assert 0 < ts(g) - ts(c) <= DAY and ts(g) == s[1]["ts_ms"]
    (lg,) = sel(ev, **{"host.name": "SRV-FILE-01", "winlog.event_id": 4624, "user.name": "helpdesk_tmp"})
    (pv,) = sel(ev, **{"host.name": "SRV-FILE-01", "winlog.event_id": 4672, "user.name": "helpdesk_tmp"})
    assert pv["winlog"]["logon"]["id"] == lg["winlog"]["logon"]["id"] and lg["source"]["ip"] == "10.10.0.10"
    (sv,) = sel(ev, **{"winlog.event_id": 7045})
    assert sv["event"]["action"] == "service_installed" and sv["service"]["name"]
    assert sv["process"]["executable"] and ts(sv) == s[3]["ts_ms"]
    (lc,) = sel(ev, **{"winlog.event_id": 1102})
    assert lc["event"]["action"] == "log_cleared" and lc["host"]["name"] == "SRV-FILE-01"
    assert ts(lc) == s[4]["ts_ms"]


# ----------------------------------------------------------------------------- S3
def test_s3_office_runkey_beacons(built) -> None:
    ev, at = built
    s = steps(at, "S3")
    (ps,) = sel(ev, **{"host.name": "WS-HR-012", "process.name": "powershell.exe",
                       "event.action": "process_created"})
    assert ps["process"]["parent"]["name"] == "winword.exe" and ps["user"]["name"] == "pmehta"
    assert ts(ps) == s[0]["ts_ms"]
    (rk,) = sel(ev, **{"host.name": "WS-HR-012", "event.action": "registry_value_set"})
    assert "\\CurrentVersion\\Run" in rk["registry"]["path"] and rk["process"]["name"] == "powershell.exe"
    bc = sel(ev, **{"destination.domain": "suspicious-example-c2.invalid"})
    assert len(bc) == 10 and {b["host"]["name"] for b in bc} == {"WS-HR-012"}
    t = [ts(b) for b in bc]
    gaps = [b - a for a, b in zip(t, t[1:])]
    assert all(54_000 <= g <= 66_000 for g in gaps)        # 60 s +/- 3 s each side
    offs = [x - t[0] - i * MIN for i, x in enumerate(t)]
    assert all(-3000 <= o <= 3000 for o in offs) and offs[0] == 0


# ----------------------------------------------------------------------------- S4
def test_s4_spray_ssh_pivot_exfil(built) -> None:
    ev, at = built
    s = steps(at, "S4")
    sp = sel(ev, **{"source.ip": "192.0.2.88", "event.outcome": "failure"})
    assert len(sp) == 20 and len({e["user"]["name"] for e in sp}) == 20
    assert {e["host"]["name"] for e in sp} == {"SRV-WEB-01"}
    assert max(map(ts, sp)) - min(map(ts, sp)) < 10 * MIN
    for e in sp + sel(ev, **{"process.name": "sshd"}):
        assert e["process"]["name"] == "sshd" and e["destination"]["port"] == 22 and "winlog" not in e
    (ok,) = sel(ev, **{"source.ip": "192.0.2.88", "event.outcome": "success"})
    assert ok["user"]["name"] == "vreddy" and ts(ok) == s[1]["ts_ms"] and ts(ok) > max(map(ts, sp))
    (piv,) = sel(ev, **{"host.name": "SRV-DB-01", "process.name": "sshd"})
    assert piv["source"]["ip"] == "10.10.0.30" and piv["user"]["name"] == "vreddy"
    assert ts(piv) == s[2]["ts_ms"]
    (ex,) = sel(ev, **{"host.name": "SRV-DB-01", "destination.ip": "203.0.113.57"})
    assert ex["network"]["bytes"] == 60 * MB and ex["network"]["direction"] == "outbound"


# ----------------------------------------------------------------------------- S5
def test_s5_logon_and_mass_rename(built) -> None:
    ev, at = built
    s = steps(at, "S5")
    (lg,) = sel(ev, **{"host.name": "SRV-FILE-01", "user.name": "svc_sql", "winlog.event_id": 4624})
    (pv,) = sel(ev, **{"host.name": "SRV-FILE-01", "user.name": "svc_sql", "winlog.event_id": 4672})
    assert lg["winlog"]["logon"]["type"] == "Network" and pv["winlog"]["logon"]["id"] == lg["winlog"]["logon"]["id"]
    rn = sel(ev, **{"event.action": "file_rename"})
    assert len(rn) == 300 and {r["host"]["name"] for r in rn} == {"SRV-FILE-01"}
    assert {r["file"]["extension"] for r in rn} == {"locked"}
    assert all(r["file"]["path"].endswith(".locked") for r in rn)
    assert max(map(ts, rn)) - min(map(ts, rn)) < 60_000 and ts(rn[0]) == s[1]["ts_ms"]


# ----------------------------------------------------------------------------- decoys (near misses)
def test_decoys_present_and_below_thresholds(built) -> None:
    ev, _ = built
    d1 = sel(ev, **{"host.name": "SRV-DC-01", "user.name": "rkumar"})
    assert sorted(e["winlog"]["event_id"] for e in d1) == [4624, 4672]
    assert ts(d1[0]) == START_MS + 10 * HOUR + 15 * MIN
    (d2,) = sel(ev, **{"user.target.name": "jdsouza"})
    assert d2["group"]["name"] == "Backup Operators"
    assert not sel(ev, **{"winlog.event_id": 4720, "user.target.name": "jdsouza"})
    (d3,) = sel(ev, **{"process.name": "splwow64.exe"})
    assert d3["process"]["parent"]["name"] == "winword.exe"
    d4 = sel(ev, **{"host.name": "SRV-FILE-01", "user.name": "kiyer", "event.outcome": "failure"})
    assert len(d4) == 30 and max(map(ts, d4)) - min(map(ts, d4)) > 20 * HOUR
    gaps = sorted(map(ts, d4))
    assert all(b - a > 10 * MIN for a, b in zip(gaps, gaps[1:]))          # never a burst
    (d5,) = sel(ev, **{"destination.ip": "10.10.0.40", "destination.port": 445})
    assert d5["network"]["bytes"] == 40 * MB and d5["user"]["name"] == "svc_backup"


# ----------------------------------------------------------------------------- hygiene
def test_no_labels_and_generator_schema(built, gen) -> None:
    ev, _ = built
    base_keys = set(gen.base_event(gen.HOSTS[0], "rkumar", "process", "start", "process_created"))
    for e in ev:
        assert not (_walk_keys(e, set()) & LABEL_KEYS)
        assert base_keys <= set(e)
        assert e["event"]["kind"] == "event" and e["event"]["severity"] == 0
        assert e["user"]["domain"] == "CORP"
    blob = "\n".join(json.dumps(e) for e in ev)
    assert '"threat"' not in blob and '"labels' not in blob and '"rule"' not in blob


def test_entities_and_addresses_are_synthetic(built, gen) -> None:
    ev, at = built
    hosts = {h["name"] for h in gen.HOSTS}
    users = set(gen.USERS) | {"helpdesk_tmp"} | set(sc.SPRAY_EXTRA)
    doc_nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    gen_ips = {h["ip"] for h in gen.HOSTS}

    def ok_ip(ip: str) -> bool:
        a = ipaddress.ip_address(ip)
        return ip in gen_ips or any(a in n for n in doc_nets)

    for e in ev:
        assert e["host"]["name"] in hosts and e["user"]["name"] in users
        for k in ("source", "destination"):
            if "ip" in e.get(k, {}):
                assert ok_ip(e[k]["ip"]), e[k]["ip"]
            if "domain" in e.get(k, {}):
                assert e[k]["domain"].endswith((".invalid", ".test", ".example"))
        cmd = e.get("process", {}).get("command_line", "")
        assert not re.search(r"[A-Za-z0-9+/=]{24,}", cmd), cmd        # placeholders only, no payloads
    for a in at["attacks"]:
        for s in a["steps"]:
            assert s["host"].upper() in hosts
            for ip in (s["src_ip"], s["dst_ip"]):
                assert ip is None or ok_ip(ip)


def test_sorted_deterministic_and_filterable(built) -> None:
    ev, at = built
    t = [ts(e) for e in ev]
    assert t == sorted(t)
    ev2, at2 = sc.scenario_events(START_MS)
    assert ev2 == ev and at2 == at
    ev3, at3 = sc.scenario_events(START_MS, seed=7)
    assert at3 == at and [e["event"]["id"] for e in ev3] != [e["event"]["id"] for e in ev]
    only, at_only = sc.scenario_events(START_MS, ids=["S3"])
    assert [a["id"] for a in at_only["attacks"]] == ["S3"]
    assert at_only["attacks"][0]["steps"] == steps(at, "S3")
    assert len(only) == 1 + 1 + 1 + 10 + 1                   # winword ctx, ps, run key, 10 beacons, decoy
    shifted, at_s = sc.scenario_events(START_MS + DAY)
    assert [s["ts_ms"] - DAY for s in steps(at_s, "S1")] == [s["ts_ms"] for s in steps(at, "S1")]


def test_scenario_events_do_not_disturb_global_random() -> None:
    import random
    random.seed(123)
    a = random.random()
    random.seed(123)
    sc.scenario_events(START_MS, ids=["S5"])
    assert random.random() == a


# ----------------------------------------------------------------------------- via gen_dataset
def test_gen_dataset_writes_identical_scenarios_for_every_size(tmp_path) -> None:
    outs = []
    for size in ("32K", "160K"):
        out = tmp_path / size
        argv = ["--size", size, "--out", str(out), "--alert-ratio", "0"]
        m = gd.build(gd.make_parser().parse_args(argv))
        assert m["scenario_ids"] == ["S1", "S2", "S3", "S4", "S5"]
        outs.append(out)
    a, b = ((o / "scenarios.jsonl").read_bytes() for o in outs)
    assert a == b and b"\r" not in a and a.endswith(b"\n")
    ga, gb = (json.loads((o / "ground_truth" / "attacks.json").read_text()) for o in outs)
    assert ga == gb == sc.scenario_events(START_MS)[1]
    m = json.loads((outs[0] / "manifest.json").read_text())
    assert m["scenario_events"] == a.count(b"\n") == len(sc.scenario_events(START_MS)[0])
    for tok in (b'"threat"', b'"labels"', b'"labels_extra"', b'"rule"'):
        assert tok not in a
