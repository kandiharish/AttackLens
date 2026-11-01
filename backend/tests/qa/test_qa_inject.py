"""QA track qa_injection: tools/qa/inject.py + tools/qa/inject_scan.py on a tiny synthetic background, plus the product
bug the injection found on the real n10 slice (QAINJ-1), reproduced at Stage 3/4 from hand-checked episodes.

Background (hand-built, 14 h from T0, organiser-like header order date/time/eventtime/tz/devname/...; eventtime is
local time written as UTC ns, like the real tiers): one traffic line every 10 min (85), +60 lines in hour 12, 3 lines
with srcip=10.10.20.15, 2 admin login failures, 1 line touching 10.77.5.5 -> busiest 12 h window starts at T0 + 1 h,
net 10.77 is taken, so the isolated remap uses 10.78 (10.10.x) and 10.79 (10.212.x).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

import duckdb
import pytest

from attacklens import config, incidents, link
from attacklens.ingest_sql import kv_select
from eval.harness import load_ground_truth
from tests.conftest import make_events_parquet, write_episodes

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools" / "qa"))
import inject  # noqa: E402
import inject_scan as isc  # noqa: E402

MIN, H = 60_000, 3_600_000
T0 = 1_792_900_800_000                       # 2026-10-26T04:00:00Z, hour-aligned
OFF = 19_800_000                             # +05:30
KCFG = config.load_config()["sources"]["kv_sources"]["fortigate_kv"]
HEAD_ORDER = ["date", "time", "eventtime", "tz", "devname", "devid", "logid", "type", "subtype", "level", "vd"]


def _bg_line(t: int, body: str) -> str:
    loc = t + OFF
    d, c = time.strftime("%Y-%m-%d", time.gmtime(loc // 1000)), time.strftime("%H:%M:%S", time.gmtime(loc // 1000))
    return (f'date={d} time={c} eventtime={loc * 1_000_000 + 123} tz="+0530" devname="BGDEV01" '
            f'devid="BGDEV0000000001" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
            f"{body}")


def write_background(path: Path) -> list[int]:
    ts = [T0 + k * 10 * MIN for k in range(85)] + [T0 + 12 * H + k * MIN for k in range(60)]
    rows = [(t, 'srcip=10.20.1.5 dstip=10.20.0.2 dstport=53 action="accept" service="DNS"') for t in ts]
    rows += [(T0 + 30 * MIN + k, 'srcip=10.10.20.15 dstip=10.20.0.2 dstport=53 action="accept"') for k in range(3)]
    rows += [(T0 + 40 * MIN + k, 'logdesc="Admin login failed" user="admin" srcip=198.51.100.200 action="login" '
              'status="failed"') for k in range(2)]
    rows.append((T0 + 50 * MIN, 'srcip=10.20.1.5 dstip=10.77.5.5 dstport=443 action="accept"'))
    rows.sort()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes("".join(_bg_line(t, b) + "\n" for t, b in rows).encode())
    return [t for t, _ in rows]


def product_ts(path: Path) -> list[tuple[str, int]]:
    """(line, ts_ms) exactly as AttackLens Stage 1 computes it (kv_select from config/sources.yaml)."""
    con = duckdb.connect()
    try:
        con.execute("SET TimeZone='UTC'")
        sql = kv_select("fortigate_kv", [path.as_posix()], path.parent.as_posix(), KCFG)
        return [(ln, int(t)) for ln, t in con.execute(f"SELECT line, ts_ms FROM ({sql})").fetchall()]
    finally:
        con.close()


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> dict:
    root = tmp_path_factory.mktemp("qainj")
    bg = root / "real" / "fw.log"
    bg_ts = write_background(bg)
    m = inject.make_set("tiny", bg, root, seed=7, tmp=root / "tmp")
    return {"root": root, "bg": bg, "bg_ts": bg_ts, "m": m, "out": root / "tiny_inj"}


# ---------------------------------------------------------------- timestamp convention mirror == product SQL
def test_product_ts_mirror_matches_kv_select_exact(tmp_path: Path) -> None:
    n = 1_792_767_000_000                    # naive 2026-10-23 14:50:00 written as if UTC
    lines = [
        f'date=2026-10-23 time=14:50:00 eventtime={n * 1_000_000 + 891_763} tz="+0530" x=1',   # local ns
        f'date=2026-10-23 time=14:50:00 eventtime={(n - OFF + 7) * 1_000_000} tz="+0530" x=2',  # UTC ns
        f'date=2026-10-23 time=14:50:00 eventtime={n + 250} tz="+05:30" x=3',                   # local ms, colon tz
        f'date=2026-10-23 time=14:50:00 eventtime={n // 1000} tz="-0400" x=4',                  # local s, west
        'date=2026-10-23 time=14:50:00 tz="+0530" x=5',                                         # no eventtime
        f'date=2026-10-23 time=14:50:00 eventtime={n * 1000 + 5} x=6',                          # us, no tz
    ]
    p = tmp_path / "ts.log"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    got = dict(product_ts(p))
    want = [n - OFF, n - OFF + 7, n - OFF + 250, n + 4 * H, n - OFF, n]
    assert [got[ln] for ln in lines] == want
    assert [isc.line_ts(ln, True) for ln in lines] == want
    # near-miss: with eventtime_is_local off the local-ns line is taken at face value (5 h 30 m late)
    assert isc.line_ts(lines[0], False) == n


# ---------------------------------------------------------------- scan (aggregates only)
def test_scan_exact_aggregates(built: dict) -> None:
    s = built["m"]["scan"]
    assert (s["rows_read"], s["rows_ok"], s["rows_valid_ts"]) == (151, 151, 151)
    assert s["conventions"] == {"local": 151} and s["eventtime_digits"] == {"19": 151}
    assert s["tz_values"] == {"+0530": 151} and s["line_ending"] == "lf"
    assert s["header_keys"] == HEAD_ORDER and s["devname_lowercase"] is False
    assert s["header_quoted"] == {k: k not in ("date", "time", "eventtime") for k in isc.GEN_HEAD}
    assert (s["ts_min_ms"], s["ts_max_ms"]) == (T0, T0 + 14 * H)
    col = s["collisions"]
    assert (col["ip:10.10.20.15"], col["ip:10.10.99.10"], col["user:admin"], col["user:qa_fwadm"]) == (3, 0, 2, 0)
    assert col["devname:qainj"] == 0 and s["private_nets_seen"] == ["10.10", "10.20", "10.77"]
    # /24 probe: only the thirds the remap writes (0 2 20 30 40 99 134); 10.20.1.5 / 10.77.5.5 are not probed
    assert s["private_24_thirds"] == [0, 2, 20, 30, 40, 99, 134]
    assert s["private_24_seen"] == ["10.10.20", "10.20.0"]
    assert col["ip:198.51.100.1"] == 0 and col["ip:192.0.2.11"] == 0 and len(inject.EXT_POOL) == 18
    assert not [k for k in col if k.startswith("net:")]


def test_free_prefixes_fall_back_past_busy_10_nets() -> None:
    style = {"collisions": {"user:qa_fwadm": 0, "user:qa_vpnusr": 0, "devname:qainj": 0}}
    internal = ["10.10.0.10", "10.10.20.15", "10.212.134.200"]
    ips, users = inject.entity_map({**style, "private_nets_seen": ["10.77", "10.79"]}, internal, "isolated")
    assert ips == {"10.10.0.10": "10.78.0.10", "10.10.20.15": "10.78.20.15", "10.212.134.200": "10.83.134.200"}
    every10 = [f"10.{o}" for o in range(256)]
    ips, _ = inject.entity_map({**style, "private_nets_seen": every10 + ["172.16"]}, internal, "isolated")
    assert ips["10.10.20.15"] == "172.17.20.15" and ips["10.212.134.200"] == "172.18.134.200"
    with pytest.raises(SystemExit):                     # near-miss: one /16 left, two needed, no /24 probe
        inject.entity_map({**style, "private_nets_seen": every10 + [f"172.{o}" for o in range(16, 31)] + ["192.168"]},
                          internal, "isolated")
    with pytest.raises(SystemExit):                     # a synthetic user already in the background
        inject.entity_map({**style, "collisions": {**style["collisions"], "user:qa_fwadm": 4},
                           "private_nets_seen": []}, internal, "isolated")


ALL16 = [f"10.{o}" for o in range(256)] + [f"172.{o}" for o in range(16, 32)] + ["192.168"]
INTERNAL = ["10.10.0.10", "10.10.2.37", "10.10.20.15", "10.10.30.5", "10.10.40.5", "10.10.99.10", "10.212.134.200"]


def test_map_nets_falls_back_to_free_24s_when_every_16_is_used() -> None:
    """n30 / n50 case: every private /16 is used. Level 24 keeps the first candidate /16 (10.77) when none of the
    remapped /24s occurs; 10.212.134.x shares it (its /24 differs)."""
    ips, lv = inject.map_nets(INTERNAL, ALL16, [])
    assert lv == {"10.10": "24", "10.212": "24"}
    assert ips == {"10.10.0.10": "10.77.0.10", "10.10.2.37": "10.77.2.37", "10.10.20.15": "10.77.20.15",
                   "10.10.30.5": "10.77.30.5", "10.10.40.5": "10.77.40.5", "10.10.99.10": "10.77.99.10",
                   "10.212.134.200": "10.77.134.200"}
    # near-miss: one remapped /24 (10.77.20) is busy -> 10.10.x moves to 10.78, 10.212.134.x stays in 10.77
    ips, _ = inject.map_nets(INTERNAL, ALL16, ["10.77.20", "10.78.134"])
    assert ips["10.10.20.15"] == "10.78.20.15" and ips["10.212.134.200"] == "10.77.134.200"
    # auto prefers a wholly unused /16 when one exists (n10 / slice behaviour unchanged)
    ips, lv = inject.map_nets(INTERNAL, ALL16[:-2], [])
    assert lv == {"10.10": "16", "10.212": "16"}
    assert ips["10.10.20.15"] == "172.31.20.15" and ips["10.212.134.200"] == "192.168.134.200"
    with pytest.raises(SystemExit):                     # every probed /24 busy everywhere
        inject.map_nets(INTERNAL, ALL16, [f"{p}.{t}" for p in ALL16 for t in (0, 134)])


def test_map_nets_busy24_prefers_used_16s() -> None:
    ips, lv = inject.map_nets(INTERNAL, ["10.10", "10.20", "10.91"], [], nets="busy24")
    assert lv == {"10.10": "24", "10.212": "24"} and ips["10.10.20.15"] == "10.91.20.15"
    assert ips["10.212.134.200"] == "10.91.134.200"
    ips, _ = inject.map_nets(INTERNAL, ["10.10", "10.20", "10.91"], ["10.91.134"], nets="busy24")
    assert ips["10.212.134.200"] == "10.20.134.200"      # near-miss: 10.91.134 busy -> next used /16


def test_map_external_swaps_busy_rfc5737_ips() -> None:
    ext = ["198.51.100.1", "203.0.113.66"]
    col = {f"ip:{x}": 0 for x in inject.EXT_POOL} | {"ip:198.51.100.1": 1, "ip:203.0.113.66": 0}
    assert inject.map_external(ext, col) == {"198.51.100.1": "192.0.2.11"}
    assert inject.map_external(ext, {**col, "ip:192.0.2.11": 2}) == {"198.51.100.1": "192.0.2.23"}
    assert inject.map_external(ext, {**col, "ip:198.51.100.1": 0}) == {}       # near-miss: not in background
    with pytest.raises(SystemExit):
        inject.map_external(ext, {"ip:198.51.100.1": 1, "ip:203.0.113.66": 0})  # pool not probed -> busy


def test_busy24_end_to_end_on_tiny_background(tmp_path: Path) -> None:
    """The scan's /24 SQL + remap into a /16 the background uses (10.77 has 10.77.5.5) without touching its /24s."""
    bg = tmp_path / "real" / "fw.log"
    write_background(bg)
    m = inject.make_set("b24", bg, tmp_path, seed=7, tmp=tmp_path / "tmp", nets="busy24")
    assert m["nets_mode"] == "busy24" and m["net_level"] == {"10.10": "24", "10.212": "24"}
    assert m["ip_map"]["10.10.20.15"] == "10.77.20.15" and m["ip_map"]["10.212.134.200"] == "10.77.134.200"
    bg_text = bg.read_text(encoding="utf-8")
    assert "10.77.5.5" in bg_text and not [ip for ip in m["ip_map"].values() if ip in bg_text]
    text = (tmp_path / "b24_inj" / "attack_inject.log").read_text(encoding="utf-8")
    assert "10.77.20.15" in text and "10.10." not in text and "10.212." not in text


def test_choose_window_exact_and_short_span() -> None:
    hist = [(T0 // H + i, 6) for i in range(14)] + [(T0 // H + 14, 1)]
    hist[12] = (T0 // H + 12, 66)
    w = isc.choose_window(hist, T0, T0 + 14 * H, inject.WINDOW_MS, inject.SPAN_MS)
    assert w == {"w0_ms": T0 + H, "w1_ms": T0 + 13 * H, "background_rows_in_window": 132, "fits": True}
    short = isc.choose_window([(T0 // H, 50)], T0 + 90_001, T0 + 2 * H, inject.WINDOW_MS, inject.SPAN_MS)
    assert short["fits"] is False and short["w0_ms"] == T0 + 60_000
    with pytest.raises(SystemExit):
        isc.choose_window([], None, None, inject.WINDOW_MS, inject.SPAN_MS)


# ---------------------------------------------------------------- the set directory
def test_background_is_a_hard_link_not_a_copy(built: dict) -> None:
    out, bg = built["out"], built["bg"]
    linked = out / bg.name
    assert os.path.samefile(bg, linked) and os.stat(linked).st_nlink == 2
    assert built["m"]["background"] == {"mode": "hardlink", "src": bg.as_posix(), "dst": "fw.log",
                                        "bytes": bg.stat().st_size, "st_nlink": 2}
    files = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    assert files == ["attack_inject.log", "fw.log", "ground_truth/attacks.json", "manifest.json"]


def test_link_failure_aborts_without_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bg = tmp_path / "real" / "fw.log"
    write_background(bg)

    def no_link(*_a: object) -> None:
        raise OSError("cross-device link")
    monkeypatch.setattr(inject.os, "link", no_link)
    with pytest.raises(OSError):
        inject.make_set("nolink", bg, tmp_path, tmp=tmp_path / "tmp")
    assert not (tmp_path / "nolink_inj" / "fw.log").exists()


def test_prepare_refuses_non_inj_and_existing(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        inject._prepare(tmp_path / "n10", force=True)
    (tmp_path / "x_inj").mkdir()
    with pytest.raises(SystemExit):
        inject._prepare(tmp_path / "x_inj", force=False)


def test_ground_truth_schema_and_exact_anchors(built: dict) -> None:
    gt_path = built["out"] / "ground_truth" / "attacks.json"
    doc, steps = load_ground_truth(gt_path)
    assert doc["attack_version"] == "v20" and [a["id"] for a in doc["attacks"]] == ["F1", "F2", "F3"]
    assert len(steps) == 13 == built["m"]["counts"]["gt_steps"]
    for a in doc["attacks"]:
        assert [s["step"] for s in a["steps"]] == list(range(1, len(a["steps"]) + 1))
        for s in a["steps"]:
            assert set(s) == {"step", "ts_ms", "technique_id", "tactic", "host", "user", "src_ip", "dst_ip"}
    tech = [s["technique_id"] for a in doc["attacks"] for s in a["steps"]]
    assert tech == ["T1110", "T1078", "T1562.004", "T1021.001", "T1021.002", "T1048", "T1190", "T1133", "T1046",
                    "T1021.006", "T1105", "T1071.001", "T1090.003"]
    w0 = built["m"]["window"]["w0_ms"]
    assert w0 == T0 + H
    first = {a["id"]: a["steps"][0] for a in doc["attacks"]}
    assert first["F1"]["ts_ms"] == w0 + 20 * MIN and first["F2"]["ts_ms"] == w0 + 3 * H
    assert first["F3"]["ts_ms"] == w0 + 5 * H + 40 * MIN      # F3 opens 10 min into its group (generator 06:10)
    assert first["F1"]["host"] == "FGT-QAINJ-TINY" and first["F1"]["user"] == "qa_fwadm"
    assert first["F1"]["dst_ip"] == "198.51.100.1" and first["F3"]["host"] == "10.78.2.37"
    assert doc["attacks"][1]["steps"][2]["host"] == "10.79.134.200"


def test_attack_timestamps_inside_window_by_product_parse(built: dict) -> None:
    m, out = built["m"], built["out"]
    rows = product_ts(out / "attack_inject.log")
    assert len(rows) == m["counts"]["attack_lines"] == 129
    w0, w1 = m["window"]["w0_ms"], m["window"]["w1_ms"]
    ts = [t for _, t in rows]
    assert w0 <= min(ts) and max(ts) <= w0 + inject.SPAN_MS <= w1
    assert min(built["bg_ts"]) <= min(ts) and max(ts) <= max(built["bg_ts"])
    assert m["attack_ts_range_ms"] == [min(ts), max(ts)] and m["attack_inside_background_span"] is True
    gt = json.loads((out / "ground_truth" / "attacks.json").read_text(encoding="utf-8"))
    tset = set(ts)
    assert all(s["ts_ms"] in tset and w0 <= s["ts_ms"] <= w1 for a in gt["attacks"] for s in a["steps"])


def test_attack_lines_copy_background_style_and_hide_generator_values(built: dict) -> None:
    text = (built["out"] / "attack_inject.log").read_text(encoding="utf-8")
    first = text.splitlines()[0]
    assert re.findall(r"(?:^| )([a-z_0-9-]+)=", first)[:11] == HEAD_ORDER
    assert re.match(r'^date=\d{4}-\d\d-\d\d time=\d\d:\d\d:\d\d eventtime=\d{19} tz="\+0530" '
                    r'devname="FGT-QAINJ-TINY" devid="FGTQAINJ00000001" logid="\d+" type="', first)
    for ln in text.splitlines():                           # same convention as the background: eventtime = local
        e, n = isc.eventtime_ms(isc.kv(ln, "eventtime")), isc.naive_ms(isc.kv(ln, "date"), isc.kv(ln, "time"))
        assert e is not None and n is not None and 0 <= e - n < 1000
    for bad in ("FGT60FTK", "49.36.200.10", 'user="admin"', 'user="vpnuser"', "10.10.", "10.212."):
        assert bad not in text
    assert b"\r" not in (built["out"] / "attack_inject.log").read_bytes()      # LF like the background
    assert built["m"]["ip_map"]["10.10.20.15"] == "10.78.20.15"
    assert built["m"]["ip_map"]["10.212.134.200"] == "10.79.134.200"
    assert built["m"]["net_level"] == {"10.10": "16", "10.212": "16"}
    assert built["m"]["synthetic"]["wan_ip"] == "198.51.100.1"
    assert built["m"]["dropped_groups"] == [f"F4@{d}" for d in range(1, 7)]


def test_same_seed_is_byte_identical_and_generator_mode_keeps_values(built: dict, tmp_path: Path) -> None:
    bg = tmp_path / "real" / "fw.log"                       # same content, own file (keeps built's st_nlink at 2)
    write_background(bg)
    m2 = inject.make_set("tiny", bg, tmp_path, seed=7, tmp=tmp_path / "tmp")
    assert m2["sha256"]["attack_inject.log"] == built["m"]["sha256"]["attack_inject.log"]
    g = inject.make_set("gen", bg, tmp_path, seed=7, tmp=tmp_path / "tmp", entities="generator")
    doc = json.loads((tmp_path / "gen_inj" / "ground_truth" / "attacks.json").read_text(encoding="utf-8"))
    assert g["ip_map"] == {} and g["user_map"] == {}
    assert doc["attacks"][0]["steps"][0]["user"] == "admin" and doc["attacks"][0]["steps"][3]["host"] == "10.10.20.15"


# ---------------------------------------------------------------- QAINJ-1 (product): admin brute-force noise chained in
# Episodes harvested from a pipeline run of the injection (entities=generator) on a tiny background with 8 unrelated
# internet brute-force bursts against "admin" on another device (fgt60ftk-sim), 30 min apart after F1's login.
_E = ("episode_id", "rule_id", "technique_id", "sub_technique_id", "tactic", "severity", "confidence", "ts_ms",
      "last_ts_ms", "host", "subject_host", "src_host", "dst_host", "src_user", "target_user", "src_ip", "dst_ip",
      "rarity", "merged_alert_count")
_DEV, _APP = "fgt-qainj-bug", "10.10.20.15"
F1_EPS = [dict(zip(_E, r)) for r in (
    ("f1", "fw_admin_bruteforce", "T1110", "T1110.001", "Credential Access", 75, 53.43, T0, T0 + 295_018, _DEV, _DEV,
     None, None, None, "admin", "203.0.113.66", None, 0.7124, 60),
    ("f2", "fw_admin_bruteforce", "T1078", None, "Initial Access", 85, 60.56, T0 + 6 * MIN, T0 + 6 * MIN, _DEV, _DEV,
     None, None, None, "admin", "203.0.113.66", None, 0.7124, 1),
    ("f3", "fw_config_change_after_login", "T1562", "T1562.004", "Defense Impairment", 80, 80.0, T0 + 10 * MIN,
     T0 + 10 * MIN, _DEV, _DEV, None, None, "admin", None, "203.0.113.66", None, 1.0, 1),
    ("f4", "inbound_remote_service", "T1021", "T1021.001", "Lateral Movement", 70, 70.0, T0 + 14 * MIN,
     T0 + 14 * MIN, _DEV, _APP, None, _APP, None, None, "203.0.113.66", _APP, 1.0, 1),
    ("f5", "internal_lateral", "T1021", "T1021.002", "Lateral Movement", 65, 46.31, T0 + 30 * MIN, T0 + 30 * MIN,
     _DEV, _APP, _APP, "10.10.30.5", None, None, _APP, "10.10.30.5", 0.7124, 1),
    ("f6", "exfil_volume", "T1048", None, "Exfiltration", 85, 85.0, T0 + 50 * MIN, T0 + 50 * MIN, _DEV, _APP, _APP,
     None, None, None, _APP, "198.51.100.150", 1.0, 1))]
BOTS = [f"198.51.100.{20 + b}" for b in range(8)]
BOT_EPS = [dict(zip(_E, (f"b{b}", "fw_admin_bruteforce", "T1110", "T1110.001", "Credential Access", 75, 53.43,
                         T0 + 30 * MIN + b * 30 * MIN, T0 + 30 * MIN + b * 30 * MIN + 162_000, "fgt60ftk-sim",
                         "fgt60ftk-sim", None, None, None, "admin", ip, None, 0.7124, 55)))
           for b, ip in enumerate(BOTS)]


@pytest.fixture(scope="module")
def qainj1(tmp_path_factory: pytest.TempPathFactory) -> dict:
    ctx = make_events_parquet(tmp_path_factory.mktemp("qainj1"), [{"ts_ms": T0, "action": "other", "host": "x"}])
    try:
        write_episodes(ctx, F1_EPS + BOT_EPS)
        link.run(ctx)
        incidents.run(ctx)
        data = json.loads((ctx.work_dir / "incidents.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    f1 = [d for d in data if any(s["episode_id"] == "f1" for s in d["backbone"])]
    return {"data": data, "f1": f1[0] if f1 else None}


def test_qainj1_precondition_f1_incident_exists(qainj1: dict) -> None:
    """Guards the xfail below: the F1 incident is built and starts with F1's brute force -> login."""
    inc = qainj1["f1"]
    assert inc is not None and [s["episode_id"] for s in inc["backbone"][:2]] == ["f1", "f2"]


@pytest.mark.xfail(strict=True, reason="QAINJ-1: R3 'account used' + R2 user session link unrelated internet "
                   "brute-force bursts on account admin (other device, other source IPs) into F1's backbone; "
                   "F1 SMB/exfil steps drop out of the shown path (attacklens/link.py R3/R2, paths.best_path)")
def test_qainj1_unrelated_bruteforce_bursts_stay_out_of_the_attack_path(qainj1: dict) -> None:
    inc = qainj1["f1"]
    shown = [s for s in inc["backbone"]] + [s for b in inc["branches"] for s in b]
    assert not [s["episode_id"] for s in shown if s.get("src_ip") in BOTS]
    assert sorted(s["episode_id"] for s in shown) == ["f1", "f2", "f3", "f4", "f5", "f6"]
