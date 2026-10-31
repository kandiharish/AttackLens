"""tools/gen_dataset.py — TESTING.md §3.1 items 1-8 (tiny runs, exact values)."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOLS = REPO / "tools"
GENERATOR = REPO / "reports" / "edr_log_generator.py"
sys.path.insert(0, str(TOOLS))

import gen_dataset as gd  # noqa: E402

START = "2026-10-24T00:00:00Z"
START_MS = 1_792_800_000_000           # 2026-10-24T00:00:00Z, hand-checked (TESTING.md §3.3 S1 = +2 h)
DAY_MS = 86_400_000
LABEL_TOKENS = (b'"threat"', b'"labels"', b'"labels_extra"', b'"rule"')


def _args(out: Path, **kw) -> object:
    argv = ["--size", kw.pop("size", "256K"), "--out", str(out), "--scenarios", kw.pop("scenarios", "none")]
    for k, v in kw.items():
        flag = "--" + k.replace("_", "-")
        argv += [flag] if v is True else [flag, str(v)]
    return gd.make_parser().parse_args(argv)


def _ts_ms(line: bytes) -> int:
    ts = json.loads(line)["@timestamp"]
    return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000)


# ----------------------------------------------------------------------------- pure helpers
def test_parse_size_base_1024() -> None:
    assert gd.parse_size("50M") == 52_428_800
    assert gd.parse_size("2K") == 2048
    assert gd.parse_size("1G") == 1_073_741_824
    assert gd.parse_size("10GB") == 10 * 1_073_741_824
    assert gd.parse_size("1.5M") == 1_572_864
    assert gd.parse_size("4096") == 4096
    for bad in ("0", "-1M", "abc", ""):
        with pytest.raises(ValueError):
            gd.parse_size(bad)


def test_parse_start_is_utc() -> None:
    assert gd.parse_start(START) == START_MS
    assert gd.parse_start("2026-10-24T05:30:00+05:30") == START_MS
    assert gd.parse_start("2026-10-24T00:00:00") == START_MS


def test_clock_format_and_clamp() -> None:
    c = gd.SimClock(START_MS, START_MS + 1500)
    assert c.iso() == "2026-10-24T00:00:00.000Z"
    c.advance(1001.4)
    assert c.ms == START_MS + 1001 and c.iso() == "2026-10-24T00:00:01.001Z"
    c.advance(10_000)                   # never leaves its slice
    assert c.ms == START_MS + 1499


def test_slice_bounds_partition_the_span() -> None:
    b = [gd.slice_bounds(START_MS, 7 * DAY_MS, 3, k) for k in range(3)]
    assert b[0][0] == START_MS and b[-1][1] == START_MS + 7 * DAY_MS
    assert b[0][1] == b[1][0] and b[1][1] == b[2][0]


def test_strip_labels_exact_record() -> None:
    ev = {"@timestamp": "x", "event": {"id": "e-1", "kind": "alert", "severity": 8, "action": "network_connection"},
          "host": {"name": "WS-FIN-010"}, "user": {"name": "rkumar"},
          "source": {"ip": "10.10.1.10"}, "destination": {"ip": "198.51.100.23"},
          "threat": {"technique": {"id": ["T1071.001"]}, "tactic": {"name": ["Command and Control"]}},
          "rule": {"name": "r"}, "labels": {"synthetic": "true"}, "labels_extra": {"n": 1}}
    rec = gd.strip_labels(ev, 123)
    assert rec == {"ts_ms": 123, "technique_id": "T1071.001", "tactic": "Command and Control",
                   "host": "WS-FIN-010", "user": "rkumar", "src_ip": "10.10.1.10",
                   "dst_ip": "198.51.100.23", "event_id": "e-1"}
    assert set(ev) == {"@timestamp", "event", "host", "user", "source", "destination"}
    assert ev["event"] == {"id": "e-1", "kind": "event", "severity": 0, "action": "network_connection"}


def test_strip_labels_benign_returns_none_and_missing_ips_are_null() -> None:
    benign = {"event": {"kind": "event", "severity": 0}, "host": {"name": "H"}, "user": {"name": "u"}}
    assert gd.strip_labels(benign, 1) is None
    alert = {"event": {"id": "x", "kind": "alert", "severity": 8}, "host": {"name": "H"}, "user": {"name": "u"},
             "threat": {"technique": {"id": ["T1547.001"]}, "tactic": {"name": ["Persistence"]}}}
    rec = gd.strip_labels(alert, 5)
    assert rec["src_ip"] is None and rec["dst_ip"] is None and rec["technique_id"] == "T1547.001"


def test_load_generator_does_not_touch_global_uuid() -> None:
    import uuid as real_uuid
    g = gd.load_generator(GENERATOR, "edr_gen_test_iso")
    rng = __import__("random").Random(1)
    gd.install_patches(g, gd.SimClock(START_MS, START_MS + 10), rng)
    a = g.base_event(g.HOSTS[0], "rkumar", "process", "start", "process_created")
    assert a["@timestamp"] == "2026-10-24T00:00:00.000Z"
    expect = str(real_uuid.UUID(int=__import__("random").Random(1).getrandbits(128), version=4))
    assert a["event"]["id"] == expect
    assert real_uuid.uuid4 is not g.uuid.uuid4           # patch is local to the module instance


# ----------------------------------------------------------------------------- end-to-end tiny runs
@pytest.fixture(scope="module")
def tiny(tmp_path_factory) -> tuple[Path, dict]:
    out = tmp_path_factory.mktemp("g") / "tiny"
    m = gd.build(_args(out, size="512K", workers=1, alert_ratio=0.01))
    return out, m


def test_manifest_fields_and_byte_target(tiny) -> None:
    out, m = tiny
    assert m["target_bytes"] == 524_288
    assert m["bytes"] >= 524_288 and m["bytes"] - 524_288 < 4096          # stops at the target
    assert m["generator_sha256"] == hashlib.sha256(GENERATOR.read_bytes()).hexdigest()
    assert m["args"]["seed"] == 42 and m["args"]["days"] == 7.0 and m["args"]["format"] == "json"
    assert m["args"]["start"] == START and m["args"]["alert_ratio"] == 0.01
    assert m["scenario_ids"] == [] and m["wall_s"] > 0 and m["mb_per_s"] > 0
    assert m["start_ms"] == START_MS and m["end_ms"] == START_MS + 7 * DAY_MS
    on_disk = json.loads((out / "manifest.json").read_text())
    assert on_disk == m
    (p,) = m["parts"]
    data = (out / "part-0.jsonl").read_bytes()
    assert p["bytes"] == len(data) and p["events"] == data.count(b"\n")
    assert p["sha256"] == hashlib.sha256(data).hexdigest()


def test_parts_are_clean_lf_and_unlabelled(tiny) -> None:
    out, _ = tiny
    data = (out / "part-0.jsonl").read_bytes()
    assert b"\r" not in data and data.endswith(b"\n")
    for tok in LABEL_TOKENS:
        assert tok not in data, tok
    for line in data.splitlines():
        e = json.loads(line)["event"]
        assert e["kind"] == "event" and e["severity"] == 0


def test_timestamps_monotonic_span_and_jitter(tiny) -> None:
    out, m = tiny
    ts = [_ts_ms(line) for line in (out / "part-0.jsonl").read_bytes().splitlines()]
    assert ts == sorted(ts)
    assert ts[0] == START_MS
    assert START_MS + 7 * DAY_MS * 98 // 100 <= ts[-1] < START_MS + 7 * DAY_MS   # reaches the end
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    mean = sum(gaps) / len(gaps)
    assert min(gaps) >= 0.6 * mean and max(gaps) <= 1.45 * mean                      # +/-30 % jitter
    assert len(set(gaps)) > len(gaps) // 4                                          # really jittered
    assert m["parts"][0]["first_ts_ms"] == ts[0] and m["parts"][0]["last_ts_ms"] == ts[-1]


def test_noise_ground_truth_matches_parts(tiny) -> None:
    out, m = tiny
    lines = (out / "ground_truth" / "noise_alerts.jsonl").read_bytes().splitlines()
    assert len(lines) == m["noise_alert_count"] == m["parts"][0]["noise_alerts"] > 0
    ids = {json.loads(line)["event"]["id"]: json.loads(line)
           for line in (out / "part-0.jsonl").read_bytes().splitlines()}
    known = {"T1059.001", "T1071.001", "T1110", "T1547.001", "T1486"}
    for line in lines:
        r = json.loads(line)
        assert set(r) == {"ts_ms", "technique_id", "tactic", "host", "user", "src_ip", "dst_ip", "event_id"}
        assert r["technique_id"] in known
        ev = ids[r["event_id"]]                                 # the stripped event is in the part
        assert _ts_ms(json.dumps(ev).encode()) == r["ts_ms"]
        assert ev["host"]["name"] == r["host"] and ev["user"]["name"] == r["user"]
    assert not list((out / "ground_truth").glob(".noise-*"))


def test_reproducible_and_seed_sensitive(tmp_path, tiny) -> None:
    _, m1 = tiny
    m2 = gd.build(_args(tmp_path / "again", size="512K", workers=1, alert_ratio=0.01))
    m3 = gd.build(_args(tmp_path / "other", size="512K", workers=1, alert_ratio=0.01, seed=7))
    assert m2["parts"][0]["sha256"] == m1["parts"][0]["sha256"]
    assert m3["parts"][0]["sha256"] != m1["parts"][0]["sha256"]


def test_alert_ratio_zero_and_one(tmp_path) -> None:
    m0 = gd.build(_args(tmp_path / "clean", size="64K", alert_ratio=0))
    assert m0["noise_alert_count"] == 0
    assert (tmp_path / "clean" / "ground_truth" / "noise_alerts.jsonl").read_bytes() == b""
    m1 = gd.build(_args(tmp_path / "all", size="64K", alert_ratio=1))
    assert m1["noise_alert_count"] == m1["events"] > 0


def test_refuses_non_empty_out_unless_force(tmp_path) -> None:
    out = tmp_path / "busy"
    out.mkdir()
    (out / "keep.txt").write_text("x")
    with pytest.raises(SystemExit):
        gd.build(_args(out, size="16K"))
    assert (out / "keep.txt").exists()
    gd.build(_args(out, size="16K", force=True))
    assert not (out / "keep.txt").exists() and (out / "part-0.jsonl").exists()


def test_refuses_dangerous_out() -> None:
    with pytest.raises(SystemExit):
        gd.build(_args(REPO, size="16K", force=True))
    with pytest.raises(SystemExit):
        gd.build(_args(REPO / "data" / "raw", size="16K", force=True))


def test_generator_file_is_never_modified(tiny) -> None:
    _, m = tiny
    assert hashlib.sha256(GENERATOR.read_bytes()).hexdigest() == m["generator_sha256"]


def test_cli_two_workers_slices_and_determinism(tmp_path) -> None:
    def run(out: Path) -> dict:
        cmd = [sys.executable, str(TOOLS / "gen_dataset.py"), "--size", "1M", "--workers", "2",
               "--out", str(out), "--scenarios", "none"]
        subprocess.run(cmd, check=True, capture_output=True, timeout=60)
        return json.loads((out / "manifest.json").read_text())

    a, b = run(tmp_path / "a"), run(tmp_path / "b")
    assert [p["sha256"] for p in a["parts"]] == [p["sha256"] for p in b["parts"]]
    assert a["parts"][0]["sha256"] != a["parts"][1]["sha256"]
    assert a["bytes"] >= 1 << 20 and all(p["bytes"] >= 1 << 19 for p in a["parts"])
    half = START_MS + 7 * DAY_MS // 2
    p0, p1 = a["parts"]
    assert p0["slice_ms"] == [START_MS, half] and p1["slice_ms"] == [half, START_MS + 7 * DAY_MS]
    assert START_MS <= p0["first_ts_ms"] <= p0["last_ts_ms"] < half
    assert half <= p1["first_ts_ms"] <= p1["last_ts_ms"] < START_MS + 7 * DAY_MS
    for p in a["parts"]:
        assert hashlib.sha256((tmp_path / "a" / p["file"]).read_bytes()).hexdigest() == p["sha256"]
