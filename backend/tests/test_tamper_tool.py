"""tools/tamper_logs.py: every op on tiny synthetic files, exact bytes + manifest, determinism, streaming guard, and
one end-to-end run through ingest + attacklens.integrity (skipped until that module exists)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "tamper_logs.py"

T0 = 1792807200000  # 2026-10-24T02:00:00Z
MIN = 60_000
LABEL_KEYS = ("threat", "rule", "labels", "labels_extra")


def _load_tool():
    spec = importlib.util.spec_from_file_location("tamper_logs_under_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


tl = _load_tool()


# ---------------------------------------------------------------- tiny synthetic sources
def iso_ms(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts // 1000)) + f".{ts % 1000:03d}Z"


def ecs_line(ts: int, host: str, i: int) -> str:
    return json.dumps({"@timestamp": iso_ms(ts), "event": {"action": "process_created", "outcome": "success"},
                       "host": {"name": host.upper(), "ip": ["10.10.0.%d" % (1 + sum(map(ord, host)) % 200)]},
                       "user": {"name": "svc_web"},
                       "process": {"name": "svchost.exe", "command_line": f"svchost.exe -k netsvcs -s {i}"}},
                      separators=(",", ":"))


def ecs_lines(hosts: tuple[str, ...] = ("ws-a", "ws-b", "ws-c"), minutes: int = 60) -> list[str]:
    return [ecs_line(T0 + m * MIN, h, m) for m in range(minutes) for h in hosts]


def syslog_lines(n: int = 30, host: str = "srv-web-01") -> list[str]:
    out = []
    for m in range(n):
        t = time.gmtime((T0 + m * MIN) // 1000)
        out.append(f"{time.strftime('%b', t)} {t.tm_mday:2d} {time.strftime('%H:%M:%S', t)} {host} sshd[{100 + m}]: "
                   f"Accepted password for vreddy from 192.0.2.88 port {50000 + m} ssh2")
    return out


def fgt_line(ts: int, i: int, dev: str = "FGT-A", tz: str = "+0000") -> str:
    hdr = time.strftime("date=%Y-%m-%d time=%H:%M:%S", time.gmtime(ts // 1000))
    return (f'{hdr} devname="{dev}" devid="FGT60F0000000001" eventtime={ts * 1_000_000} tz="{tz}" '
            f'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.0.0.5 '
            f'srcport={40000 + i} dstip=198.51.100.7 dstport=443 action="accept" sessionid={i}')


def fgt_lines(n: int = 40) -> list[str]:
    return [fgt_line(T0 + i * MIN, i) for i in range(n)]


def win_lines(n: int = 10) -> list[str]:
    return [json.dumps({"TimeCreated": iso_ms(T0 + i * MIN), "EventID": 4624, "Computer": "SRV-DC-01",
                        "TargetUserName": "jdoe", "LogonType": 3, "IpAddress": "10.10.3.10"},
                       separators=(",", ":")) for i in range(n)]


def write(root: Path, rel: str, lines: list[str], eol: str = "\n") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes("".join(x + eol for x in lines).encode())
    return p


def src_set(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    write(src, "edr/part-0.jsonl", ecs_lines())
    write(src, "auth.log", syslog_lines())
    write(src, "fw/fgt.log", fgt_lines())
    write(src, "win.json", win_lines())
    write(src, "ground_truth/attacks.json", [json.dumps({"host": "ws-a", "ts": iso_ms(T0 + 15 * MIN)})])
    return src


def run(src: Path, dst: Path, *ops: str, seed: int = 1) -> tuple[int, dict[str, Any] | None]:
    rc = tl.main(["--src", str(src), "--dst", str(dst), "--seed", str(seed), *ops])
    mp = dst / "ground_truth" / "tamper_manifest.json"
    return rc, (json.loads(mp.read_text(encoding="utf-8")) if rc == 0 else None)


def lines_of(p: Path) -> list[bytes]:
    return p.read_bytes().splitlines(keepends=True)


def entries(man: dict, op: str) -> list[dict]:
    return [e for e in man["ops"] if e["op"] == op]


def tree(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def tamper_streaming(src: Path, dst: Path, *ops: str, seed: int = 1, mp: pytest.MonkeyPatch) -> dict[str, Any]:
    """Run the tool with Path.read_bytes / read_text disabled: it must stream, never load a whole file."""
    with mp.context() as m:
        def boom(self, *a, **k):
            raise AssertionError(f"tamper_logs loaded a whole file: {self}")
        m.setattr(Path, "read_bytes", boom)
        m.setattr(Path, "read_text", boom)
        rc = tl.main(["--src", str(src), "--dst", str(dst), "--seed", str(seed), *ops])
    assert rc == 0
    return json.loads((dst / "ground_truth" / "tamper_manifest.json").read_text(encoding="utf-8"))


# ================================================================ copy + manifest basics
def test_untouched_files_copied_byte_identical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = src_set(tmp_path)
    man = tamper_streaming(src, tmp_path / "dst", "--truncate", "auth.log", mp=monkeypatch)
    a, b = tree(src), tree(tmp_path / "dst")
    assert set(b) == set(a) | {"ground_truth/tamper_manifest.json"}
    for rel in a:
        if rel != "auth.log":
            assert b[rel] == a[rel], rel
    assert man["schema_version"] == 1 and man["seed"] == 1
    assert [e["op"] for e in man["ops"]] == ["truncate"]
    import hashlib
    for rel, meta in man["files_out"].items():
        assert meta["sha256"] == hashlib.sha256(b[rel]).hexdigest() and meta["size"] == len(b[rel])


def test_no_ops_or_bad_args_exit_2(tmp_path: Path) -> None:
    src = src_set(tmp_path)
    assert run(src, tmp_path / "d1")[0] == 2
    assert run(src, tmp_path / "d2", "--zero-bytes", "nope.log:0:10")[0] == 2           # unknown file
    assert run(src, tmp_path / "d3", "--zero-bytes", "auth.log:999999:10")[0] == 2     # offset past EOF
    assert run(src, tmp_path / "d4", "--delete-window", "ws-a:2026-10-24T03:00:00Z:2026-10-24T02:00:00Z")[0] == 2
    assert run(src, src / "inside", "--truncate", "auth.log")[0] == 2                   # dst inside src
    assert run(src, tmp_path / "d5", "--duplicate", "auth.log:150")[0] == 2             # pct > 100


def test_refuses_non_empty_dst_unless_force(tmp_path: Path) -> None:
    src = src_set(tmp_path)
    dst = tmp_path / "dst"
    dst.mkdir()
    (dst / "old.txt").write_bytes(b"x")
    assert run(src, dst, "--truncate", "auth.log")[0] == 2
    assert tl.main(["--src", str(src), "--dst", str(dst), "--force", "--truncate", "auth.log"]) == 0
    assert not (dst / "old.txt").exists()


# ================================================================ zero-bytes
def test_zero_bytes_exact_region(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = src_set(tmp_path)
    orig = (src / "edr/part-0.jsonl").read_bytes()
    man = tamper_streaming(src, tmp_path / "dst", "--zero-bytes", "edr/part-0.jsonl:100:64", mp=monkeypatch)
    out = (tmp_path / "dst/edr/part-0.jsonl").read_bytes()
    assert len(out) == len(orig)
    assert out[100:164] == b"\x00" * 64 and out[:100] == orig[:100] and out[164:] == orig[164:]
    e = entries(man, "zero_bytes")
    assert len(e) == 1 and {k: e[0][k] for k in ("file", "offset", "length")} == \
        {"file": "edr/part-0.jsonl", "offset": 100, "length": 64}


def test_zero_bytes_clamped_at_eof(tmp_path: Path) -> None:
    src = src_set(tmp_path)
    size = (src / "auth.log").stat().st_size
    rc, man = run(src, tmp_path / "dst", "--zero-bytes", f"auth.log:{size - 10}:64")
    assert rc == 0
    out = (tmp_path / "dst/auth.log").read_bytes()
    assert len(out) == size and out[-10:] == b"\x00" * 10 and out[-11:-10] != b"\x00"
    assert entries(man, "zero_bytes")[0]["length"] == 10 and entries(man, "zero_bytes")[0]["requested_length"] == 64


# ================================================================ delete-window / cut-host-after
def test_delete_window_ecs_exact_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = src_set(tmp_path)
    # a line mentioning ws-a with no timestamp is kept; a longer host name sharing the prefix is not matched
    extra = ['{"host":{"name":"WS-A"},"message":"no time here"}', ecs_line(T0 + 15 * MIN, "ws-ab", 999)]
    lines = ecs_lines() + extra
    write(src, "edr/part-0.jsonl", lines)
    man = tamper_streaming(src, tmp_path / "dst", "--delete-window",
                           "ws-a:2026-10-24T02:10:00Z:2026-10-24T02:20:00Z", mp=monkeypatch)
    want_removed = [k + 1 for k, ln in enumerate(lines)
                    if '"WS-A"' in ln and '"@timestamp"' in ln
                    and T0 + 10 * MIN <= tl.line_ts(ln, 2026).timestamp() * 1000 < T0 + 20 * MIN]
    assert len(want_removed) == 10
    kept = [ln for k, ln in enumerate(lines) if k + 1 not in want_removed]
    assert (tmp_path / "dst/edr/part-0.jsonl").read_bytes() == "".join(x + "\n" for x in kept).encode()
    e = [x for x in entries(man, "delete_window") if x["file"] == "edr/part-0.jsonl"]
    assert len(e) == 1
    assert e[0]["host"] == "ws-a" and e[0]["lines_deleted"] == 10 and e[0]["src_lines"] == want_removed
    assert e[0]["src_line_range"] == [want_removed[0], want_removed[-1]]
    assert (e[0]["start_ts_ms"], e[0]["end_ts_ms"]) == (T0 + 10 * MIN, T0 + 20 * MIN)
    # ground_truth/ is never rewritten by host ops even though it mentions ws-a inside the window
    assert (tmp_path / "dst/ground_truth/attacks.json").read_bytes() == (src / "ground_truth/attacks.json").read_bytes()


def test_delete_window_syslog_and_fortigate(tmp_path: Path) -> None:
    src = src_set(tmp_path)
    rc, man = run(src, tmp_path / "dst", "--delete-window", "srv-web-01:2026-10-24T02:05:00Z:2026-10-24T02:08:00Z",
                  "--delete-window", "fgt-a:2026-10-24T02:00:00Z:2026-10-24T02:04:00Z")
    assert rc == 0
    assert len(lines_of(tmp_path / "dst/auth.log")) == 30 - 3
    assert b"02:05:00" not in (tmp_path / "dst/auth.log").read_bytes()
    assert len(lines_of(tmp_path / "dst/fw/fgt.log")) == 40 - 4
    by_file = {e["file"]: e["lines_deleted"] for e in entries(man, "delete_window")}
    assert by_file == {"auth.log": 3, "fw/fgt.log": 4}


def test_fortigate_ts_uses_eventtime_then_header_tz() -> None:
    line = fgt_line(T0, 1, tz="+0530")
    assert tl.line_ts(line, 2026).timestamp() * 1000 == T0  # eventtime wins
    no_et = line.replace(f"eventtime={T0 * 1_000_000} ", "")
    assert tl.line_ts(no_et, 2026).timestamp() * 1000 == T0 - 19_800_000  # header local time - 05:30
    assert tl.line_ts("Oct 24 02:00:00 h sshd[1]: x", 2026).timestamp() * 1000 == T0
    assert tl.line_ts('{"@timestamp":"2026-10-24T07:30:00+05:30"}', 2026).timestamp() * 1000 == T0
    assert tl.line_ts("no timestamp at all", 2026) is None


def test_cut_host_after(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = src_set(tmp_path)
    man = tamper_streaming(src, tmp_path / "dst", "--cut-host-after", "ws-b:2026-10-24T02:30:00Z", mp=monkeypatch)
    out = [json.loads(x) for x in lines_of(tmp_path / "dst/edr/part-0.jsonl")]
    wsb = [r["@timestamp"] for r in out if r["host"]["name"] == "WS-B"]
    assert len(wsb) == 30 and max(wsb) == iso_ms(T0 + 29 * MIN)
    assert sum(1 for r in out if r["host"]["name"] == "WS-A") == 60
    e = entries(man, "cut_host_after")
    assert len(e) == 1 and e[0]["lines_deleted"] == 30 and e[0]["end"] is None and e[0]["end_ts_ms"] is None


def test_host_op_matching_nothing_is_recorded(tmp_path: Path) -> None:
    rc, man = run(src_set(tmp_path), tmp_path / "dst", "--cut-host-after", "ws-zzz:2026-10-24T02:30:00Z")
    assert rc == 0
    assert entries(man, "cut_host_after") == [{**entries(man, "cut_host_after")[0], "file": None, "lines_deleted": 0}]


# ================================================================ inject-clear
def _last(p: Path) -> str:
    return lines_of(p)[-1].decode().rstrip("\r\n")


def test_inject_clear_each_format(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = src_set(tmp_path)
    man = tamper_streaming(src, tmp_path / "dst", "--inject-clear", "edr/part-0.jsonl", "--inject-clear", "win.json",
                           "--inject-clear", "auth.log", "--inject-clear", "fw/fgt.log", mp=monkeypatch)
    dst = tmp_path / "dst"
    e = {x["file"]: x for x in entries(man, "inject_clear")}
    assert {k: v["format"] for k, v in e.items()} == {"edr/part-0.jsonl": "ecs_json", "win.json": "win_json",
                                                      "auth.log": "syslog", "fw/fgt.log": "fortigate"}

    ecs = json.loads(_last(dst / "edr/part-0.jsonl"))
    assert ecs["winlog"]["event_id"] == 1102 and ecs["host"]["name"] == "WS-C"  # host of the file's last line
    assert ecs["@timestamp"] == iso_ms(T0 + 59 * MIN + 1000)
    assert not any(k in ecs for k in LABEL_KEYS) and "kind" not in ecs["event"] and "severity" not in ecs["event"]
    assert e["edr/part-0.jsonl"]["dst_line"] == 181 and len(lines_of(dst / "edr/part-0.jsonl")) == 181
    assert e["edr/part-0.jsonl"]["host"] == "ws-c" and e["edr/part-0.jsonl"]["ts_ms"] == T0 + 59 * MIN + 1000

    win = json.loads(_last(dst / "win.json"))
    assert (win["EventID"], win["Computer"], win["TimeCreated"]) == (1102, "SRV-DC-01", iso_ms(T0 + 9 * MIN + 1000))

    sl = _last(dst / "auth.log")
    assert sl.startswith("Oct 24 02:29:01 srv-web-01 ") and "wevtutil cl Security" in sl

    fg = _last(dst / "fw/fgt.log")
    assert fg.startswith("date=2026-10-24 time=02:39:01 ") and 'devname="FGT-A"' in fg and "logdesc=" in fg
    assert f"eventtime={(T0 + 39 * MIN + 1000) * 1_000_000}" in fg


def test_inject_clear_explicit_format_and_missing_final_newline(tmp_path: Path) -> None:
    src = tmp_path / "src"
    p = write(src, "x.log", syslog_lines(3))
    p.write_bytes(p.read_bytes().rstrip(b"\n"))  # no final newline: the record must start on its own line
    rc, man = run(src, tmp_path / "dst", "--inject-clear", "x.log:win_json")
    assert rc == 0
    out = lines_of(tmp_path / "dst/x.log")
    assert len(out) == 4 and json.loads(out[-1])["EventID"] == 1102
    assert entries(man, "inject_clear")[0]["format"] == "win_json"


# ================================================================ duplicate
def test_duplicate_exact_count_and_lines(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = src_set(tmp_path)
    orig = lines_of(src / "edr/part-0.jsonl")
    man = tamper_streaming(src, tmp_path / "dst", "--duplicate", "edr/part-0.jsonl:10", mp=monkeypatch)
    out = lines_of(tmp_path / "dst/edr/part-0.jsonl")
    e = entries(man, "duplicate")[0]
    assert e["lines_duplicated"] == 18 and len(out) == 180 + 18
    assert out[:180] == orig
    assert out[180:] == [orig[k - 1] for k in e["src_lines"]]
    assert e["src_lines"] == sorted(set(e["src_lines"])) and e["dst_line_range"] == [181, 198]


def test_duplicate_deterministic_by_seed(tmp_path: Path) -> None:
    src = src_set(tmp_path)
    _, a = run(src, tmp_path / "a", "--duplicate", "edr/part-0.jsonl:10", seed=5)
    _, b = run(src, tmp_path / "b", "--duplicate", "edr/part-0.jsonl:10", seed=5)
    _, c = run(src, tmp_path / "c", "--duplicate", "edr/part-0.jsonl:10", seed=6)
    assert entries(a, "duplicate")[0]["src_lines"] == entries(b, "duplicate")[0]["src_lines"]
    assert entries(a, "duplicate")[0]["src_lines"] != entries(c, "duplicate")[0]["src_lines"]


# ================================================================ edit-time
def test_edit_time_shifts_header_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = src_set(tmp_path)
    orig = [x.decode() for x in lines_of(src / "fw/fgt.log")]
    man = tamper_streaming(src, tmp_path / "dst", "--edit-time", "fw/fgt.log:25:3600", mp=monkeypatch)
    out = [x.decode() for x in lines_of(tmp_path / "dst/fw/fgt.log")]
    assert len(out) == len(orig) == 40
    changed = [k + 1 for k in range(40) if out[k] != orig[k]]
    e = entries(man, "edit_time")[0]
    assert e["lines_edited"] == 10 and e["fortigate_lines"] == 40 and e["dst_lines"] == changed
    for k in changed:
        o, n = orig[k - 1], out[k - 1]
        assert n.split(" devname=", 1)[1] == o.split(" devname=", 1)[1]  # eventtime and the rest untouched
        hdr = time.strftime("date=%Y-%m-%d time=%H:%M:%S", time.gmtime((T0 + (k - 1) * MIN) // 1000 + 3600))
        assert n.startswith(hdr + " ")


def test_edit_time_negative_and_crosses_midnight() -> None:
    line = 'date=2026-10-24 time=00:10:00 devname="F" eventtime=1 type="traffic"'
    assert tl._shift_fgt_header(line, -900) == 'date=2026-10-23 time=23:55:00 devname="F" eventtime=1 type="traffic"'


# ================================================================ truncate
@pytest.mark.parametrize("data,want,removed", [(b"a\nbbbb\n", b"a\nbb", 3), (b"a\r\nbbbb\r\n", b"a\r\nbb", 4),
                                                 (b"a\nb\n", b"a\nb", 1)])
def test_truncate(tmp_path: Path, data: bytes, want: bytes, removed: int) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "t.log").write_bytes(data)
    rc, man = run(src, tmp_path / "dst", "--truncate", "t.log")
    assert rc == 0 and (tmp_path / "dst/t.log").read_bytes() == want
    e = entries(man, "truncate")[0]
    assert e["bytes_removed"] == removed and e["new_size"] == len(want)


# ================================================================ determinism + CLI
def test_same_seed_same_bytes(tmp_path: Path) -> None:
    src = src_set(tmp_path)
    ops = ["--duplicate", "edr/part-0.jsonl:20", "--edit-time", "fw/fgt.log:50:-600", "--inject-clear", "auth.log",
           "--delete-window", "ws-a:2026-10-24T02:10:00Z:2026-10-24T02:20:00Z", "--zero-bytes", "win.json:5:70",
           "--truncate", "edr/part-0.jsonl"]
    assert run(src, tmp_path / "a", *ops, seed=9)[0] == 0
    assert run(src, tmp_path / "b", *ops, seed=9)[0] == 0
    assert tree(tmp_path / "a") == tree(tmp_path / "b")


def test_cli_subprocess(tmp_path: Path) -> None:
    src = src_set(tmp_path)
    r = subprocess.run([sys.executable, str(TOOL), "--src", str(src), "--dst", str(tmp_path / "dst"),
                        "--truncate", "auth.log"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "dst/ground_truth/tamper_manifest.json").is_file()
    assert not (tmp_path / "dst/auth.log").read_bytes().endswith(b"\n")


# ================================================================ end to end: ingest -> tamper -> integrity.check
def test_end_to_end_tamper_detected(tmp_path: Path) -> None:
    integ = pytest.importorskip("attacklens.integrity")
    from .conftest import query, run_ingest

    src = tmp_path / "clean"
    write(src, "part-0.jsonl", ecs_lines(minutes=360))  # 3 hosts x 360 events, one per minute
    clean = run_ingest(src, tmp_path / "c")
    try:
        assert query(clean, "SELECT count(*) AS n FROM events WHERE ts_ok")[0]["n"] == 1080
        rep0 = integ.check(src, clean.out_dir, parquet_dir=clean.parquet_dir)
    finally:
        clean.con.close()
    assert rep0["verdict"] == "trusted", rep0["findings"]
    assert not [f for f in rep0["findings"] if f["check"] in ("silence_gap", "log_cleared")]

    dst = tmp_path / "tampered"
    rc, man = run(src, dst, "--delete-window", "ws-a:2026-10-24T04:00:00Z:2026-10-24T06:00:00Z",
                  "--inject-clear", "part-0.jsonl")
    assert rc == 0 and entries(man, "delete_window")[0]["lines_deleted"] == 120
    ctx = run_ingest(dst, tmp_path / "t")
    try:
        rep = integ.check(dst, ctx.out_dir, parquet_dir=ctx.parquet_dir)
    finally:
        ctx.con.close()
    by = {}
    for f in rep["findings"]:
        by.setdefault(f["check"], []).append(f)
    assert any(f["severity"] == "high" and f["host"] == "host:ws-a" for f in by.get("silence_gap", [])), by
    assert any(f["severity"] == "critical" and f["host"] == "host:ws-c" for f in by.get("log_cleared", [])), by
    assert rep["verdict"] == "tampered"
