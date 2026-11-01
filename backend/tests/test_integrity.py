"""Log integrity / tamper-detection engine (attacklens.integrity), tested against its written contract.

Every test builds tiny hand-checked data in tmp_path: canonical events via make_events_parquet / events_ctx and raw
files written byte by byte. Defaults come from config/integrity.yaml (the contract's numbers). Each check gets a
positive (right severity + verdict) and a near-miss that must not fire. `assert_contract` re-derives every check
status, the trust score and the verdict from the listed findings, so every test also checks the arithmetic.
Generator labels (threat, rule, labels, ...) are never needed: fixtures set raw canonical fields only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

integ = pytest.importorskip("attacklens.integrity")

from .conftest import _new_ctx, make_events_parquet  # noqa: E402

T0 = 1792807200000  # 2026-10-24T02:00:00Z
S, MIN, H = 1000, 60_000, 3_600_000

CHECK_IDS = ["seal", "zeroed_regions", "truncated_tail", "log_cleared", "silence_gap", "went_dark", "timestamps",
             "duplicates", "embedded_time_mismatch", "ingest_drops"]
EVENT_CHECKS = ["log_cleared", "silence_gap", "went_dark", "timestamps", "duplicates", "embedded_time_mismatch"]
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2}
FINDING_KEYS = {"check", "severity", "title", "source_type", "host", "file", "start_ts_ms", "end_ts_ms", "count",
                "detail", "evidence"}
SEAL_KEYS = {"status", "path", "keyed", "files_checked", "modified", "missing", "added"}
FILE_KEYS = {"file", "size", "sha256", "zeroed_bytes", "truncated_tail"}


# ---------------------------------------------------------------- contract checker (applied to every report)
def assert_contract(rep: dict[str, Any]) -> dict[str, Any]:
    """Shape + arithmetic of an integrity report, re-derived from its findings. Returns rep."""
    assert rep["schema_version"] == 1
    for k in ("set", "generated_at", "verdict", "trust_score", "summary", "checks", "findings", "seal", "files",
              "inputs", "wall_s"):
        assert k in rep, k
    assert [c["id"] for c in rep["checks"]] == CHECK_IDS
    assert rep["verdict"] in ("trusted", "suspect", "tampered")
    assert isinstance(rep["trust_score"], int) and 0 <= rep["trust_score"] <= 100
    assert isinstance(rep["summary"], str) and rep["summary"]
    assert set(rep["seal"]) >= SEAL_KEYS and rep["seal"]["status"] in ("verified", "mismatch", "absent")
    assert set(rep["inputs"]) >= {"events_rows", "files", "bytes"}
    for f in rep["files"]:
        assert set(f) >= FILE_KEYS
    fs = rep["findings"]
    for f in fs:
        assert set(f) >= FINDING_KEYS, sorted(FINDING_KEYS - set(f))
        assert f["check"] in CHECK_IDS and f["severity"] in SEV_RANK
        assert isinstance(f["evidence"], list) and len(f["evidence"]) <= 3
        assert all(isinstance(e, str) and len(e) <= 300 for e in f["evidence"]), f["evidence"]
        assert f["host"] is None or re.fullmatch(r"host:[^A-Z\s]+", f["host"]), f["host"]
    keys = [(-SEV_RANK[f["severity"]], -(f["count"] or 0)) for f in fs]
    assert keys == sorted(keys), "findings must be sorted by severity desc, then count desc"
    score = 100
    worst = -1
    for c in rep["checks"]:
        assert c["status"] in ("pass", "warn", "fail", "skipped")
        mine = [f for f in fs if f["check"] == c["id"]]
        assert len(mine) <= 25
        assert isinstance(c["findings"], int) and c["findings"] >= len(mine)
        if c["status"] == "skipped":
            assert not mine and c["findings"] == 0 and c["reason"], c
            continue
        if c["findings"] == 0:
            assert c["status"] == "pass", c
            continue
        top = max(SEV_RANK[f["severity"]] for f in mine)
        assert c["status"] == ("fail" if top >= SEV_RANK["high"] else "warn"), c
        worst = max(worst, top)
        if c["findings"] == len(mine):  # uncapped: the score is exactly derivable
            score -= min(40, sum(WEIGHT[f["severity"]] for f in mine))
        else:  # capped: > 25 findings x >= 2 points each always exceeds the 40-point cap
            score -= 40
    score = max(0, score)
    assert rep["trust_score"] == score, (rep["trust_score"], score)
    exp = ("tampered" if worst == SEV_RANK["critical"] else
           "suspect" if worst == SEV_RANK["high"] or score < 70 else "trusted")
    assert rep["verdict"] == exp, (rep["verdict"], exp)
    return rep


def chk(rep: dict, cid: str) -> dict:
    return next(c for c in rep["checks"] if c["id"] == cid)


def fnd(rep: dict, cid: str) -> list[dict]:
    return [f for f in rep["findings"] if f["check"] == cid]


def sevs(rep: dict, cid: str) -> set[str]:
    return {f["severity"] for f in fnd(rep, cid)}


def statuses(rep: dict) -> dict[str, str]:
    return {c["id"]: c["status"] for c in rep["checks"]}


# ---------------------------------------------------------------- fixture builders
def iso(ts_ms: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts_ms // 1000)) + "Z"


def ev(ts: int | None, host: str, i: int, **kw: Any) -> dict[str, Any]:
    """A benign canonical event with a unique raw_line."""
    stamp = iso(ts) if ts is not None else "-"
    row = {"ts_ms": ts, "host": host, "action": "proc_start", "event_id": 4688, "src_user": "svc_web",
           "process_name": "svchost.exe", "command_line": f"svchost.exe -k netsvcs -s {i}",
           "raw_line": f"{stamp} {host} svchost[{i}]: started svchost.exe -k netsvcs -s {i}"}
    row.update(kw)
    return row


def steady(hosts: tuple[str, ...] = ("ws-a", "ws-b", "ws-c"), start: int = T0, minutes: int = 360,
           drop: Any = None) -> list[dict[str, Any]]:
    """One event per host per minute over [start, start + minutes). drop(host, ts) -> True removes a row."""
    rows = []
    for h in hosts:
        for i in range(minutes):
            ts = start + i * MIN
            if drop is None or not drop(h, ts):
                rows.append(ev(ts, h, i))
    return rows


def small(n: int = 40, host: str = "ws-a") -> list[dict[str, Any]]:
    """Too few rows per host for silence/went_dark eligibility and too few for the duplicates check."""
    return [ev(T0 + i * MIN, host, i) for i in range(n)]


def write_files(root: Path, files: dict[str, bytes]) -> Path:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


def clean_bytes(tag: str = "a", n: int = 20) -> bytes:
    return b"".join(f"2026-10-24T02:{i:02d}:00Z ws-{tag} app[{i}]: heartbeat {tag}-{i}\n".encode() for i in range(n))


CLEAN_RAW = {"edr/part-0.log": clean_bytes("a"), "syslog/auth.log": clean_bytes("b")}


def report_file(out_dir: Path) -> dict[str, Any]:
    return json.loads((out_dir / "integrity_report.json").read_text(encoding="utf-8"))


@pytest.fixture
def ictx(tmp_path: Path):
    """ictx(rows, raw=None) -> RunContext with events Parquet and a raw dir (clean files unless raw given)."""
    made: list = []

    def _make(rows: list[dict[str, Any]], raw: dict[str, bytes] | None = None):
        ctx = make_events_parquet(tmp_path / f"c{len(made)}", rows)
        made.append(ctx)
        write_files(ctx.raw_dir, CLEAN_RAW if raw is None else raw)
        return ctx

    yield _make
    for c in made:
        c.con.close()


def run_rep(ctx) -> dict[str, Any]:
    """integrity.run(ctx): return contract + report file; both must agree."""
    ret = integ.run(ctx)
    assert set(ret) >= {"verdict", "trust_score", "findings", "wall_s"}
    rep = report_file(ctx.out_dir)
    assert (ret["verdict"], ret["trust_score"]) == (rep["verdict"], rep["trust_score"])
    return assert_contract(rep)


def check_rep(raw: Path, out: Path, **kw: Any) -> dict[str, Any]:
    """integrity.check(); parquet_dir defaults to a missing tmp dir (check() alone would fall back to the repo's
    data/parquet/<out name>, which a hermetic test must never read)."""
    kw.setdefault("parquet_dir", out.parent / "no_parquet")
    rep = integ.check(raw, out, **kw)
    assert report_file(out) == json.loads(json.dumps(rep))
    return assert_contract(rep)


# ================================================================ 1. clean baseline
def test_clean_baseline_trusted_100(ictx) -> None:
    ctx = ictx(steady())
    rep = run_rep(ctx)
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 100
    assert rep["findings"] == []
    st = statuses(rep)
    assert st == {"seal": "skipped", "zeroed_regions": "pass", "truncated_tail": "pass", "log_cleared": "pass",
                  "silence_gap": "pass", "went_dark": "pass", "timestamps": "pass", "duplicates": "pass",
                  "embedded_time_mismatch": "skipped", "ingest_drops": "skipped"}
    for cid in ("seal", "embedded_time_mismatch", "ingest_drops"):
        assert chk(rep, cid)["reason"], cid
    assert rep["seal"]["status"] == "absent"
    assert rep["inputs"]["events_rows"] == 3 * 360
    assert rep["inputs"]["files"] == 2
    assert rep["inputs"]["bytes"] == sum(len(b) for b in CLEAN_RAW.values())
    files = {f["file"]: f for f in rep["files"]}
    assert set(files) == set(CLEAN_RAW)
    for rel, data in CLEAN_RAW.items():
        assert files[rel]["size"] == len(data)
        assert files[rel]["sha256"] == hashlib.sha256(data).hexdigest()
        assert files[rel]["zeroed_bytes"] == 0 and files[rel]["truncated_tail"] is False


def test_run_report_set_is_ctx_set_name(ictx) -> None:
    """run(ctx) names the set after ctx.set_name (here 'fx'; the out dir is '<tmp>/c0/out'). The contract lists
    `set` without defining it; RunContext.set_name is the set's name by definition, out_dir.name only by habit."""
    rep = run_rep(ictx(small()))
    assert rep["set"] == "fx"


def test_run_registers_events_view_itself(tmp_path: Path) -> None:
    """A fresh connection without the `events` view: run(ctx) registers it when the Parquet exists."""
    first = make_events_parquet(tmp_path / "x", steady() + [ev(T0 + 7 * MIN, "ws-b", 9999, event_id=1102)])
    first.con.close()
    ctx = _new_ctx(tmp_path / "x")
    write_files(ctx.raw_dir, CLEAN_RAW)
    try:
        rep = run_rep(ctx)
    finally:
        ctx.con.close()
    assert rep["inputs"]["events_rows"] == 3 * 360 + 1
    assert sevs(rep, "log_cleared") == {"critical"} and rep["verdict"] == "tampered"


# ================================================================ 2. per-check positive + near-miss
# ---- zeroed_regions
def test_zeroed_regions_64_nul_critical(tmp_path: Path) -> None:
    data = clean_bytes("a")[:200] + b"\x00" * 64 + clean_bytes("a")[264:]
    raw = write_files(tmp_path / "raw", {"wiped.log": data})
    rep = check_rep(raw, tmp_path / "out")
    f = fnd(rep, "zeroed_regions")
    assert [x["severity"] for x in f] == ["critical"] and f[0]["count"] == 64
    assert f[0]["file"].endswith("wiped.log")
    assert rep["verdict"] == "tampered" and rep["trust_score"] == 60
    row = next(x for x in rep["files"] if x["file"].endswith("wiped.log"))
    assert row["zeroed_bytes"] == 64 and row["size"] == len(data)
    assert row["sha256"] == hashlib.sha256(data).hexdigest()
    for cid in EVENT_CHECKS:
        assert chk(rep, cid)["status"] == "skipped", cid  # parquet_dir does not exist


def test_zeroed_regions_63_nul_near_miss(tmp_path: Path) -> None:
    data = clean_bytes("a")[:200] + b"\x00" * 63 + clean_bytes("a")[263:]
    raw = write_files(tmp_path / "raw", {"almost.log": data, "two_runs.log": b"x" + b"\x00" * 40 + b"y" + b"\x00" * 40
                                         + b"\n"})
    rep = check_rep(raw, tmp_path / "out")
    assert fnd(rep, "zeroed_regions") == [] and chk(rep, "zeroed_regions")["status"] == "pass"
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 100


def config_copy(tmp_path: Path, **integrity_overrides: Any) -> Path:
    """Top-level files of config/ copied to tmp_path/cfg with config/integrity.yaml keys overridden."""
    import shutil

    import yaml
    from attacklens import config as acfg
    dst = tmp_path / "cfg"
    dst.mkdir()
    for p in Path(acfg.CONFIG_DIR).iterdir():
        if p.is_file():
            shutil.copyfile(p, dst / p.name)
    ic = yaml.safe_load((dst / "integrity.yaml").read_text(encoding="utf-8"))
    missing = set(integrity_overrides) - set(ic)
    if missing:
        pytest.skip(f"config/integrity.yaml has no {sorted(missing)}; cannot shrink it for a fast test")
    ic.update(integrity_overrides)
    (dst / "integrity.yaml").write_text(yaml.safe_dump(ic), encoding="utf-8")
    return dst


def test_zeroed_region_spanning_chunk_boundary(tmp_path: Path) -> None:
    """16 MiB read chunks in production; shrunk to 4 KiB so a run straddling the boundary is cheap to build."""
    chunk = 4096
    cfg_dir = config_copy(tmp_path, raw_chunk_bytes=chunk)
    body = (clean_bytes("a", 200) * 3)[: 3 * chunk]
    start = chunk - 50  # 50 NULs before the boundary, 50 after: neither side alone reaches 64
    data = body[:start] + b"\x00" * 100 + body[start + 100:] + b"\n"
    raw = write_files(tmp_path / "raw", {"span.log": data})
    rep = check_rep(raw, tmp_path / "out", config_dir=cfg_dir)
    f = fnd(rep, "zeroed_regions")
    assert [x["severity"] for x in f] == ["critical"] and f[0]["count"] == 100
    assert next(x for x in rep["files"] if x["file"].endswith("span.log"))["zeroed_bytes"] == 100


# ---- truncated_tail
def test_truncated_tail_low(tmp_path: Path) -> None:
    raw = write_files(tmp_path / "raw", {"ok.log": clean_bytes("a"), "cut.log": clean_bytes("b") + b"2026-10-24T03"})
    rep = check_rep(raw, tmp_path / "out")
    f = fnd(rep, "truncated_tail")
    assert [x["severity"] for x in f] == ["low"] and f[0]["file"].endswith("cut.log")
    assert (chk(rep, "truncated_tail")["status"], chk(rep, "truncated_tail")["findings"]) == ("warn", 1)
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 98
    flags = {x["file"].rsplit("/", 1)[-1]: x["truncated_tail"] for x in rep["files"]}
    assert flags == {"ok.log": False, "cut.log": True}


def test_truncated_tail_near_miss_crlf_and_empty(tmp_path: Path) -> None:
    raw = write_files(tmp_path / "raw", {"crlf.log": b"a 1\r\nb 2\r\n", "empty.log": b"", "lf.log": b"x\n"})
    rep = check_rep(raw, tmp_path / "out")
    assert fnd(rep, "truncated_tail") == [] and chk(rep, "truncated_tail")["status"] == "pass"
    assert rep["trust_score"] == 100


# ---- log_cleared
# One trigger per host in one dataset (one engine run instead of 7): the host -> severity map must be exact.
CLEAR_EIDS = [(1102, "critical"), (104, "critical"), (517, "critical"), (1100, "high"), (4719, "high"),
              (4906, "high"), (1101, "high")]
CLEAR_CMDS = [("wevtutil cl Security", "wevtutil.exe", "critical"),
              ("powershell.exe -c Clear-EventLog -LogName Security", "powershell.exe", "critical"),
              ("history -c", "bash", "critical"),
              ("shred -u /var/log/auth.log", "shred", "critical"),
              ("auditctl -D", "auditctl", "critical"),
              ("systemctl stop auditd", "systemctl", "high"),
              ("sc stop eventlog", "sc.exe", "high")]


def test_log_cleared_event_ids(ictx) -> None:
    rows = small() + [ev(T0 + (5 + k) * MIN, f"ws-e{eid}", 900 + k, action="other", event_id=eid,
                         process_name=None, command_line=None,
                         raw_line=f"{iso(T0 + (5 + k) * MIN)} ws-e{eid} EventLog: event {eid}")
                      for k, (eid, _) in enumerate(CLEAR_EIDS)]
    rep = run_rep(ictx(rows))
    f = fnd(rep, "log_cleared")
    assert {x["host"]: x["severity"] for x in f} == {f"host:ws-e{eid}": sev for eid, sev in CLEAR_EIDS}
    assert len(f) == len(CLEAR_EIDS) and all(x["count"] == 1 for x in f)
    assert rep["verdict"] == "tampered" and rep["trust_score"] == 60  # 4 x 40 + 3 x 20 capped at 40


def test_log_cleared_command_lines(ictx) -> None:
    rows = small() + [ev(T0 + (5 + k) * MIN, f"srv-c{k}", 900 + k, process_name=proc, command_line=cmd,
                         raw_line=f"{iso(T0 + (5 + k) * MIN)} srv-c{k} proc: {cmd}")
                      for k, (cmd, proc, _) in enumerate(CLEAR_CMDS)]
    rep = run_rep(ictx(rows))
    f = fnd(rep, "log_cleared")
    assert {x["host"]: x["severity"] for x in f} == {f"host:srv-c{k}": s for k, (_, _, s) in enumerate(CLEAR_CMDS)}
    assert rep["verdict"] == "tampered"


def test_log_cleared_single_high_is_suspect_80(ictx) -> None:
    rows = small() + [ev(T0 + 5 * MIN, "ws-b", 900, action="other", event_id=4719, process_name=None,
                         command_line=None, raw_line=f"{iso(T0 + 5 * MIN)} ws-b Security: audit policy change")]
    rep = run_rep(ictx(rows))
    assert [(x["severity"], x["host"], x["count"]) for x in fnd(rep, "log_cleared")] == [("high", "host:ws-b", 1)]
    assert rep["verdict"] == "suspect" and rep["trust_score"] == 80


def test_log_cleared_near_misses(ictx) -> None:
    benign = [("wevtutil qe Security /c:5 /f:text", "wevtutil.exe"), ("history | tail -n 20", "bash"),
              ("systemctl status auditd", "systemctl"), ("sc query eventlog", "sc.exe"),
              ("auditctl -l", "auditctl"), ("Get-EventLog -LogName Security -Newest 5", "powershell.exe"),
              ("shred -u /tmp/scratch.bin", "shred")]
    rows = small() + [ev(T0 + (5 + k) * MIN, "srv-x", 900 + k, process_name=p, command_line=c,
                         raw_line=f"{iso(T0 + (5 + k) * MIN)} srv-x proc: {c}") for k, (c, p) in enumerate(benign)]
    rows += [ev(T0 + 30 * MIN, "srv-x", 950, action="login_success", event_id=4624, process_name=None,
                command_line=None, raw_line=f"{iso(T0 + 30 * MIN)} srv-x logon 4624")]
    rep = run_rep(ictx(rows))
    assert fnd(rep, "log_cleared") == [] and chk(rep, "log_cleared")["status"] == "pass"
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 100


# ---- silence_gap
def _gap(host: str, a_min: int, b_min: int):
    return lambda h, ts: h == host and T0 + a_min * MIN <= ts < T0 + b_min * MIN


def test_silence_gap_2h_high(ictx) -> None:
    rep = run_rep(ictx(steady(drop=_gap("ws-a", 120, 240))))
    f = fnd(rep, "silence_gap")
    assert [x["severity"] for x in f] == ["high"] and f[0]["host"] == "host:ws-a"
    assert abs(f[0]["start_ts_ms"] - (T0 + 120 * MIN)) <= 5 * MIN
    assert abs(f[0]["end_ts_ms"] - (T0 + 240 * MIN)) <= 5 * MIN
    assert fnd(rep, "went_dark") == []
    assert rep["verdict"] == "suspect" and rep["trust_score"] == 80


def test_silence_gap_30min_near_miss(ictx) -> None:
    rep = run_rep(ictx(steady(drop=_gap("ws-a", 120, 150))))
    assert fnd(rep, "silence_gap") == [] and chk(rep, "silence_gap")["status"] == "pass"
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 100


def test_silence_gap_whole_dataset_silent_is_low(ictx) -> None:
    rep = run_rep(ictx(steady(drop=lambda h, ts: T0 + 120 * MIN <= ts < T0 + 240 * MIN)))
    assert sevs(rep, "silence_gap") == {"low"}
    assert chk(rep, "silence_gap")["status"] == "warn" and rep["verdict"] == "trusted"


def test_silence_gap_ignores_small_hosts(ictx) -> None:
    """A host with < 200 events is not eligible, however long its gap."""
    rows = steady() + [ev(T0 + i * MIN, "ws-tiny", 5000 + i) for i in list(range(0, 50)) + list(range(300, 350))]
    rep = run_rep(ictx(rows))
    assert fnd(rep, "silence_gap") == [] and fnd(rep, "went_dark") == []


# ---- went_dark
def test_went_dark_high(ictx) -> None:
    rows = steady(minutes=480, drop=lambda h, ts: h == "ws-a" and ts >= T0 + 300 * MIN)
    rep = run_rep(ictx(rows))
    f = fnd(rep, "went_dark")
    assert [x["severity"] for x in f] == ["high"] and f[0]["host"] == "host:ws-a"
    assert abs(f[0]["start_ts_ms"] - (T0 + 300 * MIN)) <= 5 * MIN
    assert rep["verdict"] == "suspect"


def test_went_dark_near_miss_late_start_and_short_stop(ictx) -> None:
    rows = steady(hosts=("ws-b", "ws-c"), minutes=480)
    rows += [ev(T0 + i * MIN, "ws-late", 7000 + i) for i in range(120, 480)]   # started late, still logging
    rows += [ev(T0 + i * MIN, "ws-early", 8000 + i) for i in range(0, 420)]    # stops 60 min before the end
    rep = run_rep(ictx(rows))
    assert fnd(rep, "went_dark") == [] and fnd(rep, "silence_gap") == []
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 100


# ---- timestamps
def _bad_ts(n: int) -> list[dict[str, Any]]:
    return [ev(None, "ws-a", 9000 + k, ts_ok=False, raw_line=f"garbled-time ws-a svchost[{9000 + k}]: x")
            for k in range(n)]


@pytest.mark.parametrize("n_bad,expect", [(5, None), (50, "medium"), (150, "high")])
def test_timestamps_ts_ok_false_ratio(ictx, n_bad: int, expect: str | None) -> None:
    """5/1085 = 0.46 % (near-miss), 50/1130 = 4.4 % (medium), 150/1230 = 12.2 % (high)."""
    rep = run_rep(ictx(steady() + _bad_ts(n_bad)))
    if expect is None:
        assert fnd(rep, "timestamps") == [] and chk(rep, "timestamps")["status"] == "pass"
        assert rep["verdict"] == "trusted"
    else:
        f = fnd(rep, "timestamps")
        assert [x["severity"] for x in f] == [expect] and f[0]["source_type"] == "ecs_json"
        assert f[0]["count"] == n_bad
        assert rep["verdict"] == ("suspect" if expect == "high" else "trusted")


def test_timestamps_future_high(ictx) -> None:
    fut = int(time.time() * 1000) + 3 * 24 * H
    rep = run_rep(ictx(small() + [ev(fut, "ws-z", 1)]))
    assert sevs(rep, "timestamps") == {"high"} and rep["verdict"] == "suspect"


def test_timestamps_future_near_miss_one_hour(ictx) -> None:
    soon = int(time.time() * 1000) + H
    rep = run_rep(ictx(small() + [ev(soon, "ws-z", 1)]))
    assert fnd(rep, "timestamps") == []


def test_timestamps_before_2000_medium_and_near_miss(ictx) -> None:
    rep = run_rep(ictx(small() + [ev(946681200000, "ws-z", 1)]))   # 1999-12-31T23:00:00Z
    assert sevs(rep, "timestamps") == {"medium"} and rep["verdict"] == "trusted"
    rep2 = run_rep(ictx(small() + [ev(946771200000, "ws-z", 1)]))  # 2000-01-02T00:00:00Z
    assert fnd(rep2, "timestamps") == []


# ---- duplicates
def _with_dups(d: int) -> list[dict[str, Any]]:
    base = steady()
    return base + [dict(base[k]) for k in range(d)]


@pytest.mark.parametrize("d,expect", [(33, None), (120, "medium"), (463, "high")])
def test_duplicates_ratio(ictx, d: int, expect: str | None) -> None:
    """Exact dup ratio 33/1113 = 3.0 % (near-miss), 120/1200 = 10 % (medium), 463/1543 = 30 % (high)."""
    rep = run_rep(ictx(_with_dups(d)))
    if expect is None:
        assert fnd(rep, "duplicates") == [] and chk(rep, "duplicates")["status"] == "pass"
    else:
        f = fnd(rep, "duplicates")
        assert [x["severity"] for x in f] == [expect] and f[0]["source_type"] == "ecs_json"
    assert fnd(rep, "silence_gap") == []


def test_duplicates_needs_1000_rows(ictx) -> None:
    rows = small(400)
    rep = run_rep(ictx(rows + [dict(r) for r in rows[:200]]))  # 33 % duplicates but only 600 rows
    assert fnd(rep, "duplicates") == []


# ---- embedded_time_mismatch (FortiGate eventtime vs ts_ms)
def fgt_rows(n: int = 400, base_offset_s: int = 0, shifted: dict[int, int] | None = None) -> list[dict[str, Any]]:
    """FortiGate rows, one per minute; eventtime = ts + base_offset_s (+ shifted[i] seconds for row i), in ns."""
    rows = []
    for i in range(n):
        ts = T0 + i * MIN
        et_ns = (ts + (base_offset_s + (shifted or {}).get(i, 0)) * S) * 1_000_000
        hdr = time.strftime("date=%Y-%m-%d time=%H:%M:%S", time.gmtime(ts // 1000))
        rows.append({"ts_ms": ts, "source_type": "fortigate_kv", "host": "fgt-a", "action": "conn_allowed",
                     "src_ip": "10.0.0.5", "dst_ip": "198.51.100.7", "dst_port": 443,
                     "raw_line": f'{hdr} devname="FGT-A" devid="FGT60F0000000001" eventtime={et_ns} tz="+0000" '
                                 f'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
                                 f'srcip=10.0.0.5 srcport={40000 + i} dstip=198.51.100.7 dstport=443 '
                                 f'action="accept" sessionid={i}'})
    return rows


def test_embedded_time_mismatch_high(ictx) -> None:
    rep = run_rep(ictx(fgt_rows(shifted={i: 3600 for i in range(100, 130)})))
    f = fnd(rep, "embedded_time_mismatch")
    assert [x["severity"] for x in f] == ["high"] and f[0]["count"] == 30
    assert f[0]["host"] == "host:fgt-a" and f[0]["source_type"] == "fortigate_kv"
    assert rep["verdict"] == "suspect"


def test_embedded_time_mismatch_near_miss_small_skew(ictx) -> None:
    rep = run_rep(ictx(fgt_rows(shifted={i: 120 for i in range(100, 130)})))
    assert fnd(rep, "embedded_time_mismatch") == [] and chk(rep, "embedded_time_mismatch")["status"] == "pass"


def test_embedded_time_mismatch_near_miss_constant_tz_offset(ictx) -> None:
    """eventtime written as local +05:30 on every row: the host's modal offset absorbs it."""
    rep = run_rep(ictx(fgt_rows(base_offset_s=19800)))
    assert fnd(rep, "embedded_time_mismatch") == [] and chk(rep, "embedded_time_mismatch")["status"] == "pass"
    assert rep["verdict"] == "trusted"


# ---- ingest_drops
def _accounting(out: Path, rows_in: int, dropped: int) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "ingest_accounting.json").write_text(json.dumps([
        {"source_type": "ecs_json", "files": 1, "rows_in": rows_in, "rows_ok": rows_in - dropped,
         "dropped": dropped, "drop_reasons": {"unparseable_line": dropped} if dropped else {}}]), encoding="utf-8")


@pytest.mark.parametrize("dropped,expect", [(50, None), (1000, "medium"), (10_000, "high")])
def test_ingest_drops(tmp_path: Path, dropped: int, expect: str | None) -> None:
    """Of 100 000 rows: 0.05 % (near-miss), 1 % (medium), 10 % (high)."""
    raw = write_files(tmp_path / "raw", CLEAN_RAW)
    _accounting(tmp_path / "out", 100_000, dropped)
    rep = check_rep(raw, tmp_path / "out")
    if expect is None:
        assert fnd(rep, "ingest_drops") == [] and chk(rep, "ingest_drops")["status"] == "pass"
    else:
        assert sevs(rep, "ingest_drops") == {expect}
        assert rep["verdict"] == ("suspect" if expect == "high" else "trusted")


def test_ingest_drops_skipped_without_accounting(tmp_path: Path) -> None:
    rep = check_rep(write_files(tmp_path / "raw", CLEAN_RAW), tmp_path / "out")
    assert chk(rep, "ingest_drops")["status"] == "skipped" and chk(rep, "ingest_drops")["reason"]


# ================================================================ 3. seal round-trip
SEAL_RAW = {"a.log": clean_bytes("a"), "sub/b.log": clean_bytes("b")}


def _sealed(tmp_path: Path, **kw: Any) -> tuple[Path, dict[str, Any]]:
    raw = write_files(tmp_path / "raw", SEAL_RAW)
    man = integ.seal(raw, **kw)
    return raw, man


def test_seal_manifest_shape_unkeyed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATTACKLENS_SEAL_KEY", raising=False)
    raw, man = _sealed(tmp_path)
    path = raw / ".meta" / "integrity_seal.json"
    assert json.loads(path.read_text(encoding="utf-8")) == json.loads(json.dumps(man))
    assert man["schema_version"] == 1 and man["keyed"] is False and man["algo"] == "sha256"
    assert set(man) >= {"schema_version", "created_at", "keyed", "algo", "files", "manifest_digest"}
    assert set(man["files"]) == {"a.log", "sub/b.log"}  # the seal file never lists itself
    for rel, data in SEAL_RAW.items():
        assert man["files"][rel]["size"] == len(data)
        assert man["files"][rel]["digest"] == hashlib.sha256(data).hexdigest()
    man2 = integ.seal(raw)  # resealing: the existing .meta/ seal still is not listed
    assert set(man2["files"]) == {"a.log", "sub/b.log"}


def test_seal_verified(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATTACKLENS_SEAL_KEY", raising=False)
    raw, _ = _sealed(tmp_path)
    rep = check_rep(raw, tmp_path / "out")
    s = rep["seal"]
    assert s["status"] == "verified" and s["keyed"] is False and s["files_checked"] == 2
    assert (s["modified"], s["missing"], s["added"]) == ([], [], [])
    assert chk(rep, "seal")["status"] == "pass"
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 100  # .meta/ seal is not a truncated "log"


def test_seal_flip_one_byte_modified_critical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATTACKLENS_SEAL_KEY", raising=False)
    raw, _ = _sealed(tmp_path)
    data = bytearray((raw / "a.log").read_bytes())
    data[10] ^= 0x01
    (raw / "a.log").write_bytes(bytes(data))
    rep = check_rep(raw, tmp_path / "out")
    assert rep["seal"]["status"] == "mismatch" and rep["seal"]["modified"] == ["a.log"]
    assert rep["seal"]["missing"] == [] and rep["seal"]["added"] == []
    assert sevs(rep, "seal") == {"critical"} and rep["verdict"] == "tampered"


def test_seal_deleted_file_missing_critical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATTACKLENS_SEAL_KEY", raising=False)
    raw, _ = _sealed(tmp_path)
    (raw / "sub" / "b.log").unlink()
    rep = check_rep(raw, tmp_path / "out")
    assert rep["seal"]["status"] == "mismatch" and rep["seal"]["missing"] == ["sub/b.log"]
    assert sevs(rep, "seal") == {"critical"} and rep["verdict"] == "tampered"


def test_seal_added_file_medium(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATTACKLENS_SEAL_KEY", raising=False)
    raw, _ = _sealed(tmp_path)
    (raw / "c.log").write_bytes(clean_bytes("c"))
    rep = check_rep(raw, tmp_path / "out")
    assert rep["seal"]["added"] == ["c.log"] and rep["seal"]["modified"] == [] and rep["seal"]["missing"] == []
    assert sevs(rep, "seal") == {"medium"} and chk(rep, "seal")["status"] == "warn"
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 92


def test_seal_keyed_hmac_and_wrong_or_missing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATTACKLENS_SEAL_KEY", "k-one-test-only")
    raw, man = _sealed(tmp_path)
    assert man["keyed"] is True and man["algo"] == "hmac-sha256"
    plain = hashlib.sha256(SEAL_RAW["a.log"]).hexdigest()
    assert man["files"]["a.log"]["digest"] != plain  # not a bare sha256 an attacker could recompute
    assert check_rep(raw, tmp_path / "o1")["seal"]["status"] == "verified"

    monkeypatch.setenv("ATTACKLENS_SEAL_KEY", "k-two-test-only")
    rep = check_rep(raw, tmp_path / "o2")
    assert rep["seal"]["status"] == "mismatch" and sevs(rep, "seal") == {"critical"}
    assert rep["verdict"] == "tampered"

    monkeypatch.delenv("ATTACKLENS_SEAL_KEY")
    rep = check_rep(raw, tmp_path / "o3")
    assert rep["seal"]["status"] == "mismatch" and sevs(rep, "seal") == {"critical"}


def test_seal_manifest_digest_tampered(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATTACKLENS_SEAL_KEY", raising=False)
    raw, _ = _sealed(tmp_path)
    path = raw / ".meta" / "integrity_seal.json"
    man = json.loads(path.read_text(encoding="utf-8"))
    man["manifest_digest"] = "0" * 64
    path.write_text(json.dumps(man), encoding="utf-8")
    rep = check_rep(raw, tmp_path / "o1")
    assert rep["seal"]["status"] == "mismatch" and sevs(rep, "seal") == {"critical"}


def test_seal_entry_rewritten_without_manifest_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Attacker edits a.log and patches its digest in the manifest but cannot fix the keyed manifest_digest."""
    monkeypatch.setenv("ATTACKLENS_SEAL_KEY", "k-one-test-only")
    raw, _ = _sealed(tmp_path)
    new = SEAL_RAW["a.log"].replace(b"heartbeat", b"heartbeaT", 1)
    (raw / "a.log").write_bytes(new)
    path = raw / ".meta" / "integrity_seal.json"
    man = json.loads(path.read_text(encoding="utf-8"))
    man["files"]["a.log"] = {"size": len(new), "digest": hmac.new(b"guess", new, hashlib.sha256).hexdigest()}
    path.write_text(json.dumps(man), encoding="utf-8")
    rep = check_rep(raw, tmp_path / "o1")
    assert rep["seal"]["status"] == "mismatch" and sevs(rep, "seal") == {"critical"}
    assert rep["verdict"] == "tampered"


def test_seal_custom_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ATTACKLENS_SEAL_KEY", raising=False)
    sp = tmp_path / "seals" / "s.json"
    raw, _ = _sealed(tmp_path, seal_path=sp)
    assert sp.is_file() and not (raw / ".meta" / "integrity_seal.json").exists()
    assert check_rep(raw, tmp_path / "o1", seal_path=sp)["seal"]["status"] == "verified"
    rep = check_rep(raw, tmp_path / "o2")
    assert rep["seal"]["status"] == "absent" and chk(rep, "seal")["status"] == "skipped"


# ================================================================ 4. robustness
def test_empty_events_no_crash(tmp_path: Path) -> None:
    from attacklens.schemas import CANONICAL_COLUMNS, PARTITION_COLUMNS
    ctx = _new_ctx(tmp_path)
    d = ctx.parquet_dir / "events" / "source_type=ecs_json" / "ts_ok=true" / "event_day=2026-10-24"
    d.mkdir(parents=True)
    cols = ", ".join(f'CAST(NULL AS {t}) AS "{c}"' for c, t in CANONICAL_COLUMNS.items() if c not in PARTITION_COLUMNS)
    ctx.con.execute(f"COPY (SELECT {cols} WHERE false) TO '{(d / 'data.parquet').as_posix()}' (FORMAT PARQUET)")
    write_files(ctx.raw_dir, CLEAN_RAW)
    try:
        rep = run_rep(ctx)
    finally:
        ctx.con.close()
    assert rep["inputs"]["events_rows"] == 0
    for cid in EVENT_CHECKS:
        assert chk(rep, cid)["status"] == "skipped", cid
    assert chk(rep, "zeroed_regions")["status"] == "pass" and rep["verdict"] == "trusted"


def test_missing_parquet_raw_checks_still_run(tmp_path: Path) -> None:
    ctx = _new_ctx(tmp_path)
    assert not ctx.parquet_dir.exists()
    write_files(ctx.raw_dir, {"wiped.log": b"a\n" + b"\x00" * 128 + b"\nb\n"})
    try:
        rep = run_rep(ctx)
    finally:
        ctx.con.close()
    for cid in EVENT_CHECKS:
        assert chk(rep, cid)["status"] == "skipped", cid
    assert sevs(rep, "zeroed_regions") == {"critical"} and fnd(rep, "zeroed_regions")[0]["count"] == 128
    assert rep["verdict"] == "tampered"


def test_findings_capped_at_25_per_check_true_total_kept(tmp_path: Path) -> None:
    """30 truncated files: 25 listed, checks[].findings 30; 30 x low 2 = 60 -> capped 40 -> score 60 -> suspect."""
    raw = write_files(tmp_path / "raw", {f"f{k:02d}.log": b"line\npartial" for k in range(30)})
    rep = check_rep(raw, tmp_path / "out")
    assert len(fnd(rep, "truncated_tail")) == 25 and chk(rep, "truncated_tail")["findings"] == 30
    assert rep["trust_score"] == 60 and rep["verdict"] == "suspect"
    assert sum(1 for f in rep["files"] if f["truncated_tail"]) == 30


def test_evidence_bounded(ictx) -> None:
    long_cmd = "wevtutil cl Security " + "A" * 2000
    rows = small() + [ev(T0 + (5 + k) * MIN, "srv-x", 900 + k, process_name="wevtutil.exe", command_line=long_cmd,
                         raw_line=f"{iso(T0)} srv-x proc[{k}]: {long_cmd}") for k in range(10)]
    rep = run_rep(ictx(rows))  # assert_contract: evidence <= 3 strings, each <= 300 chars
    f = fnd(rep, "log_cleared")
    assert f and all(x["severity"] == "critical" for x in f)
    assert sum(x["count"] for x in f) == 10
    assert all(1 <= len(x["evidence"]) <= 3 for x in f)


# ================================================================ 5. score and verdict arithmetic
def test_mixed_low_medium_high_score_70_suspect(ictx) -> None:
    """truncated (low 2) + ingest drops 1 % (medium 8) + `systemctl stop auditd` (high 20) = 100 - 30 = 70."""
    rows = small() + [ev(T0 + 5 * MIN, "srv-x", 900, process_name="systemctl", command_line="systemctl stop auditd",
                         raw_line=f"{iso(T0 + 5 * MIN)} srv-x sudo: COMMAND=systemctl stop auditd")]
    ctx = ictx(rows, raw={"ok.log": clean_bytes("a"), "cut.log": b"x\npartial"})
    _accounting(ctx.out_dir, 100_000, 1000)
    rep = run_rep(ctx)
    assert rep["trust_score"] == 70 and rep["verdict"] == "suspect"
    assert [f["severity"] for f in rep["findings"]] == ["high", "medium", "low"]
    assert [f["check"] for f in rep["findings"]] == ["log_cleared", "ingest_drops", "truncated_tail"]
    st = statuses(rep)
    assert (st["log_cleared"], st["ingest_drops"], st["truncated_tail"]) == ("fail", "warn", "warn")


def test_mixed_low_and_mediums_score_82_trusted(ictx) -> None:
    """truncated (low 2) + ingest drops 1 % (medium 8) + 4/104 = 3.8 % bad ts (medium 8) = 82, no high -> trusted."""
    rows = [ev(T0 + i * 7 * MIN, f"ws-{i % 5}", i) for i in range(100)] + _bad_ts(4)
    ctx = ictx(rows, raw={"ok.log": clean_bytes("a"), "cut.log": b"x\npartial"})
    _accounting(ctx.out_dir, 100_000, 1000)
    rep = run_rep(ctx)
    assert rep["trust_score"] == 82 and rep["verdict"] == "trusted"
    assert [f["severity"] for f in rep["findings"]] == ["medium", "medium", "low"]


def test_critical_always_tampered(ictx) -> None:
    rows = small() + [ev(T0 + 5 * MIN, "ws-b", 900, action="log_cleared", event_id=1102)]
    rep = run_rep(ictx(rows))
    assert rep["trust_score"] == 60 and rep["verdict"] == "tampered"  # score >= 40 still tampered


# ================================================================ 6. CLI
def _cli(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "attacklens.integrity", *args], capture_output=True, text=True,
                          timeout=120, env=env)


def test_cli_exit_codes(tmp_path: Path) -> None:
    clean = write_files(tmp_path / "clean", CLEAN_RAW)
    np_ = str(tmp_path / "no_parquet")
    r = _cli("check", "--raw", str(clean), "--out", str(tmp_path / "o1"), "--parquet", np_, "--fail-on", "suspect")
    assert r.returncode == 0, r.stderr[-2000:]
    assert report_file(tmp_path / "o1")["verdict"] == "trusted"

    wiped = write_files(tmp_path / "wiped", {"w.log": b"a\n" + b"\x00" * 100 + b"\n"})
    r = _cli("check", "--raw", str(wiped), "--out", str(tmp_path / "o2"), "--parquet", np_, "--fail-on", "tampered")
    assert r.returncode == 2, r.stderr[-2000:]
    assert report_file(tmp_path / "o2")["verdict"] == "tampered"

    r = _cli("check", "--raw", str(tmp_path / "nope"), "--out", str(tmp_path / "o3"))
    assert r.returncode == 1, r.stderr[-2000:]


def test_cli_seal_then_check(tmp_path: Path) -> None:
    raw = write_files(tmp_path / "raw", SEAL_RAW)
    env_free = {k: v for k, v in os.environ.items() if k != "ATTACKLENS_SEAL_KEY"}
    r = _cli("seal", "--raw", str(raw), env=env_free)
    assert r.returncode == 0, r.stderr[-2000:]
    assert (raw / ".meta" / "integrity_seal.json").is_file()
    (raw / "a.log").write_bytes(b"rewritten\n")
    r = _cli("check", "--raw", str(raw), "--out", str(tmp_path / "o"), "--parquet", str(tmp_path / "no_parquet"),
             "--fail-on", "suspect", env=env_free)
    assert r.returncode == 2 and report_file(tmp_path / "o")["seal"]["modified"] == ["a.log"]


# ================================================================ 7. label hygiene
LABELS = ('"threat":{"framework":"MITRE ATT&CK","technique":{"id":["T1070.001"],'
          '"name":["Clear Windows Event Logs"]}},"rule":{"name":"Security audit log cleared (1102)"},'
          '"labels":{"attack":"log_clear","event_id":1102},"labels_extra":{"event_id":1102,"cleared":true},'
          '"event":{"kind":"alert","severity":10}')


def test_labels_in_raw_line_do_not_change_result(ictx) -> None:
    plain = small(60) + [ev(T0 + 61 * MIN, "srv-x", 61, process_name="wevtutil.exe",
                            command_line="wevtutil qe Security /c:5")]
    labelled = [dict(r, raw_line='{"msg":' + json.dumps(r["raw_line"]) + "," + LABELS + "}") for r in plain]
    assert all("T1070.001" in r["raw_line"] and "1102" in r["raw_line"] for r in labelled)
    a, b = run_rep(ictx(plain)), run_rep(ictx(labelled))
    assert (b["verdict"], b["trust_score"]) == (a["verdict"], a["trust_score"]) == ("trusted", 100)
    assert [(c["id"], c["status"], c["findings"]) for c in b["checks"]] == \
           [(c["id"], c["status"], c["findings"]) for c in a["checks"]]
    assert b["findings"] == a["findings"] == []
