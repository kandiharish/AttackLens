"""L6 robustness, ingest-level cases (TESTING.md §7). Later phases add injection / XSS / live / idempotence."""

from __future__ import annotations

import json
import shutil
import unicodedata
from pathlib import Path

import pytest

from .conftest import FIXTURES, accounting, query, run_ingest

pytest.importorskip("attacklens.ingest", reason="attacklens.ingest not written yet (BB-ingest)")


def ecs(ts: str, user: str = "pmehta", host: str = "WS-FIN-010", **extra) -> dict:
    d = {"@timestamp": ts, "event": {"action": "user_logon", "outcome": "success", "kind": "event"},
         "host": {"name": host, "ip": ["10.10.3.10"]}, "user": {"name": user, "domain": "CORP"},
         "winlog": {"event_id": 4624, "logon": {"type": "Network"}}}
    d.update(extra)
    return d


def line(d: dict) -> str:
    return json.dumps(d, separators=(",", ":"), ensure_ascii=False)


GOOD = [line(ecs("2026-10-24T03:00:00.000Z")), line(ecs("2026-10-24T03:00:01.000Z")),
        line(ecs("2026-10-24T03:00:02.000Z"))]
GOOD_MS = [1792810800000, 1792810801000, 1792810802000]


def ingest_files(tmp: Path, files: dict[str, bytes]):
    raw = tmp / "raw"
    raw.mkdir(parents=True)
    for name, data in files.items():
        (raw / name).write_bytes(data)
    return run_ingest(raw, tmp)


def assert_drop_reason(ctx, source_type: str) -> None:
    rows = json.loads((ctx.out_dir / "ingest_accounting.json").read_text(encoding="utf-8"))
    entry = [r for r in rows if r["source_type"] == source_type]
    reasons = {k: v for r in entry for k, v in r.items() if "reason" in k and v}
    assert reasons, f"{source_type}: dropped rows without a logged reason: {entry}"


def test_malformed_line_mid_file(tmp_path: Path) -> None:
    body = "\n".join([GOOD[0], '{"@timestamp":"2026-10-24T03:00:00.500Z","event":{"act', GOOD[1], GOOD[2]]) + "\n"
    ctx = ingest_files(tmp_path, {"part-0.jsonl": body.encode()})
    assert accounting(ctx)["ecs_json"] == {"rows_in": 4, "rows_ok": 3, "dropped": 1}
    assert_drop_reason(ctx, "ecs_json")
    got = [r["ts_ms"] for r in query(ctx, "SELECT ts_ms FROM events WHERE ts_ok ORDER BY ts_ms")]
    assert got == GOOD_MS


def test_truncated_last_line(tmp_path: Path) -> None:
    body = GOOD[0] + "\n" + GOOD[1] + "\n" + GOOD[2][: len(GOOD[2]) // 2]  # cut mid-line, no final newline
    ctx = ingest_files(tmp_path, {"part-0.jsonl": body.encode()})
    assert accounting(ctx)["ecs_json"] == {"rows_in": 3, "rows_ok": 2, "dropped": 1}
    assert_drop_reason(ctx, "ecs_json")
    assert [r["ts_ms"] for r in query(ctx, "SELECT ts_ms FROM events WHERE ts_ok ORDER BY ts_ms")] == GOOD_MS[:2]


def test_empty_file_ignored_and_listed(tmp_path: Path) -> None:
    ctx = ingest_files(tmp_path, {"part-0.jsonl": ("\n".join(GOOD) + "\n").encode(), "part-1.jsonl": b""})
    assert accounting(ctx)["ecs_json"] == {"rows_in": 3, "rows_ok": 3, "dropped": 0}
    prof = (ctx.out_dir / "source_profile.json").read_text(encoding="utf-8")
    assert "part-1.jsonl" in prof, "zero-byte file must be listed in source_profile.json"


def test_bom_crlf_parity(tmp_path: Path) -> None:
    clean = ("\n".join(GOOD) + "\n").encode()
    dirty = b"\xef\xbb\xbf" + ("\r\n".join(GOOD) + "\r\n").encode()
    a = ingest_files(tmp_path / "clean", {"part-0.jsonl": clean})
    b = ingest_files(tmp_path / "dirty", {"part-0.jsonl": dirty})
    sql = "SELECT * EXCLUDE (source_seq) FROM events ORDER BY ts_ms"
    ra, rb = query(a, sql), query(b, sql)
    assert len(ra) == 3 and ra == rb
    assert accounting(a) == accounting(b)


def test_mixed_formats_routed_by_content(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    for f in (FIXTURES / "ingest").rglob("*"):
        if f.is_file():
            shutil.copy(f, raw / f"{f.parent.name}__{f.name}")  # flat folder, misleading extensions
    ctx = run_ingest(raw, tmp_path)
    acc = {k: v["rows_in"] for k, v in accounting(ctx).items() if v["rows_in"]}
    assert acc == {"ecs_json": 5, "win_json": 5, "firewall_csv": 2, "syslog": 4, "cef": 1}


def test_huge_command_line(tmp_path: Path) -> None:
    cmd = "powershell.exe -enc " + "A" * (1024 * 1024)
    ev = ecs("2026-10-24T03:00:00.000Z", event={"action": "process_created", "kind": "event"},
             process={"name": "powershell.exe", "command_line": cmd, "parent": {"name": "winword.exe"}})
    del ev["winlog"]
    ctx = ingest_files(tmp_path, {"big.jsonl": (line(ev) + "\n" + GOOD[1] + "\n").encode()})
    assert accounting(ctx)["ecs_json"] == {"rows_in": 2, "rows_ok": 2, "dropped": 0}
    r = query(ctx, "SELECT length(command_line) n, action FROM events WHERE action='proc_start'")
    assert r == [{"n": len(cmd), "action": "proc_start"}]  # ingest keeps it whole; evidence truncates later


def test_homoglyph_users_distinct_and_nfc(tmp_path: Path) -> None:
    lines = [line(ecs("2026-10-24T03:00:00.000Z", user="admin")),
             line(ecs("2026-10-24T03:00:01.000Z", user="аdmin")),     # Cyrillic a
             line(ecs("2026-10-24T03:00:02.000Z", user="CORP\\José"))]  # NFD e + combining acute
    ctx = ingest_files(tmp_path, {"u.jsonl": ("\n".join(lines) + "\n").encode()})
    users = [r["target_user"] for r in query(ctx, "SELECT target_user FROM events ORDER BY ts_ms")]
    assert users == ["admin", "аdmin", "josé"]
    assert all(unicodedata.is_normalized("NFC", u) for u in users)


# ---------------------------------------------------------------- whole pipeline: time zone + re-run (§7)
REPO = Path(__file__).resolve().parents[2]
PUBLISHED = ("incidents_index.json", "suppressed.json")


def _published(out: Path) -> dict[str, bytes]:
    files = {f"incidents/{p.name}": p.read_bytes() for p in sorted((out / "incidents").glob("*.json"))}
    files.update({n: (out / n).read_bytes() for n in PUBLISHED})
    return files


def _pipeline(raw: Path, out: Path, pq: Path, tz: str) -> None:
    import os
    import subprocess
    import sys
    env = {**os.environ, "TZ": tz}
    env.pop("ANTHROPIC_API_KEY", None)
    p = subprocess.run([sys.executable, "-m", "attacklens.run", "--raw", str(raw), "--out", str(out),
                        "--parquet", str(pq)], capture_output=True, text=True, env=env, timeout=300, cwd=REPO)
    assert p.returncode == 0, p.stderr[-3000:]


@pytest.fixture(scope="module")
def g30(tmp_path_factory: pytest.TempPathFactory) -> Path:
    import subprocess
    import sys
    raw = tmp_path_factory.mktemp("g30") / "raw"
    g = subprocess.run([sys.executable, str(REPO / "tools" / "gen_dataset.py"), "--size", "30M", "--workers", "1",
                        "--seed", "42", "--out", str(raw)], capture_output=True, text=True, timeout=120)
    assert g.returncode == 0, g.stderr[-2000:]
    return raw


@pytest.fixture(scope="module")
def utc_run(g30: Path, tmp_path_factory: pytest.TempPathFactory) -> dict:
    """One TZ=UTC pipeline run shared by the time-zone and re-run tests (keeps the fast suite in budget)."""
    d = tmp_path_factory.mktemp("utc")
    out, pq = d / "out", d / "pq"
    _pipeline(g30, out, pq, "UTC")
    return {"out": out, "pq": pq, "files": _published(out),
            "acc": json.loads((out / "ingest_accounting.json").read_text(encoding="utf-8"))}


@pytest.mark.slow
def test_timezone_byte_identical_incidents(g30: Path, utc_run: dict, tmp_path: Path) -> None:
    _pipeline(g30, tmp_path / "out", tmp_path / "pq", "Asia/Kolkata")
    utc, ist = utc_run["files"], _published(tmp_path / "out")
    assert len(utc) > len(PUBLISHED), "no incidents published"
    assert utc.keys() == ist.keys()
    diff = [k for k in utc if utc[k] != ist[k]]
    assert diff == [], f"differs between TZ=UTC and TZ=Asia/Kolkata: {diff}"


@pytest.mark.slow
def test_rerun_same_dirs_idempotent(g30: Path, utc_run: dict) -> None:
    out, pq = utc_run["out"], utc_run["pq"]
    _pipeline(g30, out, pq, "UTC")  # same --out and --parquet: must not duplicate Parquet or keep stale files
    acc2 = json.loads((out / "ingest_accounting.json").read_text(encoding="utf-8"))
    assert acc2 == utc_run["acc"]
    import duckdb
    n = duckdb.connect().execute(
        f"SELECT count(*) FROM read_parquet('{(pq / 'events').as_posix()}/**/*.parquet')").fetchone()[0]
    assert n == sum(a["rows_in"] for a in acc2), "events duplicated on re-run"  # quarantined rows are kept too
    second = _published(out)
    assert second.keys() == utc_run["files"].keys()
    assert [k for k in second if second[k] != utc_run["files"][k]] == []


# ---------------------------------------------------------------- hostile bytes / layouts (code review, W3)
def accounted(ctx, source_type: str, rows_in: int) -> dict[str, int]:
    """The run completed and every line is accounted for: rows_in exact, ok + dropped = rows_in, reasons logged."""
    acc = accounting(ctx)
    assert source_type in acc, f"{source_type} missing from accounting: {acc}"
    a = acc[source_type]
    assert a["rows_in"] == rows_in, a
    assert a["rows_ok"] + a["dropped"] == a["rows_in"], a
    if a["dropped"]:
        assert_drop_reason(ctx, source_type)
    return a


def good_ts(ctx) -> list[int]:
    return [r["ts_ms"] for r in query(ctx, "SELECT ts_ms FROM events WHERE ts_ok ORDER BY ts_ms")]


def test_invalid_utf8_byte_in_json_line(tmp_path: Path) -> None:
    bad = line(ecs("2026-10-24T03:00:00.500Z", user="pméhta")).encode().replace("é".encode(), b"\xff")
    body = (GOOD[0] + "\n").encode() + bad + b"\n" + ("\n".join(GOOD[1:]) + "\n").encode()
    ctx = ingest_files(tmp_path, {"part-0.jsonl": body})
    accounted(ctx, "ecs_json", 4)
    assert set(GOOD_MS) <= set(good_ts(ctx))


def test_nul_byte_in_json_line(tmp_path: Path) -> None:
    bad = line(ecs("2026-10-24T03:00:00.500Z", user="pmehta")).encode().replace(b"pmehta", b"pm\x00ehta")
    body = (GOOD[0] + "\n").encode() + bad + b"\n" + ("\n".join(GOOD[1:]) + "\n").encode()
    ctx = ingest_files(tmp_path, {"part-0.jsonl": body})
    accounted(ctx, "ecs_json", 4)
    assert set(GOOD_MS) <= set(good_ts(ctx))


@pytest.mark.xfail(strict=True, reason="BUG (BB-ingest): a lone CR (0x0D) is treated as a line break - rows_in 5 for 4 lines (2 half-lines dropped)")
def test_lone_cr_inside_a_line(tmp_path: Path) -> None:
    bad = line(ecs("2026-10-24T03:00:00.500Z", user="pmehta")).encode().replace(b"pmehta", b"pm\rehta")
    body = (GOOD[0] + "\n").encode() + bad + b"\n" + ("\n".join(GOOD[1:]) + "\n").encode()
    ctx = ingest_files(tmp_path, {"part-0.jsonl": body})
    accounted(ctx, "ecs_json", 4)  # \n is the only line terminator
    assert set(GOOD_MS) <= set(good_ts(ctx))


def test_mixed_crlf_lf_inside_and_after_profile_sample(tmp_path: Path) -> None:
    from attacklens import config
    sample = int((config.load_config().get("pipeline") or {}).get("profile", {}).get("sample_lines", 20000))
    n = sample + 10
    base = 1792810800000
    lines = [line(ecs(f"2026-10-24T03:00:00.000Z", user=f"u{i}")).replace("03:00:00.000Z", "03:00:00.000Z")
             for i in range(n)]
    ends = [b"\r\n" if (i % 2 or i >= sample) else b"\n" for i in range(n)]  # mixed in sample, CRLF after it
    body = b"".join(l.encode() + e for l, e in zip(lines, ends))
    ctx = ingest_files(tmp_path, {"part-0.jsonl": body})
    a = accounted(ctx, "ecs_json", n)
    assert a["rows_ok"] == n and a["dropped"] == 0
    assert query(ctx, "SELECT count(*) n FROM events WHERE contains(raw_line, chr(13))")[0]["n"] == 0
    assert query(ctx, "SELECT count(DISTINCT target_user) n FROM events")[0]["n"] == n
    assert {r["ts_ms"] for r in query(ctx, "SELECT DISTINCT ts_ms FROM events")} == {base}


def test_csv_quoted_newline(tmp_path: Path) -> None:
    body = ("timestamp,device,src,dst,dport,bytes_sent,action,note\n"
            "2026-10-24T02:40:00Z,FW-EDGE-01,10.10.3.15,198.51.100.23,443,100,allow,plain\n"
            '2026-10-24T02:41:00Z,FW-EDGE-01,10.10.3.15,198.51.100.24,443,200,allow,"two\nlines"\n'
            "2026-10-24T02:42:00Z,FW-EDGE-01,10.10.3.15,198.51.100.25,443,300,deny,plain\n").encode()
    ctx = ingest_files(tmp_path, {"fw.log": body})
    a = accounted(ctx, "firewall_csv", 3)  # 3 records (4 physical data lines)
    assert a["rows_ok"] == 3
    rows = query(ctx, "SELECT ts_ms, dst_ip, bytes_out FROM events ORDER BY ts_ms")
    assert rows == [{"ts_ms": 1792809600000, "dst_ip": "198.51.100.23", "bytes_out": 100},
                    {"ts_ms": 1792809660000, "dst_ip": "198.51.100.24", "bytes_out": 200},
                    {"ts_ms": 1792809720000, "dst_ip": "198.51.100.25", "bytes_out": 300}]


def test_unrecognized_file_lines_counted(tmp_path: Path) -> None:
    ctx = ingest_files(tmp_path, {"part-0.jsonl": ("\n".join(GOOD) + "\n").encode(),
                                  "notes.dat": b"just some notes\nsecond line\nthird line\n"})
    rows = json.loads((ctx.out_dir / "ingest_accounting.json").read_text(encoding="utf-8"))
    un = [r for r in rows if r["source_type"] == "unrecognized"]
    assert len(un) == 1 and (un[0]["rows_in"], un[0]["dropped"]) == (3, 3), un
    assert accounting(ctx)["ecs_json"] == {"rows_in": 3, "rows_ok": 3, "dropped": 0}


def test_cef_raw_line_has_no_header_labels(tmp_path: Path) -> None:
    sig, name = "a1b2c3d4", "Office spawned script"
    cef = (f"CEF:0|Mitigata|SimEDR|1.0|{sig}|{name}|8|rt=2026-10-24T02:50:00.000Z dvchost=WS-HR-012 "
           "suser=pmehta act=process_created dproc=powershell.exe cs2Label=mitre cs2=T1059.001\n")
    ctx = ingest_files(tmp_path, {"edr.cef": cef.encode()})
    accounted(ctx, "cef", 1)
    raw = query(ctx, "SELECT raw_line FROM events")[0]["raw_line"]
    for leak in (sig, name, "T1059.001", "cs2Label=mitre"):
        assert leak not in raw, f"generator label {leak!r} in raw_line: {raw}"


@pytest.mark.xfail(strict=True, reason="BUG (BB-ingest): identical lines in one file share source_seq (hash(filename, raw_line)) - 3 rows, 2 distinct")
def test_duplicate_identical_lines_distinct_source_seq(tmp_path: Path) -> None:
    ctx = ingest_files(tmp_path, {"part-0.jsonl": (GOOD[0] + "\n" + GOOD[0] + "\n" + GOOD[1] + "\n").encode()})
    accounted(ctx, "ecs_json", 3)
    r = query(ctx, "SELECT count(*) n, count(DISTINCT source_seq) d FROM events")[0]
    assert r == {"n": 3, "d": 3}


def test_quote_in_directories_full_pipeline(tmp_path: Path) -> None:
    from attacklens.run import run_pipeline
    base = tmp_path / "o'brien"
    raw = base / "r'aw"
    shutil.copytree(FIXTURES / "ingest", raw)
    m = run_pipeline(raw, base / "o'ut", parquet=base / "p'q")
    assert m.get("error") is None
    acc = json.loads((base / "o'ut" / "ingest_accounting.json").read_text(encoding="utf-8"))
    assert sum(a["rows_in"] for a in acc) == 17
    assert (base / "o'ut" / "incidents_index.json").exists()
