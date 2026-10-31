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
