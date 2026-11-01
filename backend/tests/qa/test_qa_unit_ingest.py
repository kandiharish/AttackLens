"""QA unit / white-box tests for attacklens.ingest helpers (track qa_coverage_unit).

scan_lines is the physical line counter behind the "no silent data loss" accounting (rows_in = rows written +
over-long lines + undecodable lines). It is checked against an independent reference splitter (LF, CRLF, lone CR;
a line is non-empty when it is not only spaces) on exact hand-checked inputs and on a seeded random corpus with tiny
chunk / limit sizes so every chunk-boundary branch runs. _chunks / plan_batches / build_units: exact batch shapes.
"""

from __future__ import annotations

import random
import re
from pathlib import Path

import pytest

from attacklens import ingest


def ref_scan(data: bytes, limit: int) -> tuple[int, int]:
    """Independent reference: split like the DuckDB line reader, count non-blank and over-long lines."""
    pieces = re.split(rb"\r\n|\r|\n", data)
    return sum(1 for p in pieces if p.strip(b" ")), sum(1 for p in pieces if len(p) > limit)


def _write(tmp: Path, name: str, data: bytes) -> str:
    p = tmp / name
    p.write_bytes(data)
    return str(p)


@pytest.mark.parametrize("data, expected", [
    (b"", (0, 0)),
    (b"a\nb\nc\n", (3, 0)),                      # fast path: plain LF
    (b"a\nb\nc", (3, 0)),                        # last line without terminator
    (b"a\r\nb\r\n", (2, 0)),                     # CRLF = one terminator
    (b"a\rb\rc", (3, 0)),                        # lone CR terminates a line
    (b"a\n\n\nb\n", (2, 0)),                     # empty lines are not rows
    (b"a\n   \nb\n", (2, 0)),                    # space-only line is blank
    (b"\ta\n\t\n", (2, 0)),                      # tab is NOT blank (DuckDB trim() strips spaces only)
    (b"  x  \n", (1, 0)),                        # space-led but non-blank
    (b"\xff\xfe\x00\n\x00\n", (2, 0)),           # invalid UTF-8 / NUL never throws
])
def test_scan_lines_exact(tmp_path: Path, data: bytes, expected: tuple[int, int]) -> None:
    f = _write(tmp_path, "f.log", data)
    assert ingest.scan_lines([f]) == expected
    assert ingest.physical_lines([f]) == expected[0]


def test_scan_lines_too_long_boundary_exact(tmp_path: Path) -> None:
    # limit 5: a 5-byte line is NOT too long, a 6-byte line is (strictly greater), measured across chunks
    f = _write(tmp_path, "f.log", b"aaaaa\nbbbbbb\ncc\n")
    assert ingest.scan_lines([f], chunk=2, limit=5) == (3, 1)
    g = _write(tmp_path, "g.log", b"aaaaa\nbbbbb\n")
    assert ingest.scan_lines([g], chunk=2, limit=5) == (2, 0)          # near miss: exactly the limit


def test_scan_lines_unterminated_too_long_last_line(tmp_path: Path) -> None:
    f = _write(tmp_path, "f.log", b"ok\n" + b"z" * 40)                 # EOF branch: open line > limit
    assert ingest.scan_lines([f], chunk=4, limit=10) == (2, 1)
    g = _write(tmp_path, "g.log", b"z" * 40)                           # no terminator at all
    assert ingest.scan_lines([g], chunk=4, limit=10) == (1, 1)
    h = _write(tmp_path, "h.log", b" " * 40)                           # long but blank: 0 rows, still too long
    assert ingest.scan_lines([h], chunk=4, limit=10) == (0, 1)


def test_scan_lines_crlf_split_across_chunks(tmp_path: Path) -> None:
    # chunk 3: 'ab\r' | '\ncd' | '\r\n' -> the CR and LF of one terminator land in different chunks
    f = _write(tmp_path, "f.log", b"ab\r\ncd\r\n")
    assert ingest.scan_lines([f], chunk=3, limit=100) == (2, 0)


def test_scan_lines_multi_file_state_resets(tmp_path: Path) -> None:
    a = _write(tmp_path, "a.log", b"x\ny")        # unterminated last line of file a must not join file b
    b = _write(tmp_path, "b.log", b"z\n")
    assert ingest.scan_lines([a, b], chunk=2, limit=10) == (3, 0)


def test_scan_lines_chunk_capped_at_limit(tmp_path: Path) -> None:
    # chunk > limit is reduced to limit, so a 12-byte line inside one big chunk is still found too long
    f = _write(tmp_path, "f.log", b"short\n" + b"q" * 12 + b"\nend\n")
    assert ingest.scan_lines([f], chunk=1 << 20, limit=8) == (3, 1)


def _random_corpus_check(monkeypatch: pytest.MonkeyPatch, n: int, seed: int) -> None:
    """In-memory files (ingest.open patched to BytesIO): the corpus checks the algorithm, not the disk."""
    import io
    store: dict[str, bytes] = {}
    monkeypatch.setattr(ingest, "open", lambda f, mode="rb": io.BytesIO(store[f]), raising=False)
    rng = random.Random(seed)
    alpha = [b"a", b" ", b"\n", b"\r", b"\xff", b"\x00", b"aaaaaaa", b"       ", b"\r\n", b"\n\n"]
    for _ in range(n):
        data = b"".join(rng.choice(alpha) for _ in range(rng.randint(0, 40)))
        store["f.log"] = data
        limit, chunk = rng.randint(3, 15), rng.randint(1, 20)
        assert ingest.scan_lines(["f.log"], chunk=chunk, limit=limit) == ref_scan(data, limit), (data, chunk, limit)


def test_scan_lines_matches_reference_random(monkeypatch: pytest.MonkeyPatch) -> None:
    _random_corpus_check(monkeypatch, 2000, 20261101)


@pytest.mark.stress
def test_scan_lines_matches_reference_random_large(monkeypatch: pytest.MonkeyPatch) -> None:
    _random_corpus_check(monkeypatch, 200_000, 7)


# ---- batching ------------------------------------------------------------------------------------------------
def test_chunks_budget_exact() -> None:
    files = [{"path": p, "size": s} for p, s in (("a", 4), ("b", 4), ("c", 3), ("d", 20), ("e", 1))]
    got = [[f["path"] for f in c] for c in ingest._chunks(files, 10)]
    # a+b = 8 fits, +c = 11 > 10 -> new run; d alone is bigger than the budget (own run); e starts a new run
    assert got == [["a", "b"], ["c"], ["d"], ["e"]]
    assert [[f["path"] for f in c] for c in ingest._chunks(files, 11)] == [["a", "b", "c"], ["d"], ["e"]]
    assert ingest._chunks([], 10) == []
    assert [[f["path"] for f in c] for c in ingest._chunks([{"path": "x"}], 0)] == [["x"]]   # size missing = 0


def test_plan_batches_budget_exact() -> None:
    units = [{"id": i, "bytes": b} for i, b in enumerate([5, 5, 1, 9, 2])]
    got = [[u["id"] for u in b] for b in ingest.plan_batches(units, 10)]
    assert got == [[0, 1], [2, 3], [4]]           # 5+5 = 10 fits (not > budget); 10+1 > 10
    assert [[u["id"] for u in b] for b in ingest.plan_batches(units, 9)] == [[0], [1, 2], [3], [4]]
    assert ingest.plan_batches([], 10) == []


def _prof(files: list[dict]) -> dict:
    return {"raw_dir": "C:/raw/x", "files": files}


def test_build_units_groups_and_skips() -> None:
    from attacklens import config
    cfg = config.load_config()
    cfg.setdefault("pipeline", {}).setdefault("ingest", {})["batch_bytes"] = 100
    files = [
        {"path": "C:/raw/x/a.jsonl", "size": 60, "format": "json", "source_type": "ecs_json"},
        {"path": "C:/raw/x/b.jsonl", "size": 60, "format": "json", "source_type": "ecs_json"},
        {"path": "C:/raw/x/u.bin", "size": 999, "format": "unrecognized", "source_type": None},
        {"path": "C:/raw/x/f1.csv", "size": 10, "format": "csv", "source_type": "firewall_csv",
         "delimiter": ",", "columns": ["timestamp", "src", "dst"]},
        {"path": "C:/raw/x/f2.csv", "size": 10, "format": "csv", "source_type": "firewall_csv",
         "delimiter": ",", "columns": ["timestamp", "src", "dport"]},     # other header -> other unit
        {"path": "C:/raw/x/w.weird", "size": 5, "format": "mystery", "source_type": "x"},   # unknown format
    ]
    units = ingest.build_units(_prof(files), cfg)
    shape = [(u["format"], u["source_type"], [Path(f).name for f in u["files"]], u["bytes"], u["rejects"])
             for u in units]
    assert shape == [
        ("json", "ecs_json", ["a.jsonl"], 60, None),         # 60 + 60 > 100 -> two units
        ("json", "ecs_json", ["b.jsonl"], 60, None),
        ("csv", "firewall_csv", ["f1.csv"], 10, "rej_ingest_2"),   # rejects tables only for CSV
        ("csv", "firewall_csv", ["f2.csv"], 10, "rej_ingest_3"),
    ]
    assert [u["rejects_key"] for u in units] == ["unit_0", "unit_1", "unit_2", "unit_3"]
    assert units[2]["columns"] == ["timestamp", "src", "dst"] and units[2]["delimiter"] == ","
    assert all(isinstance(u["select"], str) and u["select"].startswith("SELECT") for u in units)


def test_copy_settings_only_configured() -> None:
    class Ctx:  # _copy_settings only reads ctx.cfg
        cfg = {"pipeline": {"ingest": {"threads": 3, "partitioned_write_max_open_files": 64}}}
    assert ingest._copy_settings(Ctx()) == ["SET partitioned_write_max_open_files=64", "SET threads=3"]
    Ctx.cfg = {"pipeline": {"ingest": {"partitioned_write_flush_threshold": 1000}}}
    assert ingest._copy_settings(Ctx()) == ["SET partitioned_write_flush_threshold=1000"]
    Ctx.cfg = {}
    assert ingest._copy_settings(Ctx()) == []


def test_copy_sql_batch_filename_and_compression(tmp_path: Path) -> None:
    from attacklens import config
    cfg = config.load_config()
    cfg["pipeline"].setdefault("ingest", {}).update(compression="SNAPPY", row_group_size=1000)
    sql = ingest.copy_sql(["SELECT 1 AS x"], cfg, tmp_path / "ev", batch=7)
    assert "FILENAME_PATTERN 'b00007_{i}'" in sql
    assert "COMPRESSION SNAPPY" in sql and "ROW_GROUP_SIZE 1000" in sql
    assert "PARTITION_BY (source_type, ts_ok, event_day)" in sql


# ---- product bug QA-COV-01 -------------------------------------------------------------------------------------
@pytest.mark.xfail(strict=True, reason="QA-COV-01: scan_lines treats only b' ' as blank but the reader's NONEMPTY "
                                       "filter uses DuckDB trim(), which also strips Unicode space separators "
                                       "(U+00A0, U+3000); such valid UTF-8 blank lines are reported as "
                                       "'decode_error (invalid UTF-8)' drops")
def test_unicode_space_only_lines_are_not_decode_errors(tmp_path: Path) -> None:
    import json

    from ..conftest import run_ingest
    raw = tmp_path / "raw"
    raw.mkdir()
    ev = {"@timestamp": "2026-10-30T01:00:00Z", "host": {"name": "WS-1"}, "event": {"action": "process_created"}}
    lines = [json.dumps(ev), "  ", json.dumps(ev).replace("WS-1", "WS-2"), "　"]
    (raw / "a.jsonl").write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    ctx = run_ingest(raw, tmp_path)
    try:
        acc = json.loads((ctx.out_dir / "ingest_accounting.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    ecs = next(a for a in acc if a["source_type"] == "ecs_json")
    assert (ecs["rows_ok"], ecs["dropped"]) == (2, 0), ecs     # today: rows_in 4, dropped 2 as decode_error
    assert not any(k.startswith("decode_error") for k in ecs["drop_reasons"]), ecs


def test_space_only_lines_near_miss_counted_blank(tmp_path: Path) -> None:
    """Near miss of QA-COV-01: ASCII-space-only lines are blank for both counters -> no drop at all."""
    import json

    from ..conftest import run_ingest
    raw = tmp_path / "raw"
    raw.mkdir()
    ev = {"@timestamp": "2026-10-30T01:00:00Z", "host": {"name": "WS-1"}, "event": {"action": "process_created"}}
    (raw / "a.jsonl").write_bytes((json.dumps(ev) + "\n   \n" + json.dumps(ev) + "\n").encode("utf-8"))
    ctx = run_ingest(raw, tmp_path)
    try:
        acc = json.loads((ctx.out_dir / "ingest_accounting.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    ecs = next(a for a in acc if a["source_type"] == "ecs_json")
    assert (ecs["rows_in"], ecs["rows_ok"], ecs["dropped"], ecs["drop_reasons"]) == (2, 2, 0, {})


# ---- Stage 1 accounting branches (baseline: never executed) ------------------------------------------------------
FW_HEADER = "timestamp,device,src,dst,dport,bytes_sent,action\n"
FW_OK = "2026-10-24T02:40:00Z,FW-1,10.0.0.1,198.51.100.23,443,100,allow\n"


def _ingest_text(tmp: Path, files: dict[str, bytes]):
    from ..conftest import run_ingest
    raw = tmp / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        (raw / name).write_bytes(body)
    return run_ingest(raw, tmp)


def _acc(ctx) -> dict:
    import json
    return {a["source_type"]: a for a in json.loads((ctx.out_dir / "ingest_accounting.json").read_text("utf-8"))}


def test_csv_missing_columns_counted_with_reason(tmp_path: Path) -> None:
    ctx = _ingest_text(tmp_path, {"fw.log": (FW_HEADER + FW_OK + "2026-10-24T02:41:00Z,FW-1,10.0.0.2\n").encode()})
    try:
        fw = _acc(ctx)["firewall_csv"]
        n = ctx.con.execute("SELECT count(*) FROM events").fetchone()[0]
    finally:
        ctx.con.close()
    assert (fw["rows_in"], fw["rows_ok"], fw["dropped"], fw["drop_reasons"]) == (2, 1, 1, {"csv_missing_columns": 1})
    assert n == 1


def test_csv_extra_fields_kept_with_note(tmp_path: Path) -> None:
    extra = "2026-10-24T02:41:00Z,FW-1,10.0.0.2,1.2.3.4,22,5,deny,EXTRA,MORE\n"
    ctx = _ingest_text(tmp_path, {"fw.log": (FW_HEADER + FW_OK + extra).encode()})
    try:
        fw = _acc(ctx)["firewall_csv"]
        rows = ctx.con.execute("SELECT src_ip, dst_port FROM events ORDER BY src_ip").fetchall()
    finally:
        ctx.con.close()
    assert (fw["rows_in"], fw["rows_ok"], fw["dropped"], fw["drop_reasons"]) == (2, 2, 0, {})
    assert fw["notes"] == {"truncated_columns (extra fields dropped, row kept)": 1}
    assert rows == [("10.0.0.1", 443), ("10.0.0.2", 22)]


def test_csv_clean_near_miss_no_note(tmp_path: Path) -> None:
    ctx = _ingest_text(tmp_path, {"fw.log": (FW_HEADER + FW_OK).encode()})
    try:
        fw = _acc(ctx)["firewall_csv"]
    finally:
        ctx.con.close()
    assert (fw["rows_in"], fw["rows_ok"], fw["dropped"], fw["drop_reasons"]) == (1, 1, 0, {}) and "notes" not in fw


def test_reingest_removes_stale_events(tmp_path: Path) -> None:
    from attacklens import ingest as ing
    two = (b'{"@timestamp":"2026-10-30T01:00:00Z","host":{"name":"A"}}\n'
           b'{"@timestamp":"2026-10-30T01:00:01Z","host":{"name":"B"}}\n')
    ctx = _ingest_text(tmp_path, {"a.jsonl": two})
    try:
        assert ctx.con.execute("SELECT count(*) FROM events").fetchone()[0] == 2
        (ctx.raw_dir / "a.jsonl").write_bytes(two.splitlines(keepends=True)[0])
        ctx.stats.pop("profile", None)
        (ctx.out_dir / "source_profile.json").unlink()   # force a fresh profile of the changed file
        stats = ing.run(ctx)
        n = ctx.con.execute(f"SELECT count(*) FROM read_parquet('{ctx.events_glob}')").fetchone()[0]
    finally:
        ctx.con.close()
    assert (stats["rows_in"], stats["rows_written"], n) == (1, 1, 1)   # the old 2-row partition is gone


def test_profile_reused_from_file_only_for_same_raw_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    from attacklens import ingest as ing
    ctx = _ingest_text(tmp_path, {"a.jsonl": b'{"@timestamp":"2026-10-30T01:00:00Z","host":{"name":"A"}}\n'})
    try:
        ctx.stats.pop("profile", None)                       # a new process: only source_profile.json is left
        calls: list[int] = []
        monkeypatch.setattr(ing.profile_stage, "run", lambda c: calls.append(1) or (_ for _ in ()).throw(
            AssertionError("profile re-run")))
        assert ing._load_profile(ctx)["raw_dir"] == json.loads(
            (ctx.out_dir / "source_profile.json").read_text("utf-8"))["raw_dir"]
        assert calls == []                                    # reused, Stage 0 not re-run
        prof = json.loads((ctx.out_dir / "source_profile.json").read_text("utf-8"))
        prof["raw_dir"] = str(tmp_path / "another_set")       # near miss: profile of another raw dir
        (ctx.out_dir / "source_profile.json").write_text(json.dumps(prof), "utf-8")
        with pytest.raises(AssertionError, match="profile re-run"):
            ing._load_profile(ctx)
        assert calls == [1]
    finally:
        ctx.con.close()


def test_no_recognized_files_accounts_unrecognized_only(tmp_path: Path) -> None:
    from attacklens import ingest as ing
    from attacklens import profile

    from ..conftest import _new_ctx
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "blob.log").write_bytes(b"\x00\x01\x02 binary\n\x03\x04 more\n")
    ctx = _new_ctx(tmp_path, raw_dir=raw)      # no `events` view: there is no event Parquet to register
    try:
        profile.run(ctx)
        stats = ing.run(ctx)
        acc = _acc(ctx)
    finally:
        ctx.con.close()
    assert (stats["rows_in"], stats["rows_ok"], stats["rows_written"], stats["bytes_in"]) == (2, 0, 0, 0)
    assert list(acc) == ["unrecognized"]
    u = acc["unrecognized"]
    assert (u["rows_in"], u["rows_ok"], u["dropped"], u["drop_reasons"]) == (2, 0, 2, {"unrecognized_format": 2})
