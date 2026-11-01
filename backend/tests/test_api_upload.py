"""Upload API (api_upload.py + hooks in api.py / api_runs.py): streaming, name/extension/size checks, disk checks,
partial cleanup, local hard link, GET lists, and the store switching to a run's output after rc 0.
All roots live under tmp_path (written by backend-builder by explicit exception to test ownership)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import threading
import time
import traceback
import tracemalloc
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.requests import ClientDisconnect

from attacklens.api import AppState, create_app
from attacklens.api_runs import RunManager
from attacklens.api_store import Store
from attacklens.api_upload import UploadConfig, UploadError, UploadManager, sanitize_name
from attacklens.config import REPO_ROOT

BOUNDARY = "----attacklens-test-boundary"
CTYPE = f"multipart/form-data; boundary={BOUNDARY}"
MOCK = REPO_ROOT / "frontend" / "src" / "mock" / "incident.json"

STUB_RUN = '''
import json, sys
from pathlib import Path
a = sys.argv[1:]
out = Path(a[a.index("--out") + 1]); raw = Path(a[a.index("--raw") + 1])
if (raw / "fail.log").exists():  # input data echoed in a log line, then run.py's own failure message
    print('2026-10-31 10:00:00,000 WARNING attacklens.ingest: odd line {"user":"SECRET-RAW-DATA"}')
    print("2026-10-31 10:00:01,000 ERROR attacklens.run: pipeline failed: ValueError: no recognized source files")
    print("Traceback (most recent call last):")
    print('  File "run.py", line 1, in <module>')
    print("ValueError: no recognized source files")
    print('trailing raw {"user":"SECRET-RAW-DATA"}')
    sys.exit(1)
if (raw / "crash.log").exists():
    print('raw {"user":"SECRET-RAW-DATA"}')
    sys.exit(3)
if (raw / "duck.log").exists():  # a real DuckDB conversion error, logged the way run.py logs it
    import duckdb
    print("2026-10-31 10:00:00,000 INFO attacklens.run: stage ingest start")
    try:
        duckdb.sql("SELECT CAST(x AS INTEGER) FROM (SELECT 'SECRET-RAW-DATA' AS x)").fetchall()
    except Exception as exc:
        err = f"{type(exc).__name__}: {exc}"
    print(f"2026-10-31 10:00:01,000 ERROR attacklens.run: pipeline failed: {err}")
    print("Traceback (most recent call last):")
    print(f"_duckdb.{err}")
    sys.exit(1)
inc = json.loads(Path(sys.argv[0]).with_name("incident.json").read_text(encoding="utf-8"))
(out / "incidents").mkdir(parents=True, exist_ok=True)
(out / "incidents" / (inc["id"] + ".json")).write_text(json.dumps(inc), encoding="utf-8")
row = {k: inc[k] for k in ("id", "risk", "first_ts", "last_ts", "merged_alert_count", "episode_count", "tactics")}
row.update(hosts=["srv-dc-01"], entry_summary="stub")
(out / "incidents_index.json").write_text(json.dumps([row]), encoding="utf-8")
print("stage publish done")
import time
while (raw / "hold.txt").exists():  # tests hold the run open after its outputs are written
    time.sleep(0.05)
'''


def part(name: str, data: bytes, field: str = "files") -> list[bytes]:
    head = (f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{name}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode()
    return [head, data, b"\r\n"]


def body(*parts: list[bytes]) -> bytes:
    return b"".join(b for p in parts for b in p) + f"--{BOUNDARY}--\r\n".encode()


async def agen(chunks: Iterator[bytes] | list[bytes]) -> AsyncIterator[bytes]:
    for c in chunks:
        yield c


def receive(mgr: UploadManager, chunks, length: int | None = None) -> dict:
    return asyncio.run(mgr.receive(CTYPE, length, agen(chunks)))


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    free = {"bytes": 10**15}
    cfg = UploadConfig(root=tmp_path / "data" / "raw" / "uploads", max_bytes=64 * 2**20, min_free_bytes=2**20,
                       chunk_bytes=2**20, check_every=256 * 1024)
    mgr = UploadManager(cfg, repo_root=tmp_path, disk_free=lambda p: free["bytes"])
    (tmp_path / "bin").mkdir()
    stub = tmp_path / "bin" / "stub_run.py"
    stub.write_text(STUB_RUN, encoding="utf-8")
    (tmp_path / "bin" / "incident.json").write_text(MOCK.read_text(encoding="utf-8"), encoding="utf-8")
    empty_out = tmp_path / "data" / "out" / "empty"
    empty_out.mkdir(parents=True)
    monkeypatch.setenv("ATTACKLENS_OUT", str(empty_out))
    runs = RunManager(runs_dir=tmp_path / "runs", raw_root=tmp_path / "data" / "raw",
                      out_root=tmp_path / "data" / "out", runner=[sys.executable, str(stub)])
    before = set(threading.enumerate())
    state = AppState(store=Store(), runs=runs, uploads=mgr)
    app = create_app(state)
    yield {"tmp": tmp_path, "mgr": mgr, "cfg": cfg, "free": free, "client": TestClient(app)}
    stop_scans(state, before)


def stop_scans(state: AppState, before: set[threading.Thread], timeout: float = 30.0) -> None:
    """Teardown: uploads through the client auto-start integrity quick scans (16 MiB read chunks) on a pool. Shut
    the pool down and join its workers so no scan is still reading (and counted by tracemalloc) in a later test."""
    scans = getattr(state, "integrity_scans", None)
    if scans is None:
        return
    scans.shutdown()  # queued scans cancelled; a running one finishes, then its worker exits
    deadline = time.monotonic() + timeout
    for t in set(threading.enumerate()) - before:
        if t.name.startswith("integrity-scan"):
            t.join(max(0.0, deadline - time.monotonic()))
            assert not t.is_alive(), f"integrity scan thread {t.name} still running after {timeout:.0f} s"


def wait_no_scan_running(timeout: float = 30.0) -> None:
    """Bounded wait until no thread (from any earlier test, whatever its teardown) is inside an integrity scan job.
    Idle pool workers allocate nothing; a running scan's read buffers would count in this thread's tracemalloc."""
    deadline = time.monotonic() + timeout
    while True:
        frames = sys._current_frames()
        busy = [t.name for t in threading.enumerate() if (f := frames.get(t.ident)) is not None
                and any(fr.f_code.co_name == "_work" and fr.f_code.co_filename.endswith("api_integrity.py")
                        for fr, _ in traceback.walk_stack(f))]
        if not busy:
            return
        assert time.monotonic() < deadline, f"integrity scans still running after {timeout:.0f} s: {busy}"
        time.sleep(0.05)


def no_leftovers(cfg: UploadConfig) -> bool:
    incoming = cfg.root / ".incoming"
    uploads = [d for d in cfg.root.iterdir() if not d.name.startswith(".")] if cfg.root.exists() else []
    return not uploads and (not incoming.exists() or not any(incoming.iterdir()))


# ---------------------------------------------------------------- streaming + contract
def test_upload_contract_and_content(env) -> None:
    a = os.urandom(3 * 2**20 + 17)
    b = b'{"@timestamp":"2026-10-24T00:00:00Z"}\n' * 1000
    r = env["client"].post("/api/uploads", content=body(part("fw a.log", a), part("events.jsonl", b)),
                           headers={"content-type": CTYPE})
    assert r.status_code == 201, r.text
    j = r.json()
    assert set(j) >= {"upload_id", "raw_dir", "files", "total_bytes"}
    assert j["raw_dir"] == f"data/raw/uploads/{j['upload_id']}"
    assert j["files"] == [{"name": "fw_a.log", "bytes": len(a)}, {"name": "events.jsonl", "bytes": len(b)}]
    assert j["total_bytes"] == len(a) + len(b)
    d = env["tmp"] / j["raw_dir"]
    assert hashlib.sha256((d / "fw_a.log").read_bytes()).digest() == hashlib.sha256(a).digest()
    assert (d / "events.jsonl").read_bytes() == b
    assert not any((env["cfg"].root / ".incoming").iterdir())          # renamed into place when complete


def test_upload_is_streamed_not_buffered(env) -> None:
    """24 MiB body fed in 64 KiB chunks: Python heap peak stays far below the file size."""
    blk = b"x" * 65536

    def chunks() -> Iterator[bytes]:
        head, _, tail = part("big.log", b"")
        yield head
        for _ in range(384):  # 24 MiB
            yield blk
        yield tail + f"--{BOUNDARY}--\r\n".encode()

    # tracemalloc counts every thread: keep the auto-started integrity quick scan (16 MiB read chunks) out of this
    # receive-path measurement
    env["mgr"].on_complete = None
    wait_no_scan_running()  # a scan leaked by an earlier test file would be measured too
    tracemalloc.start()
    try:
        j = receive(env["mgr"], chunks())
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert j["files"] == [{"name": "big.log", "bytes": 384 * 65536}]
    assert peak < 8 * 2**20, peak


def test_get_uploads_newest_first(env) -> None:
    c = env["client"]
    ids = []
    for n in ("one.log", "two.log"):
        ids.append(c.post("/api/uploads", content=body(part(n, b"x\n")), headers={"content-type": CTYPE})
                   .json()["upload_id"])
        time.sleep(1.1)  # ids/created_at have 1 s resolution
    lst = c.get("/api/uploads").json()
    assert [u["upload_id"] for u in lst] == ids[::-1]
    assert set(lst[0]) >= {"upload_id", "raw_dir", "files", "total_bytes", "created_at"}


# ---------------------------------------------------------------- names, extensions, size, disk, cleanup
@pytest.mark.parametrize("name", ["../evil.log", "a/../../evil.log", "C:\\Windows\\evil.log", "/etc/evil.log",
                                  "\\\\server\\share\\evil.log", "", "   "])
def test_traversal_and_empty_names_rejected(env, name: str) -> None:
    r = env["client"].post("/api/uploads", content=body(part("ok.log", b"fine\n"), part(name, b"bad\n")),
                           headers={"content-type": CTYPE})
    assert r.status_code == 400, r.text
    assert no_leftovers(env["cfg"])                                     # the good first file is gone too


def test_sanitize_keeps_basename_only() -> None:
    ext = (".log",)
    assert sanitize_name("dir/sub/fw.log", ext) == "fw.log"
    assert sanitize_name("we ird;name$.log", ext) == "we_ird_name_.log"
    assert sanitize_name(".hidden.log", ext) == "hidden.log"


@pytest.mark.parametrize("name", ["tool.exe", "noext", "a.log.ps1", "x.LOG.zip"])
def test_extension_rejected(env, name: str) -> None:
    r = env["client"].post("/api/uploads", content=body(part(name, b"x\n")), headers={"content-type": CTYPE})
    assert r.status_code == 415, r.text
    assert no_leftovers(env["cfg"])


def test_extension_case_insensitive(env) -> None:
    r = env["client"].post("/api/uploads", content=body(part("FW.LOG", b"x\n")), headers={"content-type": CTYPE})
    assert r.status_code == 201 and r.json()["files"][0]["name"] == "FW.LOG"


def test_size_cap_by_content_length(env) -> None:
    env["cfg"].max_bytes = 1000
    r = env["client"].post("/api/uploads", content=body(part("a.log", b"x" * (3 * 2**20))),
                           headers={"content-type": CTYPE})
    assert r.status_code == 413
    assert no_leftovers(env["cfg"])


def test_size_cap_while_streaming_without_length(env) -> None:
    env["cfg"].max_bytes = 100_000
    with pytest.raises(UploadError) as e:
        receive(env["mgr"], [b"".join(part("a.log", b"y" * 300_000)) + f"--{BOUNDARY}--\r\n".encode()])
    assert e.value.status == 413
    assert no_leftovers(env["cfg"])


def test_free_disk_checked_before(env) -> None:
    env["free"]["bytes"] = 2**20 + 10          # reserve is 1 MiB: a 1 KiB+ upload does not fit
    r = env["client"].post("/api/uploads", content=body(part("a.log", b"z" * 4096)), headers={"content-type": CTYPE})
    assert r.status_code == 507
    assert no_leftovers(env["cfg"])


def test_free_disk_checked_during_write(env) -> None:
    calls = {"n": 0}

    def shrinking(_: Path) -> int:
        calls["n"] += 1
        return 10**12 if calls["n"] == 1 else 0   # fine before the write, disk full during it
    env["mgr"]._disk_free = shrinking
    with pytest.raises(UploadError) as e:
        receive(env["mgr"], [b"".join(part("a.log", b"w" * (2 * 2**20))) + f"--{BOUNDARY}--\r\n".encode()],
                length=2 * 2**20 + 300)
    assert e.value.status == 507 and calls["n"] >= 2
    assert no_leftovers(env["cfg"])


def test_partial_upload_removed_on_disconnect(env) -> None:
    def chunks() -> Iterator[bytes]:
        head, _, _ = part("a.log", b"")
        yield head
        yield b"q" * 500_000
        raise ClientDisconnect()

    with pytest.raises(ClientDisconnect):
        receive(env["mgr"], chunks())
    assert no_leftovers(env["cfg"])


def test_no_files_and_bad_content_type(env) -> None:
    c = env["client"]
    r = c.post("/api/uploads", content=body(part("a.log", b"x", field="other")), headers={"content-type": CTYPE})
    assert r.status_code == 400 and no_leftovers(env["cfg"])
    assert c.post("/api/uploads", json={"files": []}).status_code == 400


# ---------------------------------------------------------------- local registration
def test_local_hard_link(env) -> None:
    src = env["tmp"] / "logs" / "firex-10G.log"
    src.parent.mkdir()
    src.write_bytes(b"date=2026-10-24 time=00:00:00 devname=FGT\n" * 100)
    r = env["client"].post("/api/uploads/local", json={"path": str(src)})
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["mode"] == "link" and j["files"] == [{"name": "firex-10G.log", "bytes": src.stat().st_size}]
    dst = env["tmp"] / j["raw_dir"] / "firex-10G.log"
    assert os.path.samefile(src, dst)                                   # same file, no copy
    assert j["raw_dir"] == f"data/raw/uploads/{j['upload_id']}"


def test_local_copy_fallback(env, monkeypatch: pytest.MonkeyPatch) -> None:
    src = env["tmp"] / "other.csv"
    src.write_bytes(b"timestamp,src,dst,dport\n" + b"2026-10-24T00:00:00Z,10.0.0.1,10.0.0.2,445\n" * 50)

    def no_link(*_a, **_k):
        raise OSError("cross-device link")
    monkeypatch.setattr(os, "link", no_link)
    j = env["client"].post("/api/uploads/local", json={"path": str(src)}).json()
    assert j["mode"] == "copy"
    dst = env["tmp"] / j["raw_dir"] / "other.csv"
    assert dst.read_bytes() == src.read_bytes() and not os.path.samefile(src, dst)


def test_local_rejections(env) -> None:
    c, tmp = env["client"], env["tmp"]
    (tmp / "tool.exe").write_bytes(b"MZ")
    (tmp / "adir.log").mkdir()
    assert c.post("/api/uploads/local", json={"path": "relative/a.log"}).status_code == 400
    assert c.post("/api/uploads/local", json={"path": str(tmp / "missing.log")}).status_code == 404
    assert c.post("/api/uploads/local", json={"path": str(tmp / "tool.exe")}).status_code == 415
    assert c.post("/api/uploads/local", json={"path": str(tmp / "adir.log")}).status_code == 400
    assert no_leftovers(env["cfg"])


# ---------------------------------------------------------------- run on an upload, then serve its output
def _wait(c: TestClient, rid: str) -> dict:
    for _ in range(300):
        s = c.get(f"/api/runs/{rid}").json()
        if s["status"] != "running":
            return s
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_run_on_upload_switches_served_output(env) -> None:
    c, tmp = env["client"], env["tmp"]
    assert c.get("/api/incidents").json() == []
    up = c.post("/api/uploads", content=body(part("a.log", b"x\n")), headers={"content-type": CTYPE}).json()
    r = c.post("/api/runs", json={"raw_dir": str(tmp / up["raw_dir"])})   # data/raw/uploads/<id> passes confined()
    assert r.status_code == 202, r.text
    rid = r.json()["run_id"]
    s = _wait(c, rid)
    assert s["status"] == "succeeded" and s["returncode"] == 0 and s["error"] is None
    inc = json.loads(MOCK.read_text(encoding="utf-8"))
    assert [i["id"] for i in c.get("/api/incidents").json()] == [inc["id"]]    # no restart needed
    h = c.get("/api/health").json()
    assert Path(h["served_out_dir"]) == (tmp / "data" / "out" / up["upload_id"]).resolve()
    assert c.get(f"/api/incidents/{inc['id']}").status_code == 200
    runs = c.get("/api/runs").json()
    assert runs[0]["run_id"] == rid and set(runs[0]) == set(s)


def test_failed_run_does_not_switch(env) -> None:
    c, tmp = env["client"], env["tmp"]
    before = c.get("/api/health").json()["served_out_dir"]
    up = c.post("/api/uploads", content=body(part("fail.log", b"x\n")), headers={"content-type": CTYPE}).json()
    rid = c.post("/api/runs", json={"raw_dir": str(tmp / up["raw_dir"])}).json()["run_id"]
    s = _wait(c, rid)
    assert s["status"] == "failed" and s["returncode"] == 1
    assert s["error"] == "ValueError: no recognized source files"          # run.py's message, not a raw line
    assert c.get("/api/health").json()["served_out_dir"] == before
    assert c.get("/api/incidents").json() == []


def test_failed_run_error_never_echoes_input(env) -> None:
    c, tmp = env["client"], env["tmp"]
    up = c.post("/api/uploads", content=body(part("crash.log", b"x\n")), headers={"content-type": CTYPE}).json()
    rid = c.post("/api/runs", json={"raw_dir": str(tmp / up["raw_dir"])}).json()["run_id"]
    s = _wait(c, rid)
    assert s["status"] == "failed" and s["error"] and "SECRET" not in s["error"] and len(s["error"]) <= 300
    listed = c.get("/api/runs").json()
    assert isinstance(listed, list) and listed[0]["error"] == s["error"]
    assert "SECRET" not in json.dumps(listed)


def test_run_error_capped_and_clean(tmp_path: Path) -> None:
    from attacklens.api_runs import run_error
    log = tmp_path / "run.log"
    log.write_text("x ERROR attacklens.run: pipeline failed: RuntimeError: " + "a\x07" * 400 + "\n", encoding="utf-8")
    e = run_error(log)
    assert len(e) <= 300 and "\x07" not in e and e.startswith("RuntimeError:")


def test_runs_list_newest_first(env) -> None:
    c, tmp = env["client"], env["tmp"]
    ids = []
    for n in ("a.log", "b.log"):
        up = c.post("/api/uploads", content=body(part(n, b"x\n")), headers={"content-type": CTYPE}).json()
        rid = c.post("/api/runs", json={"raw_dir": str(tmp / up["raw_dir"]), "out_dir": str(tmp / "data" / "out" / n[0])}
                     ).json()["run_id"]
        _wait(c, rid)
        ids.append(rid)
        time.sleep(0.02)
    assert [r["run_id"] for r in c.get("/api/runs").json()] == ids[::-1]


# ---------------------------------------------------------------- review fixes (31 Oct): names, truncation, runs
def test_names_differing_only_in_case_do_not_collide(env) -> None:
    """NTFS / APFS are case-insensitive: A.log and a.log would be one file while metadata lists two."""
    r = env["client"].post("/api/uploads", content=body(part("A.log", b"first\n"), part("a.log", b"second\n"),
                                                         part("A.LOG", b"third\n")), headers={"content-type": CTYPE})
    assert r.status_code == 201, r.text
    j = r.json()
    names = [f["name"] for f in j["files"]]
    assert names == ["A.log", "a-1.log", "A-2.LOG"]
    assert len({n.casefold() for n in names}) == 3
    d = env["tmp"] / j["raw_dir"]
    assert sorted(p.name for p in d.iterdir()) == sorted(names)                # three files on disk, not one
    assert [(d / n).read_bytes() for n in names] == [b"first\n", b"second\n", b"third\n"]


@pytest.mark.parametrize("cut", ["mid_part", "after_part", "no_close_dashes"])
def test_truncated_body_without_disconnect_rejected(env, cut: str) -> None:
    """The stream ends normally (no ClientDisconnect) but the closing boundary never arrived."""
    one = b"".join(part("a.log", b"k" * 50_000))
    full = body(part("a.log", b"k" * 50_000))
    data = {"mid_part": one[:30_000], "after_part": one, "no_close_dashes": full[: full.rindex(b"--\r\n")]}[cut]
    with pytest.raises(UploadError) as e:
        receive(env["mgr"], [data])
    assert e.value.status == 400 and "truncated" in e.value.detail
    assert no_leftovers(env["cfg"])
    r = env["client"].post("/api/uploads", content=data, headers={"content-type": CTYPE})
    assert r.status_code == 400 and no_leftovers(env["cfg"])
    assert env["client"].get("/api/uploads").json() == []


def _upload(c: TestClient, name: str = "a.log") -> dict:
    r = c.post("/api/uploads", content=body(part(name, b"x\n")), headers={"content-type": CTYPE})
    assert r.status_code == 201, r.text
    return r.json()


def _served(c: TestClient) -> Path | None:
    s = c.get("/api/health").json()["served_out_dir"]
    return Path(s) if s else None


def _until(cond, what: str, tries: int = 300) -> None:
    for _ in range(tries):
        if cond():
            return
        time.sleep(0.05)
    raise AssertionError(what)


def test_reanalyse_served_upload_writes_fresh_out_dir(env) -> None:
    c, tmp = env["client"], env["tmp"]
    up = _upload(c)
    raw = tmp / up["raw_dir"]
    first = c.post("/api/runs", json={"raw_dir": str(raw)}).json()["run_id"]
    assert _wait(c, first)["status"] == "succeeded"
    served = (tmp / "data" / "out" / up["upload_id"]).resolve()
    assert _served(c) == served
    stamp = (served / "incidents_index.json").stat().st_mtime_ns

    # explicit out_dir == the served dir: refused
    r = c.post("/api/runs", json={"raw_dir": str(raw), "out_dir": str(served)})
    assert r.status_code == 400 and "serving" in r.json()["detail"]

    # default out_dir: a fresh <upload_id>-<run_id>; the store keeps serving the old dir while the run is open
    (raw / "hold.txt").write_text("", encoding="utf-8")
    r = c.post("/api/runs", json={"raw_dir": str(raw)})
    assert r.status_code == 202, r.text
    rid = r.json()["run_id"]
    job = c.app.state.al.runs.get(rid)
    fresh = (tmp / "data" / "out" / f"{up['upload_id']}-{rid}").resolve()
    assert job.out_dir == fresh and job.cmd[job.cmd.index("--out") + 1] == str(fresh)
    assert "--parquet" in job.cmd                                       # parquet dir reused, not duplicated
    _until(lambda: (fresh / "incidents_index.json").exists(), "rerun wrote no outputs")
    time.sleep(1.1)                                                     # past the store's 1 s mtime check interval
    assert _served(c) == served and c.get(f"/api/runs/{rid}").json()["status"] == "running"
    assert (served / "incidents_index.json").stat().st_mtime_ns == stamp   # served dir never touched
    (raw / "hold.txt").unlink()
    assert _wait(c, rid)["status"] == "succeeded"
    assert _served(c) == fresh                                          # switched only after rc 0


def test_failed_reanalyse_leaves_served_output_intact(env) -> None:
    c, tmp = env["client"], env["tmp"]
    up = _upload(c)
    raw = tmp / up["raw_dir"]
    assert _wait(c, c.post("/api/runs", json={"raw_dir": str(raw)}).json()["run_id"])["status"] == "succeeded"
    served = _served(c)
    assert served is not None
    before = {p.relative_to(served).as_posix(): p.read_bytes() for p in served.rglob("*") if p.is_file()}
    (raw / "fail.log").write_bytes(b"x\n")                              # the stub fails on this raw dir now
    rid = c.post("/api/runs", json={"raw_dir": str(raw)}).json()["run_id"]
    assert _wait(c, rid)["status"] == "failed"
    assert _served(c) == served
    after = {p.relative_to(served).as_posix(): p.read_bytes() for p in served.rglob("*") if p.is_file()}
    assert after == before


def test_unpinned_newest_never_picks_a_running_run(env, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without $ATTACKLENS_OUT the store serves the newest data/out/<set>: a run still writing is excluded."""
    from attacklens import api_store
    c, tmp = env["client"], env["tmp"]
    monkeypatch.delenv("ATTACKLENS_OUT")
    monkeypatch.setattr(api_store, "REPO_ROOT", tmp)
    up = _upload(c)
    raw = tmp / up["raw_dir"]
    (raw / "hold.txt").write_text("", encoding="utf-8")
    rid = c.post("/api/runs", json={"raw_dir": str(raw)}).json()["run_id"]
    out = (tmp / "data" / "out" / up["upload_id"]).resolve()
    _until(lambda: (out / "incidents_index.json").exists(), "run wrote no outputs")
    time.sleep(1.1)
    assert _served(c) != out and c.get("/api/incidents").json() == []
    (raw / "hold.txt").unlink()
    assert _wait(c, rid)["status"] == "succeeded"
    assert _served(c) == out


def test_run_error_redacts_duckdb_input_values(tmp_path: Path) -> None:
    import duckdb

    from attacklens.api_runs import run_error
    msgs = []
    for sql in ("SELECT CAST(x AS INTEGER) FROM (SELECT 'SECRET-VALUE-1' AS x)",
                "SELECT strptime(x, '%Y') FROM (SELECT 'SECRET-VALUE-1' AS x)",
                "SELECT secret_value_1 FROM (SELECT 1 AS y)"):
        with pytest.raises(duckdb.Error) as ei:
            duckdb.sql(sql).fetchall()
        err = f"{type(ei.value).__name__}: {ei.value}"
        log = tmp_path / "run.log"
        log.write_text("2026-10-31 10:00:00,000 INFO attacklens.run: stage profile start\n"
                       "2026-10-31 10:00:00,100 INFO attacklens.run: stage ingest start\n"
                       f"2026-10-31 10:00:01,000 ERROR attacklens.run: pipeline failed: {err}\n"
                       f"Traceback (most recent call last):\n_duckdb.{err}\n", encoding="utf-8")
        e = run_error(log)
        msgs.append(e)
        assert "secret" not in e.lower() and "LINE" not in e, e
        assert e.startswith(type(ei.value).__name__ + ":") and e.endswith("(stage ingest)") and len(e) <= 300, e
    assert "Could not convert string <redacted> to INT32" in msgs[0]


def test_run_error_via_api_never_echoes_duckdb_value(env) -> None:
    c, tmp = env["client"], env["tmp"]
    up = _upload(c, "duck.log")
    s = _wait(c, c.post("/api/runs", json={"raw_dir": str(tmp / up["raw_dir"])}).json()["run_id"])
    assert s["status"] == "failed" and s["error"].startswith("ConversionException:"), s["error"]
    assert "SECRET" not in json.dumps(c.get("/api/runs").json()) and "(stage ingest)" in s["error"]


def test_sanitize_error_cases() -> None:
    from attacklens.api_runs import sanitize_error
    assert sanitize_error("ValueError: no recognized source files") == "ValueError: no recognized source files"
    assert "SECRET" not in sanitize_error("X: Could not convert string 'a\\'SECRET' to INT32")
    assert "SECRET" not in sanitize_error("ParserException: syntax error at or near SECRET")
    assert "SECRET" not in sanitize_error("X: Malformed JSON.  Input: {user:SECRET}")
    assert "SECRET" not in sanitize_error("X: cut 'SECRET")                     # unterminated quote


# ---------------------------------------------------------------- raw_dir confinement + dot-dirs
def test_runs_accept_only_sets_and_upload_ids(env) -> None:
    c, tmp = env["client"], env["tmp"]
    up = _upload(c)
    raw = tmp / "data" / "raw"
    (raw / "g1" / "sub").mkdir(parents=True)
    (raw / "g1" / "a.log").write_bytes(b"x\n")
    (raw / ".hidden").mkdir()
    (env["cfg"].root / ".incoming" / "up-20261031-000000-abcdef").mkdir(parents=True)
    (tmp / up["raw_dir"] / "nested").mkdir()
    bad = [raw, raw / "uploads", raw / "UPLOADS", raw / "uploads" / ".incoming", raw / "uploads" / ".meta",
           raw / "uploads" / ".incoming" / "up-20261031-000000-abcdef", raw / "g1" / "sub", raw / ".hidden",
           tmp / up["raw_dir"] / "nested"]
    for p in bad:
        r = c.post("/api/runs", json={"raw_dir": str(p)})
        assert r.status_code == 400, (p, r.text)
    assert c.get("/api/runs").json() == []
    for p in (raw / "g1", tmp / up["raw_dir"]):
        r = c.post("/api/runs", json={"raw_dir": str(p), "out_dir": str(tmp / "data" / "out" / p.name[:2])})
        assert r.status_code == 202, r.text
        _wait(c, r.json()["run_id"])


def test_profile_never_ingests_dot_directories(tmp_path: Path) -> None:
    from attacklens.profile import _skip
    root = tmp_path / "uploads"
    assert _skip(root / ".incoming" / "up-x" / "a.log", root, {}) == "hidden_dir"
    assert _skip(root / ".meta" / "up-x.json", root, {}) == "hidden_dir"
    assert _skip(root / "up-x" / "a.log", root, {}) is None
    assert _skip(root / "a.log", root, {}) is None


# ---------------------------------------------------------------- Host allowlist + Origin check
FOREIGN = ["http://evil.example", "null", "http://localhost:5174", "https://localhost:5173", "http://127.0.0.1:9999"]


@pytest.mark.parametrize("origin", FOREIGN)
def test_cross_origin_upload_refused(env, origin: str) -> None:
    c = env["client"]
    r = c.post("/api/uploads", content=body(part("a.log", b"x\n")), headers={"content-type": CTYPE, "origin": origin})
    assert r.status_code == 403, r.text
    assert no_leftovers(env["cfg"])
    for path, payload in (("/api/uploads/local", {"path": str(env["tmp"] / "x.log")}),
                          ("/api/runs", {"raw_dir": "data/raw/x"}), ("/api/reload", None)):
        assert c.post(path, json=payload, headers={"origin": origin}).status_code == 403
    assert c.put("/api/runs", headers={"origin": origin}).status_code == 403
    assert c.delete("/api/runs", headers={"origin": origin}).status_code == 403
    assert c.get("/api/health", headers={"origin": origin}).status_code == 200    # reads are not state-changing


@pytest.mark.parametrize("origin,host", [(None, None), ("http://localhost:5173", "localhost:8000"),
                                         ("http://127.0.0.1:5173", "127.0.0.1:8000"),
                                         ("http://testserver", None), ("http://localhost:8000", "localhost:8000"),
                                         ("http://[::1]:8000", "[::1]:8000")])
def test_same_origin_and_no_origin_uploads_pass(env, origin: str | None, host: str | None) -> None:
    """curl (no Origin), the Vite proxy (Origin :5173, Host localhost:8000) and the API's own origin."""
    h = {"content-type": CTYPE}
    if origin:
        h["origin"] = origin
    if host:
        h["host"] = host
    r = env["client"].post("/api/uploads", content=body(part("a.log", b"x\n")), headers=h)
    assert r.status_code == 201, r.text


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "127.0.0.1.nip.io", "localhost.evil.example"])
def test_untrusted_host_refused(env, host: str) -> None:
    """DNS rebinding: a page on evil.example resolved to 127.0.0.1 sends Host: evil.example."""
    c = env["client"]
    src = env["tmp"] / "secret.log"
    src.write_bytes(b"x\n")
    assert c.post("/api/uploads/local", json={"path": str(src)}, headers={"host": host}).status_code == 400
    assert c.get("/api/health", headers={"host": host}).status_code == 400
    assert c.get("/api/integrations/status", headers={"host": host}).status_code == 400
    assert no_leftovers(env["cfg"])


@pytest.mark.parametrize("host", ["localhost", "localhost:8000", "127.0.0.1:8000", "[::1]:8000"])
def test_trusted_hosts_pass(env, host: str) -> None:
    assert env["client"].get("/api/health", headers={"host": host}).status_code == 200


def test_guard_hosts_and_origins_configurable(env) -> None:
    from attacklens.api_guard import guard_config, norm_origin
    hosts, origins = guard_config({"api": {"trusted_hosts": ["AttackLens.lan"],
                                           "allowed_origins": ["http://attacklens.lan:8000"]}})
    assert {"localhost", "127.0.0.1", "[::1]", "attacklens.lan"} <= set(hosts)
    assert {"http://localhost:5173", "http://127.0.0.1:5173", "http://attacklens.lan:8000"} <= set(origins)
    assert norm_origin("HTTP://LocalHost:80/") == "http://localhost" and norm_origin("http://[::1]:80") == "http://[::1]"
    st = env["client"].app.state.al
    st.trusted_hosts, st.allowed_origins = hosts, origins
    c = TestClient(create_app(st))
    h = {"content-type": CTYPE, "host": "attacklens.lan:9000", "origin": "http://attacklens.lan:8000"}
    assert c.post("/api/uploads", content=body(part("a.log", b"x\n")), headers=h).status_code == 201
    h["origin"] = "http://other.lan"
    assert c.post("/api/uploads", content=body(part("a.log", b"x\n")), headers=h).status_code == 403
