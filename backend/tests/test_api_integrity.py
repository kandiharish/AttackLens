"""Integrity API (api_integrity.py + hooks in api.py / api_runs.py / run.py) against the workflow contract:

- GET  /api/integrity                    served out_dir/integrity_report.json, 404 {"detail":"no integrity report"}
- GET  /api/runs/{run_id}/integrity       that run's report, 404 until it exists (RUN_ID_RE validated)
- POST /api/uploads/{upload_id}/integrity (re)start the QUICK scan: 202 {"status":"running"}, 404 unknown, 409 running
- GET  /api/uploads/{upload_id}/integrity {"status":"pending"|"running"|"done"|"failed","report","error"}
- completed uploads auto-start the quick scan; the upload response gains "integrity": {"status":"running"}
- quick-scan output: <data>/out/_integrity/<upload_id>/ (confined), persisted across API restarts
- GET /api/runs/{id} gains "integrity": {"verdict","trust_score","summary","scope"} | null
- run.py: "integrity" appended after "publish" (index 8), NON-FATAL, report scope "full"
- background scans: max 2 concurrent, never block the event loop, exceptions -> status failed with a message

All roots live under tmp_path (same construction as test_api_upload.py); the repo's data/ is never touched.
"""

from __future__ import annotations

import json
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

api_integrity = pytest.importorskip("attacklens.api_integrity")

import yaml  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from attacklens import integrity  # noqa: E402
from attacklens import integrity_raw  # noqa: E402
from attacklens.api import AppState, create_app  # noqa: E402
from attacklens.api_runs import RunManager  # noqa: E402
from attacklens.api_store import Store  # noqa: E402
from attacklens.api_upload import UploadConfig, UploadManager  # noqa: E402
from attacklens.config import REPO_ROOT  # noqa: E402

from .test_api_upload import CTYPE, MOCK, STUB_RUN, body, part  # noqa: E402

CHECK_IDS = ["seal", "zeroed_regions", "truncated_tail", "log_cleared", "silence_gap", "went_dark", "timestamps",
             "duplicates", "embedded_time_mismatch", "ingest_drops"]
EVENT_CHECKS = ["log_cleared", "silence_gap", "went_dark", "timestamps", "duplicates", "embedded_time_mismatch"]
POLL_S = 60.0         # upper bound of the bounded polls (subprocess run, gate); they return as soon as ready
SCAN_WAIT_S = 120.0   # generous upper bound for a tiny quick scan on a saturated machine; normally < 1 s


def clean_bytes(tag: str = "a", n: int = 40) -> bytes:
    return b"".join(f"2026-10-24T02:{i:02d}:00Z ws-{tag} app[{i}]: heartbeat {tag}-{i}\n".encode() for i in range(n))


CLEAN = clean_bytes("a")
NUL_RUN = 4096
WIPED = CLEAN[:400] + b"\x00" * NUL_RUN + CLEAN[400:]          # 4096-byte NUL run in the middle, ends with \n


# ---------------------------------------------------------------- fixtures / helpers
def _app(tmp: Path, cfg: UploadConfig) -> TestClient:
    mgr = UploadManager(cfg, repo_root=tmp, disk_free=lambda p: 10**15)
    runs = RunManager(runs_dir=tmp / "runs", raw_root=tmp / "data" / "raw", out_root=tmp / "data" / "out",
                      runner=[sys.executable, str(tmp / "bin" / "stub_run.py")])
    return TestClient(create_app(AppState(store=Store(), runs=runs, uploads=mgr)))


def _repo_integrity_listing() -> set[str]:
    d = REPO_ROOT / "data" / "out" / "_integrity"
    return {p.name for p in d.iterdir()} if d.is_dir() else set()


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg = UploadConfig(root=tmp_path / "data" / "raw" / "uploads", max_bytes=64 * 2**20, min_free_bytes=2**20,
                       chunk_bytes=2**20, check_every=256 * 1024)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "stub_run.py").write_text(STUB_RUN, encoding="utf-8")
    (tmp_path / "bin" / "incident.json").write_text(MOCK.read_text(encoding="utf-8"), encoding="utf-8")
    served = tmp_path / "data" / "out" / "empty"
    served.mkdir(parents=True)
    monkeypatch.setenv("ATTACKLENS_OUT", str(served))
    before_repo = _repo_integrity_listing()
    client = _app(tmp_path, cfg)
    e = {"tmp": tmp_path, "cfg": cfg, "client": client, "served": served, "uploads": []}
    yield e
    # never leave a scan thread writing into a deleted tmp dir
    for uid in e["uploads"]:
        _until_settled(client, uid, strict=False)
    scans = getattr(client.app.state.al, "integrity_scans", None)
    if scans is not None:
        scans.shutdown(wait=True)  # no idle pool threads leak into later tests (tracemalloc counts every thread)
    assert _repo_integrity_listing() == before_repo, "quick scan wrote into the repo's data/out/_integrity"


def _upload(e: dict, name: str, data: bytes) -> dict:
    r = e["client"].post("/api/uploads", content=body(part(name, data)), headers={"content-type": CTYPE})
    assert r.status_code == 201, r.text
    j = r.json()
    e["uploads"].append(j["upload_id"])
    return j


def _status(c: TestClient, uid: str) -> dict:
    r = c.get(f"/api/uploads/{uid}/integrity")
    assert r.status_code == 200, r.text
    j = r.json()
    assert set(j) >= {"status", "report", "error"}, j
    assert j["status"] in ("pending", "running", "done", "failed"), j
    return j


def _until_settled(c: TestClient, uid: str, strict: bool = True) -> dict:
    # deterministic: block on the scan's own completion event (no wall-clock race on a loaded machine); the bounded
    # poll below then only reads the settled status through the API
    scans = getattr(c.app.state.al, "integrity_scans", None)
    if scans is not None and not scans.wait(uid, timeout=SCAN_WAIT_S) and strict:
        raise AssertionError(f"quick scan of {uid} did not finish within {SCAN_WAIT_S} s (machine overloaded?)")
    t_end = time.monotonic() + POLL_S
    j: dict = {}
    while time.monotonic() < t_end:
        try:
            j = _status(c, uid)
        except AssertionError:
            if strict:
                raise
            return {}
        if j["status"] in ("done", "failed"):
            return j
        time.sleep(0.05)
    if strict:
        raise AssertionError(f"quick scan of {uid} not finished in {POLL_S} s: {j}")
    return j


def _assert_quick_report(rep: dict[str, Any]) -> None:
    assert rep["schema_version"] == 1
    assert rep["scope"] == "quick"
    assert [c["id"] for c in rep["checks"]] == CHECK_IDS
    st = {c["id"]: c["status"] for c in rep["checks"]}
    for cid in EVENT_CHECKS:
        assert st[cid] == "skipped", (cid, st)                  # quick scan = raw files only
    assert st["seal"] == "skipped" and rep["seal"]["status"] == "absent"
    assert st["ingest_drops"] == "skipped"
    assert rep.get("authenticity") is None                      # absent/null on quick scans
    assert rep["inputs"]["events_rows"] in (None, 0)


def _report_path(e: dict, uid: str) -> Path:
    return e["tmp"] / "data" / "out" / "_integrity" / uid / "integrity_report.json"


# ---------------------------------------------------------------- GET /api/integrity (served dataset)
def test_served_integrity_404_then_200(env) -> None:
    c = env["client"]
    r = c.get("/api/integrity")
    assert r.status_code == 404 and r.json() == {"detail": "no integrity report"}
    rep = {"schema_version": 1, "set": "empty", "generated_at": "2026-11-01T08:00:00Z", "verdict": "suspect",
           "trust_score": 64, "summary": "SUSPECT: 1 high finding(s) — silence gap on host:ws-a", "scope": "full",
           "checks": [{"id": i, "status": "pass", "findings": 0, "reason": None} for i in CHECK_IDS],
           "findings": [], "seal": {"status": "absent"}, "files": [], "inputs": {}, "wall_s": 0.1}
    (env["served"] / "integrity_report.json").write_text(json.dumps(rep), encoding="utf-8")
    t_end = time.monotonic() + 30.0                             # store mtime check interval is 1 s (loaded box)
    while (r := c.get("/api/integrity")).status_code == 404 and time.monotonic() < t_end:
        time.sleep(0.1)
    assert r.status_code == 200, r.text
    assert r.json() == rep
    assert r.headers["content-type"].startswith("application/json")


# ---------------------------------------------------------------- GET /api/runs/{id}/integrity
@pytest.mark.parametrize("rid", ["..", "%2e%2e", "0123456789ab", "ZZZZZZZZZZZZ", "0123456789abc", "abc",
                                 "..%2f..%2fetc", "C:%5cWindows"])
def test_run_integrity_bad_or_unknown_id_404(env, rid: str) -> None:
    r = env["client"].get(f"/api/runs/{rid}/integrity")
    assert r.status_code in (404, 422), (rid, r.status_code, r.text)


def _wait_run(c: TestClient, rid: str) -> dict:
    t_end = time.monotonic() + POLL_S
    while time.monotonic() < t_end:
        s = c.get(f"/api/runs/{rid}").json()
        if s["status"] != "running":
            return s
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_run_status_and_run_integrity_once_report_exists(env) -> None:
    c, tmp = env["client"], env["tmp"]
    up = _upload(env, "a.log", CLEAN)
    _until_settled(c, up["upload_id"])
    r = c.post("/api/runs", json={"raw_dir": str(tmp / up["raw_dir"])})
    assert r.status_code == 202, r.text
    rid = r.json()["run_id"]
    s = _wait_run(c, rid)
    assert s["status"] == "succeeded", s
    assert "integrity" in s and s["integrity"] is None            # stub run writes no report
    assert c.get(f"/api/runs/{rid}/integrity").status_code == 404

    out = c.app.state.al.runs.get(rid).out_dir
    rep = {"schema_version": 1, "set": out.name, "generated_at": "2026-11-01T09:00:00Z", "verdict": "tampered",
           "trust_score": 60, "summary": "TAMPERED: 1 critical finding(s) — zeroed region in a.log", "scope": "full",
           "checks": [{"id": i, "status": "pass", "findings": 0, "reason": None} for i in CHECK_IDS],
           "findings": [], "seal": {"status": "absent"}, "files": [], "inputs": {}, "wall_s": 0.2}
    (out / "integrity_report.json").write_text(json.dumps(rep), encoding="utf-8")
    s = c.get(f"/api/runs/{rid}").json()
    assert s["integrity"] == {"verdict": "tampered", "trust_score": 60,
                              "summary": "TAMPERED: 1 critical finding(s) — zeroed region in a.log", "scope": "full"}
    r = c.get(f"/api/runs/{rid}/integrity")
    assert r.status_code == 200 and r.json() == rep
    assert [j["run_id"] for j in c.get("/api/runs").json()] == [rid]


# ---------------------------------------------------------------- upload -> auto quick scan
def test_clean_upload_auto_scan_trusted(env) -> None:
    c = env["client"]
    up = _upload(env, "clean.log", CLEAN)
    assert up["integrity"] == {"status": "running"}
    j = _until_settled(c, up["upload_id"])
    assert j["status"] == "done" and j["error"] is None, j
    rep = j["report"]
    _assert_quick_report(rep)
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 100 and rep["findings"] == []
    st = {x["id"]: x["status"] for x in rep["checks"]}
    assert st["zeroed_regions"] == "pass" and st["truncated_tail"] == "pass"
    assert rep["inputs"]["files"] == 1 and rep["inputs"]["bytes"] == len(CLEAN)
    assert [f["zeroed_bytes"] for f in rep["files"]] == [0]
    p = _report_path(env, up["upload_id"])
    assert p.is_file(), "quick scan must write <data>/out/_integrity/<upload_id>/integrity_report.json"
    assert json.loads(p.read_text(encoding="utf-8")) == rep


def test_nul_run_upload_auto_scan_tampered(env) -> None:
    c = env["client"]
    up = _upload(env, "wiped.log", WIPED)
    assert up["integrity"] == {"status": "running"}
    j = _until_settled(c, up["upload_id"])
    assert j["status"] == "done", j
    rep = j["report"]
    _assert_quick_report(rep)
    assert rep["verdict"] == "tampered" and rep["trust_score"] == 60          # one critical = -40
    z = [f for f in rep["findings"] if f["check"] == "zeroed_regions"]
    assert [(f["severity"], f["count"]) for f in z] == [("critical", NUL_RUN)]
    assert z[0]["file"].endswith("wiped.log")
    assert [f["zeroed_bytes"] for f in rep["files"]] == [NUL_RUN]
    assert rep["summary"].startswith("TAMPERED")


def test_local_upload_auto_starts_scan(env) -> None:
    src = env["tmp"] / "logs" / "wiped.log"
    src.parent.mkdir()
    src.write_bytes(WIPED)
    r = env["client"].post("/api/uploads/local", json={"path": str(src)})
    assert r.status_code == 201, r.text
    up = r.json()
    env["uploads"].append(up["upload_id"])
    assert up["integrity"] == {"status": "running"}
    j = _until_settled(env["client"], up["upload_id"])
    assert j["status"] == "done" and j["report"]["verdict"] == "tampered", j


def test_quick_report_persists_across_api_restart(env) -> None:
    up = _upload(env, "wiped.log", WIPED)
    first = _until_settled(env["client"], up["upload_id"])["report"]
    c2 = _app(env["tmp"], env["cfg"])                            # new process state, same data roots
    j = _status(c2, up["upload_id"])
    assert j["status"] == "done" and j["report"] == first and j["error"] is None


def test_rescan_after_done_returns_202_and_fresh_report(env) -> None:
    c = env["client"]
    up = _upload(env, "a.log", CLEAN)
    first = _until_settled(c, up["upload_id"])["report"]
    assert first["verdict"] == "trusted"
    # the raw file is wiped after upload: a re-scan must see it (no stale cache)
    raw = env["tmp"] / up["raw_dir"] / "a.log"
    raw.write_bytes(WIPED)
    r = c.post(f"/api/uploads/{up['upload_id']}/integrity")
    assert r.status_code == 202 and r.json() == {"status": "running"}, r.text
    j = _until_settled(c, up["upload_id"])
    assert j["status"] == "done" and j["report"]["verdict"] == "tampered", j


# ---------------------------------------------------------------- running / 409 / concurrency bound / failure
class _Gate:
    """Blocks integrity_raw.scan_files until released; counts concurrent scans."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.inside = 0
        self.peak = 0
        self.entered = 0
        orig = integrity_raw.scan_files

        def blocked(*a: Any, **kw: Any):
            with self.lock:
                self.inside += 1
                self.entered += 1
                self.peak = max(self.peak, self.inside)
            try:
                self.release.wait(POLL_S)
                return orig(*a, **kw)
            finally:
                with self.lock:
                    self.inside -= 1

        monkeypatch.setattr(integrity_raw, "scan_files", blocked)


def _until(cond, what: str) -> None:
    t_end = time.monotonic() + POLL_S
    while time.monotonic() < t_end:
        if cond():
            return
        time.sleep(0.02)
    raise AssertionError(what)


def test_post_while_running_409_then_done(env, monkeypatch: pytest.MonkeyPatch) -> None:
    gate = _Gate(monkeypatch)
    c = env["client"]
    try:
        up = _upload(env, "a.log", CLEAN)                       # returns while the scan is blocked: never blocking
        uid = up["upload_id"]
        _until(lambda: gate.entered >= 1, "auto scan never reached the raw scan")
        assert _status(c, uid)["status"] == "running"
        assert _status(c, uid)["report"] is None
        r = c.post(f"/api/uploads/{uid}/integrity")
        assert r.status_code == 409, r.text
        assert c.get("/api/health").status_code == 200          # event loop not blocked by the scan
    finally:
        gate.release.set()
    j = _until_settled(c, uid)
    assert j["status"] == "done" and j["report"]["verdict"] == "trusted"
    assert gate.entered == 1                                    # the 409 did not start a second scan


def test_at_most_two_scans_concurrently(env, monkeypatch: pytest.MonkeyPatch) -> None:
    gate = _Gate(monkeypatch)
    c = env["client"]
    try:
        ups = [_upload(env, f"f{i}.log", clean_bytes(str(i)))["upload_id"] for i in range(3)]
        _until(lambda: gate.entered >= 2, "two scans never started")
        time.sleep(0.3)                                         # a third, unbounded scan would enter now
        assert gate.inside == 2 and gate.entered == 2, (gate.inside, gate.entered)
        assert sorted(_status(c, u)["status"] for u in ups) in (["pending", "running", "running"],
                                                                ["running", "running", "running"])
    finally:
        gate.release.set()
    for u in ups:
        j = _until_settled(c, u)
        assert j["status"] == "done" and j["report"]["verdict"] == "trusted", j
    assert gate.peak == 2 and gate.entered == 3


def test_scan_exception_reports_failed_with_message(env, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any):
        raise RuntimeError("forced finalize failure")
    monkeypatch.setattr(integrity, "finalize", boom)
    up = _upload(env, "a.log", CLEAN)
    j = _until_settled(env["client"], up["upload_id"])
    assert j["status"] == "failed" and j["report"] is None, j
    assert isinstance(j["error"], str) and "forced finalize failure" in j["error"]
    monkeypatch.undo()
    r = env["client"].post(f"/api/uploads/{up['upload_id']}/integrity")   # failed scans can be retried
    assert r.status_code == 202, r.text
    j = _until_settled(env["client"], up["upload_id"])
    assert j["status"] == "done" and j["error"] is None and j["report"]["verdict"] == "trusted"


# ---------------------------------------------------------------- unknown / traversal upload ids
def _tree(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*")}


def test_unknown_upload_404(env) -> None:
    c = env["client"]
    uid = "up-20261031-000000-abcdef"                           # well-formed, never uploaded
    assert c.get(f"/api/uploads/{uid}/integrity").status_code == 404
    assert c.post(f"/api/uploads/{uid}/integrity").status_code == 404
    assert not (env["tmp"] / "data" / "out" / "_integrity" / uid).exists()


BAD_UIDS = ["..", "%2e%2e", "%2e%2e%2f%2e%2e", "..%2f..%2fdata", "%2fetc%2fpasswd", "C:%5cWindows%5cTemp", "C:",
            "up-20261031-000000-abcdef%2f..%2f..", "UP-20261031-000000-ABCDEF", ".incoming", ".meta", "_integrity",
            "up-20261031-000000-abcdef%00", "%5c%5cserver%5cshare"]


def test_upload_id_traversal_rejected_and_nothing_written(env) -> None:
    c, tmp = env["client"], env["tmp"]
    _upload(env, "a.log", CLEAN)
    _until_settled(c, env["uploads"][0])
    (env["cfg"].root / ".incoming").mkdir(exist_ok=True)       # a real dot-dir that must not count as an upload
    before = _tree(tmp)
    for uid in BAD_UIDS:
        for method in ("get", "post"):
            r = getattr(c, method)(f"/api/uploads/{uid}/integrity")
            assert r.status_code in (404, 422), (method, uid, r.status_code, r.text)
    time.sleep(0.3)                                             # a wrongly started scan would write now
    assert _tree(tmp) == before


# ---------------------------------------------------------------- pipeline stage (run.py)
def _ecs_lines(n: int = 120) -> bytes:
    hosts = ("ws-a", "ws-b", "ws-c")
    out = []
    for i in range(n):
        h = hosts[i % 3]
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(1792807200 + i * 60)) + "Z"
        out.append(json.dumps({"@timestamp": ts, "host": {"name": h, "ip": ["10.0.0.5"]},
                               "user": {"name": "svc_web"}, "event": {"action": "process_created"},
                               "process": {"name": "svchost.exe", "executable": "C:\\Windows\\svchost.exe",
                                           "command_line": f"svchost.exe -k netsvcs -s {i}",
                                           "parent": {"name": "services.exe"}}}))
    return ("\n".join(out) + "\n").encode()


@pytest.fixture(scope="module")
def tiny_run(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """One real pipeline run (Sigma off) on 120 hand-made ECS lines, shared by the pipeline tests."""
    from attacklens.run import run_pipeline
    tmp = tmp_path_factory.mktemp("tiny")
    raw = tmp / "raw"
    raw.mkdir()
    (raw / "edr.jsonl").write_bytes(_ecs_lines())
    cfg = tmp / "config"
    shutil.copytree(REPO_ROOT / "config", cfg, ignore=shutil.ignore_patterns("sigma"))
    pipe = yaml.safe_load((cfg / "pipeline.yaml").read_text(encoding="utf-8"))
    if isinstance(pipe.get("sigma"), dict):
        pipe["sigma"]["enabled"] = False
    (cfg / "pipeline.yaml").write_text(yaml.safe_dump(pipe), encoding="utf-8")
    m = run_pipeline(raw, tmp / "out", parquet=tmp / "pq", config_dir=cfg)
    return {"tmp": tmp, "raw": raw, "cfg": cfg, "out": tmp / "out", "pq": tmp / "pq", "metrics": m}


def test_stage_list_appends_integrity_after_publish() -> None:
    from attacklens.run import STAGES
    assert STAGES[:8] == ("profile", "ingest", "lookups", "detect", "episodes", "link", "incidents", "publish")
    assert STAGES[8] == "integrity" and len(STAGES) == 9


def test_pipeline_writes_full_scope_report(tiny_run: dict) -> None:
    t = tiny_run
    assert t["metrics"]["error"] is None
    rep = json.loads((t["out"] / "integrity_report.json").read_text(encoding="utf-8"))
    assert rep["schema_version"] == 1 and [c["id"] for c in rep["checks"]] == CHECK_IDS
    assert rep["inputs"]["events_rows"] == 120 and rep["inputs"]["files"] == 1
    st = {c["id"]: c["status"] for c in rep["checks"]}
    assert st["ingest_drops"] != "skipped" and st["timestamps"] != "skipped"   # events + accounting were there
    assert rep["verdict"] in ("trusted", "suspect", "tampered")
    prog = json.loads((t["out"] / "progress.json").read_text(encoding="utf-8"))
    assert [d["stage"] for d in prog["stages_done"]][-2:] == ["publish", "integrity"]   # progress knows the stage
    assert prog["finished"] is True and prog["error"] is None
    assert rep.get("scope") == "full", f"pipeline report must carry scope 'full', got {rep.get('scope')!r}"


def test_pipeline_integrity_failure_is_non_fatal(tiny_run: dict, tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-run stage 8 only (--from-stage 8) on a copy of the finished run with integrity forced to raise."""
    from attacklens.run import run_pipeline

    def boom(*_a: Any, **_k: Any):
        raise RuntimeError("forced integrity failure")
    monkeypatch.setattr(integrity, "run", boom)
    monkeypatch.setattr(integrity, "run_checks", boom)
    t = tiny_run
    out = tmp_path / "out"
    shutil.copytree(t["out"], out)
    (out / "integrity_report.json").unlink()
    m = run_pipeline(t["raw"], out, parquet=t["pq"], config_dir=t["cfg"], from_stage=8)   # must not raise
    assert m["error"] is None
    text = (out / "run_metrics.json").read_text(encoding="utf-8")
    assert "forced integrity failure" in text, "the integrity exception must be recorded in run_metrics.json"
    assert not (out / "integrity_report.json").exists()
    prog = json.loads((out / "progress.json").read_text(encoding="utf-8"))
    assert prog["finished"] is True and prog["error"] is None
