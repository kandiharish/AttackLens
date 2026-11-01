"""QA integration tests for the API (track qa_api): every route in api.py through Starlette's TestClient with all
roots under tmp_path (served out dir, upload root, raw/out roots, runs dir, SPA dist). Exact values from a tiny
hand-built out dir (frontend/src/mock/incident.json x 3) and a stub pipeline runner; no real pipeline runs here
(the real-server black-box probe is tools/qa/qa_api_probe.py).

Product bugs are strict xfails named test_qa_api_bug_*; the bug id is in the reason (reports/qa/qa_api.md).
"""

from __future__ import annotations

import copy
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from attacklens import api as api_mod
from attacklens import config as al_config
from attacklens import live, publish
from attacklens.api import AppState, create_app
from attacklens.api_runs import RunManager
from attacklens.api_store import Store, load_snapshot
from attacklens.api_upload import UploadConfig, UploadManager
from attacklens.models import Incident, IncidentSummary, dump

REPO = Path(__file__).resolve().parents[3]
MOCK = REPO / "frontend" / "src" / "mock" / "incident.json"
sys.path.insert(0, str(REPO / "tools" / "qa"))
import qa_fglines  # noqa: E402

BOUNDARY = "qa-api-test-boundary"
CTYPE = f"multipart/form-data; boundary={BOUNDARY}"
HEALTH_KEYS = {"status", "incidents", "off_contract", "out_dir", "served_out_dir", "out_dir_source", "loaded_at",
               "uptime_s"}
PROGRESS_KEYS = {"stage_elapsed_s", "stage_fraction", "stages_done", "bytes_total", "bytes_done", "rows_done",
                 "ingest_mb_s", "eta_s", "eta_basis", "eta_total_s"}
RUN_KEYS = {"run_id", "status", "stage", "percent", "error", "elapsed_s", "rss_mb", "peak_rss_mb", "returncode",
            "out_dir", "log", "raw_dir", "started", "integrity"} | PROGRESS_KEYS


def _check_progress_types(s: dict) -> None:
    """Run-progress / ETA keys of GET /api/runs (api_runs._progress): typed, nullable, never negative."""
    num = (int, float)
    for k in ("stage_elapsed_s", "ingest_mb_s", "eta_s", "eta_total_s"):
        assert s[k] is None or (isinstance(s[k], num) and not isinstance(s[k], bool) and s[k] >= 0), (k, s[k])
    for k in ("bytes_total", "bytes_done", "rows_done"):
        assert s[k] is None or (isinstance(s[k], int) and not isinstance(s[k], bool) and s[k] >= 0), (k, s[k])
    assert s["stage_fraction"] is None or 0 <= s["stage_fraction"] <= 1, s["stage_fraction"]
    assert s["eta_basis"] in (None, "history", "live", "history+live"), s["eta_basis"]
    assert isinstance(s["stages_done"], list), s["stages_done"]
    for d in s["stages_done"]:
        assert set(d) >= {"stage", "wall_s"} and isinstance(d["stage"], str) and d["wall_s"] >= 0, d
    if s["bytes_done"] is not None and s["bytes_total"] is not None:
        assert s["bytes_done"] <= s["bytes_total"], (s["bytes_done"], s["bytes_total"])
UPLOAD_KEYS = {"upload_id", "raw_dir", "files", "total_bytes", "mode", "created_at"}   # GET /api/uploads (.meta)
# POST /api/uploads[/local] responses: + "integrity" from the auto-started quick scan (api_integrity.auto_start)
UPLOAD_POST_KEYS = UPLOAD_KEYS | {"integrity"}
# api_runs.integrity_summary of the stub's report below (no "scope" in the file -> "full")
STUB_INTEGRITY = {"verdict": "suspect", "trust_score": 70, "summary": "stub: 1 warning", "scope": "full"}
RUN_METRICS = {"set": "qa", "rows_in": 281, "total_wall_s": 1.5, "peak_rss_mb": 99.0}
ACCOUNTING = [{"source_type": "fortigate_kv", "rows_in": 281, "rows_ok": 281, "dropped": 0, "drop_reasons": {}}]

# stub pipeline: writes one incident (the mock with id inc-0000c0de) into --out; waits while <raw>/hold.txt exists
STUB = '''
import json, sys, time
from pathlib import Path
a = sys.argv[1:]
out = Path(a[a.index("--out") + 1]); raw = Path(a[a.index("--raw") + 1])
print("stage ingest start", flush=True)
while (raw / "hold.txt").exists():
    time.sleep(0.02)
inc = json.loads(Path(sys.argv[0]).with_name("incident.json").read_text(encoding="utf-8"))
inc["id"] = "inc-0000c0de"
(out / "incidents").mkdir(parents=True, exist_ok=True)
(out / "incidents" / "inc-0000c0de.json").write_text(json.dumps(inc), encoding="utf-8")
row = {k: inc[k] for k in ("id", "risk", "first_ts", "last_ts", "merged_alert_count", "episode_count", "tactics")}
row.update(hosts=["srv-dc-01"], entry_summary="stub")
(out / "incidents_index.json").write_text(json.dumps([row]), encoding="utf-8")
print("stage publish done", flush=True)
rep = {"verdict": "suspect", "trust_score": 70, "summary": "stub: 1 warning", "checks": [], "findings": []}
(out / "integrity_report.json").write_text(json.dumps(rep), encoding="utf-8")
'''


# ------------------------------------------------------------------------------------------------ fixtures
def _inc(base: dict, inc_id: str, risk: int) -> dict:
    d = copy.deepcopy(base)
    d["id"], d["risk"] = inc_id, risk
    return dump(Incident.model_validate(d))


def _row(inc: dict) -> dict:
    return dump(IncidentSummary(id=inc["id"], risk=inc["risk"], first_ts=inc["first_ts"], last_ts=inc["last_ts"],
                                merged_alert_count=inc["merged_alert_count"], episode_count=inc["episode_count"],
                                tactics=inc["tactics"], hosts=["srv-dc-01"], entry_summary=inc["entry_point"]["summary"]))


def write_out(out: Path, incs: list[dict], index_rows: list[dict] | None = None, metrics: bool = True) -> None:
    (out / "incidents").mkdir(parents=True, exist_ok=True)
    for inc in incs:
        (out / "incidents" / f"{inc['id']}.json").write_text(json.dumps(inc), encoding="utf-8")
    rows = index_rows if index_rows is not None else [_row(i) for i in incs]
    (out / "incidents_index.json").write_text(json.dumps(rows), encoding="utf-8")
    if metrics:
        (out / "run_metrics.json").write_text(json.dumps(RUN_METRICS), encoding="utf-8")
        (out / "ingest_accounting.json").write_text(json.dumps(ACCOUNTING), encoding="utf-8")


def part(name: str, data: bytes, field: str = "files") -> bytes:
    return (f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{name}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + b"\r\n"


def mbody(*parts: bytes) -> bytes:
    return b"".join(parts) + f"--{BOUNDARY}--\r\n".encode()


def _build(tmp_path: Path, mp: pytest.MonkeyPatch):
    base = json.loads(MOCK.read_text(encoding="utf-8"))
    # risks 50 / 86 / 50: the two 50s must come out id-ascending (aaaa before bbbb), 86 first
    incs = [_inc(base, "inc-0000bbbb", 50), _inc(base, base["id"], 86), _inc(base, "inc-0000aaaa", 50)]
    served = tmp_path / "data" / "out" / "served"
    write_out(served, incs)
    mp.setenv("ATTACKLENS_OUT", str(served))
    cfg = UploadConfig(root=tmp_path / "data" / "raw" / "uploads", max_bytes=8 * 2**20, min_free_bytes=2**20,
                       chunk_bytes=64 * 1024, check_every=64 * 1024)
    uploads = UploadManager(cfg, repo_root=tmp_path, disk_free=lambda p: 10**15)
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "stub.py").write_text(STUB, encoding="utf-8")
    (tmp_path / "bin" / "incident.json").write_text(MOCK.read_text(encoding="utf-8"), encoding="utf-8")
    raw = tmp_path / "data" / "raw" / "fwset"
    raw.mkdir(parents=True)
    (raw / "fw.log").write_text("x\n", encoding="utf-8")
    runs = RunManager(runs_dir=tmp_path / "runs", raw_root=tmp_path / "data" / "raw",
                      out_root=tmp_path / "data" / "out", runner=[sys.executable, str(tmp_path / "bin" / "stub.py")],
                      upload_root=cfg.root, parquet_root=tmp_path / "data" / "parquet")
    app = create_app(AppState(store=Store(check_interval_s=0.0), runs=runs, uploads=uploads))
    with TestClient(app) as c:
        yield {"c": c, "tmp": tmp_path, "served": served, "incs": incs, "cfg": cfg, "raw": raw, "runs": runs}
    for j in runs.jobs():  # never leave a stub process behind
        if j.proc.poll() is None:
            j.proc.kill()


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Fresh app per test (state-changing tests)."""
    yield from _build(tmp_path, monkeypatch)


@pytest.fixture(scope="module")
def shared(tmp_path_factory: pytest.TempPathFactory):
    """One app for the stateless rejection / 404 tables (each case leaves no state the others read)."""
    with pytest.MonkeyPatch.context() as mp:
        yield from _build(tmp_path_factory.mktemp("qa_api_shared"), mp)


def no_partial(cfg: UploadConfig) -> bool:
    inc = cfg.root / ".incoming"
    return not inc.exists() or not any(inc.iterdir())


def wait_done(c: TestClient, rid: str, tries: int = 400) -> dict:
    for _ in range(tries):
        s = c.get(f"/api/runs/{rid}").json()
        if s["status"] != "running":
            return s
        time.sleep(0.025)
    raise AssertionError("stub run did not finish")


# ------------------------------------------------------------------------------------------------ reads
def test_health_exact(shared) -> None:
    h = shared["c"].get("/api/health").json()
    assert set(h) == HEALTH_KEYS
    assert (h["status"], h["incidents"], h["off_contract"], h["out_dir_source"]) == ("ok", 3, 0, "env")
    assert Path(h["served_out_dir"]) == shared["served"].resolve() == Path(h["out_dir"])


def test_index_risk_desc_then_id_asc(shared) -> None:
    r = shared["c"].get("/api/incidents")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    assert [(x["id"], x["risk"]) for x in r.json()] == [("inc-3f2a9c1e", 86), ("inc-0000aaaa", 50),
                                                         ("inc-0000bbbb", 50)]
    for row in r.json():
        IncidentSummary.model_validate(row)


@pytest.mark.parametrize("inc_id", ["inc-3f2a9c1e", "inc-0000aaaa", "inc-0000bbbb"])
def test_detail_path_pivots_exact(shared, inc_id: str) -> None:
    c = shared["c"]
    disk = json.loads((shared["served"] / "incidents" / f"{inc_id}.json").read_text(encoding="utf-8"))
    assert c.get(f"/api/incidents/{inc_id}").json() == disk
    p = c.get(f"/api/incidents/{inc_id}/path").json()
    assert set(p) == {"id", "backbone", "branches", "edges"} and p["id"] == inc_id
    assert (len(p["backbone"]), len(p["branches"]), len(p["edges"])) == (7, 0, 6)
    assert p["backbone"] == disk["backbone"] and p["edges"] == disk["edges"]
    pv = c.get(f"/api/incidents/{inc_id}/pivots").json()
    assert pv["id"] == inc_id and len(pv["steps"]) == 7 and isinstance(pv["siems"], list)
    assert [s["step"] for s in pv["steps"]] == [s["step"] for s in disk["backbone"]]


@pytest.mark.parametrize("path", ["/api/incidents/inc-00000000", "/api/incidents/INC-3F2A9C1E",
                                  "/api/incidents/inc-3f2a9c1e0", "/api/incidents/inc-3f2a9c1e%0A",
                                  "/api/incidents/..%2fincidents_index", "/api/incidents/inc-00000000/path",
                                  "/api/incidents/inc-00000000/pivots", "/api/incidents/inc-3f2a9c1e/nope",
                                  "/api/runs/000000000000", "/api/runs/ZZZ", "/api/runs/..%2f..%2fetc",
                                  "/api/nope", "/api/"])
def test_unknown_is_json_404(shared, path: str) -> None:
    r = shared["c"].get(path)
    assert r.status_code == 404 and r.headers["content-type"].startswith("application/json"), (path, r.text[:80])


def test_metrics_exact_and_reload(env) -> None:
    c = env["c"]
    assert c.get("/api/metrics").json() == {"run_metrics": RUN_METRICS, "eval_scorecard": None,
                                            "ingest_accounting": ACCOUNTING}
    base = json.loads(MOCK.read_text(encoding="utf-8"))
    write_out(env["served"], [*env["incs"], _inc(base, "inc-0000dddd", 99)])
    assert c.post("/api/reload").json() == {"incidents": 4, "out_dir": str(env["served"].resolve())}
    assert c.get("/api/incidents").json()[0]["id"] == "inc-0000dddd"


def _live_status(out: Path, updated_at: str, enabled: bool = True) -> None:
    (out / "live_status.json").write_text(json.dumps({"enabled": enabled, "running": True, "batches": 3,
                                                       "updated_at": updated_at}), encoding="utf-8")


def test_live_status_fresh_stale_garbage(env) -> None:
    c, out = env["c"], env["served"]
    now = time.strftime("%Y-%m-%dT%H:%M:%S.00Z", time.gmtime())
    _live_status(out, now)
    s = c.get("/api/live/status").json()
    assert (s["enabled"], s["stale"], s["batches"]) == (True, False, 3) and 0 <= s["heartbeat_age_s"] < 10
    _live_status(out, time.strftime("%Y-%m-%dT%H:%M:%S.00Z", time.gmtime(time.time() - 11)))  # stale_s = 10
    s = c.get("/api/live/status").json()
    assert (s["enabled"], s["stale"]) == (False, True) and s["heartbeat_age_s"] >= 10
    _live_status(out, "not-a-time")
    s = c.get("/api/live/status").json()
    assert (s["enabled"], s["stale"]) == (False, True)
    _live_status(out, now, enabled=False)   # engine stopped cleanly
    assert c.get("/api/live/status").json()["enabled"] is False


def test_integrations_status_never_returns_secret_values(shared, monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("ELASTIC_API_KEY", "SPLUNK_TOKEN", "SENTINEL_TOKEN", "SPLUNK_HEC_TOKEN", "ELASTIC_PASSWORD"):
        monkeypatch.setenv(var, f"QA-SECRET-{var}")
    r = shared["c"].get("/api/integrations/status")
    assert r.status_code == 200 and {"connectors", "sinks", "pivot_siems", "alert_input", "spool"} <= set(r.json())
    assert "QA-SECRET" not in r.text


# ------------------------------------------------------------------------------------------------ uploads
def _fw_bytes() -> bytes:
    return ("\n".join(qa_fglines.batch_file(1793350800000, n_noise=10, n_fail=5)) + "\n").encode()


def test_upload_fortigate_list_and_local_link(env) -> None:
    c, tmp, cfg = env["c"], env["tmp"], env["cfg"]
    data = _fw_bytes()
    assert data.count(b"\n") == 16 and data.count(b'logdesc="Admin login failed"') == 5
    r = c.post("/api/uploads", content=mbody(part("fortigate.log", data), part("x", b"y", field="note")),
               headers={"content-type": CTYPE})
    assert r.status_code == 201, r.text
    up = r.json()
    assert set(up) == UPLOAD_POST_KEYS and up["mode"] == "upload" and up["integrity"] == {"status": "running"}
    assert up["files"] == [{"name": "fortigate.log", "bytes": len(data)}] and up["total_bytes"] == len(data)
    assert up["raw_dir"] == f"data/raw/uploads/{up['upload_id']}"
    assert (tmp / up["raw_dir"] / "fortigate.log").read_bytes() == data
    src = tmp / "elsewhere" / "fw_local.log"
    src.parent.mkdir()
    src.write_bytes(data)
    time.sleep(1.05)  # created_at resolution is 1 s: make "newest first" observable
    lo = c.post("/api/uploads/local", json={"path": str(src)})
    assert lo.status_code == 201, lo.text
    lo = lo.json()
    assert set(lo) == UPLOAD_POST_KEYS and lo["integrity"] == {"status": "running"}
    assert lo["mode"] == "link" and lo["files"] == [{"name": "fw_local.log", "bytes": len(data)}]
    assert (tmp / lo["raw_dir"] / "fw_local.log").samefile(src) and os.stat(src).st_nlink == 2
    listed = c.get("/api/uploads").json()
    assert [u["upload_id"] for u in listed] == [lo["upload_id"], up["upload_id"]]
    assert all(set(u) == UPLOAD_KEYS for u in listed) and no_partial(cfg)


@pytest.mark.parametrize("name,status,saved", [
    ("../evil.log", 400, None), ("..\\evil.log", 400, None), ("/etc/passwd.log", 400, None),
    ("\\\\srv\\share\\x.log", 400, None), ("C:\\Windows\\x.log", 400, None), ("C:x.log", 400, None),
    ("a/../../b.log", 400, None), ("", 400, None), ("   ", 400, None),
    (".log", 415, None), ("evil.exe", 415, None), ("evil.log.exe", 415, None), ("evil.log.", 415, None),
    ("evil", 415, None),
    ("evil.LOG", 201, "evil.LOG"), ("sub/dir/ok.log", 201, "ok.log"), ("we ird$name.log", 201, "we_ird_name.log"),
    ("\u0430dmin.log", 201, "_dmin.log"), ("CON.log", 201, "CON.log"), ("NUL.txt", 201, "NUL.txt"),
])
def test_upload_hostile_names(shared, name: str, status: int, saved: str | None) -> None:
    c, tmp = shared["c"], shared["tmp"]
    payload = b"payload-" + name.encode("utf-8", "replace") + b"\n"
    r = c.post("/api/uploads", content=mbody(part(name, payload)), headers={"content-type": CTYPE})
    assert r.status_code == status, r.text
    if saved is not None:
        f = r.json()["files"][0]
        assert f["name"] == saved
        assert (tmp / r.json()["raw_dir"] / saved).read_bytes() == payload   # reserved names: not a lost write
    assert no_partial(shared["cfg"])


def test_upload_size_and_structure_errors(env) -> None:
    c = env["c"]
    big = {"content-type": CTYPE, "content-length": str(8 * 2**20 + 2**20 + 1)}
    r = c.post("/api/uploads", content=mbody(part("a.log", b"x\n")), headers=big)   # header > cap + 1 MiB overhead
    assert r.status_code == 413 and "max_bytes" in r.json()["detail"]
    r = c.post("/api/uploads", content=mbody(part("a.log", b"x" * (8 * 2**20 + 1))), headers={"content-type": CTYPE})
    assert r.status_code == 413                                       # streamed bytes over the cap
    assert c.post("/api/uploads", json={"files": "x"}).status_code == 400
    assert c.post("/api/uploads", content=b"x", headers={"content-type": "multipart/form-data"}).status_code == 400
    assert c.post("/api/uploads", content=mbody(part("a.log", b"x", field="file")),
                  headers={"content-type": CTYPE}).status_code == 400   # no 'files' part
    r = c.post("/api/uploads", content=part("a.log", b"x\n"), headers={"content-type": CTYPE})
    assert r.status_code == 400 and "truncated" in r.json()["detail"]
    assert c.post("/api/uploads", content=part("a.log", b"x\n")[:-40],
                  headers={"content-type": CTYPE}).status_code == 400
    assert no_partial(env["cfg"]) and c.get("/api/uploads").json() == []


@pytest.mark.parametrize("path_kind,status", [("relative", 400), ("missing", 404), ("dir", 400), ("ext", 415),
                                              ("empty", 400)])
def test_upload_local_rejections(shared, path_kind: str, status: int) -> None:
    tmp = shared["tmp"]
    (tmp / "cfg.toml").write_text("x", encoding="utf-8")
    path = {"relative": "data/raw/fwset/fw.log", "missing": str(tmp / "nope.log"), "dir": str(tmp / "data"),
            "ext": str(tmp / "cfg.toml"), "empty": ""}[path_kind]
    r = shared["c"].post("/api/uploads/local", json={"path": path})
    assert r.status_code == status, r.text
    assert path not in r.json()["detail"] or not path          # never echoes the submitted path
    assert no_partial(shared["cfg"])


# ------------------------------------------------------------------------------------------------ guards
@pytest.mark.parametrize("origin", ["http://evil.example", "null", "http://localhost:5174",
                                    "http://localhost:5173.evil.example"])
def test_foreign_origin_refused_on_every_post(env, origin: str) -> None:
    c, tmp = env["c"], env["tmp"]
    h = {"origin": origin}
    assert c.post("/api/uploads", content=mbody(part("a.log", b"x\n")),
                  headers={**h, "content-type": CTYPE}).status_code == 403
    assert c.post("/api/uploads/local", json={"path": str(tmp / "data" / "raw" / "fwset" / "fw.log")},
                  headers=h).status_code == 403
    assert c.post("/api/runs", json={"raw_dir": str(env["raw"])}, headers=h).status_code == 403
    assert c.post("/api/reload", headers=h).status_code == 403
    assert env["runs"].jobs() == [] and no_partial(env["cfg"]) and c.get("/api/uploads").json() == []
    g = c.get("/api/health", headers=h)
    assert g.status_code == 200 and "access-control-allow-origin" not in g.headers


def test_vite_origin_gets_cors_on_reads(shared) -> None:
    r = shared["c"].get("/api/incidents", headers={"origin": "http://localhost:5173"})
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8031", "localhost.evil.example"])
def test_untrusted_host_400_everywhere(shared, host: str) -> None:
    c = shared["c"]
    for method, path in (("GET", "/api/health"), ("GET", "/api/incidents"), ("POST", "/api/reload"),
                         ("POST", "/api/runs"), ("GET", "/api/live/status")):
        assert c.request(method, path, headers={"host": host}, json={}).status_code == 400, (method, path)


# ------------------------------------------------------------------------------------------------ runs
def test_concurrent_post_runs_one_202_then_served_switch(env) -> None:
    c, raw = env["c"], env["raw"]
    (raw / "hold.txt").write_text("x", encoding="utf-8")
    barrier = threading.Barrier(6)
    codes: list[int] = []
    rids: list[str] = []

    def go() -> None:
        barrier.wait()
        r = c.post("/api/runs", json={"raw_dir": str(raw), "out_dir": str(env["tmp"] / "data" / "out" / "qa1")})
        codes.append(r.status_code)
        if r.status_code == 202:
            rids.append(r.json()["run_id"])

    ths = [threading.Thread(target=go) for _ in range(6)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    assert sorted(codes) == [202, 409, 409, 409, 409, 409]
    rid = rids[0]
    s = c.get(f"/api/runs/{rid}").json()
    assert set(s) == RUN_KEYS and s["status"] == "running" and s["returncode"] is None
    assert s["integrity"] is None                                        # no integrity_report.json yet
    _check_progress_types(s)
    assert c.get("/api/health").json()["out_dir_source"] == "env"        # not switched while running
    assert [i["id"] for i in c.get("/api/incidents").json()][0] == "inc-3f2a9c1e"
    (raw / "hold.txt").unlink()
    s = wait_done(c, rid)
    assert (s["status"], s["returncode"], s["stage"], s["percent"], s["error"]) == ("succeeded", 0, "done", 100, None)
    assert s["integrity"] == STUB_INTEGRITY
    h = c.get("/api/health").json()
    assert h["out_dir_source"] == "api_run" and h["incidents"] == 1
    assert Path(h["served_out_dir"]) == (env["tmp"] / "data" / "out" / "qa1").resolve()
    assert [i["id"] for i in c.get("/api/incidents").json()] == ["inc-0000c0de"]
    assert c.post("/api/reload").json()["incidents"] == 1                # reload keeps the pinned run output
    lst = c.get("/api/runs").json()
    assert [x["run_id"] for x in lst] == [rid] and set(lst[0]) == RUN_KEYS and lst[0]["integrity"] == STUB_INTEGRITY
    _check_progress_types(lst[0])
    r = c.post("/api/runs", json={"raw_dir": str(raw), "out_dir": str(env["tmp"] / "data" / "out" / "qa1")})
    assert r.status_code == 400                                          # never write into the served output


@pytest.mark.parametrize("payload,status", [
    ({"raw_dir": "../../etc"}, 400), ({"raw_dir": "C:/Windows"}, 400), ({"raw_dir": "<tmp>/data/raw"}, 400),
    ({"raw_dir": "<tmp>/data/raw/uploads"}, 400), ({"raw_dir": "<tmp>/data/raw/uploads/.incoming"}, 400),
    ({"raw_dir": "<tmp>/data/raw/nope"}, 400), ({"raw_dir": "<tmp>/data/raw/fw set"}, 400),
    ({"raw_dir": "<tmp>/data/raw/fwset", "out_dir": "<tmp>/data/out/a/b"}, 400),
    ({"raw_dir": "<tmp>/data/raw/fwset", "out_dir": "<tmp>/data/out/served"}, 400),
    ({"raw_dir": "<tmp>/data/raw/fwset", "ground_truth": "<tmp>/data/raw/fwset/none.json"}, 400),
    ({"out_dir": "<tmp>/data/out/x"}, 422),
])
def test_post_runs_rejections(shared, payload: dict, status: int) -> None:
    tmp = shared["tmp"]
    (tmp / "data" / "raw" / "uploads" / ".incoming").mkdir(parents=True, exist_ok=True)
    body = {k: v.replace("<tmp>", str(tmp)) for k, v in payload.items()}
    r = shared["c"].post("/api/runs", json=body)
    assert r.status_code == status, r.text
    assert shared["runs"].jobs() == []
    if status == 400:
        assert str(tmp) not in r.json()["detail"]                       # never echoes the submitted path


# ------------------------------------------------------------------------------------------------ SPA
@pytest.fixture()
def spa(tmp_path: Path) -> TestClient:
    dist = tmp_path / "web" / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>qa-index</title>", encoding="utf-8")
    (dist / "assets" / "app-1.js").write_text("console.log('qa')", encoding="utf-8")
    (dist / "favicon.svg").write_text("<svg/>", encoding="utf-8")
    (tmp_path / "web" / "secret.txt").write_text("QA-SECRET-OUTSIDE-DIST", encoding="utf-8")
    (tmp_path / "secret2.txt").write_text("QA-SECRET-OUTSIDE-DIST", encoding="utf-8")
    app = FastAPI()
    api_mod._mount_frontend(app, dist)
    return TestClient(app)


def test_spa_index_assets_and_client_routes(spa: TestClient) -> None:
    assert spa.get("/").text == "<!doctype html><title>qa-index</title>"
    assert spa.get("/incidents/inc-3f2a9c1e").text == "<!doctype html><title>qa-index</title>"
    assert spa.get("/assets/app-1.js").text == "console.log('qa')"
    r = spa.get("/favicon.svg")
    assert r.status_code == 200 and r.text == "<svg/>"
    assert spa.get("/assets/missing.js").status_code == 404


@pytest.mark.parametrize("path", ["/..%2fsecret.txt", "/%2e%2e/secret.txt", "/..%5csecret.txt",
                                  "/%2e%2e%2f%2e%2e%2fsecret2.txt", "/assets/..%2f..%2fsecret.txt",
                                  "/assets/%2e%2e/%2e%2e/secret.txt"])
def test_spa_traversal_never_leaks(spa: TestClient, path: str) -> None:
    r = spa.get(path)
    assert "QA-SECRET-OUTSIDE-DIST" not in r.text and r.status_code in (200, 404)


def test_spa_drive_absolute_path_never_leaks(spa: TestClient, tmp_path: Path) -> None:
    target = (tmp_path / "secret2.txt").resolve().as_posix()      # e.g. C:/Users/.../secret2.txt
    r = spa.get("/" + target)
    assert "QA-SECRET-OUTSIDE-DIST" not in r.text


# ------------------------------------------------------------------------------------------------ product bugs
@pytest.mark.xfail(strict=True, reason="QA-API-01: GET /api (bare prefix, no slash) falls through to the SPA and "
                                       "returns 200 text/html instead of a JSON 404 (api.py api_not_found route "
                                       "matches /api/{rest} only)")
def test_qa_api_bug_bare_api_prefix_is_json_404(env, tmp_path: Path) -> None:
    app = env["c"].app
    dist = tmp_path / "dist2"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html>", encoding="utf-8")
    api_mod._mount_frontend(app, dist)       # the shipped app with a built SPA (frontend/dist), isolated in tmp
    r = TestClient(app).get("/api")
    assert r.status_code == 404 and r.headers["content-type"].startswith("application/json")


@pytest.mark.xfail(strict=True, reason="QA-API-02: api_store.load_snapshot keeps index rows whose incident file is "
                                       "missing/unreadable: GET /api/incidents lists an id that GET "
                                       "/api/incidents/{id} 404s, and health.incidents != len(index)")
def test_qa_api_bug_index_never_lists_unservable_incident(env) -> None:
    c, served = env["c"], env["served"]
    rows = json.loads((served / "incidents_index.json").read_text(encoding="utf-8"))
    ghost = dict(rows[0], id="inc-0000dead", risk=99)
    (served / "incidents_index.json").write_text(json.dumps([ghost, *rows]), encoding="utf-8")
    c.post("/api/reload")
    ids = [r["id"] for r in c.get("/api/incidents").json()]
    assert all(c.get(f"/api/incidents/{i}").status_code == 200 for i in ids), ids
    assert c.get("/api/health").json()["incidents"] == len(ids)


@pytest.mark.xfail(strict=True, reason="QA-API-03: publish.write_json truncates incidents_index.json in place "
                                       "(open 'w', not tmp + os.replace); an API reload during the write serves 0 "
                                       "incidents (probe: 13 of 17 reloads empty while the index was rewritten)")
def test_qa_api_bug_index_rewrite_is_atomic_for_readers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = json.loads(MOCK.read_text(encoding="utf-8"))
    out = tmp_path / "out"
    inc = _inc(base, base["id"], 86)
    write_out(out, [inc], metrics=False)
    seen: list[int] = []
    real_dumps = publish.json.dumps

    class _Json:  # the moment publish serializes, its target file is already open for writing
        @staticmethod
        def dumps(obj, **kw):
            seen.append(load_snapshot(out).count)
            return real_dumps(obj, **kw)

    monkeypatch.setattr(publish, "json", _Json)
    publish.write_json(out / "incidents_index.json", [_row(inc)])
    assert seen == [1]           # a reader during the rewrite still sees the previous complete index


@pytest.mark.xfail(strict=True, reason="QA-API-04: the live heartbeat (live_status.json updated_at) is written only "
                                       "between cycles; a cycle longer than live.yaml status_stale_s (10 s) makes "
                                       "GET /api/live/status report enabled=false for a running engine (measured: "
                                       "258 of 1066 polls during a 2 000-line live session, heartbeat age up to 27.6 s)")
def test_qa_api_bug_live_status_enabled_during_long_cycle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(live.LiveEngine, "_run_stages", lambda self, con: long_stages())
    cfg = al_config.load_config()
    cfg["live"] = {**cfg["live"], "state_dir": str(tmp_path / "state")}
    stale = float(cfg["live"].get("status_stale_s", 10))
    watch, out = tmp_path / "w", tmp_path / "out"
    watch.mkdir()
    seen: list[bool] = []

    def long_stages() -> dict:   # a cycle whose stages take stale + 1 s: ask the API's status() at that moment
        real = time.time
        time.time = lambda: real() + stale + 1   # noqa: E731 - restored below
        try:
            seen.append(bool(live.status(out, {"live": cfg["live"]})["enabled"]))
        finally:
            time.time = real
        return {}

    eng = live.LiveEngine(watch, out, cfg)
    eng.write_status()                                  # what loop() does before the first cycle
    f = qa_fglines.formatter(5)
    (watch / "fw.log").write_text(qa_fglines.noise_line(f, int(time.time() * 1000), 1) + "\n", encoding="utf-8")
    assert eng.cycle() is True
    assert seen == [True]                               # engine alive and mid-cycle -> still enabled
