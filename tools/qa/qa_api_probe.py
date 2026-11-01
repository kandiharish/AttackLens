"""QA black-box probe of a running AttackLens API (track qa_api). Every route in api.py, abuse cases, run + upload
lifecycle, served switch, and a small read-latency benchmark.

    .venv/Scripts/python tools/qa/qa_api_probe.py --port 8031 --served data/tmp/qa_api/out --json data/tmp/qa_api/probe.json

Never point it at :8000. It creates: data/raw/uploads/<ids> (the API's default upload root), data/out/qa_api_smoke,
data/out/<upload id>, data/parquet/<same names>, data/runs/run-<id>.log. --cleanup removes exactly those.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import socket
import statistics
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from attacklens.models import Incident, IncidentSummary  # noqa: E402
import qa_fglines  # noqa: E402
import qa_api_probe_integ  # noqa: E402

BOUNDARY = "qa-api-boundary-7f3a"
CTYPE = f"multipart/form-data; boundary={BOUNDARY}"
UPLOAD_ROOT = REPO / "data" / "raw" / "uploads"
RUN_OUT = "data/out/qa_api_smoke"
HEALTH_KEYS = {"status", "incidents", "off_contract", "out_dir", "served_out_dir", "out_dir_source", "loaded_at",
               "uptime_s"}
PROGRESS_KEYS = {"stage_elapsed_s", "stage_fraction", "stages_done", "bytes_total", "bytes_done", "rows_done",
                 "ingest_mb_s", "eta_s", "eta_basis", "eta_total_s"}  # api_runs._progress (progress_eta.status_fields)
RUN_KEYS = {"run_id", "status", "stage", "percent", "error", "elapsed_s", "rss_mb", "peak_rss_mb", "returncode",
            "out_dir", "log", "raw_dir", "started"} | PROGRESS_KEYS
UPLOAD_KEYS = {"upload_id", "raw_dir", "files", "total_bytes", "mode", "created_at"}

RESULTS: list[dict[str, Any]] = []
CREATED: dict[str, list[str]] = {"uploads": [], "runs": [], "out": [], "parquet": []}


def check(cid: str, what: str, ok: bool, got: Any = None, expected: Any = None) -> bool:
    RESULTS.append({"id": cid, "what": what, "ok": bool(ok), "got": got, "expected": expected})
    print(f"{'PASS' if ok else 'FAIL'} {cid}: {what}" + ("" if ok else f"  got={got!r} expected={expected!r}"))
    return bool(ok)


def part(name: str, data: bytes, field: str = "files") -> bytes:
    return (f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{name}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + b"\r\n"


def mbody(*parts: bytes) -> bytes:
    return b"".join(parts) + f"--{BOUNDARY}--\r\n".encode()


def raw_http(port: int, req: bytes, timeout: float = 10.0, close_after_send: bool = False) -> tuple[int | None, bytes]:
    """Send raw bytes; return (status, response bytes). close_after_send: hang up right after sending."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(req)
        if close_after_send:
            return None, b""
        buf = b""
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                head, _, rest = buf.partition(b"\r\n\r\n")
                m = re.search(rb"content-length:\s*(\d+)", head, re.I)
                if m and len(rest) >= int(m.group(1)):
                    break
        m = re.match(rb"HTTP/1\.[01] (\d{3})", buf)
        return (int(m.group(1)) if m else None), buf
    finally:
        s.close()


def incoming_empty() -> bool:
    inc = UPLOAD_ROOT / ".incoming"
    return not inc.exists() or not any(inc.iterdir())


def pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))], 2)


# ------------------------------------------------------------------------------------------------ reads
def probe_reads(c: httpx.Client, served: Path) -> list[str]:
    r = c.get("/api/health")
    h = r.json()
    check("R01", "GET /api/health 200 + exact key set", r.status_code == 200 and set(h) == HEALTH_KEYS, sorted(h))
    idx_file = json.loads((served / "incidents_index.json").read_text(encoding="utf-8"))
    check("R02", "health.incidents == rows in served incidents_index.json", h["incidents"] == len(idx_file),
          h["incidents"], len(idx_file))
    check("R03", "health.out_dir_source == env, served_out_dir == ATTACKLENS_OUT",
          h["out_dir_source"] == "env" and Path(h["served_out_dir"]) == served.resolve(), h["served_out_dir"])
    r = c.get("/api/incidents")
    idx = r.json()
    check("R04", "GET /api/incidents 200 application/json list",
          r.status_code == 200 and r.headers["content-type"].startswith("application/json") and isinstance(idx, list))
    bad = []
    for row in idx:
        try:
            IncidentSummary.model_validate(row)
        except Exception as exc:  # noqa: BLE001
            bad.append((row.get("id"), str(exc)[:120]))
    check("R05", "every index row validates models.IncidentSummary", not bad, bad)
    risks = [(-x["risk"], x["id"]) for x in idx]
    check("R06", "index sorted risk desc (tie: id asc)", risks == sorted(risks), [x["risk"] for x in idx])
    ids = [x["id"] for x in idx]
    check("R07", "index ids == served file ids", sorted(ids) == sorted(x["id"] for x in idx_file))
    for inc_id in ids:
        r = c.get(f"/api/incidents/{inc_id}")
        body = r.json()
        disk = json.loads((served / "incidents" / f"{inc_id}.json").read_text(encoding="utf-8"))
        try:
            Incident.model_validate(body)
            valid = True
        except Exception:  # noqa: BLE001
            valid = False
        check(f"R08:{inc_id}", "GET /api/incidents/{id} 200, == file on disk, validates Incident",
              r.status_code == 200 and body == disk and valid)
        r = c.get(f"/api/incidents/{inc_id}/path")
        p = r.json()
        check(f"R09:{inc_id}", "/path 200, keys exactly id/backbone/branches/edges, values == incident",
              r.status_code == 200 and set(p) == {"id", "backbone", "branches", "edges"}
              and all(p[k] == disk.get(k, []) for k in ("backbone", "branches", "edges")) and p["id"] == inc_id,
              sorted(p))
        r = c.get(f"/api/incidents/{inc_id}/pivots")
        pv = r.json()
        check(f"R10:{inc_id}", "/pivots 200, id + one step per backbone step",
              r.status_code == 200 and pv.get("id") == inc_id and len(pv.get("steps", [])) == len(disk["backbone"])
              and isinstance(pv.get("siems"), list), {k: (len(v) if isinstance(v, list) else v) for k, v in pv.items()})
    for bad_id, cid in (("inc-00000000", "R11a"), ("INC-" + ids[0][4:].upper() if ids else "INC-X", "R11b"),
                        ("inc-853d956b0", "R11c"), ("..%2f..%2fREADME.md", "R11d"), ("inc-zzzzzzzz", "R11e")):
        for suffix in ("", "/path", "/pivots"):
            r = c.get(f"/api/incidents/{bad_id}{suffix}")
            check(f"{cid}{suffix}", f"unknown/bad id {bad_id}{suffix} -> 404 JSON",
                  r.status_code == 404 and r.headers["content-type"].startswith("application/json"), r.status_code)
    r = c.get("/api/metrics")
    m = r.json()
    disk_m = {k: (json.loads((served / f"{k}.json").read_text(encoding="utf-8"))
                  if (served / f"{k}.json").exists() else None)
              for k in ("run_metrics", "eval_scorecard", "ingest_accounting")}
    check("R12", "GET /api/metrics keys exact and == the three files", r.status_code == 200 and m == disk_m, sorted(m))
    r = c.post("/api/reload")
    check("R13", "POST /api/reload 200 {incidents, out_dir}",
          r.status_code == 200 and r.json() == {"incidents": len(idx_file), "out_dir": str(served.resolve())}, r.json())
    r = c.get("/api/live/status")
    ls = r.json()
    check("R14", "GET /api/live/status 200, enabled is bool (no live engine on this out dir)",
          r.status_code == 200 and isinstance(ls.get("enabled"), bool), ls.get("enabled"))
    r = c.get("/api/integrations/status")
    it = r.json()
    ok = r.status_code == 200 and {"connectors", "sinks", "pivot_siems", "alert_input", "spool"} <= set(it)
    flags = [v.get("auth_env_set") for grp in ("connectors", "sinks") for v in (it.get(grp) or {}).values()]
    check("R15", "GET /api/integrations/status 200, shape, auth_env_set only bool/None/dict-of-bool",
          ok and all(isinstance(f, (bool, type(None), dict)) for f in flags), sorted(it))
    for path in ("/api/nope", "/api/incidents/x/y/z", "/api/runs/zzz"):
        r = c.get(path)
        check(f"R16{path}", f"GET {path} -> 404 JSON", r.status_code == 404
              and r.headers["content-type"].startswith("application/json"), r.status_code)
    for path in ("/api/health", "/api/incidents", "/api/metrics", "/api/runs", "/api/uploads", "/api/live/status",
                 "/api/integrations/status"):
        r = c.get(path)
        check(f"R17{path}", f"GET {path} returns application/json, never HTML",
              r.status_code == 200 and r.headers["content-type"].startswith("application/json")
              and not r.text.lstrip().startswith("<"), r.headers.get("content-type"))
    return ids


def probe_spa(c: httpx.Client, port: int) -> None:
    r = c.get("/")
    check("S01", "GET / -> 200 text/html (SPA index)", r.status_code == 200 and "text/html" in r.headers["content-type"])
    index = r.text
    r = c.get("/incidents/inc-853d956b")
    check("S02", "client route -> SPA index fallback", r.status_code == 200 and r.text == index)
    r = c.get("/favicon.svg")
    check("S03", "static file from dist served", r.status_code == 200 and "svg" in r.headers["content-type"])
    asset = re.search(r'/assets/[^"\']+\.js', index)
    if asset:
        r = c.get(asset.group(0))
        check("S04", "hashed JS asset 200", r.status_code == 200, r.status_code)
    for cid, path in (("S05", "/..%2f..%2fREADME.md"), ("S06", "/%2e%2e/%2e%2e/backend/attacklens/api.py"),
                      ("S07", "/..%5c..%5cREADME.md"), ("S08", "/C:/Windows/win.ini"), ("S09", "/assets/..%2f..%2f..%2fREADME.md"),
                      ("S10", "/../../README.md")):
        st, buf = raw_http(port, f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".encode())
        leaked = b"AttackLens API (DEVELOPMENT" in buf or b"[fonts]" in buf or b"# AttackLens" in buf
        check(cid, f"traversal {path} never serves a file outside dist", st in (200, 400, 404) and not leaked, st)
    st, buf = raw_http(port, b"GET /api HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    check("S11", "GET /api (bare prefix) -> not HTML (observation)", b"<!doctype html" not in buf.lower(),
          st, "JSON 404")


# ------------------------------------------------------------------------------------------------ guards
def probe_guards(c: httpx.Client, port: int) -> None:
    evil = {"origin": "http://evil.example"}
    for path, kw in (("/api/uploads", {"content": mbody(part("a.log", b"x\n")), "headers": {"content-type": CTYPE}}),
                     ("/api/uploads/local", {"json": {"path": str(REPO / "README.md")}}),
                     ("/api/runs", {"json": {"raw_dir": "data/raw/smoke", "out_dir": RUN_OUT}}),
                     ("/api/reload", {})):
        for origin in ("http://evil.example", "null", "http://localhost:5174", "http://127.0.0.1:8031.evil.example"):
            kw2 = {**kw, "headers": {**kw.get("headers", {}), "origin": origin}}
            r = c.post(path, **kw2)
            check(f"G01{path}|{origin}", f"POST {path} with Origin {origin} -> 403", r.status_code == 403, r.status_code)
    check("G02", "no partial upload left after refused cross-origin uploads", incoming_empty())
    r = c.get("/api/health", headers=evil)
    check("G03", "GET with foreign Origin -> 200 but no Access-Control-Allow-Origin",
          r.status_code == 200 and "access-control-allow-origin" not in r.headers, dict(r.headers).get(
              "access-control-allow-origin"))
    r = c.get("/api/health", headers={"origin": "http://localhost:5173"})
    check("G04", "GET with Vite origin -> ACAO echoes http://localhost:5173",
          r.headers.get("access-control-allow-origin") == "http://localhost:5173", r.headers.get(
              "access-control-allow-origin"))
    r = c.post("/api/reload", headers={"origin": f"http://127.0.0.1:{port}"})
    check("G05", "POST with the API's own origin passes (200)", r.status_code == 200, r.status_code)
    for host in ("evil.example", "evil.example:8031", "127.0.0.1.nip.io", "localhost.evil.example"):
        for method, path in (("GET", "/api/health"), ("POST", "/api/uploads/local"), ("GET", "/")):
            body = b'{"path":"C:/x.log"}' if method == "POST" else b""
            req = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
            st, _ = raw_http(port, req)
            check(f"G06|{host}|{method}{path}", f"Host: {host} {method} {path} -> 400", st == 400, st)
    # preflight from evil origin must not be approved
    r = c.options("/api/uploads", headers={"origin": "http://evil.example", "access-control-request-method": "POST"})
    check("G07", "CORS preflight from evil origin not approved (no ACAO)",
          "access-control-allow-origin" not in r.headers, (r.status_code, r.headers.get("access-control-allow-origin")))


# ------------------------------------------------------------------------------------------------ uploads
def probe_uploads(c: httpx.Client, port: int, tmp: Path) -> dict[str, Any]:
    start_ms = int(time.time() * 1000) - 3_600_000
    data = ("\n".join(qa_fglines.batch_file(start_ms)) + "\n").encode()
    noise = ("\n".join(qa_fglines.noise_line(qa_fglines.formatter(3), start_ms + i * 1000, i) for i in range(20))
             + "\n").encode()
    r = c.post("/api/uploads", content=mbody(part("fortigate_bf.log", data), part("noise.txt", noise),
                                             part("ignored", b"zzz", field="other")),
               headers={"content-type": CTYPE})
    up = r.json()
    ok = r.status_code == 201 and set(up) == UPLOAD_KEYS and up["mode"] == "upload"
    check("U01", "POST /api/uploads 2 files -> 201, exact keys, mode upload", ok, (r.status_code, sorted(up)))
    if r.status_code != 201:
        return {}
    CREATED["uploads"].append(up["upload_id"])
    check("U02", "files[] names/bytes exact, total_bytes = sum, other field ignored",
          up["files"] == [{"name": "fortigate_bf.log", "bytes": len(data)}, {"name": "noise.txt", "bytes": len(noise)}]
          and up["total_bytes"] == len(data) + len(noise), up["files"])
    d = REPO / up["raw_dir"]
    check("U03", "upload written byte-exact under data/raw/uploads/<id>/",
          hashlib.sha256((d / "fortigate_bf.log").read_bytes()).hexdigest() == hashlib.sha256(data).hexdigest()
          and re.fullmatch(r"up-\d{8}-\d{6}-[0-9a-f]{6}", up["upload_id"]) is not None, up["raw_dir"])
    check("U04", "created_at ISO-8601 UTC Z", re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", up["created_at"])
          is not None, up["created_at"])
    # local hard link
    src = tmp / "local_src" / "fw_local.log"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_bytes(data)
    r = c.post("/api/uploads/local", json={"path": str(src)})
    lo = r.json()
    if r.status_code == 201:
        CREATED["uploads"].append(lo["upload_id"])
    dst = REPO / lo.get("raw_dir", "x") / "fw_local.log"
    check("U05", "POST /api/uploads/local -> 201 mode link, same file (hard link, nlink 2)",
          r.status_code == 201 and lo["mode"] == "link" and dst.exists() and dst.samefile(src)
          and src.stat().st_nlink == 2 and lo["files"] == [{"name": "fw_local.log", "bytes": len(data)}],
          (r.status_code, lo.get("mode")))
    time.sleep(1.1)  # created_at has 1 s resolution
    r = c.post("/api/uploads", content=mbody(part("later.log", b"x\n")), headers={"content-type": CTYPE})
    if r.status_code == 201:
        CREATED["uploads"].append(r.json()["upload_id"])
    lst = c.get("/api/uploads").json()
    mine = [u["upload_id"] for u in lst if u["upload_id"] in CREATED["uploads"]]
    check("U06", "GET /api/uploads lists all three, newest first, same shape",
          mine[0] == CREATED["uploads"][-1] and set(mine) == set(CREATED["uploads"])
          and all(set(u) == UPLOAD_KEYS for u in lst), mine)
    # hostile names (multipart)
    names = {"../evil.log": 400, "..\\evil.log": 400, "/etc/passwd.log": 400, "\\\\srv\\share\\x.log": 400,
             "C:\\Windows\\x.log": 400, "C:x.log": 400, "a/../../b.log": 400, "": 400, "   ": 400,
             ".log": 415, "evil.exe": 415, "evil.log.exe": 415, "evil.log.": 415, "evil": 415,
             "evil.LOG": 201, "sub/dir/ok.log": 201, "we ird$name.log": 201, "\u0430dmin.log": 201}
    for name, want in names.items():
        r = c.post("/api/uploads", content=mbody(part(name, b"x\n")), headers={"content-type": CTYPE})
        if r.status_code == 201:
            CREATED["uploads"].append(r.json()["upload_id"])
        saved = r.json()["files"][0]["name"] if r.status_code == 201 else None
        ok = r.status_code == want and (saved is None or re.fullmatch(r"[A-Za-z0-9._-]+", saved) is not None)
        check(f"U07|{name!r}", f"upload name {name!r} -> {want}", ok, (r.status_code, saved), want)
    check("U08", "no partial upload left after rejected names", incoming_empty())
    # Windows reserved device names: must not 201 with a lost/empty file
    for name in ("CON.log", "NUL.log", "aux.log", "COM1.log", "nul.txt"):
        payload = b"reserved-name-payload\n"
        r = c.post("/api/uploads", content=mbody(part(name, payload)), headers={"content-type": CTYPE})
        lost = False
        if r.status_code == 201:
            u = r.json()
            CREATED["uploads"].append(u["upload_id"])
            f = REPO / u["raw_dir"] / u["files"][0]["name"]
            try:
                lost = f.read_bytes() != payload
            except OSError:
                lost = True
        check(f"U09|{name}", f"Windows reserved name {name}: refused, or stored and readable byte-exact",
              r.status_code in (400, 415) or (r.status_code == 201 and not lost), (r.status_code, "lost" if lost else ""))
    # content-type / structure
    r = c.post("/api/uploads", json={"files": "x"})
    check("U10", "JSON body to /api/uploads -> 400", r.status_code == 400, r.status_code)
    r = c.post("/api/uploads", content=b"x", headers={"content-type": "multipart/form-data"})
    check("U11", "multipart without boundary -> 400", r.status_code == 400, r.status_code)
    r = c.post("/api/uploads", content=mbody(part("a.log", b"x", field="file")), headers={"content-type": CTYPE})
    check("U12", "no 'files' field -> 400", r.status_code == 400, r.status_code)
    r = c.post("/api/uploads", content=part("a.log", b"x\n"), headers={"content-type": CTYPE})
    check("U13", "truncated multipart (closing boundary missing) -> 400", r.status_code == 400, r.status_code)
    r = c.post("/api/uploads", content=part("a.log", b"x\n")[:-30], headers={"content-type": CTYPE})
    check("U14", "multipart cut mid-headers -> 400", r.status_code == 400, r.status_code)
    check("U15", "no partial upload left after truncated bodies", incoming_empty())
    # oversize by Content-Length (64 GiB cap + 1 MiB overhead): server must answer without reading the body
    for cid, length, want in (("U16", 80 * 2**30, 413), ("U17", 64 * 2**30 + 2**20 + 1, 413)):
        req = (f"POST /api/uploads HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: {CTYPE}\r\n"
               f"Content-Length: {length}\r\nConnection: close\r\n\r\n").encode() + part("big.log", b"x" * 100)
        t = time.perf_counter()
        st, _ = raw_http(port, req, timeout=15)
        check(cid, f"Content-Length {length} -> {want} without streaming the body", st == want,
              (st, round(time.perf_counter() - t, 2)))
    free = shutil.disk_usage(UPLOAD_ROOT if UPLOAD_ROOT.exists() else REPO).free
    want = 507 if free - 60 * 2**30 < 2 * 2**30 else None
    req = (f"POST /api/uploads HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: {CTYPE}\r\n"
           f"Content-Length: {60 * 2**30}\r\nConnection: close\r\n\r\n").encode() + part("big.log", b"x" * 100)
    st, _ = raw_http(port, req, timeout=5)
    if want:
        check("U18", "Content-Length 60 GiB with less free disk -> 507", st == want, st)
    else:
        check("U18", f"Content-Length 60 GiB (free {free // 2**30} GiB): accepted then client stalls -> no 2xx",
              st != 201, st)
    # client hangs up mid-body
    req = (f"POST /api/uploads HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: {CTYPE}\r\n"
           f"Content-Length: 100000\r\n\r\n").encode() + part("cut.log", b"y" * 5000)[:4000]
    raw_http(port, req, close_after_send=True)
    for _ in range(50):
        if incoming_empty():
            break
        time.sleep(0.1)
    check("U19", "client disconnect mid-body: partial dir removed within 5 s", incoming_empty())
    # /api/uploads/local abuse
    for cid, path, want in (("U20", "data/raw/smoke/edr.jsonl", 400), ("U21", str(tmp / "does_not_exist.log"), 404),
                            ("U22", str(tmp), 400), ("U23", str(REPO / "backend" / "pyproject.toml"), 415),
                            ("U24", "", 400), ("U25", str(tmp / ".." / "qa_api" / "local_src" / "fw_local.log"), 201)):
        r = c.post("/api/uploads/local", json={"path": path})
        if r.status_code == 201:
            CREATED["uploads"].append(r.json()["upload_id"])
        check(cid, f"uploads/local {path!r} -> {want}", r.status_code == want, (r.status_code, r.json().get("detail")))
    r = c.post("/api/uploads/local", json={})
    check("U26", "uploads/local without path -> 422", r.status_code == 422, r.status_code)
    check("U27", "no partial upload left after local abuse", incoming_empty())
    return up


# ------------------------------------------------------------------------------------------------ runs
def wait_run(c: httpx.Client, rid: str, limit_s: float = 900) -> tuple[dict, list[tuple[float, str, int]]]:
    seen: list[tuple[float, str, int]] = []
    t0 = time.monotonic()
    while time.monotonic() - t0 < limit_s:
        s = c.get(f"/api/runs/{rid}").json()
        if not seen or seen[-1][1:] != (s["stage"], s["percent"]):
            seen.append((round(time.monotonic() - t0, 1), s["stage"], s["percent"]))
        if s["status"] != "running":
            return s, seen
        time.sleep(0.5)
    raise TimeoutError(rid)


def probe_runs(c: httpx.Client, base: str, served: Path, up: dict[str, Any]) -> dict[str, Any]:
    nums: dict[str, Any] = {}
    bad = (("X01", {"raw_dir": "../../etc"}, 400), ("X02", {"raw_dir": "C:/Windows"}, 400),
           ("X03", {"raw_dir": "data/raw"}, 400), ("X04", {"raw_dir": "data/raw/uploads"}, 400),
           ("X05", {"raw_dir": "data/raw/uploads/.incoming"}, 400), ("X06", {"raw_dir": "data/raw/nope_qa"}, 400),
           ("X07", {"raw_dir": "data/raw/smoke", "out_dir": "data/out/a/b"}, 400),
           ("X08", {"raw_dir": "data/raw/smoke", "out_dir": "data/out/live"}, 400),
           ("X09", {"raw_dir": "data/raw/smoke", "out_dir": "C:/temp/x"}, 400),
           ("X10", {"raw_dir": "data/raw/smoke", "out_dir": RUN_OUT, "ground_truth": "C:/Windows/win.ini"}, 400),
           ("X11", {"raw_dir": "data/raw/smoke", "out_dir": RUN_OUT, "ground_truth": "data/raw/smoke/nope.json"}, 400),
           ("X12", {"out_dir": RUN_OUT}, 422), ("X13", {"raw_dir": "data/raw/sm oke"}, 400))
    for cid, payload, want in bad:
        r = c.post("/api/runs", json=payload)
        if r.status_code == 202:  # must never happen for these; stop it from mattering by recording
            CREATED["runs"].append(r.json()["run_id"])
        detail = r.json().get("detail")
        shapes = ("data/raw/<set>", "data/raw/uploads/<upload_id>", "data/raw/", "data/out/<name>", "data/out/")
        rest = detail
        for sh in shapes:  # the documented root shapes may appear; the submitted value must not
            rest = rest.replace(sh, "") if isinstance(rest, str) else rest
        echo = isinstance(rest, str) and any(str(v) in rest for v in payload.values() if v and len(str(v)) > 8)
        check(cid, f"POST /api/runs {payload} -> {want}, detail never echoes the path",
              r.status_code == want and not echo, (r.status_code, detail))
    # concurrent starts: exactly one 202
    barrier = threading.Barrier(6)
    codes: list[int] = []
    rids: list[str] = []

    def go() -> None:
        with httpx.Client(base_url=base, timeout=60) as cc:
            barrier.wait()
            rr = cc.post("/api/runs", json={"raw_dir": "data/raw/smoke", "out_dir": RUN_OUT})
            codes.append(rr.status_code)
            if rr.status_code == 202:
                rids.append(rr.json()["run_id"])

    ths = [threading.Thread(target=go) for _ in range(6)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    CREATED["runs"] += rids
    CREATED["out"].append("qa_api_smoke")
    CREATED["parquet"].append("qa_api_smoke")
    check("X20", "6 concurrent POST /api/runs -> exactly one 202, five 409",
          sorted(codes) == [202, 409, 409, 409, 409, 409], sorted(codes))
    if len(rids) != 1:
        return nums
    rid = rids[0]
    check("X21", "run_id is 12 hex", re.fullmatch(r"[0-9a-f]{12}", rid) is not None, rid)
    s = c.get(f"/api/runs/{rid}").json()
    check("X22", "GET /api/runs/{id} exact key set while running", set(s) == RUN_KEYS, sorted(s))
    h = c.get("/api/health").json()
    check("X23", "while the run is running the served dir is unchanged",
          Path(h["served_out_dir"]) == served.resolve() and h["out_dir_source"] == "env", h["served_out_dir"])
    r = c.post("/api/runs", json={"raw_dir": f"data/raw/uploads/{up.get('upload_id', 'x')}"})
    check("X24", "a second run (other raw dir) while one runs -> 409", r.status_code == 409, r.status_code)
    s, seen = wait_run(c, rid)
    pcts = [p for _, _, p in seen]
    nums["smoke_run"] = {"elapsed_s": s["elapsed_s"], "peak_rss_mb": s["peak_rss_mb"], "stages_seen": seen}
    check("X25", "smoke run succeeded rc 0, stage done, percent 100, error null",
          s["status"] == "succeeded" and s["returncode"] == 0 and s["stage"] == "done" and s["percent"] == 100
          and s["error"] is None, {k: s[k] for k in ("status", "returncode", "stage", "percent", "error")})
    check("X26", "percent is monotonic non-decreasing while polled", pcts == sorted(pcts), pcts)
    check("X27", "peak_rss_mb > 0 recorded", s["peak_rss_mb"] > 0, s["peak_rss_mb"])
    h = c.get("/api/health").json()
    out = (REPO / RUN_OUT).resolve()
    n_out = len(json.loads((out / "incidents_index.json").read_text(encoding="utf-8")))
    check("X28", "served switch: health -> data/out/qa_api_smoke, source api_run, count == its index",
          Path(h["served_out_dir"]) == out and h["out_dir_source"] == "api_run" and h["incidents"] == n_out,
          (h["served_out_dir"], h["out_dir_source"], h["incidents"], n_out))
    nums["smoke_run"]["incidents"] = n_out
    idx = c.get("/api/incidents").json()
    check("X29", "GET /api/incidents now serves the run's index",
          sorted(i["id"] for i in idx) == sorted(i["id"] for i in json.loads((out / "incidents_index.json")
                                                                              .read_text(encoding="utf-8"))))
    rm = json.loads((out / "run_metrics.json").read_text(encoding="utf-8"))
    nums["smoke_run"]["run_metrics_total_wall_s"] = rm.get("total_wall_s")
    nums["smoke_run"]["run_metrics_rows_in"] = rm.get("rows_in")
    nums["smoke_run"]["run_metrics_peak_rss_mb"] = rm.get("peak_rss_mb")
    r = c.post("/api/reload")
    check("X30", "POST /api/reload keeps the pinned run output", r.json().get("out_dir") == str(out), r.json())
    r = c.post("/api/runs", json={"raw_dir": "data/raw/smoke", "out_dir": RUN_OUT})
    check("X31", "run into the served out_dir -> 400", r.status_code == 400, (r.status_code, r.json().get("detail")))
    # upload -> run -> served switch to the upload's output (fw brute force must become an incident)
    if up:
        r = c.post("/api/runs", json={"raw_dir": up["raw_dir"]})
        check("X32", "POST /api/runs on data/raw/uploads/<id> -> 202", r.status_code == 202, r.status_code)
        if r.status_code == 202:
            rid2 = r.json()["run_id"]
            CREATED["runs"].append(rid2)
            CREATED["out"].append(up["upload_id"])
            CREATED["parquet"].append(up["upload_id"])
            s2, _ = wait_run(c, rid2)
            nums["upload_run"] = {"elapsed_s": s2["elapsed_s"], "peak_rss_mb": s2["peak_rss_mb"]}
            h = c.get("/api/health").json()
            uout = (REPO / "data" / "out" / up["upload_id"]).resolve()
            check("X33", "upload run succeeded and the API now serves data/out/<upload_id>",
                  s2["status"] == "succeeded" and Path(h["served_out_dir"]) == uout, (s2["status"], h["served_out_dir"]))
            idx = c.get("/api/incidents").json()
            hit = [i for i in idx if "Credential Access" in i["tactics"] and "Initial Access" in i["tactics"]]
            ok = bool(hit)
            if ok:
                inc = c.get(f"/api/incidents/{hit[0]['id']}").json()
                techs = {st["technique_id"] for st in inc["backbone"]}
                ok = "T1110" in techs and any((st.get("src_ip") == qa_fglines.ATTACK_IP) for st in inc["backbone"])
            check("X34", "uploaded FortiGate brute-force-then-success is served as an incident (T1110, attacker ip)",
                  ok, [(i["id"], i["tactics"]) for i in idx])
            acc = c.get("/api/metrics").json()["ingest_accounting"]
            rows = {a["source_type"]: (a["rows_in"], a["rows_ok"], a["dropped"]) for a in acc if a["rows_in"]}
            check("X35", "upload accounting: fortigate_kv rows_in == ok == 281 lines, 0 dropped",
                  rows == {"fortigate_kv": (281, 281, 0)}, rows)
    lst = c.get("/api/runs").json()
    check("X36", "GET /api/runs newest first, same keys as /runs/{id}",
          [x["run_id"] for x in lst][: len(CREATED["runs"])] == list(reversed(CREATED["runs"]))
          and all(set(x) == RUN_KEYS for x in lst), [x["run_id"] for x in lst])
    for cid, rid_ in (("X37", "000000000000"), ("X38", "ZZZ"), ("X39", "..%2f..%2fetc")):
        r = c.get(f"/api/runs/{rid_}")
        check(cid, f"GET /api/runs/{rid_} -> 404", r.status_code == 404, r.status_code)
    return nums


# ------------------------------------------------------------------------------------------------ latency
def probe_latency(base: str, ids: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    with httpx.Client(base_url=base, timeout=30) as c:
        for path in ("/api/health", "/api/incidents", f"/api/incidents/{ids[0]}", f"/api/incidents/{ids[0]}/path",
                     "/api/metrics"):
            ts = []
            for _ in range(200):
                t = time.perf_counter()
                r = c.get(path)
                ts.append((time.perf_counter() - t) * 1000)
                assert r.status_code == 200
            out[path.replace(ids[0], "{id}")] = {"n": 200, "p50_ms": pct(ts, 50), "p95_ms": pct(ts, 95),
                                                  "p99_ms": pct(ts, 99), "max_ms": round(max(ts), 2)}
    lat: list[float] = []
    errs = [0]
    lock = threading.Lock()
    paths = ["/api/health", "/api/incidents", *[f"/api/incidents/{i}/path" for i in ids], "/api/metrics"]

    def worker(k: int) -> None:
        with httpx.Client(base_url=base, timeout=30) as cc:
            for j in range(100):
                t = time.perf_counter()
                try:
                    ok = cc.get(paths[(k + j) % len(paths)]).status_code == 200
                except httpx.HTTPError:
                    ok = False
                dt = (time.perf_counter() - t) * 1000
                with lock:
                    lat.append(dt)
                    errs[0] += 0 if ok else 1

    t0 = time.perf_counter()
    ths = [threading.Thread(target=worker, args=(k,)) for k in range(8)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    wall = time.perf_counter() - t0
    out["concurrent_8x100_mixed"] = {"n": len(lat), "errors": errs[0], "p50_ms": pct(lat, 50), "p95_ms": pct(lat, 95),
                                     "p99_ms": pct(lat, 99), "rps": round(len(lat) / wall, 1)}
    p = out["/api/incidents/{id}/path"]
    check("L01", "/path p95 < 50 ms over 200 sequential requests (TESTING.md §4.6)", p["p95_ms"] < 50, p)
    check("L02", "8 concurrent clients x 100 mixed reads: 0 errors", errs[0] == 0, out["concurrent_8x100_mixed"])
    return out


def cleanup() -> None:
    for uid in CREATED["uploads"]:
        shutil.rmtree(UPLOAD_ROOT / uid, ignore_errors=True)
        (UPLOAD_ROOT / ".meta" / f"{uid}.json").unlink(missing_ok=True)
    for name in CREATED["out"]:
        shutil.rmtree(REPO / "data" / "out" / name, ignore_errors=True)
    for name in CREATED["parquet"]:
        shutil.rmtree(REPO / "data" / "parquet" / name, ignore_errors=True)
    for rid in CREATED["runs"]:
        (REPO / "data" / "runs" / f"run-{rid}.log").unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--served", required=True, help="the ATTACKLENS_OUT the server was started with")
    ap.add_argument("--json", required=True)
    ap.add_argument("--tmp", default=str(REPO / "data" / "tmp" / "qa_api"))
    ap.add_argument("--no-runs", action="store_true")
    ap.add_argument("--cleanup", action="store_true", help="remove every upload/run/out this probe created")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")  # type: ignore[union-attr]
    if a.port in (8000, 5173):
        raise SystemExit("refusing to probe a shared port")
    base = f"http://127.0.0.1:{a.port}"
    served = Path(a.served).resolve()
    nums: dict[str, Any] = {}
    try:
        with httpx.Client(base_url=base, timeout=60) as c:
            ids = probe_reads(c, served)
            probe_spa(c, a.port)
            nums["latency"] = probe_latency(base, ids)
            probe_guards(c, a.port)
            qa_api_probe_integ.probe_integrations(c, a.port, check)
            up = probe_uploads(c, a.port, Path(a.tmp))
            if not a.no_runs:
                nums.update(probe_runs(c, base, served, up))
    finally:
        Path(a.json).write_text(json.dumps({"results": RESULTS, "numbers": nums, "created": CREATED}, indent=1,
                                           default=str), encoding="utf-8")
        if a.cleanup:
            cleanup()
    n_fail = sum(1 for r in RESULTS if not r["ok"])
    print(f"\n{len(RESULTS)} checks, {n_fail} failed -> {a.json}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
