"""AttackLens API (DEVELOPMENT.md §7.2). Serves precomputed JSON from memory; JSON responses only under /api.

Run: python -m uvicorn attacklens.api:app --port 8000   (data dir: $ATTACKLENS_OUT or newest data/out/<set>)
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.requests import ClientDisconnect
import yaml
from pydantic import BaseModel

from attacklens.api_guard import OriginGuard, guard_config
from attacklens.api_runs import RunManager, resolve_path
from attacklens.api_upload import UploadConfig, UploadError, UploadManager
from attacklens.api_store import Store
from attacklens.config import REPO_ROOT

log = logging.getLogger(__name__)

ID_RE = re.compile(r"^inc-[0-9a-f]{8}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{12}$")
DIST_DIR = REPO_ROOT / "frontend" / "dist"
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]  # Vite dev server (GET responses readable)
_JSON = "application/json"


class RunRequest(BaseModel):
    raw_dir: str
    out_dir: str | None = None
    ground_truth: str | None = None


class LocalUpload(BaseModel):
    path: str


class AppState:
    """The one app-state object: data store + run manager + uploads (components injectable for tests)."""

    def __init__(self, store: Store | None = None, runs: RunManager | None = None,
                 uploads: UploadManager | None = None) -> None:
        pipe = _pipeline_yaml()
        self.uploads = uploads or UploadManager(UploadConfig.from_pipeline(pipe))
        self.store = store or Store()
        self.runs = runs or RunManager(upload_root=self.uploads.cfg.root,
                                       parquet_root=resolve_path(str(pipe.get("parquet_root", "data/parquet"))))
        self.store.exclude = self.unfinished_out_dirs
        self.trusted_hosts, self.allowed_origins = guard_config(pipe)
        self.started = time.time()
        self._live_cfg: dict[str, Any] | None = None
        self._int_cfg: dict[str, Any] | None = None

    def live_cfg(self) -> dict[str, Any]:
        """{"live": <config/live.yaml>} loaded once (status calls must stay cheap)."""
        if self._live_cfg is None:
            path = REPO_ROOT / "config" / "live.yaml"
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                data = {}
            self._live_cfg = {"live": data if isinstance(data, dict) else {}}
        return self._live_cfg

    def integrations_cfg(self) -> dict[str, Any]:
        """{"integrations": <config/integrations.yaml>, "live": <live.yaml>} loaded once."""
        if self._int_cfg is None:
            path = REPO_ROOT / "config" / "integrations.yaml"
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError) as exc:
                log.warning("api: cannot read integrations.yaml: %s", exc)
                data = {}
            self._int_cfg = {"integrations": data if isinstance(data, dict) else {}, **self.live_cfg()}
        return self._int_cfg

    def unfinished_out_dirs(self) -> set[Path]:
        """Out dirs whose newest API run is still running or failed: never auto-picked as the newest output."""
        newest: dict[Path, Any] = {}
        for j in self.runs.jobs():
            if j.out_dir not in newest or j.started_at > newest[j.out_dir].started_at:
                newest[j.out_dir] = j
        return {d for d, j in newest.items() if j.status != "succeeded"}

    def refresh(self) -> None:
        """A run that exited with rc 0 switches the store to its out dir (newest such run wins, even with
        $ATTACKLENS_OUT set); otherwise the rate-limited mtime check."""
        done = [j for j in self.runs.jobs() if not j.reloaded and j.status == "succeeded"]
        for job in done:
            job.reloaded = True
        if done:
            newest = max(done, key=lambda j: j.started_at)
            self.store.reload(newest.out_dir)
            log.info("api: serving %s (run %s finished)", newest.out_dir, newest.run_id)
            return
        self.store.maybe_reload()


def _pipeline_yaml() -> dict[str, Any]:
    try:
        data = yaml.safe_load((REPO_ROOT / "config" / "pipeline.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        log.warning("api: cannot read pipeline.yaml: %s", exc)
        data = {}
    return data if isinstance(data, dict) else {}


def _raw(body: bytes) -> Response:
    return Response(content=body, media_type=_JSON)


def _check_id(inc_id: str) -> None:
    if not ID_RE.match(inc_id):
        raise HTTPException(status_code=404, detail="incident not found")


def create_app(state: AppState | None = None) -> FastAPI:
    state = state or AppState()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        state.store.reload()
        yield
        scans = getattr(state, "integrity_scans", None)  # never leave quick-scan threads behind the app
        if scans is not None:
            scans.shutdown(wait=True)

    app = FastAPI(title="AttackLens API", version="0.1.0", lifespan=lifespan)
    app.state.al = state
    # Added innermost first: TrustedHost (DNS rebinding) -> CORS -> OriginGuard (cross-site simple POSTs).
    app.add_middleware(OriginGuard, allowed_origins=state.allowed_origins)
    app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["GET", "POST"],
                       allow_headers=["*"])
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=state.trusted_hosts, www_redirect=False)

    def fresh() -> AppState:
        state.refresh()
        return state

    @app.get("/api/health")
    def health(st: AppState = Depends(fresh)) -> dict[str, Any]:
        snap = st.store.snap
        return {"status": "ok", "incidents": snap.count, "off_contract": snap.invalid,
                "out_dir": str(snap.out_dir) if snap.out_dir else None,
                "served_out_dir": str(snap.out_dir) if snap.out_dir else None,
                "out_dir_source": "api_run" if st.store.pinned else ("env" if os.environ.get("ATTACKLENS_OUT")
                                                                    else "newest"),
                "loaded_at": snap.loaded_at,
                "uptime_s": round(time.time() - st.started, 1)}

    @app.get("/api/incidents")
    def incidents(st: AppState = Depends(fresh)) -> Response:
        return _raw(st.store.snap.index_bytes)

    @app.get("/api/incidents/{inc_id}")
    def incident(inc_id: str, st: AppState = Depends(fresh)) -> Response:
        _check_id(inc_id)
        body = st.store.snap.incident_bytes.get(inc_id)
        if body is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return _raw(body)

    @app.get("/api/incidents/{inc_id}/path")
    def incident_path(inc_id: str, st: AppState = Depends(fresh)) -> Response:
        _check_id(inc_id)
        body = st.store.snap.path_bytes.get(inc_id)
        if body is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return _raw(body)

    @app.get("/api/incidents/{inc_id}/pivots")
    def incident_pivots(inc_id: str, st: AppState = Depends(fresh)) -> dict[str, Any]:
        _check_id(inc_id)
        body = st.store.snap.incident_bytes.get(inc_id)
        if body is None:
            raise HTTPException(status_code=404, detail="incident not found")
        from attacklens import pivots

        return pivots.build_pivots(json.loads(body), st.integrations_cfg()["integrations"])

    @app.get("/api/integrations/status")
    def integrations_status(st: AppState = Depends(fresh)) -> dict[str, Any]:
        from attacklens import integrations_status

        return integrations_status.status(st.integrations_cfg())

    from attacklens import api_integrations  # UI-driven connect (catalog, settings, test, start/stop)

    app.include_router(api_integrations.create_router(getattr(state, "integrations", None)))

    from attacklens import api_integrity  # log integrity / tamper reports (+ upload quick-scan auto-start)

    app.include_router(api_integrity.create_router(state, RUN_ID_RE))

    @app.get("/api/metrics")
    def metrics(st: AppState = Depends(fresh)) -> Response:
        return _raw(st.store.snap.metrics_bytes)

    @app.post("/api/reload")
    def reload() -> dict[str, Any]:
        snap = state.store.reload()
        return {"incidents": snap.count, "out_dir": str(snap.out_dir) if snap.out_dir else None}

    @app.post("/api/runs", status_code=202)
    def start_run(req: RunRequest) -> dict[str, str]:
        try:
            # never write into the output being served (mtime watcher would load it half-written)
            job = state.runs.start(req.raw_dir, req.out_dir, req.ground_truth,
                                   protect=(state.store.snap.out_dir, state.store.pinned))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"run_id": job.run_id}

    @app.get("/api/runs")
    def list_runs(st: AppState = Depends(fresh)) -> list[dict[str, Any]]:
        return st.runs.list()

    @app.post("/api/uploads", status_code=201)
    async def upload(request: Request) -> dict[str, Any]:
        cl = request.headers.get("content-length")
        try:
            info = await state.uploads.receive(request.headers.get("content-type"),
                                               int(cl) if cl and cl.isdigit() else None, request.stream())
        except UploadError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
        except ClientDisconnect:
            raise HTTPException(status_code=400, detail="client disconnected; partial upload removed") from None
        return state.uploads.announce(info)  # auto-starts the integrity quick scan (api_integrity)

    @app.post("/api/uploads/local", status_code=201)
    def upload_local(req: LocalUpload) -> dict[str, Any]:
        try:
            info = state.uploads.register_local(req.path)
        except UploadError as exc:
            raise HTTPException(status_code=exc.status, detail=exc.detail) from exc
        return state.uploads.announce(info)

    @app.get("/api/uploads")
    def list_uploads() -> list[dict[str, Any]]:
        return state.uploads.list()

    @app.get("/api/runs/{run_id}")
    def run_status(run_id: str, st: AppState = Depends(fresh)) -> dict[str, Any]:
        job = st.runs.get(run_id) if RUN_ID_RE.match(run_id) else None
        if job is None:
            raise HTTPException(status_code=404, detail="run not found")
        return st.runs.status(job)

    @app.get("/api/live/status")
    def live_status(st: AppState = Depends(fresh)) -> dict[str, Any]:
        try:
            live = importlib.import_module("attacklens.live")
        except ImportError:
            return {"enabled": False}
        fn = getattr(live, "status", None)
        if not callable(fn):
            return {"enabled": False}
        out = st.store.snap.out_dir
        # the served out dir if it is a live output, else live.yaml out_dir (data/out/live)
        target = out if out is not None and (out / getattr(live, "STATUS_FILE", "live_status.json")).exists() else None
        try:
            result = fn(target, st.live_cfg())
        except Exception as exc:  # noqa: BLE001 - live mode problems must not break the API
            log.warning("api: live.status() failed: %s", exc)
            return {"enabled": False, "error": type(exc).__name__}
        return result if isinstance(result, dict) else {"enabled": bool(result)}

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def api_not_found(rest: str) -> JSONResponse:
        return JSONResponse({"detail": "not found"}, status_code=404)

    _mount_frontend(app)
    return app


def _mount_frontend(app: FastAPI, dist: Path = DIST_DIR) -> None:
    """Serve the built SPA (after /api routes): static assets + index.html fallback for client routes."""
    index = dist / "index.html"
    if not index.is_file():
        log.info("api: %s not built; serving API only", dist)
        return
    if (dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")
    root = dist.resolve()

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str) -> Response:
        candidate = (root / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(root):
            return FileResponse(candidate)
        return FileResponse(index, media_type="text/html")


app = create_app()
