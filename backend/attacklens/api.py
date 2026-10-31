"""AttackLens API (DEVELOPMENT.md §7.2). Serves precomputed JSON from memory; JSON responses only under /api.

Run: python -m uvicorn attacklens.api:app --port 8000   (data dir: $ATTACKLENS_OUT or newest data/out/<set>)
"""

from __future__ import annotations

import importlib
import logging
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
import yaml
from pydantic import BaseModel

from attacklens.api_runs import RunManager
from attacklens.api_store import Store
from attacklens.config import REPO_ROOT

log = logging.getLogger(__name__)

ID_RE = re.compile(r"^inc-[0-9a-f]{8}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{12}$")
DIST_DIR = REPO_ROOT / "frontend" / "dist"
CORS_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"]
_JSON = "application/json"


class RunRequest(BaseModel):
    raw_dir: str
    out_dir: str | None = None
    ground_truth: str | None = None


class AppState:
    """The one app-state object: data store + run manager."""

    def __init__(self) -> None:
        self.store = Store()
        self.runs = RunManager()
        self.started = time.time()
        self._live_cfg: dict[str, Any] | None = None

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

    def refresh(self) -> None:
        """Reload when a finished run produced new output, else the rate-limited mtime check."""
        for job in self.runs.jobs():
            if job.status == "succeeded" and not job.reloaded:
                job.reloaded = True
                if (job.out_dir / "incidents_index.json").exists():
                    self.store.reload(job.out_dir)
                    return
        self.store.maybe_reload()


def _raw(body: bytes) -> Response:
    return Response(content=body, media_type=_JSON)


def _check_id(inc_id: str) -> None:
    if not ID_RE.match(inc_id):
        raise HTTPException(status_code=404, detail="incident not found")


def create_app() -> FastAPI:
    state = AppState()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        state.store.reload()
        yield

    app = FastAPI(title="AttackLens API", version="0.1.0", lifespan=lifespan)
    app.state.al = state
    app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["GET", "POST"],
                       allow_headers=["*"])

    def fresh() -> AppState:
        state.refresh()
        return state

    @app.get("/api/health")
    def health(st: AppState = Depends(fresh)) -> dict[str, Any]:
        snap = st.store.snap
        return {"status": "ok", "incidents": snap.count, "off_contract": snap.invalid,
                "out_dir": str(snap.out_dir) if snap.out_dir else None, "loaded_at": snap.loaded_at,
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
            job = state.runs.start(req.raw_dir, req.out_dir, req.ground_truth)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"run_id": job.run_id}

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
