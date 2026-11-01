"""One-click SIEM / cloud integrations from the UI: /api/integrations/{catalog, {id}, {id}/test|start|stop}.

- Settings saved here go to data/integrations/settings.json (overlay over config/integrations.yaml, integrations.py);
  secrets go to secrets_store (DPAPI). GET never returns a secret value, only secrets_set / secrets_source.
- start spawns `python -m attacklens.connect --source <id> --mode <m>` (and `attacklens.live` if no live mode is
  running) with ATTACKLENS_INTEGRATIONS_OVERLAY=1, so the children see the UI settings through integrations.icfg().
- Every endpoint is loopback-only, with no foreign Origin, a capped body and an id from the catalog.
Field validation: integrations_status.validate. Connection test: connect.test_connection (one tiny pull, fixed messages).
"""

from __future__ import annotations

import atexit
import copy
import ipaddress
import json
import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from attacklens import integrations as ig
from attacklens import connect as probe
from attacklens import integrations_status as ist
from attacklens import secrets_store
from attacklens.api_guard import norm_origin
from attacklens.config import CONFIG_DIR, REPO_ROOT

log = logging.getLogger(__name__)

MAX_BODY = 64 * 1024
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
ALLOWED_ORIGINS = {norm_origin(f"http://{h}:{p}") for h in ("localhost", "127.0.0.1", "[::1]") for p in (5173, 8000)}
CLIENTS_ENV = "ATTACKLENS_INTEGRATIONS_ALLOW_CLIENTS"  # extra client hosts (e.g. a Docker bridge gateway)
_CTRL = {chr(i) for i in range(32)} | {"\x7f"}


class ApiError(Exception):
    def __init__(self, status: int, error: str, field: str | None = None) -> None:
        super().__init__(error)
        self.status, self.error, self.field = status, error, field


@dataclass
class Proc:
    proc: Any
    mode: str
    started_at: float


def _spawn(cmd: list[str], env: dict[str, str], log_path: Path) -> Any:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
    with log_path.open("ab") as fh:
        return subprocess.Popen(cmd, cwd=REPO_ROOT, env=env, stdout=fh, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, creationflags=flags)


def _alive(p: Proc | None) -> bool:
    return p is not None and p.proc.poll() is None


def _terminate(p: Proc | None) -> None:
    if not _alive(p):
        return
    assert p is not None
    p.proc.terminate()
    try:
        p.proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.proc.kill()


# ---- service -------------------------------------------------------------------------------------------------------
class IntegrationsService:
    """State of the integrations page: overlay + secrets on disk, the pull loops and the live process we started."""

    def __init__(self, config_dir: Path | None = None, spawn: Callable[..., Any] = _spawn) -> None:
        self.config_dir = Path(config_dir or CONFIG_DIR)
        self.spawn = spawn
        self.loops: dict[str, Proc] = {}
        self.live: Proc | None = None
        self.lock = threading.RLock()
        self._ycache: dict[str, tuple[int, dict[str, Any]]] = {}
        atexit.register(self.stop_all)

    # -- config
    def _yaml(self, name: str) -> dict[str, Any]:
        """Parsed config/<name>.yaml, cached per file mtime (a deep copy per call: callers may mutate)."""
        path = self.config_dir / f"{name}.yaml"
        try:
            stamp = path.stat().st_mtime_ns
            hit = self._ycache.get(name)
            if hit is None or hit[0] != stamp:
                d = yaml.load(path.read_text(encoding="utf-8"), Loader=_LOADER) or {}
                hit = self._ycache[name] = (stamp, d if isinstance(d, dict) else {})
            return copy.deepcopy(hit[1])
        except (OSError, yaml.YAMLError) as exc:
            log.warning("integrations api: cannot read %s.yaml: %s", name, type(exc).__name__)
            return {}

    def cfg(self, overlay: bool = True, full: bool = False) -> dict[str, Any]:
        c = {"integrations": self._yaml("integrations"), "live": self._yaml("live")}
        if full:
            c["sources"] = self._yaml("sources")
        return ig.apply_overlay(c) if overlay else c

    def entry(self, iid: str) -> dict[str, Any]:
        if not isinstance(iid, str) or len(iid) > 64:
            raise ApiError(404, "unknown integration", "id")
        for e in ist.catalog():
            if e["id"] == iid:
                return e
        raise ApiError(404, "unknown integration", "id")

    @staticmethod
    def section(entry: dict[str, Any]) -> str:
        return "sinks" if entry["kind"] == "sink" else "connectors"

    def _conf(self, entry: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
        c = (ig.icfg(cfg).get(self.section(entry)) or {}).get(entry["id"])
        return c if isinstance(c, dict) else {}

    # -- views
    def view(self, iid: str) -> dict[str, Any]:
        e = self.entry(iid)
        with self.lock:
            cfg, base_cfg = self.cfg(), self.cfg(overlay=False)
            item = ig.read_overlay()["items"].get(iid)
            loop = self.loops.get(iid)
            running = _alive(loop) if e["kind"] != "sink" else bool(self._conf(e, cfg).get("enabled"))
        c, base, stored = self._conf(e, cfg), self._conf(e, base_cfg), secrets_store.refs()
        settings, secrets_set, source = {}, {}, {}
        for f in e["fields"]:
            if f["type"] == "secret":
                env = ist.env_set(base, f)
                saved = f"{iid}.{f['key']}" in stored
                secrets_set[f["key"]] = env or saved
                source[f["key"]] = "env" if env else ("stored" if saved else None)
            else:
                v = ig.get_dotted(c, f["key"])
                settings[f["key"]] = ist._no_userinfo(v) if f["type"] == "url" else v
        return {"id": iid, "kind": e["kind"], "configured": isinstance(item, dict),
                "enabled": bool(c.get("enabled")), "settings": settings, "secrets_set": secrets_set,
                "secrets_source": source, "running": running,
                "mode": loop.mode if running and loop is not None else None, "status": self._status(e, cfg, loop)}

    def _status(self, e: dict[str, Any], cfg: dict[str, Any], loop: Proc | None) -> dict[str, Any]:
        st = ig.read_status(cfg)
        if e["kind"] == "sink":
            s = (st.get("sinks") or {}).get(e["id"]) or {}
            last = s.get("last") or {}
            return {"last_pull": s.get("last_publish_at"), "pulled": last.get("incidents"),
                    "written": last.get("sent"), "failed": last.get("failed"), "last_error": s.get("last_error")}
        modes = [loop.mode] if loop is not None else e.get("modes") or ["events", "alerts"]
        rows = [(st.get("connectors") or {}).get(f"{e['id']}_{m}") or {} for m in modes]
        s = max(rows, key=lambda r: str(r.get("last_pull_at") or r.get("last_error_at") or ""), default={})
        tot = s.get("totals") or {}
        return {"last_pull": s.get("last_pull_at"), "pulled": tot.get("pulled"), "written": tot.get("written"),
                "failed": tot.get("failed"), "last_error": s.get("last_error"), "mode": s.get("mode")}

    # -- mutations
    def save(self, iid: str, body: Any) -> dict[str, Any]:
        e = self.entry(iid)
        with self.lock:
            cfg, base_cfg = self.cfg(), self.cfg(overlay=False)
            try:
                settings, secrets = ist.validate(e, body, self._conf(e, cfg), secrets_store.refs(),
                                                 self._conf(e, base_cfg))
            except ist.FieldError as exc:
                raise ApiError(422, str(exc), exc.field) from None
            if any(v is not None for v in secrets.values()) and not secrets_store.available():
                raise ApiError(501, "secret storage is not available on this platform; set the environment "
                                    "variables named in config/integrations.yaml instead", next(iter(secrets)))
            if secrets:
                secrets_store.update({f"{iid}.{k}": v for k, v in secrets.items()})
            ov = ig.read_overlay()
            item = ov["items"].get(iid) if isinstance(ov["items"].get(iid), dict) else {}
            merged = {**(item.get("settings") or {}), **settings}
            ov["items"][iid] = {"section": self.section(e), "enabled": True,
                                "settings": {k: v for k, v in merged.items() if v is not None},
                                "secret_env": {f["key"]: ist.env_key(f) for f in e["fields"] if f["type"] == "secret"},
                                "updated_at": ig.now_iso()}
            ig.write_overlay(ov)
            log.info("integrations api: saved %s (%d settings, %d secret changes)", iid, len(settings), len(secrets))
            loop = self.loops.get(iid)
            if _alive(loop):
                assert loop is not None
                self._start_loop(iid, loop.mode, None)  # restart with the new settings
            if e["kind"] == "sink":
                self._restart_owned_live()
        return self.view(iid)

    def start(self, iid: str, body: Any) -> dict[str, Any]:
        e = self.entry(iid)
        body = body if isinstance(body, dict) else {}
        if e["kind"] == "sink":
            return self._set_enabled(e, True)
        mode = body.get("mode", "events")
        if mode not in e.get("modes", []):
            raise ApiError(422, f"mode must be one of {e.get('modes')}", "mode")
        since = body.get("since")
        if since is not None:
            try:
                if not isinstance(since, str) or ig.parse_duration_ms(since) <= 0:
                    raise ValueError
            except ValueError:
                raise ApiError(422, "since must look like 30m, 24h or 7d", "since") from None
        with self.lock:
            cfg = self.cfg()
            if not self._conf(e, cfg).get("enabled"):
                raise ApiError(409, "not configured: save the settings first", None)
            loop = self.loops.get(iid)
            if not (_alive(loop) and loop is not None and loop.mode == mode):
                if mode == "alerts" and not (ig.icfg(cfg).get("alert_input") or {}).get("enabled"):
                    ov = ig.read_overlay()
                    ov["alert_input"] = {**(ov.get("alert_input") or {}), "enabled": True}
                    ig.write_overlay(ov)
                    self._restart_owned_live()
                self._start_loop(iid, mode, since)
            self._ensure_live(cfg)
        return self.view(iid)

    def stop(self, iid: str) -> dict[str, Any]:
        e = self.entry(iid)
        if e["kind"] == "sink":
            return self._set_enabled(e, False)
        with self.lock:
            _terminate(self.loops.pop(iid, None))
        return self.view(iid)

    def delete(self, iid: str) -> dict[str, Any]:
        e = self.entry(iid)
        with self.lock:
            _terminate(self.loops.pop(iid, None))
            ov = ig.read_overlay()
            if ov["items"].pop(iid, None) is not None:
                ig.write_overlay(ov)
            n = secrets_store.delete_prefix(iid)
            log.info("integrations api: deleted %s (%d stored secrets removed)", iid, n)
            if e["kind"] == "sink":
                self._restart_owned_live()
        return self.view(iid)

    def test(self, iid: str) -> dict[str, Any]:
        e = self.entry(iid)
        return probe.test_connection(e, self.cfg(full=True))

    # -- processes
    def _child_env(self) -> dict[str, str]:
        return {**os.environ, ig.OVERLAY_ENV: "1", ig.SETTINGS_DIR_ENV: str(ig.settings_dir()),
                secrets_store.DIR_ENV: str(secrets_store.store_dir()), "PYTHONUNBUFFERED": "1"}

    def _start_loop(self, iid: str, mode: str, since: str | None) -> None:
        _terminate(self.loops.pop(iid, None))
        cmd = [sys.executable, "-m", "attacklens.connect", "--source", iid, "--mode", mode,
               "--config", str(self.config_dir)]
        if since:
            cmd += ["--since", since]
        p = self.spawn(cmd, self._child_env(), ig.settings_dir() / "logs" / f"connect_{iid}.log")
        self.loops[iid] = Proc(p, mode, time.time())
        log.info("integrations api: started pull loop %s (%s), pid %s", iid, mode, getattr(p, "pid", None))

    def _ensure_live(self, cfg: dict[str, Any]) -> None:
        if _alive(self.live):
            return
        try:
            from attacklens import live

            if live.status(None, cfg).get("enabled"):
                return  # a live mode started elsewhere is already running
        except Exception as exc:  # noqa: BLE001
            log.warning("integrations api: live status unavailable: %s", type(exc).__name__)
        cmd = [sys.executable, "-m", "attacklens.live", "--config", str(self.config_dir)]
        self.live = Proc(self.spawn(cmd, self._child_env(), ig.settings_dir() / "logs" / "live.log"), "live",
                         time.time())
        log.info("integrations api: started live mode, pid %s", getattr(self.live.proc, "pid", None))

    def _restart_owned_live(self) -> None:
        if _alive(self.live):
            _terminate(self.live)
            self.live = None
            self._ensure_live(self.cfg())

    def _set_enabled(self, e: dict[str, Any], on: bool) -> dict[str, Any]:
        with self.lock:
            ov = ig.read_overlay()
            item = ov["items"].get(e["id"])
            if not isinstance(item, dict):
                if on:
                    raise ApiError(409, "not configured: save the settings first", None)
            else:
                item["enabled"] = on
                ig.write_overlay(ov)
                self._restart_owned_live()
        return self.view(e["id"])

    def stop_all(self) -> None:
        for p in [*self.loops.values(), self.live]:
            try:
                _terminate(p)
            except Exception:  # noqa: BLE001 - best effort at exit
                pass
        self.loops.clear()
        self.live = None


# ---- HTTP ----------------------------------------------------------------------------------------------------------
def _client_ok(request: Request) -> bool:
    host = request.client.host if request.client else ""
    extra = {h.strip() for h in os.environ.get(CLIENTS_ENV, "").split(",") if h.strip()}
    if host in ("testclient", "localhost") or host in extra:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return ip.is_loopback or bool(mapped and mapped.is_loopback)


def _guard(request: Request) -> None:
    if not _client_ok(request):
        raise ApiError(403, "integrations API accepts local (loopback) clients only")
    origin = request.headers.get("origin")
    if origin is not None and norm_origin(origin) not in ALLOWED_ORIGINS:
        raise ApiError(403, "cross-origin request refused")


async def _body(request: Request) -> Any:
    cl = request.headers.get("content-length")
    if cl and (not cl.isdigit() or int(cl) > MAX_BODY):
        raise ApiError(413, f"body larger than {MAX_BODY} bytes")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > MAX_BODY:
            raise ApiError(413, f"body larger than {MAX_BODY} bytes")
    if not buf.strip():
        return {}
    try:
        return json.loads(bytes(buf))
    except ValueError:
        raise ApiError(422, "body is not valid JSON") from None


def create_router(svc: IntegrationsService | None = None) -> APIRouter:
    svc = svc or IntegrationsService()
    r = APIRouter(prefix="/api/integrations")
    r.service = svc  # type: ignore[attr-defined]

    async def call(request: Request, fn: Callable[..., Any], *args: Any, body: bool = False) -> JSONResponse:
        try:
            _guard(request)
            extra = [await _body(request)] if body else []
            return JSONResponse(await run_in_threadpool(fn, *args, *extra))
        except ApiError as exc:
            return JSONResponse({"error": exc.error, "field": exc.field}, status_code=exc.status)

    @r.get("/catalog")
    async def get_catalog(request: Request) -> JSONResponse:
        return await call(request, ist.catalog)

    @r.get("/{iid}")
    async def get_one(iid: str, request: Request) -> JSONResponse:
        return await call(request, svc.view, iid)

    @r.put("/{iid}")
    async def put_one(iid: str, request: Request) -> JSONResponse:
        return await call(request, svc.save, iid, body=True)

    @r.delete("/{iid}")
    async def delete_one(iid: str, request: Request) -> JSONResponse:
        return await call(request, svc.delete, iid)

    @r.post("/{iid}/test")
    async def test_one(iid: str, request: Request) -> JSONResponse:
        return await call(request, svc.test, iid)

    @r.post("/{iid}/start")
    async def start_one(iid: str, request: Request) -> JSONResponse:
        return await call(request, svc.start, iid, body=True)

    @r.post("/{iid}/stop")
    async def stop_one(iid: str, request: Request) -> JSONResponse:
        return await call(request, svc.stop, iid)

    return r

