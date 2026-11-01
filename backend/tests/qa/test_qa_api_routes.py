"""QA integration tests (track qa_api, part 2): the /api/integrations router as wired into api.create_app, and the
JSON catch-all for non-GET methods. Complements test_qa_api.py (core routes) and the owner's
backend/tests/test_api_integrations.py (router alone, on a bare FastAPI app).

What is proven here: the browser guards of the full app (TrustedHost, OriginGuard, the router's own origin check)
refuse a foreign Host / Origin before the integrations service is called at all, and the router accepts the same
origins OriginGuard accepts. A spy service records every call; settings / secrets dirs point into tmp_path.

Product bugs are strict xfails named test_qa_api_bug_*; the bug id is in the reason (reports/qa/qa_api.md).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from attacklens import integrations as ig
from attacklens import live, secrets_store
from attacklens.api import AppState, create_app
from attacklens.api_runs import RunManager
from attacklens.api_store import Store
from attacklens.api_upload import UploadConfig, UploadManager

IID = "webhook"
MUTATING = [("PUT", f"/api/integrations/{IID}"), ("DELETE", f"/api/integrations/{IID}"),
            ("POST", f"/api/integrations/{IID}/test"), ("POST", f"/api/integrations/{IID}/start"),
            ("POST", f"/api/integrations/{IID}/stop")]
READS = ["/api/integrations/catalog", f"/api/integrations/{IID}", "/api/integrations/status"]


class SpyService:
    """Stands in for IntegrationsService: records (method, iid) and answers {"ok": true, "op": <method>}."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def _rec(self, op: str, iid: str, *_: Any) -> dict[str, Any]:
        self.calls.append((op, iid))
        return {"ok": True, "op": op}

    def view(self, iid: str) -> dict[str, Any]:
        return self._rec("view", iid)

    def save(self, iid: str, body: Any) -> dict[str, Any]:
        return self._rec("save", iid)

    def delete(self, iid: str) -> dict[str, Any]:
        return self._rec("delete", iid)

    def test(self, iid: str) -> dict[str, Any]:
        return self._rec("test", iid)

    def start(self, iid: str, body: Any) -> dict[str, Any]:
        return self._rec("start", iid)

    def stop(self, iid: str) -> dict[str, Any]:
        return self._rec("stop", iid)

    def stop_all(self) -> None:
        pass


@pytest.fixture()
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(ig.SETTINGS_DIR_ENV, str(tmp_path / "integrations"))
    monkeypatch.setenv(secrets_store.DIR_ENV, str(tmp_path / "secrets"))
    monkeypatch.delenv(ig.OVERLAY_ENV, raising=False)
    monkeypatch.setattr(live, "status", lambda *a, **k: {"enabled": False})
    served = tmp_path / "data" / "out" / "served"
    (served / "incidents").mkdir(parents=True)
    (served / "incidents_index.json").write_text("[]", encoding="utf-8")
    monkeypatch.setenv("ATTACKLENS_OUT", str(served))
    cfg = UploadConfig(root=tmp_path / "data" / "raw" / "uploads", max_bytes=2**20, min_free_bytes=1,
                       chunk_bytes=64 * 1024, check_every=64 * 1024)
    uploads = UploadManager(cfg, repo_root=tmp_path, disk_free=lambda p: 10**15)
    runs = RunManager(runs_dir=tmp_path / "runs", raw_root=tmp_path / "data" / "raw",
                      out_root=tmp_path / "data" / "out", runner=["python", "-c", "pass"],
                      upload_root=cfg.root, parquet_root=tmp_path / "data" / "parquet")
    state = AppState(store=Store(check_interval_s=0.0), runs=runs, uploads=uploads)
    spy = SpyService()
    state.integrations = spy  # type: ignore[attr-defined]  # api.create_app passes getattr(state, "integrations")
    return {"state": state, "spy": spy, "tmp": tmp_path}


def client(env: dict, base_url: str = "http://testserver") -> TestClient:
    return TestClient(create_app(env["state"]), base_url=base_url, client=("127.0.0.1", 50000))


# ------------------------------------------------------------------------------------------------ guards
@pytest.mark.parametrize("method,path", MUTATING)
@pytest.mark.parametrize("origin", ["http://evil.example", "null", "http://localhost:5174"])
def test_integrations_foreign_origin_refused_before_service(app_env, method: str, path: str, origin: str) -> None:
    with client(app_env) as c:
        r = c.request(method, path, headers={"Origin": origin, "Content-Type": "application/json"}, content=b"{}")
    assert r.status_code == 403
    assert app_env["spy"].calls == []


@pytest.mark.parametrize("method,path", MUTATING + [("GET", p) for p in READS])
def test_integrations_foreign_host_400_before_service(app_env, method: str, path: str) -> None:
    with client(app_env) as c:
        r = c.request(method, path, headers={"Host": "evil.example"}, content=b"{}" if method != "GET" else None)
    assert r.status_code == 400
    assert app_env["spy"].calls == []


@pytest.mark.parametrize("method,path,op", [(m, p, op) for (m, p), op in
                                             zip(MUTATING, ["save", "delete", "test", "start", "stop"])])
def test_integrations_dev_origin_reaches_service_once(app_env, method: str, path: str, op: str) -> None:
    """Positive control for the 403 table: the Vite dev origin passes every guard and calls the service once."""
    with client(app_env) as c:
        r = c.request(method, path, headers={"Origin": "http://localhost:5173", "Content-Type": "application/json"},
                      content=b"{}")
    assert (r.status_code, r.json()) == (200, {"ok": True, "op": op})
    assert app_env["spy"].calls == [(op, IID)]


def test_integrations_status_not_shadowed_by_iid_route(app_env) -> None:
    with client(app_env) as c:
        r = c.get("/api/integrations/status")
    assert r.status_code == 200
    assert {"connectors", "sinks"} <= set(r.json())
    assert app_env["spy"].calls == []  # /{iid} view was never called with iid="status"


def test_integrations_body_cap_and_bad_json(app_env) -> None:
    with client(app_env) as c:
        big = c.put(f"/api/integrations/{IID}", content=b"{" + b" " * (64 * 1024) + b"}",
                    headers={"Content-Type": "application/json"})
        bad = c.put(f"/api/integrations/{IID}", content=b"{not json", headers={"Content-Type": "application/json"})
    assert (big.status_code, big.json()) == (413, {"error": "body larger than 65536 bytes", "field": None})
    assert (bad.status_code, bad.json()) == (422, {"error": "body is not valid JSON", "field": None})
    assert app_env["spy"].calls == []


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "POST"])
def test_unknown_api_path_any_method_is_json_404(app_env, method: str) -> None:
    with client(app_env) as c:
        r = c.request(method, "/api/qa-nope/x", content=b"{}")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/json")
    assert r.json() == {"detail": "not found"}


# ------------------------------------------------------------------------------------------------ QA-API-05
# The bundled UI is served by the API itself (SPA mount), so its origin is the API's own origin. OriginGuard accepts
# the API's own origin and pipeline.yaml api.allowed_origins; the integrations router has a fixed list
# (localhost / 127.0.0.1 / [::1] x ports 5173, 8000). Served on any other port (docker-compose ATTACKLENS_PORT=8001,
# `uvicorn --port 8001`) or under an allowed_origins name, every save / test / start / stop from the UI gets 403.
OWN_CASES = [("http://127.0.0.1:8031", "http://127.0.0.1:8031", None),
             ("http://localhost:8001", "http://localhost:8001", None),
             ("http://attacklens.lan:8000", "http://attacklens.lan:8000", "attacklens.lan")]


@pytest.mark.parametrize("base,origin,extra_host", OWN_CASES)
def test_own_origin_passes_origin_guard_control(app_env, base: str, origin: str, extra_host: str | None) -> None:
    """Control (passes): the same origin is accepted by OriginGuard on POST /api/reload."""
    st = app_env["state"]
    if extra_host:
        st.trusted_hosts.append(extra_host)
        st.allowed_origins.append(origin)
    with client(app_env, base) as c:
        r = c.post("/api/reload", headers={"Origin": origin})
    assert r.status_code == 200
    assert r.json()["incidents"] == 0


@pytest.mark.xfail(strict=True, reason="QA-API-05: integrations router origin allow-list ignores the API's own "
                                       "origin and pipeline.yaml api.allowed_origins (api_integrations.py:43, :336)")
@pytest.mark.parametrize("base,origin,extra_host", OWN_CASES)
def test_qa_api_bug_integrations_accept_own_origin(app_env, base: str, origin: str, extra_host: str | None) -> None:
    st = app_env["state"]
    if extra_host:
        st.trusted_hosts.append(extra_host)
        st.allowed_origins.append(origin)
    with client(app_env, base) as c:
        r = c.post(f"/api/integrations/{IID}/stop", headers={"Origin": origin})
    assert (r.status_code, r.json()) == (200, {"ok": True, "op": "stop"})
    assert app_env["spy"].calls == [("stop", IID)]

