"""Live-vendor harness (marker `live`): real Splunk / Elasticsearch / rsyslog / LocalStack in Docker.

Opt-in only: `-m live` (or RUN_LIVE=1). The fast suite deselects these tests (backend/tests/conftest.py).
One command per vendor, documented in reports/integrations/live.md:
    .venv/Scripts/python -m pytest backend/tests/live -m live -k splunk -v
Each test module brings its vendor up (tools/live/livectl.py: gate -> compose up -> ready), seeds it with its own
code (tools/live/*_seed.py, stdlib HTTP, never the product client), runs the checks, then `docker compose down -v`
(AL_LIVE_KEEP=1 keeps it for debugging). A gate failure (no Docker, too little RAM / disk, another vendor up) SKIPS
with the reason. Results: data/live/results/{vendors,checks}.jsonl (git-ignored), summarised in live.md.

ApiEnv drives the product exactly like the Integrations page: PUT /api/integrations/{id} -> POST test -> POST start
(a real `python -m attacklens.connect` child) -> spool -> POST stop. Config copy, overlay, DPAPI secrets, spool,
state, status and logs all live under tmp_path; live mode itself is not started (this tests connectors, not the
pipeline).
"""

from __future__ import annotations

import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest
import yaml

from attacklens import config

REPO = Path(__file__).resolve().parents[3]
LIVE_TOOLS = REPO / "tools" / "live"
if str(LIVE_TOOLS) not in sys.path:
    sys.path.insert(0, str(LIVE_TOOLS))

import livectl  # noqa: E402


# ----------------------------------------------------------------------------- results recording
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> None:
    if item.get_closest_marker("live") is None:
        return
    if call.when == "call" or (call.when == "setup" and call.excinfo is not None):
        outcome = "passed" if call.excinfo is None else (
            "skipped" if call.excinfo.errisinstance(pytest.skip.Exception) else "failed")
        msg = "" if call.excinfo is None else str(call.excinfo.value).splitlines()[0][:300] if \
            str(call.excinfo.value) else call.excinfo.typename
        livectl.record("checks", {"test": item.nodeid.split("::", 1)[-1], "module": item.module.__name__,
                                  "phase": call.when, "outcome": outcome, "duration_s": round(call.duration, 1),
                                  "message": msg, "props": dict(item.user_properties)})


@contextmanager
def vendor(name: str, prepare: Callable[[livectl.Stack], None] | None = None) -> Iterator[livectl.Stack]:
    """Gate -> up -> yield -> down -v. Skips the module with the gate reason."""
    st = livectl.Stack(name)
    why = livectl.gate(name)
    if why:
        livectl.record("vendors", {"vendor": name, "status": "skipped", "reason": "; ".join(why)})
        pytest.skip(f"live {name}: " + "; ".join(why))
    if prepare:
        prepare(st)
    try:
        st.up()
    except Exception as exc:
        logs = st.logs()
        st.down()
        livectl.record("vendors", {"vendor": name, "status": "failed_to_start", "error": str(exc)[:500]})
        raise RuntimeError(f"{name} did not start: {exc}\n--- logs ---\n{logs[-3000:]}") from None
    import threading

    stop, tripped = threading.Event(), {}

    def watchdog() -> None:
        """Free RAM below WATCHDOG_RAM_GB while the vendor runs -> docker compose down -v at once (recorded)."""
        low = 0.0
        while not stop.wait(5):
            ram = livectl.free_ram_gb()
            low = ram if not low else min(low, ram)
            st.info["min_free_ram_gb"] = round(low, 2)
            if ram < livectl.WATCHDOG_RAM_GB:
                tripped["at_gb"] = round(ram, 2)
                livectl.record("vendors", {"vendor": name, "status": "stopped_low_ram", "free_ram_gb": round(ram, 2)})
                st.down()
                return

    wd = threading.Thread(target=watchdog, name=f"ram-watchdog-{name}", daemon=True)
    wd.start()
    try:
        yield st
    finally:
        stop.set()
        wd.join(10)
        livectl.record("vendors", {"vendor": name, "status": "stopped_low_ram" if tripped else "ran",
                                   **st.info, **st.timings, **({"low_ram_gb": tripped["at_gb"]} if tripped else {})})
        if os.environ.get("AL_LIVE_KEEP") != "1" and not tripped:
            st.down()
        if tripped:
            pytest.fail(f"live {name}: free RAM fell to {tripped['at_gb']} GB (< {livectl.WATCHDOG_RAM_GB} GB); "
                        f"container stopped with down -v")


# ----------------------------------------------------------------------------- product API env
class _FakeLive:
    """Stands in for the `attacklens.live` child the API would start: terminable, never touches data/."""
    pid = 0

    def __init__(self) -> None:
        self.rc: int | None = None

    def poll(self) -> int | None:
        return self.rc

    def terminate(self) -> None:
        self.rc = 0

    def wait(self, timeout: float | None = None) -> int:
        self.rc = 0
        return 0

    def kill(self) -> None:
        self.rc = -9


class ApiEnv:
    """A tmp config dir + the product API (TestClient) wired like the Integrations page."""

    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.tmp = tmp
        monkeypatch.setenv("ATTACKLENS_INTEGRATIONS_DIR", str(tmp / "integ"))
        monkeypatch.setenv("ATTACKLENS_SECRETS_DIR", str(tmp / "secrets"))
        monkeypatch.delenv("ATTACKLENS_INTEGRATIONS_OVERLAY", raising=False)
        (tmp / "out").mkdir(exist_ok=True)
        monkeypatch.setenv("ATTACKLENS_OUT", str(tmp / "out"))
        ic = yaml.safe_load((config.CONFIG_DIR / "integrations.yaml").read_text(encoding="utf-8"))
        ic["spool"].update(events_dir=str(tmp / "spool" / "events"), alerts_dir=str(tmp / "spool" / "alerts"),
                           state_dir=str(tmp / "conn_state"), status_file=str(tmp / "conn_state" / "status.json"))
        for name, c in ic["connectors"].items():
            if not isinstance(c, dict):
                continue
            for k in list(c):  # a developer's SPLUNK_TOKEN / ELASTIC_* env vars must never win over the UI secret
                if k.endswith("_env") and c[k]:
                    c[k] = f"AL_LIVE_UNSET_{name}_{k}".upper()
            c["enabled"] = False
            if name != "syslog":
                c["poll_interval_s"] = 2
        for name, s in ic["sinks"].items():
            for k in list(s):
                if k.endswith("_env") and s[k]:
                    s[k] = f"AL_LIVE_UNSET_{name}_{k}".upper()
            s["enabled"] = False
        self.ic = ic
        self._client: Any = None
        self.svc: Any = None
        self.secrets: list[str] = []

    @property
    def cfg_dir(self) -> Path:
        return self.tmp / "config"

    def client(self) -> Any:
        """Write the config copy (with self.ic) and start the API. Call after editing self.ic."""
        import shutil

        from fastapi.testclient import TestClient

        from attacklens import api, api_integrations

        d = self.cfg_dir
        if d.exists():
            shutil.rmtree(d)
        shutil.copytree(config.CONFIG_DIR, d, ignore=shutil.ignore_patterns("sigma"))
        (d / "integrations.yaml").write_text(yaml.safe_dump(self.ic, sort_keys=False), encoding="utf-8")
        lv = yaml.safe_load((d / "live.yaml").read_text(encoding="utf-8")) or {}
        lv.update(state_dir=str(self.tmp / "live_state"), watch_dir=str(self.tmp / "live_watch"),
                  out_dir=str(self.tmp / "live_out"), threads=2)
        (d / "live.yaml").write_text(yaml.safe_dump(lv, sort_keys=False), encoding="utf-8")

        def spawn(cmd: list[str], child_env: dict[str, str], log_path: Path) -> Any:
            if "attacklens.live" in cmd:
                return _FakeLive()
            return api_integrations._spawn(cmd, child_env, log_path)

        self.svc = api_integrations.IntegrationsService(config_dir=d, spawn=spawn)
        state = api.AppState()
        state.integrations = self.svc  # type: ignore[attr-defined]
        self._client = TestClient(api.create_app(state))
        self._client.__enter__()
        return self._client

    def close(self) -> None:
        if self.svc is not None:
            self.svc.stop_all()
        if self._client is not None:
            self._client.__exit__(None, None, None)

    # -- API calls (assert the HTTP status, return JSON)
    def put(self, iid: str, settings: dict[str, Any], secrets: dict[str, Any] | None = None) -> dict[str, Any]:
        self.secrets += [v for v in (secrets or {}).values() if isinstance(v, str)]
        r = self._client.put(f"/api/integrations/{iid}", json={"settings": settings, "secrets": secrets or {}})
        assert r.status_code == 200, r.text
        return r.json()

    def test(self, iid: str) -> dict[str, Any]:
        r = self._client.post(f"/api/integrations/{iid}/test")
        assert r.status_code == 200, r.text
        return r.json()

    def start(self, iid: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        r = self._client.post(f"/api/integrations/{iid}/start", json=body or {})
        assert r.status_code == 200, r.text
        return r.json()

    def stop(self, iid: str) -> dict[str, Any]:
        r = self._client.post(f"/api/integrations/{iid}/stop")
        assert r.status_code == 200, r.text
        return r.json()

    def cfg(self) -> dict[str, Any]:
        """Effective config the children see (yaml + UI overlay + secret chains)."""
        return self.svc.cfg(full=True)

    # -- outputs
    def spool_lines(self, source: str) -> list[str]:
        root = self.tmp / "spool" / "events" / source
        if not root.exists():
            return []
        return [ln for p in sorted(root.rglob("*")) if p.is_file() and not p.name.startswith(".")
                for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]

    def status(self, key: str) -> dict[str, Any]:
        p = self.tmp / "conn_state" / "status.json"
        d = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        return ((d.get("connectors") or {}).get(key)) or {}

    def log(self, source: str) -> str:
        p = self.tmp / "integ" / "logs" / f"connect_{source}.log"
        return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""

    def leaked(self) -> list[str]:
        """Secret values found anywhere in tmp output (spool, state, status, logs, overlay)."""
        text = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in self.tmp.rglob("*")
                         if p.is_file() and p.suffix not in (".bin", ".dat", ".pem", ".crt")
                         and "secrets" not in p.parts and p.stat().st_size < 50_000_000)
        return [s[:4] + "..." for s in set(self.secrets) if len(s) >= 8 and s in text]


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ApiEnv]:
    e = ApiEnv(tmp_path, monkeypatch)
    try:
        yield e
    finally:
        e.close()


def wait_until(fn: Callable[[], bool], timeout: float, what: str, diag: Callable[[], str] = lambda: "") -> float:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if fn():
            return round(time.monotonic() - t0, 1)
        time.sleep(0.5)
    raise AssertionError(f"timed out after {timeout:g}s waiting for {what}\n{diag()[-3000:]}")


def json_docs(lines: list[str]) -> list[dict[str, Any]]:
    out = []
    for ln in lines:
        try:
            d = json.loads(ln)
        except ValueError:
            continue
        if isinstance(d, dict):
            out.append(d)
    return out


def assert_accounted(status: dict[str, Any], expect_written: int) -> dict[str, int]:
    """Connector totals: pulled = written + skipped + failed, nothing failed, written == expected."""
    tot = {k: int((status.get("totals") or {}).get(k, 0)) for k in ("pulled", "written", "skipped", "failed")}
    assert tot["pulled"] == tot["written"] + tot["skipped"] + tot["failed"], tot
    assert tot["failed"] == 0, (tot, status.get("last_error"))
    assert tot["written"] == expect_written, tot
    return tot
