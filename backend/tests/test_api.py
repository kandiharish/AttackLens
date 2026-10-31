"""API tests (TESTING.md §4.6) over a tmp out dir built from frontend/src/mock/incident.json."""

from __future__ import annotations

import copy
import json
import statistics
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from attacklens.models import Incident, IncidentSummary, dump

MOCK = Path(__file__).resolve().parents[2] / "frontend" / "src" / "mock" / "incident.json"
XSS_USER = "<img src=x onerror=alert(1)>"


def _incident(base: dict, inc_id: str, risk: int, user: str | None = None) -> dict:
    d = copy.deepcopy(base)
    d["id"], d["risk"] = inc_id, risk
    if user is not None:
        d["backbone"][0]["user"] = user
    return dump(Incident.model_validate(d))


def _summary(inc: dict) -> dict:
    hosts = sorted({s["host"] for s in inc["backbone"] if s.get("host")})
    return dump(IncidentSummary(id=inc["id"], risk=inc["risk"], first_ts=inc["first_ts"], last_ts=inc["last_ts"],
                                merged_alert_count=inc["merged_alert_count"], episode_count=inc["episode_count"],
                                tactics=inc["tactics"], hosts=hosts, entry_summary=inc["entry_point"]["summary"]))


@pytest.fixture
def out_dir(tmp_path: Path) -> Path:
    base = json.loads(MOCK.read_text(encoding="utf-8"))
    incs = [_incident(base, base["id"], base["risk"]), _incident(base, "inc-0000aaaa", 40),
            _incident(base, "inc-0000bbbb", 95, user=XSS_USER)]
    out = tmp_path / "out"
    (out / "incidents").mkdir(parents=True)
    for inc in incs:
        (out / "incidents" / f"{inc['id']}.json").write_text(json.dumps(inc), encoding="utf-8")
    index = [_summary(i) for i in (incs[1], incs[0], incs[2])]  # deliberately unsorted on disk
    (out / "incidents_index.json").write_text(json.dumps(index), encoding="utf-8")
    return out


@pytest.fixture
def client(out_dir: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ATTACKLENS_OUT", str(out_dir))
    from attacklens import api
    with TestClient(api.create_app()) as c:
        yield c


def _is_json(r) -> bool:
    return r.headers["content-type"].startswith("application/json") and not r.text.lstrip().startswith("<")


def test_health(client) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200 and _is_json(r)
    body = r.json()
    assert (body["status"], body["incidents"], body["off_contract"]) == ("ok", 3, 0)


def test_incidents_sorted_by_risk_desc(client) -> None:
    r = client.get("/api/incidents")
    assert r.status_code == 200 and _is_json(r)
    assert [(x["id"], x["risk"]) for x in r.json()] == [("inc-0000bbbb", 95), ("inc-3f2a9c1e", 86),
                                                        ("inc-0000aaaa", 40)]


def test_incident_detail_is_the_published_json(client, out_dir: Path) -> None:
    r = client.get("/api/incidents/inc-3f2a9c1e")
    assert r.status_code == 200 and _is_json(r)
    assert r.json() == json.loads((out_dir / "incidents" / "inc-3f2a9c1e.json").read_text(encoding="utf-8"))
    Incident.model_validate(r.json())


def test_incident_path_has_only_path_keys(client, out_dir: Path) -> None:
    full = json.loads((out_dir / "incidents" / "inc-3f2a9c1e.json").read_text(encoding="utf-8"))
    r = client.get("/api/incidents/inc-3f2a9c1e/path")
    assert r.status_code == 200 and _is_json(r)
    assert r.json() == {k: full[k] for k in ("id", "backbone", "branches", "edges")}


@pytest.mark.parametrize("path", [
    "/api/incidents/inc-deadbeef", "/api/incidents/inc-deadbeef/path",          # well-formed, unknown
    "/api/incidents/INC-3F2A9C1E", "/api/incidents/inc-3f2a9c1e0",               # bad ids
    "/api/incidents/..%2F..%2Fincidents_index", "/api/incidents/%3Cscript%3E/path",
    "/api/no-such-endpoint",
])
def test_unknown_or_bad_id_is_json_404(client, path: str) -> None:
    r = client.get(path)
    assert r.status_code == 404 and _is_json(r), (path, r.status_code, r.text[:200])


def test_metrics_nulls_when_files_absent(client) -> None:
    r = client.get("/api/metrics")
    assert r.status_code == 200 and _is_json(r)
    assert r.json() == {"run_metrics": None, "eval_scorecard": None, "ingest_accounting": None}


def test_metrics_served_from_files(out_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    card = {"detection_pct": 95.24, "labels_pct": None, "rebuilt_pct": 100.0, "false_alarms_strict_pct": 9.5,
            "false_alarms_lenient_pct": 0.0, "singleton_recall_pct": None, "per_attack": [], "per_rule_alerts": None,
            "unmatched_incidents": [], "targets": {}}
    (out_dir / "eval_scorecard.json").write_text(json.dumps(card), encoding="utf-8")
    monkeypatch.setenv("ATTACKLENS_OUT", str(out_dir))
    from attacklens import api
    with TestClient(api.create_app()) as c:
        body = c.get("/api/metrics").json()
    assert body["eval_scorecard"] == card and body["run_metrics"] is None


def test_xss_username_served_as_json_text(client) -> None:
    r = client.get("/api/incidents/inc-0000bbbb")
    assert _is_json(r) and r.json()["backbone"][0]["user"] == XSS_USER


def test_no_api_endpoint_returns_html(client) -> None:
    for path in ("/api/health", "/api/incidents", "/api/incidents/inc-3f2a9c1e",
                 "/api/incidents/inc-3f2a9c1e/path", "/api/metrics", "/api/live/status", "/api/runs/000000000000",
                 "/api/incidents/inc-zzzz"):
        r = client.get(path)
        assert _is_json(r), (path, r.headers["content-type"])


def test_path_p95_under_50ms(client) -> None:
    client.get("/api/incidents/inc-3f2a9c1e/path")  # warm-up
    times = []
    for _ in range(200):
        t = time.perf_counter()
        r = client.get("/api/incidents/inc-3f2a9c1e/path")
        times.append((time.perf_counter() - t) * 1000)
        assert r.status_code == 200
    p95 = statistics.quantiles(times, n=100)[94]
    assert p95 < 50.0, f"path p95 {p95:.1f} ms"
