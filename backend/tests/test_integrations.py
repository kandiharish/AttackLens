"""SIEM integrations (DEVELOPMENT.md §8b): connectors pull from tools/mock_siem.py into the spool, sinks push incidents
back, API pivots / status. Exact counts on the 9-event fixture of test_mock_siem.py (4-way timestamp tie at t0+2s,
one labelled event, one malformed line) and the hand-written 7-alert fixture (tools/mock_siem_alerts.json).

Backend contract under test (backend/attacklens/connectors, sinks, pivots.py, integrations_status.py):
  connectors.get(source, cfg, mode, since_ms).cycle() -> {pulled, written, skipped, failed, skipped_reasons,
      failed_reasons, ok, error}; pulled == written + skipped + failed; spool <spool.events_dir|alerts_dir>/<source>/
  sinks.publish_all([(incident, index_row)], cfg) -> {sink: {sent, failed, skipped_unchanged, error}}; never raises
  GET /api/incidents/{id}/pivots -> {steps: [{queries: [{siem, language, query, dsl?, earliest, latest}]}]}
All plain tests except the spool-overwrite bug (xfail strict: flips red when fixed).
"""

from __future__ import annotations

import copy
import importlib
import json
import logging
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml

from attacklens import config

from .conftest import query, run_ingest
from .test_mock_siem import ALL, REPO, T0, ecs, write_fixture

sys.path.insert(0, str(REPO / "tools"))
import mock_siem as ms  # noqa: E402
import mock_siem_query as mq  # noqa: E402

SPOOL_OVERWRITE_BUG = pytest.mark.xfail(strict=True, reason=(
    "BUG connectors/base.py: spool tag is second-resolution + pid and SpoolWriter.commit() uses os.replace, so a "
    "second cycle in the same second overwrites the first cycle's committed file (events lost, uncounted). "
    "strict: remove this marker when fixed"))
SECRET = "SENTINEL-SECRET-7f3a9c"   # env token value that must never appear in output, files, logs or API
MARK = re.compile(r"evt-\d{4}")
SOURCES = ("elastic", "splunk", "sentinel")
ENV = {"elastic": "AL_TEST_ELASTIC_KEY", "splunk": "AL_TEST_SPLUNK_TOKEN", "sentinel": "AL_TEST_SENTINEL_TOKEN",
       "hec": "AL_TEST_HEC_TOKEN"}
MOCK_INCIDENT = REPO / "frontend" / "src" / "mock" / "incident.json"
# Vendor MITRE of the hand-written alert fixture (parents), mapped to v20; A7 has none -> dropped no_technique
ALERT_TECHNIQUES = {"T1110", "T1078", "T1021", "T1059", "T1048", "T1070"}
SEARCH_PATH = {"elastic": r"/_search$", "splunk": r"/services/search/jobs/export$",
               "sentinel": r"/v1/workspaces/[^/]+/query$"}
PAGE = {"elastic": 2, "splunk": 2, "sentinel": 5}   # sentinel pages by timestamp: page must hold the 4-way tie


def since_ms() -> int:
    """Covers the fixture day whatever today's date is."""
    return T0 - 86_400_000


def since_arg() -> str:
    return f"{int((time.time() * 1000 - since_ms()) // 86_400_000) + 1}d"


def conn_mod():
    return importlib.import_module("attacklens.connectors")


def sinks_mod():
    return importlib.import_module("attacklens.sinks")


# ----------------------------------------------------------------------------- config + spool helpers
def integrations(url: str, tmp: Path, *, page_size: int | None = None, timeout_s: float = 1.0,
                 use_pit: bool = True, sinks: dict[str, Any] | None = None) -> dict[str, Any]:
    """config/integrations.yaml with the three pull connectors enabled against the mock, spool/state under tmp."""
    ic = yaml.safe_load((config.CONFIG_DIR / "integrations.yaml").read_text(encoding="utf-8"))
    ic["spool"].update(events_dir=str(tmp / "spool" / "events"), alerts_dir=str(tmp / "spool" / "alerts"),
                       state_dir=str(tmp / "conn_state"), status_file=str(tmp / "conn_state" / "status.json"))
    c = ic["connectors"]
    for src in SOURCES:
        c[src].update(enabled=True, base_url=url, timeout_s=timeout_s, verify_tls=False,
                      page_size=page_size or PAGE[src])
    c["elastic"].update(api_key_env=ENV["elastic"], user_env=None, password_env=None, use_pit=use_pit)
    c["splunk"]["token_env"] = ENV["splunk"]
    c["sentinel"].update(token_env=ENV["sentinel"], workspace_id_env=None, workspace_id="ws1")
    c["sentinel"]["events"].update(
        query="AttackLensEvents_CL | where TimeGenerated >= datetime({since}) | order by TimeGenerated asc "
              "| take {page_size}", id_field="_ItemId", raw_field="RawData")
    for name, s in ic["sinks"].items():
        s["enabled"] = False
    for name, s in (sinks or {}).items():
        ic["sinks"][name] = {**ic["sinks"][name], **s, "enabled": True}
    return ic


def cfg_dir(tmp: Path, integ: dict[str, Any]) -> Path:
    """Copy of config/ with this integrations.yaml and a tmp live state dir."""
    d = tmp / "config"
    if d.exists():
        shutil.rmtree(d)
    # sigma/ is skipped: deep rule paths exceed Windows MAX_PATH under tmp, and these tests don't need it
    shutil.copytree(config.CONFIG_DIR, d, ignore=shutil.ignore_patterns("sigma"))
    (d / "integrations.yaml").write_text(yaml.safe_dump(integ, sort_keys=False), encoding="utf-8")
    lv = yaml.safe_load((d / "live.yaml").read_text(encoding="utf-8")) or {}
    lv.update(state_dir=str(tmp / "live_state"), threads=2)
    (d / "live.yaml").write_text(yaml.safe_dump(lv, sort_keys=False), encoding="utf-8")
    return d


def load(tmp: Path, integ: dict[str, Any]) -> dict[str, Any]:
    return config.load_config(cfg_dir(tmp, integ))


def pull(source: str, mode: str, cfg: dict[str, Any]) -> dict[str, Any]:
    st = importlib.import_module("attacklens.connect").pull(source, mode, cfg, since=since_ms())
    assert (st["fetched"], st["dropped"], st["errors"], st["last_error"]) ==         (st["pulled"], st["skipped"] + st["failed"], 0 if st["ok"] else 1, st["error"]), st   # flat view agrees
    return st


def spool_lines(tmp: Path, kind: str = "events") -> list[str]:
    """Committed spool lines (dot-prefixed .part files are in-flight, not data)."""
    root = tmp / "spool" / kind
    if not root.exists():
        return []
    return [ln for p in sorted(root.rglob("*")) if p.is_file() and not p.name.startswith(".")
            for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


def markers(lines: list[str]) -> list[str]:
    out = []
    for ln in lines:
        found = set(MARK.findall(ln))
        assert len(found) == 1, f"spool line must carry exactly one fixture event: {ln[:200]}"
        out += list(found)
    return out


def tree_text(*roots: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="replace") for r in roots if r.exists()
                     for p in r.rglob("*") if p.is_file())


def assert_accounted(st: dict[str, Any], lines: list[str], pulled: int) -> None:
    assert st["pulled"] == pulled, st
    assert st["pulled"] == st["written"] + st["skipped"] + st["failed"], st      # rows in == out + counted drops
    assert st["skipped"] == sum(st["skipped_reasons"].values()), st
    assert st["failed"] == sum(st["failed_reasons"].values()), st
    assert st["written"] == len(lines), st


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    for v in ENV.values():
        monkeypatch.setenv(v, SECRET)
    return dict(ENV)


@pytest.fixture
def siem(tmp_path: Path):
    """Mock with every vendor's auth ON (token = SECRET) over the 9-event fixture."""
    with ms.MockSIEM(write_fixture(tmp_path / "raw"), elastic_api_key=SECRET, splunk_token=SECRET,
                     hec_token=SECRET, sentinel_token=SECRET, workspace_id="ws1") as m:
        yield m


CASES = [("elastic", True), ("elastic", False), ("splunk", True), ("sentinel", True)]
IDS = ["elastic-pit", "elastic-nopit", "splunk", "sentinel"]


# ============================================================================= connectors: events mode
@pytest.mark.parametrize("source,pit", CASES, ids=IDS)
def test_pull_events_complete_and_label_free(source, pit, siem, env, tmp_path, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    cfg = load(tmp_path, integrations(siem.url, tmp_path, use_pit=pit))
    st = pull(source, "events", cfg)
    lines = spool_lines(tmp_path)
    assert st["ok"] is True and st["error"] is None, st
    assert sorted(markers(lines)) == sorted(ALL)                              # every event exactly once
    assert_accounted(st, lines, st["pulled"])
    assert st["failed"] == 0 and set(st["skipped_reasons"]) <= {"duplicate"}  # re-reads only at the page boundary
    text = "\n".join(lines)
    assert '"threat"' not in text and "labels_extra" not in text and '"labels"' not in text
    assert SECRET not in tree_text(tmp_path / "spool", tmp_path / "conn_state") + caplog.text + json.dumps(st)


@pytest.mark.parametrize("source,pit", CASES, ids=IDS)
def test_pull_twice_without_new_data_writes_nothing(source, pit, siem, env, tmp_path) -> None:
    cfg = load(tmp_path, integrations(siem.url, tmp_path, use_pit=pit))
    pull(source, "events", cfg)
    st = pull(source, "events", cfg)
    assert st["ok"] and st["written"] == 0 and st["failed"] == 0
    assert sorted(markers(spool_lines(tmp_path))) == sorted(ALL)


@pytest.mark.parametrize("source,pit", [c for c in CASES if c[0] != "splunk"],
                         ids=[i for i in IDS if i != "splunk"])
def test_failure_inside_tie_group_is_counted_and_retry_is_exact(source, pit, siem, env, tmp_path) -> None:
    """Request 1 succeeds (it ends inside the 4-way tie at t0+2s), request 2 gets a 500. The cycle must fail loudly
    and leave no partial spool; the retry must neither skip nor duplicate a tie member."""
    page = 3 if source == "elastic" else 5                                  # sentinel: page must hold the tie
    cfg = load(tmp_path, integrations(siem.url, tmp_path, use_pit=pit, page_size=page))
    real_take, n = siem.take_fault, {"search": 0}

    def fail_second_search(method: str, path: str):
        if re.search(SEARCH_PATH[source], path):
            n["search"] += 1
            if n["search"] == 2:
                return ms.Fault(".", 500, 1, 0.0, None, None)
        return real_take(method, path)

    siem.take_fault = fail_second_search  # type: ignore[method-assign]
    st1 = pull(source, "events", cfg)
    siem.take_fault = real_take  # type: ignore[method-assign]
    assert n["search"] >= 2, "fixture did not page; tie test is vacuous"
    assert st1["ok"] is False and "500" in str(st1["error"]) and st1["written"] == 0, st1
    assert spool_lines(tmp_path) == []                                       # part files aborted
    st2 = pull(source, "events", load(tmp_path, integrations(siem.url, tmp_path, use_pit=pit, page_size=page)))
    assert st2["ok"] is True
    assert sorted(markers(spool_lines(tmp_path))) == sorted(ALL)


def _distinct_cycle_tags(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every cycle its own spool tag, so tie tests don't depend on the clock (the same-second overwrite is
    pinned separately by test_two_cycles_in_one_second_never_overwrite_spool)."""
    import itertools
    import types
    from attacklens.connectors import base
    n = itertools.count()
    frozen = types.SimpleNamespace(**{k: getattr(time, k) for k in dir(time) if not k.startswith("_")})
    frozen.strftime = lambda fmt, t=None: f"20261031T{next(n):06d}"
    monkeypatch.setattr(base, "time", frozen)


@pytest.mark.parametrize("source,pit", CASES, ids=IDS)
def test_resume_picks_up_late_tie_and_newer_events(source, pit, siem, env, tmp_path, monkeypatch) -> None:
    """After a complete pull (checkpoint = t0+5s), E9 arrives with the SAME timestamp and E10 later: both pulled once,
    nothing earlier re-written."""
    _distinct_cycle_tags(monkeypatch)
    cfg = load(tmp_path, integrations(siem.url, tmp_path, use_pit=pit))
    pull(source, "events", cfg)
    (tmp_path / "raw" / "c.jsonl").write_text(
        json.dumps(ecs(9, T0 + 5_000)) + "\n" + json.dumps(ecs(10, T0 + 6_000)) + "\n", encoding="utf-8")
    st = pull(source, "events", cfg)
    assert st["ok"] and st["written"] == 2, st
    assert sorted(markers(spool_lines(tmp_path))) == sorted(ALL | {"evt-0009", "evt-0010"})


@pytest.mark.parametrize("source", SOURCES)
def test_auth_failure_is_counted(source, siem, monkeypatch, tmp_path, caplog) -> None:
    wrong = "wrong-" + SECRET[::-1]
    for v in ENV.values():
        monkeypatch.setenv(v, wrong)
    cfg = load(tmp_path, integrations(siem.url, tmp_path))
    st = pull(source, "events", cfg)
    assert st["ok"] is False and re.search(r"\b40[13]\b", str(st["error"])), st
    assert st["written"] == 0 and spool_lines(tmp_path) == []
    status = json.loads((tmp_path / "conn_state" / "status.json").read_text(encoding="utf-8"))
    assert status["connectors"][f"{source}_events"]["last_error"]                 # visible to the API
    assert wrong not in caplog.text + json.dumps(st) + tree_text(tmp_path / "conn_state")


@pytest.mark.parametrize("source", SOURCES)
def test_http_500_is_counted_and_cli_exits_nonzero(source, siem, env, tmp_path) -> None:
    d = cfg_dir(tmp_path, integrations(siem.url, tmp_path))
    siem.fail(SEARCH_PATH[source], status=500, times=None)
    st = pull(source, "events", config.load_config(d))
    assert st["ok"] is False and "500" in str(st["error"]) and st["written"] == 0
    rc = importlib.import_module("attacklens.connect").main(
        ["--source", source, "--mode", "events", "--since", since_arg(), "--once", "--config", str(d)])
    assert rc == 1


@pytest.mark.parametrize("source", SOURCES)
def test_timeout_is_counted_and_bounded(source, siem, env, tmp_path) -> None:
    cfg = load(tmp_path, integrations(siem.url, tmp_path, timeout_s=0.3))
    siem.fail(SEARCH_PATH[source], status=None, times=None, delay_s=3.0)
    t = time.monotonic()
    st = pull(source, "events", cfg)
    assert time.monotonic() - t < 2.5                                       # gave up on its own timeout
    assert st["ok"] is False and st["written"] == 0
    assert re.search(r"time(d)? ?out", str(st["error"]), re.I), st


@pytest.mark.parametrize("source", SOURCES)
def test_missing_env_var_disables_connector_without_crash(source, siem, monkeypatch, tmp_path, caplog) -> None:
    """DEVELOPMENT.md §8b: 'A missing env var disables that connector and logs its name. It does not crash.'"""
    caplog.set_level(logging.INFO)
    for v in ENV.values():
        monkeypatch.delenv(v, raising=False)
    cfg = load(tmp_path, integrations(siem.url, tmp_path))
    st = pull(source, "events", cfg)
    assert st["written"] == 0 and spool_lines(tmp_path) == []
    assert ENV[source] in caplog.text + json.dumps(st)                       # names the env var
    assert not [r for r in siem.requests if re.search(SEARCH_PATH[source], r["path"])]  # never sent unauthenticated


def test_sentinel_row_cap_is_not_silent_loss(tmp_path, env) -> None:
    with ms.MockSIEM(write_fixture(tmp_path / "raw"), sentinel_token=SECRET, workspace_id="ws1",
                     sentinel_max_rows=3) as m:
        cfg = load(tmp_path, integrations(m.url, tmp_path, page_size=100))
        st = pull("sentinel", "events", cfg)
        got = markers(spool_lines(tmp_path))
        assert len(got) == len(set(got))
        assert (st["ok"] and set(got) == ALL) or (not st["ok"] and "PartialError" in str(st["error"])), st


def test_cli_once_writes_spool(siem, env, tmp_path) -> None:
    d = cfg_dir(tmp_path, integrations(siem.url, tmp_path))
    rc = importlib.import_module("attacklens.connect").main(
        ["--source", "elastic", "--mode", "events", "--since", since_arg(), "--once", "--config", str(d)])
    assert rc == 0 and sorted(markers(spool_lines(tmp_path))) == sorted(ALL)
    files = [p for p in (tmp_path / "spool").rglob("*") if p.is_file()]
    assert files and all(p.is_relative_to(tmp_path / "spool" / "events" / "elastic") for p in files)


# ============================================================================= connectors: alerts mode
def _detect_with_siem_alerts(tmp: Path, cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """Stage 0-2 on the fixture events with alert-input mode ON (what run.py --siem-alerts does)."""
    from attacklens import db, detect, ingest, lookups, profile
    from attacklens.context import RunContext
    con = db.connect(memory_limit="1GB", threads=2, temp_directory=tmp / "spill")
    ctx = RunContext(set_name="siem", raw_dir=tmp / "raw", parquet_dir=tmp / "pq", out_dir=tmp / "out", con=con,
                     cfg=cfg, siem_alerts=True)
    try:
        profile.run(ctx)
        ingest.run(ctx)
        db.register_events(con, ctx.events_glob)
        lookups.run(ctx)
        detect.run(ctx)
        return query(ctx, f"SELECT rule_id, technique_id, sub_technique_id, tactic, host FROM read_parquet("
                          f"'{(ctx.work_dir / 'raw_alerts.parquet').as_posix()}')")
    finally:
        con.close()


@pytest.mark.parametrize("source", SOURCES)
def test_alerts_mode_reaches_raw_alerts_with_siem_prefix(source, siem, env, tmp_path) -> None:
    cfg = load(tmp_path, integrations(siem.url, tmp_path, page_size=100))
    st = pull(source, "alerts", cfg)
    lines = spool_lines(tmp_path, "alerts")
    assert_accounted(st, lines, 7)
    assert st["written"] == 6 and any("no_technique" in r for r in st["failed_reasons"]), st   # A7: counted drop
    assert spool_lines(tmp_path, "events") == []                             # alerts never enter the event spool
    rows = [r for r in _detect_with_siem_alerts(tmp_path, cfg) if r["rule_id"].startswith("siem:")]
    assert len(rows) == 6 and all(r["rule_id"].startswith(f"siem:{source}:") for r in rows)
    assert {r["technique_id"] for r in rows} == ALERT_TECHNIQUES
    assert {r["tactic"] for r in rows if r["technique_id"] == "T1070"} == {"Defense Impairment"}  # v20 mapping
    assert {r["tactic"] for r in rows if r["technique_id"] == "T1110"} == {"Credential Access"}
    assert {r["host"] for r in rows} == {"srv-dc-01", "ws-fin-010", "srv-file-01"}            # normalized


# ============================================================================= eval honesty: file ingest
def _alert_shaped_raw(raw: Path) -> int:
    """ECS events (one office->powershell that a real rule must catch) + SIEM-alert-shaped docs in the raw set."""
    raw.mkdir(parents=True)
    ev = [ecs(n, T0 + n * 1000) for n in range(5)]
    ps = ecs(5, T0 + 5000)
    ps["process"] = {"name": "powershell.exe", "command_line": "powershell.exe -nop -enc ZQBjAGgAbwA= marker evt-0005",
                     "parent": {"name": "winword.exe"}, "executable": r"C:\Windows\System32\powershell.exe"}
    ev.append(ps)
    alerts = [mq.elastic_alert(a) for a in ms.load_alerts()]
    notables = [mq.splunk_notable(a, int(datetime.fromisoformat(a["ts"].replace("Z", "+00:00")).timestamp() * 1000))
                for a in ms.load_alerts()]
    (raw / "part-0.jsonl").write_text("\n".join(json.dumps(e) for e in ev) + "\n", encoding="utf-8")
    (raw / "siem_alerts.jsonl").write_text("\n".join(json.dumps(a) for a in alerts + notables) + "\n",
                                           encoding="utf-8")
    return len(ev) + len(alerts) + len(notables)


@pytest.fixture(scope="module")
def file_run(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    tmp = tmp_path_factory.mktemp("honesty")
    n = _alert_shaped_raw(tmp / "raw")
    from attacklens import detect, lookups
    ctx = run_ingest(tmp / "raw", tmp)
    try:
        lookups.run(ctx)
        detect.run(ctx)
        rows = query(ctx, f"SELECT rule_id FROM read_parquet('{(ctx.work_dir / 'raw_alerts.parquet').as_posix()}')")
        acc = json.loads((ctx.out_dir / "ingest_accounting.json").read_text(encoding="utf-8"))
    finally:
        ctx.con.close()
    return {"tmp": tmp, "lines": n, "rule_ids": [r["rule_id"] for r in rows], "acc": acc}


def test_file_ingest_never_produces_siem_rows(file_run) -> None:
    """Scored runs are raw-events-only (§8b eval-honesty): vendor alerts sitting in a raw folder are just lines."""
    assert sum(a["rows_in"] for a in file_run["acc"]) == file_run["lines"] == 20   # nothing silently skipped
    assert "office_spawns_script" in file_run["rule_ids"]                          # detection did run
    assert [r for r in file_run["rule_ids"] if r.startswith("siem:")] == []


def test_scored_run_refuses_siem_alerts_and_records_inputs(file_run, tmp_path) -> None:
    from attacklens.run import run_pipeline
    gt = tmp_path / "attacks.json"
    gt.write_text(json.dumps({"attack_version": "v20", "attacks": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="raw-events-only"):
        run_pipeline(file_run["tmp"] / "raw", tmp_path / "o1", parquet=tmp_path / "p1", ground_truth=gt,
                     siem_alerts=True)
    m = run_pipeline(file_run["tmp"] / "raw", tmp_path / "o2", parquet=tmp_path / "p2")
    assert m["input_mode"] == "file" and m["inputs"]["siem_alerts"] is False
    assert json.loads((tmp_path / "o2" / "run_metrics.json").read_text(encoding="utf-8"))["inputs"][
        "siem_alerts"] is False


def test_siem_alert_union_refuses_a_ground_truth_run(tmp_path) -> None:
    from attacklens import db, siem_alerts
    con = db.connect(memory_limit="1GB", threads=1, temp_directory=tmp_path / "spill")
    try:
        with pytest.raises(siem_alerts.EvalGuardError):
            siem_alerts.union_into(con, config.load_config(), True)
    finally:
        con.close()


# ============================================================================= sinks
def _items(n: int = 2) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    base = json.loads(MOCK_INCIDENT.read_text(encoding="utf-8"))
    out = []
    for i in range(n):
        d = copy.deepcopy(base)
        d["id"], d["risk"] = f"inc-0000{i:04x}", 90 - i
        out.append((d, {"id": d["id"], "risk": d["risk"], "first_ts": d["first_ts"], "last_ts": d["last_ts"],
                        "tactics": d["tactics"], "hosts": ["srv-dc-01", "ws-fin-010"],
                        "entry_summary": d["entry_point"]["summary"], "merged_alert_count": d["merged_alert_count"],
                        "episode_count": d["episode_count"]}))
    return out


def _sinks(m: ms.MockSIEM, webhook_url: str | None = None, only_changed: bool = True) -> dict[str, Any]:
    oc = {"only_changed": only_changed, "verify_tls": False, "timeout_s": 1}
    return {"splunk_hec": {"base_url": m.url, "token_env": ENV["hec"], **oc},
            "elastic_bulk": {"base_url": m.url, "index": "attacklens-incidents", "api_key_env": ENV["elastic"],
                             "user_env": None, "password_env": None, **oc},
            "webhook": {"url": webhook_url or f"{m.url}/webhook/soar", **oc},
            "syslog_cef": {"host": m.syslog_addr[0], "port": m.syslog_addr[1], "protocol": "udp",
                           "only_changed": only_changed}}


@pytest.fixture
def sink_mock():
    with ms.MockSIEM(None, elastic_api_key=SECRET, hec_token=SECRET, syslog_udp=True) as m:
        yield m


def _wait(cond, timeout: float = 2.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def _ids(obj: Any) -> set[str]:
    return set(re.findall(r"inc-[0-9a-f]{8}", obj if isinstance(obj, str) else json.dumps(obj)))


def test_sinks_deliver_every_incident(sink_mock, env, tmp_path) -> None:
    m, items = sink_mock, _items(2)
    ids = {inc["id"] for inc, _ in items}
    cfg = load(tmp_path, integrations(m.url, tmp_path, sinks=_sinks(m)))
    res = sinks_mod().publish_all(items, cfg)
    assert set(res) == {"splunk_hec", "elastic_bulk", "webhook", "syslog_cef"}
    assert all(r["error"] is None and r["sent"] == 2 and r["failed"] == 0 for r in res.values()), res
    assert _ids([e["event"] for e in m.received["hec"]]) == ids
    assert set(m.indexed) == {("attacklens-incidents", i) for i in ids}        # Elastic doc id == incident id
    assert {m.indexed[("attacklens-incidents", i)]["id"] for i in ids} == ids
    assert [w["body"]["id"] for w in m.received["webhook"]] == [inc["id"] for inc, _ in items]
    assert _wait(lambda: ids <= _ids("\n".join(m.received["syslog"])))
    assert all("CEF:0|" in ln for ln in m.received["syslog"])
    assert SECRET not in json.dumps(m.snapshot()["received"]["webhook"]) + json.dumps(res)


def test_elastic_republish_is_idempotent(sink_mock, env, tmp_path) -> None:
    m, items = sink_mock, _items(2)
    cfg = load(tmp_path, integrations(m.url, tmp_path, sinks={"elastic_bulk": _sinks(m, only_changed=False)[
        "elastic_bulk"]}))
    sinks_mod().publish_all(items, cfg)
    sinks_mod().publish_all(items, cfg)
    assert len(m.received["bulk"]) == 4                                     # really re-sent ...
    assert len(m.indexed) == 2 and set(m.versions.values()) == {2}          # ... and overwritten, never duplicated


def test_only_changed_skips_unchanged_and_resends_changed(sink_mock, env, tmp_path) -> None:
    m, items = sink_mock, _items(2)
    cfg = load(tmp_path, integrations(m.url, tmp_path, sinks={"elastic_bulk": _sinks(m)["elastic_bulk"]}))
    sinks_mod().publish_all(items, cfg)
    r = sinks_mod().publish_all(items, cfg)["elastic_bulk"]
    assert (r["sent"], r["skipped_unchanged"]) == (0, 2)
    items[1][0]["risk"] = 99
    r = sinks_mod().publish_all(items, cfg)["elastic_bulk"]
    assert (r["sent"], r["skipped_unchanged"]) == (1, 1)
    assert m.indexed[("attacklens-incidents", "inc-00000001")]["risk"] == 99


def test_dead_sink_does_not_fail_the_others(sink_mock, env, tmp_path) -> None:
    m = sink_mock
    dead = f"http://127.0.0.1:{ms.free_port()}/webhook"                     # nothing listens there
    m.fail(r"^/services/collector", status=503, times=None)
    cfg = load(tmp_path, integrations(m.url, tmp_path, sinks=_sinks(m, webhook_url=dead)))
    res = sinks_mod().publish_all(_items(1), cfg)                           # must not raise
    assert res["webhook"]["failed"] == 1 and res["webhook"]["error"]
    assert res["splunk_hec"]["failed"] == 1 and "503" in res["splunk_hec"]["error"]
    assert res["elastic_bulk"]["sent"] == 1 and len(m.indexed) == 1
    again = sinks_mod().publish_all(_items(1), cfg)                         # failed sends are retried next time
    assert again["webhook"]["skipped_unchanged"] == 0 and again["elastic_bulk"]["skipped_unchanged"] == 1


# ============================================================================= API
@pytest.fixture
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """API over one incident (the mock incident, plus an injection host on the last step); integrations config
    swappable through state['icfg']."""
    from fastapi.testclient import TestClient
    from attacklens import api
    from attacklens.models import Incident, dump
    inc, row = _items(1)[0]
    inc["backbone"][-1]["host"] = 'ws-fin-010" OR host="*'
    inc = dump(Incident.model_validate(inc))
    out = tmp_path / "out"
    (out / "incidents").mkdir(parents=True)
    (out / "incidents" / f"{inc['id']}.json").write_text(json.dumps(inc), encoding="utf-8")
    (out / "incidents_index.json").write_text(json.dumps([row]), encoding="utf-8")
    monkeypatch.setenv("ATTACKLENS_OUT", str(out))
    state = {"icfg": integrations("http://127.0.0.1:9", tmp_path)}
    monkeypatch.setattr(api.AppState, "integrations_cfg",
                        lambda self: {"integrations": state["icfg"], "live": {}})
    with TestClient(api.create_app()) as c:
        yield c, inc, state


def _epochs(q: str) -> list[int]:
    return [int(x) * 1000 for x in re.findall(r"(?:earliest|latest)=(\d{10})\b", q)]


def _isos(q: str) -> list[int]:
    return [int(datetime.fromisoformat(x.replace("Z", "+00:00")).timestamp() * 1000)
            for x in re.findall(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", q)]


def test_pivots_have_host_and_exact_time_range_per_step(api_client) -> None:
    c, inc, _ = api_client
    r = c.get(f"/api/incidents/{inc['id']}/pivots")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["id"] == inc["id"] and set(body["siems"]) == {"splunk", "sentinel", "elastic"}
    win = body["window_ms"]
    assert win == 900_000
    for step, piv in zip(inc["backbone"], body["steps"]):
        ts = int(datetime.fromisoformat(step["ts"].replace("Z", "+00:00")).timestamp() * 1000)
        qs = piv["queries"]
        q = qs if isinstance(qs, dict) else {x["siem"]: x for x in qs}
        assert set(q) == {"splunk", "sentinel", "elastic"}, piv
        spl, kql, dsl = q["splunk"]["query"], q["sentinel"]["query"], json.dumps(q["elastic"]["dsl"])
        assert sorted(_epochs(spl)) == [ts - win, ts + win], spl
        assert sorted(_isos(kql)) == [ts - win, ts + win], kql
        assert sorted(_isos(dsl)) == [ts - win, ts + win], dsl
        if '"' not in step["host"]:
            assert f'host="{step["host"]}"' in spl and f'Computer =~ "{step["host"]}"' in kql
            assert f'"host.name": "{step["host"]}"' in dsl
    lq = body["steps"][len(inc["backbone"]) - 1]["queries"]
    last = {k: v["query"] for k, v in lq.items()} if isinstance(lq, dict) else {x["siem"]: x["query"] for x in lq}
    assert '" OR host="*' not in last["splunk"] and '" OR host="*' not in last["sentinel"]   # escaped, no breakout
    assert c.get("/api/incidents/inc-deadbeef/pivots").status_code == 404


def test_integrations_status_never_contains_a_secret(api_client, siem, monkeypatch, tmp_path) -> None:
    c, _, state = api_client
    for v in ENV.values():
        monkeypatch.setenv(v, SECRET)
    ic = integrations(siem.url, tmp_path)
    ic["connectors"]["splunk"]["base_url"] = siem.url.replace("http://", f"http://admin:{SECRET}@")
    ic["sinks"]["webhook"] = {**ic["sinks"]["webhook"], "enabled": True,
                              "url": f"{siem.url}/webhook?token={SECRET}"}
    state["icfg"] = ic
    siem.fail(SEARCH_PATH["elastic"], status=401, times=None, body={"error": f"bad key {SECRET}"})
    cfg = config.load_config(cfg_dir(tmp_path, ic))
    for src in SOURCES:                                                     # leave errors in the status file
        pull(src, "events", cfg)
    sinks_mod().publish_all(_items(1), cfg)
    r = c.get("/api/integrations/status")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    leaks = [m.start() for m in re.finditer(re.escape(SECRET), r.text)]
    assert not leaks, [r.text[max(0, i - 120):i + 40] for i in leaks]
    body = r.json()
    assert body["connectors"]["elastic"]["auth_env_set"] == {"api_key_env": True}
    assert body["connectors"]["elastic"]["modes"]["events"]["last_error"]   # the failure is reported ...
    assert SECRET not in tree_text(tmp_path / "conn_state")                 # ... and never stored with the secret


# ============================================================================= end to end
def test_end_to_end_mock_elastic_to_webhook(tmp_path, env) -> None:
    """mock Elastic (S1 events) -> connect --once -> live --once -> incident -> mock webhook. A dead HEC sink in the
    same run must not stop delivery or fail the cycle."""
    import scenarios as sc
    from attacklens import live
    start = int(datetime(2026, 10, 24, tzinfo=timezone.utc).timestamp() * 1000)
    events, _ = sc.scenario_events(start, ["S1"])
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "s1.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    with ms.MockSIEM(raw, elastic_api_key=SECRET) as m:
        m.fail(r"^/services/collector", status=503, times=None)
        sinks = {"webhook": {"url": f"{m.url}/webhook", "verify_tls": False, "timeout_s": 2},
                 "splunk_hec": {"base_url": m.url, "token_env": ENV["hec"], "timeout_s": 1}}
        ic = integrations(m.url, tmp_path, page_size=500, sinks=sinks)
        ic["spool"]["events_dir"] = str(tmp_path / "watch" / "siem")
        d = cfg_dir(tmp_path, ic)
        first = min(int(datetime.fromisoformat(e["@timestamp"].replace("Z", "+00:00")).timestamp() * 1000)
                    for e in events)                                          # S1 history starts days earlier
        since = f"{int((time.time() * 1000 - first) // 86_400_000) + 1}d"
        assert importlib.import_module("attacklens.connect").main(
            ["--source", "elastic", "--mode", "events", "--since", since, "--once", "--config", str(d)]) == 0
        n = sum(1 for p in (tmp_path / "watch").rglob("*") if p.is_file()
                for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip())
        assert n == len(events)
        out = tmp_path / "out"
        assert live.main(["--watch", str(tmp_path / "watch"), "--out", str(out), "--once", "--config", str(d)]) == 0
        st = json.loads((out / "live_status.json").read_text(encoding="utf-8"))
        assert st["last_error"] is None and st["rows"] == len(events)
        index = json.loads((out / "incidents_index.json").read_text(encoding="utf-8"))
        assert index, "live produced no incident from S1"
        assert {r["id"] for r in index} <= _ids([w["body"] for w in m.received["webhook"]])
        assert "srv-dc-01" in json.dumps([w["body"] for w in m.received["webhook"]]).lower()


# ============================================================================= regressions (bugs found here)
@pytest.mark.parametrize("source", SOURCES)
def test_two_cycles_in_one_second_never_overwrite_spool(source, siem, env, tmp_path, monkeypatch) -> None:
    """BUG (found 31 Oct): the spool file tag is second-resolution + pid and commit() uses os.replace, so a second
    cycle within the same second replaced the first cycle's committed file: 9 events lost, nothing counted."""
    from attacklens.connectors import base
    import types
    frozen = types.SimpleNamespace(**{k: getattr(time, k) for k in dir(time) if not k.startswith("_")})
    frozen.strftime = lambda fmt, t=None: "20261031T000000"                 # same second, same pid
    monkeypatch.setattr(base, "time", frozen)                                # only base.py sees the frozen clock
    cfg = load(tmp_path, integrations(siem.url, tmp_path))
    assert pull(source, "events", cfg)["written"] == 9
    (tmp_path / "raw" / "c.jsonl").write_text(json.dumps(ecs(10, T0 + 6_000)) + "\n", encoding="utf-8")
    assert pull(source, "events", cfg)["written"] == 1
    assert sorted(markers(spool_lines(tmp_path))) == sorted(ALL | {"evt-0010"})


def test_spool_guard_covers_every_default_integration_path() -> None:
    """conftest._repo_spool_untouched fails any test that writes here; it must watch the paths the product
    actually defaults to, or the guard is decorative."""
    from attacklens import integrations as ig
    from .conftest import GUARDED_DIRS
    cfg = config.load_config()
    for p in (ig.state_dir(cfg), ig.status_file(cfg), ig.alerts_spool_dir(cfg), ig.events_spool_dir(cfg)):
        assert any(p.resolve().is_relative_to(g) for g in GUARDED_DIRS), p


def test_integrations_helper_keeps_every_path_in_tmp(tmp_path) -> None:
    from attacklens import integrations as ig
    cfg = load(tmp_path, integrations("http://127.0.0.1:9", tmp_path))
    for p in (ig.state_dir(cfg), ig.status_file(cfg), ig.alerts_spool_dir(cfg), ig.events_spool_dir(cfg)):
        assert p.resolve().is_relative_to(tmp_path.resolve()), p
