"""Live mode (B-5) review-finding regressions: transactional cycles, future-timestamp guard, p99 watermark,
lookback pruning with open-incident protection, CSV header on appended chunks, RunManager validation and
start lock. Stages are stubbed (these tests are about transaction / accounting logic, not detection)."""

from __future__ import annotations

import json
import shutil
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from attacklens import config, live
from attacklens.config import REPO_ROOT

BASE = datetime(2026, 10, 24, 0, 0, 0, tzinfo=timezone.utc)


def ecs_line(i: int, ts: datetime | str | None = None) -> bytes:
    t = ts if isinstance(ts, str) else (ts or BASE + timedelta(seconds=i)).isoformat(timespec="milliseconds")
    t = t.replace("+00:00", "Z")
    ev = {"@timestamp": t, "event": {"action": "process_created", "kind": "event"},
          "host": {"name": f"WS-FIN-{i % 7:03d}", "ip": ["10.10.3.10"]}, "user": {"name": "pmehta"},
          "process": {"name": "notepad.exe", "command_line": f"notepad.exe doc{i}.txt"}}
    return json.dumps(ev, separators=(",", ":")).encode()


@pytest.fixture
def make(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """make() -> (engine factory, watch dir, out dir). Stages stubbed to a no-op unless a test patches them."""
    monkeypatch.setattr(live.LiveEngine, "_run_stages", lambda self, con: {})
    cfg = config.load_config()
    cfg["live"] = {**cfg["live"], "state_dir": str(tmp_path / "state")}
    watch, out = tmp_path / "w", tmp_path / "out"
    watch.mkdir()
    return (lambda: live.LiveEngine(watch, out, cfg)), watch, out


def window_rows(e: live.LiveEngine) -> int:
    con = e._con()
    try:
        return live.lw.count_rows(con, e.window)
    finally:
        con.close()


def acc(out: Path) -> dict[str, dict]:
    return {a["source_type"]: a for a in json.loads((out / "ingest_accounting.json").read_text(encoding="utf-8"))}


# ---------------------------------------------------------------- 1: a failed cycle is rolled back, retried once
def test_failed_cycle_rolls_back_then_retry_and_restart(make, monkeypatch: pytest.MonkeyPatch) -> None:
    mk, watch, out = make
    (watch / "a.jsonl").write_bytes(b"\n".join(ecs_line(i) for i in range(5)) + b"\n")
    e = mk()

    def boom(self, con):
        raise RuntimeError("boom in detect")

    monkeypatch.setattr(live.LiveEngine, "_run_stages", boom)
    with pytest.raises(RuntimeError, match="boom"):
        e.cycle()
    assert (window_rows(e), e.batch_no) == (0, 0)                        # 1a: nothing committed
    assert e.status["last_error"] == "RuntimeError: boom in detect"
    monkeypatch.setattr(live.LiveEngine, "_run_stages", lambda self, con: {})
    assert e.cycle() is True
    assert window_rows(e) == 5 and acc(out)["ecs_json"]["rows_in"] == 5   # 1b: the 5 lines exactly once
    e2 = mk()                                                            # 1c: restart on the committed state
    assert e2.cycle() is False and window_rows(e2) == 5 and e2.batch_no == 1


# ---------------------------------------------------------------- 2: future timestamps, watermark, pruning
def test_future_dated_line_rejected_watermark_kept(make) -> None:
    mk, watch, out = make
    (watch / "a.jsonl").write_bytes(b"\n".join(ecs_line(i) for i in range(1000)) + b"\n")
    e = mk()
    e.cycle()
    wm0, rows0 = e.watermark, window_rows(e)
    with open(watch / "a.jsonl", "ab") as f:
        f.write(ecs_line(1000, "2099-01-01T00:00:00.000Z") + b"\n")
    e.cycle()
    assert (e.watermark, window_rows(e)) == (wm0, rows0)                 # 2a
    a = acc(out)["ecs_json"]
    assert (a["rows_in"], a["rows_ok"], a["dropped"]) == (1001, 1000, 1)  # 2b
    assert a["drop_reasons"] == {live.FUTURE_REASON: 1}
    assert live.FUTURE_REASON.startswith("future_timestamp")


def test_one_far_ahead_line_does_not_set_watermark_p99(make) -> None:
    mk, watch, _ = make
    lines = [ecs_line(i) for i in range(999)] + [ecs_line(999, BASE + timedelta(days=6))]
    (watch / "a.jsonl").write_bytes(b"\n".join(lines) + b"\n")
    e = mk()
    e.cycle()
    assert live._iso_ms(e.watermark) < "2026-10-25"                      # 2c: p99, not max (max = 10-30)
    assert e.watermark < int((BASE + timedelta(days=6)).timestamp() * 1000)


def _prune_case(make, open_incident: bool) -> tuple[live.LiveEngine, dict]:
    mk, watch, out = make
    (watch / "a.jsonl").write_bytes(b"\n".join(ecs_line(i) for i in range(200)) + b"\n")  # all 2026-10-24
    e = mk()
    e.cycle()
    if open_incident:  # a published incident that started 10-24 and is still open at the new cutoff
        idx = [{"id": "inc-00000001", "risk": 50, "first_ts": "2026-10-24T00:01:00Z", "last_ts": "2026-10-27T23:00:00Z",
                "merged_alert_count": 1, "episode_count": 2, "tactics": [], "hosts": [], "entry_summary": "x"}]
        (out / "incidents_index.json").write_text(json.dumps(idx), encoding="utf-8")
    # 6 agreeing rows (>= watermark_jump_min_rows) 4.5 d later (> 72 h lookback) move the watermark
    with open(watch / "a.jsonl", "ab") as f:
        f.write(b"".join(ecs_line(k, f"2026-10-28T12:0{k}:00.000Z") + b"\n" for k in range(6)))
    e.cycle()
    return e, acc(out)["ecs_json"]


def test_jump_params_from_config() -> None:
    lc = config.load_config()["live"]
    assert int(lc["watermark_jump_min_rows"]) == 5 and int(lc["watermark_jump_ms"]) == 3_600_000
    assert int(lc["watermark_min_rows"]) == 100 and int(lc["watermark_sample"]) == 1000


def test_lookback_prunes_and_counts(make) -> None:
    e, a = _prune_case(make, open_incident=False)
    assert a["pruned_outside_window"] == 200 and e.status["window_rows"] == 6   # 2d
    assert a["rows_in"] == 206 and a["rows_ok"] == 206
    assert live._iso_ms(e.watermark) >= "2026-10-28T12:00"


def test_open_incident_keeps_its_early_days(make) -> None:
    e, a = _prune_case(make, open_incident=True)
    assert a.get("pruned_outside_window", 0) == 0 and e.status["window_rows"] == 206   # 4


def test_lone_far_ahead_row_does_not_move_watermark(make) -> None:
    mk, watch, out = make
    (watch / "a.jsonl").write_bytes(b"\n".join(ecs_line(i) for i in range(50)) + b"\n")
    e = mk()
    e.cycle()
    wm0 = e.watermark
    with open(watch / "a.jsonl", "ab") as f:
        f.write(ecs_line(50, "2026-10-29T00:00:00.000Z") + b"\n")
    e.cycle()
    assert e.watermark == wm0 and window_rows(e) == 51                    # ingested, but no jump on one row
    jump_rows = int(config.load_config()["live"]["watermark_jump_min_rows"])
    with open(watch / "a.jsonl", "ab") as f:
        f.write(b"".join(ecs_line(60 + k, f"2026-10-29T00:0{k}:00.000Z") + b"\n" for k in range(jump_rows + 1)))
    e.cycle()
    assert live._iso_ms(e.watermark) >= "2026-10-29"
    assert e.watermark >= wm0                                            # never decreases


# ---------------------------------------------------------------- 3: CSV appended in chunks keeps its header
def test_csv_second_chunk_keeps_header(make) -> None:
    mk, watch, out = make
    hdr = "timestamp,device,src,sport,dst,dport,bytes_sent,disposition"
    row = lambda i: f"2026-10-24T01:{i:02d}:00Z,fw-01,10.0.0.{i},5000{i % 10},10.0.1.5,445,{100 + i},allowed"  # noqa: E731
    (watch / "fw.csv").write_text(hdr + "\n" + "\n".join(row(i) for i in range(3)) + "\n", encoding="utf-8",
                                  newline="\n")
    e = mk()
    e.cycle()
    with open(watch / "fw.csv", "a", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(row(i) for i in range(3, 8)) + "\n")
    e.cycle()
    a = acc(out)
    assert "unrecognized" not in a
    assert (a["firewall_csv"]["rows_in"], a["firewall_csv"]["rows_ok"]) == (8, 8) and window_rows(e) == 8


# ---------------------------------------------------------------- 12/13: RunManager
class _FakeProc:
    pid = 4242
    returncode = None

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0


@pytest.fixture
def run_manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from attacklens import api_runs
    monkeypatch.setattr(api_runs.subprocess, "Popen", lambda *a, **k: _FakeProc())
    name = f"_test_live_{uuid.uuid4().hex[:8]}"
    raw = REPO_ROOT / "data" / "raw" / name   # confined(): raw_dir must be an existing dir under data/raw
    raw.mkdir(parents=True)
    try:
        yield api_runs.RunManager(runs_dir=tmp_path / "runs"), name
    finally:
        shutil.rmtree(raw, ignore_errors=True)


@pytest.mark.parametrize("bad,token", [("data/out/x/g1", "x/g1"), ("data/out", None),
                                       ("data/out/../../etc", "etc"), ("data/out/a b", "a b")])
def test_run_out_dir_rejected_without_echo(run_manager, bad: str, token: str | None) -> None:
    rm, name = run_manager
    with pytest.raises(ValueError) as ei:
        rm.start(f"data/raw/{name}", bad, None)
    if token:  # the submitted path never appears in the error (only the allowed root does)
        assert token not in str(ei.value)
    assert rm.jobs() == []


def test_concurrent_starts_exactly_one_run(run_manager) -> None:
    rm, name = run_manager
    results: list[str] = []

    def go() -> None:
        try:
            results.append("ok:" + rm.start(f"data/raw/{name}", f"data/out/{name}", None).run_id)
        except RuntimeError as exc:
            results.append(f"409:{exc}")

    ts = [threading.Thread(target=go) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    started = [r for r in results if r.startswith("ok:")]
    assert len(started) == 1 and len(results) == 4
    assert sum(r.startswith("409:") for r in results) == 3
    assert [j.run_id for j in rm.jobs()] == [started[0][3:]]


# ================================================================ BB-serve live fixes (review findings 1-8)
def _append(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "ab") as f:
        f.write(data)


def _lines(rng, ts: str | None = None) -> bytes:
    return b"".join(ecs_line(i, ts) + b"\n" for i in rng)


def _acc_in(out: Path) -> int:
    return sum(a["rows_in"] for a in json.loads((out / "ingest_accounting.json").read_text(encoding="utf-8")))


@pytest.fixture
def make_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """make_cfg(**live_overrides) -> (factory, watch, out) with stubbed stages."""
    monkeypatch.setattr(live.LiveEngine, "_run_stages", lambda self, con: {})

    def _mk(**lcfg):
        cfg = config.load_config()
        cfg["live"] = {**cfg["live"], "state_dir": str(tmp_path / "state"), **lcfg}
        watch, out = tmp_path / "w", tmp_path / "out"
        watch.mkdir(exist_ok=True)
        return (lambda: live.LiveEngine(watch, out, cfg)), watch, out

    return _mk


def test_compaction_keeps_rows_and_restart_reads_nothing(make_cfg) -> None:
    mk, watch, out = make_cfg(compact_max_files=3)
    e = mk()
    for b in range(6):
        _append(watch / f"f{b}.jsonl", _lines(range(b * 5, b * 5 + 5)))
        assert e.cycle() is True
    assert window_rows(e) == 30 and _acc_in(out) == 30 and e.status["last_error"] is None
    assert sum(1 for _ in e.window.rglob("*.parquet")) <= 3          # compaction ran
    e2 = mk()
    assert e2.cycle() is False and window_rows(e2) == 30


def test_post_commit_compaction_failure_recorded_not_reingested(make_cfg, monkeypatch: pytest.MonkeyPatch) -> None:
    from attacklens import live_window
    mk, watch, out = make_cfg()
    e = mk()

    def broken(*a, **k):
        raise OSError("disk full (simulated)")

    monkeypatch.setattr(live_window, "compact", broken)
    _append(watch / "a.jsonl", _lines(range(5)))
    assert e.cycle() is True                                           # the batch itself committed
    st = json.loads((out / "live_status.json").read_text(encoding="utf-8"))
    assert "compaction: OSError" in str(st["last_error"])
    monkeypatch.undo()
    monkeypatch.setattr(live.LiveEngine, "_run_stages", lambda self, con: {})
    e2 = mk()
    assert e2.cycle() is False and window_rows(e2) == 5 and _acc_in(out) == 5


def test_colliding_flattened_names_all_ingested(make_cfg) -> None:
    mk, watch, out = make_cfg()
    _append(watch / "a" / "b__c.jsonl", _lines(range(3)))
    _append(watch / "a__b" / "c.jsonl", _lines(range(10, 13)))
    e = mk()
    e.cycle()
    assert window_rows(e) == 6 and _acc_in(out) == 6


def test_rename_rotation_not_ingested_twice(make_cfg) -> None:
    import os
    mk, watch, _ = make_cfg()
    e = mk()
    _append(watch / "app.jsonl", _lines(range(5)))
    e.cycle()
    os.replace(watch / "app.jsonl", watch / "app.jsonl.1")
    _append(watch / "app.jsonl.1", _lines(range(5, 6)))               # the writer flushes one more line
    _append(watch / "app.jsonl", _lines(range(20, 23)))
    e.cycle()
    assert window_rows(e) == 9 and e.tailer.counters["renames"] == 1


def test_replaced_file_reread_and_partial_line_counted(make_cfg) -> None:
    import os
    mk, watch, _ = make_cfg()
    e = mk()
    p = watch / "x.jsonl"
    _append(p, _lines(range(3)))
    e.cycle()
    partial = ecs_line(3)[:40]
    _append(p, partial)                                                # observed, incomplete
    e.cycle()
    tmp = watch / ".x.new"
    tmp.write_bytes(_lines(range(30, 38)))
    os.replace(tmp, p)                                                 # replaced by a bigger file
    e.cycle()
    assert window_rows(e) == 11
    assert e.tailer.counters["rotations"] == 1 and e.tailer.counters["skipped_bytes"] == 40


def test_replaced_csv_gets_its_new_header(make_cfg) -> None:
    import os
    mk, watch, out = make_cfg()
    e = mk()
    c = watch / "fw.csv"
    c.write_text("timestamp,device,src,dst,dport\n2026-10-24T01:00:00Z,fw,10.0.0.1,10.0.0.2,445\n", encoding="utf-8",
                 newline="\n")
    e.cycle()
    tmp = watch / ".fw.new"
    tmp.write_text("dport,src,dst,timestamp,device,bytes_sent\n" + "".join(
        f"22,10.0.1.{i},10.0.0.9,2026-10-24T02:0{i}:00Z,fw2,{i}\n" for i in range(4)), encoding="utf-8", newline="\n")
    os.replace(tmp, c)
    e.cycle()
    a = acc(out)
    assert "unrecognized" not in a and (a["firewall_csv"]["rows_in"], a["firewall_csv"]["rows_ok"]) == (5, 5)
    assert window_rows(e) == 5


def test_frozen_incident_survives_failed_post_publish_cycle(make_cfg, monkeypatch: pytest.MonkeyPatch) -> None:
    mk, watch, out = make_cfg()

    def publish_nothing(self, con):  # what publish does when the window no longer holds the incident
        out.mkdir(parents=True, exist_ok=True)
        (out / "incidents_index.json").write_text("[]", encoding="utf-8")
        return {}

    monkeypatch.setattr(live.LiveEngine, "_run_stages", publish_nothing)
    e = mk()
    _append(watch / "a.jsonl", _lines(range(20)))                      # all 2026-10-24 00:00
    e.cycle()
    base = json.loads((REPO_ROOT / "frontend" / "src" / "mock" / "incident.json").read_text(encoding="utf-8"))
    inc = {**base, "id": "inc-0000aaaa", "first_ts": "2026-10-24T00:00:00Z", "last_ts": "2026-10-24T00:30:00Z"}
    row = {"id": inc["id"], "risk": inc["risk"], "first_ts": inc["first_ts"], "last_ts": inc["last_ts"],
           "merged_alert_count": 1, "episode_count": 1, "tactics": [], "hosts": [], "entry_summary": "x"}
    (out / "incidents").mkdir(exist_ok=True)
    (out / "incidents" / "inc-0000aaaa.json").write_text(json.dumps(inc), encoding="utf-8")
    (out / "incidents_index.json").write_text(json.dumps([row]), encoding="utf-8")
    _append(watch / "a.jsonl", _lines(range(30, 36), "2026-10-28T12:00:00.000Z"))
    e.cycle()
    ids = lambda: {r["id"] for r in json.loads((out / "incidents_index.json").read_text(encoding="utf-8"))}  # noqa: E731
    assert "inc-0000aaaa" in e.frozen and "inc-0000aaaa" in ids()
    assert "inc-0000aaaa" in json.loads((e.state / "live_state.json").read_text(encoding="utf-8"))["frozen"]

    def publish_then_raise(self, con):
        publish_nothing(self, con)
        raise RuntimeError("after publish")

    monkeypatch.setattr(live.LiveEngine, "_run_stages", publish_then_raise)
    _append(watch / "a.jsonl", _lines(range(40, 41), "2026-10-28T12:05:00.000Z"))
    with pytest.raises(RuntimeError):
        e.cycle()
    assert "inc-0000aaaa" in json.loads((e.state / "live_state.json").read_text(encoding="utf-8"))["frozen"]
    monkeypatch.setattr(live.LiveEngine, "_run_stages", publish_nothing)
    e.cycle()
    assert "inc-0000aaaa" in ids()                                     # restored after the next success


def test_batch_run_refused_on_live_out_dirs(run_manager) -> None:
    from datetime import datetime, timezone
    rm, name = run_manager
    lv = REPO_ROOT / "data" / "out" / f"{name}_lv"
    lv.mkdir(parents=True)
    try:
        (lv / "live_status.json").write_text(json.dumps({"enabled": True, "updated_at": datetime.now(
            timezone.utc).isoformat()}), encoding="utf-8")
        for target in ("data/out/live", f"data/out/{name}_lv"):
            with pytest.raises(ValueError):
                rm.start(f"data/raw/{name}", target, None)
        assert rm.jobs() == []
    finally:
        shutil.rmtree(lv, ignore_errors=True)


def test_env_out_dir_then_finished_run_pins_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    from attacklens import api
    a, b = tmp_path / "env_out", tmp_path / "run_out"
    for d in (a, b):
        d.mkdir()
        (d / "incidents_index.json").write_text("[]", encoding="utf-8")
    monkeypatch.setenv("ATTACKLENS_OUT", str(a))
    app = api.create_app()
    with TestClient(app) as cl:
        h0 = cl.get("/api/health").json()
        app.state.al.store.reload(b)                                   # what AppState.refresh does for a finished run
        h1 = cl.get("/api/health").json()
    assert h0["out_dir_source"] == "env" and Path(h0["out_dir"]).name == "env_out"
    assert h1["out_dir_source"] == "api_run" and Path(h1["out_dir"]).name == "run_out"
