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
    with open(watch / "a.jsonl", "ab") as f:
        f.write(ecs_line(0, "2026-10-28T12:00:00.000Z") + b"\n")           # +4.5 d > 72 h lookback
    e.cycle()
    return e, acc(out)["ecs_json"]


def test_lookback_prunes_and_counts(make) -> None:
    e, a = _prune_case(make, open_incident=False)
    assert a["pruned_outside_window"] == 200 and e.status["window_rows"] == 1   # 2d
    assert a["rows_in"] == 201 and a["rows_ok"] == 201


def test_open_incident_keeps_its_early_days(make) -> None:
    e, a = _prune_case(make, open_incident=True)
    assert a.get("pruned_outside_window", 0) == 0 and e.status["window_rows"] == 201   # 4


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
