"""QA unit / white-box tests for attacklens.telemetry (track qa_coverage_unit): run_metrics.json keys are binding
(DEVELOPMENT.md §15.6) and every number shown comes from them, so the edge branches are pinned exactly."""

from __future__ import annotations

import json
from pathlib import Path

import psutil
import pytest

from attacklens import telemetry
from attacklens.telemetry import Telemetry


class _Mem:
    def __init__(self, rss: int) -> None:
        self.rss = rss


class _Proc:
    """psutil.Process stand-in: rss in bytes, children, optional failure."""

    def __init__(self, rss: int, children: list | None = None, fail: type[Exception] | None = None) -> None:
        self._rss, self._children, self._fail = rss, children or [], fail

    def memory_info(self) -> _Mem:
        if self._fail:
            raise self._fail(pid=1) if self._fail is psutil.NoSuchProcess else self._fail()
        return _Mem(self._rss)

    def children(self, recursive: bool = False) -> list:
        return self._children


MB = 1024 * 1024


def test_rss_mb_sums_children_and_skips_vanished() -> None:
    kids = [_Proc(2 * MB), _Proc(5 * MB, fail=psutil.NoSuchProcess), _Proc(1 * MB, fail=psutil.AccessDenied)]
    assert telemetry.rss_mb(_Proc(10 * MB, kids)) == 12.0         # the two failing children are skipped
    assert telemetry.rss_mb(_Proc(3 * MB)) == 3.0                  # near miss: no children


def test_rss_mb_parent_gone_is_zero() -> None:
    assert telemetry.rss_mb(_Proc(10 * MB, fail=psutil.NoSuchProcess)) == 0.0
    assert telemetry.rss_mb(_Proc(10 * MB, fail=psutil.AccessDenied)) == 0.0


def _tel(monkeypatch: pytest.MonkeyPatch, values: list[float]) -> Telemetry:
    """Telemetry whose samples come from `values` in order (last value repeats)."""
    seq = list(values)
    monkeypatch.setattr(telemetry, "rss_mb", lambda proc: seq.pop(0) if len(seq) > 1 else seq[0])
    return Telemetry(interval_s=3600)   # the background thread never samples during the test


def test_stage_peak_is_per_stage_and_global_peak_is_max(monkeypatch: pytest.MonkeyPatch) -> None:
    t = _tel(monkeypatch, [100.0, 300.0, 250.0, 120.0, 80.0, 90.0])
    with t.stage("ingest") as rec:   # samples: enter 100, exit 300
        rec["rows"] = 7
    with t.stage("detect"):          # samples: enter 250, exit 120
        pass
    assert [(s["name"], s["peak_rss_mb"]) for s in t.stages] == [("ingest", 300.0), ("detect", 250.0)]
    assert t.stages[0]["rows"] == 7 and t.stages[0]["wall_s"] >= 0
    assert t.peak_rss_mb == 300.0


def test_stage_recorded_even_when_block_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    t = _tel(monkeypatch, [50.0])
    with pytest.raises(RuntimeError):
        with t.stage("link"):
            raise RuntimeError("boom")
    assert [s["name"] for s in t.stages] == ["link"]
    assert set(t.stages[0]) == {"name", "wall_s", "peak_rss_mb"}
    assert t._stage_peak is None                  # outside a stage again: samples no longer feed a stage peak


def test_summary_rows_per_s_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    t = _tel(monkeypatch, [10.0])
    monkeypatch.setattr(t, "total_wall_s", lambda: 2.0)
    assert t.summary(rows=1001)["rows_per_s"] == 500.5
    assert t.summary(rows=0)["rows_per_s"] is None          # near miss: 0 rows is not a rate
    assert t.summary(rows=None)["rows_per_s"] is None
    monkeypatch.setattr(t, "total_wall_s", lambda: 0.0)
    assert t.summary(rows=10)["rows_per_s"] is None          # zero wall time never divides
    assert set(t.summary()) == {"total_wall_s", "peak_rss_mb", "rows_per_s", "stages"}


def test_write_extra_never_overrides_measured_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    t = _tel(monkeypatch, [42.0])
    out = tmp_path / "deep" / "run_metrics.json"            # parent dirs are created
    data = t.write(out, extra={"peak_rss_mb": 1.0, "total_wall_s": -5, "incidents": 3}, rows=None)
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk == data
    assert on_disk["peak_rss_mb"] == 42.0 and on_disk["total_wall_s"] >= 0 and on_disk["incidents"] == 3


def test_start_is_idempotent_and_stop_joins(monkeypatch: pytest.MonkeyPatch) -> None:
    t = _tel(monkeypatch, [5.0, 7.0, 9.0])
    assert t.start() is t
    th = t._thread
    assert th is not None and th.daemon and th.name == "telemetry"
    t.start()                                   # second start: same thread, no extra sample thread
    assert t._thread is th
    t.stop()
    assert t._thread is None and not th.is_alive()
    assert t.peak_rss_mb == 7.0                 # samples: start 5, stop 7 (the second start does not sample)
    t.stop()                                    # stop twice is harmless (no thread)
    assert t.peak_rss_mb == 9.0
