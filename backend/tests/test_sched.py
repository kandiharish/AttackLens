"""tools/sched/jobq.py - rank, admission math, backfill vs no-starvation, locks, dead pids, priority mapping.
Pure functions get monkeypatched RAM/RSS; nothing here allocates real memory."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psutil
import pytest

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("jobq", REPO / "tools" / "sched" / "jobq.py")
jobq = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jobq)

NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("JOBQ_DIR", str(tmp_path / "sched"))
    monkeypatch.setenv("JOBQ_POLL", "0.05")
    return tmp_path / "sched"


def job(id_, prio=5, ram=1.0, est=10.0, enq_s=0, state="waiting", start_min_ago=None, rss=0.0):
    e = {"id": id_, "name": id_, "prio": prio, "ram_gb": ram, "est_min": est, "pid": 1, "child_pid": None,
         "state": state, "enq": jobq.iso(NOW - timedelta(hours=1) + timedelta(seconds=enq_s)),
         "start": None, "_rss": rss}
    if state == "running":
        e["start"] = jobq.iso(NOW - timedelta(minutes=start_min_ago or 0))
    return e


def rss(e):  # monkeypatched RSS: read from the fixture entry
    return e["_rss"]


# ---------------------------------------------------------------- rank
def test_rank_prio_then_est_then_enqueue():
    es = [job("a", prio=3, est=1), job("b", prio=1, est=50), job("c", prio=1, est=5, enq_s=1),
          job("d", prio=1, est=5, enq_s=2), job("e", prio=1, est=None), job("f", prio=9, est=0.5)]
    assert [e["id"] for e in sorted(es, key=jobq.rank)] == ["c", "d", "b", "e", "a", "f"]


def test_missing_est_ranks_as_default_60():
    es = [job("none", prio=2, est=None), job("59", prio=2, est=59, enq_s=5), job("61", prio=2, est=61)]
    assert [e["id"] for e in sorted(es, key=jobq.rank)] == ["59", "none", "61"]


# ---------------------------------------------------------------- admission math
def test_avail_subtracts_only_unspent_reservation_of_running_jobs():
    es = [job("r1", ram=6, state="running", rss=2.0), job("r2", ram=2, state="running", rss=3.5),
          job("w", ram=4)]  # r1 unspent 4, r2 over its reservation -> 0, waiting jobs reserve nothing
    assert jobq.unspent_gb(es[0], rss) == 4.0
    assert jobq.unspent_gb(es[1], rss) == 0.0
    assert jobq.avail_gb(es, 9.0, rss) == 5.0


def test_head_starts_exactly_at_ram_plus_1gb_headroom():
    run = job("r1", ram=6, state="running", rss=2.0, est=30, start_min_ago=1)
    assert jobq.pick_next([run, job("w", ram=3.0)], 8.0, rss, NOW) == "w"      # 8-4=4 >= 3+1
    assert jobq.pick_next([run, job("w", ram=3.01)], 8.0, rss, NOW) is None    # 4 < 4.01


def test_higher_rank_goes_first_when_both_fit():
    es = [job("low", prio=6, ram=1, est=1), job("hi", prio=2, ram=1, est=90)]
    assert jobq.pick_next(es, 10.0, rss, NOW) == "hi"


def test_nothing_waiting_returns_none():
    assert jobq.pick_next([job("r", state="running", start_min_ago=1)], 10.0, rss, NOW) is None


# ---------------------------------------------------------------- backfill vs starvation
def _blocked(small_est, small_ram=1.0):
    # r1 holds 6 GB (rss 6), 20 min left. free 3 -> avail 3. Head needs 6+1=7; after r1 ends: 3+6=9 -> wait 20.
    return [job("r1", ram=6, rss=6.0, state="running", est=30, start_min_ago=10),
            job("head", prio=1, ram=6, est=5),
            job("small", prio=5, ram=small_ram, est=small_est)]


def test_head_wait_is_remaining_time_of_the_job_that_frees_enough():
    es = _blocked(15)
    assert jobq.head_wait_min(es[1], es, 3.0, rss, NOW) == 20.0


def test_backfill_small_job_that_ends_before_head_could_start():
    assert jobq.pick_next(_blocked(15), 3.0, rss, NOW) == "small"


def test_no_backfill_when_small_job_would_delay_head():
    assert jobq.pick_next(_blocked(25), 3.0, rss, NOW) is None
    assert jobq.pick_next(_blocked(20), 3.0, rss, NOW) is None  # strict: est must be < wait


def test_no_backfill_when_small_job_does_not_fit():
    assert jobq.pick_next(_blocked(1, small_ram=2.01), 3.0, rss, NOW) is None  # 2.01+1 > 3


def test_backfill_picks_best_ranked_candidate_and_skips_non_fitting():
    es = _blocked(15) + [job("big2", prio=2, ram=5, est=1), job("small2", prio=3, ram=0.5, est=2)]
    assert jobq.pick_next(es, 3.0, rss, NOW) == "small2"  # big2 ranks ahead but doesn't fit; small2 beats small


def test_head_wait_accumulates_several_running_jobs():
    # avail = 5 - (0 + 3) = 2; head needs 6. r1 ends (5 min) -> 4; r2 ends (40 min) -> 4 + max(4, 1) = 8.
    es = [job("r1", ram=2, rss=2.0, state="running", est=10, start_min_ago=5),
          job("r2", ram=4, rss=1.0, state="running", est=50, start_min_ago=10),
          job("head", prio=1, ram=5)]
    assert jobq.avail_gb(es, 5.0, rss) == 2.0
    assert jobq.head_wait_min(es[2], es, 2.0, rss, NOW) == 40.0


def test_unknown_wait_under_external_pressure_allows_only_short_backfill():
    # no scheduled job running: head blocked by RAM outside the queue -> assumed wait UNKNOWN_WAIT_MIN = 10
    es = [job("head", prio=1, ram=6), job("tiny", prio=7, ram=0.5, est=9.9)]
    assert jobq.pick_next(es, 3.0, rss, NOW) == "tiny"
    es[1]["est_min"] = 10.0
    assert jobq.pick_next(es, 3.0, rss, NOW) is None


def test_overrun_job_counts_zero_remaining():
    es = [job("r1", ram=6, rss=6.0, state="running", est=5, start_min_ago=30), job("head", prio=1, ram=6)]
    assert jobq.head_wait_min(es[1], es, 3.0, rss, NOW) == 0.0
    assert jobq.pick_next(es + [job("s", prio=9, ram=0.1, est=0.5)], 3.0, rss, NOW) is None


# ---------------------------------------------------------------- lock + dead pids
def _exited_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def test_stale_lock_from_reused_pid_is_recovered(_state):
    _state.mkdir(parents=True, exist_ok=True)
    (_state / "queue.lock").write_text(f"{os.getpid()} 1.0")  # live pid, wrong create time -> dead holder
    t0 = time.monotonic()
    with jobq.queue_lock(timeout_s=2):
        assert (_state / "queue.lock").read_text().split()[0] == str(os.getpid())
    assert time.monotonic() - t0 < 1.0
    assert not (_state / "queue.lock").exists()


def test_stale_lock_from_exited_pid_is_recovered(_state):
    _state.mkdir(parents=True, exist_ok=True)
    (_state / "queue.lock").write_text(f"{_exited_pid()} 1700000000.0")
    with jobq.queue_lock(timeout_s=2):
        pass


def test_live_lock_blocks_until_timeout(_state):
    _state.mkdir(parents=True, exist_ok=True)
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])  # live OTHER process
    try:
        (_state / "queue.lock").write_text(f"{holder.pid} {psutil.Process(holder.pid).create_time()}")
        with pytest.raises(TimeoutError):
            with jobq.queue_lock(timeout_s=0.2):
                pass
        assert (_state / "queue.lock").exists()  # a live holder's lock is never removed
    finally:
        holder.kill()
        holder.wait()


def test_empty_lock_is_stale_only_when_old(_state):
    _state.mkdir(parents=True, exist_ok=True)
    lock = _state / "queue.lock"
    lock.write_text("")
    with pytest.raises(TimeoutError):
        with jobq.queue_lock(timeout_s=0.2):
            pass
    old = time.time() - 60
    os.utime(lock, (old, old))
    with jobq.queue_lock(timeout_s=1):
        pass


def test_clean_dead_keeps_only_live_same_process_entries():
    me, ct = os.getpid(), psutil.Process().create_time()
    es = [dict(job("live"), pid=me, pid_ctime=ct), dict(job("reused"), pid=me, pid_ctime=ct - 100),
          dict(job("gone"), pid=_exited_pid(), pid_ctime=None), dict(job("zero"), pid=0)]
    assert [e["id"] for e in jobq.clean_dead(es)] == ["live"]


def test_load_save_roundtrip_and_corrupt_file(_state):
    assert jobq.load() == []
    jobq.save([{"id": "x"}])
    assert json.loads((_state / "queue.json").read_text()) == [{"id": "x"}]
    (_state / "queue.json").write_text("{not json")
    assert jobq.load() == []


# ---------------------------------------------------------------- priority
def test_prio_level_mapping():
    assert [jobq.prio_level(p) for p in range(1, 10)] == ["high"] * 2 + ["normal"] * 3 + ["below"] * 4


@pytest.mark.skipif(sys.platform != "win32", reason="Windows priority classes")
def test_prio_class_windows_constants():
    assert [jobq.prio_class(p) for p in (1, 2, 3, 5, 6, 9)] == [
        psutil.HIGH_PRIORITY_CLASS, psutil.HIGH_PRIORITY_CLASS, psutil.NORMAL_PRIORITY_CLASS,
        psutil.NORMAL_PRIORITY_CLASS, psutil.BELOW_NORMAL_PRIORITY_CLASS, psutil.BELOW_NORMAL_PRIORITY_CLASS]


def test_renice_tree_sets_class_and_never_kills():
    # the venv python.exe is a launcher that spawns the real interpreter -> often a 2-process tree
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    try:
        time.sleep(0.5)
        tree = [psutil.Process(p.pid)] + psutil.Process(p.pid).children(recursive=True)
        assert jobq.renice_tree(p.pid, 8) == len(tree)
        assert [q.nice() for q in tree] == [jobq.prio_class(8)] * len(tree)
        assert p.poll() is None and all(q.is_running() for q in tree)
    finally:
        p.kill()
        p.wait()


# ---------------------------------------------------------------- end to end (tiny child, fake free RAM)
def test_run_passes_threads_env_returns_child_rc_and_removes_entry(_state, monkeypatch):
    monkeypatch.setattr(jobq, "free_ram_gb", lambda: 8.0)
    monkeypatch.setattr(jobq.signal, "signal", lambda *a: None)
    code = "import os,sys; sys.exit(int(os.environ['OMP_NUM_THREADS']) + int(os.environ['ATTACKLENS_THREADS']))"
    rc = jobq.main(["run", "--name", "t", "--prio", "4", "--ram-gb", "0.1", "--est-min", "1", "--threads", "3",
                    "--", sys.executable, "-c", code])
    assert rc == 6
    assert jobq.load() == []


def test_run_rejects_job_larger_than_total_ram(monkeypatch):
    monkeypatch.setattr(jobq.signal, "signal", lambda *a: None)
    total = psutil.virtual_memory().total / jobq.GB
    assert jobq.main(["run", "--name", "huge", "--prio", "1", "--ram-gb", str(total), "--", "x"]) == 2
    assert jobq.load() == []


def test_status_rows_exact():
    es = [job("w1", prio=3, ram=2, est=None, enq_s=0),
          dict(job("r1", prio=1, ram=6, est=30, enq_s=3000, state="running", start_min_ago=5, rss=2.5),
               child_pid=4242)]
    rows = jobq.status_rows(es, rss, NOW)
    assert rows[1] == ("running", "r1", "1", "4242", "2.50", "6.0", "3.50", "30", "10m00s")
    assert rows[2] == ("waiting", "w1", "3", "1", "-", "2.0", "-", "-", "1h00m")


# ---------------------------------------------------------------- lock contention never crashes a run
def _tiny_lock_timeout(monkeypatch):
    """Shrink the lock's default timeout: a run must never depend on it (it waits with backoff instead)."""
    monkeypatch.setattr(jobq.queue_lock.__wrapped__, "__defaults__", (0.2,))
    monkeypatch.setattr(jobq, "free_ram_gb", lambda: 8.0)
    monkeypatch.setattr(jobq.signal, "signal", lambda *a: None)


def test_waiting_run_outlasts_a_busy_lock(_state, monkeypatch):
    _tiny_lock_timeout(monkeypatch)
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    try:
        _state.mkdir(parents=True, exist_ok=True)
        lock = _state / "queue.lock"
        lock.write_text(f"{holder.pid} {psutil.Process(holder.pid).create_time()}")  # live foreign holder
        import threading
        threading.Timer(1.0, lambda: lock.unlink(missing_ok=True)).start()  # holder releases after 1 s
        t0 = time.monotonic()
        rc = jobq.main(["run", "--name", "w", "--prio", "4", "--ram-gb", "0.1", "--est-min", "1",
                        "--", sys.executable, "-c", "import sys; sys.exit(3)"])
        assert rc == 3 and time.monotonic() - t0 >= 0.9
        assert jobq.load() == []
    finally:
        holder.kill()
        holder.wait()


def test_finished_run_returns_child_rc_even_if_its_own_lock_leaked(_state, monkeypatch):
    # Windows: os.remove of the lock can fail (another process has it open), leaving OUR pid in it.
    _tiny_lock_timeout(monkeypatch)
    me = f"{os.getpid()} {jobq.ctime_of(os.getpid()) or 0}"
    code = f"import pathlib,sys; pathlib.Path(r'{_state / 'queue.lock'}').write_text('{me}'); sys.exit(5)"
    rc = jobq.main(["run", "--name", "f", "--prio", "4", "--ram-gb", "0.1", "--", sys.executable, "-c", code])
    assert rc == 5
    assert jobq.load() == [] and not (_state / "queue.lock").exists()


def test_live_holder_lock_older_than_held_max_is_reclaimed(_state):
    _state.mkdir(parents=True, exist_ok=True)
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    try:
        lock = _state / "queue.lock"
        lock.write_text(f"{holder.pid} {psutil.Process(holder.pid).create_time()}")
        with pytest.raises(TimeoutError):  # fresh lock of a live holder: respected
            with jobq.queue_lock(timeout_s=0.2):
                pass
        old = time.time() - jobq.LOCK_HELD_MAX_S - 1
        os.utime(lock, (old, old))  # live holder that leaked it long ago: reclaimed
        with jobq.queue_lock(timeout_s=1):
            pass
    finally:
        holder.kill()
        holder.wait()


def test_garbage_lock_content_does_not_crash(_state):
    _state.mkdir(parents=True, exist_ok=True)
    lock = _state / "queue.lock"
    lock.write_text("abc def")
    old = time.time() - 60
    os.utime(lock, (old, old))
    with jobq.queue_lock(timeout_s=1):
        pass


# ---------------------------------------------------------------- command resolution + thread caps
def test_relative_command_without_exe_suffix_resolves_against_cwd(_state, monkeypatch):
    monkeypatch.setattr(jobq, "free_ram_gb", lambda: 8.0)
    monkeypatch.setattr(jobq.signal, "signal", lambda *a: None)
    exe = Path(sys.executable)
    monkeypatch.chdir(exe.parent.parent)
    rel = f"{exe.parent.name}/{exe.stem}"  # e.g. Scripts/python, like .venv/Scripts/python from the repo root
    rc = jobq.main(["run", "--name", "rel", "--prio", "4", "--ram-gb", "0.1", "--", rel, "-c", "raise SystemExit(4)"])
    assert rc == 4


def test_unknown_command_fails_fast_without_queueing(_state, monkeypatch):
    monkeypatch.setattr(jobq.signal, "signal", lambda *a: None)
    assert jobq.main(["run", "--name", "x", "--prio", "4", "--ram-gb", "0.1", "--", "no/such/prog_jobq"]) == 127
    assert jobq.load() == []


def test_threads_exports_standard_thread_caps():
    env = jobq._child_env(2)
    assert all(env[k] == "2" for k in ("ATTACKLENS_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS",
                                       "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS"))
