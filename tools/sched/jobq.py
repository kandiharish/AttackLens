"""jobq - RAM/CPU-aware local job queue for heavy AttackLens jobs (stdlib + psutil).
Usage:
  python tools/sched/jobq.py run --name g10 --prio 2 --ram-gb 6 --est-min 20 --threads 6 -- .venv/Scripts/python -m attacklens.run ...
  python tools/sched/jobq.py status                       # running + waiting jobs, free RAM, CPU
  python tools/sched/jobq.py renice --pid 1234 --prio 8   # re-prioritise a process tree started elsewhere (never kills)
Rank = (prio 1..9, est-min, enqueue time). Start iff free RAM - unspent reservations >= ram-gb + 1 GB and no job ranks ahead.
--threads N only exports ATTACKLENS_THREADS (attacklens does NOT read it) plus the standard OpenMP/BLAS caps
  (OMP/MKL/OPENBLAS/NUMEXPR/VECLIB). It does not cap DuckDB: set `threads:` in config/pipeline.yaml for that.
A waiting job never gives up on the queue lock (backoff); a relative command is resolved against the cwd first.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

import psutil

log = logging.getLogger("jobq")
GB = 1024 ** 3
HEADROOM_GB = 1.0
DEFAULT_EST_MIN = 60.0
UNKNOWN_WAIT_MIN = 10.0  # head can't fit even after all scheduled jobs end (external pressure): assumed wait
LOCK_STALE_S = 10.0  # empty/garbled lock older than this: holder died between create and write
LOCK_HELD_MAX_S = 120.0  # lock sections take ms; a live holder's lock older than this leaked (failed remove)
LOCK_BACKOFF_MAX_S = 1.0
THREAD_CAP_VARS = ("ATTACKLENS_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS",
                   "NUMEXPR_NUM_THREADS", "VECLIB_MAXIMUM_THREADS")


def state_dir() -> Path:
    d = Path(os.environ.get("JOBQ_DIR") or Path(__file__).resolve().parents[2] / "data" / "sched")
    d.mkdir(parents=True, exist_ok=True)
    return d


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(t: datetime) -> str:
    return t.isoformat(timespec="milliseconds")


def ctime_of(pid: int) -> float | None:
    try:
        return psutil.Process(pid).create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        return None


def alive(pid: int | None, ctime: float | None = None) -> bool:
    """pid exists and (if ctime given) is the same process, not a reused pid."""
    if not pid:
        return False
    c = ctime_of(pid)
    return c is not None and (ctime is None or abs(c - ctime) < 1.0)


# ---------------------------------------------------------------- lock + queue file
@contextmanager
def queue_lock(timeout_s: float | None = 30.0) -> Iterator[None]:
    """Exclusive lock file. timeout_s=None waits forever with capped exponential backoff (never raises)."""
    path = state_dir() / "queue.lock"
    me = f"{os.getpid()} {ctime_of(os.getpid()) or 0}"
    deadline = None if timeout_s is None else time.monotonic() + timeout_s
    delay, warn_at = 0.05, time.monotonic() + 60
    while True:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, me.encode())
            os.close(fd)
            break
        except (FileExistsError, PermissionError):  # PermissionError: Windows, lock file is pending delete
            if _lock_is_stale(path, me):
                log.warning("removing stale lock %s", path)
                _remove(path)
                continue
            if deadline is not None and time.monotonic() > deadline:
                raise TimeoutError(f"could not acquire {path}")
            if time.monotonic() > warn_at:
                log.warning("still waiting for %s", path)
                warn_at = time.monotonic() + 60
            time.sleep(delay)
            delay = min(delay * 2, LOCK_BACKOFF_MAX_S)
    try:
        yield
    finally:
        _remove(path)


def _remove(path: Path) -> None:
    for _ in range(20):  # Windows: remove fails while another process has the file open (stale check)
        try:
            os.remove(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.05)
    log.warning("could not remove %s; it will be reclaimed as stale", path)


def _lock_is_stale(path: Path, me: str = "") -> bool:
    try:
        raw = path.read_text()
        age = time.time() - path.stat().st_mtime
    except OSError:
        return False  # vanished or unreadable right now: just retry
    if raw == me:
        return True  # our own leaked lock (failed remove): we never nest the lock
    try:
        pid, ctime = (int(raw.split()[0]), float(raw.split()[1]))
    except (ValueError, IndexError):
        return age > LOCK_STALE_S  # holder died between create and write, or garbage
    return not alive(pid, ctime or None) or age > LOCK_HELD_MAX_S


def load() -> list[dict]:
    p = state_dir() / "queue.json"
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text() or "[]")
    except json.JSONDecodeError:
        log.error("corrupt %s, starting empty", p)
        return []


def save(entries: list[dict]) -> None:
    p = state_dir() / "queue.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=1))
    os.replace(tmp, p)


def clean_dead(entries: list[dict]) -> list[dict]:
    keep = [e for e in entries if alive(e["pid"], e.get("pid_ctime"))]
    for e in entries:
        if e not in keep:
            log.info("removing dead entry %s (pid %s)", e["name"], e["pid"])
    return keep


# ---------------------------------------------------------------- admission (pure)
def rank(e: dict) -> tuple:
    return (e["prio"], e.get("est_min") or DEFAULT_EST_MIN, e["enq"])


def tree_rss_gb(pid: int | None) -> float:
    try:
        p = psutil.Process(pid)
        procs = [p] + p.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError, TypeError):
        return 0.0
    total = 0
    for q in procs:
        try:
            total += q.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return total / GB


def unspent_gb(e: dict, rss_gb: Callable[[dict], float]) -> float:
    return max(0.0, e["ram_gb"] - rss_gb(e))


def avail_gb(entries: list[dict], free_gb: float, rss_gb: Callable[[dict], float]) -> float:
    return free_gb - sum(unspent_gb(e, rss_gb) for e in entries if e["state"] == "running")


def remaining_min(e: dict, now: datetime) -> float:
    elapsed = (now - datetime.fromisoformat(e["start"])).total_seconds() / 60
    return max(0.0, (e.get("est_min") or DEFAULT_EST_MIN) - elapsed)


def head_wait_min(head: dict, entries: list[dict], avail: float, rss_gb: Callable[[dict], float],
                  now: datetime) -> float:
    """Minutes until the head fits, assuming running jobs end at est-min and each frees max(R, RSS)."""
    running = sorted(((remaining_min(e, now), e) for e in entries if e["state"] == "running"),
                     key=lambda t: t[0])
    need = head["ram_gb"] + HEADROOM_GB
    for rem, e in running:
        avail += max(e["ram_gb"], rss_gb(e))
        if avail >= need:
            return rem
    return max([r for r, _ in running] + [UNKNOWN_WAIT_MIN])


def pick_next(entries: list[dict], free_gb: float, rss_gb: Callable[[dict], float],
              now: datetime) -> str | None:
    """id of the one waiting job allowed to start now, or None."""
    waiting = sorted((e for e in entries if e["state"] == "waiting"), key=rank)
    if not waiting:
        return None
    avail = avail_gb(entries, free_gb, rss_gb)
    head = waiting[0]
    if avail >= head["ram_gb"] + HEADROOM_GB:
        return head["id"]
    wait = head_wait_min(head, entries, avail, rss_gb, now)
    for e in waiting[1:]:  # backfill: fits now AND finishes before the head could start anyway
        if avail >= e["ram_gb"] + HEADROOM_GB and (e.get("est_min") or DEFAULT_EST_MIN) < wait:
            return e["id"]
    return None


# ---------------------------------------------------------------- priority
def prio_level(prio: int) -> str:
    return "high" if prio <= 2 else "normal" if prio <= 5 else "below"


def prio_class(prio: int) -> int:
    lvl = prio_level(prio)
    if sys.platform == "win32":
        return {"high": psutil.HIGH_PRIORITY_CLASS, "normal": psutil.NORMAL_PRIORITY_CLASS,
                "below": psutil.BELOW_NORMAL_PRIORITY_CLASS}[lvl]
    return {"high": -5, "normal": 0, "below": 10}[lvl]


def renice_tree(pid: int, prio: int) -> int:
    """Set the priority class on pid and all descendants. Returns how many processes changed. Never kills."""
    root = psutil.Process(pid)
    n = 0
    for p in [root] + root.children(recursive=True):
        try:
            p.nice(prio_class(prio))
            n += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            log.warning("renice pid %s failed: %s", p.pid, exc)
    return n


# ---------------------------------------------------------------- commands
def free_ram_gb() -> float:
    return psutil.virtual_memory().available / GB


def entry_rss(e: dict) -> float:
    return tree_rss_gb(e.get("child_pid"))


def _child_env(threads: int | None) -> dict[str, str]:
    env = dict(os.environ)
    if threads:  # caps OpenMP/BLAS pools only; DuckDB threads come from config/pipeline.yaml
        env.update(dict.fromkeys(THREAD_CAP_VARS, str(threads)))
    return env


def cmd_run(a: argparse.Namespace) -> int:
    cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    if not cmd:
        log.error("no command given after --")
        return 2
    if a.ram_gb + HEADROOM_GB > psutil.virtual_memory().total / GB:
        log.error("--ram-gb %.1f + %.1f headroom exceeds total RAM; can never start", a.ram_gb, HEADROOM_GB)
        return 2
    exe = shutil.which(cmd[0]) or shutil.which(str(Path.cwd() / cmd[0]))  # Windows: relative/no-.exe -> WinError 2
    if not exe:
        log.error("command not found: %s (cwd %s)", cmd[0], Path.cwd())
        return 127
    cmd = [os.path.abspath(exe)] + cmd[1:]
    pid = os.getpid()
    me = {"id": f"{pid}-{time.time_ns()}", "name": a.name, "prio": a.prio, "ram_gb": a.ram_gb,
          "est_min": a.est_min, "threads": a.threads, "pid": pid, "pid_ctime": ctime_of(pid),
          "state": "waiting", "enq": iso(utcnow()), "start": None, "child_pid": None, "cmd": cmd}
    for sig in ("SIGTERM", "SIGBREAK"):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), lambda *_: sys.exit(130))
    with queue_lock(timeout_s=None):
        save(clean_dead(load()) + [me])
    log.info("queued %s (prio %d, %.1f GB, est %s min)", a.name, a.prio, a.ram_gb, a.est_min)
    child = None
    try:
        poll, last_log = float(os.environ.get("JOBQ_POLL", "2")), 0.0
        while child is None:
            with queue_lock(timeout_s=None):
                entries = clean_dead(load())
                if not any(e["id"] == me["id"] for e in entries):
                    entries.append(me)
                if pick_next(entries, free_ram_gb(), entry_rss, utcnow()) == me["id"]:
                    child = subprocess.Popen(cmd, env=_child_env(a.threads))
                    try:
                        psutil.Process(child.pid).nice(prio_class(a.prio))
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                        log.warning("could not set priority: %s", exc)
                    for e in entries:
                        if e["id"] == me["id"]:
                            e.update(state="running", start=iso(utcnow()), child_pid=child.pid)
                save(entries)
            if child is None:
                if time.monotonic() - last_log > 60:
                    log.info("waiting: %s (free %.1f GB)", a.name, free_ram_gb())
                    last_log = time.monotonic()
                time.sleep(poll)
        log.info("started %s pid %d [%s]", a.name, child.pid, prio_level(a.prio))
        try:
            rc = child.wait()
        except KeyboardInterrupt:  # child got Ctrl-C too; give it time to exit cleanly
            try:
                rc = child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                log.warning("child %d ignored Ctrl-C, terminating our own child", child.pid)
                child.terminate()
                rc = child.wait()
        log.info("finished %s rc=%d", a.name, rc)
        return rc
    except KeyboardInterrupt:
        log.info("cancelled %s while waiting", a.name)
        return 130
    finally:  # never lose the child's rc: if this fails, clean_dead drops our entry once we exit
        try:
            with queue_lock(timeout_s=None):
                save([e for e in load() if e["id"] != me["id"]])
        except OSError as exc:
            log.warning("could not remove queue entry %s: %s", a.name, exc)


def _age(ts: str, now: datetime) -> str:
    s = int((now - datetime.fromisoformat(ts)).total_seconds())
    return f"{s // 3600}h{s % 3600 // 60:02d}m" if s >= 3600 else f"{s // 60}m{s % 60:02d}s"


def status_rows(entries: list[dict], rss_gb: Callable[[dict], float], now: datetime) -> list[tuple]:
    entries = sorted(entries, key=lambda e: (e["state"] != "running", rank(e)))
    rows = [("STATE", "NAME", "PRIO", "PID", "RSS_GB", "RES_GB", "UNSPENT", "EST_MIN", "AGE")]
    for e in entries:
        run = e["state"] == "running"
        rss = rss_gb(e) if run else 0.0
        rows.append((e["state"], e["name"][:24], str(e["prio"]), str(e.get("child_pid") or e["pid"]),
                     f"{rss:.2f}" if run else "-", f"{e['ram_gb']:.1f}",
                     f"{max(0.0, e['ram_gb'] - rss):.2f}" if run else "-",
                     str(e.get("est_min") or "-"), _age(e["enq"], now)))
    return rows


def cmd_status(_: argparse.Namespace) -> int:
    with queue_lock():
        entries = clean_dead(load())
        save(entries)
    rows = status_rows(entries, entry_rss, utcnow())
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        print("  ".join(c.ljust(w) for c, w in zip(r, widths)))
    vm = psutil.virtual_memory()
    free = vm.available / GB
    print(f"\nfree RAM {free:.1f} / {vm.total / GB:.1f} GB  |  after reservations "
          f"{avail_gb(entries, free, entry_rss):.1f} GB  |  CPU {psutil.cpu_percent(interval=0.5):.0f} %")
    return 0


def cmd_renice(a: argparse.Namespace) -> int:
    n = renice_tree(a.pid, a.prio)
    log.info("pid %d tree: %d process(es) set to %s", a.pid, n, prio_level(a.prio))
    return 0 if n else 1


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s jobq %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(prog="jobq")
    sub = ap.add_subparsers(dest="op", required=True)
    r = sub.add_parser("run")
    r.add_argument("--name", required=True)
    r.add_argument("--prio", type=int, choices=range(1, 10), required=True)
    r.add_argument("--ram-gb", type=float, required=True)
    r.add_argument("--est-min", type=float, default=None)
    r.add_argument("--threads", type=int, default=None,
                   help="export ATTACKLENS_THREADS (unused by attacklens) + OMP/BLAS caps; DuckDB: config threads")
    r.add_argument("cmd", nargs=argparse.REMAINDER)
    sub.add_parser("status")
    n = sub.add_parser("renice")
    n.add_argument("--pid", type=int, required=True)
    n.add_argument("--prio", type=int, choices=range(1, 10), required=True)
    a = ap.parse_args(argv)
    return {"run": cmd_run, "status": cmd_status, "renice": cmd_renice}[a.op](a)


if __name__ == "__main__":
    sys.exit(main())
