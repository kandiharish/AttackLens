"""Shared helpers for tools/perf: resource monitor, DuckDB JSON-profile summaries, a profiling connection proxy.

Nothing here touches product code paths; scale_detect.py imports the production detect functions and runs them
on a connection made by attacklens.db.connect.
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import duckdb
import psutil

NCPU = psutil.cpu_count() or 1
_LIT = re.compile(r"'[^']*'")


def dir_bytes(p: Path) -> int:
    total = 0
    if not p.exists():
        return 0
    for root, _dirs, files in os.walk(p):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


class Monitor:
    """Samples every interval_s: own RSS, system CPU %, own CPU % (normalised to the machine), free RAM, spill dir
    bytes. `others` = system CPU minus this process (the load of other jobs on the shared box)."""

    def __init__(self, spill_dir: Path, interval_s: float = 0.5) -> None:
        self.proc = psutil.Process()
        self.spill_dir = spill_dir
        self.interval_s = interval_s
        self.samples: list[tuple[float, float, float, float, float, int]] = []
        self._stop = threading.Event()
        self._lock = threading.Lock()
        psutil.cpu_percent(None)
        self.proc.cpu_percent(None)
        self._t = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> Monitor:
        self._t.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._t.join(timeout=5)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_s):
            tot = psutil.cpu_percent(None)
            own = self.proc.cpu_percent(None) / NCPU
            rss = self.proc.memory_info().rss / 2**20
            free = psutil.virtual_memory().available / 2**20
            spill = dir_bytes(self.spill_dir)
            with self._lock:
                self.samples.append((time.perf_counter(), tot, own, rss, free, spill))

    @contextmanager
    def window(self) -> Iterator[dict[str, Any]]:
        out: dict[str, Any] = {}
        t0 = time.perf_counter()
        rss0 = self.proc.memory_info().rss / 2**20
        c0 = self.proc.cpu_times()
        pf0 = getattr(self.proc.memory_info(), "num_page_faults", 0)
        yield out
        t1 = time.perf_counter()
        c1 = self.proc.cpu_times()
        # Windows: soft + hard page faults of this process (hard faults = paging when other jobs hold the RAM)
        out["page_faults"] = int(getattr(self.proc.memory_info(), "num_page_faults", 0) - pf0)
        # OS CPU seconds of this process (user + system): unlike wall and DuckDB's per-operator wall timers, it does
        # not grow when other jobs steal the cores (it still grows with paging / cache misses)
        out["proc_cpu_s"] = round((c1.user - c0.user) + (c1.system - c0.system), 3)
        time.sleep(self.interval_s * 1.1)   # one sample after the end
        with self._lock:
            s = [x for x in self.samples if t0 <= x[0] <= t1 + self.interval_s]
        out.update(summarise(s, rss0))


def summarise(s: list[tuple[float, float, float, float, float, int]], rss0: float) -> dict[str, Any]:
    if not s:
        return {"n_samples": 0, "peak_rss_mb": round(rss0, 1)}
    others = [max(0.0, t - o) for _, t, o, _, _, _ in s]
    return {"n_samples": len(s),
            "cpu_total_mean": round(sum(x[1] for x in s) / len(s), 1),
            "cpu_own_mean": round(sum(x[2] for x in s) / len(s), 1),
            "cpu_others_mean": round(sum(others) / len(others), 1),
            "cpu_others_max": round(max(others), 1),
            "free_ram_min_mb": round(min(x[4] for x in s)),
            "peak_rss_mb": round(max(rss0, max(x[3] for x in s)), 1),
            "spill_dir_peak_mb": round(max(x[5] for x in s) / 2**20, 1)}


def idle_load(seconds: float = 2.0) -> dict[str, float]:
    """System CPU % and free RAM over `seconds` while this process is idle (= other jobs' load)."""
    psutil.cpu_percent(None)
    time.sleep(seconds)
    return {"cpu_idle_load": round(psutil.cpu_percent(None), 1),
            "free_ram_mb": round(psutil.virtual_memory().available / 2**20)}


def wait_for_quiet(max_load: float, max_wait_s: float, log: Any) -> dict[str, float]:
    """Block until other jobs' CPU load <= max_load (or max_wait_s passed). Returns the last idle reading."""
    t0 = time.perf_counter()
    while True:
        r = idle_load(3.0)
        if r["cpu_idle_load"] <= max_load or time.perf_counter() - t0 > max_wait_s:
            return {**r, "waited_s": round(time.perf_counter() - t0, 1)}
        log.info("box busy (%.0f %% CPU by others, %d MB free); waiting", r["cpu_idle_load"], r["free_ram_mb"])
        time.sleep(20)


# ---------------------------------------------------------------- DuckDB profile JSON

def enable_profiling(con: duckdb.DuckDBPyConnection, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con.execute("PRAGMA enable_profiling='json'")
    con.execute("SET profiling_coverage='ALL'")
    con.execute(f"PRAGMA profiling_output='{path.as_posix()}'")


def _walk(op: dict[str, Any], depth: int = 0) -> Iterator[tuple[int, dict[str, Any]]]:
    yield depth, op
    for c in op.get("children") or []:
        yield from _walk(c, depth + 1)


def _detail(op: dict[str, Any]) -> str:
    """Short, literal-free operator detail (join type/conditions, window expressions, aggregates)."""
    ei = op.get("extra_info") or {}
    parts = []
    for k in ("Join Type", "Conditions", "Projections", "Aggregates", "Groups"):
        v = ei.get(k)
        if v is None:
            continue
        if isinstance(v, list):
            v = "; ".join(map(str, v))
        if op.get("type") not in ("WINDOW", "STREAMING_WINDOW") and k == "Projections":
            continue
        parts.append(f"{k}={v}")
    return _LIT.sub("'.'", " | ".join(parts))[:220]


def _plan_s(d: dict[str, Any]) -> float:
    tot = 0.0
    for k in ("planner", "optimizer", "physical_planner"):
        v = d.get(k)
        if isinstance(v, dict):
            tot += sum(float(x) for x in v.values() if isinstance(x, (int, float)))
        elif isinstance(v, (int, float)):
            tot += float(v)
    return tot


def summarise_profile(path: Path, top: int = 8) -> dict[str, Any]:
    """Top operators by operator CPU time (summed over threads) + query-level metrics."""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    ops = [(depth, o) for root in d.get("operator") or [] for depth, o in _walk(root)]
    q = d.get("query") or {}
    sysm = d.get("system") or {}
    io = d.get("io") or {}
    scans = [o for _, o in ops if "SCAN" in str(o.get("type")) or "READ_PARQUET" in str(o.get("type"))]
    windows = [o for _, o in ops if "WINDOW" in str(o.get("type"))]
    op_cpu = sum(float(o.get("timing") or 0) for _, o in ops)
    rows = sorted(ops, key=lambda x: -float(x[1].get("timing") or 0))[:top]
    return {
        "latency_s": round(float(q.get("total_time") or 0), 3),
        "cpu_s": round(float(q.get("cpu_time") or 0), 3),
        "plan_s": round(_plan_s(d), 4),
        "op_cpu_s": round(op_cpu, 3),
        "peak_buffer_mb": round(float(sysm.get("peak_buffer_memory") or 0) / 2**20, 1),
        "peak_temp_dir_mb": round(float(sysm.get("peak_temp_dir_size") or 0) / 2**20, 1),
        "blocked_thread_s": round(float(sysm.get("blocked_thread_time") or 0), 3),
        "io_read_mb": round(float(io.get("total_bytes_read") or 0) / 2**20, 1),
        "io_written_mb": round(float(io.get("total_bytes_written") or 0) / 2**20, 1),
        "rows_scanned": int(sum(int(o.get("rows_scanned") or 0) for o in scans)),
        "scan_out_rows": int(sum(int(o.get("intermediate_rows") or 0) for o in scans)),
        "n_scans": len(scans),
        "window_rows": int(sum(int(o.get("intermediate_rows") or 0) for o in windows)),
        "intermediate_rows": int(q.get("total_intermediate_rows") or 0),
        "top_ops": [{"op": str(o.get("type")), "depth": dep, "rows": int(o.get("intermediate_rows") or 0),
                     "cpu_s": round(float(o.get("timing") or 0), 3),
                     "share": round(float(o.get("timing") or 0) / op_cpu, 3) if op_cpu else 0.0,
                     "detail": _detail(o)} for dep, o in rows],
    }


class ProfilingCon:
    """Delegates to a DuckDB connection; after every execute of a non-trivial statement it reads the JSON profile
    (profiling_output) and appends {label, kind, wall_s, profile} to `records`. `label` is settable by callers
    (e.g. the Sigma group being run)."""

    TRIVIAL = ("SET ", "SELECT CURRENT_SETTING", "DROP ", "PRAGMA ")

    def __init__(self, con: duckdb.DuckDBPyConnection, prof_path: Path, min_wall_s: float = 0.05) -> None:
        self._con = con
        self._prof = prof_path
        self._min = min_wall_s
        self.records: list[dict[str, Any]] = []
        self.label = ""

    def execute(self, sql: str, *args: Any) -> Any:
        t0 = time.perf_counter()
        r = self._con.execute(sql, *args)
        dt = time.perf_counter() - t0
        s = sql.lstrip().upper()
        if not s.startswith(self.TRIVIAL) and dt >= self._min:
            self.records.append({"label": self.label, "kind": statement_kind(sql), "wall_s": round(dt, 3),
                                 "profile": summarise_profile(self._prof)})
        return r

    def __getattr__(self, name: str) -> Any:
        return getattr(self._con, name)


def statement_kind(sql: str) -> str:
    s = " ".join(sql.split())[:400]
    if "TEMP TABLE al_sg_v" in s:
        return "sigma_distinct_tuples"
    if "INSERT INTO al_sg_m" in s:
        return "sigma_predicates_on_tuples"
    if "INSERT INTO al_sigma_hits SELECT e." in s or ("INSERT INTO al_sigma_hits" in s and "FROM events e JOIN" in s):
        return "sigma_join_back"
    if "INSERT INTO al_sigma_hits" in s:
        return "sigma_direct_scan"
    if s.upper().startswith("SELECT COUNT(*) FROM EVENTS"):
        return "sigma_gate_count"
    if "al_sigma_a" in s or "al_sigma_x" in s or "al_sg_native" in s:
        return "sigma_post"
    return "other"
