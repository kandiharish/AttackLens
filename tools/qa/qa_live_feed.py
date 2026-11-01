"""QA live-mode latency benchmark (track qa_api): start `attacklens.live` on a private watch/out/config, append
FortiGate lines at a steady rate (one embedded brute-force-then-success), measure cycle times and the delay from
appending the success line to the incident being visible (out dir file, and optionally a private API), then stop it.

    .venv/Scripts/python tools/qa/qa_live_feed.py --root data/tmp/qa_api/live --lines 2000 --rate 20 \
        --api-port 8032 --json data/tmp/qa_api/live_result.json

Everything lives under --root (watch/, out/, cfg/ = copy of config/ with live.yaml state_dir under --root,
DuckDB memory_limit 1GB, threads 2, poll_s unchanged). Never touches data/raw/live or data/out/live.
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import qa_fglines  # noqa: E402


def make_config(root: Path, threads: int, mem: str) -> Path:
    cfg = root / "cfg"
    shutil.rmtree(cfg, ignore_errors=True)
    shutil.copytree(REPO / "config", cfg)
    live = yaml.safe_load((cfg / "live.yaml").read_text(encoding="utf-8")) or {}
    live.update(state_dir=(root / "state").as_posix(), memory_limit=mem, threads=threads)
    (cfg / "live.yaml").write_text(yaml.safe_dump(live, sort_keys=False), encoding="utf-8")
    pipe = (cfg / "pipeline.yaml").read_text(encoding="utf-8")
    pipe = pipe.replace('temp_directory: "data/spill"', f'temp_directory: "{(root / "spill").as_posix()}"')
    (cfg / "pipeline.yaml").write_text(pipe, encoding="utf-8")
    return cfg


def _read(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def has_bf(index: Any) -> str | None:
    for row in index or []:
        if isinstance(row, dict) and {"Credential Access", "Initial Access"} <= set(row.get("tactics") or []) \
                and qa_fglines.ATTACK_IP in str(row.get("entry_summary")):
            return str(row["id"])
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--lines", type=int, default=2000)
    ap.add_argument("--rate", type=float, default=20.0, help="lines per second")
    ap.add_argument("--fail-at", type=int, default=900, help="line index where the brute force starts")
    ap.add_argument("--n-fail", type=int, default=60)
    ap.add_argument("--threads", type=int, default=2)
    ap.add_argument("--mem", default="1GB")
    ap.add_argument("--api-port", type=int, default=None)
    ap.add_argument("--settle-s", type=float, default=90.0)
    ap.add_argument("--json", required=True)
    a = ap.parse_args()
    if a.api_port in (8000, 5173):
        raise SystemExit("refusing a shared port")
    root = Path(a.root).resolve()
    if REPO / "data" / "tmp" not in root.parents:
        raise SystemExit("--root must be under data/tmp")
    for d in ("watch", "out", "state", "spill"):
        shutil.rmtree(root / d, ignore_errors=True)
    (root / "watch").mkdir(parents=True)
    (root / "out").mkdir(parents=True)
    cfg = make_config(root, a.threads, a.mem)
    log = open(root / "live.log", "wb")  # noqa: SIM115
    proc = subprocess.Popen([sys.executable, "-m", "attacklens.live", "--watch", str(root / "watch"), "--out",
                             str(root / "out"), "--config", str(cfg), "--reset"], stdout=log, stderr=subprocess.STDOUT,
                            cwd=str(REPO / "backend"))
    status_p, index_p = root / "out" / "live_status.json", root / "out" / "incidents_index.json"
    stop = threading.Event()
    samples: list[dict[str, Any]] = []
    seen: dict[str, float] = {}
    status_polls: list[tuple[float, bool | None, float | None]] = []
    api_cli = httpx.Client(base_url=f"http://127.0.0.1:{a.api_port}", timeout=5) if a.api_port else None

    def monitor() -> None:
        last_batch = None
        while not stop.is_set():
            now = time.time()
            st = _read(status_p)
            if isinstance(st, dict) and st.get("batches") != last_batch:
                last_batch = st.get("batches")
                samples.append({"t": now, **{k: st.get(k) for k in ("batches", "cycles", "last_cycle_s", "ingest_s",
                                                                    "window_s", "stage_wall_s", "rows", "window_rows",
                                                                    "incidents", "new_bytes", "last_error")}})
            if "file" not in seen and has_bf(_read(index_p)):
                seen["file"] = now
            if api_cli is not None:
                try:
                    ls = api_cli.get("/api/live/status").json()
                    status_polls.append((now, bool(ls.get("enabled")), ls.get("heartbeat_age_s")))
                except (httpx.HTTPError, ValueError):
                    status_polls.append((now, None, None))
            if api_cli is not None and "api" not in seen:
                try:
                    if has_bf(api_cli.get("/api/incidents").json()):
                        seen["api"] = time.time()
                except (httpx.HTTPError, ValueError):
                    pass
            time.sleep(0.1)

    # wait for the engine heartbeat before feeding
    t_start = time.time()
    while not isinstance(_read(status_p), dict) and time.time() - t_start < 120:
        time.sleep(0.2)
    startup_s = round(time.time() - t_start, 2)
    mon = threading.Thread(target=monitor, daemon=True)
    mon.start()
    f = qa_fglines.formatter(11)
    watch = root / "watch" / "fortigate_live.log"
    appended: list[tuple[float, int]] = []
    t_success = None
    n_fail = 0
    i = 0
    per_tick = max(1, int(round(a.rate / 10)))
    t_feed0 = time.time()
    with open(watch, "ab", buffering=0) as fh:
        while i < a.lines:
            buf = []
            for _ in range(per_tick):
                if i >= a.lines:
                    break
                ms = int(time.time() * 1000)
                if a.fail_at <= i and n_fail < a.n_fail and (i - a.fail_at) % 2 == 0:
                    buf.append(qa_fglines.fail_line(f, ms))
                    n_fail += 1
                elif n_fail == a.n_fail and t_success is None:
                    buf.append(qa_fglines.success_line(f, ms))
                    t_success = -1.0  # set after the write
                else:
                    buf.append(qa_fglines.noise_line(f, ms, i))
                i += 1
            fh.write(("\n".join(buf) + "\n").encode())
            now = time.time()
            appended.append((now, i))
            if t_success == -1.0:
                t_success = now
            time.sleep(max(0.0, t_feed0 + len(appended) * 0.1 - time.time()))
    t_feed_end = time.time()
    # settle: all lines ingested and incident seen (or timeout)
    while time.time() - t_feed_end < a.settle_s:
        st = _read(status_p) or {}
        if st.get("rows", 0) >= a.lines and "file" in seen and ("api" in seen or api_cli is None):
            break
        time.sleep(0.2)
    time.sleep(0.5)
    stop.set()
    mon.join(timeout=5)
    final = _read(status_p) or {}
    acc = _read(root / "out" / "ingest_accounting.json") or []
    proc.terminate()  # Windows: TerminateProcess (no Ctrl+C); heartbeat goes stale after status_stale_s
    proc.wait(timeout=30)
    t_kill = time.time()
    stale_after = None
    if api_cli is not None:
        while time.time() - t_kill < 30:
            try:
                if api_cli.get("/api/live/status").json().get("enabled") is False:
                    stale_after = round(time.time() - t_kill, 1)
                    break
            except (httpx.HTTPError, ValueError):
                pass
            time.sleep(0.5)
    cycles = [s["last_cycle_s"] for s in samples if s.get("last_cycle_s") is not None]
    res = {
        "lines": a.lines, "rate_lps": a.rate, "n_fail": a.n_fail, "threads": a.threads, "memory_limit": a.mem,
        "startup_to_heartbeat_s": startup_s, "feed_s": round(t_feed_end - t_feed0, 2),
        "batches": final.get("batches"), "rows_final": final.get("rows"), "last_error": final.get("last_error"),
        "accounting": [{k: x.get(k) for k in ("source_type", "rows_in", "rows_ok", "dropped", "drop_reasons",
                                               "pruned_outside_window")} for x in acc],
        "cycle_s": {"n": len(cycles), "p50": round(statistics.median(cycles), 3) if cycles else None,
                    "p95": round(sorted(cycles)[int(0.95 * (len(cycles) - 1))], 3) if cycles else None,
                    "max": max(cycles) if cycles else None},
        "delay_success_to_incident_file_s": round(seen["file"] - t_success, 2) if "file" in seen and t_success else None,
        "delay_success_to_incident_api_s": round(seen["api"] - t_success, 2) if "api" in seen and t_success else None,
        "status_disabled_after_kill_s": stale_after,
        "incident_id": has_bf(_read(index_p)),
        "live_status_polls": len(status_polls),
        "live_status_disabled_while_running": sum(1 for _, en, _ in status_polls if en is False),
        "live_status_max_heartbeat_age_s": max((age for _, _, age in status_polls if age is not None), default=None),
        "samples": samples,
    }
    Path(a.json).write_text(json.dumps(res, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "samples"}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
