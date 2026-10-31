"""Live mode (B-5): tail a folder every poll_s, ingest the delta, re-run Stages 2-7 on a bounded event-time window.

    python -m attacklens.live --watch data/raw/live --out data/out/live [--once] [--reset] [--config DIR]

Per cycle with new data (one transaction: nothing is committed unless the stages succeed):
1. Tail every file by byte offset (live_tail.py); only complete lines; CSV chunks get their file's header.
2. Delta -> pending batch dir -> Stage 0 profile + Stage 1 ingest (batch code, unchanged) -> batch Parquet.
3. Robust watermark: rows with ts > now + max_future_skew_s are rejected (drop reason future_timestamp);
   batch watermark = p99 of the rest (max for small batches). lookback = max(rule *_window_ms, link *tau_ms).
4. Window (live_window.py): batch rows in [cutoff, now + skew] are added; whole event days before the cutoff
   are moved to trash (rows counted as pruned_outside_window), except days still holding the first step of an
   incident that is still open (last_ts >= cutoff), bounded by max_window_ms.
5. Stages 2-7 (lookups ... publish) over the window. Alerts are recomputed from the window every cycle, so an
   alert exists once per (rule, key, window). Success -> commit (window, accounting, offsets, watermark in one
   atomic live_state.json); failure -> rollback, and the same bytes are re-read next cycle (no double ingest).
6. Incidents entirely before the window start are kept from the previous index (frozen).
State lives in <parquet_root>/<out name>; it is discarded if it belongs to another watch/out dir. --reset also
clears this out dir's published incidents. live_status.json is the heartbeat (GET /api/live/status).
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attacklens import ingest, profile
from attacklens import live_window as lw
from attacklens import run as batch
from attacklens.config import REPO_ROOT, load_config
from attacklens.context import RunContext
from attacklens.db import connect, register_events
from attacklens.live_tail import Tailer
from attacklens.live_tail import read_json as _read_json
from attacklens.live_tail import write_json as _write_json

log = logging.getLogger("attacklens.live")

STATUS_FILE = "live_status.json"
PUBLISHED_FILES = (STATUS_FILE, "incidents_index.json", "ingest_accounting.json", "suppressed.json",
                   "run_metrics.json", "eval_scorecard.json", "source_profile.json")
LIVE_STAGES = batch.STAGES[2:]  # lookups, detect, episodes, link, incidents, publish
FUTURE_REASON = "future_timestamp (ts > now + max_future_skew_s; not used)"
DAY_MS = 86_400_000


def _repo_path(p: str | Path) -> Path:
    p = Path(p)
    return (p if p.is_absolute() else REPO_ROOT / p).resolve()


def _iso_ms(ms: int | float | None) -> str | None:
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def lookback_ms(cfg: dict[str, Any]) -> int:
    """Longest rule window or link window, so every rule and every link rule sees its full span."""
    lcfg = cfg.get("live") or {}
    base = lcfg.get("lookback_ms") or max(lw.longest_ms(cfg.get("rules"), ("_window_ms",)),
                                          lw.longest_ms(cfg.get("linking"), ("tau_ms",)))
    return int(base) + int(lcfg.get("extra_lookback_ms") or 0)


def _merge_acc(total: dict[str, dict[str, Any]], part: dict[str, dict[str, Any]]) -> None:
    for st, a in part.items():
        acc = total.setdefault(st, {"source_type": st, "rows_in": 0, "rows_ok": 0, "dropped": 0,
                                    "drop_reasons": {}, "pruned_outside_window": 0})
        for k in ("rows_in", "rows_ok", "dropped", "pruned_outside_window"):
            acc[k] = acc.get(k, 0) + int(a.get(k) or 0)
        for r, n in (a.get("drop_reasons") or {}).items():
            acc["drop_reasons"][r] = acc["drop_reasons"].get(r, 0) + int(n)


class LiveEngine:
    def __init__(self, watch: Path, out: Path, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        self.lcfg: dict[str, Any] = cfg.get("live") or {}
        pipe = cfg.get("pipeline") or {}
        self.watch, self.out = watch, out
        state = self.lcfg.get("state_dir")
        self.state = _repo_path(state) if state else _repo_path(pipe.get("parquet_root", "data/parquet")) / out.name
        self.window = self.state / "window"
        self.temp = _repo_path(pipe.get("temp_directory", "data/spill"))
        self.lookback = lookback_ms(cfg)
        saved = _read_json(self.state / "live_state.json", {})
        if saved and (saved.get("watch_dir"), saved.get("out_dir")) != (watch.as_posix(), out.as_posix()):
            log.warning("live: state in %s belongs to another watch/out dir; starting fresh", self.state)
            reset(self.state, out)  # its published incidents came from the other watch dir too
            saved = {}
        elif not saved:  # no committed batch: any window files are leftovers
            shutil.rmtree(self.state, ignore_errors=True)
        for leftover in ("batches", "trash"):  # transient dirs of a killed cycle
            shutil.rmtree(self.state / leftover, ignore_errors=True)
        sources = cfg.get("sources") or {}
        self.tailer = Tailer(watch, pipe.get("profile") or {}, int(self.lcfg.get("max_read_bytes", 256 * 2**20)),
                             lambda line: profile.sniff(line, sources).get("format") == "csv", saved.get("tail"))
        self.batch_no = int(saved.get("batch_no", 0))
        self.watermark: int | None = saved.get("watermark_ms")
        self.accounting: dict[str, dict[str, Any]] = saved.get("accounting", {})
        self.status: dict[str, Any] = {"enabled": True, "running": True, "pid": os.getpid(),
                                       "watch_dir": watch.as_posix(), "out_dir": out.as_posix(),
                                       "lookback_ms": self.lookback, "cycles": 0, "batches": self.batch_no,
                                       "rows": sum(a["rows_in"] for a in self.accounting.values()),
                                       "last_batch_ts": saved.get("last_batch_ts"), "last_cycle_s": None,
                                       "incidents": len(_read_json(out / "incidents_index.json", [])),
                                       "last_error": None}

    def _con(self) -> Any:
        con = connect(memory_limit=str(self.lcfg.get("memory_limit", "1.5GB")), threads=self.lcfg.get("threads"),
                      temp_directory=self.temp)
        con.execute("SET enable_progress_bar=false")
        return con

    def _ingest(self, con: Any, bdir: Path, chunks: dict[str, bytes], tag: str) -> dict[str, dict[str, Any]]:
        """Pending batch: raw chunks -> profile + ingest -> bdir/pq. Returns its accounting (not yet applied)."""
        raw = bdir / "raw"
        raw.mkdir(parents=True)
        for rel, data in chunks.items():
            (raw / rel.replace("/", "__")).write_bytes(data)
        bctx = RunContext(set_name=f"live-{tag}", raw_dir=raw, parquet_dir=bdir / "pq", out_dir=bdir / "meta",
                          con=con, cfg=self.cfg)
        profile.run(bctx)
        ingest.run(bctx)
        acc: dict[str, dict[str, Any]] = {}
        _merge_acc(acc, {a["source_type"]: a for a in _read_json(bdir / "meta" / "ingest_accounting.json", [])})
        return acc

    def _open_incident_day(self, cutoff_iso: str) -> str | None:
        """Earliest first_ts day of a published incident that is still open (last_ts >= cutoff)."""
        days = [str(r.get("first_ts", ""))[:10] for r in _read_json(self.out / "incidents_index.json", [])
                if isinstance(r, dict) and str(r.get("last_ts", "")) >= cutoff_iso and r.get("first_ts")]
        return min(days) if days else None

    def _frozen(self, start_iso: str | None) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        """Previously published incidents that ended before the window start (kept as-is)."""
        if start_iso is None or self.batch_no == 0:  # first batch: an existing index is not ours
            return []
        keep = []
        for row in _read_json(self.out / "incidents_index.json", []):
            if isinstance(row, dict) and str(row.get("last_ts", "")) < start_iso:
                inc = _read_json(self.out / "incidents" / f"{row['id']}.json", None)
                if isinstance(inc, dict):
                    keep.append((row, inc))
        return keep

    def _merge_frozen(self, frozen: list[tuple[dict[str, Any], dict[str, Any]]]) -> int:
        index = _read_json(self.out / "incidents_index.json", [])
        have = {r["id"] for r in index}
        added = [(r, inc) for r, inc in frozen if r["id"] not in have]
        if added:
            for r, inc in added:
                _write_json(self.out / "incidents" / f"{r['id']}.json", inc)
            index += [r for r, _ in added]
            index.sort(key=lambda x: (-(x.get("risk") or 0), x.get("first_ts", ""), x["id"]))
            _write_json(self.out / "incidents_index.json", index)
        return len(index)

    def _run_stages(self, con: Any) -> dict[str, float]:
        ctx = RunContext(set_name=self.out.name, raw_dir=self.watch, parquet_dir=self.window, out_dir=self.out,
                         con=con, cfg=self.cfg)
        if lw.parquet_glob(self.window):
            register_events(con, ctx.events_glob)
        walls: dict[str, float] = {}
        for name in LIVE_STAGES:
            fn = batch._load_stage(name, strict=False)
            if fn is None:
                continue
            t = time.perf_counter()
            fn(ctx)
            walls[name] = round(time.perf_counter() - t, 3)
        return walls

    def _save(self) -> None:
        _write_json(self.state / "live_state.json", {
            "batch_no": self.batch_no, "watch_dir": self.watch.as_posix(), "out_dir": self.out.as_posix(),
            "watermark_ms": self.watermark, "accounting": self.accounting, "tail": self.tailer.state(),
            "last_batch_ts": self.status.get("last_batch_ts")})

    def write_status(self, **extra: Any) -> None:
        self.status.update(extra, updated_at=_now_iso())
        _write_json(self.out / STATUS_FILE, self.status)

    def cycle(self) -> bool:
        """Process whatever is new as one transaction. Returns True if a batch was committed."""
        self.status["cycles"] += 1
        chunks = self.tailer.poll()
        if not chunks:
            self.write_status()
            return False
        t0 = time.perf_counter()
        tag = f"b{self.batch_no + 1:06d}"
        bdir = self.state / "batches" / tag
        shutil.rmtree(bdir, ignore_errors=True)
        txn = lw.WindowTxn(self.window, self.state / "trash")
        con = self._con()
        try:
            acc = self._ingest(con, bdir, chunks, tag)
            t_ing = time.perf_counter() - t0
            skew_ms = int(float(self.lcfg.get("max_future_skew_s", 300)) * 1000)
            limit = int(time.time() * 1000) + skew_ms
            bs = lw.batch_stats(con, bdir / "pq", limit, int(self.lcfg.get("watermark_min_rows", 100)))
            wm = max(w for w in (self.watermark, bs.watermark) if w is not None) \
                if (self.watermark is not None or bs.watermark is not None) else None
            for st, n in bs.future.items():
                a = acc[st]
                a["rows_ok"] -= n
                a["dropped"] += n
                a["drop_reasons"][FUTURE_REASON] = a["drop_reasons"].get(FUTURE_REASON, 0) + n
                log.warning("live: %d %s rows dated beyond now + %d s rejected", n, st, skew_ms // 1000)
            cutoff = (wm - self.lookback) if wm is not None else None
            late = txn.add_batch(con, bdir / "pq", tag, cutoff if cutoff is not None else 0, limit)
            if cutoff is not None:
                cutoff_iso = str(_iso_ms(cutoff))
                prune_day = cutoff_iso[:10]
                open_day = self._open_incident_day(cutoff_iso)
                floor_day = str(_iso_ms(wm - int(self.lcfg.get("max_window_ms", 7 * DAY_MS))))[:10]
                if open_day and open_day < prune_day:  # keep the early steps of incidents still open
                    prune_day = max(open_day, floor_day)
                txn.prune_before(con, prune_day)
            for st, n in [*late.items(), *txn.pruned.items()]:
                _merge_acc(acc, {st: {"pruned_outside_window": n}})
            start_iso = lw.kept_start_iso(self.window)
            t_win = time.perf_counter() - t0 - t_ing
            frozen = self._frozen(start_iso)
            walls = self._run_stages(con)
            n_inc = self._merge_frozen(frozen)
        except Exception as exc:
            log.exception("live: cycle failed; rolling back batch %s", tag)
            txn.rollback()
            self.write_status(last_error=f"{type(exc).__name__}: {exc}")
            con.close()
            shutil.rmtree(bdir, ignore_errors=True)
            raise
        # ---- commit: window, accounting, watermark, offsets (one atomic live_state.json) ----
        txn.commit()
        shutil.rmtree(bdir, ignore_errors=True)
        self.batch_no += 1
        self.watermark = wm
        _merge_acc(self.accounting, acc)
        self.tailer.commit()
        try:
            lw.compact(con, self.window, int(self.lcfg.get("compact_max_files", 200)))
            wrows = lw.count_rows(con, self.window)
        finally:
            con.close()
        dt = round(time.perf_counter() - t0, 3)
        self.write_status(last_batch_ts=_now_iso(), batches=self.batch_no, last_cycle_s=dt,
                          ingest_s=round(t_ing, 3), window_s=round(t_win, 3), stage_wall_s=walls,
                          watermark_ts=_iso_ms(wm), window_start_ts=start_iso, window_rows=wrows, incidents=n_inc,
                          frozen=len(frozen), rows=sum(a["rows_in"] for a in self.accounting.values()),
                          new_bytes=sum(len(b) for b in chunks.values()), last_error=None)
        self._save()
        _write_json(self.out / "ingest_accounting.json", sorted(self.accounting.values(),
                                                                 key=lambda a: a["source_type"]))
        log.info("live: batch %d: %d bytes, window %d rows, %d incidents in %.2f s",
                 self.batch_no, self.status["new_bytes"], wrows, n_inc, dt)
        return True

    def loop(self, poll_s: float) -> None:
        self.write_status()
        try:
            while True:
                t = time.monotonic()
                try:
                    self.cycle()
                except Exception:  # keep serving; error is in live_status.json
                    pass
                time.sleep(max(0.05, poll_s - (time.monotonic() - t)))
        except KeyboardInterrupt:
            log.info("live: stopped")
        finally:
            self.write_status(running=False, enabled=False)


def reset(state: Path, out: Path) -> None:
    """Forget tail offsets + window Parquet and remove this live out dir's published files (named files only)."""
    shutil.rmtree(state, ignore_errors=True)
    for d in ("incidents", "work"):
        shutil.rmtree(out / d, ignore_errors=True)
    for f in PUBLISHED_FILES:
        (out / f).unlink(missing_ok=True)
    log.info("live: reset state %s and outputs in %s", state, out)


def status(out_dir: str | Path | None = None, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Live status for the API: live_status.json of out_dir (default live.yaml out_dir); enabled only if fresh."""
    lcfg = (cfg if cfg is not None else load_config()).get("live") or {}
    out = Path(out_dir) if out_dir else _repo_path(lcfg.get("out_dir", "data/out/live"))
    st = _read_json(out / STATUS_FILE, None)
    if not isinstance(st, dict):
        return {"enabled": False}
    try:
        age = time.time() - datetime.fromisoformat(str(st.get("updated_at")).replace("Z", "+00:00")).timestamp()
    except ValueError:
        age = float("inf")
    stale = age > float(lcfg.get("status_stale_s", 10))
    return {**st, "enabled": bool(st.get("enabled")) and not stale, "stale": stale,
            "heartbeat_age_s": round(age, 1)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="attacklens.live", description="AttackLens live mode")
    ap.add_argument("--watch", help="folder to tail (default live.yaml watch_dir)")
    ap.add_argument("--out", help="output dir (default live.yaml out_dir)")
    ap.add_argument("--config", help="config directory")
    ap.add_argument("--once", action="store_true", help="run one cycle and exit")
    ap.add_argument("--reset", action="store_true",
                    help="start clean: forget tail offsets + window state and clear this out dir's incidents")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config(Path(a.config) if a.config else None)
    lcfg = cfg.get("live") or {}
    watch = _repo_path(a.watch or lcfg.get("watch_dir", "data/raw/live"))
    out = _repo_path(a.out or lcfg.get("out_dir", "data/out/live"))
    watch.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    eng = LiveEngine(watch, out, cfg)
    if a.reset:
        reset(eng.state, out)
        eng = LiveEngine(watch, out, cfg)
    log.info("live: watching %s -> %s (poll %.1f s, lookback %d ms, state %s)", watch, out,
             float(lcfg.get("poll_s", 2.0)), eng.lookback, eng.state)
    if a.once:
        eng.cycle()
        return 0
    eng.loop(float(lcfg.get("poll_s", 2.0)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
