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
7. Alert-input mode (integrations.yaml alert_input.enabled): detect also unions the SIEM alert spool; a change in
   the spool alone (no new event bytes) triggers a stages-only cycle. live_status.json `inputs` records it.
State lives in <parquet_root>/<out name>; it is discarded if it belongs to another watch/out dir. --reset also
clears this out dir's published incidents. live_status.json is the heartbeat (GET /api/live/status).
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attacklens import ingest, profile
from attacklens import integrations as ig
from attacklens import live_incidents as li
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
        shutil.rmtree(self.state / "batches", ignore_errors=True)  # transient dir of a killed cycle
        lw.recover(self.state / "window", self.state / "trash", int(saved.get("batch_no", 0)))
        sources = cfg.get("sources") or {}
        self.tailer = Tailer(watch, pipe.get("profile") or {}, int(self.lcfg.get("max_read_bytes", 256 * 2**20)),
                             lambda line: profile.sniff(line, sources).get("format") == "csv", saved.get("tail"))
        self.batch_no = int(saved.get("batch_no", 0))
        self.watermark: int | None = saved.get("watermark_ms")
        self.wm_sample: list[int] = list(saved.get("watermark_sample") or [])
        self.frozen: li.Frozen = dict(saved.get("frozen") or {})
        self.accounting: dict[str, dict[str, Any]] = saved.get("accounting", {})
        self.alert_input = bool((ig.icfg(cfg).get("alert_input") or {}).get("enabled"))
        self.alert_sig: str | None = saved.get("alert_sig")
        self.status: dict[str, Any] = {"enabled": True, "running": True, "pid": os.getpid(),
                                       "watch_dir": watch.as_posix(), "out_dir": out.as_posix(),
                                       "lookback_ms": self.lookback, "cycles": 0, "batches": self.batch_no,
                                       "rows": sum(a["rows_in"] for a in self.accounting.values()),
                                       "last_batch_ts": saved.get("last_batch_ts"), "last_cycle_s": None,
                                       "incidents": len(_read_json(out / "incidents_index.json", [])),
                                       "last_error": None,
                                       "input_mode": "live+siem_alerts" if self.alert_input else "live",
                                       "inputs": {"raw_events": watch.as_posix(), "siem_alerts": self.alert_input,
                                                  "siem_alert_dir": ig.alerts_spool_dir(cfg).as_posix()
                                                  if self.alert_input else None}}

    def _con(self) -> Any:
        con = connect(memory_limit=str(self.lcfg.get("memory_limit", "1.5GB")), threads=self.lcfg.get("threads"),
                      temp_directory=self.temp)
        con.execute("SET enable_progress_bar=false")
        return con

    def _ingest(self, con: Any, bdir: Path, chunks: dict[str, bytes], tag: str) -> dict[str, dict[str, Any]]:
        """Pending batch: raw chunks -> profile + ingest -> bdir/pq. Returns its accounting (not yet applied)."""
        raw = bdir / "raw"
        raw.mkdir(parents=True)
        names = {}
        for i, (rel, data) in enumerate(sorted(chunks.items())):
            name = f"{i:05d}_{hashlib.sha1(rel.encode('utf-8')).hexdigest()[:8]}{Path(rel).suffix}"
            names[name] = rel
            (raw / name).write_bytes(data)
        _write_json(bdir / "chunk_map.json", names)  # chunk file -> watched path (outside raw/, never ingested)
        bctx = RunContext(set_name=f"live-{tag}", raw_dir=raw, parquet_dir=bdir / "pq", out_dir=bdir / "meta",
                          con=con, cfg=self.cfg)
        profile.run(bctx)
        ingest.run(bctx)
        acc: dict[str, dict[str, Any]] = {}
        _merge_acc(acc, {a["source_type"]: a for a in _read_json(bdir / "meta" / "ingest_accounting.json", [])})
        return acc

    def _run_stages(self, con: Any) -> dict[str, float]:
        ctx = RunContext(set_name=self.out.name, raw_dir=self.watch, parquet_dir=self.window, out_dir=self.out,
                         con=con, cfg=self.cfg, siem_alerts=self.alert_input)
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
            "last_batch_ts": self.status.get("last_batch_ts"), "alert_sig": self.alert_sig,
            "watermark_sample": self.wm_sample, "frozen": self.frozen})

    def write_status(self, **extra: Any) -> None:
        """Best effort: a heartbeat write failure is logged, never raised (write_json retries PermissionError)."""
        self.status.update(extra, updated_at=_now_iso())
        try:
            _write_json(self.out / STATUS_FILE, self.status)
        except OSError as exc:
            log.warning("live: cannot write %s: %s", STATUS_FILE, exc)

    def cycle(self) -> bool:
        """Process whatever is new as one transaction. Returns True if a batch was committed."""
        self.status["cycles"] += 1
        chunks = self.tailer.poll()
        sig = self._alert_sig()
        if not chunks:
            if self.tailer.has_pending():  # size/identity/rename updates only (no bytes consumed)
                self.tailer.commit()
                self._save()
            if sig != self.alert_sig:
                return self._alerts_cycle(sig)
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
            bs = lw.batch_stats(con, bdir / "pq", limit, int(self.lcfg.get("watermark_sample", 1000)))
            wm, wsample = lw.robust_watermark(self.watermark, self.wm_sample, bs.sample, self.lcfg)
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
                open_day = li.open_incident_day(self.out, cutoff_iso)
                floor_day = str(_iso_ms(wm - int(self.lcfg.get("max_window_ms", 7 * DAY_MS))))[:10]
                if open_day and open_day < prune_day:  # keep the early steps of incidents still open
                    prune_day = max(open_day, floor_day)
                txn.prune_before(con, prune_day)
            for st, n in [*late.items(), *txn.pruned.items()]:
                _merge_acc(acc, {st: {"pruned_outside_window": n}})
            start_iso = lw.kept_start_iso(self.window)
            t_win = time.perf_counter() - t0 - t_ing
            frozen = li.frozen_now(self.out, self.frozen, start_iso, self.batch_no == 0)
            walls = self._run_stages(con)
            n_inc = li.merge_frozen(self.out, frozen)
        except Exception as exc:
            log.exception("live: cycle failed; rolling back batch %s", tag)
            txn.rollback()
            self.write_status(last_error=f"{type(exc).__name__}: {exc}")
            con.close()
            shutil.rmtree(bdir, ignore_errors=True)
            raise
        # ---- commit: window, accounting, watermark, offsets, frozen (one atomic live_state.json) ----
        txn.commit()
        shutil.rmtree(bdir, ignore_errors=True)
        try:
            self.batch_no += 1
            self.watermark, self.wm_sample = wm, wsample
            self.alert_sig = sig
            self.frozen = frozen
            _merge_acc(self.accounting, acc)
            self.tailer.commit()
        finally:  # the window is already committed: the state that describes it must be saved
            self._save()
            self._write_accounting()
        post_err = self._post_commit(con)
        dt = round(time.perf_counter() - t0, 3)
        self.write_status(last_batch_ts=_now_iso(), batches=self.batch_no, last_cycle_s=dt,
                          ingest_s=round(t_ing, 3), window_s=round(t_win, 3), stage_wall_s=walls,
                          watermark_ts=_iso_ms(wm), window_start_ts=start_iso, window_rows=self.status.get("window_rows"),
                          incidents=n_inc, frozen=len(frozen), rows=sum(a["rows_in"] for a in self.accounting.values()),
                          new_bytes=sum(len(b) for b in chunks.values()), tail=self.tailer.counters,
                          last_error=post_err)
        self._save()  # last_batch_ts
        log.info("live: batch %d: %d bytes, window %s rows, %d incidents in %.2f s",
                 self.batch_no, self.status["new_bytes"], self.status.get("window_rows"), n_inc, dt)
        return True

    def _write_accounting(self) -> None:
        _write_json(self.out / "ingest_accounting.json", sorted(self.accounting.values(),
                                                                 key=lambda a: a["source_type"]))

    def _post_commit(self, con: Any) -> str | None:
        """Compaction + row count after the state is saved; a failure here is reported, never re-ingests."""
        err = None
        try:
            lw.compact(con, self.window, int(self.lcfg.get("compact_max_files", 200)))
        except Exception as exc:  # noqa: BLE001 - window is intact (compact restores it); report and go on
            log.exception("live: compaction failed")
            err = f"compaction: {type(exc).__name__}: {exc}"
        try:
            self.status["window_rows"] = lw.count_rows(con, self.window)
        except Exception as exc:  # noqa: BLE001
            err = err or f"count: {type(exc).__name__}: {exc}"
        finally:
            con.close()
        return err

    def _alert_sig(self) -> str | None:
        """Cheap change signature of the SIEM alert spool (names, sizes, mtimes); None when alert input is off."""
        if not self.alert_input:
            return None
        d = ig.alerts_spool_dir(self.cfg)
        files = sorted(p for p in d.rglob("*.jsonl") if not p.name.startswith(".")) if d.is_dir() else []
        key = "|".join(f"{p.as_posix()}:{p.stat().st_size}:{p.stat().st_mtime_ns}" for p in files)
        return hashlib.sha1(key.encode("utf-8")).hexdigest()

    def _alerts_cycle(self, sig: str | None) -> bool:
        """New SIEM alerts but no new event bytes: re-run Stages 2-7 over the unchanged window."""
        t0 = time.perf_counter()
        con = self._con()
        try:
            frozen = li.frozen_now(self.out, self.frozen, lw.kept_start_iso(self.window), self.batch_no == 0)
            walls = self._run_stages(con)
            n_inc = li.merge_frozen(self.out, frozen)
        except Exception as exc:
            log.exception("live: alerts-only cycle failed")
            self.write_status(last_error=f"{type(exc).__name__}: {exc}")
            raise
        finally:
            con.close()
        self.alert_sig = sig
        self.frozen = frozen
        self.write_status(last_alerts_cycle_ts=_now_iso(), last_cycle_s=round(time.perf_counter() - t0, 3),
                          stage_wall_s=walls, incidents=n_inc, last_error=None)
        self._save()
        log.info("live: alerts-only cycle: %d incidents", n_inc)
        return True

    def loop(self, poll_s: float) -> None:
        self.write_status()
        try:
            while True:
                t = time.monotonic()
                try:
                    self.cycle()
                except Exception as exc:  # keep serving; the error is recorded in live_status.json
                    log.exception("live: cycle error")
                    self.write_status(last_error=f"{type(exc).__name__}: {exc}")
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
