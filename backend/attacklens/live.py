"""Live mode (B-5): tail a folder every poll_s, ingest the delta, re-run Stages 2-7 on a bounded event-time window.

    python -m attacklens.live --watch data/raw/live --out data/out/live [--once] [--config DIR]

Per cycle with new data:
1. Tail every file by byte offset; only complete lines ('\\n'-terminated) are taken (offsets in tail_state.json).
2. Delta lines -> batch raw dir -> Stage 0 profile + Stage 1 ingest (the batch code, unchanged) -> batch Parquet.
3. Window Parquet = (previous window UNION batch) WHERE ts_ok AND ts_ms >= watermark - lookback (one DuckDB COPY).
   lookback = longest *_window_ms in rules.yaml (configurable), so every rule sees its full window.
4. Stages 2-7 (lookups ... publish) over the window into out_dir. Alerts are recomputed from the window each
   cycle, so an alert exists once per (rule, key, window) - no duplicates across cycles.
5. Incidents that ended before the window start are kept from the previous index (frozen), not dropped.
6. live_status.json heartbeat (read by GET /api/live/status).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attacklens import ingest, profile
from attacklens import run as batch
from attacklens.config import REPO_ROOT, load_config
from attacklens.context import RunContext
from attacklens.db import HIVE_TYPES, connect, register_events, sql_path

log = logging.getLogger("attacklens.live")

STATUS_FILE = "live_status.json"
LIVE_STAGES = batch.STAGES[2:]  # lookups, detect, episodes, link, incidents, publish


def _repo_path(p: str | Path) -> Path:
    p = Path(p)
    return (p if p.is_absolute() else REPO_ROOT / p).resolve()


def _iso_ms(ms: int | float | None) -> str | None:
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _write_json(path: Path, obj: Any) -> None:
    """Atomic write (tmp + replace) so the API never reads a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def longest_window_ms(rules: Any) -> int:
    """Max of every numeric *_window_ms value anywhere in rules.yaml."""
    best = 0
    stack = [rules]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool) and str(k).endswith("_window_ms"):
                    best = max(best, int(v))
                else:
                    stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
    return best


def _parquet_glob(d: Path) -> str | None:
    ev = d / "events"
    return (ev / "**" / "*.parquet").as_posix() if ev.exists() and any(ev.rglob("*.parquet")) else None


class Tailer:
    """Byte-offset tail of every file under watch_dir; returns only complete lines."""

    def __init__(self, watch: Path, state_file: Path, pcfg: dict[str, Any], max_read: int) -> None:
        self.watch, self.state_file, self.max_read = watch, state_file, max_read
        self.offsets: dict[str, int] = _read_json(state_file, {})
        self._pending: dict[str, int] = {}
        self.skip_names = set(pcfg.get("skip_names") or ["manifest.json"])
        self.skip_suffixes = tuple(pcfg.get("skip_suffixes") or [".md"])
        self.skip_dirs = set(pcfg.get("skip_dir_components") or ["ground_truth"])

    def _skip(self, p: Path) -> bool:
        rel = p.relative_to(self.watch)
        return (p.name in self.skip_names or p.name.endswith(self.skip_suffixes) or p.name.startswith(".")
                or bool(self.skip_dirs.intersection(rel.parts[:-1])))

    def poll(self) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        self._pending = {}
        if not self.watch.is_dir():
            return out
        for p in sorted(x for x in self.watch.rglob("*") if x.is_file()):
            if self._skip(p):
                continue
            rel = p.relative_to(self.watch).as_posix()
            off = self.offsets.get(rel, 0)
            size = p.stat().st_size
            if size < off:  # truncated / replaced -> start again
                log.warning("live: %s shrank (%d < %d); re-reading from 0", rel, size, off)
                off = 0
            if size == off:
                continue
            with p.open("rb") as fh:
                fh.seek(off)
                data = fh.read(min(size - off, self.max_read))
            cut = data.rfind(b"\n")
            if cut < 0:
                continue  # no complete line yet
            out[rel] = data[: cut + 1]
            self._pending[rel] = off + cut + 1
        return out

    def commit(self) -> None:
        """Advance offsets only after the batch was processed (a failed cycle re-reads the same bytes)."""
        self.offsets.update(self._pending)
        self._pending = {}
        _write_json(self.state_file, self.offsets)


class LiveEngine:
    def __init__(self, watch: Path, out: Path, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        self.lcfg: dict[str, Any] = cfg.get("live") or {}
        pipe = cfg.get("pipeline") or {}
        self.watch, self.out = watch, out
        state = self.lcfg.get("state_dir")
        self.state = _repo_path(state) if state else _repo_path(pipe.get("parquet_root", "data/parquet")) / out.name
        self.temp = _repo_path(pipe.get("temp_directory", "data/spill"))
        self.lookback = int(self.lcfg.get("lookback_ms") or longest_window_ms(cfg.get("rules")))
        self.lookback += int(self.lcfg.get("extra_lookback_ms") or 0)
        self.tailer = Tailer(watch, self.state / "tail_state.json", pipe.get("profile") or {},
                             int(self.lcfg.get("max_read_bytes", 256 * 2**20)))
        saved = _read_json(self.state / "live_state.json", {})
        self.batch_no = int(saved.get("batch_no", 0))
        self.window_name: str | None = saved.get("window")
        self.watermark: int | None = saved.get("watermark_ms")
        self.accounting: dict[str, dict[str, Any]] = saved.get("accounting", {})
        self.status: dict[str, Any] = {"enabled": True, "running": True, "pid": os.getpid(),
                                       "watch_dir": watch.as_posix(), "out_dir": out.as_posix(),
                                       "lookback_ms": self.lookback, "cycles": 0, "batches": self.batch_no,
                                       "rows": sum(a["rows_in"] for a in self.accounting.values()),
                                       "last_batch_ts": saved.get("last_batch_ts"), "last_cycle_s": None,
                                       "incidents": len(_read_json(out / "incidents_index.json", [])),
                                       "last_error": None}

    # ---- helpers -------------------------------------------------------------------------------------------
    def _con(self) -> Any:
        con = connect(memory_limit=str(self.lcfg.get("memory_limit", "1.5GB")), threads=self.lcfg.get("threads"),
                      temp_directory=self.temp)
        con.execute("SET enable_progress_bar=false")
        return con

    def _ingest_batch(self, con: Any, chunks: dict[str, bytes]) -> Path:
        self.batch_no += 1
        bdir = self.state / "batches" / f"b{self.batch_no:06d}"
        if bdir.exists():
            shutil.rmtree(bdir)
        raw = bdir / "raw"
        raw.mkdir(parents=True)
        for rel, data in chunks.items():
            (raw / rel.replace("/", "__")).write_bytes(data)
        bctx = RunContext(set_name=f"live-b{self.batch_no}", raw_dir=raw, parquet_dir=bdir / "pq",
                          out_dir=bdir / "meta", con=con, cfg=self.cfg)
        profile.run(bctx)
        ingest.run(bctx)
        for a in _read_json(bdir / "meta" / "ingest_accounting.json", []):
            acc = self.accounting.setdefault(a["source_type"], {"source_type": a["source_type"], "rows_in": 0,
                                                                 "rows_ok": 0, "dropped": 0, "drop_reasons": {}})
            for k in ("rows_in", "rows_ok", "dropped"):
                acc[k] += int(a.get(k) or 0)
            for r, n in (a.get("drop_reasons") or {}).items():
                acc["drop_reasons"][r] = acc["drop_reasons"].get(r, 0) + int(n)
        return bdir

    def _rebuild_window(self, con: Any, bdir: Path) -> tuple[Path, int | None, int, str | None]:
        """Add the batch to the window by moving its Parquet files (no rewrite), then drop whole event days that
        end before watermark - lookback. Returns (window dir, watermark ms, window rows, window start ISO)."""
        win = self.state / "window"
        ev = win / "events"
        ev.mkdir(parents=True, exist_ok=True)
        bglob = _parquet_glob(bdir / "pq")
        if bglob:
            bwm = con.execute(f"SELECT max(ts_ms) FROM read_parquet({sql_path(bglob)}, hive_partitioning=true, "
                              f"hive_types={HIVE_TYPES}) WHERE ts_ok").fetchone()[0]
            if bwm is not None:
                self.watermark = max(int(bwm), self.watermark or 0)
            src = bdir / "pq" / "events"
            for f in src.rglob("*.parquet"):
                rel = f.relative_to(src)
                if "ts_ok=true" not in rel.parts:  # unusable rows stay out (already counted in accounting)
                    continue
                dst = ev / rel.parent / f"b{self.batch_no:06d}_{f.name}"
                dst.parent.mkdir(parents=True, exist_ok=True)
                os.replace(f, dst)
        shutil.rmtree(bdir, ignore_errors=True)
        start_iso: str | None = None
        if self.watermark is not None:
            cutoff_day = _iso_ms(self.watermark - self.lookback)[:10]  # type: ignore[index]
            days = sorted({d.name.split("=", 1)[1] for d in ev.glob("*/*/event_day=*")})
            for d in ev.glob("*/*/event_day=*"):
                if d.name.split("=", 1)[1] < cutoff_day:
                    shutil.rmtree(d, ignore_errors=True)
            kept = [d for d in days if d >= cutoff_day]
            start_iso = f"{kept[0]}T00:00:00Z" if kept else None
        if sum(1 for _ in ev.rglob("*.parquet")) > int(self.lcfg.get("compact_max_files", 200)):
            self._compact(con, win)
        glob = _parquet_glob(win)
        rows = int(con.execute(f"SELECT count(*) FROM read_parquet({sql_path(glob)})").fetchone()[0]) if glob else 0
        self.window_name = "window"
        return win, self.watermark, rows, start_iso

    def _compact(self, con: Any, win: Path) -> None:
        """Rewrite the window into one file per partition (bounded file count)."""
        glob = _parquet_glob(win)
        if not glob:
            return
        tmp = self.state / "window.compact"
        shutil.rmtree(tmp, ignore_errors=True)
        con.execute(f"COPY (SELECT * FROM read_parquet({sql_path(glob)}, hive_partitioning=true, union_by_name=true, "
                    f"hive_types={HIVE_TYPES})) TO {sql_path(tmp / 'events')} "
                    f"(FORMAT PARQUET, PARTITION_BY (source_type, ts_ok, event_day))")
        shutil.rmtree(win / "events")
        os.replace(tmp / "events", win / "events")
        shutil.rmtree(tmp, ignore_errors=True)
        log.info("live: window compacted")

    def _frozen(self, cutoff_iso: str | None) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        """Previously published incidents that ended before the window start (kept as-is)."""
        if cutoff_iso is None:
            return []
        keep = []
        for row in _read_json(self.out / "incidents_index.json", []):
            if isinstance(row, dict) and str(row.get("last_ts", "")) < cutoff_iso:
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

    def _run_stages(self, con: Any, window: Path) -> dict[str, float]:
        ctx = RunContext(set_name=self.out.name, raw_dir=self.watch, parquet_dir=window, out_dir=self.out,
                         con=con, cfg=self.cfg)
        if _parquet_glob(window):
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
        _write_json(self.state / "live_state.json", {"batch_no": self.batch_no, "window": self.window_name,
                                                      "watermark_ms": self.watermark,
                                                      "accounting": self.accounting,
                                                      "last_batch_ts": self.status.get("last_batch_ts")})

    def write_status(self, **extra: Any) -> None:
        self.status.update(extra, updated_at=_now_iso())
        _write_json(self.out / STATUS_FILE, self.status)

    # ---- one cycle -------------------------------------------------------------------------------------------
    def cycle(self) -> bool:
        """Process whatever is new. Returns True if a batch was processed."""
        self.status["cycles"] += 1
        chunks = self.tailer.poll()
        if not chunks:
            self.write_status()
            return False
        t0 = time.perf_counter()
        con = self._con()
        try:
            bdir = self._ingest_batch(con, chunks)
            t_ing = time.perf_counter() - t0
            window, wm, wrows, cutoff_iso = self._rebuild_window(con, bdir)
            t_win = time.perf_counter() - t0 - t_ing
            frozen = self._frozen(cutoff_iso)
            walls = self._run_stages(con, window)
            n_inc = self._merge_frozen(frozen)
        except Exception as exc:
            log.exception("live: cycle failed")
            self.write_status(last_error=f"{type(exc).__name__}: {exc}")
            raise
        finally:
            con.close()
        self.tailer.commit()
        dt = round(time.perf_counter() - t0, 3)
        self.write_status(last_batch_ts=_now_iso(), batches=self.batch_no, last_cycle_s=dt,
                          ingest_s=round(t_ing, 3), window_s=round(t_win, 3), stage_wall_s=walls, watermark_ts=_iso_ms(wm),
                          window_start_ts=cutoff_iso, window_rows=wrows, incidents=n_inc, frozen=len(frozen),
                          rows=sum(a["rows_in"] for a in self.accounting.values()),
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
    ap.add_argument("--reset", action="store_true", help="forget tail offsets and window state first")
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
        shutil.rmtree(eng.state, ignore_errors=True)
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
