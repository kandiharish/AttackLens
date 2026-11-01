"""Live window Parquet (used by live.py): add a batch, prune old days, compact. Every change is reversible until
commit, so a failed cycle never leaves a batch half-applied (a re-read would otherwise double-ingest it).

Layout: <state>/window/events/source_type=*/ts_ok=true/event_day=*/<file>.parquet (same as batch ingest).
"""

from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from attacklens.db import HIVE_TYPES, sql_path

log = logging.getLogger("attacklens.live")


def parquet_glob(d: Path) -> str | None:
    ev = d / "events"
    return (ev / "**" / "*.parquet").as_posix() if ev.exists() and any(ev.rglob("*.parquet")) else None


def _src(glob: str) -> str:
    return f"read_parquet({sql_path(glob)}, hive_partitioning=true, union_by_name=true, hive_types={HIVE_TYPES})"


def longest_ms(node: Any, suffixes: tuple[str, ...]) -> int:
    """Max numeric value whose key ends with one of `suffixes`, anywhere in a nested config."""
    best, stack = 0, [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool) and str(k).endswith(suffixes):
                    best = max(best, int(v))
                else:
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return best


@dataclass
class BatchStats:
    future: dict[str, int] = field(default_factory=dict)          # source_type -> rows beyond now + skew
    sample: list[int] = field(default_factory=list)               # <= sample_n usable ts_ms values


def batch_stats(con: Any, batch_dir: Path, limit_ms: int, sample_n: int) -> BatchStats:
    """Future-dated rows (ts > limit) are rejected; a reservoir sample of the rest feeds robust_watermark."""
    st = BatchStats()
    glob = parquet_glob(batch_dir)
    if not glob:
        return st
    for stype, n in con.execute(f"SELECT source_type, count(*) FROM {_src(glob)} WHERE ts_ok AND ts_ms > {limit_ms} "
                                f"GROUP BY 1").fetchall():
        st.future[str(stype)] = int(n)
    st.sample = [int(r[0]) for r in con.execute(
        f"SELECT ts_ms FROM (SELECT ts_ms FROM {_src(glob)} WHERE ts_ok AND ts_ms <= {limit_ms}) "
        f"USING SAMPLE reservoir({int(sample_n)} ROWS) REPEATABLE (42)").fetchall()]
    return st


def robust_watermark(prev: int | None, hist: list[int], batch: list[int], cfg: dict[str, Any]
                     ) -> tuple[int | None, list[int]]:
    """Watermark from a rolling sample of recent timestamps (across batches), never decreasing.

    - >= watermark_min_rows samples: candidate = p99 of the sample (one stray timestamp cannot move it), else max.
    - a jump of more than watermark_jump_ms beyond the previous watermark needs >= watermark_jump_min_rows sampled
      rows beyond that point; otherwise the far-ahead rows are ignored for the watermark (they are still ingested).
    Returns (watermark, new rolling sample).
    """
    n = int(cfg.get("watermark_sample", 1000))
    hist = [*hist, *batch][-n:]
    if not hist:
        return prev, hist
    ordered = sorted(hist)
    big = len(ordered) >= int(cfg.get("watermark_min_rows", 100))
    q = ordered[int(0.99 * (len(ordered) - 1))] if big else ordered[-1]
    if prev is not None:
        edge = prev + int(cfg.get("watermark_jump_ms", 3_600_000))
        if q > edge and sum(1 for t in hist if t > edge) < int(cfg.get("watermark_jump_min_rows", 5)):
            q = max((t for t in ordered if t <= edge), default=prev)
        q = max(prev, q)
    return q, hist


@dataclass
class WindowTxn:
    """Pending changes to the window; rollback() restores it exactly."""

    window: Path
    trash: Path
    added: list[Path] = field(default_factory=list)
    trashed: list[tuple[Path, Path]] = field(default_factory=list)   # (trash path, original path)
    pruned: dict[str, int] = field(default_factory=dict)             # source_type -> rows removed

    def add_batch(self, con: Any, batch_dir: Path, tag: str, lo_ms: int, hi_ms: int) -> dict[str, int]:
        """Write the batch rows with lo_ms <= ts <= hi_ms into the window (new files, prefixed by tag).
        Returns source_type -> rows older than lo_ms (late arrivals, never used)."""
        glob = parquet_glob(batch_dir)
        late: dict[str, int] = {}
        if not glob:
            return late
        for stype, n in con.execute(f"SELECT source_type, count(*) FROM {_src(glob)} WHERE ts_ok AND ts_ms < {lo_ms} "
                                    f"GROUP BY 1").fetchall():
            late[str(stype)] = int(n)
        tmp = batch_dir / "window_part"
        shutil.rmtree(tmp, ignore_errors=True)
        con.execute(f"COPY (SELECT * FROM {_src(glob)} WHERE ts_ok AND ts_ms BETWEEN {lo_ms} AND {hi_ms}) "
                    f"TO {sql_path(tmp)} (FORMAT PARQUET, PARTITION_BY (source_type, ts_ok, event_day), "
                    f"FILENAME_PATTERN '{tag}_{{i}}', OVERWRITE_OR_IGNORE)")
        ev = self.window / "events"
        for f in tmp.rglob("*.parquet"):
            dst = ev / f.relative_to(tmp)
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.replace(f, dst)
            self.added.append(dst)
        return late

    def prune_before(self, con: Any, day: str) -> None:
        """Move whole event_day partitions older than `day` (YYYY-MM-DD) to trash, counting their rows."""
        ev = self.window / "events"
        for d in sorted(ev.glob("*/*/event_day=*")):
            if d.name.split("=", 1)[1] >= day:
                continue
            stype = d.parent.parent.name.split("=", 1)[1]
            files = [f.as_posix() for f in d.glob("*.parquet")]
            if files:
                n = con.execute(f"SELECT count(*) FROM read_parquet({sql_path(d.as_posix() + '/*.parquet')})").fetchone()[0]
                self.pruned[stype] = self.pruned.get(stype, 0) + int(n)
            dst = self.trash / d.relative_to(ev)
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.replace(d, dst)
            self.trashed.append((dst, d))

    def rollback(self) -> None:
        for f in self.added:
            f.unlink(missing_ok=True)
        for dst, orig in reversed(self.trashed):
            orig.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                os.replace(dst, orig)
        shutil.rmtree(self.trash, ignore_errors=True)
        log.warning("live: window rolled back (%d files added, %d day partitions restored)",
                    len(self.added), len(self.trashed))

    def commit(self) -> None:
        shutil.rmtree(self.trash, ignore_errors=True)


def kept_start_iso(window: Path) -> str | None:
    days = sorted({d.name.split("=", 1)[1] for d in (window / "events").glob("*/*/event_day=*")})
    return f"{days[0]}T00:00:00Z" if days else None


def count_rows(con: Any, window: Path) -> int:
    glob = parquet_glob(window)
    return int(con.execute(f"SELECT count(*) FROM read_parquet({sql_path(glob)})").fetchone()[0]) if glob else 0


def compact(con: Any, window: Path, max_files: int) -> None:
    """Rewrite into one file per partition when the file count exceeds max_files (after commit only)."""
    ev = window / "events"
    if sum(1 for _ in ev.rglob("*.parquet")) <= max_files:
        return
    glob = parquet_glob(window)
    tmp = window.parent / "window.compact"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)  # DuckDB COPY creates only the last path component
    con.execute(f"COPY (SELECT * FROM {_src(glob)}) TO {sql_path(tmp / 'events')} "  # type: ignore[arg-type]
                f"(FORMAT PARQUET, PARTITION_BY (source_type, ts_ok, event_day))")
    old = window.parent / "window.old"
    shutil.rmtree(old, ignore_errors=True)
    os.replace(ev, old)
    try:
        os.replace(tmp / "events", ev)
    except OSError:
        os.replace(old, ev)  # put the uncompacted window back
        raise
    shutil.rmtree(old, ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)
    log.info("live: window compacted")


def recover(window: Path, trash: Path, committed: int) -> None:
    """Startup after a killed process: (1) files added by an uncommitted batch (tag b<n> with n > committed)
    are removed, (2) day partitions it moved to trash go back, (3) an interrupted compaction is undone."""
    ev, old = window / "events", window.parent / "window.old"
    for f in list(ev.rglob("b*_*.parquet")) if ev.exists() else []:
        tag = f.name.split("_", 1)[0][1:]
        if tag.isdigit() and int(tag) > committed:
            f.unlink(missing_ok=True)
            log.warning("live: removed uncommitted window file %s", f.name)
    if trash.exists():
        for d in sorted(trash.glob("*/*/event_day=*")):
            dst = ev / d.relative_to(trash)
            if not dst.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                os.replace(d, dst)
                log.warning("live: restored pruned partition %s from an uncommitted cycle", d.name)
        shutil.rmtree(trash, ignore_errors=True)
    if not ev.exists() and old.exists():
        window.mkdir(parents=True, exist_ok=True)
        os.replace(old, ev)
        log.warning("live: restored window from an interrupted compaction")
    for d in (old, window.parent / "window.compact"):
        shutil.rmtree(d, ignore_errors=True)
