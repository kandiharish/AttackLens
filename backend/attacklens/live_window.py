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
    watermark: int | None = None                                  # robust batch watermark (ms)
    future: dict[str, int] = field(default_factory=dict)          # source_type -> rows beyond now + skew
    late: dict[str, int] = field(default_factory=dict)            # source_type -> rows older than the cutoff


def batch_stats(con: Any, batch_dir: Path, limit_ms: int, min_rows_quantile: int) -> BatchStats:
    """Future-dated rows (ts > limit) are rejected; the batch watermark is p99 of the rest when the batch has
    >= min_rows_quantile rows (one bad timestamp cannot move it), else max."""
    st = BatchStats()
    glob = parquet_glob(batch_dir)
    if not glob:
        return st
    for stype, n in con.execute(f"SELECT source_type, count(*) FROM {_src(glob)} WHERE ts_ok AND ts_ms > {limit_ms} "
                                f"GROUP BY 1").fetchall():
        st.future[str(stype)] = int(n)
    n, mx, p99 = con.execute(f"SELECT count(*), max(ts_ms), quantile_disc(ts_ms, 0.99) FROM {_src(glob)} "
                             f"WHERE ts_ok AND ts_ms <= {limit_ms}").fetchone()
    if n:
        st.watermark = int(p99 if n >= min_rows_quantile else mx)
    return st


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
    con.execute(f"COPY (SELECT * FROM {_src(glob)}) TO {sql_path(tmp / 'events')} "  # type: ignore[arg-type]
                f"(FORMAT PARQUET, PARTITION_BY (source_type, ts_ok, event_day))")
    old = window.parent / "window.old"
    shutil.rmtree(old, ignore_errors=True)
    os.replace(ev, old)
    os.replace(tmp / "events", ev)
    shutil.rmtree(old, ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)
    log.info("live: window compacted")
