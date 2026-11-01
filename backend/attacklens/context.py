"""RunContext: everything a stage needs. Each stage module exposes `run(ctx: RunContext) -> dict` (its stats)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import duckdb


@dataclass
class RunContext:
    set_name: str
    raw_dir: Path            # data/raw/<set>
    parquet_dir: Path        # data/parquet/<set>   (events/ lives under it)
    out_dir: Path            # data/out/<set>       (published JSON)
    con: duckdb.DuckDBPyConnection
    cfg: dict[str, Any]
    ground_truth: Path | None = None
    siem_alerts: bool = False  # alert-input mode: detect unions the SIEM alert spool (never with ground_truth)
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def work_dir(self) -> Path:  # intermediate Parquet: data/out/<set>/work
        p = self.out_dir / "work"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def events_glob(self) -> str:
        return (self.parquet_dir / "events" / "**" / "*.parquet").as_posix()
