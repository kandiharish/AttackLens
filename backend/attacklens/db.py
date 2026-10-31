"""DuckDB connection factory. Every connection in AttackLens goes through connect()."""

from __future__ import annotations

import os
from pathlib import Path

import duckdb


def connect(memory_limit: str = "5GB", threads: int | None = None,
            temp_directory: str | Path = "data/spill", database: str = ":memory:") -> duckdb.DuckDBPyConnection:
    Path(temp_directory).mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(database)
    con.execute("SET TimeZone='UTC'")
    con.execute(f"SET memory_limit='{memory_limit}'")
    con.execute(f"SET temp_directory='{Path(temp_directory).as_posix()}'")
    con.execute("SET preserve_insertion_order=false")
    con.execute(f"SET threads={int(threads or os.cpu_count() or 4)}")
    return con


def register_events(con: duckdb.DuckDBPyConnection, events_glob: str) -> None:
    """(Re)create the `events` view over the partitioned Parquet written by Stage 1."""
    con.execute(f"CREATE OR REPLACE VIEW events AS SELECT * FROM read_parquet('{events_glob}', "
                "hive_partitioning=true, union_by_name=true)")
