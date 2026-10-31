"""DuckDB connection factory. Every connection in AttackLens goes through connect()."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

import duckdb

# Partition columns are typed explicitly: hive inference would read ts_ok back as VARCHAR.
HIVE_TYPES = "{'source_type': 'VARCHAR', 'ts_ok': 'BOOLEAN', 'event_day': 'DATE'}"


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
                f"hive_partitioning=true, union_by_name=true, hive_types={HIVE_TYPES})")


def sql_str(value: str) -> str:
    """Quote a Python string as a SQL string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def sql_list(values: Sequence[str]) -> str:
    return "[" + ", ".join(sql_str(v) for v in values) + "]"


def line_reader(files: Sequence[str], filename: bool = True) -> str:
    """Table function reading files as one VARCHAR column `line` per physical line (no quoting, no parsing).

    Empty lines come back as NULL; a UTF-8 BOM and CRLF endings are stripped by the reader.
    Delimiter NUL never occurs in text logs, so the whole line lands in one column.
    """
    fn = ", filename=true" if filename else ""
    return (f"read_csv({sql_list(files)}, columns={{'line': 'VARCHAR'}}, header=false, delim='\0', "
            f"quote='', escape='', auto_detect=false, max_line_size=16777216{fn})")
