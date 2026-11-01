"""DuckDB connection factory. Every connection in AttackLens goes through connect()."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

import duckdb

# Longest line the DuckDB line reader accepts; longer lines are skipped (ingest counts them as line_too_long).
MAX_LINE_SIZE = 16_777_216

# Source-file pseudo-column of the CSV reader. Never `filename`: DuckDB matches column names case-insensitively, so
# a header with a FileName column (MDE, proxy, DLP exports) would raise a BinderException and abort the ingest.
SRC_FILE_COL = "__al_src_file"

# Partition columns are typed explicitly: hive inference would read ts_ok back as VARCHAR.
HIVE_TYPES = "{'source_type': 'VARCHAR', 'ts_ok': 'BOOLEAN', 'event_day': 'DATE'}"


def connect(memory_limit: str = "5GB", threads: int | None = None,
            temp_directory: str | Path = "data/spill", database: str = ":memory:") -> duckdb.DuckDBPyConnection:
    Path(temp_directory).mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(database)
    con.execute("SET TimeZone='UTC'")
    con.execute(f"SET memory_limit='{memory_limit}'")
    con.execute(f"SET temp_directory={sql_path(temp_directory)}")
    con.execute("SET preserve_insertion_order=false")
    con.execute(f"SET threads={int(threads or os.cpu_count() or 4)}")
    return con


def register_events(con: duckdb.DuckDBPyConnection, events_glob: str) -> None:
    """(Re)create the `events` view over the partitioned Parquet written by Stage 1."""
    con.execute(f"CREATE OR REPLACE VIEW events AS SELECT * FROM read_parquet({sql_path(events_glob)}, "
                f"hive_partitioning=true, union_by_name=true, hive_types={HIVE_TYPES})")


def sql_str(value: str) -> str:
    """Quote a Python string as a SQL string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def sql_list(values: Sequence[str]) -> str:
    return "[" + ", ".join(sql_str(v) for v in values) + "]"


def sql_path(path: str | Path) -> str:
    """A filesystem path (or glob) as a quoted SQL string literal: forward slashes, `'` doubled.

    Use for every path interpolated into SQL: f"read_parquet({sql_path(p)})".
    """
    return sql_str(Path(path).as_posix() if isinstance(path, Path) else str(path).replace("\\", "/"))


def line_reader(files: Sequence[str], filename: bool = True, rejects: str | None = None,
                encoding: str | None = None) -> str:
    """Table function reading files as one VARCHAR column `line` per physical line (no quoting, no parsing).

    - compression='none': DuckDB never gunzips by file extension. Stage 0 (cloud_unpack) decompresses, so profile
      (raw bytes) and ingest always read the same bytes; a compressed file left in place stays binary / unrecognized.
    - Empty lines come back as NULL; a UTF-8 BOM and CR/LF/CRLF endings (also mixed) are stripped.
    - Delimiter chr(1) (SOH, a control byte text logs never carry): the whole line lands in one column.
      NUL bytes (corrupt / preallocated tails) stay in the line, so a NUL run is a kept unparseable row and
      NUL inside JSON makes it malformed: both counted. A SOH byte truncates the line there (strict_mode=false).
      Never write delim='\\0' in SQL: DuckDB reads backslash + '0' and cut every line at JSON-escaped registry
      paths like ...\\\\LEGACY_X\\\\0000; delim=chr(0) would turn NUL runs into NULL and cut kv lines silently.
    - Lines that cannot be read (invalid UTF-8) are skipped by the reader; pass `rejects=<name>` to record
      them in temp tables <name>_err / <name>_scan (see count_rejects). Rejects tables hold every rejected
      line in memory, so for big line files count physical lines with encoding='latin-1' instead (every byte
      decodes, so nothing is skipped) and report the difference.
    """
    fn = ", filename=true" if filename else ""
    rj = (f", store_rejects=true, rejects_table={sql_str(rejects + '_err')}, "
          f"rejects_scan={sql_str(rejects + '_scan')}") if rejects else ""
    rj += f", encoding={sql_str(encoding)}" if encoding else ""
    return (f"read_csv({sql_list([str(f).replace(chr(92), '/') for f in files])}, columns={{'line': 'VARCHAR'}}, "
            f"header=false, delim=chr(1), quote='', escape='', auto_detect=false, max_line_size={MAX_LINE_SIZE}, "
            f"compression='none', "
            f"strict_mode=false, ignore_errors=true{fn}{rj})")


def count_rejects(con: duckdb.DuckDBPyConnection, rejects: str) -> list[tuple[str, str, int]]:
    """[(file_path, error_type, distinct rejected lines)] recorded by a reader created with rejects=<name>."""
    try:
        return [(str(f).replace("\\", "/"), str(e), int(n)) for f, e, n in con.execute(
            f"SELECT s.file_path, e.error_type, count(DISTINCT (e.scan_id, e.file_id, e.line)) "
            f"FROM {rejects}_err e JOIN {rejects}_scan s USING (scan_id, file_id) GROUP BY ALL").fetchall()]
    except duckdb.CatalogException:
        return []


def drop_rejects(con: duckdb.DuckDBPyConnection, rejects: str) -> None:
    con.execute(f"DROP TABLE IF EXISTS {rejects}_err")
    con.execute(f"DROP TABLE IF EXISTS {rejects}_scan")
