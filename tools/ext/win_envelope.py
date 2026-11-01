"""Envelope facts of a JSON-lines Windows log file (before any pipeline run): rows, valid JSON rows, top-level keys,
hosts, channels, event ids, time span. Uses DuckDB, reads data only.
    python -I tools/ext/win_envelope.py FILE.json [FILE ...]
"""
from __future__ import annotations

import json
import sys

import duckdb


def q(con, sql):
    return con.execute(sql).fetchall()


def main() -> int:
    con = duckdb.connect()
    con.execute("SET TimeZone='UTC'")
    con.execute("SET memory_limit='2GB'")
    for path in sys.argv[1:]:
        p = path.replace("'", "''")
        con.execute(f"CREATE OR REPLACE TEMP VIEW l AS SELECT line FROM read_csv('{p}', columns={{'line':'VARCHAR'}}, "
                    "delim=CHR(1), quote='', escape='', header=false, auto_detect=false, max_line_size=67108864)")
        con.execute("CREATE OR REPLACE TEMP TABLE j AS SELECT line::JSON AS j FROM l WHERE json_valid(line)")
        rows = q(con, "SELECT count(*) FROM l")[0][0]
        valid = q(con, "SELECT count(*) FROM j")[0][0]
        keys = q(con, "SELECT k, count(*) n FROM (SELECT unnest(json_keys(j)) k FROM j) GROUP BY 1 ORDER BY 2 DESC LIMIT 60")
        def top(expr, n=20):
            return q(con, f"SELECT {expr} v, count(*) FROM j GROUP BY 1 ORDER BY 2 DESC LIMIT {n}")
        out = {
            "file": path, "rows": rows, "valid_json": valid,
            "top_keys": {k: n for k, n in keys},
            "hostname": top("coalesce(j->>'Hostname', j->>'Computer', j->'host'->>'name', j->'winlog'->>'computer_name', j->>'host')"),
            "channel": top("coalesce(j->>'Channel', j->'winlog'->>'channel')"),
            "event_id": top("coalesce(j->>'EventID', j->'winlog'->>'event_id', j->'event'->>'code')", 25),
            "ts_@timestamp": q(con, "SELECT min(j->>'@timestamp'), max(j->>'@timestamp'), count(j->>'@timestamp') FROM j"),
            "ts_UtcTime": q(con, "SELECT min(j->>'UtcTime'), max(j->>'UtcTime'), count(j->>'UtcTime') FROM j"),
            "ts_EventTime": q(con, "SELECT min(j->>'EventTime'), max(j->>'EventTime'), count(j->>'EventTime') FROM j"),
            "ts_TimeCreated": q(con, "SELECT min(j->>'TimeCreated'), max(j->>'TimeCreated'), count(j->>'TimeCreated') FROM j"),
        }
        print(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
