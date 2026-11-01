"""Synthetic micro-benchmarks for the Stage 2 operator patterns suspected of super-linear cost (no log data).

Each case keeps the ROW COUNT fixed and raises the DENSITY (rows per key per window), which is what changes
between the organiser's 10 GB and 30 GB sets (same 8 days, 3x the rows). A linear operator's time stays flat.

  A  count(DISTINCT u) OVER (PARTITION BY k ORDER BY ts RANGE BETWEEN CURRENT ROW AND w FOLLOWING)
     (detect_sql.window_bursts with a DISTINCT aggregate: password_spray / fw_admin_spray, port_scan, kerberoasting)
  B  the same frame with count(*) (non-DISTINCT; ransom_rename) and sum() (exfil_volume)
  C  equi-join on key + range predicate b.last <= s.ts <= b.last + w   (brute_force_then_success `cs`)
     vs ASOF JOIN on the same key (password_spray `bs`)
  D  the same windowed DISTINCT with a 300-char payload column carried through (raw_line in the window input)
  E  one partition, tied timestamps (timestamp pile-up) vs spread: count(DISTINCT) / count(*) RANGE frame

  python tools/perf/micro_window.py [--rows 4000000] [--threads 12] [--memory 5GB]
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import duckdb

REPO = Path(__file__).resolve().parents[2]


def timed(con: duckdb.DuckDBPyConnection, sql: str) -> float:
    t0 = time.perf_counter()
    con.execute(sql).fetchall()
    return round(time.perf_counter() - t0, 3)


def build(con: duckdb.DuckDBPyConnection, rows: int, keys: int, span_ms: int, users: int, payload: bool) -> None:
    pay = ", repeat('x', 300) AS raw_line" if payload else ""
    con.execute(f"""CREATE OR REPLACE TABLE t AS
        SELECT (hash(i) % {keys}) AS k, (hash(i * 7 + 1) % {span_ms})::BIGINT AS ts, i AS seq,
               'u' || (hash(i * 13 + 5) % {users}) AS u, (hash(i * 3) % 100000) AS b{pay}
        FROM range({rows}) r(i)""")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=4_000_000)
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--memory", default="5GB")
    ap.add_argument("--only-e", action="store_true", help="run only case E")
    ap.add_argument("--tied-sizes", type=lambda v: [int(x) for x in v.split(",")], default=[2000, 4000, 8000, 16000])
    ap.add_argument("--out", type=Path, default=REPO / "reports" / "perf" / "round0" / "micro_window.json")
    a = ap.parse_args(argv)
    con = duckdb.connect()
    con.execute(f"SET threads={a.threads}")
    con.execute(f"SET memory_limit='{a.memory}'")
    tmp = REPO / "data" / "tmp" / "perf" / "spill" / "micro"
    tmp.mkdir(parents=True, exist_ok=True)
    con.execute(f"SET temp_directory='{tmp.as_posix()}'")
    con.execute("SET preserve_insertion_order=false")
    win = 600_000          # 10 min frame (spray_window_ms)
    span = 12 * 3600_000   # the 30 GB burst day spans ~3.3 h; 12 h keeps the frame a small share of the span
    res: dict[str, list[dict[str, float]]] = {}
    if a.only_e:
        a.rows = 0
    # density x: the same rows over keys / x  -> rows per key per frame grows x-fold
    for case, payload in (() if a.only_e else (("A_distinct_range", False), ("D_distinct_range_payload", True))):
        res[case] = []
        for x in (1, 2, 4, 8):
            build(con, a.rows, max(1, 4000 // x), span, 200, payload)
            sel = ", max(raw_line) OVER (PARTITION BY k ORDER BY ts ROWS UNBOUNDED PRECEDING) AS l" if payload else ""
            t = timed(con, f"""SELECT count(*), sum(wv) FROM (SELECT count(DISTINCT u) OVER (PARTITION BY k ORDER BY ts
                               RANGE BETWEEN CURRENT ROW AND {win - 1} FOLLOWING) AS wv{sel} FROM t)""")
            fr = a.rows / max(1, 4000 // x) * win / span
            res[case].append({"density_x": x, "rows_per_frame": round(fr, 1), "s": t})
            print(case, x, round(fr, 1), t, flush=True)   # noqa: T201
    res["B_count_sum_range"] = []
    for x in (() if a.only_e else (1, 2, 4, 8)):
        build(con, a.rows, max(1, 4000 // x), span, 200, False)
        t1 = timed(con, f"""SELECT sum(wv) FROM (SELECT count(*) OVER (PARTITION BY k ORDER BY ts
                            RANGE BETWEEN CURRENT ROW AND {win - 1} FOLLOWING) AS wv FROM t)""")
        t2 = timed(con, f"""SELECT sum(wv) FROM (SELECT sum(b) OVER (PARTITION BY k ORDER BY ts
                            RANGE BETWEEN CURRENT ROW AND {win - 1} FOLLOWING) AS wv FROM t)""")
        res["B_count_sum_range"].append({"density_x": x, "count_s": t1, "sum_s": t2})
        print("B", x, t1, t2, flush=True)   # noqa: T201
    # C: bursts b (one per key per 30 min) x successes s (dense) joined on key + range
    res["C_range_join_vs_asof"] = []
    for x in (() if a.only_e else (1, 2, 4, 8)):
        keys = max(1, 4000 // x)
        build(con, a.rows, keys, span, 200, False)
        con.execute(f"""CREATE OR REPLACE TABLE b AS SELECT k, (ts // 1800000) * 1800000 AS last FROM t
                        GROUP BY ALL""")
        t1 = timed(con, f"""SELECT count(*) FROM b JOIN t s ON s.k = b.k AND s.ts >= b.last
                            AND s.ts - b.last <= 900000""")
        t2 = timed(con, """SELECT count(*) FROM b ASOF LEFT JOIN t s ON s.k = b.k AND s.ts >= b.last""")
        nb = con.execute("SELECT count(*) FROM b").fetchone()[0]
        res["C_range_join_vs_asof"].append({"density_x": x, "bursts": nb, "range_join_s": t1, "asof_s": t2})
        print("C", x, nb, t1, t2, flush=True)   # noqa: T201
    # E: ONE partition of n rows, timestamps all tied (the pile-up second: 15 distinct ts_ms for 26 M rows) vs
    # spread over 8 days; frame = RANGE CURRENT ROW .. 599999 FOLLOWING (spray_window_ms). Tied -> frame = rest of
    # the partition for every row.
    res["E_tied_vs_spread_one_partition"] = []
    for n in a.tied_sizes:
        row = {"n": n}
        for lab, ts in (("tied", "1000 + (i % 15)"), ("spread", f"(i * 691200000 // {n})")):
            con.execute(f"""CREATE OR REPLACE TABLE e AS SELECT {ts}::BIGINT AS ts, i AS seq,
                            'u' || (hash(i) % 950) AS u FROM range({n}) r(i)""")
            row[f"{lab}_distinct_s"] = timed(con, f"""SELECT sum(wv) FROM (SELECT count(DISTINCT u) OVER (ORDER BY ts
                RANGE BETWEEN CURRENT ROW AND {win - 1} FOLLOWING) AS wv FROM e)""")
            row[f"{lab}_count_s"] = timed(con, f"""SELECT sum(wv) FROM (SELECT count(*) OVER (ORDER BY ts
                RANGE BETWEEN CURRENT ROW AND {win - 1} FOLLOWING) AS wv FROM e)""")
        res["E_tied_vs_spread_one_partition"].append(row)
        print("E", row, flush=True)   # noqa: T201
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps({"rows": a.rows, "threads": a.threads, "memory": a.memory,
                                 "duckdb": duckdb.__version__, "cases": res}, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
