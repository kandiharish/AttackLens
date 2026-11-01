"""Print raw alerts and episodes of a run (for miss-cause analysis); reads run outputs only.
    python -I tools/ext/win_alerts.py data/out/ext_win_<name> [limit]
"""
import sys
import duckdb

out = sys.argv[1].rstrip("/")
lim = int(sys.argv[2]) if len(sys.argv) > 2 else 60
con = duckdb.connect()
con.execute("SET TimeZone='UTC'")
for f in ("raw_alerts", "episodes"):
    p = f"{out}/work/{f}.parquet"
    try:
        cols = [r[0] for r in con.execute(f"DESCRIBE SELECT * FROM read_parquet('{p}')").fetchall()]
    except Exception as e:
        print(f, "missing", e)
        continue
    want = [c for c in ("rule_id", "technique_id", "sub_technique_id", "tactic", "confidence", "ts_ms", "ts_first_ms",
                        "ts_last_ms", "host", "subject_host", "src_user", "target_user", "user", "src_ip", "dst_ip",
                        "raw_alert_count", "alert_count") if c in cols]
    print(f"== {f} ({len(cols)} cols): {cols}")
    tcol = next((c for c in ("ts_ms", "ts_first_ms") if c in want), None)
    sel = ", ".join((f"make_timestamp({c}::BIGINT*1000) AS {c}" if c.endswith("_ms") else c) for c in want)
    for r in con.execute(f"SELECT {sel} FROM read_parquet('{p}') ORDER BY {tcol or 1} LIMIT {lim}").fetchall():
        print(" ", r)
