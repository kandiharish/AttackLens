# detect.py hook for native cloud detection (NOT applied)

`attacklens/detect_cloud.run_cloud(con, cfg, ctx)` writes `work/raw_alerts_cloud.parquet` with exactly the
`raw_alerts` columns (`detect_sql.RAW_ALERT_COLUMNS`). It never raises, and it is a no-op (it returns at once and
deletes a stale parquet) when the events contain no cloud rows.

Where: in `detect.run()`, after the `if ctx.siem_alerts: ...` block and BEFORE the loop that fills `per_rule`
from `al_raw`, so the cloud alerts are counted in `alerts_per_rule`, written to `raw_alerts.parquet` and seen by
`rule_host_baseline`. `sql_path` is already imported in detect.py (from detect_sql). The events view and
`detect_sql.prepare()` already exist at that point, so run_cloud reuses them.

```python
    from attacklens import detect_cloud  # native cloud rules (config/rules_cloud.yaml, config/cloud.yaml)
    cloud = detect_cloud.run_cloud(con, cfg, ctx)
    if cloud.get("parquet"): con.execute(f"INSERT INTO al_raw BY NAME SELECT * FROM read_parquet({sql_path(cloud['parquet'])})")
```

Optional 4th change (stats): add `"cloud": cloud` to the dict that `detect.run()` returns, so run_metrics.json shows
`cloud_rows`, `alerts_per_rule`, `capped_by_rule`, `errors`, `geo` and `wall_s`.

Run without the hook (end to end, after Stage 0 + 1 of a set):

```
.venv/Scripts/python -m attacklens.detect_cloud --work data/out/<set>/work [--events "data/parquet/<set>/events/**/*.parquet"]
```

Notes for the session that applies it:
- Cloud rule ids are not in `config/rules.yaml`. Any downstream code that looks a rule id up in rules.yaml
  (rule severity, relabel, harness per-rule tables) must tolerate unknown ids; the Sigma ids already are.
- Live mode: run_cloud rebuilds `cloud_ev` from the window every cycle; first-seen baselines therefore only see the
  live look-back (the persisted `data/state/cloud_baseline.parquet` from catalog §5 is not built yet).
- Planning cost: ~130 branch queries, about 10-12 s of fixed time per run on a small set (measured on
  data/raw/cloud_small: 11.2 s wall for 25 394 cloud rows). It does not grow with data volume.
