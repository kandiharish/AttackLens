"""Ingest-only probe for the robustness sweep: run stages profile + ingest on one raw dir, then report
source routing, accounting and per-column fill rates of the canonical events. Never runs detection.

usage: python tools/robust/ingest_only.py --raw data/raw/robust_<x>/<case> --out data/out/robust_<x>/<case>
       [--config data/snap/robust_cfg]   (default: the low-RAM sweep config, 512MB / 1 thread)
Prints one JSON object to stdout and writes it to <out>/ingest_probe.json.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

from attacklens import run as r  # noqa: E402
from attacklens.config import load_config  # noqa: E402
from attacklens.db import connect  # noqa: E402

SKIP_COLS = {"raw_line", "source_seq", "file_id", "ts_ok", "source_type"}


def probe(raw: Path, out: Path, config_dir: Path) -> dict:
    cfg = load_config(config_dir)
    pipe = cfg.get("pipeline") or {}
    out.mkdir(parents=True, exist_ok=True)
    pq = out / "parquet"
    con = connect(memory_limit=str(pipe.get("memory_limit", "512MB")), threads=pipe.get("threads") or 1,
                  temp_directory=r._repo_path(pipe.get("temp_directory", "data/spill")))
    ctx = r.RunContext(set_name=out.name, raw_dir=raw.resolve(), parquet_dir=pq, out_dir=out, con=con, cfg=cfg,
                       ground_truth=None, siem_alerts=False)
    res: dict = {"raw": raw.as_posix(), "stages": {}, "error": None}
    try:
        for name in ("profile", "ingest"):
            fn = r._load_stage(name, True)
            res["stages"][name] = r._call_stage(name, fn, ctx, {})
    except Exception as exc:  # noqa: BLE001 - the probe reports failures, it never hides them
        res["error"] = f"{type(exc).__name__}: {exc}"[:2000]
    for f in ("source_profile.json", "ingest_accounting.json"):
        p = out / f
        res[f.removesuffix(".json")] = json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    parts = sorted(pq.rglob("*.parquet")) if pq.exists() else []
    events = [p for p in parts if "events" in p.as_posix()]
    res["fill"] = {}
    if events:
        glob = (pq / "**" / "*.parquet").as_posix() if not (pq / "events").exists() else (pq / "events" / "**" / "*.parquet").as_posix()
        cols = [c[0] for c in con.execute(f"DESCRIBE SELECT * FROM read_parquet('{glob}', hive_partitioning=true)").fetchall()]
        n = con.execute(f"SELECT count(*) FROM read_parquet('{glob}', hive_partitioning=true)").fetchone()[0]
        res["rows_in_parquet"] = n
        if n:
            sel = ", ".join(f"count(\"{c}\")" for c in cols)
            vals = con.execute(f"SELECT {sel} FROM read_parquet('{glob}', hive_partitioning=true)").fetchone()
            res["fill"] = {c: round(v / n, 3) for c, v in zip(cols, vals) if c not in SKIP_COLS}
            res["ts_range_utc"] = list(con.execute(
                f"SELECT strftime(to_timestamp(min(ts_ms)/1000), '%Y-%m-%dT%H:%M:%SZ'), "
                f"strftime(to_timestamp(max(ts_ms)/1000), '%Y-%m-%dT%H:%M:%SZ') "
                f"FROM read_parquet('{glob}', hive_partitioning=true)").fetchone()) if "ts_ms" in cols else None
            if "source_type" in cols:
                res["source_types"] = dict(con.execute(
                    f"SELECT source_type, count(*) FROM read_parquet('{glob}', hive_partitioning=true) "
                    f"GROUP BY 1").fetchall())
    con.close()
    (out / "ingest_probe.json").write_text(json.dumps(res, indent=1, default=str), encoding="utf-8")
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--config", type=Path, default=REPO / "data" / "snap" / "robust_cfg")
    a = ap.parse_args()
    logging.basicConfig(level=logging.WARNING)
    print(json.dumps(probe(a.raw, a.out, a.config), indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
