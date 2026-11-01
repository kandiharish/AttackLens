"""Stage 2 (detect) per-rule scaling profiler.

Runs every detect rule ONE AT A TIME with the production code paths (attacklens.detect.rule_sql /
build_match_hits / relabel_without_context, attacklens.sigma_detect.run, attacklens.lookups.host_ip_map_sql) on a
connection from attacklens.db.connect with pipeline.yaml memory_limit / threads, and records per rule: wall,
rows in (slice rows, rows the rule's scans emit, rows through windows), alerts out, top DuckDB operators
(JSON profile = EXPLAIN ANALYZE), peak RSS, spill, CPU load of other jobs, free RAM. A rule whose run saw other
jobs above --max-load % CPU is repeated (up to --repeats) after waiting for a quieter box.

  slice: build an events slice under data/tmp/perf/slices/<name>/events (hive layout identical to Stage 1)
    --where "ts_ms // 1000 <> 1793330316"   row predicate (COPY; e.g. without the timestamp pile-up second)
    --days 2026-10-23,2026-10-24   whole event_day partitions, hard-linked (no copy)
    --keep 1/3                     nested hash sample hash(source_seq) % 3 < 1 (density scaling), COPY'd
  run:   profile one events root (a slice or a Stage 1 parquet dir, read-only) -> reports/perf/round0/<name>.json

The output JSON holds counts, timings, rule ids and operator names only (no log values).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from attacklens import detect, lookups, sigma_detect  # noqa: E402
from attacklens.config import load_config  # noqa: E402
from attacklens.db import HIVE_TYPES, connect  # noqa: E402
from attacklens.detect_sql import RAW_ALERT_COLUMNS, ensure_events, prepare, register_macros, sql_path  # noqa: E402

from perf_common import (Monitor, ProfilingCon, enable_profiling, idle_load, summarise_profile,  # noqa: E402
                         wait_for_quiet)

log = logging.getLogger("scale_detect")
TMP = REPO / "data" / "tmp" / "perf"
FORBIDDEN = ("data/out/n30", "data/out/n50", "data/parquet/n50", "data/out/_logs", "data/raw/n50")


def _guard_write(p: Path) -> None:
    s = p.resolve().as_posix().lower()
    for f in FORBIDDEN:
        if (REPO / f).resolve().as_posix().lower() in s:
            raise SystemExit(f"refusing to write under {f}: {p}")


def _guard_read(p: Path) -> None:
    s = p.resolve().as_posix().lower()
    for f in ("data/parquet/n50", "data/raw/n50", "data/out/n50"):
        if (REPO / f).resolve().as_posix().lower() in s:
            raise SystemExit(f"the 50 GB set is paused: {p}")


# ---------------------------------------------------------------- slicing

def make_slice(src: Path, name: str, days: list[str] | None, keep: tuple[int, int] | None,
               where: str | None = None) -> Path:
    _guard_read(src)
    dst = TMP / "slices" / name / "events"
    _guard_write(dst)
    if dst.exists() and any(dst.rglob("*.parquet")):
        log.info("slice %s exists", dst)
        return dst.parent
    files = sorted((src / "events").rglob("*.parquet"))
    if days:
        files = [f for f in files if any(f"event_day={d}" in f.as_posix() for d in days)]
    if not files:
        raise SystemExit("no files selected")
    if keep is None and not where:
        for f in files:
            rel = f.relative_to(src)
            t = dst.parent / rel
            t.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(f, t)
            except OSError:
                import shutil
                shutil.copy2(f, t)
        log.info("slice %s: %d files hard-linked", name, len(files))
        return dst.parent
    k, m = keep or (1, 1)
    pred = f"hash(source_seq) % {m} < {k}" + (f" AND ({where})" if where else "")
    cfg = load_config()
    ing = (cfg.get("pipeline") or {}).get("ingest") or {}
    con = connect(memory_limit=str((cfg.get("pipeline") or {}).get("memory_limit", "5GB")),
                  temp_directory=TMP / "spill" / f"slice_{name}")
    con.execute(f"SET partitioned_write_flush_threshold={int(ing.get('partitioned_write_flush_threshold', 16384))}")
    lst = "[" + ", ".join(sql_path(f) for f in files) + "]"
    dst.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    con.execute(f"""COPY (SELECT * FROM read_parquet({lst}, hive_partitioning=true, union_by_name=true,
                                               hive_types={HIVE_TYPES})
                    WHERE {pred})
                    TO {sql_path(dst)} (FORMAT PARQUET, PARTITION_BY (source_type, ts_ok, event_day),
                    COMPRESSION ZSTD, ROW_GROUP_SIZE {int(ing.get('row_group_size', 32768))})""")
    con.close()
    log.info("slice %s: %d/%d sample, where %s, written in %.1f s", name, k, m, where, time.perf_counter() - t0)
    return dst.parent


# ---------------------------------------------------------------- run

def fingerprint() -> dict[str, str]:
    """sha1[:10] of the config and Stage 2 code this run used (other sessions edit them during long batches)."""
    import hashlib
    files = sorted([*(REPO / "config").glob("*.yaml"), *(REPO / "backend" / "attacklens").glob("detect*.py"),
                    *(REPO / "backend" / "attacklens").glob("sigma*.py")])
    out = {f.name: hashlib.sha1(f.read_bytes()).hexdigest()[:10] for f in files}
    out["_all"] = hashlib.sha1("".join(out.values()).encode()).hexdigest()[:10]
    return out


def code_hashes() -> dict[str, str]:
    """Short content hashes of the detect code + config this run used (other sessions edit them concurrently)."""
    import hashlib
    names = ["config/rules.yaml", "config/pipeline.yaml", "config/sigma_map.yaml", "config/ioc.yaml"]
    names += sorted(p.relative_to(REPO).as_posix() for p in (REPO / "backend" / "attacklens").glob("detect*.py"))
    names += ["backend/attacklens/sigma_detect.py", "backend/attacklens/db.py"]
    return {n: hashlib.sha256((REPO / n).read_bytes()).hexdigest()[:12] for n in names if (REPO / n).exists()}


def _host_ip_map(con: Any, work: Path) -> float:
    p = work / "host_ip_map.parquet"
    if p.exists():
        return 0.0
    t0 = time.perf_counter()
    register_macros(con)
    con.execute(f"COPY ({lookups.host_ip_map_sql()}) TO {sql_path(p)} (FORMAT PARQUET)")
    return round(time.perf_counter() - t0, 3)


class Runner:
    def __init__(self, root: Path, name: str, out: Path, max_load: float, repeats: int, wait_s: float,
                 null_raw_line: bool = False) -> None:
        _guard_read(root)
        self.root, self.name, self.out = root, name, out
        self.max_load, self.repeats, self.wait_s = max_load, repeats, wait_s
        self.null_raw_line = null_raw_line
        self.min_repeat_s = 3.0   # shorter rules are not repeated (load noise is small next to their fit weight)
        self.cfg = load_config()
        self.pipe = self.cfg.get("pipeline") or {}
        self.work = TMP / "work" / name
        self.spill = TMP / "spill" / name
        self.prof = TMP / "prof" / name / "last.json"
        for p in (self.work, self.spill, self.prof.parent):
            _guard_write(p)
            p.mkdir(parents=True, exist_ok=True)
        self.res: dict[str, Any] = {"slice": name, "events_root": root.as_posix(), "rules": {}, "steps": {}}

    def save(self) -> None:
        self.out.parent.mkdir(parents=True, exist_ok=True)
        self.out.write_text(json.dumps(self.res, indent=1), encoding="utf-8")

    def _timed(self, mon: Monitor, label: str, fn: Any) -> dict[str, Any]:
        with mon.window() as w:
            t0 = time.perf_counter()
            extra = fn()
            wall = time.perf_counter() - t0
        rec = {"wall_s": round(wall, 3), **w, "profile": summarise_profile(self.prof)}
        if isinstance(extra, dict):
            rec.update(extra)
        log.info("%-28s %8.2f s  rss %6.0f MB  others %4.0f %%  free %5d MB", label, wall, rec.get("peak_rss_mb", 0),
                 rec.get("cpu_others_mean", -1), rec.get("free_ram_min_mb", -1))
        return rec

    def run(self, only: set[str] | None, sigma: bool) -> None:
        cfg, pipe = self.cfg, self.pipe
        threads = pipe.get("threads") or os.cpu_count()
        con = connect(memory_limit=str(pipe.get("memory_limit", "5GB")), threads=pipe.get("threads"),
                      temp_directory=self.spill)
        con.execute("SET enable_progress_bar=false")
        glob = (self.root / "events" / "**" / "*.parquet").as_posix()
        mon = Monitor(self.spill).start()
        self.res.update({"code_hashes": code_hashes(), "memory_limit": pipe.get("memory_limit", "5GB"),
                         "threads": threads,
                         "duckdb": __import__("duckdb").__version__, "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
                         "idle_before": idle_load(3.0), "fingerprint": fingerprint()})
        try:
            ensure_events(con, glob)
            if self.null_raw_line:   # experiment: the same production SQL without the raw_line payload
                con.execute("ALTER VIEW events RENAME TO al_perf_events_src")
                con.execute("CREATE VIEW events AS SELECT * REPLACE (NULL::VARCHAR AS raw_line) FROM al_perf_events_src")
                self.res["null_raw_line"] = True
            self.res["rows"] = int(con.execute("SELECT count(*) FROM events").fetchone()[0])
            self.res["rows_ok"] = int(con.execute("SELECT count(*) FROM events WHERE CAST(ts_ok AS BOOLEAN)")
                                      .fetchone()[0])
            self.res["rows_per_day"] = {str(d): int(n) for d, n in con.execute(
                "SELECT event_day, count(*) FROM events GROUP BY 1 ORDER BY 1").fetchall()}
            self.res["steps"]["lookups_host_ip_map_s"] = _host_ip_map(con, self.work)
            t0 = time.perf_counter()
            detect.validate(cfg)
            self.res["steps"]["validate_s"] = round(time.perf_counter() - t0, 3)
            t0 = time.perf_counter()
            prepare(con, cfg, self.work)
            self.res["steps"]["prepare_s"] = round(time.perf_counter() - t0, 3)
            rules, th = detect.rules_and_thresholds(cfg)
            cols = ", ".join(f"{c} {t}" for c, t in RAW_ALERT_COLUMNS.items())
            con.execute(f"CREATE OR REPLACE TEMP TABLE al_raw ({cols})")
            enable_profiling(con, self.prof)
            ioc = cfg.get("ioc") or {}
            rec = self._timed(mon, "match_scan", lambda: detect.build_match_hits(con, rules, ioc, th))
            rec["alerts"] = int(con.execute("SELECT count(*) FROM al_match_hits").fetchone()[0])
            self.res["steps"]["match_scan"] = rec
            self.save()
            for r in rules:
                rid = str(r["id"])
                if only and rid not in only:
                    continue
                self.res["rules"][rid] = self._rule(con, mon, r, th)
                self.save()
            if not only:
                ctx_ms = int(th.get("lateral_context_window_ms", 86400000))
                self.res["steps"]["relabel"] = self._timed(mon, "relabel", lambda: {"relabelled": sum(
                    detect.relabel_without_context(con, r, ctx_ms) for r in rules
                    if r.get("relabel_without_context"))})
            if sigma:
                self.res["sigma"] = self._sigma(con, mon, th)
                self.save()
            if not only:
                base = detect.baseline_sql(int(th.get("baseline_max_other_rules", 0)))
                self.res["steps"]["copy_raw_alerts"] = self._timed(mon, "copy_raw_alerts", lambda: con.execute(
                    f"COPY (SELECT {', '.join(RAW_ALERT_COLUMNS)} FROM al_raw) TO "
                    f"{sql_path(self.work / 'raw_alerts.parquet')} (FORMAT PARQUET)") and None)
                self.res["steps"]["baseline"] = self._timed(mon, "baseline", lambda: con.execute(
                    f"COPY ({base}) TO {sql_path(self.work / 'rule_host_baseline.parquet')} (FORMAT PARQUET)")
                    and None)
        finally:
            mon.stop()
            self.res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            self.save()
            con.close()

    def _rule(self, con: Any, mon: Monitor, r: dict[str, Any], th: dict[str, Any]) -> dict[str, Any]:
        rid = str(r["id"])
        attempts = []
        for i in range(1 + self.repeats):
            pre = idle_load(1.0) if i == 0 else wait_for_quiet(self.max_load, self.wait_s, log)
            con.execute("DELETE FROM al_raw WHERE rule_id = ?", [rid])
            t0 = time.perf_counter()
            sql = detect.rule_sql(con, r, th)
            build_s = time.perf_counter() - t0
            rec = self._timed(mon, rid, lambda: con.execute(f"INSERT INTO al_raw BY NAME {sql}") and None)
            rec.update({"attempt": i, "sql_build_s": round(build_s, 4), **{f"pre_{k}": v for k, v in pre.items()},
                        "alerts": int(con.execute("SELECT count(*) FROM al_raw WHERE rule_id = ?", [rid])
                                      .fetchone()[0])})
            attempts.append(rec)
            busy = max(rec.get("cpu_others_mean", 0), pre.get("cpu_idle_load", 0) if i == 0 else 0)
            if busy <= self.max_load or rec["wall_s"] < self.min_repeat_s:
                break
            log.warning("%s: others' load %.0f %% > %.0f %%: repeating", rid, busy, self.max_load)
        # min wall: a quieter-CPU attempt can still be slower (measured: RAM pressure from other jobs -> page faults)
        best = min(attempts, key=lambda a: a["wall_s"])
        return {"template": r.get("template") or r.get("kind"), **best,
                "attempts": [{k: a.get(k) for k in ("wall_s", "proc_cpu_s", "cpu_others_mean", "pre_cpu_idle_load",
                                                    "free_ram_min_mb", "peak_rss_mb")} for a in attempts]}

    def _sigma(self, con: Any, mon: Monitor, th: dict[str, Any]) -> dict[str, Any]:
        pc = ProfilingCon(con, self.prof)
        orig = sigma_detect._run_group

        def run_group(c: Any, gate: str, rules: list[dict[str, Any]], *a: Any) -> dict[str, Any]:
            pc.label = str(rules[0].get("logsource"))
            t0 = time.perf_counter()
            out = orig(c, gate, rules, *a)
            pc.records.append({"label": pc.label, "kind": "group_total", "wall_s": round(time.perf_counter() - t0, 3),
                               "n_rules": len(rules), "tuples": out.get("tuples"),
                               "matched_tuples": out.get("matched_tuples"), "mode": out.get("mode", "distinct")})
            return out

        sigma_detect._run_group = run_group   # runtime instrumentation of the production function (no copy)
        try:
            def go() -> dict[str, Any]:
                st = sigma_detect.run(pc, self.cfg, th, None)
                keep = ("sigma_alerts", "rows_matched", "load_s", "scan_s", "group_s", "batches", "sigma_wall_s")
                return {"stats": {**{k: v for k, v in st.items() if k in keep},
                                  "cache_key": (st.get("coverage") or {}).get("cache_key")}}
            rec = self._timed(mon, "sigma", go)
        finally:
            sigma_detect._run_group = orig
        rec["statements"] = pc.records
        return rec


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("slice")
    s.add_argument("--src", required=True, type=Path, help="Stage 1 parquet dir (contains events/)")
    s.add_argument("--name", required=True)
    s.add_argument("--days", default="all", help="comma list of event_day values, or all")
    s.add_argument("--keep", default=None, help="k/m nested hash sample of source_seq")
    s.add_argument("--where", default=None, help="extra SQL row predicate (e.g. drop a timestamp pile-up second)")
    r = sub.add_parser("run")
    r.add_argument("--parquet", required=True, type=Path, help="dir containing events/ (slice or Stage 1 dir)")
    r.add_argument("--name", required=True)
    r.add_argument("--out", type=Path, default=None)
    r.add_argument("--rules", default="", help="comma list of rule ids (default: all)")
    r.add_argument("--no-sigma", action="store_true")
    r.add_argument("--null-raw-line", action="store_true",
                   help="experiment: events.raw_line read as NULL (payload cost of the same SQL)")
    r.add_argument("--max-load", type=float, default=60.0)
    r.add_argument("--repeats", type=int, default=1)
    r.add_argument("--wait-s", type=float, default=600.0)
    a = ap.parse_args(argv)
    if a.cmd == "slice":
        days = None if a.days == "all" else [d.strip() for d in a.days.split(",") if d.strip()]
        keep = tuple(int(x) for x in a.keep.split("/")) if a.keep else None
        print(make_slice(a.src.resolve(), a.name, days, keep, a.where))   # noqa: T201 (CLI output: the slice dir)
        return 0
    out = a.out or REPO / "reports" / "perf" / "round0" / f"{a.name}.json"
    _guard_write(out)
    only = {x.strip() for x in a.rules.split(",") if x.strip()} or None
    Runner(a.parquet.resolve(), a.name, out, a.max_load, a.repeats, a.wait_s, a.null_raw_line).run(
        only, not a.no_sigma)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
