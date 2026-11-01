"""Log integrity / tamper-detection engine: are these logs genuine, or were they tampered with or corrupted?

Writes <out_dir>/integrity_report.json (schema_version 1) with a verdict (trusted < suspect < tampered), a
0..100 trust score and per-check findings. Checks, in report order:
  seal, zeroed_regions, truncated_tail          raw files (integrity_raw: one streaming pass per file)
  log_cleared, silence_gap, went_dark,          events view (integrity_sql: DuckDB aggregates only)
  timestamps, duplicates, embedded_time_mismatch
  ingest_drops                                  out_dir/ingest_accounting.json (integrity_drops)
Every threshold / pattern: config/integrity.yaml (cfg["integrity"]). One failing check is `skipped` with
reason `error: <ExcType>: <msg>`; the others still run.

CLI:
  python -m attacklens.integrity check --raw DIR --out DIR [--parquet DIR] [--seal FILE] [--config DIR]
                                       [--fail-on suspect|tampered]     exit 2 if verdict >= --fail-on
  python -m attacklens.integrity seal --raw DIR [--seal FILE]
Seal key: env ATTACKLENS_SEAL_KEY (HMAC-SHA256 when set, else SHA-256). The key is never written anywhere.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from attacklens import integrity_authenticity as iauth
from attacklens import integrity_raw as raw
from attacklens import integrity_sql as isql
from attacklens.config import REPO_ROOT, load_config
from attacklens.context import RunContext
from attacklens.db import connect, register_events
from attacklens.integrity_drops import check_ingest_drops  # re-exported as integrity.check_ingest_drops
from attacklens.integrity_raw import SEV_RANK, Skip

log = logging.getLogger("attacklens.integrity")

REPORT_NAME = "integrity_report.json"
SCHEMA_VERSION = 1
CHECK_IDS: tuple[str, ...] = ("seal", "zeroed_regions", "truncated_tail", "log_cleared", "silence_gap", "went_dark",
                              "timestamps", "duplicates", "embedded_time_mismatch", "ingest_drops")
VERDICTS: tuple[str, ...] = ("trusted", "suspect", "tampered")
DEFAULT_SEAL_REL = Path(".meta") / "integrity_seal.json"
# Fallbacks when config/integrity.yaml lacks a scalar (the YAML is the source of truth; values match it).
DEFAULTS: dict[str, Any] = {
    "severity_weights": {"critical": 40, "high": 20, "medium": 8, "low": 2}, "max_penalty_per_check": 40,
    "suspect_below": 70, "max_findings_per_check": 25, "evidence_max_chars": 300, "raw_scan": True,
    "drop_warn": 0.001, "drop_high": 0.05,
}

CheckResult = tuple[list[dict[str, Any]] | None, str | None]   # (findings, skip reason)


def _repo_path(p: str | Path) -> Path:
    p = Path(p)
    return p if p.is_absolute() else REPO_ROOT / p


def _icfg(cfg: dict[str, Any]) -> dict[str, Any]:
    return {**DEFAULTS, **(cfg.get("integrity") or {})}


def _guard(cid: str, fn: Callable[[], list[dict[str, Any]]]) -> CheckResult:
    t0 = time.perf_counter()
    try:
        fs = list(fn())
        log.info("integrity check %s: %d finding(s) in %.2f s", cid, len(fs), time.perf_counter() - t0)
        return fs, None
    except Skip as s:
        log.info("integrity check %s skipped: %s", cid, s)
        return None, str(s)
    except Exception as exc:  # one broken check never stops the others
        log.exception("integrity check %s failed", cid)
        return None, f"error: {type(exc).__name__}: {exc}"


def default_seal_path(raw_dir: Path) -> Path:
    return Path(raw_dir) / DEFAULT_SEAL_REL


def _seal_path(raw_dir: Path, c: dict[str, Any], override: Path | None) -> Path:
    if override is not None:
        return Path(override).resolve()
    return _repo_path(c["seal_path"]).resolve() if c.get("seal_path") else default_seal_path(raw_dir).resolve()


def _source_map(out_dir: Path) -> dict[str, str]:
    """rel path -> source_type from out_dir/source_profile.json (Stage 0), if present."""
    try:
        prof = json.loads((Path(out_dir) / "source_profile.json").read_text(encoding="utf-8"))
        return {f["rel"]: f["source_type"] for f in prof.get("files", []) if f.get("rel") and f.get("source_type")}
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


# --- raw part (runs on a worker thread while DuckDB runs the event checks) --------------------------------------

def _raw_part(raw_dir: Path, out_dir: Path, cfg: dict[str, Any], c: dict[str, Any],
              seal_file: Path) -> dict[str, Any]:
    res: dict[str, Any] = {"seal_section": {"status": "absent", "path": None, "keyed": False, "files_checked": 0,
                                            "modified": [], "missing": [], "added": []},
                           "files": [], "n_files": 0, "bytes": 0, "results": {}}
    if not raw_dir.is_dir():
        reason = f"raw dir not found: {raw_dir.as_posix()}"
        res["results"] = {k: (None, reason) for k in ("seal", "zeroed_regions", "truncated_tail")}
        return res
    pcfg = (cfg.get("pipeline") or {}).get("profile") or {}
    files = raw.list_files(raw_dir, pcfg, exclude={seal_file})
    res["n_files"], res["bytes"] = len(files), sum(p.stat().st_size for p in files)
    manifest, merr, key = None, None, None
    if seal_file.is_file():
        manifest, merr = raw.read_manifest(seal_file)
        key = raw.seal_key() if (manifest or {}).get("keyed") else None
    do_scan = bool(c.get("raw_scan", True))
    scans: list[raw.FileScan] = []
    if do_scan or seal_file.is_file():
        scans = raw.scan_files(raw_dir, files, c, key=key, nul_scan=do_scan)
    if do_scan:
        res["files"] = [s.report_entry() for s in scans if s.error is None]
        z, t = raw.raw_findings(scans, _source_map(out_dir))
        res["results"]["zeroed_regions"], res["results"]["truncated_tail"] = (z, None), (t, None)
    else:
        for k in ("zeroed_regions", "truncated_tail"):
            res["results"][k] = (None, "raw_scan disabled in config/integrity.yaml")
    if seal_file.is_file():
        section, fs = raw.verify_seal(manifest, merr, key, scans)
        res["seal_section"] = {**section, "path": seal_file.as_posix()}
        res["results"]["seal"] = (fs, None)
    else:
        res["results"]["seal"] = (None, "no seal manifest")
    return res


# --- scoring / report -----------------------------------------------------------------------------------------------

def _sort_key(f: dict[str, Any]) -> tuple[Any, ...]:
    return (-SEV_RANK[f["severity"]], -f["count"], CHECK_IDS.index(f["check"]) if f["check"] in CHECK_IDS else 99,
            f["title"], f["host"] or "", f["file"] or "", f["start_ts_ms"] or 0)


def _phrase(f: dict[str, Any]) -> str:
    where = (f" on {f['host']}" if f["host"] else "") + (f" in {f['file']}" if f["file"] else "")
    if not where and f["source_type"]:
        where = f" ({f['source_type']})"
    return f["title"] + where


def finalize(results: dict[str, CheckResult], c: dict[str, Any]) -> dict[str, Any]:
    """checks list, capped + sorted findings, trust score, verdict and summary from the per-check results."""
    weights = {**DEFAULTS["severity_weights"], **(c.get("severity_weights") or {})}
    cap, max_pen = int(c["max_findings_per_check"]), int(c["max_penalty_per_check"])
    checks, kept, everything = [], [], []
    penalty = 0
    for cid in CHECK_IDS:
        fs, reason = results.get(cid, (None, "not run"))
        if fs is None:
            checks.append({"id": cid, "status": "skipped", "findings": 0, "reason": reason or "skipped"})
            continue
        fs = sorted(fs, key=_sort_key)
        worst = max((SEV_RANK[f["severity"]] for f in fs), default=-1)
        status = "fail" if worst >= SEV_RANK["high"] else "warn" if worst >= 0 else "pass"
        checks.append({"id": cid, "status": status, "findings": len(fs), "reason": None})
        penalty += min(max_pen, sum(int(weights.get(f["severity"], 0)) for f in fs))
        if len(fs) > cap:
            log.info("integrity check %s: %d findings, %d cut from the report (max_findings_per_check=%d)",
                     cid, len(fs), len(fs) - cap, cap)
        kept += fs[:cap]
        everything += fs
    score = max(0, 100 - penalty)
    sev = {s: sum(1 for f in everything if f["severity"] == s) for s in SEV_RANK}
    verdict = ("tampered" if sev["critical"] else
               "suspect" if sev["high"] or score < int(c["suspect_below"]) else "trusted")
    kept.sort(key=_sort_key)
    if everything:
        counts = ", ".join(f"{sev[s]} {s}" for s in ("critical", "high", "medium", "low") if sev[s])
        summary = f"{verdict.upper()}: {counts} finding(s) — " + "; ".join(_phrase(f) for f in kept[:2])
    else:
        ran = sum(1 for ch in checks if ch["status"] != "skipped")
        summary = f"{verdict.upper()}: no findings in {ran} check(s) ({len(checks) - ran} skipped)"
    return {"verdict": verdict, "trust_score": int(score), "summary": summary, "checks": checks, "findings": kept}


def _events_ready(ctx: RunContext) -> tuple[set[str] | None, dict[str | None, int], str | None]:
    """(columns, rows per source_type, skip reason) for the `events` view, registering it if Parquet exists."""
    cols = isql.columns(ctx.con)
    if cols is None:
        events = Path(ctx.parquet_dir) / "events"
        if events.is_dir() and any(events.rglob("*.parquet")):
            register_events(ctx.con, ctx.events_glob)
            cols = isql.columns(ctx.con)
        if cols is None:
            return None, {}, f"no events view and no events Parquet under {events.as_posix()}"
    counts = isql.source_counts(ctx.con, cols)
    if not sum(counts.values()):
        return cols, counts, "events table is empty"
    return cols, counts, None


def _event_part(ctx: RunContext, c: dict[str, Any]) -> tuple[dict[str, CheckResult], int | None]:
    ids = ("log_cleared", "silence_gap", "went_dark", "timestamps", "duplicates", "embedded_time_mismatch")
    try:
        cols, counts, reason = _events_ready(ctx)
    except Exception as exc:
        log.exception("integrity: events view unusable")
        cols, counts, reason = None, {}, f"error: {type(exc).__name__}: {exc}"
    if reason is not None or cols is None:
        return {k: (None, reason) for k in ids}, (sum(counts.values()) if cols is not None else None)
    con = ctx.con
    now_ms = int(datetime.now(UTC).timestamp() * 1000)
    res: dict[str, CheckResult] = {"log_cleared": _guard("log_cleared", lambda: isql.check_log_cleared(con, cols, c))}
    info: dict[str, Any] = {}

    def _build() -> list[dict[str, Any]]:
        info.update(isql.build_buckets(con, cols, c))
        return []

    build = _guard("buckets", _build)
    if build[1] is not None:
        res["silence_gap"] = res["went_dark"] = build
    else:
        res["silence_gap"] = _guard("silence_gap", lambda: isql.check_silence_gap(con, info, c))
        res["went_dark"] = _guard("went_dark", lambda: isql.check_went_dark(con, info, c))
    res["timestamps"] = _guard("timestamps", lambda: isql.check_timestamps(con, cols, c, now_ms))
    res["duplicates"] = _guard("duplicates", lambda: isql.check_duplicates(con, cols, c, counts))
    res["embedded_time_mismatch"] = _guard("embedded_time_mismatch",
                                           lambda: isql.check_embedded_time(con, cols, c, counts))
    isql.drop_temp(con)
    return res, sum(counts.values())


def _authenticity(ctx: RunContext) -> dict[str, Any]:
    """Looks-generated block (full scope only). Informational: never changes verdict, score or summary."""
    try:
        return iauth.analyze(ctx.con, ctx.cfg)  # module attribute lookup at call time (monkeypatchable)
    except Exception as exc:  # a broken assessment never fakes a label
        log.exception("integrity: authenticity failed")
        return {"label": "unknown", "score": 0, "signals": [], "reason": f"error: {type(exc).__name__}: {exc}"}


def run_checks(ctx: RunContext, seal_path: Path | None = None) -> dict[str, Any]:
    """Run every check, write ctx.out_dir/integrity_report.json and return the report."""
    t0 = time.perf_counter()
    c = _icfg(ctx.cfg)
    raw_dir, out_dir = Path(ctx.raw_dir).resolve(), Path(ctx.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    seal_file = _seal_path(raw_dir, c, seal_path)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="integrity") as pool:
        fut = pool.submit(_raw_part, raw_dir, out_dir, ctx.cfg, c, seal_file)
        results, events_rows = _event_part(ctx, c)
        scope = "full" if any(r[0] is not None for r in results.values()) else "quick"  # any event check ran
        auth = _authenticity(ctx) if scope == "full" else None
        try:
            rawres = fut.result()
        except Exception as exc:
            log.exception("integrity: raw scan failed")
            reason = f"error: {type(exc).__name__}: {exc}"
            rawres = {"seal_section": {"status": "absent", "path": None, "keyed": False, "files_checked": 0,
                                       "modified": [], "missing": [], "added": []}, "files": [], "n_files": 0,
                      "bytes": 0, "results": {k: (None, reason) for k in ("seal", "zeroed_regions", "truncated_tail")}}
    results.update(rawres["results"])
    results["ingest_drops"] = _guard("ingest_drops", lambda: check_ingest_drops(
        out_dir, c, results.get("timestamps", (None, ""))[0] is not None))
    fin = finalize(results, c)
    report = {"schema_version": SCHEMA_VERSION, "set": ctx.set_name or out_dir.name, "generated_at": raw.utc_now_iso(),
              "scope": scope, "verdict": fin["verdict"], "trust_score": fin["trust_score"], "summary": fin["summary"],
              "checks": fin["checks"], "findings": fin["findings"], "seal": rawres["seal_section"],
              "files": rawres["files"], "authenticity": auth,
              "inputs": {"events_rows": events_rows, "files": rawres["n_files"], "bytes": rawres["bytes"]},
              "wall_s": round(time.perf_counter() - t0, 3)}
    (out_dir / REPORT_NAME).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    log.info("integrity: %s (score %d, %.1f s) -> %s", report["summary"], report["trust_score"], report["wall_s"],
             (out_dir / REPORT_NAME).as_posix())
    return report


def run(ctx: RunContext) -> dict[str, Any]:
    """Stage-compatible entry point: writes the report, returns its headline numbers."""
    rep = run_checks(ctx)
    return {"verdict": rep["verdict"], "trust_score": rep["trust_score"], "findings": len(rep["findings"]),
            "wall_s": rep["wall_s"]}


def check(raw_dir: Path, out_dir: Path, parquet_dir: Path | None = None, seal_path: Path | None = None,
          config_dir: Path | None = None) -> dict[str, Any]:
    """Build a RunContext like run.py (pipeline memory_limit / temp_directory, UTC) and run every check."""
    raw_dir = Path(raw_dir).resolve()
    if not raw_dir.is_dir():
        raise FileNotFoundError(f"raw dir not found: {raw_dir}")
    cfg = load_config(Path(config_dir) if config_dir else None)
    pipe = cfg.get("pipeline") or {}
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    pq = Path(parquet_dir).resolve() if parquet_dir else _repo_path(pipe.get("parquet_root", "data/parquet")) / out.name
    con = connect(memory_limit=str(pipe.get("memory_limit", "5GB")), threads=pipe.get("threads"),
                  temp_directory=_repo_path(pipe.get("temp_directory", "data/spill")))
    try:
        ctx = RunContext(set_name=out.name, raw_dir=raw_dir, parquet_dir=pq, out_dir=out, con=con, cfg=cfg)
        return run_checks(ctx, Path(seal_path) if seal_path else None)
    finally:
        con.close()


def seal(raw_dir: Path, seal_path: Path | None = None) -> dict[str, Any]:
    """Write the seal manifest (default <raw_dir>/.meta/integrity_seal.json) and return it."""
    raw_dir = Path(raw_dir).resolve()
    if not raw_dir.is_dir():
        raise FileNotFoundError(f"raw dir not found: {raw_dir}")
    cfg = load_config()
    c = _icfg(cfg)
    target = _seal_path(raw_dir, c, Path(seal_path) if seal_path else None)
    files = raw.list_files(raw_dir, (cfg.get("pipeline") or {}).get("profile") or {}, exclude={target})
    key = raw.seal_key()
    manifest = raw.build_manifest(raw.scan_files(raw_dir, files, c, key=key, nul_scan=False), key)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    log.info("integrity seal: %d file(s), %s -> %s", len(manifest["files"]), manifest["algo"], target.as_posix())
    return manifest


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # usage errors exit 1 (2 is reserved for --fail-on)
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(1)


def main(argv: list[str] | None = None) -> int:
    ap = _Parser(prog="attacklens.integrity", description="AttackLens log integrity / tamper detection")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pc = sub.add_parser("check", help="check raw logs (+ parsed events) and write integrity_report.json")
    pc.add_argument("--raw", required=True)
    pc.add_argument("--out", required=True)
    pc.add_argument("--parquet")
    pc.add_argument("--seal")
    pc.add_argument("--config")
    pc.add_argument("--fail-on", choices=("suspect", "tampered"))
    ps = sub.add_parser("seal", help="write a seal manifest of the raw directory")
    ps.add_argument("--raw", required=True)
    ps.add_argument("--seal")
    for p in (ap, pc, ps):
        p.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(a, "verbose", False) else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if not Path(a.raw).is_dir():
        log.error("raw dir not found: %s", a.raw)
        return 1
    if a.cmd == "seal":
        m = seal(Path(a.raw), Path(a.seal) if a.seal else None)
        sys.stdout.write(json.dumps({"files": len(m["files"]), "algo": m["algo"], "keyed": m["keyed"]}) + "\n")
        return 0
    rep = check(Path(a.raw), Path(a.out), Path(a.parquet) if a.parquet else None,
                Path(a.seal) if a.seal else None, Path(a.config) if a.config else None)
    sys.stdout.write(json.dumps({"verdict": rep["verdict"], "trust_score": rep["trust_score"],
                                 "summary": rep["summary"],
                                 "report": (Path(a.out).resolve() / REPORT_NAME).as_posix()}) + "\n")
    if a.fail_on and VERDICTS.index(rep["verdict"]) >= VERDICTS.index(a.fail_on):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
