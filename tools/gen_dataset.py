"""Synthetic dataset builder: wraps reports/edr_log_generator.py (never edits it).

TESTING.md §3.1. Per worker k: own slice of [start, start+days), simulated monotonic clock with
+/-30 % jitter, random.seed(seed + k), seeded uuid4, byte target size/workers, label stripping into
ground_truth/noise_alerts.jsonl. Writes part-<k>.jsonl, scenarios.jsonl, ground_truth/attacks.json,
manifest.json (layout: DEVELOPMENT.md §15.3).

Usage:
  python tools/gen_dataset.py --size 50M --workers 2 --out data/raw/g50m --force
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import logging
import math
import multiprocessing as mp
import random
import shutil
import sys
import time
import types
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("gen_dataset")

REPO = Path(__file__).resolve().parents[1]
DEFAULT_GENERATOR = REPO / "reports" / "edr_log_generator.py"
LABEL_KEYS = ("threat", "rule", "labels", "labels_extra")
BUF_BYTES = 1 << 20          # 1 MB write buffer
INITIAL_AVG_BYTES = 800.0    # first guess of bytes/event, re-estimated every RECAL events
RECAL = 64
JITTER = 0.30
TAIL_MARGIN = 8.0         # aim this many events short of the slice end so jitter never hits the clamp
ALL_SCENARIOS = ("S1", "S2", "S3", "S4", "S5")


# ----------------------------------------------------------------------------- parsing
def parse_size(text: str) -> int:
    """'50M' -> 52428800 (base 1024). Accepts K/M/G/T with optional B, or plain bytes."""
    s = text.strip().upper().removesuffix("B")
    mult = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}
    if s and s[-1] in mult:
        val = float(s[:-1]) * mult[s[-1]]
    else:
        val = float(s)
    if val <= 0 or not math.isfinite(val):
        raise ValueError(f"bad size {text!r}")
    return int(val)


def parse_start(text: str) -> int:
    """ISO-8601 (Z or offset) -> UTC epoch ms. Naive input is treated as UTC."""
    dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def load_generator(path: str | Path, name: str = "edr_log_generator") -> types.ModuleType:
    """Import the generator as a fresh module instance (never edits the file)."""
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load generator from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(BUF_BYTES), b""):
            h.update(chunk)
    return h.hexdigest()


# ----------------------------------------------------------------------------- clock
class SimClock:
    """Monotonic simulated clock in [lo, hi). Formats like the generator: 2026-10-24T00:00:00.000Z."""

    def __init__(self, lo_ms: int, hi_ms: int) -> None:
        self.lo, self.hi = lo_ms, hi_ms
        self.ms = lo_ms
        self._sec = -1
        self._prefix = ""

    def advance(self, step_ms: float) -> None:
        self.ms = min(self.hi - 1, self.ms + int(round(step_ms)))

    def iso(self) -> str:
        sec, milli = divmod(self.ms, 1000)
        if sec != self._sec:
            self._sec = sec
            self._prefix = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec))
        return f"{self._prefix}.{milli:03d}Z"


def install_patches(gen: types.ModuleType, clock: SimClock, rng: random.Random) -> None:
    """Point the generator's clock and uuid4 at seeded, simulated sources (module instance only)."""
    gen.now_iso = clock.iso

    def uuid4() -> uuid.UUID:
        return uuid.UUID(int=rng.getrandbits(128), version=4)

    gen.uuid = types.SimpleNamespace(uuid4=uuid4, UUID=uuid.UUID)


# ----------------------------------------------------------------------------- labels
def _first(v: Any) -> Any:
    return v[0] if isinstance(v, list) and v else v


def strip_labels(ev: dict, ts_ms: int) -> dict | None:
    """Remove generator ground truth from ev in place; return the noise record if it was an alert."""
    rec = None
    threat = ev.get("threat")
    if threat is not None:
        rec = {
            "ts_ms": ts_ms,
            "technique_id": _first(threat.get("technique", {}).get("id")),
            "tactic": _first(threat.get("tactic", {}).get("name")),
            "host": ev.get("host", {}).get("name"),
            "user": ev.get("user", {}).get("name"),
            "src_ip": ev.get("source", {}).get("ip"),
            "dst_ip": ev.get("destination", {}).get("ip"),
            "event_id": ev.get("event", {}).get("id"),
        }
    for k in LABEL_KEYS:
        ev.pop(k, None)
    e = ev.get("event")
    if isinstance(e, dict):
        e["kind"] = "event"
        e["severity"] = 0
    return rec


# ----------------------------------------------------------------------------- worker
def slice_bounds(start_ms: int, span_ms: int, workers: int, k: int) -> tuple[int, int]:
    return start_ms + span_ms * k // workers, start_ms + span_ms * (k + 1) // workers


def run_worker(job: dict) -> dict:
    """Generate one part file. job keys: k, workers, seed, start_ms, span_ms, target_bytes,
    alert_ratio, fmt, generator, out."""
    k, seed = job["k"], job["seed"]
    gen = load_generator(job["generator"], f"edr_log_generator_w{k}")
    lo, hi = slice_bounds(job["start_ms"], job["span_ms"], job["workers"], k)
    clock = SimClock(lo, hi)
    random.seed(seed + k)                                  # the generator uses the global random
    aux = random.Random(f"gen_dataset:{seed}:{k}")         # uuid + jitter, separate stream
    install_patches(gen, clock, aux)

    out = Path(job["out"])
    ext = "cef" if job["fmt"] == "cef" else "jsonl"
    part = out / f"part-{k}.{ext}"
    noise_tmp = out / "ground_truth" / f".noise-{k}.jsonl"
    target, ratio, fmt = job["target_bytes"], job["alert_ratio"], job["fmt"]
    render = gen.to_cef if fmt == "cef" else gen.to_json
    gen_alert, gen_benign = gen.gen_alert, gen.gen_benign
    rnd = random.random
    uni = aux.uniform

    written = events = alerts = 0
    step = (hi - lo) / max(1.0, target / INITIAL_AVG_BYTES)
    first_ms = last_ms = None
    buf = bytearray()
    h = hashlib.sha256()
    t0 = time.perf_counter()
    with open(part, "wb", buffering=0) as f, open(noise_tmp, "wb") as nf:
        while written < target:
            if events:
                clock.advance(step * uni(1 - JITTER, 1 + JITTER))
            ev = gen_alert() if rnd() < ratio else gen_benign()
            ts = clock.ms
            rec = strip_labels(ev, ts)
            if rec is not None:
                alerts += 1
                nf.write(json.dumps(rec, separators=(",", ":")).encode() + b"\n")
            line = render(ev).encode("utf-8") + b"\n"
            buf += line
            written += len(line)
            events += 1
            if first_ms is None:
                first_ms = ts
            last_ms = ts
            if len(buf) >= BUF_BYTES:
                f.write(buf)
                h.update(buf)
                buf.clear()
            if events % RECAL == 0:                        # re-aim the clock at the slice end
                remaining = (target - written) / (written / events)
                if remaining >= RECAL:                     # keep the step steady near the end
                    step = max(0.0, (hi - clock.ms) / (remaining + TAIL_MARGIN))
        if buf:
            f.write(buf)
            h.update(buf)
    wall = time.perf_counter() - t0
    return {"k": k, "file": part.name, "bytes": written, "events": events, "noise_alerts": alerts,
            "sha256": h.hexdigest(), "first_ts_ms": first_ms, "last_ts_ms": last_ms,
            "slice_ms": [lo, hi], "wall_s": round(wall, 3)}


# ----------------------------------------------------------------------------- driver
def _check_out(out: Path, force: bool) -> None:
    resolved = out.resolve()
    forbidden = {Path(resolved.anchor), REPO, REPO / "data", REPO / "data" / "raw", Path.home()}
    if resolved in forbidden:
        raise SystemExit(f"refusing to use {resolved} as --out")
    if resolved.exists() and any(resolved.iterdir()):
        if not force:
            raise SystemExit(f"--out {resolved} is not empty (use --force to replace it)")
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True, exist_ok=True)


def _scenario_ids(text: str) -> list[str]:
    t = text.strip()
    if t.lower() == "all":
        return list(ALL_SCENARIOS)
    if t.lower() in ("none", ""):
        return []
    ids = [s.strip().upper() for s in t.split(",") if s.strip()]
    bad = [s for s in ids if s not in ALL_SCENARIOS]
    if bad:
        raise SystemExit(f"unknown scenario ids {bad}")
    return ids


def write_scenarios(out: Path, start_ms: int, ids: list[str], generator: str, seed: int,
                    ioc_free: bool = True) -> int:
    """scenarios.jsonl + ground_truth/attacks.json. Returns the scenario event count."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import scenarios  # noqa: PLC0415  (tools/scenarios.py)

    events, attacks = scenarios.scenario_events(start_ms, ids=ids, generator=generator, seed=seed, ioc_free=ioc_free)
    with open(out / "scenarios.jsonl", "wb") as f:
        for ev in events:
            f.write(json.dumps(ev, separators=(",", ":")).encode("utf-8") + b"\n")
    with open(out / "ground_truth" / "attacks.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(attacks, f, indent=1)
    return len(events)


def build(args: argparse.Namespace) -> dict:
    t0 = time.perf_counter()
    out = Path(args.out)
    target = parse_size(args.size)
    start_ms = parse_start(args.start)
    span_ms = int(args.days * 86_400_000)
    workers = max(1, int(args.workers))
    if not (0.0 <= args.alert_ratio <= 1.0):
        raise SystemExit("--alert-ratio must be in [0, 1]")
    ids = _scenario_ids(args.scenarios)
    gen_path = str(Path(args.generator).resolve())
    _check_out(out, args.force)
    (out / "ground_truth").mkdir(exist_ok=True)

    per = -(-target // workers)                            # ceil: total >= target
    jobs = [{"k": k, "workers": workers, "seed": args.seed, "start_ms": start_ms, "span_ms": span_ms,
             "target_bytes": per, "alert_ratio": args.alert_ratio, "fmt": args.format,
             "generator": gen_path, "out": str(out)} for k in range(workers)]
    if workers == 1:
        parts = [run_worker(jobs[0])]
    else:
        with mp.get_context("spawn").Pool(workers) as pool:
            parts = pool.map(run_worker, jobs)
    parts.sort(key=lambda p: p["k"])

    noise_path = out / "ground_truth" / "noise_alerts.jsonl"
    with open(noise_path, "wb") as dst:
        for k in range(workers):
            tmp = out / "ground_truth" / f".noise-{k}.jsonl"
            with open(tmp, "rb") as src:
                shutil.copyfileobj(src, dst)
            tmp.unlink()

    ioc_free = not getattr(args, "ioc_scenarios", False)
    n_scen = write_scenarios(out, start_ms, ids, gen_path, args.seed, ioc_free) if ids else 0
    wall = time.perf_counter() - t0
    total = sum(p["bytes"] for p in parts)
    manifest = {
        "args": {"size": args.size, "out": str(args.out), "seed": args.seed, "workers": workers,
                 "start": args.start, "days": args.days, "alert_ratio": args.alert_ratio,
                 "format": args.format, "scenarios": args.scenarios, "generator": args.generator,
                 "ioc_scenarios": bool(getattr(args, "ioc_scenarios", False))},
        "scenario_ioc_free": ioc_free,
        "target_bytes": target,
        "start_ms": start_ms,
        "end_ms": start_ms + span_ms,
        "generator_sha256": sha256_file(Path(gen_path)),
        "parts": parts,
        "bytes": total,
        "events": sum(p["events"] for p in parts),
        "noise_alert_count": sum(p["noise_alerts"] for p in parts),
        "scenario_ids": ids,
        "scenario_events": n_scen,
        "wall_s": round(wall, 3),
        "mb_per_s": round(total / (1 << 20) / wall, 2) if wall > 0 else None,
    }
    with open(out / "manifest.json", "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=1)
    return manifest


def make_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Build a synthetic AttackLens dataset (TESTING.md §3).")
    p.add_argument("--size", required=True, help="total part bytes, e.g. 50M, 1G (base 1024)")
    p.add_argument("--out", required=True)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--start", default="2026-10-24T00:00:00Z")
    p.add_argument("--days", type=float, default=7.0)
    p.add_argument("--alert-ratio", type=float, default=0.0005)
    p.add_argument("--format", choices=["json", "cef"], default="json")
    p.add_argument("--scenarios", default="all", help="all | none | S1,S3,...")
    p.add_argument("--generator", default=str(DEFAULT_GENERATOR))
    p.add_argument("--force", action="store_true", help="delete a non-empty --out first")
    p.add_argument("--ioc-scenarios", action="store_true",
                   help="legacy: plant attacks on the config/ioc.yaml addresses (default: IOC-free addresses)")
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    m = build(make_parser().parse_args(argv))
    log.info("wrote %d bytes, %d events, %d noise alerts, scenarios=%s in %.1fs (%.1f MB/s)",
             m["bytes"], m["events"], m["noise_alert_count"], m["scenario_ids"], m["wall_s"],
             m["mb_per_s"] or 0)
    for p in m["parts"]:
        log.info("%s sha256=%s", p["file"], p["sha256"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
