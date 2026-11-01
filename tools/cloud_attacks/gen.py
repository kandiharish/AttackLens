"""Generate a multi-cloud attack dataset with ground truth.

    python tools/cloud_attacks/gen.py --size small --out data/raw/cloud_small --seed 7
    python tools/cloud_attacks/gen.py --size 1G    --out data/raw/cloud1      --seed 7

Layout mirrors what the connectors spool (so Stage 0 routes by content exactly as in production):
    <out>/aws_cloudtrail/cloudtrail/part-*.jsonl
    <out>/azure_monitor/azure_signinlogs|azure_auditlogs|azure_azureactivity|azure_storagebloblogs/part-*.jsonl
    <out>/gcp_logging/gcp_audit/part-*.jsonl
    <out>/manifest.json
    <out>/ground_truth/attacks.json      (harness schema; stripped of any marker from the served events)

--size sets a byte target by scaling the benign baseline; the planted attacks and decoys are fixed, so they appear
identically in every size. Served records carry NO ground-truth field: labels live only in ground_truth/attacks.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Iterable

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[1]))   # tools/ on path so `cloud_attacks` imports when run as a script

from cloud_attacks import baseline, baseline_fixed, stories as st   # noqa: E402
from cloud_attacks.common import START_MS, Ev, iso_s   # noqa: E402

DAYS = 14
SIZES = {"small": 28 * 1024 * 1024, "1g": 1024 * 1024 * 1024}
MAX_PART_BYTES = 8 * 1024 * 1024

# feed -> (connector source folder, spool bucket folder)
FEED_DEST = {"cloudtrail": ("aws_cloudtrail", "cloudtrail"), "signin": ("azure_monitor", "azure_signinlogs"),
             "audit": ("azure_monitor", "azure_auditlogs"), "activity": ("azure_monitor", "azure_azureactivity"),
             "blob": ("azure_monitor", "azure_storagebloblogs"), "gcp": ("gcp_logging", "gcp_audit")}


def line(ev: Ev) -> str:
    # exactly how connectors/base.py serializes an event doc (no sort_keys; insertion order is deterministic)
    return json.dumps(ev.doc, ensure_ascii=False, default=str)


def byte_len(evs: Iterable[Ev]) -> int:
    return sum(len(line(e).encode("utf-8")) + 1 for e in evs)


def fixed_events(seed: int) -> list[Ev]:
    """Planted attacks + explicit decoys + the fixed-volume benign automation (size-independent)."""
    out: list[Ev] = []
    for story in st.build_stories(seed):
        out += story.events()
    for decoy in st.build_decoys(seed):
        out += decoy.events
    for day in range(DAYS):
        out += baseline_fixed.fixed_daily(seed, day)
        for hour in range(24):
            out += baseline_fixed.fixed_hourly(seed, day, hour)
    return out


def baseline_events(seed: int, scale: float) -> list[Ev]:
    out: list[Ev] = []
    if scale <= 0:
        return out
    for day in range(DAYS):
        for hour in range(24):
            out += baseline.benign_hour(seed, scale, day, hour)
    return out


def pick_scale(seed: int, target: int) -> tuple[float, int, int]:
    """Choose a baseline scale so total bytes approach target. Counts are ~linear in scale."""
    bf = byte_len(fixed_events(seed))
    b1 = byte_len(baseline_events(seed, 1.0))
    scale = max(0.0, (target - bf) / b1) if b1 else 0.0
    return round(scale, 4), bf, b1


def generate(seed: int, scale: float) -> list[Ev]:
    evs = fixed_events(seed) + baseline_events(seed, scale)
    evs.sort(key=lambda e: (e.ts, e.feed, e.rid))
    return evs


def _sha256_self() -> str:
    h = hashlib.sha256()
    for p in sorted(_HERE.parent.glob("*.py")):
        h.update(p.read_bytes())
    return h.hexdigest()


def write(out: Path, seed: int, size: str, force: bool) -> dict:
    target = SIZES[size.lower()]
    if out.exists():
        if not force and any(out.iterdir()):
            raise SystemExit(f"refusing to write into non-empty {out} (use --force)")
        shutil.rmtree(out)
    out.mkdir(parents=True)

    t0 = time.time()
    scale, bf, b1 = pick_scale(seed, target)
    evs = generate(seed, scale)

    # bucket events by destination folder, write rotated part files, record per-feed byte / event counts
    by_dest: dict[tuple[str, str], list[Ev]] = {}
    for e in evs:
        by_dest.setdefault(FEED_DEST[e.feed], []).append(e)
    parts, total_bytes = [], 0
    for (source, bucket), items in sorted(by_dest.items()):
        d = out / source / bucket
        d.mkdir(parents=True, exist_ok=True)
        seq, buf, nbytes, nrows = 0, [], 0, 0

        def flush() -> None:
            nonlocal seq, buf, nbytes, nrows, total_bytes
            if not buf:
                return
            seq += 1
            p = d / f"part-{seq:04d}.jsonl"
            data = "".join(buf)
            p.write_text(data, encoding="utf-8", newline="")
            parts.append({"source_type": source, "bucket": bucket, "file": p.relative_to(out).as_posix(),
                          "events": nrows, "bytes": len(data.encode("utf-8"))})
            total_bytes += len(data.encode("utf-8"))
            buf, nbytes, nrows = [], 0, 0

        for e in items:
            ln = line(e) + "\n"
            b = len(ln.encode("utf-8"))
            if nbytes + b > MAX_PART_BYTES and buf:
                flush()
            buf.append(ln)
            nbytes += b
            nrows += 1
        flush()

    stories = st.build_stories(seed)
    decoys = st.build_decoys(seed)
    gt = {"attack_version": "v20", "anchor_ms": START_MS, "anchor": iso_s(START_MS),
          "generated_by": "tools/cloud_attacks/gen.py", "seed": seed, "size": size,
          "note": "Stratus Red Team (Apache-2.0) + public incident write-ups; all IPs RFC 5737 / RFC 1918.",
          "attacks": [s.gt() for s in stories],
          "decoys": [d.gt() for d in decoys] + st.RECURRING_DECOYS}
    (out / "ground_truth").mkdir(exist_ok=True)
    (out / "ground_truth" / "attacks.json").write_text(json.dumps(gt, indent=1), encoding="utf-8")

    manifest = {
        "generator": "tools/cloud_attacks/gen.py", "generator_sha256": _sha256_self(),
        "seed": seed, "size": size, "target_bytes": target, "baseline_scale": scale,
        "fixed_bytes_estimate": bf, "baseline_bytes_at_scale1": b1,
        "days": DAYS, "start_ms": START_MS, "start": iso_s(START_MS),
        "end": iso_s(START_MS + DAYS * 86_400_000),
        "total_events": len(evs), "total_bytes": total_bytes,
        "parts": parts,
        "feeds": sorted({f"{s}/{b}" for s, b in by_dest}),
        "attacks": [{"id": s.id, "name": s.name, "clouds": list(s.clouds), "novel": s.novel,
                     "steps": [{"step": i + 1, "technique_id": st_.technique_id, "tactic": st_.tactic,
                                "events": len(st_.events)} for i, st_ in enumerate(s.steps)]} for s in stories],
        "decoys": [d.id for d in decoys] + [d["id"] for d in st.RECURRING_DECOYS],
        "wall_s": round(time.time() - t0, 2),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="generate a cloud attack dataset with ground truth")
    ap.add_argument("--size", required=True, type=str.lower, choices=sorted(SIZES),
                    help="small (<50 MB) or 1G (~1 GB)")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    m = write(a.out, a.seed, a.size, a.force)
    print(f"wrote {m['total_events']} events, {m['total_bytes'] / 1e6:.1f} MB, scale {m['baseline_scale']} "
          f"-> {a.out} in {m['wall_s']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
