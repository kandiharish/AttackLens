"""Generate the AWS network / sign-in / S3 / findings attack set with ground truth (track AWS).

    python tools/cloud_attacks/gen_aws.py --out data/raw/cloud_aws [--seed 11] [--scale 1.0] [--text-flow DIR]

Layout (Stage 0 routes by content, never by folder):
    <out>/aws_cloudtrail/cloudtrail/part-*.jsonl     CloudTrail (management, S3 data events, Identity Center sign-in)
    <out>/aws_vpcflow/<shape>/part-*.jsonl           VPC Flow Logs v5 JSON: hyphen / underscore / sentinel shapes
    <out>/aws_route53resolver/part-*.jsonl           Route 53 Resolver query logs (+ DNS Firewall verdicts)
    <out>/aws_networkfirewall/part-*.jsonl           Network Firewall netflow / alert / tls
    <out>/aws_findings/guardduty|securityhub.jsonl   vendor findings (context rows; alert-input via findings_aws)
    <out>/ground_truth/attacks.json, <out>/manifest.json
--text-flow DIR also writes the native text forms (S3 file with header, CloudWatch headerless lines) to DIR; those
need the space-delimited CSV patch (reports/cloud/patches/aws-*.diff) and are kept out of <out> until it lands.
Served records carry no ground-truth field.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[1]))

from cloud_attacks import aws_baseline as bl, aws_feeds as af   # noqa: E402
from cloud_attacks.aws_stories import build_decoys, build_stories   # noqa: E402
from cloud_attacks.common import START_MS, Ev, iso_s   # noqa: E402

MAX_PART_BYTES = 8 * 1024 * 1024
TEXT_FIELDS = ["version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol",
               "packets", "bytes", "start", "end", "action", "log-status", "vpc-id", "subnet-id", "instance-id",
               "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr", "flow-direction"]


def dest(ev: Ev) -> str:
    if ev.feed == "vpcflow":
        d = ev.doc
        shape = "hyphen" if "interface-id" in d else "underscore" if "interface_id" in d else "sentinel"
        return f"aws_vpcflow/{shape}"
    return {"cloudtrail": "aws_cloudtrail/cloudtrail", "r53": "aws_route53resolver", "nfw": "aws_networkfirewall",
            "guardduty": "aws_findings/guardduty", "securityhub": "aws_findings/securityhub"}[ev.feed]


def generate(seed: int, scale: float) -> list[Ev]:
    evs = bl.baseline(seed, scale)
    for s in build_stories(seed):
        evs += s.events()
    for dcy in build_decoys(seed):
        evs += dcy.events
    return sorted(evs, key=lambda e: (e.ts, e.rid))


def write_text_flow(evs: list[Ev], out: Path) -> dict[str, int]:
    """Native text forms of the hyphen-shaped flows: an S3-style file with the header line, and CloudWatch-style
    headerless lines in the default v2 field order."""
    out.mkdir(parents=True, exist_ok=True)
    rows = [e.doc for e in evs if e.feed == "vpcflow" and "interface-id" in e.doc]
    v2 = TEXT_FIELDS[:14]
    (out / "s3_flow.log").write_text(" ".join(TEXT_FIELDS) + "\n" + "".join(af.text_line(d, TEXT_FIELDS) + "\n"
                                                                            for d in rows), encoding="utf-8")
    (out / "cloudwatch_flow.log").write_text("".join(af.text_line({**d, "version": 2}, v2) + "\n" for d in rows),
                                             encoding="utf-8")
    return {"s3_rows": len(rows), "cloudwatch_rows": len(rows)}


def write(out: Path, seed: int, scale: float, force: bool, text_flow: Path | None = None) -> dict[str, Any]:
    if out.exists():
        if not force and any(out.iterdir()):
            raise SystemExit(f"refusing to write into non-empty {out} (use --force)")
        shutil.rmtree(out)
    out.mkdir(parents=True)
    t0 = time.time()
    evs = generate(seed, scale)
    by: dict[str, list[Ev]] = {}
    for e in evs:
        by.setdefault(dest(e), []).append(e)
    parts, total = [], 0
    for folder, items in sorted(by.items()):
        d = out / folder
        d.mkdir(parents=True, exist_ok=True)
        buf: list[str] = []
        size, seq = 0, 0
        for i, e in enumerate(items):
            ln = json.dumps(e.doc, ensure_ascii=False, default=str) + "\n"
            buf.append(ln)
            size += len(ln.encode("utf-8"))
            if size >= MAX_PART_BYTES or i == len(items) - 1:
                seq += 1
                p = d / f"part-{seq:04d}.jsonl"
                p.write_text("".join(buf), encoding="utf-8", newline="")
                parts.append({"folder": folder, "file": p.relative_to(out).as_posix(), "events": len(buf), "bytes": size})
                total += size
                buf, size = [], 0
    stories, decoys = build_stories(seed), build_decoys(seed)
    gt = {"attack_version": "v20", "anchor_ms": START_MS, "anchor": iso_s(START_MS),
          "generated_by": "tools/cloud_attacks/gen_aws.py", "seed": seed, "size": f"scale{scale:g}",
          "note": "AWS network / Identity Center / S3 / findings stories; all IPs RFC 5737 / RFC 1918, names fake.",
          "attacks": [s.gt() for s in stories], "decoys": [x.gt() for x in decoys]}
    (out / "ground_truth").mkdir()
    (out / "ground_truth" / "attacks.json").write_text(json.dumps(gt, indent=1), encoding="utf-8")
    manifest = {"generator": "tools/cloud_attacks/gen_aws.py", "seed": seed, "scale": scale, "days": bl.DAYS,
                "start": iso_s(START_MS), "end": iso_s(START_MS + bl.DAYS * 86_400_000), "total_events": len(evs),
                "total_bytes": total, "parts": parts,
                "events_per_feed": {f: sum(1 for e in evs if e.feed == f) for f in sorted({e.feed for e in evs})},
                "attacks": [{"id": s.id, "name": s.name, "steps": len(s.steps)} for s in stories],
                "decoys": [x.id for x in decoys], "wall_s": round(time.time() - t0, 2)}
    if text_flow:
        manifest["text_flow"] = {"dir": text_flow.as_posix(), **write_text_flow(evs, text_flow)}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="generate the AWS track attack set with ground truth")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--scale", type=float, default=1.0, help="benign volume multiplier (attacks are fixed)")
    ap.add_argument("--text-flow", type=Path, default=None)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    m = write(a.out, a.seed, a.scale, a.force, a.text_flow)
    print(f"wrote {m['total_events']} events, {m['total_bytes'] / 1e6:.1f} MB -> {a.out} in {m['wall_s']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
