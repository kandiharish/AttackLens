"""Summarise OTRF ThreatHunter-Playbook APT29 step YAMLs (documentation, not telemetry): per sub-step the
technique, the earliest UtcTime / time printed in the documented query outputs, and accounts / hosts named there.
    python -I tools/ext/win_otrf_steps.py DIR_WITH_YAMLS > summary.json
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

TIME_RES = [re.compile(r"UtcTime:\s*(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?)"),
            re.compile(r"(?:TimeCreated|EventTime|@timestamp)\W+(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?)")]
USER_RE = re.compile(r"(?:^|\n)\s*(?:User|Account Name):\s*([^\r\n]+)")
HOST_RE = re.compile(r"\b(SCRANTON|NASHUA|UTICA|NEWYORK)(?:\.dmevals\.local)?\b", re.I)


def key(p: Path) -> tuple:
    a, b, c = p.name.split("_", 1)[0].split(".")
    return int(a), b, int(c)


def main() -> int:
    out = []
    for p in sorted(Path(sys.argv[1]).glob("*.yaml"), key=key):
        d = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace"))
        times, users, hosts, types = [], set(), set(), []
        for det in d.get("detections") or []:
            types.append(det.get("main_type"))
            for q in det.get("queries") or []:
                o = str(q.get("output") or "")
                for r in TIME_RES:
                    times += r.findall(o)
                users |= {u.strip() for u in USER_RE.findall(o) if u.strip() not in ("-", "")}
                hosts |= {h.upper() for h in HOST_RE.findall(o)}
        out.append({"substep": d["step"], "technique": d["technique"]["id"], "name": d["technique"]["name"],
                    "procedure": d.get("procedure"), "criteria": d.get("criteria"), "detection_types": types,
                    "times": sorted(times), "users": sorted(users), "hosts": sorted(hosts), "file": p.name})
    json.dump(out, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
