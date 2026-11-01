"""Read-only inventory of CloudTrail files for the external-data evaluation (reports/ext/cloud_eval.md).

Never executes or extracts anything; treats every input as untrusted data. Run with `python -I`.
Accepts: JSON lines (one record per line), {"Records": [...]} files, *.gz of either, and a .tar of those
(members are streamed, never written to disk).

    python -I tools/ext/cloud_inventory.py summary  <file-or-dir> [...]
    python -I tools/ext/cloud_inventory.py events   <file-or-dir> [...] [--names A,B] [--ip X] [--user U]
           [--from 2017-02-26T00:00:00Z --to ...]       -> TSV: eventTime, eventName, account, user, ip, error, ua
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Iterator


sys.path.insert(0, str(Path(__file__).resolve().parent))  # our own tools/ext, never the data folder
from cloud_stream import iter_raw  # noqa: E402


def iter_records(paths: list[Path]) -> Iterator[tuple[str, dict]]:
    for name, kind, raw in iter_raw(paths):
        if kind != "record":
            yield name, {"__bad_line__": True}
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            obj = {"__bad_line__": True}
        yield name, obj if isinstance(obj, dict) else {"__bad_line__": True}


def user_of(r: dict) -> str:
    ui = r.get("userIdentity") or {}
    return str(ui.get("userName") or ui.get("arn") or (ui.get("sessionContext") or {}).get("sessionIssuer", {})
               .get("userName") or ui.get("principalId") or ui.get("type") or "")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["summary", "events"])
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--names", default="")
    ap.add_argument("--ip", default="")
    ap.add_argument("--user", default="")
    ap.add_argument("--from", dest="t_from", default="")
    ap.add_argument("--to", dest="t_to", default="")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--detail", type=int, default=0, help="also print requestParameters[:N], response, extra")
    a = ap.parse_args()
    names = {n.strip().lower() for n in a.names.split(",") if n.strip()}
    out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")
    per_file: Counter[str] = Counter()
    ev: Counter[str] = Counter()
    accts: Counter[str] = Counter()
    bad = 0
    tmin, tmax = "9999", "0000"
    for fname, r in iter_records(a.paths):
        if r.get("__bad_line__"):
            bad += 1
            continue
        per_file[fname] += 1
        t = str(r.get("eventTime") or "")
        if a.mode == "summary":
            ev[str(r.get("eventName"))] += 1
            accts[str(r.get("recipientAccountId"))] += 1
            if t:
                tmin, tmax = min(tmin, t), max(tmax, t)
            continue
        if names and str(r.get("eventName", "")).lower() not in names:
            continue
        if a.ip and r.get("sourceIPAddress") != a.ip:
            continue
        u = user_of(r)
        if a.user and a.user.lower() not in u.lower():
            continue
        if (a.t_from and t < a.t_from) or (a.t_to and t > a.t_to):
            continue
        out.write("\t".join([t, str(r.get("eventName")), str(r.get("eventSource")),
                             str(r.get("recipientAccountId")), u, str(r.get("sourceIPAddress")),
                             str(r.get("errorCode") or ""), str(r.get("userAgent") or "")[:60]]
                            + ([json.dumps(r.get("requestParameters"))[:a.detail],
                                json.dumps(r.get("responseElements"))[:120],
                                json.dumps(r.get("additionalEventData"))[:120],
                                str((r.get("userIdentity") or {}).get("type")), str(r.get("eventID"))]
                               if a.detail else [])) + "\n")
    if a.mode == "summary":
        out.write(f"records={sum(per_file.values())} bad_lines={bad} time={tmin}..{tmax}\n")
        for k, v in sorted(per_file.items()):
            out.write(f"  file {k}: {v}\n")
        out.write(f"accounts: {dict(accts.most_common(5))}\n")
        out.write(f"top events: {ev.most_common(a.top)}\n")
    out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
