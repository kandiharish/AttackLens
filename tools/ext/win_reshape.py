"""Structure-only reshaping of OTRF / Mordor Windows JSON lines so AttackLens's win_json source is chosen.
Changes ONLY the envelope; never adds a value that is not in the record, never labels anything:
  1. '@timestamp' (Logstash/NXLog collector time, ISO-8601 'Z') is moved to TimeCreated.SystemTime when the record has
     no TimeCreated; if it has one, '@timestamp' is renamed '_collector_timestamp'. (The '@timestamp' key alone makes
     profile.py pick ecs_json, whose aliases expect nested ECS fields that these records do not have.)
  2. A string TimeCreated with no UTC designator / offset (e.g. '2020-10-18 07:49:39.776', a 12-hour clock with no
     AM/PM) is renamed 'TimeCreatedLocal' so it is not read as UTC; ts then comes from the next alias (UtcTime).
  3. Everything else is copied unchanged, one record per line, same order. Invalid JSON lines are copied verbatim.
    python -I tools/ext/win_reshape.py IN.json OUT.json
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter

TZ_RE = re.compile(r"(Z|[+-]\d\d:?\d\d)$")


def reshape(d: dict, c: Counter) -> dict:
    tc = d.get("TimeCreated")
    if isinstance(tc, str) and not TZ_RE.search(tc.strip()):
        d["TimeCreatedLocal"] = d.pop("TimeCreated")
        c["timecreated_naive_renamed"] += 1
        tc = None
    if "@timestamp" in d:
        ts = d.pop("@timestamp")
        if tc is None and "TimeCreated" not in d:
            d["TimeCreated"] = {"SystemTime": ts}
            c["timestamp_moved_to_timecreated"] += 1
        else:
            d["_collector_timestamp"] = ts
            c["timestamp_renamed"] += 1
    return d


def main() -> int:
    src, dst = sys.argv[1], sys.argv[2]
    c: Counter = Counter()
    with open(src, encoding="utf-8", errors="surrogateescape", newline="") as fi, \
            open(dst, "w", encoding="utf-8", errors="surrogateescape", newline="\n") as fo:
        for line in fi:
            c["lines"] += 1
            s = line.rstrip("\r\n")
            try:
                d = json.loads(s)
            except ValueError:
                c["invalid_copied"] += 1
                fo.write(s + "\n")
                continue
            if not isinstance(d, dict):
                c["non_object_copied"] += 1
                fo.write(s + "\n")
                continue
            fo.write(json.dumps(reshape(d, c), ensure_ascii=False) + "\n")
    print(json.dumps(dict(c)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
