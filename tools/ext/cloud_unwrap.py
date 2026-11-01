"""Structure-only converter for CloudTrail exports (reports/ext/cloud_eval.md, finding F1).

CloudTrail is published as {"Records": [...]} documents, usually gzipped, sometimes inside a .tar. This writes
each record's EXACT source text on its own line (JSON lines). It never adds, removes, renames or labels a field;
the only selection is an optional [--from, --to) eventTime slice. Inputs are untrusted: nothing is executed or
extracted. Run with `python -I`.

    python -I tools/ext/cloud_unwrap.py <src file|dir> <out_dir> [--from 2020-09-01T00:00:00Z --to ...]
           [--per-file 200000]
Writes <out_dir>/part-NNNN.jsonl and prints rows in / written / bad / outside slice.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # our own tools/ext, never the data folder
from cloud_stream import iter_raw  # noqa: E402

TS_RE = re.compile(r'"eventTime"\s*:\s*"([^"]+)"')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--from", dest="t_from", default="")
    ap.add_argument("--to", dest="t_to", default="")
    ap.add_argument("--per-file", type=int, default=200_000)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    if any(a.out.iterdir()):
        raise SystemExit(f"{a.out} is not empty")
    n_in = n_out = n_bad = n_skip = 0
    part, fh = 0, None
    for _, kind, raw in iter_raw([a.src]):
        if kind != "record":
            n_bad += 1
            continue
        n_in += 1
        if a.t_from or a.t_to:
            m = TS_RE.search(raw)
            t = m.group(1) if m else ""
            if (a.t_from and t < a.t_from) or (a.t_to and t >= a.t_to):
                n_skip += 1
                continue
        if "\n" in raw or "\r" in raw:  # pretty-printed source: keep the text, only the line breaks between tokens
            raw = json.dumps(json.loads(raw), ensure_ascii=False, separators=(",", ":"))
        if fh is None or n_out % a.per_file == 0:
            if fh:
                fh.close()
            fh = (a.out / f"part-{part:04d}.jsonl").open("w", encoding="utf-8", newline="\n")
            part += 1
        fh.write(raw + "\n")
        n_out += 1
    if fh:
        fh.close()
    print(json.dumps({"records_in": n_in, "written": n_out, "bad": n_bad, "outside_slice": n_skip, "parts": part}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
