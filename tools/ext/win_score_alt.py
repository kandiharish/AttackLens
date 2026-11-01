"""Score an existing pipeline output against an alternative ground truth with the FROZEN harness (snapshot copy),
writing to a separate file so the run's own eval_scorecard.json is untouched.
    PYTHONPATH=data/snap/ext_win/backend python tools/ext/win_score_alt.py OUT_DIR GT.json DEST.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from eval import harness


def main() -> int:
    out, gt, dest = map(Path, sys.argv[1:4])
    card = harness.evaluate(out, gt)
    card["harness_module"] = harness.__file__
    dest.write_text(json.dumps(card, indent=2), encoding="utf-8")
    print(dest, {k: card[k] for k in ("detection_pct", "labels_pct", "rebuilt_pct", "false_alarms_strict_pct",
                                       "step_precision_pct")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
