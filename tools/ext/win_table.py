"""One markdown row per run: accounting, time, RAM, every headline scorecard metric (measured files only).
    python -I tools/ext/win_table.py name1 name2 ...
"""
import json
import sys
from pathlib import Path

K = ["detection_pct", "labels_pct", "labels_technique_only_pct", "rebuilt_pct", "false_alarms_strict_pct",
     "false_alarms_lenient_pct", "step_precision_pct", "step_precision_all_pct"]
print("| set | source | rows in | ok | dropped (reason) | wall s | peak RSS MB | episodes | incidents | det % | "
      "labels % | tech-only % | rebuilt % | FA strict % | FA lenient % | step prec % | step prec all % |")
print("|" + "---|" * 17)
for n in sys.argv[1:]:
    o = Path(f"data/out/ext_win_{n}")
    m = json.loads((o / "run_metrics.json").read_text())
    a = json.loads((o / "ingest_accounting.json").read_text())
    c = json.loads((o / "eval_scorecard.json").read_text())
    a = a if isinstance(a, list) else [a]
    src = "+".join(x["source_type"] for x in a)
    rin, ok, dr = (sum(x[k] for x in a) for k in ("rows_in", "rows_ok", "dropped"))
    rs = "; ".join(f"{k.split(' ')[0]} {v}" for x in a for k, v in (x.get("drop_reasons") or {}).items())
    print(f"| {n} | {src} | {rin} | {ok} | {dr} ({rs or '-'}) | {m['total_wall_s']} | {m['peak_rss_mb']} | "
          f"{m['episodes']} | {m['incidents']} | " + " | ".join(str(c.get(k)) for k in K) + " |")
