"""Collect measured numbers of one run into markdown (report helper). Reads only files the run wrote.
    python -I tools/ext/win_collect.py data/out/ext_win_<name> [alt_scorecard.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

METRICS = ["detection_pct", "labels_pct", "labels_technique_only_pct", "rebuilt_pct", "false_alarms_strict_pct",
           "false_alarms_lenient_pct", "step_precision_pct", "step_precision_all_pct"]


def load(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def main() -> int:
    out = Path(sys.argv[1])
    card = load(Path(sys.argv[2])) if len(sys.argv) > 2 else load(out / "eval_scorecard.json")
    m = load(out / "run_metrics.json") or {}
    acc = load(out / "ingest_accounting.json") or []
    prof = load(out / "source_profile.json") or {}
    print(f"### {out.name}")
    print(f"- profile: per_source {prof.get('files_per_source') and {k: len(v) for k, v in prof['files_per_source'].items()}}"
          f", unrecognized {[(u['path'], u['reason']) for u in prof.get('unrecognized', [])]}")
    for a in acc if isinstance(acc, list) else [acc]:
        print(f"- ingest {a.get('source_type')}: rows_in {a.get('rows_in')} ok {a.get('rows_ok')} dropped "
              f"{a.get('dropped')} reasons {a.get('drop_reasons')} quarantined {a.get('quarantined')} "
              f"notes {a.get('notes')}")
    print(f"- run: error {m.get('error')} wall {m.get('total_wall_s')} s, peak RSS {m.get('peak_rss_mb')} MB, "
          f"episodes {m.get('episodes')}, incidents {m.get('incidents')}")
    print(f"- stages: {[(s['name'], s['wall_s'], s['peak_rss_mb']) for s in m.get('stages', [])]}")
    det = (m.get("stage_stats") or {}).get("detect") or {}
    print(f"- alerts_per_rule (non-zero): {{{', '.join(f'{k}: {v}' for k, v in sorted((det.get('alerts_per_rule') or {}).items()) if v)}}}")
    for k in [x for x in det if x != "alerts_per_rule"]:
        print(f"- detect.{k}: {json.dumps(det[k], default=str)[:600]}")
    if not card:
        print("- NO SCORECARD")
        return 0
    print("- scorecard: " + ", ".join(f"{k} {card.get(k)}" for k in METRICS))
    print(f"- counts: {card.get('counts')}")
    for a in card.get("per_attack", []):
        print(f"- attack {a['id']}: steps {a['steps']} matched {a['steps_matched']} in_incident "
              f"{a['steps_in_matched_incident']} labels_ok {a['labels_correct']} incident {a['matched_incident']} "
              f"lcs {a['lcs_ratio']} rebuilt {a['rebuilt']}")
        print("  | step | GT technique | GT tactic | host | matched | incident | pred technique | pred tactic | label ok | dt s |")
        print("  |---|---|---|---|---|---|---|---|---|---|")
        for s in a["step_detail"]:
            dt = None if s["dt_ms"] is None else round(s["dt_ms"] / 1000)
            print(f"  | {s['step']} | {s['technique_id']} | {s['tactic']} | {s['host']} | {s['matched']} | "
                  f"{s['incident_id']} | {s['pred_technique_id']} | {s['pred_tactic']} | {s['label_ok']} | {dt} |")
    for u in card.get("unmatched_incidents", [])[:10]:
        print(f"- unmatched {u['id']} risk {u['risk']} eps {u['episode_count']}: "
              + "; ".join(f"{e['rule_id']} {e['technique_id']} {e['host']} {e['user']} {e['ts']}" for e in u["top_episodes"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
