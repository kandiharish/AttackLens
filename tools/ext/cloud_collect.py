"""Collect one ext_cloud run into a JSON summary (reports/ext/cloud_eval.md). Read-only on the run outputs.

Harness numbers are copied verbatim from eval_scorecard.json / run_metrics.json / ingest_accounting.json.
The extra per-step diagnosis ("which episode covered this GT step, and what happened to it") is OUR analysis,
not the harness: GT step ~ episode iff host equal AND (user OR ip equal) AND step ts in
[episode first ts - 10 min, episode last ts + 10 min] (same tolerance as the harness), all lower-cased.

    python tools/ext/cloud_collect.py <out_dir> <attacks.json> <summary.json>
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import duckdb

TOL = 600_000


def norm_user(v: object) -> str | None:
    if v is None:
        return None
    s = str(v).strip().lower()
    if "\\" in s:
        s = s.rsplit("\\", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[0]
    return s or None


def main() -> int:
    out, gt_path, dst = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    sc = json.loads((out / "eval_scorecard.json").read_text(encoding="utf-8"))
    rm = json.loads((out / "run_metrics.json").read_text(encoding="utf-8"))
    acc = json.loads((out / "ingest_accounting.json").read_text(encoding="utf-8"))
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    steps = [(a["id"], s["step"], int(s["ts_ms"]), str(s.get("host") or "").lower(), norm_user(s.get("user")),
              str(s.get("src_ip") or "").lower(), s["technique_id"], s.get("stage") or "")
             for a in gt["attacks"] for s in a["steps"]]
    inc_of: dict[str, str] = {}
    for p in sorted((out / "incidents").glob("*.json")):
        inc = json.loads(p.read_text(encoding="utf-8"))
        for s in inc.get("backbone", []):
            inc_of.setdefault(s["episode_id"], inc["id"])
        for br in inc.get("branches", []):
            for s in br:
                inc_of.setdefault(s["episode_id"], inc["id"])
    con = duckdb.connect()
    con.execute("SET TimeZone='UTC'")
    con.execute("SET memory_limit='1GB'")
    con.execute("SET threads=2")
    w = out / "work"
    con.execute("CREATE TABLE gt(attack VARCHAR, step INT, ts BIGINT, host VARCHAR, usr VARCHAR, ip VARCHAR, "
                "tech VARCHAR, stage VARCHAR)")
    con.executemany("INSERT INTO gt VALUES (?,?,?,?,?,?,?,?)", steps)
    ep = (w / "episodes.parquet").as_posix()
    sup = (w / "suppressed.parquet").as_posix()
    has_sup = (w / "suppressed.parquet").exists()
    rows = con.execute(f"""
        WITH e AS (SELECT episode_id, rule_id, coalesce(sub_technique_id, technique_id) AS tech, tactic, ts_ms,
                          coalesce(last_ts_ms, ts_ms) AS last_ts, confidence,
                          lower(coalesce(subject_host, host)) AS h, lower(host) AS h2,
                          lower(regexp_replace(regexp_replace(coalesce(user, ''), '^.*\\\\', ''), '@.*$', '')) AS u1,
                          lower(regexp_replace(regexp_replace(coalesce(src_user, ''), '^.*\\\\', ''), '@.*$', '')) AS u2,
                          lower(regexp_replace(regexp_replace(coalesce(target_user, ''), '^.*\\\\', ''), '@.*$', '')) AS u3,
                          lower(coalesce(src_ip, '')) AS i1, lower(coalesce(dst_ip, '')) AS i2
                   FROM read_parquet('{ep}'))
        SELECT g.attack, g.step, e.episode_id, e.rule_id, e.tech, e.tactic, e.confidence
        FROM gt g JOIN e ON (g.host = e.h OR g.host = e.h2)
          AND g.ts BETWEEN e.ts_ms - {TOL} AND e.last_ts + {TOL}
          AND ((g.usr IS NOT NULL AND g.usr IN (e.u1, e.u2, e.u3)) OR (g.ip <> '' AND g.ip IN (e.i1, e.i2)))
    """).fetchall()
    sup_reason: dict[str, str] = {}
    if has_sup:
        for eid, reason in con.execute(f"SELECT episode_id, reason FROM read_parquet('{sup}')").fetchall():
            sup_reason[eid] = reason
    by_step: dict[tuple, list] = {}
    for att, st, eid, rule, tech, tac, conf in rows:
        by_step.setdefault((att, st), []).append((eid, rule, tech, tac, conf))
    harness_step = {(a["id"], d["step"]): d for a in sc.get("per_attack", []) for d in a.get("step_detail", [])}
    detail, fate_counter, rule_counter = [], Counter(), Counter()
    for att, st, ts, host, usr, ip, tech, stage in steps:
        cands = by_step.get((att, st), [])
        parent = tech.split(".")[0]
        lab = [c for c in cands if c[2] and (c[2] == tech or c[2].split(".")[0] == parent)]
        best = max(lab or cands, key=lambda c: (c[1] is not None, c[4] or 0), default=None)
        if best is None:
            fate = "no_episode"
        elif best[0] in inc_of:
            fate = "in_incident"
        elif best[0] in sup_reason:
            fate = "suppressed: " + sup_reason[best[0]]
        else:
            fate = "episode_not_in_incident_or_suppressed"
        fate_counter[fate.split(" and ")[0] if fate.startswith("suppressed") else fate] += 1
        if best:
            rule_counter[best[1]] += 1
        h = harness_step.get((att, st), {})
        detail.append({"attack": att, "step": st, "stage": stage, "gt_technique": tech,
                       "harness_matched": h.get("matched"), "harness_incident": h.get("incident_id"),
                       "harness_pred_technique": h.get("pred_technique_id"), "harness_label_ok": h.get("label_ok"),
                       "episodes": len(cands), "label_episode": bool(lab),
                       "best_rule": best[1] if best else None, "best_technique": best[2] if best else None,
                       "best_confidence": best[4] if best else None, "fate": fate,
                       "incident": inc_of.get(best[0]) if best else None})
    keys = ["detection_pct", "labels_pct", "labels_technique_only_pct", "rebuilt_pct", "false_alarms_strict_pct",
            "false_alarms_lenient_pct", "singleton_recall_pct", "step_precision_pct", "step_precision_all_pct"]
    summary = {
        "out": out.as_posix(), "gt": gt_path.as_posix(),
        "accounting": acc, "total_wall_s": rm.get("total_wall_s"), "peak_rss_mb": rm.get("peak_rss_mb"),
        "rows_in": rm.get("rows_in"), "rows_ok": rm.get("rows_ok"), "episodes": rm.get("episodes"),
        "incidents": rm.get("incidents"), "error": rm.get("error"),
        "stages": [(s["name"], s["wall_s"], s["peak_rss_mb"]) for s in rm.get("stages", [])],
        "scorecard": {k: sc.get(k) for k in keys}, "counts": sc.get("counts"),
        "per_rule_alerts": sc.get("per_rule_alerts"),
        "unmatched_incidents": sc.get("unmatched_incidents"),
        "step_fates": dict(fate_counter), "best_rules": dict(rule_counter.most_common(30)),
        "steps_with_episode": sum(1 for d in detail if d["episodes"]),
        "steps_with_label_episode": sum(1 for d in detail if d["label_episode"]),
        "gt_steps": len(detail), "step_detail": detail,
    }
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(summary, indent=1, default=str), encoding="utf-8")
    s = summary
    print(json.dumps({k: s[k] for k in ("rows_in", "rows_ok", "total_wall_s", "peak_rss_mb", "episodes", "incidents",
                                        "gt_steps", "steps_with_episode", "steps_with_label_episode", "step_fates")}))
    print(json.dumps(s["scorecard"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
