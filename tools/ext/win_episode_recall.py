"""DIAGNOSTIC ONLY (not a scorecard metric): would each ground-truth step have matched an EPISODE (Stage 2.5, before
the incident gate)? Uses the frozen harness's own match primitives (same tolerance, host AND user-or-IP, one-to-one,
label rule) with episodes.parquet as the predictions. Separates "never detected" from "detected but the gate /
linking dropped it". Also lists, per GT step, the nearest same-host episodes for miss-cause analysis.
    PYTHONPATH=data/snap/ext_win/backend python tools/ext/win_episode_recall.py OUT_DIR GT.json [DEST.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import duckdb

from eval.harness import load_ground_truth
from eval.match import (PredStep, candidates, greedy_assign, norm_host, norm_ip, norm_tactic, norm_technique,
                        norm_user)


def episodes(out: Path) -> list[PredStep]:
    con = duckdb.connect()
    con.execute("SET TimeZone='UTC'")
    p = (out / "work" / "episodes.parquet").as_posix()
    rows = con.execute(f"SELECT episode_id, technique_id, sub_technique_id, tactic, ts_ms, coalesce(subject_host, host),"
                       f" user, src_user, target_user, src_ip, dst_ip, rule_id, confidence FROM read_parquet('{p}')"
                       ).fetchall()
    out_l = []
    for k, (eid, tid, sub, tac, ts, host, u, su, tu, sip, dip, rule, conf) in enumerate(rows):
        users = [x for x in (norm_user(u), norm_user(tu), norm_user(su)) if x]
        out_l.append(PredStep(incident_id="episodes", episode_id=eid, order=k, ts_ms=int(ts),
                              technique=norm_technique(tid), sub_technique=norm_technique(sub),
                              tactic=norm_tactic(tac), host=norm_host(host), user=users[0] if users else None,
                              alt_users=frozenset(users[1:]),
                              ips=frozenset(x for x in (norm_ip(sip), norm_ip(dip)) if x),
                              extra={"rule_id": rule, "confidence": conf, "technique_id": tid, "tactic": tac}))
    return out_l


def main() -> int:
    out, gt = Path(sys.argv[1]), Path(sys.argv[2])
    _, gts = load_ground_truth(gt)
    eps = episodes(out)
    chosen = {c.gt.key: c for c in greedy_assign(candidates(gts, eps))}
    rows = []
    for g in gts:
        c = chosen.get(g.key)
        near = sorted((p for p in eps if p.host == g.host), key=lambda p: abs(p.ts_ms - g.ts_ms))[:3]
        rows.append({"step": g.step, "gt_technique": g.technique, "gt_tactic": g.tactic, "host": g.host,
                     "episode_match": c is not None, "label_ok": bool(c and c.label),
                     "episode": c and {"rule": c.pred.extra["rule_id"], "technique": c.pred.extra["technique_id"],
                                       "tactic": c.pred.extra["tactic"], "dt_s": round(c.dt_ms / 1000),
                                       "confidence": c.pred.extra["confidence"]},
                     "nearest_same_host": [{"rule": p.extra["rule_id"], "technique": p.extra["technique_id"],
                                            "user": p.user, "dt_s": round((p.ts_ms - g.ts_ms) / 1000)} for p in near]})
    n = len(gts)
    m = sum(r["episode_match"] for r in rows)
    lab = sum(r["label_ok"] for r in rows)
    res = {"diagnostic": "episode-level step recall (pre-gate); NOT the scorecard", "gt_steps": n,
           "episode_matched": m, "episode_recall_pct": round(100 * m / n, 2) if n else None,
           "episode_labels_ok": lab, "episodes_total": len(eps), "steps": rows}
    txt = json.dumps(res, indent=1)
    if len(sys.argv) > 3:
        Path(sys.argv[3]).write_text(txt, encoding="utf-8")
    print(json.dumps({k: res[k] for k in res if k != "steps"}))
    for r in rows:
        print(r["step"], r["gt_technique"], r["host"], "EP" if r["episode_match"] else "--",
              r["episode"] and (r["episode"]["rule"], r["episode"]["technique"], r["episode"]["dt_s"]),
              "| near:", [(x["rule"], x["technique"], x["user"], x["dt_s"]) for x in r["nearest_same_host"]])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
