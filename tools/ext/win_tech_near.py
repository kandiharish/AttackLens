"""DIAGNOSTIC: per GT step, is there an episode on the same host within +-10 min with the RIGHT parent technique,
and does it carry a user / IP (the harness needs host AND (user OR IP))? Reads episodes.parquet + GT only.
    python -I tools/ext/win_tech_near.py OUT_DIR GT.json
"""
import json
import sys

import duckdb

out, gt = sys.argv[1], sys.argv[2]
steps = json.load(open(gt, encoding="utf-8"))["attacks"][0]["steps"]
con = duckdb.connect()
ep = con.execute(f"SELECT lower(coalesce(subject_host, host)), ts_ms, split_part(coalesce(sub_technique_id, technique_id),"
                 f" '.', 1), rule_id, coalesce(user, target_user, src_user), coalesce(src_ip, dst_ip) "
                 f"FROM read_parquet('{out}/work/episodes.parquet')").fetchall()
tot = with_user = 0
for s in steps:
    par = s["technique_id"].split(".")[0]
    hits = [e for e in ep if e[0] == s["host"].lower() and abs(e[1] - s["ts_ms"]) <= 600_000 and e[2] == par]
    tot += bool(hits)
    wu = [e for e in hits if e[4] or e[5]]
    with_user += bool(wu)
    print(s["step"], s.get("emulation_step"), s["technique_id"], "right-tech episodes:", len(hits),
          "with user/ip:", len(wu), [(e[3], e[4], round((e[1] - s["ts_ms"]) / 1000)) for e in hits[:3]])
print(f"steps with a right-technique episode within 10 min: {tot}/{len(steps)}; of those with user or IP: {with_user}")
