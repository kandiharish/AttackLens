"""Ground truth for the flaws.cloud CloudTrail release (reports/ext/cloud_eval.md). PARTIAL by design.

Source: the documented flaws.cloud attack path (level hint pages, flaws.cloud levels 3-6) as published by
Scott Piper / Summit Route. The release post (summitroute.com/blog/2020/10/09/...) says the logs are the
players' (attackers') activity; the hint pages name the identities and API calls of each level:
  L3  leaked IAM key of user "backup" (from the bucket's .git)  -> `s3 ls`, `sts get-caller-identity`
  L4  `ec2 describe-snapshots --owner-id <account>` with that key (public EBS snapshot hunt)
  L5  SSRF to 169.254.169.254 -> instance-role credentials of role "flaws", used off-host (`s3 ls level6...`)
  L6  user "Level6" (SecurityAudit): `iam get-user`, `list-attached-user-policies`, `get-policy`,
      `get-policy-version`, then `lambda list-functions`, `lambda get-policy`, `apigateway get-stages`
Only these behaviour PATTERNS are ground truth. Other attacker activity in the logs (GetBucketAcl / AssumeRole
brute force, RunInstances spam, backdoor attempts) is NOT in this file, so strict false alarms are an upper bound.

Instance rule (fixed before any run): one ATTACK = one (source IP, UTC day) that performs >= 1 documented stage;
one STEP per documented stage = that stage's first event of the attack. Entities copied from that event.
Nothing here reads AttackLens output.

    python -I tools/ext/cloud_flaws_gt.py <src> <out_attacks.json> [--from 2020-09-01T00:00:00Z --to ...]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # our own tools/ext, never the data folder
from cloud_stream import iter_raw  # noqa: E402

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$")
L6_IAM = {"GetUser", "ListAttachedUserPolicies", "ListUserPolicies", "GetPolicy", "GetPolicyVersion", "ListPolicies"}
STAGES = {  # stage -> (technique, tactic, doc)
    "L3": ("T1078.004", "Initial Access", "flaws L3: leaked access key of IAM user 'backup' used (hint3: s3 ls)"),
    "L4": ("T1580", "Discovery", "flaws L4: describe-snapshots with the leaked key (hint1)"),
    "L5": ("T1552.005", "Credential Access", "flaws L5: role 'flaws' instance credentials from 169.254.169.254 used "
                                              "off-host (hint2/hint3)"),
    "L6a": ("T1069.003", "Discovery", "flaws L6: Level6 IAM policy enumeration (hint1)"),
    "L6b": ("T1526", "Discovery", "flaws L6: Level6 lambda / API Gateway discovery (hint2)"),
}


def stage_of(r: dict) -> str | None:
    ui = r.get("userIdentity") or {}
    name, src = str(r.get("eventName") or ""), str(r.get("eventSource") or "")
    ip = str(r.get("sourceIPAddress") or "")
    if not IP_RE.match(ip):  # AWS-internal callers (ec2.amazonaws.com, apigateway...) are not the player
        return None
    if ui.get("type") == "IAMUser" and ui.get("userName") == "backup":
        return "L4" if name == "DescribeSnapshots" else "L3"
    # v2 fix (2026-11-01): v1 tested "/assumed-role/flaws/", but the ARN is "arn:aws:sts::<acct>:assumed-role/flaws/..."
    # (a colon before assumed-role), so v1 silently dropped the documented L5 stage. v1 files are kept unchanged.
    if ui.get("type") == "AssumedRole" and ":assumed-role/flaws/" in str(ui.get("arn") or ""):
        return "L5"
    if ui.get("type") == "IAMUser" and ui.get("userName") == "Level6":
        if src == "iam.amazonaws.com" and name in L6_IAM:
            return "L6a"
        if (src == "lambda.amazonaws.com" and (name.startswith("ListFunctions") or name.startswith("GetPolicy"))) \
                or (src == "apigateway.amazonaws.com" and name in ("GetStages", "GetRestApis")):
            return "L6b"
    return None


def user_of(r: dict) -> str:
    ui = r.get("userIdentity") or {}
    return str(ui.get("userName") or ui.get("arn") or "")


def ts_ms(s: str) -> int:
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--from", dest="t_from", default="")
    ap.add_argument("--to", dest="t_to", default="")
    a = ap.parse_args()
    first: dict[tuple[str, str], dict[str, dict]] = {}
    n_pos = 0
    for _, kind, raw in iter_raw([a.src]):
        if kind != "record":
            continue
        if '"backup"' not in raw and '"Level6"' not in raw and "assumed-role/flaws/" not in raw:
            continue  # cheap pre-filter; stage_of() decides
        r = json.loads(raw)
        t = str(r.get("eventTime") or "")
        if (a.t_from and t < a.t_from) or (a.t_to and t >= a.t_to):
            continue
        st = stage_of(r)
        if st is None:
            continue
        n_pos += 1
        key = (str(r["sourceIPAddress"]), t[:10])
        cur = first.setdefault(key, {})
        if st not in cur or t < cur[st]["eventTime"]:
            cur[st] = r
    attacks = []
    for (ip, day), stages in sorted(first.items(), key=lambda kv: min(r["eventTime"] for r in kv[1].values())):
        rs = sorted(stages.items(), key=lambda kv: kv[1]["eventTime"])
        steps = []
        for i, (st, r) in enumerate(rs, start=1):
            tech, tac, doc = STAGES[st]
            steps.append({"step": i, "ts_ms": ts_ms(r["eventTime"]), "technique_id": tech, "tactic": tac,
                          "host": r.get("recipientAccountId"), "user": user_of(r), "src_ip": ip, "dst_ip": None,
                          "stage": st, "doc": doc,
                          "evidence": {"eventName": r.get("eventName"), "eventTime": r["eventTime"],
                                       "eventID": r.get("eventID")}})
        attacks.append({"id": f"FL{len(attacks) + 1}", "actor": f"{ip}@{day}",
                        "stages": "".join(s for s, _ in rs), "steps": steps})
    doc = {"attack_version": "v20", "dataset": "flaws.cloud CloudTrail (Summit Route 2020 release)",
           "slice": {"from": a.t_from or None, "to": a.t_to or None},
           "partial": "documented flaws.cloud L3-L6 behaviour patterns only; see tools/ext/cloud_flaws_gt.py",
           "positive_events": n_pos, "attacks": attacks}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    multi = sum(1 for x in attacks if len(x["steps"]) >= 2)
    print(f"positives={n_pos} attacks={len(attacks)} multi_step={multi} "
          f"steps={sum(len(x['steps']) for x in attacks)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
