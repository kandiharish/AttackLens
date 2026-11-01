"""Build ground_truth/attacks.json for the Splunk attack_data CloudTrail sets (reports/ext/cloud_eval.md).

Ground truth comes ONLY from each dataset's documentation (its .yml description + mitre_technique, and the
Splunk detection the dataset was recorded for). The criteria below are written from that text; the raw records
are read only to copy the timestamp / account / caller / IP of the events that meet the documented criteria.
Nothing here reads any AttackLens output.

Instance rule (fixed before any run): one ATTACK = the positive events of one (account, caller, source IP, UTC day);
one STEP = a run of positive events of that attack with gaps <= 10 min (the harness step tolerance); the step's
ts = its first event. Entities are copied exactly as in the record (user = userIdentity.userName, else arn).

    python -I tools/ext/cloud_gt_build.py <set> <src_dir> <out_attacks.json>
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))  # our own tools/ext, never the data folder
from cloud_stream import iter_raw  # noqa: E402

GAP_MS = 10 * 60 * 1000


def _caller(r: dict) -> str:
    ui = r.get("userIdentity") or {}
    return str(ui.get("userName") or ui.get("arn") or "")


def _caller_short(r: dict) -> str:
    """Caller's own user name, to compare with requestParameters.userName (assumed-role -> session name)."""
    ui = r.get("userIdentity") or {}
    if ui.get("userName"):
        return str(ui["userName"]).lower()
    arn = str(ui.get("arn") or "")
    return arn.rsplit("/", 1)[-1].split("@", 1)[0].lower()


def _ok(r: dict) -> bool:
    return not r.get("errorCode")


def _req(r: dict) -> dict:
    return r.get("requestParameters") or {}


# documented criteria per set: (predicate, technique, tactic, citation)
def _sfa(r: dict) -> bool:  # "successful Console login without MFA"
    return (r.get("eventName") == "ConsoleLogin" and (r.get("responseElements") or {}).get("ConsoleLogin") == "Success"
            and (r.get("additionalEventData") or {}).get("MFAUsed") == "No")


def _loginfail(r: dict) -> bool:  # "cloudtrail events with AWS login failure"
    return r.get("eventName") == "ConsoleLogin" and (r.get("responseElements") or {}).get("ConsoleLogin") == "Failure"


def _stoptrail(r: dict) -> bool:  # "a cloudtrail is stopped from logging" (stop_delete_cloudtrail: StopLogging/DeleteTrail)
    return r.get("eventName") in ("StopLogging", "DeleteTrail") and _ok(r)


def _snapexfil(r: dict) -> bool:  # snapshot shared to another account / public (createVolumePermission add)
    if r.get("eventName") != "ModifySnapshotAttribute" or not _ok(r):
        return False
    add = ((_req(r).get("createVolumePermission") or {}).get("add") or {}).get("items") or []
    acct = str(r.get("recipientAccountId") or "")
    return any(i.get("group") == "all" or (i.get("userId") and str(i["userId"]) != acct) for i in add)


def _s3public(r: dict) -> bool:  # "creation of a public S3 bucket": ACL grant to AllUsers / AuthenticatedUsers
    if r.get("eventName") != "PutBucketAcl" or not _ok(r):
        return False
    blob = json.dumps(_req(r))
    return "acs.amazonaws.com/groups/global/AllUsers" in blob or "acs.amazonaws.com/groups/global/AuthenticatedUsers" in blob


def _createkey(r: dict) -> bool:  # "user A ... create access keys for another user B"
    if r.get("eventName") != "CreateAccessKey" or not _ok(r):
        return False
    target = str(_req(r).get("userName") or "").lower()
    return bool(target) and target != _caller_short(r)


SETS: dict[str, tuple[Callable[[dict], bool], str, str, str]] = {
    "sfa": (_sfa, "T1078.004", "Initial Access",
            "splunk/attack_data T1078.004/aws_login_sfa: 'successful Console login without MFA'"),
    "loginfail": (_loginfail, "T1110.001", "Credential Access",
                  "splunk/attack_data T1110.001/aws_login_failure: 'cloudtrail events with AWS login failure'"),
    "stoptrail": (_stoptrail, "T1685.002", "Defense Impairment",
                  "splunk/attack_data T1562.008/stop_delete_cloudtrail (T1562.008 = v20 T1685.002): "
                  "'a cloudtrail is stopped from logging' (Stratus aws.defense-evasion.cloudtrail-stop / -delete)"),
    "snapexfil": (_snapexfil, "T1537", "Exfiltration",
                  "splunk/attack_data T1537/aws_snapshot_exfil: transfer backups to another cloud account "
                  "(Stratus aws.exfiltration.ec2-share-ebs-snapshot)"),
    "s3public": (_s3public, "T1530", "Collection",
                 "splunk/attack_data T1530/aws_s3_public_bucket: 'creation of a public S3 bucket'"),
    "createkey": (_createkey, "T1078", "Privilege Escalation",
                  "splunk/attack_data T1078/aws_createaccesskey: 'user A ... create access keys for another user B' "
                  "(privilege escalation)"),
}


def ts_ms(s: str) -> int:
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


def build(name: str, src: Path) -> dict[str, Any]:
    pred, tech, tactic, cite = SETS[name]
    seen: set[str] = set()
    pos: list[dict] = []
    for _, kind, raw in iter_raw([src]):
        if kind != "record":
            continue
        r = json.loads(raw)
        if not pred(r):
            continue
        eid = str(r.get("eventID"))
        if eid in seen:  # duplicate copy of the same CloudTrail event
            continue
        seen.add(eid)
        pos.append(r)
    groups: dict[tuple, list[dict]] = {}
    for r in sorted(pos, key=lambda x: x["eventTime"]):
        key = (r.get("recipientAccountId"), _caller(r), r.get("sourceIPAddress"), r["eventTime"][:10])
        groups.setdefault(key, []).append(r)
    attacks = []
    for n, (key, rs) in enumerate(sorted(groups.items(), key=lambda kv: kv[1][0]["eventTime"]), start=1):
        steps, last = [], None
        for r in rs:
            t = ts_ms(r["eventTime"])
            if last is None or t - last > GAP_MS:
                steps.append({"step": len(steps) + 1, "ts_ms": t, "technique_id": tech, "tactic": tactic,
                              "host": key[0], "user": key[1], "src_ip": key[2], "dst_ip": None,
                              "evidence": {"eventName": r["eventName"], "eventTime": r["eventTime"],
                                           "eventID": r.get("eventID")}})
            last = t
        attacks.append({"id": f"{name.upper()}{n}", "source": cite, "steps": steps})
    return {"attack_version": "v20", "dataset": f"ext_cloud_splunk_{name}",
            "derivation": "documented criteria in tools/ext/cloud_gt_build.py; one attack per (account, caller, IP, "
                          "UTC day); one step per run of positive events with gaps <= 10 min",
            "positive_events": len(pos), "attacks": attacks}


def main() -> int:
    name, src, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    doc = build(name, src)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"{name}: positives={doc['positive_events']} attacks={len(doc['attacks'])} "
          f"steps={sum(len(a['steps']) for a in doc['attacks'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
