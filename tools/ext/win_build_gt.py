"""Build ground_truth/attacks.json (TESTING.md §3.3) for the external Windows datasets, from documentation only.

Sources (all fetched into data/raw/ext_win_<name>/.dl/ and hashed in SOURCE.md):
- APT29 day 1: MITRE / OTRF emulation plan (apt29.xlsx: steps, hosts, users) + OTRF ThreatHunter-Playbook step
  YAMLs (docs/evals/apt29/steps at commit f7a58156, the commit before they were removed): technique per sub-step
  and the UtcTime printed in the documented query output. Legacy ATT&CK IDs are mapped to v20 (LEGACY below).
- Atomic sets: OTRF metadata yaml (technique, tactic, adversary view: host, user, time). Where the docs name no
  time or no account, a documented string (the command / module / artefact in the metadata) anchors one raw event
  and only its time and account are read. That is stated per step in "gt_notes".

Never reads pipeline output. Run BEFORE any AttackLens run:
    python -I tools/ext/win_build_gt.py apt29d1 SUMMARY.json      (SUMMARY from win_otrf_steps.py)
    python -I tools/ext/win_build_gt.py atomic NAME
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[2]
V20 = json.loads((ROOT / "config" / "attack_v20.json").read_text(encoding="utf-8"))
TACTIC_ORDER = [t["name"] for t in V20["tactics"]]

# ATT&CK v6-era IDs used by the APT29 plan -> v20 (MITRE revoked-by relationships; T1043 deprecated, no successor).
LEGACY = {"T1065": "T1571", "T1032": "T1573", "T1086": "T1059.001", "T1002": "T1560", "T1022": "T1560",
          "T1122": "T1546.015", "T1088": "T1548.002", "T1043": None, "T1107": "T1070.004", "T1063": "T1518.001",
          "T1050": "T1543.003", "T1060": "T1547.001", "T1081": "T1552.001", "T1145": "T1552.004",
          "T1028": "T1021.006", "T1045": "T1027.002", "T1077": "T1021.002", "T1035": "T1569.002",
          "T1562.002": "T1685.001"}  # v20 bundle: Disable Windows Event Logging -> Disable or Modify Windows Event Log
# Multi-tactic techniques: tactic from the plan stage / metadata (must be valid for the technique in v20).
TACTIC_HINT = {"T1546.015": "Privilege Escalation", "T1112": "Defense Impairment", "T1543.003": "Persistence",
               "T1547.001": "Persistence", "T1056": "Collection", "T1134": "Privilege Escalation"}


def v20(tid: str) -> str | None:
    t = LEGACY.get(tid, tid)
    if t is not None and t not in V20["techniques"]:
        raise ValueError(f"{tid} -> {t} not in ATT&CK v20")
    return t


def tactic_of(tid: str, hint: str | None = None) -> str:
    valid = V20["techniques"][tid]["tactics"]
    h = hint or TACTIC_HINT.get(tid)
    if h in valid:
        return h
    return sorted(valid, key=TACTIC_ORDER.index)[0]   # rule: first valid tactic in v20 kill-chain order


def ms(utc: str) -> int:
    s = utc.replace("T", " ").rstrip("Z")
    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in s else "%Y-%m-%d %H:%M:%S"
    return int(datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).timestamp() * 1000)


def iso(t: int) -> str:
    return datetime.fromtimestamp(t / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def write(name: str, doc: dict) -> None:
    d = ROOT / "data" / "raw" / f"ext_win_{name}" / "ground_truth"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "attacks.json"
    if p.exists():
        raise SystemExit(f"{p} exists: ground truth is write-once (see tools/ext/README in reports/ext/win_eval.md)")
    p.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(p.as_posix(), hashlib.sha256(p.read_bytes()).hexdigest())


# ---------------------------------------------------------------- APT29 day 1
SCR, NAS = "SCRANTON.dmevals.local", "NASHUA.dmevals.local"
# lettered step -> (host, user, src_ip, dst_ip, tactic hint for the step's primary technique)
# hosts/users: plan Target / User columns + OTRF descriptions (Pam = pbeesly; SCRANTON 10.0.1.4, NASHUA 10.0.1.6)
STEPS = {
    "1.A": (SCR, "pbeesly", None, None), "1.B": (SCR, "pbeesly", None, None),
    "2.A": (SCR, "pbeesly", None, None), "2.B": (SCR, "pbeesly", None, None),
    "3.A": (SCR, "pbeesly", None, None), "3.B": (SCR, "pbeesly", None, None), "3.C": (SCR, "pbeesly", None, None),
    "4.A": (SCR, "pbeesly", None, None), "4.B": (SCR, "pbeesly", None, None), "4.C": (SCR, "pbeesly", None, None),
    "5.A": (SCR, "pbeesly", None, None), "5.B": (SCR, "pbeesly", None, None),
    "6.A": (SCR, "pbeesly", None, None), "6.B": (SCR, "pbeesly", None, None), "6.C": (SCR, "pbeesly", None, None),
    "7.A": (SCR, "pbeesly", None, None), "7.B": (SCR, "pbeesly", None, "192.168.0.4"),
    "8.A": (SCR, "pbeesly", None, None),
    "8.B": (NAS, "pbeesly", "10.0.1.4", None), "8.C": (NAS, "pbeesly", "10.0.1.4", None),
    "9.A": (NAS, "pbeesly", None, None), "9.B": (NAS, "pbeesly", None, None), "9.C": (NAS, "pbeesly", None, None),
    "10.A": (SCR, "SYSTEM", None, None), "10.B": (SCR, "pbeesly", None, None),
}
SUB_HOST = {"8.A.2": (SCR, "pbeesly", None, "10.0.1.6"), "8.A.3": (NAS, "pbeesly", "10.0.1.4", None)}
DATA_END_UTC = "2020-05-02 03:28:17.683"   # last Sysmon UtcTime of the published file (dataset timeframe end)


def apt29d1(summary_path: str) -> None:
    subs = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    by_letter: dict[str, list[dict]] = {}
    for s in subs:
        by_letter.setdefault(".".join(s["substep"].split(".")[:2]), []).append(s)
    letters = list(STEPS)
    # documented step time = earliest UtcTime among the step's sub-steps, ignoring a time earlier than the previous
    # documented step (the plan is executed in order; 4.A.1's output is step 2.A's Draft.Zip, a doc copy error)
    times: dict[str, int | None] = {}
    prev = 0
    for L in letters:
        cands = [ms(t) for s in by_letter[L] for t in s["times"] if " " in t and len(t) > 19]  # UtcTime has ms
        cands = [t for t in cands if t >= prev]
        times[L] = min(cands) if cands else None
        if times[L] is not None:
            prev = times[L]
    notes: dict[str, str] = {}
    for i, L in enumerate(letters):  # no documented time: midpoint of the window between neighbouring steps
        if times[L] is None:
            lo = next(times[x] for x in reversed(letters[:i]) if times[x] is not None)
            hi = next((times[x] for x in letters[i + 1:] if times[x] is not None), ms(DATA_END_UTC))
            times[L] = (lo + hi) // 2
            notes[L] = f"no documented time; midpoint of window {iso(lo)} .. {iso(hi)}"
    steps, sub_steps = [], []
    for n, L in enumerate(letters, start=1):
        first = by_letter[L][0]
        tid = v20(first["technique"])
        host, user, sip, dip = STEPS[L]
        steps.append({"step": n, "ts_ms": times[L], "technique_id": tid, "tactic": tactic_of(tid), "host": host,
                      "user": user, "src_ip": sip, "dst_ip": dip, "emulation_step": L,
                      "technique_legacy": first["technique"], "procedure": first["procedure"],
                      "gt_notes": notes.get(L, "time = earliest UtcTime in OTRF documented output of this step")})
    k = 0
    for L in letters:
        for s in by_letter[L]:
            tid = v20(s["technique"])
            if tid is None:
                continue  # deprecated technique with no v20 successor (T1043)
            k += 1
            own = [ms(t) for t in s["times"] if " " in t and len(t) > 19]
            own = [t for t in own if t >= times[L] - 60_000]
            host, user, sip, dip = SUB_HOST.get(s["substep"], STEPS[L])
            sub_steps.append({"step": k, "ts_ms": min(own) if own else times[L], "technique_id": tid,
                              "tactic": tactic_of(tid), "host": host, "user": user, "src_ip": sip, "dst_ip": dip,
                              "emulation_step": s["substep"], "technique_legacy": s["technique"],
                              "gt_notes": "own documented UtcTime" if own else f"time of step {L}"})
    doc = {"attack_version": "v20", "source": "MITRE APT29 emulation plan day 1 (OTRF apt29.xlsx) + OTRF "
           "ThreatHunter-Playbook docs/evals/apt29/steps @f7a58156", "granularity": "emulation step (letter)",
           "attacks": [{"id": "APT29-D1", "steps": steps}]}
    write("apt29d1", doc)
    sub = ROOT / "data" / "raw" / "ext_win_apt29d1" / "ground_truth" / "substeps"
    sub.mkdir(exist_ok=True)
    p = sub / "attacks.json"
    if p.exists():
        raise SystemExit(f"{p} exists")
    p.write_text(json.dumps({"attack_version": "v20", "granularity": "ATT&CK Evals sub-step",
                             "attacks": [{"id": "APT29-D1", "steps": sub_steps}]}, indent=1), encoding="utf-8")
    print(p.as_posix(), hashlib.sha256(p.read_bytes()).hexdigest())


# ---------------------------------------------------------------- atomic sets
# technique / tactic / host / user: metadata yaml. anchor: a documented string -> one raw event (time, account).
ATOMIC = {
    "lsass_comsvcs": {"id": "SDWIN-201018195009", "technique": "T1003.001", "tactic": "Credential Access",
                      "host": "WORKSTATION5", "user": None,
                      "anchor": "lower(j->>'CommandLine') LIKE '%comsvcs%minidump%'",
                      "doc": "adversary view: rundll32.exe comsvcs.dll, MiniDump (Get-Process lsass).id ...; host = "
                             "the only Hostname in the recording (metadata says 'Lab VM')"},
    "vbs_launcher": {"id": "SDWIN-190518182022", "technique": "T1059.005", "tactic": "Execution",
                     "host": "WORKSTATION5.theshire.local", "user": None,
                     "anchor": "j->>'EventID' = '1' AND regexp_matches(lower(j->>'CommandLine'), '\\.vbs')",
                     "doc": "agent from 172.18.39.5 (= WORKSTATION5 in the Mordor shire docs); .vbs launcher"},
    "runkeys": {"id": "SDWIN-190319023812", "technique": "T1547.001", "tactic": "Persistence",
                "host": "WORKSTATION5.theshire.local", "user": "pgustavo",
                "anchor": "j->>'EventID' = '13' AND lower(j->>'TargetObject') LIKE '%\\currentversion\\run\\%'"
                          " AND lower(j->>'Image') LIKE '%powershell%'",
                "doc": "agent KU86XWEL WORKSTATION5 THESHIRE\\pgustavo, persistence/userland/registry (HKCU Run)"},
    "psexec": {"id": "SDWIN-190518210652", "technique": "T1021", "tactic": "Lateral Movement",
               "host": "WORKSTATION6.theshire.local", "user": "pgustavo", "src_ip": "172.18.39.5",
               "anchor": "j->>'EventID' IN ('7045', '4697') AND j->>'Hostname' ILIKE 'workstation6%'",
               "doc": "agent UF5MYK42 WORKSTATION5 172.18.39.5 THESHIRE\\pgustavo, invoke_psexec ComputerName "
                      "WORKSTATION6.theshire.local (remote service create + start)"},
    "sharpwmi": {"id": "SDWIN-200806035621", "technique": "T1047", "tactic": "Execution",
                 "host": "WORKSTATION6.theshire.local", "user": None,
                 "anchor": "j->>'EventID' IN ('1', '4688') AND j->>'Hostname' ILIKE 'workstation6%' AND "
                           "lower(coalesce(j->>'Image', j->>'NewProcessName')) LIKE '%grunthttp2.exe'",
                 "doc": "SharpWMI action=exec computername=WORKSTATION6 command=C:\\Windows\\System32\\GruntHTTP2.exe"},
    "overpth": {"id": "SDWIN-190319131123", "technique": "T1550.002", "tactic": "Stealth",
                "host": "WORKSTATION6.theshire.local", "user": "wardog",
                "anchor": "j->>'EventID' = '4624' AND j->>'LogonType' = '9' AND j->>'Hostname' ILIKE 'workstation6%'",
                "doc": "agent 4EH9PC5S WORKSTATION6 THESHIRE\\wardog, mimikatz/pth user pgustavo; metadata tactics "
                       "TA0005 (-> v20 Stealth) and TA0008; first listed valid tactic used"},
    "evtlog_disable": {"id": "SDWIN-220708104215", "technique": "T1562.002", "tactic": "Defense Impairment",
                       "host": "Pedro01", "user": "IT01-Pedro", "doc_time": "2022-08-04 15:36:38",
                       "anchor": "j->>'EventID' = '13' AND lower(j->>'TargetObject') LIKE "
                                 "'%\\services\\eventlog\\start'",
                       "doc": "meterpreter session 21 opened 2022-08-04 11:36:38 -0400, powershell_execute "
                              "Set-Service -Name EventLog -StartUpType Disabled; user dir C:\\Users\\IT01-Pedro"},
}


def anchor(name: str, where: str) -> tuple[int | None, str | None, int]:
    files = sorted((ROOT / "data" / "raw" / f"ext_win_{name}" / "src").glob("*.json"))
    con = duckdb.connect()
    con.execute("SET TimeZone='UTC'")
    lst = "[" + ",".join("'" + f.as_posix().replace("'", "''") + "'" for f in files) + "]"
    con.execute(f"CREATE TEMP TABLE r AS SELECT line::JSON j FROM read_csv({lst}, columns={{'line':'VARCHAR'}}, "
                "delim=CHR(1), quote='', escape='', header=false, auto_detect=false, max_line_size=67108864) "
                "WHERE json_valid(line)")
    rows = con.execute(f"SELECT j->>'UtcTime', coalesce(j->>'User', j->>'TargetUserName', j->>'SubjectUserName') "
                       f"FROM r WHERE {where} AND j->>'UtcTime' IS NOT NULL ORDER BY j->>'UtcTime'").fetchall()
    if not rows:
        rows = con.execute(f"SELECT j->>'@timestamp', coalesce(j->>'User', j->>'TargetUserName', "
                           f"j->>'SubjectUserName') FROM r WHERE {where} ORDER BY 1").fetchall()
    if not rows:
        return None, None, 0
    return ms(rows[0][0]), rows[0][1], len(rows)


def atomic(name: str) -> None:
    a = ATOMIC[name]
    tid = v20(a["technique"])
    tac = a["tactic"]
    if tac not in V20["techniques"][tid]["tactics"]:
        raise ValueError(f"{tac} not valid for {tid}")
    t, acct, n = anchor(name, a["anchor"])
    notes = [a["doc"]]
    if t is None:
        if "doc_time" not in a:
            raise SystemExit(f"{name}: anchor found nothing and no documented time")
        t = ms(a["doc_time"])
        notes.append("time = documented session time (explicit -0400 offset); anchor found no event")
    else:
        notes.append(f"time = first of {n} anchor events ({a['anchor']})")
        if "doc_time" in a:
            notes.append(f"documented time {a['doc_time']}Z; anchor offset {(t - ms(a['doc_time'])) / 1000:.0f} s")
    user = a["user"]
    if user is None:
        user = acct
        notes.append(f"user not documented: account of the anchor event ({acct})")
    step = {"step": 1, "ts_ms": t, "technique_id": tid, "tactic": tac, "host": a["host"], "user": user,
            "src_ip": a.get("src_ip"), "dst_ip": None, "technique_metadata": a["technique"], "gt_notes": "; ".join(notes)}
    write(name, {"attack_version": "v20", "source": f"OTRF Security-Datasets metadata {a['id']}",
                 "attacks": [{"id": a["id"], "steps": [step]}]})


if __name__ == "__main__":
    if sys.argv[1] == "apt29d1":
        apt29d1(sys.argv[2])
    else:
        atomic(sys.argv[2])
