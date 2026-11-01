"""Generate the Azure attack dataset (Key Vault, Microsoft Graph activity, Entra ID Protection, AAD* sign-in tables,
diagnostic-export shapes) with ground truth.

    python tools/cloud_attacks/gen_azure.py --out data/raw/cloud_azure --seed 11 [--scale 1.0] [--force]

Layout (one record shape per bucket folder, routed by content exactly as Stage 0 does):
    <out>/azure_monitor/<table>/part-*.jsonl      Log Analytics rows (SigninLogs, AAD*, AZKVAuditLogs, ...)
    <out>/azure_export/<category>/part-*.jsonl    diagnostic-settings export records (storage account / Event Hub)
    <out>/graph_api/riskdetections/part-*.jsonl   Microsoft Graph riskDetection objects
    <out>/manifest.json, <out>/ground_truth/attacks.json (harness schema)
Benign baseline: 14 days, 48 staff (diurnal, weekends x0.15), CI / HR-sync / inventory / mail-backup / rotation service
principals, managed identities reading Key Vault, low-risk Identity Protection noise, decoys (azure_stories). Records
carry NO ground-truth field.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[1]))   # tools/ on path so `cloud_attacks` imports when run as a script

from cloud_attacks import azure_feeds as A   # noqa: E402
from cloud_attacks import azure_stories as S   # noqa: E402
from cloud_attacks import formats as F   # noqa: E402
from cloud_attacks.baseline import AZ_OPS, W, WSUM, _count, human_ip   # noqa: E402
from cloud_attacks.common import (ALL_STAFF, AZ_AUTOMATION_IP, CI_IPS, CORP_IPS, DAY, DOMAIN, HOUR, MIN,  # noqa: E402
                                  SEC, START_MS, TRAVEL_IP, Ev, Rand, home_ip, iso_s, staff_index, sub_rng)

DAYS = 14
MAX_PART_BYTES = 8 * 1024 * 1024
FEED_DEST = {"signin": ("azure_monitor", "signinlogs"), "signin_x": ("azure_export", "signinlogs"),
             "signin_ni": ("azure_monitor", "aadnoninteractiveusersigninlogs"),
             "signin_sp": ("azure_monitor", "aadserviceprincipalsigninlogs"),
             "signin_mi": ("azure_monitor", "aadmanagedidentitysigninlogs"),
             "audit": ("azure_monitor", "auditlogs"), "audit_x": ("azure_export", "auditlogs"),
             "activity": ("azure_monitor", "azureactivity"), "activity_x": ("azure_export", "administrative"),
             "kv": ("azure_monitor", "azkvauditlogs"), "kv_x": ("azure_export", "keyvault_auditevent"),
             "kv_diag": ("azure_monitor", "azurediagnostics"), "graph": ("azure_monitor", "microsoftgraphactivitylogs"),
             "graph_x": ("azure_export", "microsoftgraphactivitylogs"), "risk": ("azure_monitor", "aaduserriskevents"),
             "risk_sp": ("azure_monitor", "aadserviceprincipalriskevents"),
             "risk_api": ("graph_api", "riskdetections"), "riskyusers": ("azure_monitor", "aadriskyusers")}
# per weekday at scale 1 (human, diurnal)
RATE = {"signin": 160, "session": 500, "activity": 40, "audit": 15}
USERS = [u for u, _, _ in ALL_STAFF]
ADMINS = ("asharma", "rnair", "akumar")
USER_PATHS = ("/me", "/me/messages?$top=25", "/me/events?$top=10", "/me/drive/recent", "/me/chats",
              "/users/{c}/photo/$value", "/groups/{g}/members?$top=50", "/me/mailFolders/inbox/messages/delta")
SP_IP = {"hr-sync": AZ_AUTOMATION_IP, "secinventory": "198.51.100.61", "mailbackup": "198.51.100.62",
         "kv-rotator": "198.51.100.63"}
MI_IP = {"mi-payroll-web": "10.20.1.4", "mi-func-billing": "10.20.2.7"}
AUDIT_OPS = (("Update user", "UserManagement"), ("Reset user password", "UserManagement"),
             ("Add member to group", "GroupManagement"), ("Update group", "GroupManagement"),
             ("Update application", "ApplicationManagement"))


def _geo(ip: str) -> tuple[str, str]:
    return ("SG", "Singapore") if ip == TRAVEL_IP else ("IN", "Bengaluru")


def _tok(r: Rand) -> str:
    return "tok-" + r.guid()


def humans(r: Rand, t0: int, day: int, hour: int, wk: float, scale: float) -> list[Ev]:
    out: list[Ev] = []
    f = W[hour] / WSUM * wk * scale
    for _ in range(_count(r, RATE["signin"] * f)):                       # interactive sign-ins
        u, t = r.choice(USERS), t0 + r.randrange(HOUR - 5 * MIN)
        ip = human_ip(r, u, day)
        cc, city = _geo(ip)
        x = r.random()
        if x < 0.03:
            out.append(F.signin(r, t, u, u, ip, result="50126", country=cc, city=city))
            t += r.randint(20, 90) * SEC
        elif x < 0.08:
            out.append(F.signin(r, t, u, u, ip, result="50074", country=cc, city=city))
            t += r.randint(10, 40) * SEC
        ev = F.signin(r, t, u, u, ip, country=cc, city=city, app=r.choice(("Azure Portal", "Microsoft Teams",
                                                                        "Office 365 Exchange Online")),
                      mfa="Mobile app notification" if r.random() < 0.7 else None)
        tok = _tok(r)
        ev.doc["UniqueTokenIdentifier"] = tok
        out.append(A.signin_export(ev, tok) if r.random() < 0.1 else ev)
    for _ in range(_count(r, RATE["session"] * f)):                      # token refresh + Graph from the same IP
        u, t = r.choice(USERS), t0 + r.randrange(HOUR - 15 * MIN)
        ip, tok, uid = human_ip(r, u, day), _tok(r), F._uid(u)
        out.append(A.signin_ni(r, t, u, ip, tok, cc=_geo(ip)[0]))
        for k in range(r.randint(1, 4)):
            p = r.choice(USER_PATHS).format(c=F._uid(r.choice(USERS)), g=r.guid())
            out.append(A.graph(r, t + (k + 1) * r.randint(5, 120) * SEC, "graph", uid, p, ip, tok,
                               status=404 if "photo" in p and r.random() < 0.2 else 200))
    for _ in range(_count(r, RATE["activity"] * f)):
        u, t = r.choice(ADMINS), t0 + r.randrange(HOUR - MIN)
        evs = F.activity(r, t, r.choice(AZ_OPS), f"{u}@{DOMAIN}", CORP_IPS[staff_index(u) % 2],
                         F.res_id(f"resourcegroups/rg-prod/providers/microsoft.compute/virtualmachines/vm-{r.randint(1, 30)}"))
        out += [A.activity_export(e, u) for e in evs] if r.random() < 0.15 else evs
    for _ in range(_count(r, RATE["audit"] * f)):
        u, (op, cat) = r.choice(ADMINS), r.choice(AUDIT_OPS)
        ev = F.audit(r, t0 + r.randrange(HOUR - MIN), op, cat, CORP_IPS[staff_index(u) % 2],
                     [F.user_target(r.choice(USERS))], actor=u)
        out.append(A.audit_export(ev) if r.random() < 0.2 else ev)
    return out


def automation(r: Rand, t0: int, day: int, hour: int) -> list[Ev]:
    out: list[Ev] = []
    weekday = day % 7 < 5
    ci_ip = CI_IPS[r.randrange(len(CI_IPS))]
    out.append(A.signin_sp(r, t0 + r.randrange(10 * MIN), S.CI_SP, ci_ip, _tok(r), resource="Azure Resource Manager"))
    if weekday and hour in (5, 8, 11):                                    # deploys read 4 app secrets
        t = t0 + 20 * MIN + r.randrange(10 * MIN)
        out.append(A.signin_sp(r, t, S.CI_SP, ci_ip, _tok(r)))
        out += [A.kv(r, t + (i + 1) * 3 * SEC, "kv", "kv-prod-app", "SecretGet", S.sp_app(S.CI_SP), ci_ip,
                     f"secrets/{n}", ua=A.UA_KV_PY) for i, n in enumerate(S.SECRETS_PROD[:4])]
        out += F.activity(r, t + MIN, "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE", S.sp_app(S.CI_SP), ci_ip,
                          F.res_id(f"resourcegroups/rg-prod/providers/microsoft.resources/deployments/rel-{r.hexs(6)}"))
    tok = _tok(r)                                                         # hr-sync: hourly user directory sync
    out.append(A.signin_sp(r, t0 + 2 * MIN, "hr-sync", SP_IP["hr-sync"], tok, resource="Microsoft Graph"))
    out += [A.graph(r, t0 + 3 * MIN + k * 4 * SEC, "graph", "spid-hr-sync", f"/users?$select=id,department&$top=999"
                    f"&$skiptoken={r.hexs(8)}", SP_IP["hr-sync"], tok, sp=True, ua="hr-sync/3.2",
                    roles="User.Read.All", app=S.sp_app("hr-sync")) for k in range(2)]
    if hour == 1:                                                         # ZD3 nightly directory inventory
        tok = _tok(r)
        out.append(A.signin_sp(r, t0 + 4 * MIN, "secinventory", SP_IP["secinventory"], tok, resource="Microsoft Graph"))
        out += [A.graph(r, t0 + 5 * MIN + k * 5 * SEC, "graph", "spid-secinventory",
                        f"{S.ENUM_PATHS[k % 6]}?$top=999&$skiptoken={r.hexs(8)}", SP_IP["secinventory"], tok, sp=True,
                        ua="secinventory/5.1", roles="Directory.Read.All", app=S.sp_app("secinventory"))
                for k in range(60)]
    if hour == 0:                                                         # ZD4 nightly mailbox backup (export shape)
        tok = _tok(r)
        out.append(A.signin_sp(r, t0 + 10 * MIN, "mailbackup", SP_IP["mailbackup"], tok, resource="Microsoft Graph"))
        out += [A.graph(r, t0 + 11 * MIN + k * 20 * SEC, "graph_x", "spid-mailbackup",
                        f"/users/{u}@{DOMAIN}/messages/delta", SP_IP["mailbackup"], tok, sp=True, ua="mailbackup/1.4",
                        roles="Mail.Read", app=S.sp_app("mailbackup")) for k, u in enumerate(USERS[:40])]
    if day % 7 == 0 and hour == 4:                                        # ZD5 Monday rotation: SET, not read
        ip = SP_IP["kv-rotator"]
        out.append(A.signin_sp(r, t0 + MIN, "kv-rotator", ip, _tok(r)))
        out += [A.kv(r, t0 + 2 * MIN + i * 4 * SEC, "kv", "kv-prod-app", op, S.sp_app("kv-rotator"), ip,
                     f"secrets/{n}", ua=A.UA_KV_NET)
                for i, (op, n) in enumerate([("SecretSet", n) for n in S.SECRETS_PROD] +
                                            [("SecretGet", n) for n in S.SECRETS_PROD[:3]])]
    for mi, ip in MI_IP.items():                                          # managed identities
        out.append(A.signin_sp(r, t0 + r.randrange(5 * MIN), mi, ip, _tok(r), managed=True))
    for m in range(0, 60, 20):
        out += [A.kv(r, t0 + m * MIN + i * SEC, "kv", "kv-prod-app", "SecretGet", S.sp_app("mi-payroll-web"),
                     MI_IP["mi-payroll-web"], f"secrets/{n}", ua=A.UA_KV_NET) for i, n in enumerate(("payroll-db", "jwt-signing"))]
    out.append(A.kv(r, t0 + 30 * MIN, "kv", "kv-shared", "SecretGet", S.sp_app("mi-func-billing"), MI_IP["mi-func-billing"],
                    "secrets/billing-api-key", ua=A.UA_KV_NET))
    if hour in (3, 9):                                                    # ZD6 stale access policy: one 403
        out.append(A.kv(r, t0 + 31 * MIN, "kv_x", "kv-finance", "SecretGet", S.sp_app("mi-func-billing"),
                        MI_IP["mi-func-billing"], "secrets/ledger-db", status=403, ua=A.UA_KV_NET))
    if hour % 2 == 0:                                                     # legacy batch app via AzureDiagnostics
        out += [A.kv(r, t0 + 40 * MIN + i * SEC, "kv_diag", "kv-legacy", "SecretGet", S.sp_app("legacy-batch"),
                     "10.20.3.9", f"secrets/{n}", ua=A.UA_KV_NET) for i, n in enumerate(("ftp-password", "db-conn"))]
    return out


def people_ops(r: Rand, t0: int, day: int, hour: int) -> list[Ev]:
    """Daily admin / finance Key Vault use, the admin-center browsing decoy, Identity Protection noise."""
    out: list[Ev] = []
    weekday = day % 7 < 5
    if weekday and hour == 5:                                             # ZD7 admin center browsing (4 types)
        ip, tok, uid = CORP_IPS[0], _tok(r), F._uid("asharma")
        out.append(A.signin_ni(r, t0, "asharma", ip, tok, app="Azure Portal"))
        out += [A.graph(r, t0 + MIN + k * 20 * SEC, "graph", uid, f"{S.ENUM_PATHS[k % 4]}?$top=100", ip, tok,
                        ua=F.UA_CONSOLE, app="c44b4083-3bb0-49c1-b47d-974e53cbdf3c") for k in range(12)]
    if weekday and hour == 6:
        out.append(A.kv(r, t0 + 5 * MIN, "kv_x", "kv-finance", "SecretList", "asharma@corp.example", CORP_IPS[0],
                        ua=A.UA_PS))
        ip = human_ip(r, "nbose", day)
        out.append(A.kv(r, t0 + 20 * MIN, "kv_x", "kv-finance", "SecretGet", "nbose@corp.example", ip,
                        "secrets/erp-admin", ua=A.UA_PS))
    if hour == 7 and r.random() < 0.6:                                    # Identity Protection noise (low / closed)
        u = r.choice(USERS)
        ip = home_ip(staff_index(u))
        rtype = r.choice(("unfamiliarFeatures", "unfamiliarFeatures", "leakedCredentials", "anonymizedIPAddress"))
        state = r.choice(("remediated", "dismissed", "atRisk"))
        level = "medium" if (rtype == "unfamiliarFeatures" and r.random() < 0.2) else "low"
        out.append(A.risk(r, t0 + r.randrange(HOUR), "risk_api" if r.random() < 0.2 else "risk", u, rtype, ip,
                          level=level, state=state, detail="userPassedMFADrivenByRiskBasedPolicy"
                          if state == "remediated" else "none"))
    if hour == 0:                                                         # daily risky-user snapshot
        for u, lvl, st, det in ((USERS[20], "low", "atRisk", "none"), (USERS[31], "none", "remediated",
                                "userPerformedSecuredPasswordChange"), (USERS[7], "none", "dismissed",
                                                                        "adminDismissedAllRiskForUser")):
            out.append(A.risky_user(r, t0 + 30 * MIN, u, lvl, st, det))
    return out


def generate(seed: int, scale: float) -> tuple[list[Ev], list[S.Story], list[dict]]:
    out: list[Ev] = []
    for day in range(DAYS):
        wk = 0.15 if day % 7 >= 5 else 1.0
        for hour in range(24):
            t0 = START_MS + day * DAY + hour * HOUR
            out += humans(sub_rng(seed, "azh", day, hour), t0, day, hour, wk, scale)
            out += automation(sub_rng(seed, "aza", day, hour), t0, day, hour)
            out += people_ops(sub_rng(seed, "azp", day, hour), t0, day, hour)
    stories, decoys = S.build_stories(seed), S.build_decoys(seed)
    for s in stories:
        out += s.events()
    for d in decoys:
        out += d["_events"]
    out.sort(key=lambda e: (e.ts, e.feed, e.rid))
    return out, stories, decoys


def write(out: Path, seed: int, scale: float, force: bool) -> dict:
    if out.exists():
        if not force and any(out.iterdir()):
            raise SystemExit(f"refusing to write into non-empty {out} (use --force)")
        shutil.rmtree(out)
    out.mkdir(parents=True)
    t0 = time.time()
    evs, stories, decoys = generate(seed, scale)
    by_dest: dict[tuple[str, str], list[Ev]] = {}
    for e in evs:
        by_dest.setdefault(FEED_DEST[e.feed], []).append(e)
    parts, total = [], 0
    for (src, bucket), items in sorted(by_dest.items()):
        d = out / src / bucket
        d.mkdir(parents=True, exist_ok=True)
        buf: list[str] = []
        nbytes, seq = 0, 0
        for i, e in enumerate(items):
            ln = json.dumps(e.doc, ensure_ascii=False, default=str) + "\n"
            buf.append(ln)
            nbytes += len(ln.encode("utf-8"))
            if nbytes >= MAX_PART_BYTES or i == len(items) - 1:
                seq += 1
                p = d / f"part-{seq:04d}.jsonl"
                data = "".join(buf)
                p.write_text(data, encoding="utf-8", newline="")
                parts.append({"source": src, "bucket": bucket, "file": p.relative_to(out).as_posix(),
                              "events": len(buf), "bytes": len(data.encode("utf-8"))})
                total += len(data.encode("utf-8"))
                buf, nbytes = [], 0
    decoy_gt = [{k: v for k, v in d.items() if k != "_events"} for d in decoys] + S.RECURRING_DECOYS
    gt = {"attack_version": "v20", "anchor_ms": START_MS, "anchor": iso_s(START_MS),
          "generated_by": "tools/cloud_attacks/gen_azure.py", "seed": seed, "size": f"scale{scale:g}",
          "note": "Azure track: Key Vault, Graph activity, Identity Protection, AAD* + export shapes; all IPs RFC 5737 / "
                  "RFC 1918; attacker infrastructure 203.0.113.140-189 only.",
          "attacks": [s.gt() for s in stories], "decoys": decoy_gt}
    (out / "ground_truth").mkdir()
    (out / "ground_truth" / "attacks.json").write_text(json.dumps(gt, indent=1), encoding="utf-8")
    h = hashlib.sha256()
    for p in sorted(_HERE.parent.glob("*.py")):
        h.update(p.read_bytes())
    manifest = {"generator": "tools/cloud_attacks/gen_azure.py", "generator_sha256": h.hexdigest(), "seed": seed,
                "scale": scale, "days": DAYS, "start": iso_s(START_MS), "end": iso_s(START_MS + DAYS * DAY),
                "total_events": len(evs), "total_bytes": total, "parts": parts,
                "feeds": sorted(f"{s}/{b}" for s, b in by_dest),
                "attacks": [{"id": s.id, "name": s.name, "steps": len(s.steps)} for s in stories],
                "decoys": [d["id"] for d in decoy_gt], "wall_s": round(time.time() - t0, 2)}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="generate the Azure attack dataset with ground truth")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--scale", type=float, default=1.0, help="benign human volume multiplier")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    m = write(a.out, a.seed, a.scale, a.force)
    print(f"wrote {m['total_events']} events, {m['total_bytes'] / 1e6:.1f} MB -> {a.out} in {m['wall_s']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
