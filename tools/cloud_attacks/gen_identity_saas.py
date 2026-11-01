"""Generate the identity SaaS attack dataset (Okta, Google Workspace, Microsoft 365, Auth0, Duo) with ground truth.

    python tools/cloud_attacks/gen_identity_saas.py --out data/raw/cloud_identity_saas --seed 7 [--force]

Layout (one folder per product / export, routed by content in Stage 0):
    <out>/okta/system_log/part-*.jsonl              Okta System Log LogEvent (/api/v1/logs)
    <out>/google_workspace/reports/part-*.jsonl     Admin SDK Reports activities (login / admin / token)
    <out>/google_workspace/cloud_logging/*.jsonl    the Cloud Logging copy (protoPayload, gcp_audit_json)
    <out>/m365/management_api|officeactivity|cloudappevents/*.jsonl   UAL in its three JSON delivery shapes
    <out>/auth0/logs/*.jsonl, <out>/duo/authentication/*.jsonl, <out>/aws_cloudtrail/cloudtrail/*.jsonl
    <out>/manifest.json, <out>/ground_truth/attacks.json (backend/eval harness schema)

Served records carry no ground-truth field. Stories follow public write-ups of IdP intrusions (Okta / Scattered
Spider push fatigue and session replay, Workspace OAuth abuse, M365 BEC forwarding + hiding rules, Auth0 credential
stuffing); every name, key and IP is fake (RFC 5737 ranges, .example domains).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[1]))   # tools/ on path when run as a script

from cloud_attacks import formats as fx, identity_saas_docs as dx   # noqa: E402
from cloud_attacks.common import ACCT_PROD, DAY, HOUR, MIN, SEC, START_MS, Ev, iso_s, sub_rng   # noqa: E402
from cloud_attacks.identity_saas_baseline import CORP_ASN, CUSTOMERS, STAFF, benign_day, home, home_asn   # noqa: E402

DAYS = 8
MAX_PART_BYTES = 8 * 1024 * 1024
SPRAY_IP, GWS_IP, BEC_IP, DUO_IP, STUFF_IP = "203.0.113.61", "203.0.113.71", "203.0.113.81", "203.0.113.91", "203.0.113.101"
EVIL_ASN = 64999


def at(day: int, hour: int, minute: int = 0) -> int:
    return START_MS + day * DAY + hour * HOUR + minute * MIN


@dataclass
class Step:
    technique_id: str
    tactic: str
    events: list[Ev]
    what: str
    user: Any = "__keep__"

    def gt(self, n: int) -> dict[str, Any]:
        a = min(self.events, key=lambda e: (e.ts, e.rid))
        ent = dx.entity(a)
        return {"step": n, "ts_ms": a.ts, "ts": iso_s(a.ts), "technique_id": self.technique_id, "tactic": self.tactic,
                "host": ent["host"], "user": ent["user"] if self.user == "__keep__" else self.user,
                "src_ip": ent["src_ip"], "dst_ip": None, "source": f"{dx.SOURCE_TYPE[a.feed]}:{ent['action']}",
                "event_id": a.rid, "events": len(self.events), "what": self.what}


@dataclass
class Story:
    id: str
    name: str
    sources: tuple[str, ...]
    steps: list[Step]
    extra: list[Ev] = field(default_factory=list)

    def events(self) -> list[Ev]:
        return [e for s in self.steps for e in s.events] + self.extra

    def gt(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "clouds": list(self.sources), "novel": False, "refs": [],
                "steps": [s.gt(i + 1) for i, s in enumerate(self.steps)]}


def s1_okta(seed: int) -> Story:
    """Okta: spray -> push fatigue -> session -> super admin grant -> API token -> own factor -> rogue IdP + policy off."""
    r = sub_rng(seed, "idsaas-s1")
    kw = {"asn": EVIL_ASN, "as_org": "bulletproof hosting", "ua": dx.UA_PY, "country": "Netherlands"}
    t = at(3, 18, 40)
    victims = [u for u in STAFF if u != "akumar"][3:18] + ["akumar"]
    spray = [dx.okta(r, t + i * 40 * SEC, "user.session.start", u, SPRAY_IP, result="FAILURE",
                     reason="INVALID_CREDENTIALS", **kw) for i, u in enumerate(victims[:-1])]
    t2 = t + 12 * MIN
    sess = "102" + r.b32(22)
    kw2 = {**kw, "ua": dx.UA_ATTACK, "sess": sess}
    push = []
    for k in range(7):
        push.append(dx.okta(r, t2 + k * 50 * SEC, "system.push.send_factor_verify_push", "akumar", SPRAY_IP, cred="OTP", **kw2))
        if k < 5:
            push.append(dx.okta(r, t2 + k * 50 * SEC + 30 * SEC, "user.mfa.okta_verify.deny_push", "akumar", SPRAY_IP,
                                result="DENY", reason="INVALID_CREDENTIALS", cred="OTP", **kw2))
    t3 = t2 + 7 * 50 * SEC
    mfa_ok = dx.okta(r, t3, "user.authentication.auth_via_mfa", "akumar", SPRAY_IP, cred="OTP", **kw2)
    login = dx.okta(r, t3 + 5 * SEC, "user.session.start", "akumar", SPRAY_IP, **kw2)
    grant = dx.okta(r, t3 + 15 * MIN, "user.account.privilege.grant", "akumar", SPRAY_IP,
                    target=dx.okta_user_target("anita.rao"), debug={"privilegeGranted": "Super administrator"}, **kw2)
    token = dx.okta(r, t3 + 20 * MIN, "system.api_token.create", "akumar", SPRAY_IP,
                    target=[{"id": "00T1", "type": "Token", "alternateId": "sync-token", "displayName": "sync-token"}], **kw2)
    factor = dx.okta(r, t3 + 25 * MIN, "user.mfa.factor.activate", "akumar", SPRAY_IP, cred="OTP", **kw2)
    t4 = at(4, 2, 10)
    idp = dx.okta(r, t4, "system.idp.lifecycle.create", "akumar", SPRAY_IP,
                  target=[{"id": "0oa9", "type": "IdentityProvider", "alternateId": "SAML partner", "displayName": "SAML partner"}],
                  **kw2)
    pol = dx.okta(r, t4 + 4 * MIN, "policy.rule.deactivate", "akumar", SPRAY_IP,
                  target=[{"id": "0pr1", "type": "PolicyRule", "alternateId": "Require MFA", "displayName": "Require MFA"}],
                  **kw2)
    # the same person federates into AWS from the attacker IP (unscored: shows the cross-source user link)
    ident = fx.assumed(r, ACCT_PROD, "AWSReservedSSO_AdministratorAccess_1a2b", "akumar@corp.example")
    aws = [fx.ct(r, t3 + 30 * MIN, ACCT_PROD, "ap-south-1", "sts.amazonaws.com", "GetCallerIdentity", ident, SPRAY_IP, ro=True),
           fx.ct(r, t3 + 31 * MIN, ACCT_PROD, "ap-south-1", "s3.amazonaws.com", "ListBuckets", ident, SPRAY_IP, ro=True)]
    return Story("I1", "Okta: password spray -> MFA push fatigue -> admin session -> super admin + API token + own factor "
                       "-> rogue IdP + MFA rule off", ("okta",), [
        Step("T1110.003", "Credential Access", spray, f"password spray over {len(spray)} users from one IP", user=None),
        Step("T1621", "Credential Access", push, "7 Okta Verify pushes, 5 denied, then approved"),
        Step("T1078.004", "Initial Access", [mfa_ok, login], "akumar session from the spraying IP"),
        Step("T1098.003", "Privilege Escalation", [grant], "Super administrator granted to anita.rao"),
        Step("T1098.001", "Persistence", [token], "Okta API token created"),
        Step("T1556.006", "Persistence", [factor], "attacker MFA factor enrolled for akumar"),
        Step("T1484.002", "Privilege Escalation", [idp], "new SAML identity provider"),
        Step("T1556.009", "Defense Impairment", [pol], "MFA policy rule deactivated"),
    ], extra=aws)


def s2_gws(seed: int) -> Story:
    r = sub_rng(seed, "idsaas-s2")
    t = at(4, 6, 10)
    users = ["dsingh", "mjoshi", "pmehta", "lfernandes", "vreddy", "tgupta", "rnair", "kiyer", "skapoor", "nbose",
             "akumar", "asharma"]
    spray = [dx.gws(r, t + i * 70 * SEC, "login", "login_failure", u, GWS_IP,
                    {"login_type": "google_password", "login_failure_type": "login_failure_invalid_password",
                     "is_suspicious": False}) for i, u in enumerate(users[:-1])]
    ok = dx.gws(r, t + 14 * MIN, "login", "login_success", "asharma", GWS_IP,
                {"login_type": "google_password", "is_suspicious": True})
    oauth = dx.gws(r, t + 24 * MIN, "token", "authorize", "asharma", GWS_IP,
                   {"client_id": "88231.apps.googleusercontent.com", "app_name": "Mail Exporter",
                    "scope": ["https://mail.google.com/", "https://www.googleapis.com/auth/drive"]})
    role = dx.gws_cl(r, t + 34 * MIN, "admin.googleapis.com", "google.admin.AdminService.assignRole", "ASSIGN_ROLE",
                     "asharma", GWS_IP, {"ROLE_NAME": "_SEED_ADMIN_ROLE", "USER_EMAIL": "it.helpdesk@corp.example"})
    dwd = dx.gws_cl(r, t + 39 * MIN, "admin.googleapis.com", "google.admin.AdminService.authorizeApiClientAccess",
                    "AUTHORIZE_API_CLIENT_ACCESS", "asharma", GWS_IP,
                    {"API_CLIENT_NAME": "104729384756", "API_SCOPES": "https://mail.google.com/"})
    off = dx.gws(r, t + 44 * MIN, "login", "2sv_disable", "asharma", GWS_IP, {})
    return Story("I2", "Workspace: spray -> suspicious admin login -> OAuth mail scope -> super admin -> domain-wide "
                       "delegation -> 2SV off", ("gws",), [
        Step("T1110.003", "Credential Access", spray, "Workspace password spray over 11 users", user=None),
        Step("T1078.004", "Initial Access", [ok], "suspicious login of the admin from the spraying IP"),
        Step("T1528", "Credential Access", [oauth], "OAuth grant with full mail + drive scope"),
        Step("T1098.003", "Privilege Escalation", [role], "super admin role assigned (Cloud Logging copy)"),
        Step("T1550.001", "Lateral Movement", [dwd], "domain-wide delegation for an API client"),
        Step("T1556.006", "Persistence", [off], "2-step verification disabled"),
    ])


def s3_bec(seed: int) -> Story:
    r = sub_rng(seed, "idsaas-s3")
    t = at(4, 9, 0)
    sess = "102" + r.b32(22)
    i = STAFF.index("kiyer")
    legit = dx.okta(r, t - 5 * MIN, "user.authentication.sso", "kiyer", home(i), sess=sess, asn=home_asn(i),
                    target=dx.okta_app_target("Office 365"))
    replay = [dx.okta(r, t + k * 2 * MIN, "user.authentication.sso", "kiyer", BEC_IP, sess=sess, asn=64998,
                      as_org="vps provider", ua=dx.UA_ATTACK, country="Netherlands",
                      target=dx.okta_app_target(a)) for k, a in enumerate(("Office 365", "Salesforce"))]
    aad = dx.ual(r, t + 3 * MIN, "UserLoggedIn", "kiyer", BEC_IP, "AzureActiveDirectory", status="Success",
                 ObjectId="00000003-0000-0ff1-ce00-000000000000")
    fwd = dx.ual(r, t + 8 * MIN, "New-InboxRule", "kiyer", f"{BEC_IP}:51544", "Exchange", shape="ual_la",
                 params={"Name": ".", "ForwardTo": "kiyer.backup@mail-relay.example", "StopProcessingRules": "False"})
    hide = dx.ual(r, t + 10 * MIN, "New-InboxRule", "kiyer", f"{BEC_IP}:51544", "Exchange", shape="ual_la",
                  params={"Name": "..", "SubjectOrBodyContainsWords": "invoice;payment;wire;bank",
                          "MoveToFolder": "RSS Feeds", "MarkAsRead": "True"})
    dl = [dx.ual(r, t + 15 * MIN + k * 15 * SEC, "FileDownloaded", "kiyer", BEC_IP, "SharePoint", status=None,
                 ObjectId=f"https://corp.sharepoint.com/sites/finance/Shared Documents/vendors/v{k:03d}.pdf",
                 SourceFileName=f"v{k:03d}.pdf", UserAgent=dx.UA_ATTACK) for k in range(120)]
    share = [dx.ual(r, t + 50 * MIN + k * MIN, "AnonymousLinkCreated", "kiyer", BEC_IP, "SharePoint", shape="cae",
                    status=None, ObjectId=f"https://corp.sharepoint.com/sites/finance/Shared Documents/bank/b{k}.xlsx",
                    SourceFileName=f"b{k}.xlsx") for k in range(8)]
    return Story("I3", "M365 BEC: Okta session cookie replay -> forwarding + hiding rules -> SharePoint mass download "
                       "-> anonymous links", ("okta", "m365"), [
        Step("T1550.004", "Lateral Movement", [legit] + replay, "the user's Okta session replayed from a VPS"),
        Step("T1114.003", "Collection", [fwd], "inbox rule forwarding to an external mailbox"),
        Step("T1564.008", "Stealth", [hide], "inbox rule hiding payment mails in RSS Feeds"),
        Step("T1213.002", "Collection", dl, "120 finance files downloaded in 30 min"),
        Step("T1567", "Exfiltration", share, "8 anonymous sharing links"),
    ], extra=[aad])


def s4_duo(seed: int) -> Story:
    r = sub_rng(seed, "idsaas-s4")
    t = at(5, 15, 0)
    deny = [dx.duo(r, t + k * 50 * SEC, "nbose", "denied", ("no_response", "user_cancelled")[k % 2], DUO_IP,
                   country="Netherlands") for k in range(8)]
    ok = dx.duo(r, t + 8 * 50 * SEC + 20 * SEC, "nbose", "success", "user_approved", DUO_IP, country="Netherlands")
    consent = dx.ual(r, t + 25 * MIN, "Consent to application.", "nbose", DUO_IP, "AzureActiveDirectory",
                     status="Success", ObjectId="Mail Sync Pro",
                     ModifiedProperties=[{"Name": "ConsentContext.IsAdminConsent", "NewValue": "False", "OldValue": ""},
                                         {"Name": "ConsentAction.Permissions",
                                          "NewValue": "[] => [[Scope: Mail.Read Mail.Send offline_access User.Read]]",
                                          "OldValue": ""}])
    return Story("I4", "Duo push bombing on VPN -> access -> OAuth consent to a mail app", ("duo", "m365"), [
        Step("T1621", "Credential Access", deny, "8 Duo pushes denied / unanswered in 7 min"),
        Step("T1078.004", "Initial Access", [ok], "the 9th push approved: VPN session"),
        Step("T1528", "Credential Access", [consent], "user consent: Mail.Read / Mail.Send / offline_access"),
    ])


def s5_auth0(seed: int) -> Story:
    r = sub_rng(seed, "idsaas-s5")
    t = at(6, 20, 0)
    targets = CUSTOMERS[::9][:45]
    stuff = [dx.auth0(r, t + k * 30 * SEC, "fu" if k % 3 == 0 else "fp", c, STUFF_IP, ua=dx.UA_PY,
                      desc="Wrong email or password.") for k, c in enumerate(targets)]
    wins = [dx.auth0(r, t + 23 * MIN + k * MIN, "s", c, STUFF_IP, ua=dx.UA_PY, desc="Successful login")
            for k, c in enumerate(("cust0042@mail.example", "cust0117@mail.example", "cust0300@mail.example"))]
    block = dx.auth0(r, t + 27 * MIN, "limit_mu", targets[-1], STUFF_IP, ua=dx.UA_PY,
                     desc="An IP address is blocked because it attempted too many failed logins")
    return Story("I5", "Auth0 credential stuffing on the customer portal -> account takeovers", ("auth0",), [
        Step("T1110.004", "Credential Access", stuff, "45 customer accounts tried from one IP", user=None),
        Step("T1078.004", "Initial Access", wins, "3 customer accounts taken over"),
    ], extra=[block])


def stories(seed: int) -> list[Story]:
    return [s1_okta(seed), s2_gws(seed), s3_bec(seed), s4_duo(seed), s5_auth0(seed)]


def decoys(seed: int) -> list[tuple[str, str, list[Ev]]]:
    r = sub_rng(seed, "idsaas-decoys")
    i_r, i_t, i_m = STAFF.index("rnair"), STAFF.index("tgupta"), STAFF.index("mjoshi")
    s = "102" + r.b32(22)
    return [
        ("ID1", "helpdesk admin role granted by the IT admin from the office",
         [dx.okta(r, at(2, 5), "user.account.privilege.grant", "asharma", "192.0.2.10", asn=CORP_ASN,
                  target=dx.okta_user_target("skapoor"), debug={"privilegeGranted": "Help Desk administrator"})]),
        ("ID2", "laptop roams office -> home inside one Okta session (same browser)",
         [dx.okta(r, at(1, 11), "user.authentication.sso", "rnair", "192.0.2.11", sess=s, asn=CORP_ASN,
                  target=dx.okta_app_target("Jira")),
          dx.okta(r, at(1, 11, 40), "user.authentication.sso", "rnair", home(i_r), sess=s, asn=home_asn(i_r),
                  target=dx.okta_app_target("Jira"))]),
        ("ID3", "two unanswered Duo pushes, then approved",
         [dx.duo(r, at(2, 4, k), "tgupta", "denied", "no_response", home(i_t)) for k in range(2)]
         + [dx.duo(r, at(2, 4, 3), "tgupta", "success", "user_approved", home(i_t))]),
        ("ID4", "marketing shares one brochure with an anonymous link",
         [dx.ual(r, at(3, 7), "AnonymousLinkCreated", "mjoshi", home(i_m), "SharePoint", status=None,
                 ObjectId="https://corp.sharepoint.com/sites/marketing/Shared Documents/brochure.pdf")]),
        ("ID5", "HR forwards a shared mailbox to an internal team",
         [dx.ual(r, at(1, 6), "New-InboxRule", "skapoor", "192.0.2.10:40112", "Exchange", shape="ual_la",
                 params={"Name": "to team", "ForwardTo": "hr-team@corp.example"})]),
        ("ID6", "a customer office NAT: six customers mistype passwords over three hours",
         [dx.auth0(r, at(2, 9) + k * 30 * MIN, "fp", CUSTOMERS[200 + k], "198.51.100.77") for k in range(6)]),
        ("ID7", "engineer authorizes a backup tool with the narrow drive.file scope",
         [dx.gws(r, at(2, 8), "token", "authorize", "lfernandes", "192.0.2.10",
                 {"client_id": "5521.apps.googleusercontent.com", "app_name": "Drive Backup",
                  "scope": ["https://www.googleapis.com/auth/drive.file"]})]),
    ]


def _write_parts(out: Path, evs: list[Ev]) -> tuple[list[dict[str, Any]], int]:
    by: dict[tuple[str, str], list[Ev]] = {}
    for e in evs:
        by.setdefault(dx.FEED_DEST[e.feed], []).append(e)
    parts, total = [], 0
    for (a, b), items in sorted(by.items()):
        d = out / a / b
        d.mkdir(parents=True, exist_ok=True)
        buf: list[str] = []
        size, seq = 0, 0
        for k, e in enumerate(items):
            ln = json.dumps(e.doc, ensure_ascii=False) + "\n"
            buf.append(ln)
            size += len(ln.encode("utf-8"))
            if size >= MAX_PART_BYTES or k == len(items) - 1:
                seq += 1
                p = d / f"part-{seq:04d}.jsonl"
                data = "".join(buf)
                p.write_text(data, encoding="utf-8", newline="")
                parts.append({"file": p.relative_to(out).as_posix(), "source_type": dx.SOURCE_TYPE[e.feed],
                              "events": len(buf), "bytes": len(data.encode("utf-8"))})
                total += parts[-1]["bytes"]
                buf, size = [], 0
    return parts, total


def write(out: Path, seed: int, force: bool) -> dict[str, Any]:
    if out.exists():
        if not force and any(out.iterdir()):
            raise SystemExit(f"refusing to write into non-empty {out} (use --force)")
        shutil.rmtree(out)
    out.mkdir(parents=True)
    t0 = time.time()
    sts, dcs = stories(seed), decoys(seed)
    evs = [e for s in sts for e in s.events()] + [e for _, _, d in dcs for e in d]
    for day in range(DAYS):
        evs += benign_day(seed, day)
    evs.sort(key=lambda e: (e.ts, e.feed, e.rid))
    parts, total = _write_parts(out, evs)
    gt = {"attack_version": "v20", "anchor_ms": START_MS, "anchor": iso_s(START_MS),
          "generated_by": "tools/cloud_attacks/gen_identity_saas.py", "seed": seed,
          "note": "Identity SaaS stories; all IPs RFC 5737, all domains .example.",
          "attacks": [s.gt() for s in sts],
          "decoys": [{"id": i, "why": why, "ts_ms": min(e.ts for e in d), "events": len(d),
                      "source": f"{dx.SOURCE_TYPE[d[0].feed]}:{dx.entity(d[0])['action']}",
                      "user": dx.entity(d[0])["user"], "host": dx.entity(d[0])["host"]} for i, why, d in dcs]}
    (out / "ground_truth").mkdir(exist_ok=True)
    (out / "ground_truth" / "attacks.json").write_text(json.dumps(gt, indent=1), encoding="utf-8")
    h = hashlib.sha256()
    for p in sorted(_HERE.parent.glob("*.py")):
        h.update(p.read_bytes())
    manifest = {"generator": "tools/cloud_attacks/gen_identity_saas.py", "generator_sha256": h.hexdigest(), "seed": seed,
                "days": DAYS, "start": iso_s(START_MS), "end": iso_s(START_MS + DAYS * DAY), "total_events": len(evs),
                "total_bytes": total, "parts": parts,
                "attacks": [{"id": s.id, "name": s.name, "steps": len(s.steps)} for s in sts],
                "decoys": [i for i, _, _ in dcs], "wall_s": round(time.time() - t0, 2)}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="generate the identity SaaS attack dataset with ground truth")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    m = write(a.out, a.seed, a.force)
    sys.stdout.write(f"wrote {m['total_events']} events, {m['total_bytes'] / 1e6:.1f} MB -> {a.out} in {m['wall_s']}s\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
