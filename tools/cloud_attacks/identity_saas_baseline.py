"""Benign identity SaaS baseline for gen_identity_saas.py: a working week of a 48-person company (Bengaluru, business
hours 03:30-13:30 UTC) on Okta (IdP), Duo (VPN MFA), Microsoft 365 (mail / SharePoint), Google Workspace (an
engineering subset) and an Auth0 customer portal. Noise that resembles attacks is deliberate: password typos, roaming
laptops, slow pushes, admin grants, internal forwarding, daily OneDrive syncs of hundreds of files.
"""

from __future__ import annotations

from cloud_attacks import identity_saas_docs as dx
from cloud_attacks.common import ALL_STAFF, CORP_IPS, DAY, GCP_HUMANS, HOUR, MIN, SEC, START_MS, Ev, Rand, sub_rng

STAFF = [u for u, _, _ in ALL_STAFF]
GWS_USERS = sorted(set(GCP_HUMANS) | set(STAFF[12:22]))
CORP_ASN, HOME_ASN0 = 64496, 64510
APPS = ("Salesforce", "Slack", "AWS IAM Identity Center", "Jira", "Workday", "Zoom", "Office 365")
CUSTOMERS = [f"cust{i:04d}@mail.example" for i in range(1, 401)]
SITES = ("finance", "engineering", "marketing", "hr", "ops")


def home(i: int) -> str:
    return f"198.51.100.{100 + i}"


def home_asn(i: int) -> int:
    return HOME_ASN0 + i % 12


def ua_of(i: int) -> str:
    return dx.UA_MAC if i % 4 == 0 else dx.UA_CHROME


def _okta_day(r: Rand, t: int, i: int, u: str, ip: str, asn: int) -> list[Ev]:
    out: list[Ev] = []
    sess = "102" + r.b32(22)
    ua = ua_of(i)
    if r.random() < 0.03:   # password typo first
        out.append(dx.okta(r, t - 40 * SEC, "user.session.start", u, ip, result="FAILURE",
                           reason="INVALID_CREDENTIALS", sess=sess, asn=asn, ua=ua))
    out.append(dx.okta(r, t, "system.push.send_factor_verify_push", u, ip, sess=sess, asn=asn, ua=ua, cred="OTP"))
    out.append(dx.okta(r, t + 9 * SEC, "user.authentication.auth_via_mfa", u, ip, sess=sess, asn=asn, ua=ua, cred="OTP"))
    out.append(dx.okta(r, t + 12 * SEC, "user.session.start", u, ip, sess=sess, asn=asn, ua=ua))
    roam = r.random() < 0.04   # laptop moves office -> home with the same browser session (near miss)
    for k in range(r.randint(5, 14)):
        ts = t + r.randint(1, 9 * 60) * MIN // 1
        sip, sasn = (home(i), home_asn(i)) if roam and k % 2 else (ip, asn)
        app = APPS[r.randrange(len(APPS))]
        out.append(dx.okta(r, ts, "user.authentication.sso", u, sip, sess=sess, asn=sasn, ua=ua,
                           target=dx.okta_app_target(app)))
    return out


def _m365_day(r: Rand, t: int, i: int, u: str, ip: str) -> list[Ev]:
    out = [dx.ual(r, t + 20 * SEC, "UserLoggedIn", u, ip, "AzureActiveDirectory", status="Success",
                  ObjectId="00000003-0000-0ff1-ce00-000000000000")]
    site = SITES[i % len(SITES)]
    for k in range(r.randint(8, 30)):
        ts = t + r.randint(5, 540) * MIN
        f = f"https://corp.sharepoint.com/sites/{site}/Shared Documents/doc{r.randint(1, 400)}.docx"
        op = "FileDownloaded" if k % 3 == 0 else "FileAccessed"
        out.append(dx.ual(r, ts, op, u, ip, "SharePoint", status=None, ObjectId=f, SiteUrl=f"https://corp.sharepoint.com/sites/{site}/",
                          SourceFileName=f.rsplit("/", 1)[1], UserAgent=ua_of(i)))
    if u == "dsingh":   # data team: OneDrive sync client pulls ~150 files every morning (recurring near miss)
        for k in range(150):
            f = f"https://corp-my.sharepoint.com/personal/dsingh/Documents/datasets/part{k:03d}.parquet"
            out.append(dx.ual(r, t + 30 * MIN + k * 15 * SEC, "FileSyncDownloadedFull", u, ip, "OneDrive", status=None,
                              ObjectId=f, SourceFileName=f.rsplit("/", 1)[1], UserAgent="Microsoft SkyDriveSync 24.180"))
    if r.random() < 0.02:   # tidy-up rule: newsletters to a folder (not a hiding folder, no lure words)
        out.append(dx.ual(r, t + HOUR, "New-InboxRule", u, f"{ip}:{r.randint(1024, 65000)}", "Exchange", shape="ual_la",
                          params={"Name": "news", "FromAddressContainsWords": "newsletter", "MoveToFolder": "Newsletters"}))
    return out


def _admin_day(r: Rand, day: int, t: int) -> list[Ev]:
    """asharma (IT admin): routine directory work in every console."""
    ip = CORP_IPS[0]
    out = [dx.okta(r, t + 2 * HOUR, "group.user_membership.add", "asharma", ip, asn=CORP_ASN,
                   target=dx.okta_user_target(STAFF[(day * 7) % len(STAFF)])),
           dx.ual(r, t + 3 * HOUR, "Set-Mailbox", "asharma", f"{ip}:{r.randint(1024, 65000)}", "Exchange", shape="ual_la",
                  params={"Identity": STAFF[(day * 5) % len(STAFF)], "ProhibitSendQuota": "49 GB"}),
           dx.gws(r, t + 4 * HOUR, "admin", "CHANGE_GROUP_SETTING", "asharma", ip,
                  {"GROUP_EMAIL": "eng@corp.example", "SETTING_NAME": "WHO_CAN_POST", "NEW_VALUE": "ALL_IN_DOMAIN_CAN_POST"},
                  etype="GROUP_SETTINGS")]
    if day % 2 == 0:
        out.append(dx.okta(r, t + 5 * HOUR, "policy.rule.update", "asharma", ip, asn=CORP_ASN))
    return out


def _auth0_day(r: Rand, d0: int, weekend: bool) -> list[Ev]:
    out: list[Ev] = []
    for _ in range(400 if weekend else 700):
        ts = d0 + r.randint(0, DAY - 1)
        c = CUSTOMERS[r.randrange(len(CUSTOMERS))]
        ip = f"198.51.100.{r.randint(2, 99)}"
        if r.random() < 0.06:
            out.append(dx.auth0(r, ts - 25 * SEC, "fp", c, ip, desc="Wrong email or password."))
        out.append(dx.auth0(r, ts, "s", c, ip, desc="Successful login"))
    return out


def benign_day(seed: int, day: int) -> list[Ev]:
    r = sub_rng(seed, "idsaas-day", day)
    d0 = START_MS + day * DAY
    weekend = day % 7 in (5, 6)
    out: list[Ev] = []
    for i, u in enumerate(STAFF):
        ru = sub_rng(seed, "idsaas-user", day, u)
        if weekend and ru.random() > 0.2:
            continue
        office = not weekend and ru.random() < 0.7
        ip, asn = (CORP_IPS[i % 2], CORP_ASN) if office else (home(i), home_asn(i))
        t = d0 + 3 * HOUR + 30 * MIN + ru.randint(0, 90) * MIN
        out += _okta_day(ru, t, i, u, ip, asn)
        out += _m365_day(ru, t, i, u, ip)
        if ru.random() < (0.2 if office else 0.8):   # VPN from home / travel
            if ru.random() < 0.05:   # slow phone: one or two unanswered pushes, then approve (near miss)
                for k in range(ru.randint(1, 2)):
                    out.append(dx.duo(ru, t - (3 - k) * MIN, u, "denied", "no_response", ip))
            out.append(dx.duo(ru, t - MIN, u, "success", "user_approved", ip))
        if u in GWS_USERS:
            if ru.random() < 0.03:   # password typo
                out.append(dx.gws(ru, t - 30 * SEC, "login", "login_failure", u, ip,
                                  {"login_type": "google_password",
                                   "login_failure_type": "login_failure_invalid_password", "is_suspicious": False}))
            out.append(dx.gws(ru, t + 25 * SEC, "login", "login_success", u, ip,
                              {"login_type": "google_password", "is_suspicious": False}))
            if ru.random() < 0.05:
                out.append(dx.gws(ru, t + 2 * HOUR, "token", "authorize", u, ip,
                                  {"client_id": "4114.apps.googleusercontent.com", "app_name": "Zoom for Google",
                                   "scope": ["https://www.googleapis.com/auth/calendar.events", "openid"]}))
    if not weekend:
        out += _admin_day(r, day, d0 + 3 * HOUR + 30 * MIN)
    out += _auth0_day(r, d0, weekend)
    return out
