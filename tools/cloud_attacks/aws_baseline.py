"""Benign AWS baseline for gen_aws.py: a 10-instance VPC, Identity Center users, instance roles, IaC and S3 apps.

Noise that resembles the attacks on purpose (the near misses the rules must not fire on, or only at low severity):
internet scanners probing the web tier, a nightly 600 MB backup to the S3 endpoint, a 5-minute payment API poll with
jitter, CDN names with hashed labels, typo NXDOMAINs, password / TOTP typos, a data engineer listing 4 buckets, IaC
lifecycle rules (365 days; one 3-day noncurrent rule by the deploy role), a 30-day log lifecycle by a human, weekly
version clean-up of 5 old backups, and an internal-only security group change.
"""

from __future__ import annotations

from typing import Any

from cloud_attacks import aws_feeds as af
from cloud_attacks.common import (ACCT_PROD, CI_IPS, CORP_IPS, DAY, HOUR, MIN, START_MS, Ev, Rand, home_ip,
                                  staff_index, sub_rng)
from cloud_attacks.formats import UA_BOTO, UA_CLI, assumed, ct, iam_user, s3_data, stable

DAYS = 7
REGION = af.REGION
SSO_ROLES = {"admin": "AWSReservedSSO_AdministratorAccess_1a2b3c4d", "data": "AWSReservedSSO_DataEngineer_3c4d5e6f",
             "dev": "AWSReservedSSO_Developer_5e6f7a8b"}
SSO_USERS = {"asharma": "admin", "rnair": "admin", "akumar": "admin", "lfernandes": "data", "dsingh": "data",
             "pmehta": "dev", "vreddy": "dev", "tgupta": "dev"}
INST_ROLE = {"bastion": "bastion-role", "web": "web-app-role", "app": "app-svc-role", "build": "build-runner-role",
             "db": "db-backup-role"}
BUCKETS = ("media-assets", "analytics-raw", "analytics-curated", "finance-reports", "app-config", "build-cache",
           "db-backups", "web-logs", "ml-features", "partner-exchange", "audit-archive", "static-site")
SVC = {"partner": "198.51.100.180", "payments": "198.51.100.181", "cdn": "198.51.100.185", "mirror": "198.51.100.150",
       "git": "198.51.100.151", "registry": "198.51.100.152", "ntp": "198.51.100.190", "aws": "198.51.100.161"}
CUSTOMERS = tuple(f"198.51.100.{i}" for i in range(1, 36))
SCANNERS = tuple(f"198.51.100.{i}" for i in range(210, 231))
ROTATE_H = 4                         # instance-role credentials rotate at 04:00 / 10:00 / 16:00 / 22:00 UTC


def kind(inst: str) -> str:
    return inst.split("-")[0]


def role_ident(r: Rand, inst: str, ts: int) -> dict[str, Any]:
    """Instance-profile session: session name = instance id, access key fixed per 6 h credential window."""
    d = assumed(r, ACCT_PROD, INST_ROLE[kind(inst)], af.iid(inst))
    d["accessKeyId"] = stable("ASIA", f"{inst}|{(ts - ROTATE_H * HOUR) // (6 * HOUR)}", 16)
    return d


def sso_session(r: Rand, user: str) -> dict[str, Any]:
    return assumed(r, ACCT_PROD, SSO_ROLES[SSO_USERS[user]], f"{user}@corp.example", mfa=True)


def user_ip(user: str, r: Rand) -> str:
    return r.choice(CORP_IPS) if r.random() < 0.4 else home_ip(staff_index(user))


# ---------------------------------------------------------------------------------------------------- network
def _egress(r: Rand, ts: int, inst: str, dst: str, dport: int, nbytes: int, *, via_fw: bool = True,
            sni: str | None = None, proto: str = "tcp") -> list[Ev]:
    ip = af.INSTANCES[inst][0]
    sport = r.randint(32768, 60999)
    out = [af.flow(r, ts, inst, ip, dst, sport, dport, nbytes=nbytes, pkts=max(1, nbytes // 1200), proto=proto)]
    if via_fw and r.random() < 0.35:
        out.append(af.nfw(r, ts + 500, "netflow", ip, sport, dst, dport, nbytes=nbytes, pkts=max(1, nbytes // 1200),
                          app="tls" if dport == 443 else None, proto=proto.upper()))
        if sni:
            out.append(af.nfw(r, ts + 200, "tls", ip, sport, dst, dport, sni=sni))
    return out


def network_day(seed: int, d: int, scale: float) -> list[Ev]:
    r = sub_rng(seed, "aws-net", d)
    t0 = START_MS + d * DAY
    out: list[Ev] = []
    for inst, (ip, _, _) in af.INSTANCES.items():
        k = kind(inst)
        for slot in range(96):                                          # every 15 min
            ts = t0 + slot * 15 * MIN + r.randint(0, 600) * 1000
            out.append(af.dns(r, ts, inst, f"ssm.{REGION}.amazonaws.com", answer=SVC["aws"]))
            out += _egress(r, ts + 300, inst, af.S3_ENDPOINT_IP, 443, r.randint(20_000, 200_000), via_fw=False)
            if r.random() < 0.3:                                         # NTP at irregular times
                out.append(af.dns(r, ts + 900, inst, "time.ntp.example", answer=SVC["ntp"]))
                out.append(af.flow(r, ts + 900, inst, ip, SVC["ntp"], 123, 123, proto="udp", pkts=1, nbytes=76))
            if k == "web":
                for _ in range(int(3 * scale)):                          # customers -> 443 and the responses
                    c, cp, tt = r.choice(CUSTOMERS), r.randint(1024, 65000), ts + r.randint(0, 800) * 1000
                    out.append(af.flow(r, tt, inst, c, ip, cp, 443, nbytes=r.randint(800, 4000), direction="ingress"))
                    out.append(af.flow(r, tt, inst, ip, c, 443, cp, nbytes=r.randint(20_000, 900_000)))
                out.append(af.flow(r, ts + 60_000, inst, ip, "10.0.2.2" + str(r.randint(1, 3)), r.randint(32768, 60999),
                                   8080, nbytes=r.randint(2000, 40_000)))
                if r.random() < 0.5:
                    h = f"img-{r.hexs(12)}.cdn.example"                  # hashed CDN names (tunnel near miss)
                    out.append(af.dns(r, ts + 120_000, inst, h, answer=SVC["cdn"]))
                    out += _egress(r, ts + 121_000, inst, SVC["cdn"], 443, r.randint(50_000, 900_000), sni=h)
                if slot % 3 == 0:
                    out.append(af.dns(r, ts + 200_000, inst, "api.partner.example", answer=SVC["partner"]))
                    out += _egress(r, ts + 201_000, inst, SVC["partner"], 443, r.randint(3000, 30_000),
                                   sni="api.partner.example")
            elif k == "app":
                for _ in range(2):
                    out.append(af.flow(r, ts + r.randint(0, 800) * 1000, inst, ip, r.choice(("10.0.3.31", "10.0.3.32")),
                                       r.randint(32768, 60999), 5432, nbytes=r.randint(2000, 80_000)))
                for j in range(3):                                       # 5-minute payment poll, +-50 % jitter
                    tt = ts + j * 5 * MIN + r.randint(-150, 150) * 1000
                    out += _egress(r, tt, inst, SVC["payments"], 443, r.randint(2000, 9000), sni="api.payments.example")
                if slot % 8 == 0:
                    out.append(af.dns(r, ts + 30_000, inst, "api.payments.example", answer=SVC["payments"]))
            elif k == "build" and 8 <= slot // 4 <= 20 and r.random() < 0.3:  # CI jobs, 08-20 UTC
                for name, key in (("mirror.pkgs.example", "mirror"), ("git.code.example", "git"),
                                  ("registry.containers.example", "registry")):
                    out.append(af.dns(r, ts, inst, name, answer=SVC[key]))
                    out += _egress(r, ts + 2000, inst, SVC[key], 443, r.randint(5_000, 60_000), sni=name)
                    out.append(af.flow(r, ts + 2000, inst, SVC[key], ip, 443, r.randint(32768, 60999),
                                       nbytes=r.randint(2_000_000, 40_000_000), direction="ingress"))
            elif k == "bastion" and 4 <= slot // 4 <= 13 and r.random() < 0.3 and d < 5:
                c = r.choice(CORP_IPS)                                   # admins from the corp egress
                out.append(af.flow(r, ts, inst, c, ip, r.randint(1024, 65000), 22, nbytes=r.randint(5000, 90_000),
                                   direction="ingress"))
                out.append(af.flow(r, ts + 5000, inst, ip, r.choice(("10.0.2.21", "10.0.3.31")), r.randint(32768, 60999),
                                   22, nbytes=r.randint(3000, 50_000)))
            elif k == "db" and slot == 8 and inst == "db-1":             # nightly backup 02:00, 3 x 200 MB
                for m in range(3):                                       # (one record per 10-min aggregation)
                    out.append(af.flow(r, ts + m * 10 * MIN, inst, ip, af.S3_ENDPOINT_IP, 50122, 443,
                                       nbytes=200_000_000 + r.randint(0, 9_000_000), pkts=140000))
            if r.random() < 0.004:                                       # typo NXDOMAIN
                out.append(af.dns(r, ts + 50_000, inst, f"mirorr{r.randint(1, 9)}.pkgs.example", rcode="NXDOMAIN"))
        if inst == "db-2":
            out += [af.nodata(t0 + h * HOUR + 7 * MIN, inst) for h in range(0, 24, 6)]
    # internet background scanners against the web tier (blocked by the security group)
    for _ in range(int(150 * scale)):
        s, w = r.choice(SCANNERS), r.choice(("web-1", "web-2", "web-3"))
        ts, port = t0 + r.randint(0, DAY // 1000 - 1) * 1000, r.choice((22, 23, 445, 3389, 3306, 6379, 8080, 8443, 5900))
        out.append(af.flow(r, ts, w, s, af.INSTANCES[w][0], r.randint(1024, 65000), port, pkts=1, nbytes=44,
                           action="REJECT", direction="ingress"))
        if port == 3306 and r.random() < 0.5:
            out.append(af.nfw(r, ts, "alert", s, r.randint(1024, 65000), af.INSTANCES[w][0], 3306, app=None,
                              alert={"action": "blocked", "signature_id": 2010937, "category": "Potentially Bad Traffic",
                                     "signature": "ET SCAN Suspicious inbound to mySQL port 3306", "severity": 2}))
    sweep, ts = r.choice(SCANNERS), t0 + r.randint(1, 22) * HOUR      # one quick vertical sweep per day
    for p in r.sample(range(1, 1024), 25):
        out.append(af.flow(r, ts, "web-1", sweep, "10.0.1.11", 40000 + p, p, pkts=1, nbytes=44, action="REJECT",
                           direction="ingress"))
    for _ in range(6):                                                  # benign policy alerts (curl UA etc.)
        inst = r.choice(("build", "app-1", "bastion"))
        ts = t0 + r.randint(0, 23) * HOUR + r.randint(0, 3599) * 1000
        out.append(af.nfw(r, ts, "alert", af.INSTANCES[inst][0], r.randint(32768, 60999), SVC["mirror"], 443,
                          alert={"signature_id": 2013028, "category": "Attempted Information Leak", "severity": 2,
                                 "signature": "ET POLICY curl User-Agent Outbound"}))
    return out


# ---------------------------------------------------------------------------------------------------- CloudTrail
def cloudtrail_day(seed: int, d: int, scale: float) -> list[Ev]:
    r = sub_rng(seed, "aws-ct", d)
    t0 = START_MS + d * DAY
    weekend = d % 7 in (5, 6)
    out: list[Ev] = []
    for inst in af.INSTANCES:                                           # instance roles every 10 min from the NAT EIP
        for slot in range(144):
            ts = t0 + slot * 10 * MIN + 5 * MIN + r.randint(0, 30) * 1000
            ident = role_ident(r, inst, ts)
            out.append(ct(r, ts, ACCT_PROD, REGION, "ssm.amazonaws.com", "UpdateInstanceInformation", ident, af.NAT_EIP,
                          ua=UA_BOTO, req={"instanceId": af.iid(inst), "agentVersion": "3.3.40.0"}))
            if kind(inst) in ("web", "app") and slot % 2 == 0:
                b = "static-site" if kind(inst) == "web" else "app-config"
                out.append(s3_data(r, ts + 2000, ACCT_PROD, ident, af.NAT_EIP, "GetObject", b,
                                   f"conf/{r.randint(1, 40)}.json", ua=UA_BOTO, region=REGION))
    for user, grp in SSO_USERS.items():                                 # Identity Center sign-ins + work
        if weekend and r.random() < 0.85:
            continue
        for _ in range(r.randint(1, 2)):
            ts = t0 + int(3.5 * HOUR) + r.randint(0, 9 * 3600) * 1000
            ip = user_ip(user, r)
            out += af.sso_login(r, ts, user, ip, pw_fail=int(r.random() < 0.1), mfa_fail=int(r.random() < 0.06))
            sess = sso_session(r, user)
            t = ts + 30_000
            for _ in range(int(r.randint(8, 20) * scale)):
                t += r.randint(5, 90) * 1000
                api = r.choice(("DescribeInstances", "DescribeSecurityGroups", "ListBuckets", "DescribeVpcs",
                                "GetCallerIdentity", "DescribeAlarms"))
                src = {"ListBuckets": "s3.amazonaws.com", "GetCallerIdentity": "sts.amazonaws.com",
                       "DescribeAlarms": "monitoring.amazonaws.com"}.get(api, "ec2.amazonaws.com")
                out.append(ct(r, t, ACCT_PROD, REGION, src, api, sess, ip, ua=UA_CLI, ro=True))
            if grp == "data":                                           # 4 buckets listed, curated reads
                for b in BUCKETS[1:3] + ("ml-features", "web-logs"):
                    out.append(s3_data(r, t + 5000, ACCT_PROD, sess, ip, "ListObjectsV2", b, None, region=REGION))
                for _ in range(30):
                    t += r.randint(2, 20) * 1000
                    out.append(s3_data(r, t, ACCT_PROD, sess, ip, "GetObject", "analytics-curated",
                                       f"daily/{d}/part-{r.randint(0, 999):04d}.parquet", region=REGION))
    media = iam_user(r, ACCT_PROD, "svc-media-upload")                  # media app (long-term key)
    for _ in range(int(50 * scale)):
        ts = t0 + r.randint(0, DAY // 1000 - 1) * 1000
        out.append(s3_data(r, ts, ACCT_PROD, media, af.NAT_EIP, "PutObject", "media-assets",
                           f"uploads/{r.hexs(10)}.jpg", ua=UA_BOTO, region=REGION))
    for h in range(0, 24, 2):
        out.append(s3_data(r, t0 + h * HOUR + 17 * MIN, ACCT_PROD, media, af.NAT_EIP, "ListObjectsV2", "media-assets",
                           None, ua=UA_BOTO, region=REGION))
    fin = assumed(r, ACCT_PROD, "finance-app-role", "finance-batch")    # finance-reports store history
    for _ in range(40):
        out.append(s3_data(r, t0 + r.randint(0, DAY // 1000 - 1) * 1000, ACCT_PROD, fin, af.NAT_EIP, "GetObject",
                           "finance-reports", f"2026/q3/{r.randint(1, 300)}.pdf", ua=UA_BOTO, region=REGION))
    bk = role_ident(r, "db-1", t0 + 2 * HOUR)                           # nightly backups + weekly version clean-up
    out.append(s3_data(r, t0 + 2 * HOUR + 21 * MIN, ACCT_PROD, bk, af.NAT_EIP, "PutObject", "db-backups",
                       f"pg/{d}.dump", ua=UA_BOTO, region=REGION))
    if d % 7 == 2:
        for i in range(5):
            out.append(ct(r, t0 + 3 * HOUR + i * 4000, ACCT_PROD, REGION, "s3.amazonaws.com", "DeleteObject", bk,
                          af.NAT_EIP, ua=UA_BOTO, data=True, req={"bucketName": "db-backups", "key": f"pg/old-{i}.dump",
                                                                  "versionId": r.hexs(32)}))
    tf = assumed(r, ACCT_PROD, "terraform-deploy", "gha-infra-deploy")  # IaC apply from CI
    ci = r.choice(CI_IPS)
    tt = t0 + 6 * HOUR + r.randint(0, 3600) * 1000
    out.append(ct(r, tt, ACCT_PROD, REGION, "s3.amazonaws.com", "PutBucketLifecycleConfiguration", tf, ci, ua=UA_BOTO,
                  req={"bucketName": "web-logs", "LifecycleConfiguration": {"Rule": [{"ID": "expire-logs",
                       "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 365}}]}}))
    out.append(ct(r, tt + 20_000, ACCT_PROD, REGION, "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", tf, ci,
                  ua=UA_BOTO, req={"groupId": "sg-0app", "ipPermissions": {"items": [{"ipProtocol": "tcp",
                  "fromPort": 8080, "toPort": 8080, "ipRanges": {"items": [{"cidrIp": "10.0.0.0/16"}]}}]}}))
    if d == 2:
        out.append(ct(r, tt + 40_000, ACCT_PROD, REGION, "s3.amazonaws.com", "PutBucketLifecycleConfiguration", tf, ci,
                      ua=UA_BOTO, req={"bucketName": "build-cache", "LifecycleConfiguration": {"Rule": [{
                          "ID": "cache", "Status": "Enabled", "Filter": {"Prefix": ""},
                          "NoncurrentVersionExpiration": {"NoncurrentDays": 3}}]}}))
        ds = sso_session(r, "dsingh")
        out.append(ct(r, t0 + 9 * HOUR, ACCT_PROD, REGION, "s3.amazonaws.com", "PutBucketLifecycleConfiguration", ds,
                      CORP_IPS[0], req={"bucketName": "audit-archive", "LifecycleConfiguration": {"Rule": {
                          "ID": "expire", "Status": "Enabled", "Expiration": {"Days": "30"}}}}))
    return out


def baseline(seed: int, scale: float = 1.0) -> list[Ev]:
    out: list[Ev] = []
    for d in range(DAYS):
        out += network_day(seed, d, scale) + cloudtrail_day(seed, d, scale)
    return out
