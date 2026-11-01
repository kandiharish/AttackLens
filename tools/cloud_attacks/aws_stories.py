"""AWS track attack stories and decoys (ground truth from each step's FIRST event, like story.py).

A1 SSRF on web-2 -> instance-role credentials used off-host -> internal scan -> 300 MB egress   (NFW, CT, flow)
A2 build runner: DNS tunnel C2 -> DGA lookups -> Monero mining pool                            (R53, flow, NFW)
A3 Identity Center spray -> MFA request flood -> sign-in -> new WebAuthn device -> S3 enum + bulk read (CT)
A4 leaked access key: bucket enumeration -> SSE-C re-encryption -> 1-day lifecycle -> version purge (CT, Codefinger)
A5 hijacked admin session opens SSH to the world -> attacker SSH in -> Cobalt Strike beacon      (CT, flow, NFW)
Findings (GuardDuty / Security Hub) for A1, A2, A4 are served as context rows; they are never scored steps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_attacks import aws_baseline as bl, aws_feeds as af
from cloud_attacks.common import ACCT_PROD, DAY, HOUR, MIN, START_MS, Ev, home_ip, iso_s, staff_index, sub_rng
from cloud_attacks.formats import UA_BOTO, UA_CLI, assumed, ct, entity as ct_entity, iam_user, s3_data

ATK = {"a1": "203.0.113.50", "a1_drop": "203.0.113.80", "a2_pool": "203.0.113.90", "a3": "203.0.113.30",
       "a4": "203.0.113.60", "a5": "203.0.113.70", "a5_c2": "203.0.113.71"}
SRC = {"cloudtrail": "aws_cloudtrail", "vpcflow": "aws_vpcflow", "r53": "aws_route53resolver", "nfw": "aws_networkfirewall"}


def at(day: int, hour: int, minute: int = 0) -> int:
    return START_MS + day * DAY + hour * HOUR + minute * MIN


def ent(ev: Ev) -> dict[str, Any]:
    return ct_entity(ev) if ev.feed == "cloudtrail" else af.entity(ev)


def first(evs: list[Ev]) -> Ev:
    return min(evs, key=lambda e: (e.ts, e.rid))


@dataclass
class Step:
    technique_id: str
    tactic: str
    events: list[Ev]
    what: str
    anchor: Ev | None = None          # the event the step is anchored on (default: the first one)
    user: Any = "keep"

    def gt(self, n: int) -> dict[str, Any]:
        a = self.anchor or first(self.events)
        e = ent(a)
        return {"step": n, "ts_ms": a.ts, "ts": iso_s(a.ts), "technique_id": self.technique_id, "tactic": self.tactic,
                "host": e["host"], "user": e["user"] if self.user == "keep" else self.user, "src_ip": e["src_ip"],
                "dst_ip": None, "source": f"{SRC[a.feed]}:{e['action']}", "event_id": a.rid,
                "events": len(self.events), "what": self.what}


@dataclass
class Story:
    id: str
    name: str
    steps: list[Step]
    extra: list[Ev] = field(default_factory=list)

    def events(self) -> list[Ev]:
        return [e for s in self.steps for e in s.events] + self.extra

    def gt(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "clouds": ["aws"], "novel": False,
                "refs": ["https://github.com/DataDog/stratus-red-team", "https://www.halcyon.ai/blog (Codefinger)"],
                "steps": [s.gt(i + 1) for i, s in enumerate(self.steps)]}


@dataclass
class Decoy:
    id: str
    why: str
    events: list[Ev]
    recurring: bool = False

    def gt(self) -> dict[str, Any]:
        a = first(self.events)
        e = ent(a)
        return {"id": self.id, "ts_ms": a.ts, "ts": iso_s(a.ts), "source": f"{SRC[a.feed]}:{e['action']}",
                "host": e["host"], "user": e["user"], "src_ip": e["src_ip"], "event_id": a.rid,
                "events": len(self.events), "recurring": self.recurring, "why": self.why}


# ------------------------------------------------------------------------------------------------------- stories
def a1(seed: int) -> Story:
    r = sub_rng(seed, "aws-a1")
    web2, ip = "web-2", af.INSTANCES["web-2"][0]
    t = at(4, 10)
    exploit = [af.nfw(r, t, "alert", ATK["a1"], 51123, ip, 443, sni="www.shop.example", alert={
        "signature_id": 2034567, "category": "Web Application Attack", "severity": 1,
        "signature": "ET WEB_SERVER Possible SSRF Attempt to AWS Instance Metadata Service (169.254.169.254)"}),
        af.flow(r, t, web2, ATK["a1"], ip, 51123, 443, nbytes=3400, direction="ingress")]
    ident = bl.role_ident(r, web2, t + 8 * MIN)
    creds = [ct(r, t + 8 * MIN + i * 20_000, ACCT_PROD, af.REGION, src, api, ident, ATK["a1"], ua=UA_CLI, ro=True,
                req=req) for i, (src, api, req) in enumerate([
                    ("sts.amazonaws.com", "GetCallerIdentity", None), ("s3.amazonaws.com", "ListBuckets", None),
                    ("ec2.amazonaws.com", "DescribeInstances", None), ("iam.amazonaws.com", "ListRoles", None),
                    ("secretsmanager.amazonaws.com", "ListSecrets", None)])]
    scan = []
    for k, (net, port) in enumerate((("10.0.2", 22), ("10.0.3", 5432))):
        ts = t + (20 + k) * MIN
        for h in range(1, 61):
            dst = f"{net}.{h}"
            scan.append(af.flow(r, ts, web2, ip, dst, 41000 + h, port, pkts=1, nbytes=60))
            owner = next((n for n, v in af.INSTANCES.items() if v[0] == dst), None)
            if owner:
                scan.append(af.flow(r, ts, owner, ip, dst, 41000 + h, port, pkts=1, nbytes=60, action="REJECT",
                                    direction="ingress"))
    exfil = [af.dns(r, t + 39 * MIN, web2, "upload.files-sync.example", answer=ATK["a1_drop"])]
    exfil += [af.flow(r, t + (40 + m * 10) * MIN, web2, ip, ATK["a1_drop"], 49812, 443, nbytes=150_000_000 + m * 1000,
                      pkts=110000) for m in range(2)]
    gd_scan = af.guardduty(r, t + 20 * MIN, "Recon:EC2/Portscan", 5.0, inst=web2, remote="10.0.2.21", outbound=True)
    extra = [af.guardduty(r, t + 8 * MIN, "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", 8.0,
                          user="web-app-role", remote=ATK["a1"]), gd_scan,
             af.guardduty(r, t + 20 * MIN, "Recon:EC2/Portscan", 5.0, inst=web2, remote="10.0.2.21", outbound=True,
                          fid=gd_scan.doc["id"], count=120, updated_ms=t + 35 * MIN),
             af.asff(t + 8 * MIN, "Credentials for an EC2 instance role were used from outside AWS",
                     ["TTPs/Initial Access/UnauthorizedAccess:IAMUser-InstanceCredentialExfiltration.OutsideAWS"],
                     "HIGH", remote=ATK["a1"])]
    return Story("A1", "SSRF on web-2 -> instance-role creds used off-host -> internal scan -> 300 MB egress", [
        Step("T1190", "Initial Access", exploit, "SSRF exploit alert (Network Firewall) against web-2", anchor=exploit[0]),
        Step("T1552.005", "Credential Access", creds, "web-2 role session key used from the attacker IP"),
        Step("T1046", "Discovery", scan, "web-2 sweeps 10.0.2.0/24:22 and 10.0.3.0/24:5432", anchor=scan[0]),
        Step("T1048", "Exfiltration", exfil[1:], "300 MB to a new external IP in 20 min")], extra=exfil[:1] + extra)


def a2(seed: int) -> Story:
    r = sub_rng(seed, "aws-a2")
    t = at(4, 15)
    tun = [af.dns(r, t + i * 10_000, "build", f"{r.b32(40).lower()}.t.cdn-sync.example", qtype="TXT", fw="ALERT")
           for i in range(120)]
    dga = [af.dns(r, t + 25 * MIN + i * 7000, "build", f"{r.hexs(14)}.{r.choice(('com', 'net', 'org', 'info'))}",
                  rcode="NXDOMAIN") for i in range(30)]
    ip = af.INSTANCES["build"][0]
    pool = [af.dns(r, t + 40 * MIN, "build", "pool.supportxmr.example", answer=ATK["a2_pool"])]
    pool += [af.flow(r, t + (41 + m) * MIN, "build", ip, ATK["a2_pool"], 50333 + i, 3333,
                     nbytes=r.randint(400_000, 900_000), pkts=3000) for i, m in enumerate((0, 6, 19, 27, 41))]
    pool += [af.nfw(r, t + 41 * MIN, "alert", ip, 50333, ATK["a2_pool"], 3333, app=None, alert={
        "signature_id": 2024792, "category": "Crypto Currency Mining Activity Detected", "severity": 1,
        "signature": "ET COINMINER CryptoNight Proof of Work Stratum Submit"})]
    pool += [af.nfw(r, t + (41 + m) * MIN + 500, "netflow", ip, 50333 + i, ATK["a2_pool"], 3333, app=None,
                    nbytes=600_000, pkts=3000) for i, m in enumerate((0, 19, 41))]
    extra = [af.eventbridge(af.guardduty(r, t + 5 * MIN, "Trojan:EC2/DNSDataExfiltration", 8.0, inst="build")),
             af.guardduty(r, t + 41 * MIN, "CryptoCurrency:EC2/BitcoinTool.B!DNS", 8.0, inst="build",
                          remote=ATK["a2_pool"], outbound=True)]
    return Story("A2", "build runner: DNS tunnel C2 -> DGA lookups -> Monero mining", [
        Step("T1071.004", "Command and Control", tun, "120 TXT lookups with 40-char labels under cdn-sync.example"),
        Step("T1568.002", "Command and Control", dga, "30 NXDOMAIN random domains in 4 min"),
        Step("T1496.001", "Impact", pool, "mining pool lookup, stratum sessions on 3333", anchor=pool[0])],
        extra=extra)


def a3(seed: int) -> Story:
    r = sub_rng(seed, "aws-a3")
    t, ip, victim = at(6, 2), ATK["a3"], "lfernandes"
    spray = []
    for i, u in enumerate(("asharma", "pmehta", "vreddy", "tgupta", "rnair", "dsingh", "akumar", "kiyer", "mjoshi",
                           "nbose", "skapoor", "lfernandes")):
        spray += af.sso_login(r, t + i * 50_000, u, ip, pw_fail=1, ok=False)[:2]
    login = af.sso_login(r, t + 20 * MIN, victim, ip, mfa_fail=5, step_ms=60_000)
    mfa = login[2:-1]
    ok = [login[-1]]
    dev = af.sso_mfa_register(r, t + 35 * MIN, victim, ip)
    sess = assumed(r, ACCT_PROD, bl.SSO_ROLES["data"], f"{victim}@corp.example", mfa=True)
    enum = [ct(r, t + 40 * MIN, ACCT_PROD, af.REGION, "s3.amazonaws.com", "ListBuckets", sess, ip, ua=UA_CLI, ro=True)]
    for i, b in enumerate(bl.BUCKETS):
        enum.append(s3_data(r, t + 40 * MIN + (i + 1) * 15_000, ACCT_PROD, sess, ip, "ListObjectsV2", b, None,
                            region=af.REGION))
    steal = [s3_data(r, t + 50 * MIN + i * 4000, ACCT_PROD, sess, ip, "GetObject", "finance-reports",
                     f"2026/q{1 + i % 3}/report-{i:04d}.pdf", region=af.REGION) for i in range(400)]
    return Story("A3", "Identity Center spray -> MFA flood -> sign-in -> new WebAuthn device -> S3 enum + bulk read", [
        Step("T1110.003", "Credential Access", spray, "password failures for 12 users from one IP in 10 min",
             user=None),
        Step("T1621", "Credential Access", mfa, "6 TOTP challenges, 5 failed, for lfernandes"),
        Step("T1078.004", "Initial Access", ok, "UserAuthentication success from the spraying IP"),
        Step("T1556.006", "Persistence", dev, "WebAuthn device registered from the attacker network"),
        Step("T1619", "Discovery", enum, "ListBuckets + ListObjectsV2 over 12 buckets in 3 min"),
        Step("T1530", "Collection", steal, "400 objects pulled from finance-reports")])


def a4(seed: int) -> Story:
    r = sub_rng(seed, "aws-a4")
    t, ip = at(5, 9), ATK["a4"]
    user = iam_user(r, ACCT_PROD, "svc-media-upload")
    enum = [ct(r, t, ACCT_PROD, af.REGION, "s3.amazonaws.com", "ListBuckets", user, ip, ua=UA_BOTO, ro=True)]
    enum += [s3_data(r, t + (i + 1) * 15_000, ACCT_PROD, user, ip, "ListObjectsV2", b, None, ua=UA_BOTO,
                     region=af.REGION) for i, b in enumerate(bl.BUCKETS[:10])]
    keys = [f"uploads/{r.hexs(10)}.jpg" for _ in range(60)]
    enc = [ct(r, t + 10 * MIN + i * 5000, ACCT_PROD, af.REGION, "s3.amazonaws.com", "CopyObject", user, ip, ua=UA_BOTO,
              data=True, req={"bucketName": "media-assets", "key": k, "x-amz-copy-source": f"media-assets/{k}",
                              "x-amz-server-side-encryption-customer-algorithm": "AES256"})
           for i, k in enumerate(keys)]
    lc = [ct(r, t + 20 * MIN, ACCT_PROD, af.REGION, "s3.amazonaws.com", "PutBucketLifecycleConfiguration", user, ip,
             ua=UA_BOTO, req={"bucketName": "media-assets", "LifecycleConfiguration": {"Rule": [{
                 "ID": "x", "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 1}}]}})]
    purge = [ct(r, t + 25 * MIN + i * 9000, ACCT_PROD, af.REGION, "s3.amazonaws.com", "DeleteObject", user, ip,
                ua=UA_BOTO, data=True, req={"bucketName": "media-assets", "key": k, "versionId": r.hexs(32)})
             for i, k in enumerate(keys[:40])]
    note = [s3_data(r, t + 35 * MIN, ACCT_PROD, user, ip, "PutObject", "media-assets", "README-RECOVER-FILES.txt",
                    ua=UA_BOTO, region=af.REGION)]
    extra = note + [af.guardduty(r, t + 40 * MIN, "AttackSequence:S3/CompromisedData", 9.5, user="svc-media-upload",
                                 remote=ip, indicators=[{"key": "ATTACK_TECHNIQUE",
                                                         "values": ["Data Encrypted for Impact", "T1485"]}]),
                    af.asff(t + 40 * MIN, "Potential data compromise: S3 objects re-encrypted and deleted",
                            ["Effects/Data Destruction"], "CRITICAL", remote=ip)]
    return Story("A4", "leaked access key: bucket enum -> SSE-C re-encryption -> 1-day lifecycle -> version purge", [
        Step("T1619", "Discovery", enum, "ListBuckets + ListObjectsV2 over 10 buckets"),
        Step("T1486", "Impact", enc, "60 objects copied in place with SSE-C (attacker-held key)"),
        Step("T1485.001", "Impact", lc, "lifecycle rule: expire every object after 1 day"),
        Step("T1485", "Impact", purge, "40 original versions deleted by versionId")], extra=extra)


def a5(seed: int) -> Story:
    r = sub_rng(seed, "aws-a5")
    t, ip = at(3, 18), ATK["a5"]
    sess = assumed(r, ACCT_PROD, bl.SSO_ROLES["admin"], "rnair@corp.example", mfa=True)
    open_ = [ct(r, t + 5 * MIN, ACCT_PROD, af.REGION, "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", sess, ip,
                ua=UA_CLI, req={"groupId": "sg-0bastion", "ipPermissions": {"items": [{
                    "ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}})]
    bip = af.INSTANCES["bastion"][0]
    ssh = [af.flow(r, t + 30 * MIN, "bastion", ip, bip, 52222, 22, nbytes=48_000, direction="ingress"),
           af.flow(r, t + 30 * MIN, "bastion", bip, ip, 22, 52222, nbytes=310_000)]
    beacon = [af.nfw(r, t + 46 * MIN, "alert", bip, 50555, ATK["a5_c2"], 8443, sni="cdn.update-check.example", alert={
        "signature_id": 2027082, "category": "A Network Trojan was Detected", "severity": 1,
        "signature": "ET MALWARE Cobalt Strike Beacon Observed"})]
    beacon += [af.flow(r, t + 45 * MIN + m * 60_000 + r.randint(-2, 2) * 1000, "bastion", bip, ATK["a5_c2"],
                       50556 + m, 8443, nbytes=r.randint(900, 1400), pkts=6, dur_s=2) for m in range(60)]
    beacon += [af.nfw(r, t + 45 * MIN + m * 60_000 + 300, "netflow", bip, 50555, ATK["a5_c2"], 8443, nbytes=1200,
                      pkts=6) for m in range(0, 60, 10)]
    return Story("A5", "hijacked admin session opens SSH to the world -> attacker SSH in -> Cobalt Strike beacon", [
        Step("T1686.001", "Defense Impairment", open_, "sg-0bastion: tcp/22 from 0.0.0.0/0, from the attacker IP"),
        Step("T1133", "Initial Access", ssh, "accepted SSH from the attacker 25 min later", anchor=ssh[0]),
        Step("T1071", "Command and Control", beacon, "Cobalt Strike beacon alert + 60 one-minute check-ins",
             anchor=beacon[0])])


def build_stories(seed: int) -> list[Story]:
    return [a1(seed), a2(seed), a3(seed), a4(seed), a5(seed)]


def build_decoys(seed: int) -> list[Decoy]:
    r = sub_rng(seed, "aws-decoys")
    t = at(3, 9)
    typo = af.sso_login(r, t, "pmehta", home_ip(staff_index("pmehta")), pw_fail=2, mfa_fail=1)
    big = [af.flow(r, at(5, 13) + m * 10 * MIN, "db-2", "10.0.3.32", af.S3_ENDPOINT_IP, 50999, 443,
                   nbytes=100_000_000, pkts=70000) for m in range(2)]
    sg = assumed(r, ACCT_PROD, bl.SSO_ROLES["admin"], "asharma@corp.example", mfa=True)
    sg_ev = [ct(r, at(4, 7), ACCT_PROD, af.REGION, "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", sg,
                "192.0.2.10", req={"groupId": "sg-0db", "ipPermissions": {"items": [{"ipProtocol": "tcp",
                "fromPort": 5432, "toPort": 5432, "ipRanges": {"items": [{"cidrIp": "10.0.0.0/16"}]}}]}})]
    return [Decoy("D1", "pmehta mistypes the password twice and the TOTP once, then signs in from home", typo),
            Decoy("D2", "db-2 one-off 200 MB snapshot copy to the S3 endpoint (known AWS service IP)", big),
            Decoy("D3", "asharma opens 5432 to the VPC CIDR only (internal, not the world)", sg_ev)]
