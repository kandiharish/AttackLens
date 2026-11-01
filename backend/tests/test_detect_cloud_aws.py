"""Track AWS native rules (config/rules_cloud.yaml aws_vpcflow_* / aws_r53_* / aws_nfw_* / aws_s3_* / aws_sso_*).

One synthetic set (VPC flow, Route 53 Resolver, Network Firewall, CloudTrail S3 data events and Identity Center
sign-ins, built with tools/cloud_attacks/aws_feeds.py) goes through the real Stage 0 + 1 ingest, then run_cloud with
only these rules (plus cl_firewall_open_world / cl_storage_ransom_encrypt, which two sequences read). Every rule has a
positive and a near miss; IPs are RFC 5737 / RFC 1918.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from .conftest import run_ingest
from .test_detect_cloud import run, subset

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
from cloud_attacks import aws_feeds as af  # noqa: E402
from cloud_attacks.common import Rand  # noqa: E402
from cloud_attacks.formats import assumed, ct, iam_user  # noqa: E402

ACCT = af.ACCT_PROD
T0 = int(datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp() * 1000)
DAY, HOUR, MIN = 86_400_000, 3_600_000, 60_000
D4 = T0 + 4 * DAY + 9 * HOUR
NEW = {"aws_vpcflow_mining_port", "aws_vpcflow_inbound_after_open", "aws_r53_dns_tunnel", "aws_r53_dga_nxdomain",
       "aws_r53_firewall_hit", "aws_r53_mining_pool", "aws_nfw_mining_alert", "aws_nfw_c2_alert",
       "aws_nfw_exploit_alert", "aws_nfw_scan_alert", "aws_s3_lifecycle_expire", "aws_s3_version_purge",
       "aws_s3_bucket_enum", "aws_s3_anonymous_read", "aws_sso_password_spray", "aws_sso_bruteforce",
       "aws_sso_mfa_fatigue", "aws_sso_mfa_device_new_net"}
IP = {n: v[0] for n, v in af.INSTANCES.items()}


def _s3(r: Rand, ts: int, ident: dict, ip: str, api: str, req: dict) -> Any:
    return ct(r, ts, ACCT, af.REGION, "s3.amazonaws.com", api, ident, ip, data=api not in (
        "PutBucketLifecycleConfiguration",), req=req)


def network(r: Rand) -> list[Any]:
    out = [af.dns(r, T0 + d * DAY + h * HOUR, n, "time.ntp.example", answer="198.51.100.190")
           for d in range(4) for h in (1, 13) for n in af.INSTANCES]                  # IP -> instance (host_ip_map)
    t = D4
    out += [af.flow(r, t + m * 5 * MIN, "build", IP["build"], "203.0.113.90", 50333, 3333, nbytes=9000) for m in range(4)]
    out += [af.flow(r, t + m * 5 * MIN, "web-1", IP["web-1"], "203.0.113.91", 50334, 3333, nbytes=9000) for m in range(2)]
    out += [af.flow(r, t + m * 5 * MIN, "app-1", IP["app-1"], IP["app-2"], 50335, 3333, nbytes=9000) for m in range(5)]
    # security group opened to the world, then SSH from the internet (p) / HTTPS to a web server (n)
    sess = assumed(r, ACCT, "AWSReservedSSO_AdministratorAccess_1a2b", "rnair@corp.example")
    out.append(ct(r, t, ACCT, af.REGION, "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", sess, "203.0.113.70",
                  req={"groupId": "sg-0b", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22,
                       "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}))
    out.append(af.flow(r, t + 20 * MIN, "bastion", "203.0.113.70", IP["bastion"], 52222, 22, direction="ingress"))
    out.append(af.flow(r, t + 21 * MIN, "web-3", "203.0.113.72", IP["web-3"], 52223, 443, direction="ingress"))
    # DNS: tunnel (p) vs hashed CDN names and allow-listed AWS names (n); DGA (p) vs typo flood of one domain (n)
    out += [af.dns(r, t + i * 20_000, "build", f"{r.b32(40).lower()}.t.cdn-sync.example", qtype="TXT") for i in range(50)]
    out += [af.dns(r, t + i * 20_000, "web-1", f"img-{r.hexs(12)}.cdn.example") for i in range(50)]
    out += [af.dns(r, t + i * 20_000, "app-1", f"{r.b32(40).lower()}.s3.amazonaws.com") for i in range(50)]
    out += [af.dns(r, t + HOUR + i * 9000, "build", f"{r.hexs(14)}.{tld}", rcode="NXDOMAIN")
            for i, tld in enumerate(["com", "net", "org", "info", "biz"] * 5)]
    out += [af.dns(r, t + HOUR + i * 9000, "web-2", f"host{i}.corp.example", rcode="NXDOMAIN") for i in range(25)]
    out += [af.dns(r, t + 2 * HOUR, "app-2", "evil.badlist.example", fw="ALERT"),
            af.dns(r, t + 2 * HOUR, "app-3", "evil2.badlist2.example", fw="BLOCK"),
            af.dns(r, t + 2 * HOUR, "build", "pool.supportxmr.example", answer="203.0.113.90"),
            af.dns(r, t + 2 * HOUR, "web-3", "0.amazon.pool.ntp.org", answer="198.51.100.190")]
    # Network Firewall alerts
    t3 = t + 3 * HOUR

    def alert(src: str, dst: str, sig: str, cat: str, sev: int = 2, action: str = "allowed", port: int = 443) -> Any:
        return af.nfw(r, t3, "alert", src, 50000, dst, port, app=None, alert={
            "signature": sig, "category": cat, "severity": sev, "action": action, "signature_id": r.randint(1, 9999)})
    out += [alert(IP["build"], "203.0.113.90", "ET COINMINER CryptoNight Stratum Submit",
                  "Crypto Currency Mining Activity Detected", 1, port=3333),
            alert(IP["bastion"], "203.0.113.71", "ET MALWARE Cobalt Strike Beacon Observed",
                  "A Network Trojan was Detected", 1),
            alert(IP["app-1"], "203.0.113.73", "ET MALWARE Generic Trojan Checkin", "A Network Trojan was Detected",
                  2, "blocked"),
            alert("203.0.113.50", IP["web-2"], "ET WEB_SERVER Possible SSRF Attempt to AWS Metadata",
                  "Web Application Attack", 1),
            alert("203.0.113.51", IP["web-1"], "ET SCAN Nmap Scripting Engine User-Agent Detected",
                  "Detection of a Network Scan", 2, "blocked"),
            alert(IP["app-3"], "198.51.100.150", "ET POLICY curl User-Agent Outbound", "Attempted Information Leak"),
            alert(IP["app-2"], "198.51.100.150", "ET INFO Observed EC2 Metadata Style Request", "Misc activity")]
    return out


def s3(r: Rand) -> list[Any]:
    t, out = D4 + 5 * HOUR, []
    u = {n: iam_user(r, ACCT, n) for n in ("p_lc", "p_ssec", "n_lc", "p_purge", "n_purge", "p_enum", "n_enum")}

    def lc(user: str, ts: int, rule: dict) -> Any:
        return _s3(r, ts, u[user], "203.0.113.60", "PutBucketLifecycleConfiguration",
                   {"bucketName": "b-" + user, "LifecycleConfiguration": {"Rule": [{"ID": "x", "Status": "Enabled",
                                                                                   **rule}]}})
    out.append(lc("p_lc", t, {"Expiration": {"Days": 1}}))
    out += [_s3(r, t + i * 5000, u["p_ssec"], "203.0.113.61", "CopyObject", {"bucketName": "b-p_ssec", "key": f"k{i}",
             "x-amz-server-side-encryption-customer-algorithm": "AES256"}) for i in range(25)]
    out.append(lc("p_ssec", t + 20 * MIN, {"Expiration": {"Days": "2"}}))
    out.append(lc("n_lc", t, {"Expiration": {"Days": 365}, "NoncurrentVersionExpiration": {"NoncurrentDays": 30},
                              "Transition": {"Days": 1, "StorageClass": "GLACIER"}}))
    out += [_s3(r, t + i * 20_000, u["p_purge"], "203.0.113.62", "DeleteObject",
                {"bucketName": "b1", "key": f"k{i}", "versionId": f"v{i}"}) for i in range(25)]
    out += [_s3(r, t + i * 20_000, u["n_purge"], "192.0.2.10", "DeleteObject",
                {"bucketName": "b2", "key": f"k{i}", **({"versionId": f"v{i}"} if i < 5 else {})}) for i in range(25)]
    out += [_s3(r, t + i * 30_000, u["p_enum"], "203.0.113.63", "ListObjectsV2", {"bucketName": f"bk{i}"})
            for i in range(9)]
    out += [_s3(r, t + i * 30_000, u["n_enum"], "192.0.2.11", "ListObjectsV2", {"bucketName": f"bk{i}"})
            for i in range(5)]
    anon = {"type": "AWSAccount", "principalId": "", "accountId": "anonymous"}
    out += [_s3(r, t + i * 10_000, anon, "203.0.113.44", "GetObject", {"bucketName": "pub", "key": f"o{i}"})
            for i in range(25)]
    out += [_s3(r, t + i * 10_000, anon, "203.0.113.45", "GetObject", {"bucketName": "pub", "key": f"o{i}"})
            for i in range(10)]
    return out


def sso(r: Rand) -> list[Any]:
    out = []
    for d in range(4):                                                   # history for the new-network check
        out += af.sso_login(r, T0 + d * DAY + 4 * HOUR, "p_dev", "198.51.100.120")
        out += af.sso_login(r, T0 + d * DAY + 4 * HOUR, "n_dev", "198.51.100.121")
    t = D4 + 8 * HOUR
    for i, user in enumerate(("u1", "u2", "u3", "u4", "u5", "p_victim")):
        out += af.sso_login(r, t + i * 60_000, user, "203.0.113.30", pw_fail=1, ok=False)[:2]
    out += af.sso_login(r, t + 12 * MIN, "p_victim", "203.0.113.30")
    for i, user in enumerate(("u6", "u7", "u8")):
        out += af.sso_login(r, t + i * 60_000, user, "203.0.113.31", pw_fail=1, ok=False)[:2]
    out += af.sso_login(r, t, "p_bf", "203.0.113.32", pw_fail=12, ok=False, step_ms=60_000)[:-2]
    out += af.sso_login(r, t, "n_bf", "203.0.113.33", pw_fail=4, step_ms=60_000)
    out += af.sso_login(r, t, "p_mfa", "203.0.113.34", mfa_fail=5, step_ms=60_000)
    out += af.sso_login(r, t, "n_mfa", "198.51.100.122", mfa_fail=1, step_ms=60_000)
    out += af.sso_mfa_register(r, t + HOUR, "p_dev", "203.0.113.35")
    out += af.sso_mfa_register(r, t + HOUR, "n_dev", "198.51.100.121")
    return out


@pytest.fixture(scope="module")
def ds(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("aws_detect")
    raw = tmp / "raw"
    raw.mkdir()
    r = Rand(5)
    evs = network(r) + s3(r) + sso(r)
    for feed in sorted({e.feed for e in evs}):
        (raw / f"{feed}.log").write_text("".join(json.dumps(e.doc) + "\n" for e in evs if e.feed == feed),
                                         encoding="utf-8")
    ctx = run_ingest(raw, tmp)
    cfg = subset(ctx.cfg, NEW | {"cl_firewall_open_world", "cl_storage_ransom_encrypt"})
    st, alerts = run(ctx.con, cfg, tmp / "work", ctx.events_glob)
    yield {"stats": st, "alerts": alerts}
    ctx.con.close()


def of(ds: dict, rule: str) -> list[dict]:
    return [a for a in ds["alerts"] if a["rule_id"] == rule]


def test_rules_ran_cleanly(ds) -> None:
    st = ds["stats"]
    assert st["errors"] == 0, st["error_messages"]
    assert NEW <= set(st["alerts_per_rule"])
    assert {r for r in NEW if not of(ds, r)} == set()       # every new rule has its positive


def test_vpcflow(ds) -> None:
    m = of(ds, "aws_vpcflow_mining_port")
    assert [(a["host"], a["src_ip"], a["technique_id"], a["sub_technique_id"]) for a in m] == \
        [(af.iid("build"), IP["build"], "T1496", "T1496.001")]
    o = of(ds, "aws_vpcflow_inbound_after_open")
    assert [(a["host"], a["src_ip"], a["tactic"]) for a in o] == [(af.iid("bastion"), "203.0.113.70", "Initial Access")]


def test_route53(ds) -> None:
    tun = of(ds, "aws_r53_dns_tunnel")
    assert [(a["host"], a["severity"]) for a in tun] == [(af.iid("build"), 85)]       # TXT-heavy -> 85
    assert [a["host"] for a in of(ds, "aws_r53_dga_nxdomain")] == [af.iid("build")]
    fw = sorted((a["host"], a["severity"]) for a in of(ds, "aws_r53_firewall_hit"))
    assert fw == sorted([(af.iid("app-2"), 65), (af.iid("app-3"), 50)])
    assert [a["host"] for a in of(ds, "aws_r53_mining_pool")] == [af.iid("build")]


def test_network_firewall_classes_and_endpoint_host(ds) -> None:
    assert [(a["host"], a["severity"]) for a in of(ds, "aws_nfw_mining_alert")] == [(af.iid("build"), 75)]
    c2 = sorted((a["host"], a["severity"]) for a in of(ds, "aws_nfw_c2_alert"))
    assert c2 == sorted([(af.iid("bastion"), 85), (af.iid("app-1"), 45)])      # allowed sev 1 / blocked
    ex = of(ds, "aws_nfw_exploit_alert")
    assert [(a["host"], a["src_ip"], a["severity"]) for a in ex] == [(af.iid("web-2"), "203.0.113.50", 80)]
    sc = of(ds, "aws_nfw_scan_alert")
    assert [(a["host"], a["technique_id"], a["severity"]) for a in sc] == [(af.iid("web-1"), "T1595", 30)]


def test_s3(ds) -> None:
    lc = sorted((a["src_user"], a["severity"]) for a in of(ds, "aws_s3_lifecycle_expire"))
    assert lc == [("p_lc", 65), ("p_ssec", 65), ("p_ssec", 90)]          # n_lc (365 / 30 / transition 1) silent
    assert [a["src_user"] for a in of(ds, "aws_s3_version_purge")] == ["p_purge"]
    assert [a["src_user"] for a in of(ds, "aws_s3_bucket_enum")] == ["p_enum"]
    assert [a["src_ip"] for a in of(ds, "aws_s3_anonymous_read")] == ["203.0.113.44"]


def test_identity_center(ds) -> None:
    sp = of(ds, "aws_sso_password_spray")
    assert sorted((a["src_ip"], a["technique_id"]) for a in sp) == [("203.0.113.30", "T1078"),
                                                                    ("203.0.113.30", "T1110")]
    assert [a["target_user"] or a["src_user"] for a in of(ds, "aws_sso_bruteforce")] == ["p_bf"]
    mfa = of(ds, "aws_sso_mfa_fatigue")
    assert [(a["src_user"] or a["target_user"], a["severity"]) for a in mfa] == [("p_mfa", 80)]
    dev = sorted((a["src_user"], a["severity"]) for a in of(ds, "aws_sso_mfa_device_new_net"))
    assert dev == [("n_dev", 35), ("p_dev", 75)]
