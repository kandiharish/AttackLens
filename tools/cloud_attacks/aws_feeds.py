"""AWS network / sign-in / findings record builders for tools/cloud_attacks/gen_aws.py (stdlib only).

Shapes (reports/cloud/log_coverage.md research; config/sources.yaml aws_* entries):
- VPC Flow Logs v5 as JSON lines in three shapes: hyphenated header names ("interface-id"), underscore names
  (Parquet / Athena), Sentinel AWSVPCFlow PascalCase. `text_line` renders the native space-separated text form.
- Route 53 Resolver query log (CloudWatch / S3 JSON), with DNS Firewall fields when a rule matched.
- AWS Network Firewall EVE records (netflow / alert / tls) with event.timestamp "...+0000".
- IAM Identity Center sign-in CloudTrail events (CredentialChallenge / CredentialVerification / UserAuthentication).
- GuardDuty findings (bare / EventBridge) and Security Hub ASFF findings.

Address plan of this generator (all RFC 5737 / RFC 1918): 10.0.0.0/16 = the VPC; 203.0.113.0/24 = attacker ONLY;
198.51.100.1-35 = web customers; 198.51.100.150-199 = external services (mirrors, SaaS, NAT EIP, S3 endpoint);
198.51.100.210-230 = internet background scanners (noise, never an attack step); 192.0.2.0/24 = corp egress.
"""

from __future__ import annotations

import hashlib
from typing import Any

from cloud_attacks.common import ACCT_PROD, Ev, Rand, iso_s
from cloud_attacks.formats import UA_CONSOLE, ct

REGION = "ap-south-1"
VPC = "vpc-0a1b2c3d4e5f60718"
FIREWALL = "prod-egress-fw"
NAT_EIP = "198.51.100.170"
S3_ENDPOINT_IP = "198.51.100.160"


def _h(s: str, n: int) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:n]


def iid(name: str) -> str:
    return "i-0" + _h("inst" + name, 16)


def eni(name: str) -> str:
    return "eni-0" + _h("eni" + name, 16)


# name -> (private ip, subnet, flow shape)
INSTANCES: dict[str, tuple[str, str, str]] = {
    "bastion": ("10.0.1.5", "subnet-0a01", "underscore"),
    "web-1": ("10.0.1.11", "subnet-0a01", "hyphen"), "web-2": ("10.0.1.12", "subnet-0a01", "hyphen"),
    "web-3": ("10.0.1.13", "subnet-0a01", "hyphen"),
    "app-1": ("10.0.2.21", "subnet-0a02", "hyphen"), "app-2": ("10.0.2.22", "subnet-0a02", "hyphen"),
    "app-3": ("10.0.2.23", "subnet-0a02", "hyphen"), "build": ("10.0.2.50", "subnet-0a02", "underscore"),
    "db-1": ("10.0.3.31", "subnet-0a03", "sentinel"), "db-2": ("10.0.3.32", "subnet-0a03", "sentinel"),
}
IP_OWNER = {ip: iid(n) for n, (ip, _, _) in INSTANCES.items()}
PROTO = {"tcp": 6, "udp": 17, "icmp": 1}


# ============================================================================ VPC Flow Logs
def flow(r: Rand, ts: int, inst: str, src: str, dst: str, sport: int, dport: int, *, proto: str = "tcp",
         pkts: int = 10, nbytes: int = 2000, action: str = "ACCEPT", direction: str = "egress",
         dur_s: int = 600) -> Ev:
    """One aggregated flow record captured on `inst`'s ENI (default 10-min aggregation interval: a long connection
    yields one record per interval). ts = first packet in the interval (epoch s in the record)."""
    ip, subnet, shape = INSTANCES[inst]
    s = ts // 1000
    rec = {"version": 5, "account-id": ACCT_PROD, "interface-id": eni(inst), "srcaddr": src, "dstaddr": dst,
           "srcport": sport, "dstport": dport, "protocol": PROTO[proto], "packets": pkts, "bytes": nbytes,
           "start": s, "end": s + dur_s, "action": action, "log-status": "OK", "vpc-id": VPC, "subnet-id": subnet,
           "instance-id": iid(inst), "tcp-flags": 2 if proto == "tcp" else 0, "type": "IPv4",
           "pkt-srcaddr": src, "pkt-dstaddr": dst, "flow-direction": direction}
    rid = f"fl-{_h(f'{inst}|{s}|{src}|{dst}|{sport}|{dport}|{r.random()}', 20)}"
    return Ev(s * 1000, "vpcflow", rid, reshape(rec, shape))


def nodata(ts: int, inst: str) -> Ev:
    s = ts // 1000
    rec = {"version": 5, "account-id": ACCT_PROD, "interface-id": eni(inst), "srcaddr": "-", "dstaddr": "-",
           "srcport": "-", "dstport": "-", "protocol": "-", "packets": "-", "bytes": "-", "start": s, "end": s + 60,
           "action": "-", "log-status": "NODATA", "vpc-id": VPC, "subnet-id": INSTANCES[inst][1],
           "instance-id": iid(inst), "tcp-flags": "-", "type": "-", "pkt-srcaddr": "-", "pkt-dstaddr": "-",
           "flow-direction": "-"}
    return Ev(s * 1000, "vpcflow", f"fl-nodata-{inst}-{s}", reshape(rec, INSTANCES[inst][2]))


_PASCAL = {"version": "Version", "account-id": "AccountId", "interface-id": "InterfaceId", "srcaddr": "SrcAddr",
           "dstaddr": "DstAddr", "srcport": "SrcPort", "dstport": "DstPort", "protocol": "Protocol",
           "packets": "Packets", "bytes": "Bytes", "start": "Start", "end": "End", "action": "Action",
           "log-status": "LogStatus", "vpc-id": "VpcId", "subnet-id": "SubnetId", "instance-id": "InstanceId",
           "tcp-flags": "TcpFlags", "type": "Type", "pkt-srcaddr": "PktSrcAddr", "pkt-dstaddr": "PktDstAddr",
           "flow-direction": "FlowDirection"}


def reshape(rec: dict[str, Any], shape: str) -> dict[str, Any]:
    if shape == "hyphen":
        return rec
    if shape == "underscore":
        return {k.replace("-", "_"): v for k, v in rec.items()}
    out = {"TimeGenerated": iso_s(int(rec["start"]) * 1000)}
    for k, v in rec.items():
        out[_PASCAL[k]] = iso_s(int(v) * 1000) if k in ("start", "end") else v
    return out


def text_line(rec: dict[str, Any], fields: list[str]) -> str:
    """The native text form of a hyphen-shaped record (S3 file body / CloudWatch message)."""
    return " ".join(str(rec.get(f, "-")) for f in fields)


# ============================================================================ Route 53 Resolver
def dns(r: Rand, ts: int, inst: str, name: str, *, qtype: str = "A", rcode: str = "NOERROR",
        answer: str | None = None, fw: str | None = None) -> Ev:
    ip = INSTANCES[inst][0]
    rec: dict[str, Any] = {"version": "1.100000", "account_id": ACCT_PROD, "region": REGION, "vpc_id": VPC,
                           "query_timestamp": iso_s(ts)[:-1] + f".{ts % 1000:03d}Z", "query_name": name.rstrip(".") + ".",
                           "query_type": qtype, "query_class": "IN", "rcode": rcode,
                           "answers": ([{"Rdata": answer, "Type": qtype, "Class": "IN"}] if answer else []),
                           "srcaddr": ip, "srcport": str(r.randint(32768, 60999)), "transport": "UDP",
                           "srcids": {"instance": iid(inst)}}
    if fw:
        rec.update(firewall_rule_group_id="rslvr-frg-" + _h("frg", 16), firewall_rule_action=fw,
                   firewall_domain_list_id="rslvr-fdl-" + _h("fdl", 16))
    return Ev(ts, "r53", f"dns-{_h(f'{inst}|{ts}|{name}|{r.random()}', 20)}", rec)


# ============================================================================ Network Firewall
def _nfw_ts(ts: int, r: Rand) -> str:
    return iso_s(ts)[:-1] + f".{ts % 1000:03d}{r.randint(0, 999):03d}+0000"


def nfw(r: Rand, ts: int, etype: str, src: str, sport: int, dst: str, dport: int, *, proto: str = "TCP",
        app: str | None = "tls", nbytes: int = 0, pkts: int = 0, sni: str | None = None,
        alert: dict[str, Any] | None = None) -> Ev:
    flow_id = r.getrandbits(50)
    ev: dict[str, Any] = {"timestamp": _nfw_ts(ts, r), "flow_id": flow_id, "event_type": etype, "src_ip": src,
                          "src_port": sport, "dest_ip": dst, "dest_port": dport, "proto": proto}
    if app:
        ev["app_proto"] = app
    if etype == "netflow":
        ev["netflow"] = {"pkts": pkts, "bytes": nbytes, "start": _nfw_ts(ts, r), "end": _nfw_ts(ts + 60_000, r),
                         "age": 60, "min_ttl": 63, "max_ttl": 64}
    if etype == "tls" or (sni and etype == "alert"):
        ev["tls"] = {"sni": sni, "version": "TLS 1.3"}
    if etype == "alert":
        ev["alert"] = {"action": "allowed", "signature_id": 2000000, "rev": 1, "signature": "", "category": "",
                       "severity": 3, **(alert or {})}
    rec = {"firewall_name": FIREWALL, "availability_zone": REGION + "a", "event_timestamp": str(ts // 1000), "event": ev}
    return Ev(ts, "nfw", f"nfw-{flow_id}-{etype}", rec)


# ============================================================================ Identity Center sign-in (CloudTrail)
def sso_ident(user: str) -> dict[str, Any]:
    return {"type": "Unknown", "principalId": ACCT_PROD, "arn": "", "accountId": ACCT_PROD, "accessKeyId": "",
            "userName": user}


def sso_signin(r: Rand, ts: int, user: str, ip: str, name: str, cred: str | None, verdict: str, wf: str) -> Ev:
    add: dict[str, Any] = {"AuthWorkflowID": wf}
    if cred:
        add["CredentialType"] = cred
    if name == "UserAuthentication":
        add["LoginTo"] = "https://d-9067c1a2b3.awsapps.com/start/"
    return ct(r, ts, ACCT_PROD, REGION, "signin.amazonaws.com", name, sso_ident(user), ip, ua=UA_CONSOLE,
              etype="AwsServiceEvent", extra={"serviceEventDetails": {name: verdict}, "additionalEventData": add})


def sso_login(r: Rand, ts: int, user: str, ip: str, *, pw_fail: int = 0, mfa_fail: int = 0, mfa: str = "TOTP",
              ok: bool = True, step_ms: int = 4000) -> list[Ev]:
    """A full sign-in workflow: password (with failures), then the MFA factor (with failures), then the result."""
    wf, t, out = r.guid(), ts, []
    for _ in range(pw_fail):
        out += [sso_signin(r, t, user, ip, "CredentialChallenge", "PASSWORD", "Success", wf),
                sso_signin(r, t + 1000, user, ip, "CredentialVerification", "PASSWORD", "Failure", wf)]
        t += step_ms
    out += [sso_signin(r, t, user, ip, "CredentialChallenge", "PASSWORD", "Success", wf),
            sso_signin(r, t + 1000, user, ip, "CredentialVerification", "PASSWORD", "Success", wf)]
    t += step_ms
    for _ in range(mfa_fail):
        out += [sso_signin(r, t, user, ip, "CredentialChallenge", mfa, "Success", wf),
                sso_signin(r, t + 1000, user, ip, "CredentialVerification", mfa, "Failure", wf)]
        t += step_ms
    if ok:
        out += [sso_signin(r, t, user, ip, "CredentialChallenge", mfa, "Success", wf),
                sso_signin(r, t + 1000, user, ip, "CredentialVerification", mfa, "Success", wf),
                sso_signin(r, t + 2000, user, ip, "UserAuthentication", f"PASSWORD,{mfa}", "Success", wf)]
    return out


def sso_mfa_register(r: Rand, ts: int, user: str, ip: str) -> list[Ev]:
    dev = {"deviceName": "laptop-key", "mfaType": "WebAuthn"}
    return [ct(r, ts + i * 20_000, ACCT_PROD, REGION, "sso-directory.amazonaws.com", n, sso_ident(user), ip,
               ua=UA_CONSOLE, req=dev) for i, n in enumerate(("StartWebAuthnDeviceRegistration",
                                                               "CompleteWebAuthnDeviceRegistration"))]


# ============================================================================ findings
def guardduty(r: Rand, ts: int, ftype: str, sev: float, *, inst: str | None = None, user: str | None = None,
              remote: str | None = None, outbound: bool = False, fid: str | None = None, count: int = 1,
              updated_ms: int | None = None, indicators: list[dict[str, Any]] | None = None) -> Ev:
    fid = fid or _h(f"gd|{ftype}|{ts}", 32)
    res: dict[str, Any] = {"resourceType": "Instance" if inst else "AccessKey"}
    if inst:
        res["instanceDetails"] = {"instanceId": iid(inst), "networkInterfaces": [
            {"privateIpAddress": INSTANCES[inst][0], "networkInterfaceId": eni(inst)}]}
    if user:
        res["accessKeyDetails"] = {"userName": user, "principalId": "AROA" + _h(user, 17).upper(),
                                   "userType": "AssumedRole"}
    action: dict[str, Any] = {}
    if remote and inst and not user:
        action = {"actionType": "NETWORK_CONNECTION", "networkConnectionAction": {
            "connectionDirection": "OUTBOUND" if outbound else "INBOUND", "remoteIpDetails": {"ipAddressV4": remote},
            "localIpDetails": {"ipAddressV4": INSTANCES[inst][0]}, "protocol": "TCP", "blocked": False}}
    elif remote:
        action = {"actionType": "AWS_API_CALL", "awsApiCallAction": {"api": "ListBuckets", "remoteIpDetails":
                                                                       {"ipAddressV4": remote}}}
    svc: dict[str, Any] = {"serviceName": "guardduty", "detectorId": _h("detector", 32), "action": action,
                           "eventFirstSeen": iso_s(ts), "eventLastSeen": iso_s(updated_ms or ts), "count": count,
                           "archived": False}
    if indicators:
        svc["detection"] = {"sequence": {"sequenceIndicators": indicators}}
    rec = {"schemaVersion": "2.0", "accountId": ACCT_PROD, "region": REGION, "partition": "aws", "id": fid,
           "arn": f"arn:aws:guardduty:{REGION}:{ACCT_PROD}:detector/x/finding/{fid}", "type": ftype,
           "resource": res, "service": svc, "severity": sev, "createdAt": iso_s(ts),
           "updatedAt": iso_s(updated_ms or ts), "title": ftype.split("/")[-1], "description": "synthetic finding"}
    return Ev(ts, "guardduty", f"gd-{fid}-{updated_ms or ts}", rec)


def eventbridge(ev: Ev) -> Ev:
    return Ev(ev.ts, ev.feed, ev.rid + "-eb", {"version": "0", "id": _h(ev.rid, 32), "detail-type": "GuardDuty Finding",
                                              "source": "aws.guardduty", "account": ACCT_PROD, "time": iso_s(ev.ts),
                                              "region": REGION, "resources": [], "detail": ev.doc})


def asff(ts: int, title: str, types: list[str], label: str, *, product: str = "GuardDuty", inst: str | None = None,
         remote: str | None = None) -> Ev:
    fid = f"arn:aws:securityhub:{REGION}:{ACCT_PROD}:finding/{_h(title + str(ts), 32)}"
    res = ([{"Type": "AwsEc2Instance", "Id": f"arn:aws:ec2:{REGION}:{ACCT_PROD}:instance/{iid(inst)}"}] if inst
           else [{"Type": "AwsAccount", "Id": f"AWS::::Account:{ACCT_PROD}"}])
    rec: dict[str, Any] = {"SchemaVersion": "2018-10-08", "Id": fid,
                           "ProductArn": f"arn:aws:securityhub:{REGION}::product/aws/{product.lower()}",
                           "ProductName": product, "GeneratorId": f"{product.lower()}-{_h(title, 8)}",
                           "AwsAccountId": ACCT_PROD, "Types": types, "FirstObservedAt": iso_s(ts),
                           "CreatedAt": iso_s(ts), "UpdatedAt": iso_s(ts), "Severity": {"Label": label},
                           "Title": title, "Description": "synthetic finding", "Resources": res,
                           "RecordState": "ACTIVE", "Workflow": {"Status": "NEW"}}
    if remote:
        rec["Network"] = {"Direction": "IN", "SourceIpV4": remote}
    return Ev(ts, "securityhub", f"sh-{_h(fid, 20)}", rec)


# ============================================================================ ground-truth entity
def entity(ev: Ev) -> dict[str, Any]:
    """host / user / src_ip / action as the AttackLens rules report them for these feeds."""
    d = ev.doc
    if ev.feed == "vpcflow":
        g = lambda *ks: next((d[k] for k in ks if k in d), None)  # noqa: E731
        return {"host": g("instance-id", "instance_id", "InstanceId"), "user": None,
                "src_ip": g("pkt-srcaddr", "pkt_srcaddr", "PktSrcAddr"), "action": g("action", "Action")}
    if ev.feed == "r53":
        return {"host": d["srcids"]["instance"], "user": None, "src_ip": d["srcaddr"], "action": d["query_type"]}
    if ev.feed == "nfw":
        e = d["event"]
        owner = IP_OWNER.get(e["src_ip"]) or IP_OWNER.get(e["dest_ip"])
        return {"host": owner, "user": None, "src_ip": e["src_ip"], "action": e["event_type"]}
    raise ValueError(ev.feed)
