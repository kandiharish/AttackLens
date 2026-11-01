"""Record builders for the Kubernetes + GCP network generator (gen_k8s_and_gcp.py). Stdlib only.

Shapes (as the sources ship them; Stage 0 routes them by keys, config/sources.yaml):
  k8s   generic audit.k8s.io/v1 Event JSON line (kube-apiserver audit file / Fluent Bit with cluster_name)  -> k8s_audit_json
  aks   AKS Log Analytics AKSAudit row (PascalCase, dynamic columns as objects, _ResourceId)             -> k8s_audit_json
  gcp   Cloud Logging LogEntry with protoPayload AuditLog (GKE k8s.io rows included)                    -> gcp_audit_json
  flow  VPC Flow Logs LogEntry (jsonPayload.reporter / connection / bytes_sent)                          -> gcp_vpcflow_json
  fw    Firewall Rules Logging LogEntry (jsonPayload.rule_details / disposition)                         -> gcp_firewall_json
  dns   Cloud DNS query log LogEntry (jsonPayload.queryName ...)                                         -> gcp_dns_json
  scc   Security Command Center Pub/Sub notification {notificationConfigName, finding, resource}        -> gcp_scc_json
No record carries a ground-truth marker: labels live only in ground_truth/attacks.json.
"""

from __future__ import annotations

import re
from typing import Any

from cloud_attacks.common import Ev, Rand, iso_9, iso_s

EKS, AKS, GKE = "prod-eks-1", "aks-prod-2", "gke-prod-1"
AKS_RID = ("/subscriptions/9b0e6a51-0000-4000-8000-0000000000b2/resourcegroups/rg-aks/providers/"
           "Microsoft.ContainerService/managedClusters/" + AKS)
KUBECTL = "kubectl/v1.30.2 (linux/amd64) kubernetes/39683505"
CONNECTOR = {"k8s": "k8s_audit", "aks": "azure_monitor:AKSAudit", "gcp": "gcp_logging", "flow": "gcp_logging:vpc_flows",
             "fw": "gcp_logging:firewall", "dns": "gcp_logging:dns_queries", "scc": "gcp_scc"}
_SESSION = re.compile(r"^arn:aws[a-z-]*:sts::[0-9]*:assumed-role/[^/]+/([^/]+)$")


def iso_us(ms: int) -> str:
    return iso_s(ms)[:-1] + f".{ms % 1000:03d}000Z"


def k8s(r: Rand, ts: int, user: str, verb: str, res: str | None, *, ns: str | None = None, name: str | None = None,
        sub: str | None = None, code: int = 200, ip: str = "10.0.0.10", ua: str = KUBECTL,
        req: dict[str, Any] | None = None, uri: str | None = None, groups: list[str] | None = None,
        stage: str = "ResponseComplete", shape: str = "k8s", audit_id: str | None = None) -> Ev:
    """One audit event. shape k8s = generic JSON line (EKS cluster), aks = AKSAudit row (AKS cluster)."""
    aid = audit_id or r.guid()
    if uri is None:
        grp = "/apis/rbac.authorization.k8s.io/v1" if res and "role" in res else (
            "/apis/apps/v1" if res in ("deployments", "daemonsets", "statefulsets", "replicasets") else (
                "/apis/batch/v1" if res in ("jobs", "cronjobs") else "/api/v1"))
        uri = grp + (f"/namespaces/{ns}" if ns else "") + (f"/{res}" if res else "") + (f"/{name}" if name else "") + \
            (f"/{sub}" if sub else "")
    ref = {k: v for k, v in (("resource", res), ("namespace", ns), ("name", name), ("subresource", sub)) if v}
    if ref:
        ref["apiVersion"] = "v1"
    grp_list = groups or (["system:authenticated"] if not user.startswith("system:anonymous") else
                          ["system:unauthenticated"])
    decision = "forbid" if code in (401, 403) else "allow"
    if shape == "aks":
        doc: dict[str, Any] = {"TenantId": "4d5f1c2e-0000-4000-8000-0000000000a1", "TimeGenerated": iso_9(ts + 900, 0)[:-3] + "Z",
                               "Level": "Request" if req else "Metadata", "AuditId": aid, "Stage": stage,
                               "RequestUri": uri, "Verb": verb, "User": {"username": user, "groups": grp_list},
                               "SourceIps": [ip], "UserAgent": ua}
        if ref:
            doc["ObjectRef"] = ref
        if stage != "RequestReceived":
            doc["ResponseStatus"] = {"metadata": {}, "code": code}
        if req is not None:
            doc["RequestObject"] = req
        doc.update({"RequestReceivedTime": iso_us(ts), "StageReceivedTime": iso_us(ts + 15),
                    "Annotations": {"authorization.k8s.io/decision": decision}, "_ResourceId": AKS_RID,
                    "Type": "AKSAudit"})
        return Ev(ts, "aks", f"{aid}:{stage}", doc)
    doc = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Request" if req else "Metadata", "auditID": aid,
           "stage": stage, "requestURI": uri, "verb": verb, "user": {"username": user, "groups": grp_list},
           "sourceIPs": [ip], "userAgent": ua}
    if ref:
        doc["objectRef"] = ref
    if stage != "RequestReceived":
        doc["responseStatus"] = {"metadata": {}, "code": code}
    if req is not None:
        doc["requestObject"] = req
    doc.update({"requestReceivedTimestamp": iso_us(ts), "stageTimestamp": iso_us(ts + r.randint(2, 40)),
                "annotations": {"authorization.k8s.io/decision": decision}, "cluster_name": EKS})
    return Ev(ts, "k8s", f"{aid}:{stage}", doc)


def pod_spec(*, image: str = "registry.corp.example/app:1.4", priv: bool = False, host_path: str | None = None,
             host_pid: bool = False, host_net: bool = False, cmd: list[str] | None = None) -> dict[str, Any]:
    c: dict[str, Any] = {"name": "main", "image": image}
    if priv:
        c["securityContext"] = {"privileged": True}
    if cmd:
        c["command"] = cmd
    spec: dict[str, Any] = {"containers": [c]}
    if host_pid:
        spec["hostPID"] = True
    if host_net:
        spec["hostNetwork"] = True
    if host_path:
        spec["volumes"] = [{"name": "host", "hostPath": {"path": host_path, "type": ""}}]
        c["volumeMounts"] = [{"name": "host", "mountPath": "/host"}]
    return spec


def gke(r: Rand, ts: int, project: str, principal: str, method: str, resource_name: str, ip: str, *,
        code: int = 0, request: dict[str, Any] | None = None, ua: str = KUBECTL) -> Ev:
    """GKE audit LogEntry (k8s.io). The vendor `labels` (authorization decision) is real GKE evidence, not ground truth."""
    insert = r.hexs(16)
    pp: dict[str, Any] = {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                          "authenticationInfo": {"principalEmail": principal},
                          "authorizationInfo": [{"granted": code == 0, "permission": method,
                                                 "resource": resource_name}],
                          "methodName": method, "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": ua},
                          "resourceName": resource_name, "serviceName": "k8s.io",
                          "status": {"code": code, "message": "PERMISSION_DENIED"} if code else {"code": 0}}
    if request is not None:
        pp["request"] = request
    entry = {"protoPayload": pp, "insertId": insert,
             "resource": {"type": "k8s_cluster", "labels": {"cluster_name": GKE, "location": "asia-south1",
                                                            "project_id": project}},
             "timestamp": iso_9(ts, r.randint(0, 999_999)),
             "labels": {"authorization.k8s.io/decision": "forbid" if code else "allow",
                        "authorization.k8s.io/reason": "access granted by IAM permissions." if not code else ""},
             "logName": f"projects/{project}/logs/cloudaudit.googleapis.com%2Factivity",
             "receiveTimestamp": iso_9(ts + r.randint(300, 1500), r.randint(0, 999_999))}
    return Ev(ts, "gcp", insert, entry)


def _logentry(r: Rand, ts: int, project: str, log: str, payload: dict[str, Any], rtype: str,
              rlabels: dict[str, Any], prefix: str) -> dict[str, Any]:
    return {"insertId": prefix + r.hexs(14), "jsonPayload": payload,
            "logName": f"projects/{project}/logs/{log}", "receiveTimestamp": iso_us(ts + r.randint(3000, 9000)),
            "resource": {"type": rtype, "labels": {"project_id": project, **rlabels}},
            # flow logs: the entry is written after the aggregation interval (the flow's own time is start_time)
            "timestamp": iso_us(ts + 5000 if prefix == "fl" else ts)}


def flow(r: Rand, ts: int, project: str, src: str, dst: str, dport: int, *, src_vm: str | None = None,
         dst_vm: str | None = None, nbytes: int = 4096, reporter: str = "SRC", sport: int | None = None) -> Ev:
    conn = {"src_ip": src, "src_port": sport or r.randint(32768, 60999), "dest_ip": dst, "dest_port": dport,
            "protocol": 6}
    p: dict[str, Any] = {"bytes_sent": str(nbytes), "connection": conn, "start_time": iso_us(ts),
                         "end_time": iso_us(ts + r.randint(200, 4000)), "packets_sent": str(max(1, nbytes // 1200)),
                         "reporter": reporter, "rtt_msec": str(r.randint(1, 60))}
    for key, vm in (("src_instance", src_vm), ("dest_instance", dst_vm)):
        if vm:
            p[key] = {"project_id": project, "region": "asia-south1", "vm_name": vm, "zone": "asia-south1-a"}
    if src_vm:
        p["src_vpc"] = {"project_id": project, "subnetwork_name": "prod-sub", "vpc_name": "prod-vpc"}
    d = _logentry(r, ts, project, "compute.googleapis.com%2Fvpc_flows", p, "gce_subnetwork",
                  {"location": "asia-south1-a", "subnetwork_name": "prod-sub"}, "fl")
    return Ev(ts, "flow", d["insertId"], d)


def fw(r: Rand, ts: int, project: str, src: str, dst: str, dport: int, vm: str, *, allowed: bool,
       rule: str) -> Ev:
    p = {"connection": {"src_ip": src, "src_port": r.randint(32768, 60999), "dest_ip": dst, "dest_port": dport,
                        "protocol": 6},
         "disposition": "ALLOWED" if allowed else "DENIED",
         "instance": {"project_id": project, "region": "asia-south1", "vm_name": vm, "zone": "asia-south1-a"},
         "rule_details": {"action": "ALLOW" if allowed else "DENY", "direction": "INGRESS",
                          "priority": 1000 if allowed else 65534, "reference": f"network:prod-vpc/firewall:{rule}",
                          "source_range": ["0.0.0.0/0"]},
         "vpc": {"project_id": project, "subnetwork_name": "prod-sub", "vpc_name": "prod-vpc"}}
    d = _logentry(r, ts, project, "compute.googleapis.com%2Ffirewall", p, "gce_subnetwork",
                  {"subnetwork_name": "prod-sub"}, "fw")
    return Ev(ts, "fw", d["insertId"], d)


def dns(r: Rand, ts: int, project: str, vm: str, src: str, name: str, *, qtype: str = "A",
        rcode: str = "NOERROR") -> Ev:
    p = {"authAnswer": False, "destinationIP": "169.254.169.254", "protocol": "UDP", "queryName": name + ".",
         "queryType": qtype, "rdata": "" if rcode != "NOERROR" else f"{name}.\t300\tIN\t{qtype}\t...",
         "responseCode": rcode, "serverLatency": r.randint(1, 30), "sourceIP": src, "sourceNetwork": "prod-vpc",
         "vmInstanceIdString": str(4011234567890123000 + sum(map(ord, vm))),
         "vmInstanceName": f"{project}.asia-south1-a.{vm}", "vmProjectId": project, "vmZoneName": "asia-south1-a"}
    d = _logentry(r, ts, project, "dns.googleapis.com%2Fdns_queries", p, "dns_query",
                  {"location": "global", "source_type": "gce-vm", "target_type": "external"}, "dn")
    return Ev(ts, "dns", d["insertId"], d)


def scc(r: Rand, ts: int, project: str, category: str, severity: str, tactic: str, techniques: list[str],
        resource: str, *, principal: str | None = None, ip: str | None = None) -> Ev:
    fid = r.hexs(32)
    f: dict[str, Any] = {"name": f"organizations/123456789012/sources/5678/findings/{fid}",
                         "parent": "organizations/123456789012/sources/5678", "resourceName": resource,
                         "state": "ACTIVE", "category": category, "eventTime": iso_us(ts),
                         "createTime": iso_us(ts + 60_000), "severity": severity, "findingClass": "THREAT",
                         "mitreAttack": {"primaryTactic": tactic, "primaryTechniques": techniques}}
    if principal:
        f["access"] = {"principalEmail": principal, "callerIp": ip}
    d = {"notificationConfigName": "organizations/123456789012/notificationConfigs/to-siem", "finding": f,
         "resource": {"name": resource, "projectDisplayName": project}}
    return Ev(ts, "scc", fid, d)


def entity(ev: Ev) -> dict[str, Any]:
    """host / user / src_ip / action following the config/sources.yaml alias precedence (and value_regex)."""
    d = ev.doc
    if ev.feed in ("k8s", "aks"):
        u = (d.get("user") or d.get("User") or {}).get("username")
        m = _SESSION.match(u or "")
        ip = (d.get("sourceIPs") or d.get("SourceIps") or [None])[0]
        host = d.get("cluster_name") or AKS
        return {"host": host, "user": m.group(1) if m else u, "src_ip": ip, "action": d.get("verb") or d.get("Verb")}
    if ev.feed == "gcp":
        pp = d["protoPayload"]
        return {"host": d["resource"]["labels"]["project_id"], "user": pp["authenticationInfo"].get("principalEmail"),
                "src_ip": pp["requestMetadata"].get("callerIp"), "action": pp["methodName"]}
    p = d.get("jsonPayload") or {}
    if ev.feed == "flow":
        c = p["connection"]
        vm = (p.get("src_instance") or p.get("dest_instance") or {}).get("vm_name")
        return {"host": vm, "user": None, "src_ip": c["src_ip"], "action": p["reporter"]}
    if ev.feed == "fw":
        return {"host": p["instance"]["vm_name"], "user": None, "src_ip": p["connection"]["src_ip"],
                "action": p["disposition"]}
    if ev.feed == "dns":
        return {"host": p["vmInstanceName"].rsplit(".", 1)[-1], "user": None, "src_ip": p["sourceIP"],
                "action": p["queryType"]}
    f = d["finding"]
    return {"host": d["resource"]["projectDisplayName"], "user": (f.get("access") or {}).get("principalEmail"),
            "src_ip": (f.get("access") or {}).get("callerIp"), "action": f["category"]}
