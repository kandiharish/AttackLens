"""Kubernetes + GCP (GKE, audit, VPC flow, firewall, Cloud DNS, SCC) attack dataset with ground truth. Stdlib only.

    python tools/cloud_attacks/gen_k8s_and_gcp.py --out data/raw/cloud_k8s_and_gcp --seed 11 [--days 7] [--scale 1.0]

Layout (Stage 0 routes every file by its keys, never by its name):
    k8s_audit/eks/part-*.jsonl          generic audit.k8s.io/v1 lines (cluster prod-eks-1)       -> k8s_audit_json
    azure_monitor/aksaudit/part-*.jsonl AKSAudit rows (cluster aks-prod-2)                      -> k8s_audit_json
    gcp_logging/gcp_audit/part-*.jsonl  Cloud Audit Logs incl. GKE k8s.io (gke-prod-1)           -> gcp_audit_json
    gcp_logging/vpc_flows|firewall|dns_queries/part-*.jsonl                                       -> gcp_*_json
    gcp_scc/findings.jsonl              SCC notifications (context only)                          -> gcp_scc_json
    manifest.json, ground_truth/attacks.json (harness schema, backend/eval/harness.py)

Benign baseline: 7 days of control-plane noise (kubelets, controllers, scheduler), operators (Argo CD, Prometheus,
CI), people (developers, ops, data engineers) and GCP network / DNS / BigQuery / Cloud Run activity, including
near misses that resemble the attacks (k8s_gcp_stories.DECOYS). Served records carry NO ground-truth field.
Addresses: 203.0.113.0/24 attacker only; 192.0.2.0/24 corp + VPN; 198.51.100.0/24 homes, partners, background
internet scanners; 10.0.0.0/8 workloads (common.py). Domains are *.example.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
sys.path.insert(0, str(_HERE.parents[1]))   # tools/ on path so `cloud_attacks` imports when run as a script

from cloud_attacks import k8s_gcp_feeds as kf   # noqa: E402
from cloud_attacks import k8s_gcp_stories as ks   # noqa: E402
from cloud_attacks.common import (CI_IPS, CORP_IPS, DAY, HOUR, MIN, PROJ_DATA, PROJ_PROD, START_MS, VPN_IPS, Ev,  # noqa: E402
                                  Rand, home_ip, iso_s, sub_rng)

FEED_DIR = {"k8s": "k8s_audit/eks", "aks": "azure_monitor/aksaudit", "gcp": "gcp_logging/gcp_audit",
            "flow": "gcp_logging/vpc_flows", "fw": "gcp_logging/firewall", "dns": "gcp_logging/dns_queries",
            "scc": "gcp_scc"}
MAX_PART_BYTES = 8 * 1024 * 1024
NODES = [f"system:node:ip-10-0-1-{i}.ec2.internal" for i in (5, 6, 7, 8)]
AKS_NODES = [f"system:node:aks-nodepool1-3141592-vmss00000{i}" for i in range(3)]
DEVS, OPS, DATA = ("pmehta", "vreddy", "tgupta"), ("rnair", "akumar"), ("dsingh", "lfernandes")
NS = ("payments", "shop", "data", "ci", "monitoring", "web")
ARGO = "system:serviceaccount:argocd:argocd-application-controller"
PROM = "system:serviceaccount:monitoring:prometheus"
CI = "system:serviceaccount:ci:terraform"
ETL = f"etl-nightly@{PROJ_DATA}.iam.gserviceaccount.com"
CLOUDBUILD = "555000111222@cloudbuild.gserviceaccount.com"
WEB = (("web-1", "10.128.0.10"), ("web-2", "10.128.0.11"))
DB, BACKUP = ("db-1", "10.128.0.21"), ("db-backup-1", "10.128.0.22")


def user_ip(r: Rand, u: str) -> str:
    return r.choice(VPN_IPS) if r.random() < 0.6 else home_ip(sum(map(ord, u)) % 50)


def business(hour: int) -> bool:
    return 3 <= hour <= 13          # 09:00-19:00 IST


def k8s_hour(seed: int, day: int, hour: int, scale: float) -> list[Ev]:
    r = sub_rng(seed, "k8s", day, hour)
    t0 = START_MS + day * DAY + hour * HOUR
    out: list[Ev] = []
    n = lambda k: max(1, int(k * scale))   # noqa: E731
    for i in range(n(24)):                                   # kubelets fetch pod secrets / configmaps
        node = NODES[i % len(NODES)]
        res = r.choice(("secrets", "configmaps"))
        out.append(kf.k8s(r, t0 + r.randint(0, HOUR - 1), node, "get", res, ns=r.choice(NS), name=f"{res[:3]}-{i % 9}",
                          ip=f"10.0.1.{5 + i % 4}", ua="kubelet/v1.30.2 (linux/amd64) kubernetes/39683505"))
    for i in range(n(12)):                                   # controllers and the scheduler
        ts = t0 + r.randint(0, HOUR - 1)
        ctl = r.choice(("replicaset-controller", "deployment-controller", "endpointslice-controller"))
        out.append(kf.k8s(r, ts, f"system:serviceaccount:kube-system:{ctl}", r.choice(("create", "update", "patch")),
                          r.choice(("pods", "replicasets", "endpointslices")), ns=r.choice(NS), name=f"x-{r.hexs(5)}",
                          ip="10.0.0.2", code=201, ua="kube-controller-manager/v1.30.2"))
        out.append(kf.k8s(r, ts + 900, "system:kube-scheduler", "create", "pods", ns=r.choice(NS),
                          name=f"x-{r.hexs(5)}", sub="binding", ip="10.0.0.2", code=201, ua="kube-scheduler/v1.30.2"))
    for i in range(n(12)):                                   # Prometheus scrapes cluster-wide
        out.append(kf.k8s(r, t0 + i * 5 * MIN, PROM, "list", ("pods", "nodes", "endpoints", "services")[i % 4],
                          ip="10.42.0.20", ua="Prometheus/2.53.0"))
    for i, ns in enumerate(r.sample(NS, 6)):                 # D2: Argo CD repo credentials, 6 namespaces per hour
        out.append(kf.k8s(r, t0 + i * 7 * MIN, ARGO, "get", "secrets", ns=ns, name="repo-creds", ip="10.42.0.9",
                          ua="argocd-application-controller/v2.11.3"))
    for i in range(n(12)):                                   # D8: LB health probes, no objectRef
        out.append(kf.k8s(r, t0 + i * 5 * MIN, "system:anonymous", "get", None, ip="10.0.0.250",
                          uri=r.choice(("/healthz", "/livez", "/readyz")), ua="ELB-HealthChecker/2.0"))
    if business(hour) and day % 7 not in (5, 6):
        for u in DEVS + OPS:                                 # people: read, logs, `kubectl get all`, rollouts
            ip = user_ip(sub_rng(seed, "ip", u, day), u)
            arn = ks.eks_user(u, "eks-ops" if u in OPS else "eks-devs")
            for _ in range(n(4)):
                ts = t0 + r.randint(0, HOUR - 1)
                v, res = r.choice((("get", "pods"), ("list", "pods"), ("get", "deployments"), ("list", "events"),
                                   ("get", "services")))
                out.append(kf.k8s(r, ts, arn, v, res, ns=r.choice(NS[:3]), ip=ip))
                if r.random() < 0.3:
                    out.append(kf.k8s(r, ts + 2000, arn, "get", "pods", ns="payments", name=f"api-{r.randint(1, 6)}",
                                      sub="log", ip=ip))
            if r.random() < 0.15:
                for j, res in enumerate(("pods", "services", "deployments", "replicasets", "statefulsets",
                                         "daemonsets", "jobs", "cronjobs", "horizontalpodautoscalers")):
                    out.append(kf.k8s(r, t0 + 50 * MIN + j * 300, arn, "list", res, ns="payments", ip=ip))
            if u in OPS and hour in (5, 9) and r.random() < 0.7:   # D1: routine ops exec
                ts = t0 + r.randint(0, 50) * MIN
                for st in ("RequestReceived", "ResponseComplete"):
                    out.append(kf.k8s(r, ts, arn, "create", "pods", ns="payments", name="db-0", sub="exec", code=101,
                                      ip=ip, stage=st, audit_id=f"ops-{u}-{day}-{hour}",
                                      uri="/api/v1/namespaces/payments/pods/db-0/exec?command=psql&container=db"
                                          "&stdin=true&stdout=true&tty=true"))
            if r.random() < 0.05:                            # an occasional forbidden request
                out.append(kf.k8s(r, t0 + r.randint(0, HOUR - 1), arn, "list", "secrets", ns="kube-system", ip=ip,
                                  code=403))
        for i in range(n(3)):                                # CI rollouts
            out.append(kf.k8s(r, t0 + r.randint(0, HOUR - 1), CI, "patch", "deployments", ns=r.choice(NS[:3]),
                              name=f"svc-{i}", ip=r.choice(CI_IPS), code=200, ua="kubectl/v1.30.2 (gha)"))
    if day == 1 and hour == 4:                               # D3: node-exporter with hostPID + /proc via CI
        ds = {"kind": "DaemonSet", "metadata": {"name": "node-exporter", "namespace": "monitoring"},
              "spec": {"template": {"spec": kf.pod_spec(image="quay.io/prometheus/node-exporter:v1.8.1", host_pid=True,
                                                        host_net=True, host_path="/proc")}}}
        out.append(kf.k8s(r, t0 + 10 * MIN, CI, "create", "daemonsets", ns="monitoring", name="node-exporter",
                          ip=CI_IPS[0], code=201, req=ds))
    return out


def aks_hour(seed: int, day: int, hour: int, scale: float) -> list[Ev]:
    r = sub_rng(seed, "aks", day, hour)
    t0 = START_MS + day * DAY + hour * HOUR
    out = [kf.k8s(r, t0 + r.randint(0, HOUR - 1), AKS_NODES[i % 3], "get", "configmaps", ns="default",
                  name="kube-root-ca.crt", ip=f"10.224.0.{4 + i % 3}", shape="aks") for i in range(max(1, int(8 * scale)))]
    out += [kf.k8s(r, t0 + i * 10 * MIN, "system:anonymous", "get", None, ip="10.224.0.250", uri="/readyz",
                   shape="aks", ua="Azure-LB-Probe/1.0") for i in range(6)]
    if business(hour) and day % 7 not in (5, 6):
        for u in ("pmehta", "asharma"):
            for _ in range(max(1, int(2 * scale))):
                out.append(kf.k8s(r, t0 + r.randint(0, HOUR - 1), f"{u}@corp.example", r.choice(("get", "list")),
                                  "pods", ns="default", ip=user_ip(sub_rng(seed, "ip", u, day), u), shape="aks"))
    return out


def gcp_hour(seed: int, day: int, hour: int, scale: float) -> list[Ev]:
    r = sub_rng(seed, "gcp", day, hour)
    t0 = START_MS + day * DAY + hour * HOUR
    out: list[Ev] = []
    weekday = day % 7 not in (5, 6)
    if business(hour) and weekday:
        for u in DATA:
            p, ip = f"{u}@corp.example", user_ip(sub_rng(seed, "ip", u, day), u)
            for _ in range(max(1, int(2 * scale))):           # BigQuery queries + table reads
                ts = t0 + r.randint(0, HOUR - 1)
                out.append(ks.gcp_ev(r, ts, PROJ_DATA, p, ip, "bigquery.googleapis.com",
                                     "google.cloud.bigquery.v2.JobService.InsertJob", f"projects/{PROJ_DATA}/jobs/q{r.hexs(8)}",
                                     log="data_access", metadata=ks.bq_job("QUERY", billed=r.randint(1, 40) * 1024 ** 3 // 8,
                                                                           tables=r.randint(1, 3))))
                out += [ks.table_read(r, ts + 3000 + j, p, ip, f"t{r.randint(0, 30)}") for j in range(r.randint(1, 3))]
            out.append(kf.gke(r, t0 + r.randint(0, HOUR - 1), PROJ_DATA, p, "io.k8s.core.v1.pods.list",
                              "core/v1/namespaces/analytics/pods", ip))
            if u == "dsingh" and hour == 6:                  # routine notebook exec + D6 VPC-SC ingress violation
                out.append(kf.gke(r, t0 + 20 * MIN, PROJ_DATA, p, "io.k8s.core.v1.pods.exec.create",
                                  "core/v1/namespaces/analytics/pods/jupyter-1/exec", ip))
                out.append(ks.vpcsc(r, t0 + 40 * MIN, p, home_ip(7), "corp-raw/objects/sample.csv", egress=False))
        if hour == 8:                                        # Cloud Build deploys (automation)
            out.append(ks.gcp_ev(r, t0 + 5 * MIN, PROJ_PROD, CLOUDBUILD, "10.130.0.5", "run.googleapis.com",
                                 "google.cloud.run.v1.Services.ReplaceService",
                                 f"projects/{PROJ_PROD}/locations/asia-south1/services/web",
                                 request={"service": {"spec": {"template": {"spec": {"serviceAccountName":
                                                                                      f"web@{PROJ_PROD}.iam.gserviceaccount.com"}}}}}))
    if hour == 20:                                           # D5: nightly ETL export to the corp bucket
        out.append(ks.gcp_ev(r, t0 + 15 * MIN, PROJ_DATA, ETL, "10.130.0.9", "bigquery.googleapis.com",
                             "google.cloud.bigquery.v2.JobService.InsertJob", f"projects/{PROJ_DATA}/jobs/etl{day}",
                             log="data_access", metadata=ks.bq_job("EXTRACT", dest=f"gs://corp-exports/d{day}/orders-*.avro")))
    for i in range(max(1, int(3 * scale))):                  # GKE control plane noise
        out.append(kf.gke(r, t0 + r.randint(0, HOUR - 1), PROJ_DATA,
                          "system:serviceaccount:kube-system:replicaset-controller", "io.k8s.core.v1.pods.create",
                          f"core/v1/namespaces/analytics/pods/w-{r.hexs(5)}", "10.20.0.2"))
    if day == 2 and hour == 7:                               # D4: GitHub Actions WIF provider with a condition
        out.append(ks.gcp_ev(r, t0 + 7 * MIN, PROJ_PROD, "asharma@corp.example", CORP_IPS[0], "iam.googleapis.com",
                             "google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPoolProvider",
                             f"projects/{PROJ_PROD}/locations/global/workloadIdentityPools/gh/providers/actions",
                             request={"workloadIdentityPoolProvider": {
                                 "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"},
                                 "attributeCondition": "assertion.repository_owner == 'corp-example'"}}))
        out.append(ks.gcp_ev(r, t0 + 9 * MIN, PROJ_PROD, "pmehta@corp.example", CORP_IPS[0], "run.googleapis.com",
                             "google.cloud.run.v1.Services.SetIamPolicy",
                             f"projects/{PROJ_PROD}/locations/asia-south1/services/web",
                             request={"policy": {"bindings": [{"role": "roles/run.invoker",
                                                               "members": ["group:qa@corp.example"]}]}}))
    return out


def net_hour(seed: int, day: int, hour: int, scale: float) -> list[Ev]:
    r = sub_rng(seed, "net", day, hour)
    t0 = START_MS + day * DAY + hour * HOUR
    out: list[Ev] = []
    for i in range(max(1, int(12 * scale))):                 # web -> db (both reporters), web -> partner API
        vm, ip = WEB[i % 2]
        ts = t0 + i * 5 * MIN + r.randint(0, 60_000)
        sp = r.randint(32768, 60999)
        out.append(kf.flow(r, ts, PROJ_PROD, ip, DB[1], 5432, src_vm=vm, dst_vm=DB[0], nbytes=r.randint(2000, 90000), sport=sp))
        out.append(kf.flow(r, ts, PROJ_PROD, ip, DB[1], 5432, src_vm=vm, dst_vm=DB[0], nbytes=r.randint(2000, 90000),
                           reporter="DEST", sport=sp))
        out.append(kf.flow(r, ts + 1000, PROJ_PROD, ip, "198.51.100.150", 443, src_vm=vm, nbytes=r.randint(900, 20000)))
        out.append(kf.dns(r, ts, PROJ_PROD, vm, ip, r.choice(("api.partner.example", "storage.googleapis.com",
                                                                "login.corp.example", "metadata.google.internal"))))
        out.append(kf.dns(r, ts + 500, PROJ_PROD, vm, ip, f"{r.hexs(32)}.cdn.partner.example"))      # D7
    if hour == 21:                                           # nightly backup to the partner vault
        out += [kf.flow(r, t0 + i * 60_000, PROJ_PROD, BACKUP[1], "198.51.100.160", 443, src_vm=BACKUP[0],
                        nbytes=r.randint(5, 20) * 1024 * 1024) for i in range(5)]
    if r.random() < 0.3:                                     # typo NXDOMAIN
        out.append(kf.dns(r, t0 + r.randint(0, HOUR - 1), PROJ_PROD, WEB[0][0], WEB[0][1], "api.partnr.example",
                          rcode="NXDOMAIN"))
    if business(hour) and day % 7 not in (5, 6) and hour == 4:   # admin SSH via the jump host
        out.append(kf.fw(r, t0 + 9 * MIN, PROJ_PROD, CORP_IPS[0], "10.128.0.5", 22, "jump-1", allowed=True,
                         rule="allow-ssh-corp"))
    for i in range(r.randint(0, 2)):                         # internet background: single-port probes
        out.append(kf.fw(r, t0 + r.randint(0, HOUR - 1), PROJ_PROD, f"198.51.100.{240 + r.randint(0, 9)}", WEB[i % 2][1],
                         r.choice((23, 3389, 445)), WEB[i % 2][0], allowed=False, rule="default-deny-ingress"))
    return out


def generate(out: Path, seed: int, days: int, scale: float) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    stories = ks.build_stories(seed)
    fixed = [e for s in stories for e in s.events()]
    parts: dict[str, list[dict]] = {}
    handles: dict[str, tuple] = {}
    counts = {"events": 0, "bytes": 0}

    def write(ev: Ev) -> None:
        d = FEED_DIR[ev.feed]
        line = json.dumps(ev.doc, ensure_ascii=False) + "\n"
        b = len(line.encode("utf-8"))
        cur = handles.get(d)
        if cur is None or cur[1] + b > MAX_PART_BYTES:
            if cur:
                cur[0].close()
            n = len(parts.setdefault(d, [])) + 1
            p = out / d / f"part-{n:04d}.jsonl"
            p.parent.mkdir(parents=True, exist_ok=True)
            parts[d].append({"file": p.relative_to(out).as_posix(), "events": 0, "bytes": 0})
            cur = (p.open("w", encoding="utf-8", newline="\n"), 0)
        cur[0].write(line)
        handles[d] = (cur[0], cur[1] + b)
        parts[d][-1]["events"] += 1
        parts[d][-1]["bytes"] += b
        counts["events"] += 1
        counts["bytes"] += b

    for day in range(days):                                  # one day in memory at a time (bounded)
        evs = [e for e in fixed if START_MS + day * DAY <= e.ts < START_MS + (day + 1) * DAY]
        for hour in range(24):
            for fn in (k8s_hour, aks_hour, gcp_hour, net_hour):
                evs += fn(seed, day, hour, scale)
        for ev in sorted(evs, key=lambda e: (e.ts, e.feed, e.rid)):
            write(ev)
    for h, _ in handles.values():
        h.close()
    gt = {"attack_version": "v20", "anchor_ms": START_MS, "anchor": iso_s(START_MS),
          "generated_by": "tools/cloud_attacks/gen_k8s_and_gcp.py", "seed": seed, "days": days, "scale": scale,
          "note": "Synthetic. Attacker IPs 203.0.113.0/24 only (RFC 5737); domains *.example.",
          "attacks": [s.gt() for s in stories],
          "decoys": [{"id": i, "why": w, "recurring": True} for i, w in ks.DECOYS]}
    (out / "ground_truth").mkdir(exist_ok=True)
    (out / "ground_truth" / "attacks.json").write_text(json.dumps(gt, indent=1), encoding="utf-8")
    man = {"generator": "tools/cloud_attacks/gen_k8s_and_gcp.py", "seed": seed, "days": days, "scale": scale,
           "start": iso_s(START_MS), "end": iso_s(START_MS + days * DAY), "total_events": counts["events"],
           "total_bytes": counts["bytes"], "parts": [p for d in sorted(parts) for p in parts[d]]}
    (out / "manifest.json").write_text(json.dumps(man, indent=1), encoding="utf-8")
    return man


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--scale", type=float, default=1.0)
    a = ap.parse_args(argv)
    if a.days < 7:
        raise SystemExit("--days must be >= 7 (the attack stories run on days 4-6)")
    man = generate(Path(a.out), a.seed, a.days, a.scale)
    sys.stdout.write(f"{man['total_events']} events, {man['total_bytes']} bytes -> {a.out}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
