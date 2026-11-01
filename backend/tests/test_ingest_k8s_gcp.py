"""Kubernetes audit + GCP network / DNS / SCC ingest (config/sources.yaml k8s_audit_json, gcp_firewall_json,
gcp_vpcflow_json, gcp_dns_json, gcp_scc_json; GKE audit stays gcp_audit_json). One fixture file per shape variant,
copied under neutral names: routing is by content (keys), never by file name. Every row in is a row ok."""

from __future__ import annotations

import json
import shutil

import pytest

from .conftest import FIXTURES, accounting, query, run_ingest

FX = FIXTURES / "cloud" / "k8s_gcp"
T0 = 1792807200000  # 2026-10-24T02:00:00Z
FILES = {"k8s_audit_generic.jsonl": ("k8s_audit_json", 4), "k8s_aksaudit.jsonl": ("k8s_audit_json", 2),
         "gcp_gke_audit.jsonl": ("gcp_audit_json", 1), "gcp_vpcflow.jsonl": ("gcp_vpcflow_json", 2),
         "gcp_vpcflow_la.jsonl": ("gcp_vpcflow_json", 1), "gcp_firewall.jsonl": ("gcp_firewall_json", 2),
         "gcp_dns.jsonl": ("gcp_dns_json", 2), "gcp_dns_snake.jsonl": ("gcp_dns_json", 1),
         "gcp_scc.jsonl": ("gcp_scc_json", 2)}


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("k8sgcp")
    raw = tmp / "raw"
    raw.mkdir()
    for i, name in enumerate(FILES):
        shutil.copy(FX / name, raw / f"part-{i}.log")
    c = run_ingest(raw, tmp)
    yield c
    c.con.close()


def rows(ctx, stype: str) -> list[dict]:
    return query(ctx, "SELECT * FROM events WHERE source_type = ? ORDER BY ts_ms, source_seq", [stype])


def test_routed_by_content_and_fully_accounted(ctx) -> None:
    prof = json.loads((ctx.out_dir / "source_profile.json").read_text(encoding="utf-8"))
    routed = {f["rel"]: f.get("source_type") for f in prof["files"]}
    for i, (name, (stype, _)) in enumerate(FILES.items()):
        assert routed[f"part-{i}.log"] == stype, name
    want: dict[str, int] = {}
    for stype, n in FILES.values():
        want[stype] = want.get(stype, 0) + n
    acc = {k: v for k, v in accounting(ctx).items() if v["rows_in"]}
    assert set(acc) == set(want)
    for stype, n in want.items():
        assert acc[stype]["rows_in"] == acc[stype]["rows_ok"] == n, (stype, acc[stype])
        assert acc[stype]["dropped"] == 0
        assert all(r["ts_ok"] for r in rows(ctx, stype)), stype


def test_k8s_generic_and_eks_mapping(ctx) -> None:
    r = [x for x in rows(ctx, "k8s_audit_json") if x["host"] == "prod-eks-1"]
    assert len(r) == 4
    first2 = sorted(r[:2], key=lambda x: x["outcome"] is not None)
    recv, done, forbid, crb = *first2, r[2], r[3]
    assert recv["ts_ms"] == done["ts_ms"] == T0           # requestReceivedTimestamp, not the stage time
    assert '"RequestReceived"' in recv["raw_line"] and recv["outcome"] is None   # no response yet
    assert (done["src_user"], done["src_ip"], done["signature"], done["app"], done["outcome"]) == \
        ("alice", "203.0.113.50", "create", "pods", "success")       # 101 Switching Protocols = exec opened
    assert done["file_path"].startswith("/api/v1/namespaces/payments/pods/api-7f9c/exec")
    assert (forbid["src_user"], forbid["outcome"], forbid["app"]) == \
        ("system:serviceaccount:payments:api", "failure", "secrets")
    # EKS access-entry session ARN -> session name; log group -> cluster; first sourceIP; impersonated -> target
    assert (crb["src_user"], crb["host"], crb["src_ip"], crb["target_user"], crb["outcome"]) == \
        ("bob", "prod-eks-1", "198.51.100.23", "ops-bot", "success")


def test_k8s_aksaudit_mapping(ctx) -> None:
    tok, anon = [x for x in rows(ctx, "k8s_audit_json") if x["host"] == "aks-prod-2"]
    assert tok["ts_ms"] == T0 + 3000 and anon["ts_ms"] == T0 + 4000   # RequestReceivedTime, not TimeGenerated
    assert (tok["src_user"], tok["src_ip"], tok["signature"], tok["app"], tok["outcome"]) == \
        ("masterclient", "203.0.113.51", "create", "serviceaccounts", "success")
    assert (anon["src_user"], anon["signature"], anon["outcome"]) == ("system:anonymous", "list", "success")


def test_gke_audit_stays_gcp_audit(ctx) -> None:
    (g,) = rows(ctx, "gcp_audit_json")
    assert (g["host"], g["src_user"], g["src_ip"], g["signature"], g["app"], g["outcome"]) == \
        ("corp-prod-1234", "carol", "203.0.113.53", "io.k8s.core.v1.pods.exec.create", "k8s.io", "success")


def test_vpcflow_both_shapes(ctx) -> None:
    egress, ingress, la = _flows(ctx)
    assert (egress["host"], egress["src_ip"], egress["dst_ip"], egress["dst_port"], egress["bytes_out"],
            egress["action"]) == ("db-backup-1", "10.128.0.21", "203.0.113.60", 443, 734003200, "conn_allowed")
    assert egress["ts_ms"] == T0 + 6000                     # start_time, not the LogEntry timestamp
    assert (ingress["host"], ingress["src_ip"], ingress["dst_port"], ingress["action"]) == \
        ("db-backup-1", "203.0.113.61", 22, "conn_allowed")  # ingress from outside: host = dest VM
    assert (la["host"], la["src_ip"], la["dst_ip"], la["dst_port"], la["ts_ms"]) == \
        ("web-2", "10.128.0.22", "10.128.0.21", 5432, T0 + 8000)


def _flows(ctx) -> tuple[dict, dict, dict]:
    r = {x["src_ip"]: x for x in rows(ctx, "gcp_vpcflow_json")}
    return r["10.128.0.21"], r["203.0.113.61"], r["10.128.0.22"]


def test_firewall_mapping(ctx) -> None:
    deny, allow = rows(ctx, "gcp_firewall_json")
    assert (deny["action"], deny["host"], deny["src_ip"], deny["dst_ip"], deny["dst_port"], deny["signature"]) == \
        ("conn_denied", "db-backup-1", "203.0.113.62", "10.128.0.21", 3389, "network:prod-vpc/firewall:default-deny-ingress")
    assert (allow["action"], allow["dst_port"]) == ("conn_allowed", 22)


def test_dns_both_namings(ctx) -> None:
    tun, ok, snake = rows(ctx, "gcp_dns_json")
    assert (tun["action"], tun["host"], tun["src_ip"], tun["dst_domain"], tun["signature"], tun["outcome"]) == \
        ("dns_query", "db-backup-1", "10.128.0.21", "agvsbg8gd29ybgqgdghpcybpcybkyxrh.t1.exfil-cdn.example", "TXT",
         "failure")
    assert (ok["host"], ok["dst_domain"], ok["outcome"]) == ("web-2", "storage.googleapis.com", "success")
    assert (snake["action"], snake["host"], snake["src_ip"], snake["dst_domain"]) == \
        ("dns_query", "jump-1", "10.128.0.23", "login.corp.example")


def test_scc_context_rows(ctx) -> None:
    grant, miner = rows(ctx, "gcp_scc_json")
    assert (grant["host"], grant["src_user"], grant["src_ip"], grant["signature"], grant["action"]) == \
        ("corp-prod-1234", "mallory", "203.0.113.70", "Persistence: IAM Anomalous Grant", "other")
    assert grant["ts_ms"] == T0 + 16000 and miner["host"] == "corp-prod-1234"
