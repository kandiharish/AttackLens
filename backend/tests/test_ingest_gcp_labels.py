"""P0-4 (reports/cloud/log_coverage.md): GCP / GKE LogEntry `labels` vs generator label stripping.

- Generator labels (threat, rule, labels, labels_extra, event.kind / event.severity ...) are ground truth: they must be
  absent from raw_line for EVERY source, including the GCP / Kubernetes ones (always true).
- Vendor LogEntry labels (authorization.k8s.io/decision, ...) are evidence: with sources.yaml `keep_labels` they come
  back as raw_line.log_labels, ONLY for the allow-listed keys and ONLY on LogEntry-shaped rows. That needs the
  ingest_sql.py patch reports/cloud/patches/k8s_and_gcp-ingest_sql.diff (ingest_sql.py is owned by another session),
  so test_gcp_vendor_labels_kept is xfail until the patch is applied.
"""

from __future__ import annotations

import json

import pytest

from .conftest import query, run_ingest

GEN = {"synthetic": "true", "simulated_detection": "true", "technique": "T1609"}   # generator-style label values


def _write(raw, name: str, recs: list[dict]) -> None:
    (raw / name).write_text("\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("labels")
    raw = tmp / "raw"
    raw.mkdir()
    ts = "2026-10-24T02:00:00Z"
    _write(raw, "ecs.log", [{"@timestamp": ts, "event": {"action": "process_started", "kind": "alert", "severity": 9},
                             "host": {"name": "ws-1"}, "threat": {"technique": "T1059"}, "rule": {"name": "x"},
                             "labels": GEN, "labels_extra": {"n": 3}}])
    _write(raw, "gke.log", [{"protoPayload": {"methodName": "io.k8s.core.v1.pods.exec.create", "serviceName": "k8s.io",
                                              "authenticationInfo": {"principalEmail": "carol@corp.example"},
                                              "resourceName": "core/v1/namespaces/shop/pods/p/exec"},
                             "resource": {"type": "k8s_cluster", "labels": {"project_id": "corp-prod-1234",
                                                                            "cluster_name": "gke-1"}},
                             "timestamp": ts, "threat": "T1609", "labels_extra": {"x": 1},
                             "labels": {**GEN, "authorization.k8s.io/decision": "allow",
                                        "authorization.k8s.io/reason": "access granted by IAM permissions."}}])
    _write(raw, "k8s.log", [{"auditID": "a1", "stage": "ResponseComplete", "verb": "get", "rule": "r", "labels": GEN,
                             "user": {"username": "alice"}, "requestReceivedTimestamp": ts, "cluster_name": "c1",
                             "objectRef": {"resource": "pods", "namespace": "d", "name": "p"},
                             "responseStatus": {"code": 200}}])
    _write(raw, "flow.log", [{"jsonPayload": {"reporter": "SRC", "start_time": ts, "bytes_sent": "1",
                                              "connection": {"src_ip": "10.0.0.1", "dest_ip": "10.0.0.2"}},
                              "timestamp": ts, "labels": GEN, "threat": "T1046"}])
    c = run_ingest(raw, tmp)
    yield c
    c.con.close()


def _rows(ctx) -> dict[str, dict]:
    return {r["source_type"]: json.loads(r["raw_line"])
            for r in query(ctx, "SELECT source_type, raw_line FROM events ORDER BY source_type")}


def test_generator_labels_stripped_for_every_source(ctx) -> None:
    rows = _rows(ctx)
    assert set(rows) == {"ecs_json", "gcp_audit_json", "k8s_audit_json", "gcp_vpcflow_json"}
    for stype, doc in rows.items():
        assert not {"threat", "rule", "labels", "labels_extra"} & set(doc), stype
        text = json.dumps(doc)
        assert "simulated_detection" not in text and '"synthetic"' not in text and "T1609" not in text.replace(
            "io.k8s", ""), stype
        if "event" in doc:
            assert "kind" not in doc["event"] and "severity" not in doc["event"]


@pytest.mark.xfail(reason="needs reports/cloud/patches/k8s_and_gcp-ingest_sql.diff (ingest_sql.py keep_labels)",
                   strict=False)
def test_gcp_vendor_labels_kept(ctx) -> None:
    gke = _rows(ctx)["gcp_audit_json"]
    assert gke["log_labels"] == {"authorization.k8s.io/decision": "allow",
                                 "authorization.k8s.io/reason": "access granted by IAM permissions."}
