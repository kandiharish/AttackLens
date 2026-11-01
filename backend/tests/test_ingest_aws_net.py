"""AWS network + findings ingest (config/sources.yaml aws_vpcflow_json / aws_r53resolver_json / aws_nfw_json /
aws_guardduty_json / aws_securityhub_json, and the Identity Center outcome / action aliases of cloudtrail_json).
Fixtures are made up (fixtures/cloud_aws/*.jsonl), one file per shape, copied under neutral names: routing is by
content (keys), never by file name. Every shape: rows in == rows ok, nothing dropped, fields mapped."""

from __future__ import annotations

import shutil

import pytest

from .conftest import FIXTURES, accounting, query, run_ingest

FX = FIXTURES / "cloud_aws"
T0 = 1792807200000  # 2026-10-24T02:00:00Z
FILES = {"vpcflow_hyphen.jsonl": ("aws_vpcflow_json", 3), "vpcflow_underscore.jsonl": ("aws_vpcflow_json", 1),
         "vpcflow_sentinel.jsonl": ("aws_vpcflow_json", 1), "r53.jsonl": ("aws_r53resolver_json", 3),
         "nfw.jsonl": ("aws_nfw_json", 3), "guardduty.jsonl": ("aws_guardduty_json", 2),
         "securityhub.jsonl": ("aws_securityhub_json", 2), "cloudtrail_sso.jsonl": ("cloudtrail_json", 3)}


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("aws_net")
    raw = tmp / "raw"
    raw.mkdir()
    for i, name in enumerate(FILES):
        shutil.copy(FX / name, raw / f"part-{i}.log")
    c = run_ingest(raw, tmp)
    yield c
    c.con.close()


def rows(ctx, stype: str) -> list[dict]:
    return query(ctx, "SELECT * FROM events WHERE source_type = ? ORDER BY ts_ms, source_seq", [stype])


def test_every_shape_routed_and_fully_accounted(ctx) -> None:
    prof = {f["rel"]: f.get("source_type") for f in ctx.stats["profile"]["files"]}
    assert prof == {f"part-{i}.log": FILES[n][0] for i, n in enumerate(FILES)}
    acc = {k: v for k, v in accounting(ctx).items() if v["rows_in"]}
    want: dict[str, int] = {}
    for stype, n in FILES.values():
        want[stype] = want.get(stype, 0) + n
    assert set(acc) == set(want)
    for stype, n in want.items():
        assert acc[stype]["rows_in"] == acc[stype]["rows_ok"] == n and acc[stype]["dropped"] == 0, (stype, acc[stype])


def test_vpcflow_three_shapes(ctx) -> None:
    r = rows(ctx, "aws_vpcflow_json")
    assert [x["ts_ms"] for x in r] == [T0, T0 + 1000, T0 + 2000, T0 + 3000, T0 + 4000]
    egress, nat, nodata, under, sent = r
    assert (egress["host"], egress["src_ip"], egress["dst_ip"], egress["src_port"], egress["dst_port"],
            egress["bytes_out"], egress["action"], egress["outcome"], egress["app"]) == \
        ("i-0abc1234def567890", "10.0.1.12", "203.0.113.80", 49812, 443, 30000000, "conn_allowed", "success", "6")
    # no instance -> the ENI is the host; pkt-dstaddr (behind the NAT) wins over dstaddr; REJECT -> conn_denied
    assert (nat["host"], nat["dst_ip"], nat["action"], nat["outcome"]) == \
        ("eni-0nat00001", "10.0.2.21", "conn_denied", "failure")
    # NODATA: kept with its window start, no addresses, signature = log-status
    assert (nodata["src_ip"], nodata["dst_ip"], nodata["action"], nodata["signature"], nodata["bytes_out"]) == \
        (None, None, "other", "NODATA", None)
    assert (under["host"], under["dst_port"], under["action"]) == ("i-0build0000000000b", 3333, "conn_allowed")
    assert (sent["host"], sent["src_ip"], sent["dst_ip"], sent["bytes_out"], sent["action"]) == \
        ("i-0db1000000000000c", "10.0.3.31", "198.51.100.160", 31000000, "conn_allowed")


def test_route53_resolver(ctx) -> None:
    a, txt, nx = rows(ctx, "aws_r53resolver_json")
    assert a["ts_ms"] == T0 + 5120
    assert (a["host"], a["host_ip"], a["src_ip"], a["dst_domain"], a["dst_ip"], a["action"], a["outcome"],
            a["signature"]) == ("i-0abc1234def567890", "10.0.1.12", "10.0.1.12", "api.partner.example",
                                "198.51.100.180", "dns_query", "success", "A")
    assert (txt["signature"], txt["app"], txt["dst_ip"], txt["dst_domain"]) == \
        ("TXT", "alert", None, "mfzwizltoq2dsnjsgy3tsojrgi2dk.t.cdn-sync.example")
    assert (nx["outcome"], nx["action"]) == ("failure", "dns_query")


def test_network_firewall(ctx) -> None:
    flow, alert, tls = rows(ctx, "aws_nfw_json")
    assert flow["ts_ms"] == T0 + 8250                 # "+0000" offset without a colon, microseconds -> ms
    assert (flow["host"], flow["action"], flow["src_ip"], flow["dst_ip"], flow["dst_port"], flow["bytes_out"],
            flow["app"]) == ("prod-egress-fw", "conn_allowed", "10.0.1.5", "203.0.113.71", 8443, 1200, "tls")
    assert (alert["action"], alert["outcome"], alert["signature"], alert["vendor_severity"]) == \
        ("ips_alert", "blocked", "ET MALWARE Cobalt Strike Beacon Observed", "1")
    assert (tls["action"], tls["dst_domain"]) == ("web_access", "api.partner.example")


def test_findings_are_context_rows(ctx) -> None:
    gd, eb = rows(ctx, "aws_guardduty_json")
    assert (gd["ts_ms"], gd["host"], gd["host_ip"], gd["signature"], gd["vendor_severity"], gd["action"]) == \
        (T0 + 11000, "i-0abc1234def567890", "10.0.1.12", "Recon:EC2/Portscan", "5.0", "other")
    assert (eb["host"], eb["src_user"], eb["src_ip"], eb["signature"]) == \
        ("111122223333", "web-app-role", "203.0.113.50",
         "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS")
    asff, wrapped = rows(ctx, "aws_securityhub_json")
    assert (asff["host"], asff["src_ip"], asff["vendor_severity"], asff["app"]) == \
        ("i-0abc1234def567890", "203.0.113.50", "high", "guardduty")
    assert wrapped["ts_ok"] and wrapped["host"] == "111122223333"   # EventBridge detail.findings[] document


def test_identity_center_outcome_and_actions(ctx) -> None:
    fail, chal, auth = rows(ctx, "cloudtrail_json")
    assert (fail["action"], fail["outcome"], fail["target_user"], fail["src_ip"]) == \
        ("login_failed", "failure", "lfernandes", "203.0.113.30")
    assert (chal["action"], chal["outcome"], chal["src_user"]) == ("other", "success", "lfernandes")
    assert (auth["action"], auth["outcome"], auth["target_user"]) == ("login_success", "success", "lfernandes")


def test_generator_labels_never_mapped() -> None:
    from attacklens.config import load_config
    src = load_config()["sources"]["json_sources"]
    for name in ("aws_vpcflow_json", "aws_r53resolver_json", "aws_nfw_json", "aws_guardduty_json",
                 "aws_securityhub_json"):
        paths = [p for v in src[name]["fields"].values() for p in v]
        assert not [p for p in paths if p.split(".")[1].strip('"') in ("threat", "rule", "labels", "labels_extra")
                    or p.startswith(("$.event.kind", "$.event.severity", "$.event.module", "$.event.dataset"))], name
