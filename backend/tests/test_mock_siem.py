"""tools/mock_siem.py is test infrastructure: if it is generous, every connector test passes for the wrong reason.
These pin its vendor semantics on a 9-event hand-checked fixture (exact markers, orders, totals, status codes)."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import mock_siem as ms  # noqa: E402
from mock_siem_store import iso_ms  # noqa: E402

T0 = 1792807200000  # 2026-10-24T02:00:00Z
S = 1000
LABELS = {"threat": {"technique": {"id": ["T1059.001"]}, "tactic": {"name": ["Execution"]}},
          "rule": {"name": "x"}, "labels": {"attack": "yes"}, "labels_extra": {"failed_count_5min": 60}}


def ecs(n: int, ts_ms: int, labelled: bool = False) -> dict[str, Any]:
    ev: dict[str, Any] = {"@timestamp": iso_ms(ts_ms), "event": {"action": "process_created", "kind": "event",
                                                                 "severity": 0, "id": f"evt-{n:04d}"},
                          "host": {"name": f"WS-FIN-{n:03d}"}, "user": {"name": "pmehta"},
                          "process": {"name": "cmd.exe", "command_line": f"cmd.exe /c marker evt-{n:04d}"}}
    if labelled:
        ev.update(LABELS)
        ev["event"].update(kind="alert", severity=73)
    return ev


# E0 t0, E1 +1s, E2/E3/E4 +2s (a.jsonl), E6 +2s (b.jsonl, tie across files), E5 +3s, E7 +4s, E8 +5s (labelled)
FIXTURE_TS = {0: 0, 1: 1, 2: 2, 3: 2, 4: 2, 5: 3, 6: 2, 7: 4, 8: 5}
ALL = {f"evt-{n:04d}" for n in FIXTURE_TS}


def write_fixture(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    a = [ecs(n, T0 + FIXTURE_TS[n] * S) for n in (0, 1, 2, 3, 4, 5)]
    b = [ecs(6, T0 + 2 * S), ecs(7, T0 + 4 * S), ecs(8, T0 + 5 * S, labelled=True)]
    (root / "a.jsonl").write_bytes(b"\xef\xbb\xbf" + b"\r\n".join(json.dumps(e).encode() for e in a) + b"\r\n")
    (root / "b.jsonl").write_text("\n".join(json.dumps(e) for e in b[:2]) + '\n{"half": \n'
                                  + json.dumps(b[2]) + "\n", encoding="utf-8")
    (root / "ground_truth").mkdir(exist_ok=True)
    (root / "ground_truth" / "attacks.jsonl").write_text(json.dumps(ecs(99, T0)) + "\n", encoding="utf-8")
    (root / "manifest.json").write_text(json.dumps(ecs(98, T0)), encoding="utf-8")
    return root


def http(method: str, url: str, body: Any = None, headers: dict[str, str] | None = None,
         timeout: float = 5.0) -> tuple[int, bytes]:
    data = body if isinstance(body, bytes) or body is None else (
        urllib.parse.urlencode(body).encode() if isinstance(body, dict) and (headers or {}).get(
            "Content-Type") == "application/x-www-form-urlencoded" else json.dumps(body).encode())
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json",
                                                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def jhttp(method: str, url: str, body: Any = None, **kw: Any) -> tuple[int, Any]:
    st, raw = http(method, url, body, **kw)
    return st, json.loads(raw) if raw.strip() else None


def marker(doc: dict | str) -> str:
    text = doc if isinstance(doc, str) else json.dumps(doc)
    return text.split("marker ")[1][:8]


@pytest.fixture
def mock(tmp_path: Path):
    with ms.MockSIEM(write_fixture(tmp_path / "raw"), now_ms=lambda: T0 + 3_600_000) as m:
        yield m


# ============================================================================= Elastic
def es_page(m, after=None, size=2, sort=None, query=None):
    body: dict[str, Any] = {"size": size, "sort": sort or [{"@timestamp": "asc"}, {"_id": "asc"}]}
    if after is not None:
        body["search_after"] = after
    if query is not None:
        body["query"] = query
    return jhttp("POST", f"{m.url}/logs-*/_search", body)


def es_drain(m, **kw) -> list[str]:
    out, after = [], None
    for _ in range(50):
        st, r = es_page(m, after, **kw)
        assert st == 200, r
        hits = r["hits"]["hits"]
        if not hits:
            return out
        out += [marker(h["_source"]) for h in hits]
        after = hits[-1]["sort"]
    raise AssertionError("pagination did not terminate")


def test_es_search_after_with_tiebreaker_returns_each_event_once_in_order(mock) -> None:
    got = es_drain(mock)
    assert sorted(got) == sorted(ALL) and len(got) == 9                    # malformed, GT, manifest not served
    assert [FIXTURE_TS[int(g[4:])] for g in got] == [0, 1, 2, 2, 2, 2, 3, 4, 5]


def test_es_search_after_on_timestamp_only_skips_rest_of_tie_like_elasticsearch(mock) -> None:
    got = es_drain(mock, sort=[{"@timestamp": "asc"}])
    assert len(got) == 7 and ALL - set(got) == {"evt-0004", "evt-0006"}   # the trap a connector must avoid


def test_es_hit_shape_sort_values_and_total(mock) -> None:
    st, r = es_page(mock, size=3)
    assert st == 200 and r["hits"]["total"] == {"value": 9, "relation": "eq"}
    h = r["hits"]["hits"][0]
    assert h["sort"][0] == T0 and isinstance(h["_id"], str) and h["_index"] == ms.EVENTS_INDEX_NAME
    assert h["_source"]["event"] == {"action": "process_created", "id": "evt-0000"}


def test_es_range_bounds_inclusive_exclusive(mock) -> None:
    q = {"bool": {"filter": [{"range": {"@timestamp": {"gte": iso_ms(T0 + S), "lt": T0 + 3 * S,
                                                       "format": "strict_date_optional_time||epoch_millis"}}}]}}
    got = es_drain(mock, query=q)
    assert sorted(got) == ["evt-0001", "evt-0002", "evt-0003", "evt-0004", "evt-0006"]
    st, r = es_page(mock, query={"range": {"@timestamp": {"gt": "now-1h"}}})   # now = T0 + 1 h
    assert r["hits"]["total"]["value"] == 8                                     # E0 at exactly now-1h excluded


def test_es_term_query_on_nested_field(mock) -> None:
    st, r = es_page(mock, size=10, query={"term": {"host.name": "WS-FIN-007"}})
    assert st == 200 and [marker(h["_source"]) for h in r["hits"]["hits"]] == ["evt-0007"]


def test_es_strips_generator_labels(mock) -> None:
    st, r = es_page(mock, size=10)
    e8 = next(h["_source"] for h in r["hits"]["hits"] if "evt-0008" in json.dumps(h["_source"]))
    assert not {"threat", "rule", "labels", "labels_extra"} & set(e8)
    assert e8["event"] == {"action": "process_created", "id": "evt-0008"}       # kind + severity gone


@pytest.mark.parametrize("body,needle", [
    ({"size": 10001}, "Result window is too large"),
    ({"from": 9995, "size": 10}, "Result window is too large"),
    ({"sort": [{"@timestamp": "asc"}], "search_after": [T0, "x"]}, "search_after has 2 value(s) but sort has 1"),
    ({"search_after": [T0]}, "Sort must contain at least one field"),
    ({"from": 2, "sort": ["@timestamp"], "search_after": [T0]}, "[from] parameter must be set to 0"),
    ({"query": {"query_string": {"query": "*"}}}, "unsupported query type [query_string]"),
])
def test_es_rejects_what_elasticsearch_rejects(mock, body, needle) -> None:
    st, r = jhttp("POST", f"{mock.url}/logs-*/_search", body)
    assert st == 400 and needle in r["error"]["reason"]


def test_es_auth(tmp_path: Path) -> None:
    with ms.MockSIEM(write_fixture(tmp_path / "raw"), elastic_api_key="k1") as m:
        assert http("POST", f"{m.url}/logs-*/_search", {})[0] == 401
        assert http("POST", f"{m.url}/logs-*/_search", {}, headers={"Authorization": "ApiKey nope"})[0] == 401
        st, r = jhttp("POST", f"{m.url}/logs-*/_search", {}, headers={"Authorization": "ApiKey k1"})
        assert st == 200 and r["hits"]["total"]["value"] == 9


def test_es_alerts_index_serves_fixture_with_vendor_mitre(mock) -> None:
    st, r = jhttp("POST", f"{mock.url}/{ms.ELASTIC_ALERTS_INDEX}/_search",
                  {"size": 100, "sort": [{"@timestamp": "asc"}]})
    hits = [h["_source"] for h in r["hits"]["hits"]]
    assert st == 200 and [h["kibana.alert.uuid"] for h in hits] == [f"mock-alert-A{i}" for i in range(1, 8)]
    a1 = hits[0]["kibana.alert.rule.threat"][0]
    assert (a1["tactic"]["id"], a1["technique"][0]["id"], a1["technique"][0]["subtechnique"][0]["id"]) == \
        ("TA0006", "T1110", "T1110.001")
    assert hits[5]["kibana.alert.rule.threat"][0]["tactic"]["name"] == "Defense Evasion"   # pre-v20 vendor name
    assert hits[6]["kibana.alert.rule.threat"] == []                                       # A7: no MITRE


def test_es_appended_file_is_visible_on_next_query(mock, tmp_path: Path) -> None:
    assert len(es_drain(mock)) == 9
    (tmp_path / "raw" / "c.jsonl").write_text(json.dumps(ecs(10, T0 + 9 * S)) + "\n", encoding="utf-8")
    assert es_drain(mock)[-1] == "evt-0010"


# ============================================================================= Elastic _bulk receiver
def bulk(m, lines: list[dict], index: str | None = None, terminate: bool = True, ctype="application/x-ndjson"):
    body = "\n".join(json.dumps(x) for x in lines) + ("\n" if terminate else "")
    path = f"/{index}/_bulk" if index else "/_bulk"
    return jhttp("POST", m.url + path, body.encode(), headers={"Content-Type": ctype})


def test_bulk_index_is_idempotent_by_id_and_create_conflicts(mock) -> None:
    doc = {"id": "inc-0000aaaa", "risk": 80, "first_ts": "2026-10-24T02:00:00Z"}
    for _ in range(2):
        st, r = bulk(mock, [{"index": {"_index": "attacklens-incidents", "_id": "inc-0000aaaa"}}, doc])
        assert st == 200 and r["errors"] is False
    assert r["items"][0]["index"]["result"] == "updated" and r["items"][0]["index"]["_version"] == 2
    assert list(mock.indexed) == [("attacklens-incidents", "inc-0000aaaa")] and len(mock.received["bulk"]) == 2
    st, r = bulk(mock, [{"create": {"_id": "inc-0000aaaa"}}, doc], index="attacklens-incidents")
    assert r["errors"] is True and r["items"][0]["create"]["status"] == 409
    st, r = jhttp("GET", f"{mock.url}/attacklens-incidents/_doc/inc-0000aaaa")
    assert st == 200 and r["_source"] == doc and r["_version"] == 2
    st, r = jhttp("POST", f"{mock.url}/attacklens-incidents/_search", {"size": 10})
    assert [h["_id"] for h in r["hits"]["hits"]] == ["inc-0000aaaa"]


def test_bulk_rejects_unterminated_body_and_wrong_content_type(mock) -> None:
    line = [{"index": {"_index": "x", "_id": "1"}}, {"a": 1}]
    assert bulk(mock, line, terminate=False)[0] == 400
    assert bulk(mock, line, ctype="text/plain")[0] == 406
    assert mock.indexed == {}


# ============================================================================= Splunk
def spl(m, search: str, token: str | None = None, **params: str) -> tuple[int, list[dict]]:
    hdr = {"Content-Type": "application/x-www-form-urlencoded"}
    if token:
        hdr["Authorization"] = f"Bearer {token}"
    st, raw = http("POST", f"{m.url}/services/search/jobs/export",
                   {"search": search, "output_mode": "json", **params}, headers=hdr)
    if st != 200:
        return st, [json.loads(raw)]
    return st, [json.loads(ln) for ln in raw.splitlines() if ln.strip()]


def test_splunk_export_newest_first_by_default(mock) -> None:
    st, rows = spl(mock, "search index=main")
    assert st == 200 and len(rows) == 9 and [r["offset"] for r in rows] == list(range(9))
    assert all(r["preview"] is False for r in rows)
    assert [marker(r["result"]["_raw"]) for r in rows][:2] == ["evt-0008", "evt-0007"]
    r8 = rows[0]["result"]
    assert r8["_time"] == "2026-10-24T02:00:05.000+00:00" and r8["host"] == "WS-FIN-008"
    assert '"threat"' not in r8["_raw"] and "labels" not in r8["_raw"] and '"kind"' not in r8["_raw"]
    assert len({r["result"]["_cd"] for r in rows}) == 9


def test_splunk_export_ascending_and_time_bounds(mock) -> None:
    st, rows = spl(mock, "search index=main | sort 0 _time", earliest_time=str((T0 + 2 * S) / 1000),
                   latest_time=iso_ms(T0 + 4 * S))
    got = [marker(r["result"]["_raw"]) for r in rows]
    assert got == ["evt-0002", "evt-0003", "evt-0004", "evt-0006", "evt-0005"]  # earliest incl., latest excl.
    st, rows = spl(mock, "search index=main earliest=-1h | reverse | head 2")       # now = T0 + 1 h
    assert [marker(r["result"]["_raw"]) for r in rows] == ["evt-0000", "evt-0001"]


def test_splunk_rejects_search_without_command_and_bad_auth(tmp_path: Path) -> None:
    with ms.MockSIEM(write_fixture(tmp_path / "raw"), splunk_token="s1") as m:
        assert spl(m, "search index=main")[0] == 401
        assert spl(m, "search index=main", token="wrong")[0] == 401
        st, err = spl(m, "index=main", token="s1")
        assert st == 400 and "Unknown search command 'index'" in err[0]["error"]["reason"]
        assert spl(m, "search index=main", token="s1")[0] == 200


def test_splunk_notables_carry_mitre_annotations(mock) -> None:
    st, rows = spl(mock, "search index=notable | sort 0 _time")
    res = [r["result"] for r in rows]
    assert [r["event_id"] for r in res] == [f"mock-notable-A{i}" for i in range(1, 8)]
    assert res[0]["annotations.mitre_attack"] == ["T1110", "T1110.001"]
    assert res[0]["annotations.mitre_attack.mitre_tactic"] == ["credential-access"]
    assert res[5]["annotations.mitre_attack.mitre_tactic_id"] == ["TA0005"]
    assert "annotations.mitre_attack" not in res[6]


def test_hec_auth_codes_and_concatenated_events(tmp_path: Path) -> None:
    with ms.MockSIEM(None, hec_token="h1") as m:
        u = f"{m.url}/services/collector/event"
        body = b'{"event": {"id": "inc-1"}, "sourcetype": "attacklens:incident"}{"event": {"id": "inc-2"}}'
        assert jhttp("POST", u, body)[1] == {"text": "Token is required", "code": 2}
        assert jhttp("POST", u, body, headers={"Authorization": "Splunk bad"})[0] == 403
        assert jhttp("POST", u, body, headers={"Authorization": "Bearer h1"})[0] == 403   # HEC wants 'Splunk'
        assert m.received["hec"] == []
        assert jhttp("POST", u, body, headers={"Authorization": "Splunk h1"}) == (200, {"text": "Success", "code": 0})
        assert [e["event"]["id"] for e in m.received["hec"]] == ["inc-1", "inc-2"]
        assert jhttp("POST", u, b'{"no_event": 1}', headers={"Authorization": "Splunk h1"})[0] == 400


# ============================================================================= Sentinel
def kql(m, query: str, token: str | None = None, ws: str = "ws1", **extra: Any) -> tuple[int, Any]:
    hdr = {"Authorization": f"Bearer {token}"} if token else {}
    return jhttp("POST", f"{m.url}/v1/workspaces/{ws}/query", {"query": query, **extra}, headers=hdr)


def test_sentinel_events_shape_and_default_desc_order(mock) -> None:
    st, r = kql(mock, "AttackLensEvents_CL | order by TimeGenerated")
    t = r["tables"][0]
    assert st == 200 and t["name"] == "PrimaryResult"
    assert [c["name"] for c in t["columns"]] == ["TimeGenerated", "Computer", "RawData", "_ItemId", "Type"]
    raw = [json.loads(row[2]) for row in t["rows"]]
    assert [marker(x) for x in raw][:2] == ["evt-0008", "evt-0007"]              # KQL order by: desc default
    assert t["rows"][0][0] == "2026-10-24T02:00:05.000Z" and "threat" not in raw[0]
    assert len({row[3] for row in t["rows"]}) == 9


def test_sentinel_time_filters_take_and_timespan(mock) -> None:
    q = (f"AttackLensEvents_CL | where TimeGenerated > datetime({iso_ms(T0 + S)}) and "
         f"TimeGenerated <= datetime({iso_ms(T0 + 3 * S)}) | order by TimeGenerated asc | take 3")
    st, r = kql(mock, q)
    assert [marker(json.loads(row[2])) for row in r["tables"][0]["rows"]] == ["evt-0002", "evt-0003", "evt-0004"]
    st, r = kql(mock, "AttackLensEvents_CL", timespan=f"{iso_ms(T0 + 4 * S)}/{iso_ms(T0 + 6 * S)}")
    assert sorted(marker(json.loads(row[2])) for row in r["tables"][0]["rows"]) == ["evt-0007", "evt-0008"]


def test_sentinel_row_cap_is_a_partial_error_not_silent(tmp_path: Path) -> None:
    with ms.MockSIEM(write_fixture(tmp_path / "raw"), sentinel_max_rows=4) as m:
        st, r = kql(m, "AttackLensEvents_CL | order by TimeGenerated asc")
        assert len(r["tables"][0]["rows"]) == 4 and r["error"]["code"] == "PartialError"


def test_sentinel_security_alert_table(mock) -> None:
    st, r = kql(mock, "SecurityAlert | order by TimeGenerated asc | project TimeGenerated, SystemAlertId, "
                      "Tactics, Techniques, SubTechniques, CompromisedEntity")
    rows = r["tables"][0]["rows"]
    assert [x[1] for x in rows] == [f"mock-sa-A{i}" for i in range(1, 8)]
    assert rows[0][2:] == ["CredentialAccess", '["T1110"]', '["T1110.001"]', "SRV-DC-01"]
    assert rows[5][2] == "DefenseEvasion" and rows[6][2:4] == ["", "[]"]


def test_sentinel_auth_workspace_and_unsupported(tmp_path: Path) -> None:
    with ms.MockSIEM(write_fixture(tmp_path / "raw"), sentinel_token="z1", workspace_id="ws1") as m:
        assert kql(m, "SecurityAlert")[0] == 401
        assert kql(m, "SecurityAlert", token="z1", ws="other")[0] == 404
        assert kql(m, "SecurityAlert | summarize count()", token="z1")[0] == 400
        assert kql(m, "SecurityAlert", token="z1")[0] == 200


# ============================================================================= faults, webhook, syslog, CLI
def test_fault_injection_status_times_and_delay(mock) -> None:
    mock.fail(r"/_search$", status=500, times=1)
    assert es_page(mock)[0] == 500
    assert es_page(mock)[0] == 200
    mock.fail(r"/_search$", status=None, times=1, delay_s=2.0)
    t = time.monotonic()
    with pytest.raises((TimeoutError, socket.timeout, urllib.error.URLError)):
        http("POST", f"{mock.url}/logs-*/_search", {}, timeout=0.3)
    assert time.monotonic() - t < 1.5
    statuses = [r["status"] for r in mock.requests if r["path"].endswith("_search")]
    assert statuses[:2] == [500, 200]


def test_webhook_and_syslog_receivers(tmp_path: Path) -> None:
    with ms.MockSIEM(None, syslog_udp=True, webhook_token="w1") as m:
        assert http("POST", f"{m.url}/webhook", {"id": "inc-1"})[0] == 401
        assert http("POST", f"{m.url}/webhook/soar", {"id": "inc-1"}, headers={"Authorization": "Bearer w1"})[0] == 200
        assert m.received["webhook"][0]["path"] == "/webhook/soar" and m.received["webhook"][0]["body"] == {"id": "inc-1"}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"<134>CEF:0|AttackLens|AttackLens|0.1|incident|inc-1|8|", m.syslog_addr)
        for _ in range(50):
            if m.received["syslog"]:
                break
            time.sleep(0.02)
        assert m.received["syslog"] == ["<134>CEF:0|AttackLens|AttackLens|0.1|incident|inc-1|8|"]
        st, snap = jhttp("GET", f"{m.url}/_mock/received")
        assert snap["received"]["webhook"][0]["body"] == {"id": "inc-1"}


def test_cli_serves_data(tmp_path: Path) -> None:
    port = ms.free_port()
    p = subprocess.Popen([sys.executable, str(REPO / "tools" / "mock_siem.py"), "--data",
                          str(write_fixture(tmp_path / "raw")), "--port", str(port)],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            try:
                st, r = jhttp("POST", f"http://127.0.0.1:{port}/logs-*/_search", {"size": 0}, timeout=1)
                break
            except urllib.error.URLError:
                time.sleep(0.05)
        else:
            raise AssertionError(p.stderr.read().decode() if p.poll() is not None else "CLI never answered")
        assert st == 200 and r["hits"]["total"]["value"] == 9 and r["hits"]["hits"] == []
    finally:
        p.terminate()
        p.wait(timeout=10)


# ============================================================================= Elastic point in time
def test_es_pit_snapshot_shard_doc_paging_and_close(mock, tmp_path: Path) -> None:
    st, r = jhttp("POST", f"{mock.url}/logs-*/_pit?keep_alive=2m")
    pit = r["id"]
    (tmp_path / "raw" / "c.jsonl").write_text(json.dumps(ecs(10, T0 + 2 * S)) + "\n", encoding="utf-8")
    got, after = [], None
    for _ in range(20):
        body: dict[str, Any] = {"size": 2, "pit": {"id": pit, "keep_alive": "2m"}, "track_total_hits": False,
                                "sort": [{"@timestamp": {"order": "asc"}}, {"_shard_doc": "asc"}]}
        if after:
            body["search_after"] = after
        st, r = jhttp("POST", f"{mock.url}/_search", body)
        assert st == 200 and r["pit_id"] == pit and "total" not in r["hits"]
        if not r["hits"]["hits"]:
            break
        got += [marker(h["_source"]) for h in r["hits"]["hits"]]
        after = r["hits"]["hits"][-1]["sort"]
    assert sorted(got) == sorted(ALL)                       # evt-0010 appended after open: invisible in the PIT
    assert len(es_drain(mock)) == 10                        # but visible without one
    assert jhttp("DELETE", f"{mock.url}/_pit", {"id": pit})[1] == {"succeeded": True, "num_freed": 1}
    assert jhttp("POST", f"{mock.url}/_search", {"pit": {"id": pit}})[0] == 404


def test_es_pit_rules(mock) -> None:
    st, r = jhttp("POST", f"{mock.url}/logs-*/_search", {"sort": [{"_shard_doc": "asc"}]})
    assert st == 400 and "_shard_doc" in r["error"]["reason"]
    pit = jhttp("POST", f"{mock.url}/logs-*/_pit?keep_alive=1m")[1]["id"]
    st, r = jhttp("POST", f"{mock.url}/logs-*/_search", {"pit": {"id": pit}})
    assert st == 400 and "point in time" in r["error"]["reason"]
    assert jhttp("POST", f"{mock.url}/logs-*/_pit")[0] == 400   # keep_alive required


# ============================================================================= cloud (Azure / AWS / GCP) mocks
import base64  # noqa: E402
import gzip  # noqa: E402
import re as _re  # noqa: E402

import mock_cloud_seed as seed  # noqa: E402

A = seed.ANCHOR_MS
MIN = 60_000
ATT = seed.ATTACKER_IP
CLOUD_CFG = {"azure_tenant": seed.TENANT, "azure_client_id": "cid-1", "azure_client_secret": "good-secret",
             "aws_access_key_id": "AKIDMOCK0000000001", "gcp_client_email": "sa@corp-prod-1234.iam.gserviceaccount.com"}
CT_TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"
LABEL_WORDS = ("threat", "labels_extra", "tactic", "ground_truth", "technique", "T1078", "T1098", "T1530", '"C1"')


@pytest.fixture
def cloud():
    with ms.MockSIEM(None, now_ms=lambda: A + 7 * 3_600_000, cloud=dict(CLOUD_CFG)) as m:
        yield m


def form(m, path: str, fields: dict[str, str], **kw: Any) -> tuple[int, Any]:
    return jhttp("POST", f"{m.url}{path}", fields, headers={"Content-Type": "application/x-www-form-urlencoded",
                                                             **kw.pop("headers", {})}, **kw)


def az_token(m, secret: str = "good-secret", **over: str) -> tuple[int, Any]:
    f = {"grant_type": "client_credentials", "client_id": "cid-1", "client_secret": secret,
         "scope": "https://api.loganalytics.io/.default", **over}
    return form(m, f"/{over.pop('tenant', seed.TENANT)}/oauth2/v2.0/token", f)


def la(m, query: str, token: str | None, **extra: Any) -> tuple[int, Any]:
    hdr = {"Authorization": f"Bearer {token}"} if token else {}
    return jhttp("POST", f"{m.url}/v1/workspaces/{seed.WORKSPACE}/query", {"query": query, **extra}, headers=hdr)


def kq_dt(ms_: int) -> str:
    return f"datetime({iso_ms(ms_)})"


def test_azure_token_endpoint_success_and_errors(cloud) -> None:
    st, r = az_token(cloud)
    assert st == 200 and r["token_type"] == "Bearer" and r["expires_in"] == 3599 and r["access_token"]
    st, r = az_token(cloud, "wrong")
    assert st == 401 and r["error"] == "invalid_client" and r["error_description"].startswith("AADSTS7000215")
    assert az_token(cloud, grant_type="password")[1]["error"] == "unsupported_grant_type"
    assert az_token(cloud, scope="https://api.loganalytics.io")[1]["error"] == "invalid_scope"
    assert az_token(cloud, client_id="other")[1]["error"] == "unauthorized_client"
    st, r = form(cloud, "/not-my-tenant/oauth2/v2.0/token", {"grant_type": "client_credentials"})
    assert st == 400 and r["error_codes"] == [90002]


def test_log_analytics_cloud_tables_shape_time_filter_take_and_bearer(cloud) -> None:
    tok = az_token(cloud)[1]["access_token"]
    assert la(cloud, "SigninLogs", None)[0] == 401
    assert la(cloud, "SigninLogs", "not-issued")[0] == 401
    q = f"SigninLogs | where TimeGenerated >= {kq_dt(A + 170 * MIN)} | order by TimeGenerated asc | take 2"
    st, r = la(cloud, q, tok)
    t = r["tables"][0]
    names = [c["name"] for c in t["columns"]]
    types = {c["name"]: c["type"] for c in t["columns"]}
    assert st == 200 and t["name"] == "PrimaryResult" and len(t["rows"]) == 2
    assert (types["TimeGenerated"], types["IsInteractive"], types["LocationDetails"], types["IPAddress"]) == \
        ("datetime", "bool", "dynamic", "string")
    got = [(row[names.index("UserPrincipalName")], row[names.index("IPAddress")], row[names.index("TimeGenerated")])
           for row in t["rows"]]
    assert got == [("kiyer@corp.example", "192.0.2.11", "2026-10-31T02:55:00.000Z"),
                   ("vreddy@corp.example", ATT, "2026-10-31T03:00:00.000Z")]
    assert json.loads(t["rows"][1][names.index("LocationDetails")])["countryOrRegion"] == "NL"
    counts = {tb: len(la(cloud, tb, tok)[1]["tables"][0]["rows"]) for tb in seed.LA_TABLES}
    assert counts == {"AzureActivity": 12, "SigninLogs": 25, "AuditLogs": 8}
    st, r = la(cloud, "AuditLogs | where OperationName == \"Reset user password\" | project TimeGenerated, "
                      "OperationName", tok)
    assert r["tables"][0]["rows"] == [["2026-10-31T01:45:00.000Z", "Reset user password"]]
    st, r = la(cloud, "AzureActivity", tok, timespan=f"{iso_ms(A)}/{iso_ms(A + 36 * MIN)}")
    assert len(r["tables"][0]["rows"]) == 2                  # +5 and +35 min


def test_azure_token_expiry_then_refresh(cloud) -> None:
    tok = az_token(cloud)[1]["access_token"]
    assert la(cloud, "AuditLogs", tok)[0] == 200
    cloud.cloud.expire_tokens("azure")
    st, raw = http("POST", f"{cloud.url}/v1/workspaces/{seed.WORKSPACE}/query", {"query": "AuditLogs"},
                   headers={"Authorization": f"Bearer {tok}"})
    assert st == 401 and "expired" in json.loads(raw)["error"]["message"]
    assert la(cloud, "AuditLogs", az_token(cloud)[1]["access_token"])[0] == 200


def test_sentinel_oauth_switch_requires_issued_azure_token(tmp_path: Path) -> None:
    with ms.MockSIEM(write_fixture(tmp_path / "raw"), cloud={**CLOUD_CFG, "sentinel_oauth": True}) as m:
        assert kql(m, "SecurityAlert", token="anything")[0] == 401
        tok = az_token(m)[1]["access_token"]
        assert kql(m, "SecurityAlert", token=tok, ws="any")[0] == 200
        m.cloud.expire_tokens()
        assert kql(m, "SecurityAlert", token=tok, ws="any")[0] == 401


def ct(m, body: dict[str, Any], akid: str = "AKIDMOCK0000000001", service: str = "cloudtrail",
       authz: str | None = None, date: bool = True) -> tuple[int, Any]:
    hdr = {"X-Amz-Target": CT_TARGET, "Content-Type": "application/x-amz-json-1.1"}
    if authz is None:
        authz = (f"AWS4-HMAC-SHA256 Credential={akid}/20261031/us-east-1/{service}/aws4_request, "
                 "SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=" + "ab" * 32)
    if authz:
        hdr["Authorization"] = authz
    if date:
        hdr["X-Amz-Date"] = "20261031T070000Z"
    return jhttp("POST", f"{m.url}/", body, headers=hdr)


def test_cloudtrail_lookup_auth_shape_order_and_window(cloud) -> None:
    assert ct(cloud, {}, authz="")[1]["__type"] == "MissingAuthenticationTokenException"
    assert ct(cloud, {}, authz="Bearer x")[1]["__type"] == "IncompleteSignatureException"
    assert ct(cloud, {}, date=False)[1]["__type"] == "IncompleteSignatureException"
    assert ct(cloud, {}, service="s3")[0] == 403
    assert ct(cloud, {}, akid="AKIDOTHER")[1]["__type"] == "UnrecognizedClientException"
    st, r = ct(cloud, {"StartTime": (A + 185 * MIN) / 1000, "EndTime": (A + 194 * MIN) / 1000})
    assert st == 200 and "NextToken" not in r
    assert [e["EventName"] for e in r["Events"]] == ["AttachUserPolicy", "CreateAccessKey", "ConsoleLogin"]
    e = r["Events"][0]
    assert (e["EventTime"], e["Username"], e["ReadOnly"], e["EventSource"]) == \
        ((A + 194 * MIN) / 1000, "vreddy", "false", "iam.amazonaws.com")
    assert {"ResourceType": "AWS::IAM::Policy", "ResourceName": "arn:aws:iam::aws:policy/AdministratorAccess"} \
        in e["Resources"]
    rec = json.loads(e["CloudTrailEvent"])
    assert (rec["sourceIPAddress"], rec["eventTime"], rec["eventID"]) == (ATT, "2026-10-31T03:14:00Z", e["EventId"])
    st, r = ct(cloud, {"StartTime": iso_ms(A + 185 * MIN), "EndTime": iso_ms(A + 185 * MIN)})
    assert [x["EventName"] for x in r["Events"]] == ["ConsoleLogin"]      # ISO accepted, bounds inclusive
    st, r = ct(cloud, {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "CreateAccessKey"}],
                       "StartTime": A / 1000})
    assert [json.loads(x["CloudTrailEvent"])["userIdentity"]["userName"] for x in r["Events"]] == ["vreddy", "asharma"]


def test_cloudtrail_next_token_paging_and_errors(cloud) -> None:
    body: dict[str, Any] = {"StartTime": A / 1000, "MaxResults": 10}
    pages, ids, times = 0, [], []
    while True:
        st, r = ct(cloud, body)
        assert st == 200
        pages += 1
        ids += [e["EventId"] for e in r["Events"]]
        times += [e["EventTime"] for e in r["Events"]]
        if "NextToken" not in r:
            break
        body["NextToken"] = r["NextToken"]
    assert (pages, len(ids), len(set(ids))) == (4, 35, 35)      # management events only (10 data events excluded)
    assert times == sorted(times, reverse=True)                  # newest first
    assert ct(cloud, {"MaxResults": 51})[1]["__type"] == "InvalidMaxResultsException"
    assert ct(cloud, {"StartTime": 2, "EndTime": 1})[1]["__type"] == "InvalidTimeRangeException"
    tok = ct(cloud, {"StartTime": A / 1000, "MaxResults": 10})[1]["NextToken"]
    assert ct(cloud, {"StartTime": A / 1000 + 1, "MaxResults": 10, "NextToken": tok})[1]["__type"] == \
        "InvalidNextTokenException"
    assert ct(cloud, {"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "a"},
                                           {"AttributeKey": "Username", "AttributeValue": "b"}]})[1]["__type"] == \
        "InvalidLookupAttributesException"


def s3get(m, path: str, sha: bool = True, auth: bool = True) -> tuple[int, bytes]:
    hdr = {"X-Amz-Date": "20261031T070000Z"}
    if sha:
        hdr["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
    if auth:
        hdr["Authorization"] = ("AWS4-HMAC-SHA256 Credential=AKIDMOCK0000000001/20261031/us-east-1/s3/aws4_request, "
                                "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" + "cd" * 32)
    return http("GET", f"{m.url}{path}", headers=hdr)


def test_s3_trail_listing_paging_and_gzip_records(cloud) -> None:
    b = f"/{seed.S3_BUCKET}"
    prefix = f"AWSLogs/{seed.ACCOUNT}/CloudTrail/{seed.REGION}/2026/10/31/"
    keys, tok = [], None
    while True:
        q = f"?list-type=2&prefix={urllib.parse.quote(prefix)}&max-keys=7" + (
            f"&continuation-token={urllib.parse.quote(tok)}" if tok else "")
        st, raw = s3get(cloud, b + q)
        assert st == 200, raw
        xml = raw.decode()
        keys += _re.findall(r"<Key>([^<]+)</Key>", xml)
        m_ = _re.search(r"<NextContinuationToken>([^<]+)</NextContinuationToken>", xml)
        if not m_:
            assert "<IsTruncated>false</IsTruncated>" in xml
            break
        tok = m_.group(1)
    assert keys == sorted(keys) and len(keys) == len(set(keys))
    assert all(_re.fullmatch(rf"{prefix}{seed.ACCOUNT}_CloudTrail_{seed.REGION}_20261031T\d{{4}}Z_[0-9A-F]{{16}}"
                             r"\.json\.gz", k) for k in keys)
    recs = []
    for k in keys:
        st, data = s3get(cloud, f"{b}/{k}")
        assert st == 200 and data[:2] == b"\x1f\x8b"
        recs += json.loads(gzip.decompress(data))["Records"]
    assert len(recs) == 45 and len({r["eventID"] for r in recs}) == 45
    assert sum(r["eventCategory"] == "Data" for r in recs) == 10
    assert s3get(cloud, b + "?list-type=2", sha=False)[0] == 400
    assert s3get(cloud, b + "?list-type=2", auth=False)[0] == 403
    assert b"NoSuchKey" in s3get(cloud, f"{b}/AWSLogs/nope.json.gz")[1]
    assert b"NoSuchBucket" in s3get(cloud, "/other-bucket?list-type=2")[1]


def jwt(claims: dict[str, Any], alg: str = "RS256") -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': alg, 'typ': 'JWT'})}.{enc(claims)}.c2lnbmF0dXJl"


def gcp_claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    return {"iss": CLOUD_CFG["gcp_client_email"], "scope": "https://www.googleapis.com/auth/logging.read",
            "aud": "https://oauth2.googleapis.com/token", "iat": now, "exp": now + 3600, **over}


def gcp_tok(m, claims: dict[str, Any] | None = None, alg: str = "RS256",
            grant: str = "urn:ietf:params:oauth:grant-type:jwt-bearer") -> tuple[int, Any]:
    return form(m, "/token", {"grant_type": grant, "assertion": jwt(claims or gcp_claims(), alg)})


def test_gcp_token_jwt_bearer_checks(cloud) -> None:
    st, r = gcp_tok(cloud)
    assert st == 200 and r["token_type"] == "Bearer" and r["access_token"].startswith("ya29.")
    assert r["expires_in"] == 3599
    assert gcp_tok(cloud, alg="HS256")[1]["error"] == "invalid_grant"
    assert gcp_tok(cloud, gcp_claims(exp=int(time.time()) + 7200))[1]["error"] == "invalid_grant"
    assert gcp_tok(cloud, gcp_claims(iss="x@y"))[1]["error_description"] == "Invalid grant: account not found"
    assert gcp_tok(cloud, grant="client_credentials")[1]["error"] == "unsupported_grant_type"
    st, r = form(cloud, "/token", {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": "a.b"})
    assert st == 400 and r["error"] == "invalid_grant"


def entries(m, token: str | None, **body: Any) -> tuple[int, Any]:
    hdr = {"Authorization": f"Bearer {token}"} if token else {}
    return jhttp("POST", f"{m.url}/v2/entries:list", {"resourceNames": [f"projects/{seed.PROJECT}"], **body},
                 headers=hdr)


def test_gcp_entries_list_filter_order_and_page_token(cloud) -> None:
    tok = gcp_tok(cloud)[1]["access_token"]
    st, r = entries(cloud, None)
    assert st == 401 and r["error"]["status"] == "UNAUTHENTICATED"
    assert entries(cloud, tok, resourceNames=["projects/other"])[1]["error"]["status"] == "PERMISSION_DENIED"
    flt = f'timestamp>="{iso_ms(A + 210 * MIN)}" AND protoPayload.requestMetadata.callerIp="{ATT}"'
    body: dict[str, Any] = {"filter": flt, "pageSize": 15, "orderBy": "timestamp asc"}
    sizes, got = [], []
    while True:
        st, r = entries(cloud, tok, **body)
        assert st == 200
        sizes.append(len(r["entries"]))
        got += r["entries"]
        if "nextPageToken" not in r:
            break
        body["pageToken"] = r["nextPageToken"]
    assert sizes == [15, 15, 10] and len({e["insertId"] for e in got}) == 40
    e = got[0]
    assert (e["timestamp"], e["protoPayload"]["methodName"], e["protoPayload"]["authenticationInfo"]["principalEmail"],
            e["logName"], e["resource"]["labels"]["bucket_name"]) == (
        "2026-10-31T03:30:00.000Z", "storage.objects.get", "vreddy@corp.example",
        f"projects/{seed.PROJECT}/logs/cloudaudit.googleapis.com%2Fdata_access", seed.BUCKET_GCS)
    assert [x["timestamp"] for x in got] == sorted(x["timestamp"] for x in got)
    assert entries(cloud, tok, filter="timestamp>=\"x\" AND a=b", pageToken=body["pageToken"])[0] == 400
    assert entries(cloud, tok, filter="timestamp ~~ 3")[1]["error"]["status"] == "INVALID_ARGUMENT"
    n = lambda f: len(entries(cloud, tok, filter=f, pageSize=1000)[1].get("entries", []))  # noqa: E731
    assert (n('logName:"data_access"'), n('logName="projects/corp-prod-1234/logs/cloudaudit.googleapis.com/activity"'),
            n("")) == (70, 10, 80)
    st, r = entries(cloud, tok, filter=flt, orderBy="timestamp desc", pageSize=1)
    assert r["entries"][0]["insertId"] == got[-1]["insertId"]


def test_fault_switches_429_retry_after_on_page_n_401_500_and_slow(cloud) -> None:
    cloud.fail("cloudtrail", status=429, after=1, retry_after=2)
    first = ct(cloud, {"StartTime": A / 1000, "MaxResults": 10})
    page2 = urllib.request.Request(f"{cloud.url}/", method="POST", headers={"X-Amz-Target": CT_TARGET},
                                   data=json.dumps({"StartTime": A / 1000, "MaxResults": 10,
                                                    "NextToken": first[1]["NextToken"]}).encode())
    with pytest.raises(urllib.error.HTTPError) as ei:            # page 2 of the pull -> 429 + Retry-After
        urllib.request.urlopen(page2, timeout=5)
    assert first[0] == 200 and ei.value.code == 429 and ei.value.headers["Retry-After"] == "2"
    req = urllib.request.Request(f"{cloud.url}/v2/entries:list?mock_fault=429&mock_retry_after=5", data=b"{}",
                                 method="POST")
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(req, timeout=5)
    assert ei.value.code == 429 and ei.value.headers["Retry-After"] == "5"
    assert ct(cloud, {"StartTime": A / 1000, "MaxResults": 10, "NextToken": first[1]["NextToken"]})[0] == 200
    assert http("POST", f"{cloud.url}/v2/entries:list?mock_fault=500", {})[0] == 500
    assert http("POST", f"{cloud.url}/{seed.TENANT}/oauth2/v2.0/token?mock_fault=401", b"")[0] == 401
    t = time.monotonic()
    with pytest.raises((TimeoutError, socket.timeout, urllib.error.URLError)):
        http("POST", f"{cloud.url}/v2/entries:list?mock_fault=slow&mock_delay=2", {}, timeout=0.3)
    assert time.monotonic() - t < 1.5
    assert ms.parse_fault_spec("cloudtrail,429,after=2,retry_after=3") == {
        "path_re": "cloudtrail", "status": 429, "times": 1, "after": 2, "retry_after": 3.0, "delay_s": 0.0}
    assert ms.parse_fault_spec("gcp_logs,slow,times=0")["status"] is None
    with pytest.raises(ValueError):
        ms.parse_fault_spec("gcp_logs,500,bogus=1")


def test_data_switches_tie_burst_late_row_and_future_row(cloud) -> None:
    tok = az_token(cloud)[1]["access_token"]
    cloud.cloud.configure(tie_burst=5001)
    tie = A + seed.TIE_OFFSET_MS
    st, r = la(cloud, f"AzureActivity | where TimeGenerated == {kq_dt(tie)}", tok)
    assert len(r["tables"][0]["rows"]) == 5001 and len({row[0] for row in r["tables"][0]["rows"]}) == 1
    cloud.cloud.configure(tie_burst=0, late_after=1, future_row=True)
    base = 25 + 1                                            # sign-ins + the future row (visible at once)
    q = f"SigninLogs | where TimeGenerated <= {kq_dt(A + 30 * MIN)} | project TimeGenerated"
    assert la(cloud, q, tok)[1]["tables"][0]["rows"] == [["2026-10-31T00:10:00.000Z"], ["2026-10-31T00:25:00.000Z"]]
    assert la(cloud, q, tok)[1]["tables"][0]["rows"] == [["2026-10-31T00:10:00.000Z"], ["2026-10-31T00:20:00.000Z"],
                                                          ["2026-10-31T00:25:00.000Z"]]   # late row, old timestamp
    rows = la(cloud, "SigninLogs | order by TimeGenerated desc | project TimeGenerated", tok)[1]["tables"][0]["rows"]
    assert len(rows) == base + 1 and rows[0] == [iso_ms(A + 7 * 3_600_000 + seed.FUTURE_MS)]
    st, r = jhttp("POST", f"{cloud.url}/_mock/cloud", {"bogus": 1})
    assert st == 400
    st, r = jhttp("POST", f"{cloud.url}/_mock/cloud", {"tie_burst": 2, "late_after": 0, "future_row": False})
    assert r["switches"] == {"tie_burst": 2, "late_after": 0, "future_row": False, "late_ts_ms": None}
    added = jhttp("POST", f"{cloud.url}/_mock/cloud", {"add_rows_ts_ms": A + 400 * MIN})[1]["added"]
    assert set(added) == set(seed.FEEDS) and jhttp("GET", f"{cloud.url}/_mock/cloud")[1]["feeds"]["CloudTrail"] == 48


def test_seed_ground_truth_matches_served_records_and_is_never_served(cloud, tmp_path: Path) -> None:
    gt = jhttp("GET", f"{cloud.url}/_mock/cloud/ground_truth")[1]
    assert gt == seed.ground_truth(A) == json.loads((REPO / "tools" / "mock_cloud_ground_truth.json").read_text())
    steps = gt["attacks"][0]["steps"]
    assert [(s["technique_id"], s["tactic"]) for s in steps] == [
        ("T1078.004", "Initial Access"), ("T1078.004", "Initial Access"), ("T1098.001", "Persistence"),
        ("T1098.003", "Privilege Escalation"), ("T1530", "Collection")]
    f = cloud.cloud.seed.feeds
    first_att = lambda feed, ip: min(it.ts_ms for it in f[feed] if ip(it.doc) == ATT)  # noqa: E731
    assert steps[0]["ts_ms"] == first_att("SigninLogs", lambda d: d["IPAddress"])
    att_ct = {it.doc["eventName"]: it.ts_ms for it in f["CloudTrail"] if it.doc["sourceIPAddress"] == ATT}
    assert [steps[i]["ts_ms"] for i in (1, 2, 3)] == [att_ct["ConsoleLogin"], att_ct["CreateAccessKey"],
                                                      att_ct["AttachUserPolicy"]]
    assert steps[4]["ts_ms"] == first_att("GcpLogging", lambda d: d["protoPayload"]["requestMetadata"]["callerIp"])
    assert sum(it.doc["sourceIPAddress"] == ATT for it in f["CloudTrail"]) == 3
    for feed, items in f.items():                            # no label anywhere in a served record
        for it in items:
            text = json.dumps(it.doc)
            assert not any(w in text for w in LABEL_WORDS), (feed, text[:200])
    out = seed.write(tmp_path / "cloud_seed")
    assert json.loads((out / "ground_truth" / "attacks.json").read_text()) == seed.ground_truth()
    assert {p.name: len(p.read_text().splitlines()) for p in out.glob("*.jsonl")} == {
        "AzureActivity.jsonl": 12, "SigninLogs.jsonl": 25, "AuditLogs.jsonl": 8, "CloudTrail.jsonl": 45,
        "GcpLogging.jsonl": 80}
    assert seed.build().feeds["CloudTrail"][0].doc == seed.build().feeds["CloudTrail"][0].doc   # deterministic


def test_hec_indexer_ack_channel_and_size_limit(tmp_path: Path) -> None:
    with ms.MockSIEM(None, hec_ack=True, hec_max_bytes=200) as m:
        ev = {"event": {"id": "inc-1"}}
        st, r = jhttp("POST", f"{m.url}/services/collector/event", ev)
        assert (st, r) == (400, {"text": "Data channel is missing", "code": 10})
        ch = {"X-Splunk-Request-Channel": "0f6c7d43-7b4c-4a35-9f47-5c4f6b1d2e3a"}
        assert jhttp("POST", f"{m.url}/services/collector/event", ev, headers=ch)[1]["ackId"] == 0
        assert jhttp("POST", f"{m.url}/services/collector/event", ev, headers=ch)[1]["ackId"] == 1
        st, r = jhttp("POST", f"{m.url}/services/collector/ack", {"acks": [0, 1, 5]}, headers=ch)
        assert r == {"acks": {"0": True, "1": True, "5": False}}
        st, r = jhttp("POST", f"{m.url}/services/collector/event", {"event": "x" * 300}, headers=ch)
        assert st == 413 and len(m.received["hec"]) == 2


def test_syslog_tcp_octet_counting_and_newline_framing() -> None:
    frames, rest = ms.split_syslog_frames(b"5 hello10 two\nlines!3 ab")
    assert (frames, rest) == ([b"hello", b"two\nlines!"], b"3 ab")
    assert ms.split_syslog_frames(b"<134>a b\n<134>c\r\n") == ([b"<134>a b", b"<134>c"], b"")
    with ms.MockSIEM(None, syslog_tcp=True) as m:
        cef = "<134>CEF:0|AttackLens|AttackLens|0.1|incident|inc-1|8|msg=multi\nline"
        ms.send_syslog(m.syslog_tcp_addr, [cef, "<134>second"], framing="octet")
        ms.send_syslog(m.syslog_tcp_addr, ["<134>third"], framing="lf")
        for _ in range(100):
            if len(m.received["syslog"]) >= 3:
                break
            time.sleep(0.02)
        assert sorted(m.received["syslog"]) == sorted([cef, "<134>second", "<134>third"])


def test_cli_serves_cloud_endpoints_with_fault_flag() -> None:
    port = ms.free_port()
    p = subprocess.Popen([sys.executable, str(REPO / "tools" / "mock_siem.py"), "--port", str(port),
                          "--cloud-anchor", "fixed", "--azure-client-secret", "s3cr3t",
                          "--fault", "gcp_logs,429,retry_after=3"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                st, r = jhttp("GET", f"{url}/_mock/cloud", timeout=1)
                break
            except urllib.error.URLError:
                time.sleep(0.05)
        else:
            raise AssertionError(p.stderr.read().decode() if p.poll() is not None else "CLI never answered")
        assert r["anchor_ms"] == A and r["feeds"]["GcpLogging"] == 80
        hdr = {"Content-Type": "application/x-www-form-urlencoded"}
        f = {"grant_type": "client_credentials", "client_id": "c", "scope": "x/.default"}
        assert jhttp("POST", f"{url}/t/oauth2/v2.0/token", {**f, "client_secret": "no"}, headers=hdr)[0] == 401
        assert jhttp("POST", f"{url}/t/oauth2/v2.0/token", {**f, "client_secret": "s3cr3t"}, headers=hdr)[0] == 200
        st, raw = http("POST", f"{url}/v2/entries:list", {})
        assert st == 429
        assert http("POST", f"{url}/v2/entries:list", {})[0] == 401          # fault used up; no token
    finally:
        p.terminate()
        p.wait(timeout=10)


KEYSET_Q = ("{head} | where TimeGenerated >= datetime({since}) and TimeGenerated <= datetime({until}) "
            "| extend AlId = tostring(_ItemId) {after} | order by TimeGenerated asc, AlId asc | take {size}")


def keyset_drain(m, head: str, size: int, token: str | None, ws: str, since: int, until: int) -> list[list]:
    """The loganalytics connector's keyset loop: (TimeGenerated, AlId) > last row, page by page."""
    got, after = [], ""
    while True:
        q = KEYSET_Q.format(head=head, since=iso_ms(since), until=iso_ms(until), after=after, size=size)
        hdr = {"Authorization": f"Bearer {token}"} if token else {}
        st, r = jhttp("POST", f"{m.url}/v1/workspaces/{ws}/query", {"query": q}, headers=hdr)
        assert st == 200, r
        t = r["tables"][0]
        names = [c["name"] for c in t["columns"]]
        rows = [dict(zip(names, row)) for row in t["rows"]]
        got += rows
        if len(rows) < size:
            return got
        last = rows[-1]
        after = (f'| where TimeGenerated > datetime({last["TimeGenerated"]}) or (TimeGenerated == '
                 f'datetime({last["TimeGenerated"]}) and AlId > "{last["AlId"]}")')


def test_kql_union_extend_keyset_pages_through_a_tie_larger_than_a_page(cloud) -> None:
    tok = az_token(cloud)[1]["access_token"]
    cloud.cloud.configure(tie_burst=7)
    rows = keyset_drain(cloud, "union isfuzzy=true AzureActivity, SigninLogs, AuditLogs", 3, tok, seed.WORKSPACE,
                        A, A + 7 * 3_600_000)
    keys = [(r["TimeGenerated"], r["AlId"]) for r in rows]
    assert len(rows) == 12 + 7 + 25 + 8 and len(set(keys)) == len(rows) and keys == sorted(keys)
    assert {r["Type"] for r in rows} == set(seed.LA_TABLES)
    assert sum(r["TimeGenerated"] == iso_ms(A + seed.TIE_OFFSET_MS) for r in rows) == 7


def test_kql_keyset_on_sentinel_event_table_through_the_4way_tie(mock) -> None:
    rows = keyset_drain(mock, "SecurityEvent", 2, None, "ws1", T0 - S, T0 + 10 * S)
    assert sorted(marker(json.loads(r["RawData"])) for r in rows) == sorted(ALL)
    assert [r["AlId"] for r in rows] == [r["_ItemId"] for r in rows]
    st, r = kql(mock, "SecurityEvent | where TimeGenerated > datetime(2026-10-24T02:00:00Z) or (TimeGenerated == "
                      'datetime(2026-10-24T02:00:00Z) and AlId > "x")')
    assert st == 400 and "AlId" in r["error"]["reason"]                # keyset column must be extended first
