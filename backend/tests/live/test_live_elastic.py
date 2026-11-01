"""Elasticsearch 8.x (security on, HTTPS with the auto-generated CA) against the AttackLens Elastic connector and the
elastic_bulk sink, through the HTTP API.

Seed (fixture): 1234 ECS events into the data stream logs-attacklens-default, 2 s apart from now-50 min, except
seq 400..649 which all share ONE @timestamp (250 docs: with page_size 100 the PIT / search_after paging crosses two
page boundaries inside the tie). API keys are least-privilege, exactly as the catalog help documents them.

Run: .venv/Scripts/python -m pytest backend/tests/live -m live -k elastic -v
"""

from __future__ import annotations

import copy
import math
import time
import uuid
from typing import Any, Iterator

import pytest

from .conftest import ApiEnv, assert_accounted, json_docs, vendor, wait_until

import elastic_seed as es_seed  # noqa: E402  (tools/live, on sys.path via conftest)
import livectl  # noqa: E402
import vhttp  # noqa: E402

pytestmark = pytest.mark.live

N, TIE_FROM, TIE_LEN, PAGE = 1234, 400, 250, 100


@pytest.fixture(scope="module")
def elastic() -> Iterator[dict[str, Any]]:
    run = uuid.uuid4().hex[:10]
    box: dict[str, Any] = {}

    def prepare(st: livectl.Stack) -> None:
        st.ports = {"http": livectl.free_port()}
        box["password"] = livectl.password()
        st.env = {"ELASTIC_PASSWORD": box["password"], "AL_ES_PORT": str(st.ports["http"])}

    with vendor("elastic", prepare) as st:
        ca = st.dir / "http_ca.crt"
        t0 = time.perf_counter()
        wait_until(lambda: _cp_ca(st, ca), 240, "http_ca.crt in the container", st.logs)
        es = es_seed.Elastic(f"https://127.0.0.1:{st.ports['http']}", box["password"], str(ca))
        try:
            keys = es_seed.setup(es)
        except Exception as exc:
            raise RuntimeError(f"elastic setup failed: {exc}\n{st.logs()[-3000:]}") from None
        st.timings["setup_s"] = round(time.perf_counter() - t0, 1)
        st.info["es_version"] = keys["version"]
        t1 = time.perf_counter()
        ts = es_seed.seed(es, N, run, int(time.time() * 1000), TIE_FROM, TIE_LEN)
        st.timings["seed_s"] = round(time.perf_counter() - t1, 1)
        yield {"es": es, "run": run, "ts": ts, "stack": st, **keys}


def _cp_ca(st: livectl.Stack, dst: Any) -> bool:
    try:
        st.cp_out("al-live-es", "/usr/share/elasticsearch/config/certs/http_ca.crt", dst)
        return dst.exists() and dst.stat().st_size > 0
    except RuntimeError:
        return False


def es_settings(e: dict[str, Any], **kw: Any) -> dict[str, Any]:
    out = {"base_url": e["es"].url, "verify_tls": True, "ca_file": e["es"].ca_file,
           "events.index": es_seed.STREAM, "default_since": "24h"}
    out.update(kw)
    return out


def seqs(api: ApiEnv, run: str) -> list[int]:
    return [d["al_seq"] for d in json_docs(api.spool_lines("elastic")) if d.get("al_run") == run]


def query_total(es: es_seed.Elastic) -> int:
    d = es.ok(es.call("GET", f"/{es_seed.STREAM}/_stats/search"), "index stats")
    return int(d["_all"]["primaries"]["search"]["query_total"])


# ============================================================================= pull: API -> spool, PIT paging
def test_elastic_api_pull_pit_paging_equals_seed(elastic, api: ApiEnv, record_property) -> None:
    es, run = elastic["es"], elastic["run"]
    api.ic["connectors"]["elastic"].update(page_size=PAGE, use_pit=True)
    api.client()
    view = api.put("elastic", es_settings(elastic), {"api_key": elastic["reader"]})
    assert view["secrets_set"]["api_key"] is True
    t = api.test("elastic")
    assert t["ok"] is True, t
    pit0, q0 = es.pit_stats(), query_total(es)
    t0 = time.perf_counter()
    assert api.start("elastic", {"mode": "events", "since": "2h"})["running"] is True
    first = wait_until(lambda: len(seqs(api, run)) >= N, 240, "1234 events in the spool", lambda: api.log("elastic"))
    time.sleep(5)                                    # further cycles re-read the overlap: nothing written twice
    assert api.stop("elastic")["running"] is False
    pit1, q1 = es.pit_stats(), query_total(es)

    got = seqs(api, run)
    record_property("seeded", N)
    record_property("pulled_unique", len(set(got)))
    record_property("spool_rows", len(got))
    record_property("first_pull_s", first)
    record_property("wall_s", round(time.perf_counter() - t0, 1))
    record_property("search_queries", q1 - q0)
    record_property("pit_stats_before_after", [pit0, pit1])
    assert sorted(got) == list(range(N)), "every seeded doc exactly once (250-doc timestamp tie included)"
    tot = assert_accounted(api.status("elastic_events"), N)
    record_property("totals", tot)
    assert "PIT unavailable" not in api.log("elastic"), "connector fell back from PIT"
    assert q1 - q0 >= math.ceil(N / PAGE), f"expected >= {math.ceil(N / PAGE)} page queries, saw {q1 - q0}"
    if pit0 is not None and pit1 is not None:
        assert pit1["total"] > pit0["total"], (pit0, pit1)
        assert pit1["current"] == 0, f"PIT left open: {pit1}"
    lines = "\n".join(api.spool_lines("elastic"))
    assert '"labels_extra"' not in lines and '"threat"' not in lines
    assert not api.leaked(), f"secret values written to tmp outputs: {api.leaked()}"


def test_elastic_tls_verify_without_ca_fails_actionably(elastic, api: ApiEnv) -> None:
    api.client()
    api.put("elastic", es_settings(elastic, ca_file=None), {"api_key": elastic["reader"]})
    t = api.test("elastic")
    assert t["ok"] is False and t["error_code"] == "tls_error", t
    assert "not trusted" in t["message"], t


def test_elastic_bad_api_key_gives_actionable_401(elastic, api: ApiEnv) -> None:
    api.client()
    api.put("elastic", es_settings(elastic), {"api_key": "bm90LWEta2V5Om5vcGUtbm9wZS1ub3Bl"})
    t = api.test("elastic")
    assert t["ok"] is False and t["error_code"] == "auth_failed", t
    assert "rejected the credentials (HTTP 401)" in t["message"], t


# ============================================================================= elastic_bulk sink
def _items(tag: str, n: int = 3) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    from ..test_integrations import _items as base_items

    out = []
    for i, (inc, row) in enumerate(base_items(n)):
        inc, row = copy.deepcopy(inc), dict(row)
        inc["id"] = row["id"] = f"inc-{tag}-{i}"
        out.append((inc, row))
    return out


def _ids_in(es: es_seed.Elastic, index: str, tag: str) -> list[str]:
    es.call("POST", f"/{index}/_refresh")
    r = es.call("POST", f"/{index}/_search", {"size": 1000, "query": {"match_all": {}}, "_source": ["id"]})
    if r.status != 200:
        return []
    return sorted(i for h in r.json()["hits"]["hits"] if str(i := h["_source"].get("id", "")).startswith(f"inc-{tag}"))


def test_elastic_bulk_sink_writes_to_data_stream(elastic, api: ApiEnv, record_property) -> None:
    from attacklens import sinks

    es = elastic["es"]
    tag = f"al{uuid.uuid4().hex[:10]}"
    api.ic["sinks"]["elastic_bulk"].update(only_changed=False, ca_file=es.ca_file)
    api.client()
    api.put("elastic_bulk", {"base_url": es.url, "index": es_seed.SINK_STREAM, "verify_tls": True},
            {"api_key": elastic["writer"]})
    t = api.test("elastic_bulk")          # asserted last: a probe failure must not hide the delivery result
    record_property("api_test", {k: t.get(k) for k in ("ok", "error_code", "message")})
    items = _items(tag)
    res = sinks.publish_all(items, api.cfg())
    assert res["elastic_bulk"]["sent"] == 3 and res["elastic_bulk"]["failed"] == 0, res
    ds = es.call("GET", f"/_data_stream/{es_seed.SINK_STREAM}")
    assert ds.status == 200 and ds.json()["data_streams"][0]["name"] == es_seed.SINK_STREAM, ds.text[:300]
    want = sorted(inc["id"] for inc, _ in items)
    assert _ids_in(es, es_seed.SINK_STREAM, tag) == want
    res2 = sinks.publish_all(items, api.cfg())      # re-send: create -> 409 per doc = already delivered
    assert res2["elastic_bulk"]["sent"] == 3 and res2["elastic_bulk"]["failed"] == 0, res2
    assert _ids_in(es, es_seed.SINK_STREAM, tag) == want, "a re-send must not duplicate incidents"
    record_property("sent", 3)
    record_property("stored", len(want))
    assert t["ok"] is True, f"delivery works, but the sink connection test (minimum key, ca_file) says: {t}"


def test_elastic_bulk_sink_plain_index_upsert(elastic, api: ApiEnv) -> None:
    from attacklens import sinks

    es = elastic["es"]
    tag = f"al{uuid.uuid4().hex[:10]}"
    api.ic["sinks"]["elastic_bulk"].update(only_changed=False, ca_file=es.ca_file)
    api.client()
    api.put("elastic_bulk", {"base_url": es.url, "index": es_seed.SINK_INDEX, "verify_tls": True},
            {"api_key": elastic["writer"]})
    items = _items(tag, 2)
    assert sinks.publish_all(items, api.cfg())["elastic_bulk"]["sent"] == 2
    items[0][0]["risk"] = 11
    res = sinks.publish_all(items, api.cfg())
    assert res["elastic_bulk"]["sent"] == 2 and res["elastic_bulk"]["failed"] == 0, res
    assert _ids_in(es, es_seed.SINK_INDEX, tag) == sorted(i["id"] for i, _ in items)
    doc = es.call("GET", f"/{es_seed.SINK_INDEX}/_doc/{items[0][0]['id']}").json()
    assert doc["_source"]["risk"] == 11, "index op overwrites the stored incident"


def test_elastic_peer_cert_is_autogenerated_ca(elastic) -> None:
    port = int(elastic["es"].url.rsplit(":", 1)[1])
    assert "Elasticsearch security auto-configuration" in vhttp.peer_cert_issuer("127.0.0.1", port)
