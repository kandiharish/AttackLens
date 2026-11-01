"""Splunk Enterprise (splunk/splunk image) against the AttackLens Splunk connector + HEC sink, through the HTTP API.

Seed (fixture): token auth on + JWT auth token, HEC tokens with and without indexer acknowledgement, 499 ECS events
into index `attacklens` (now-50 min .. now-8 min, 5 s apart; seq 250 shares seq 249's millisecond; every 100th
carries label keys). The 500th event is indexed by the test AFTER the first pull, dated 5 min before the checkpoint
(a late-indexed row). Splunk serves a throwaway CA-signed cert (SAN 127.0.0.1) on 8089 and 8088.

Run: .venv/Scripts/python -m pytest backend/tests/live -m live -k splunk -v
"""

from __future__ import annotations

import copy
import time
import uuid
from typing import Any, Iterator

import pytest

from .conftest import ApiEnv, assert_accounted, json_docs, vendor, wait_until

import certs  # noqa: E402  (tools/live, on sys.path via conftest)
import livectl  # noqa: E402
import splunk_seed as ss  # noqa: E402
import vhttp  # noqa: E402

pytestmark = pytest.mark.live

N = 500           # seeded events in total (499 before the first pull + 1 late)
TIE = 250         # seq TIE has the same _time as seq TIE-1
LATE = N - 1      # seq of the late-indexed event


@pytest.fixture(scope="module")
def splunk() -> Iterator[dict[str, Any]]:
    run = uuid.uuid4().hex[:10]
    box: dict[str, Any] = {}

    def prepare(st: livectl.Stack) -> None:
        tls = certs.make(st.dir / "tls")
        app = ss.tls_app(st.dir / "attacklens_tls", tls["bundle"])
        st.ports = {"mgmt": livectl.free_port(), "hec": livectl.free_port()}
        box.update(password=livectl.password(), ca=str(tls["ca"]))
        st.env = {"SPLUNK_PASSWORD": box["password"], "AL_SPLUNK_MGMT_PORT": str(st.ports["mgmt"]),
                  "AL_SPLUNK_HEC_PORT": str(st.ports["hec"]), "AL_SPLUNK_TLS_APP": app.as_posix()}

    with vendor("splunk", prepare) as st:
        sp = ss.Splunk(f"https://127.0.0.1:{st.ports['mgmt']}", f"https://127.0.0.1:{st.ports['hec']}",
                       box["password"], box["ca"])
        t0 = time.perf_counter()
        try:
            toks = ss.setup(sp)
        except Exception as exc:
            raise RuntimeError(f"splunk setup failed: {exc}\n{st.logs()[-3000:]}") from None
        st.timings["setup_s"] = round(time.perf_counter() - t0, 1)
        now = int(time.time() * 1000)
        ts = ss.plan(N, now, TIE)
        ts[LATE] = max(ts[:LATE]) - 5 * 60_000      # dated before the checkpoint the first pull will set
        t1 = time.perf_counter()
        sp.hec_send(toks["hec_noack"], [(ts[i], ss.ecs_line(i, ts[i], run)) for i in range(LATE)])
        st.timings["seed_wait_searchable_s"] = sp.wait_count(f"index={ss.INDEX} al_run={run}", LATE)
        st.timings["seed_s"] = round(time.perf_counter() - t1, 1)
        version = sp.rest("GET", "/services/server/info").json()["entry"][0]["content"].get("version")
        st.info["splunk_version"] = version
        st.info["tls_app_applied"] = toks["tls_app_applied"]
        yield {"sp": sp, "run": run, "ts": ts, "stack": st, **toks}


def splunk_settings(s: dict[str, Any], **kw: Any) -> dict[str, Any]:
    """Connector settings; verified against the test CA when splunkd serves it (else verify off, see precondition)."""
    out = {"base_url": s["sp"].mgmt, "verify_tls": s["sp"].verify, "ca_file": s["sp"].ca_file,
           "events.search": f"search index={ss.INDEX}", "default_since": "24h"}
    out.update(kw)
    return out


def seqs(api: ApiEnv, run: str) -> list[int]:
    return [d["al_seq"] for d in json_docs(api.spool_lines("splunk")) if d.get("al_run") == run]


# ============================================================================= pull: API -> spool, counts
def test_splunk_served_cert_is_the_test_ca(splunk) -> None:
    """Precondition for the ca_file checks: splunkd (8089) and HEC (8088) present our throwaway CA's cert, not
    Splunk's default one. If this fails, the pull tests still ran (with verify off) but the TLS cases are invalid."""
    port = int(splunk["sp"].mgmt.rsplit(":", 1)[1])
    assert splunk["tls_app_applied"] == "yes", vhttp.peer_cert_issuer("127.0.0.1", port)


def test_splunk_api_pull_equals_seed_incl_tie_and_late_event(splunk, api: ApiEnv, record_property) -> None:
    sp, run, ts = splunk["sp"], splunk["run"], splunk["ts"]
    api.client()
    view = api.put("splunk", splunk_settings(splunk), {"token": splunk["token"]})
    assert view["configured"] and view["secrets_set"]["token"] is True
    t = api.test("splunk")
    assert t["ok"] is True, t
    t0 = time.perf_counter()
    assert api.start("splunk", {"mode": "events", "since": "2h"})["running"] is True
    first = wait_until(lambda: len(seqs(api, run)) >= LATE, 240, "first 499 events in the spool",
                       lambda: api.log("splunk"))
    cp = api.status("splunk_events").get("checkpoint") or {}
    # the late event: dated 5 min before the newest pulled row, indexed only now
    assert ts[LATE] < max(ts[:LATE])
    sp.hec_send(splunk["hec_noack"], [(ts[LATE], ss.ecs_line(LATE, ts[LATE], run))])
    sp.wait_count(f"index={ss.INDEX} al_run={run}", N)
    late = wait_until(lambda: len(seqs(api, run)) >= N, 120, "late event in the spool", lambda: api.log("splunk"))
    time.sleep(5)                                          # two more cycles: nothing may be written twice
    assert api.stop("splunk")["running"] is False
    wall = round(time.perf_counter() - t0, 1)

    got = seqs(api, run)
    record_property("seeded", N)
    record_property("pulled_unique", len(set(got)))
    record_property("spool_rows", len(got))
    record_property("first_pull_s", first)
    record_property("late_event_pulled_after_s", late)
    record_property("wall_s", wall)
    assert sorted(got) == list(range(N)), "every seeded event exactly once (tie pair and late event included)"
    assert cp.get("last_ts_ms") is None or ts[LATE] < int(cp["last_ts_ms"]), "late event was older than checkpoint"
    tot = assert_accounted(api.status("splunk_events"), N)
    record_property("totals", tot)
    lines = "\n".join(api.spool_lines("splunk"))
    assert '"labels_extra"' not in lines and '"threat"' not in lines, "label keys stripped from the spool"
    assert not api.leaked(), f"secret values written to tmp outputs: {api.leaked()}"


def test_splunk_spool_ingests_without_loss(splunk, api: ApiEnv, tmp_path, record_property) -> None:
    """The pulled spool goes through Stage 0-1 with rows in = rows ok = spool rows (no silent drop at ingest)."""
    from ..conftest import accounting, run_ingest

    run = splunk["run"]
    in_splunk = splunk["sp"].count(f"index={ss.INDEX} al_run={run}")   # 499, or 500 after the late-event test
    assert in_splunk in (LATE, N)
    api.client()
    api.put("splunk", splunk_settings(splunk), {"token": splunk["token"]})
    api.start("splunk", {"mode": "events", "since": "2h"})
    wait_until(lambda: len(seqs(api, run)) >= in_splunk, 240, "spool", lambda: api.log("splunk"))
    api.stop("splunk")
    n_lines = len(api.spool_lines("splunk"))
    assert sorted(seqs(api, run)) == list(range(in_splunk))
    record_property("seeded", in_splunk)
    record_property("spool_rows", n_lines)
    ctx = run_ingest(tmp_path / "spool" / "events" / "splunk", tmp_path / "ingest")
    try:
        acc = accounting(ctx)
    finally:
        ctx.con.close()
    record_property("ingest_accounting", acc)
    rows_in = sum(v["rows_in"] for v in acc.values())
    rows_ok = sum(v["rows_ok"] for v in acc.values())
    assert rows_in == n_lines and rows_ok == n_lines, acc


# ============================================================================= auth + TLS messages
def test_splunk_bad_token_gives_actionable_401(splunk, api: ApiEnv) -> None:
    api.client()
    bogus = "bogus-" + uuid.uuid4().hex
    api.put("splunk", splunk_settings(splunk), {"token": bogus})
    t = api.test("splunk")
    assert t["ok"] is False and t["error_code"] == "auth_failed", t
    assert "rejected the credentials (HTTP 401)" in t["message"], t
    assert "check the key, token or secret" in t["message"], t
    assert bogus not in t["message"]


@pytest.mark.parametrize("case", ["verify_no_ca", "verify_with_ca", "no_verify"])
def test_splunk_self_signed_tls(case: str, splunk, api: ApiEnv) -> None:
    api.client()
    if case != "no_verify" and splunk["tls_app_applied"] != "yes":
        pytest.fail("splunk does not serve the test CA's cert: TLS case invalid (see the precondition test)")
    kw = {"verify_no_ca": {"verify_tls": True, "ca_file": None},
          "verify_with_ca": {"verify_tls": True, "ca_file": splunk["sp"].ca_file},
          "no_verify": {"verify_tls": False, "ca_file": None}}[case]
    api.put("splunk", splunk_settings(splunk, **kw), {"token": splunk["token"]})
    t = api.test("splunk")
    if case == "verify_no_ca":
        assert t["ok"] is False and t["error_code"] == "tls_error", t
        assert "not trusted" in t["message"] and "CA file" in t["message"], t
    else:
        assert t["ok"] is True, t


# ============================================================================= HEC sink
def _items(tag: str, n: int = 3) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    from ..test_integrations import _items as base_items

    out = []
    for i, (inc, row) in enumerate(base_items(n)):
        inc, row = copy.deepcopy(inc), dict(row)
        inc["id"] = row["id"] = f"inc-{tag}-{i}"
        out.append((inc, row))
    return out


@pytest.mark.parametrize("ack", [False, True], ids=["ack_off", "ack_on"])
def test_splunk_hec_sink_delivers(ack: bool, splunk, api: ApiEnv, record_property) -> None:
    from attacklens import sinks

    sp = splunk["sp"]
    tag = f"al{uuid.uuid4().hex[:10]}{'a' if ack else 'n'}"
    api.ic["sinks"]["splunk_hec"]["only_changed"] = False
    api.client()
    tok = splunk["hec_ack" if ack else "hec_noack"]
    view = api.put("splunk_hec", {"base_url": sp.hec, "index": ss.SINK_INDEX, "verify_tls": False}, {"token": tok})
    assert view["secrets_set"]["token"] is True
    t = api.test("splunk_hec")            # asserted last: a probe failure must not hide the delivery result
    record_property("api_test", {k: t.get(k) for k in ("ok", "error_code", "message")})
    assert api.start("splunk_hec")["enabled"] is True
    t0 = time.perf_counter()
    res = sinks.publish_all(_items(tag), api.cfg())
    assert res.get("splunk_hec", {}).get("sent") == 3 and res["splunk_hec"]["failed"] == 0, res
    searchable = sp.wait_count(f'index={ss.SINK_INDEX} sourcetype="attacklens:incident" {tag}', 3)
    record_property("sent", 3)
    record_property("indexed", 3)
    record_property("searchable_after_s", searchable)
    record_property("wall_s", round(time.perf_counter() - t0, 1))
    assert t["ok"] is True, f"delivery works, but POST /api/integrations/splunk_hec/test says: {t}"


def test_splunk_hec_sink_verifies_with_ca_file(splunk, api: ApiEnv) -> None:
    """Sink with verify_tls on + ca_file (config key; the sink form has no CA field) delivers over our CA."""
    from attacklens import sinks

    sp = splunk["sp"]
    tag = f"al{uuid.uuid4().hex[:10]}c"
    if splunk["tls_app_applied"] != "yes":
        pytest.fail("HEC does not serve the test CA's cert: ca_file case invalid (see the precondition test)")
    api.ic["sinks"]["splunk_hec"].update(only_changed=False, verify_tls=True, ca_file=sp.ca_file)
    api.client()
    api.put("splunk_hec", {"base_url": sp.hec, "index": ss.SINK_INDEX}, {"token": splunk["hec_noack"]})
    res = sinks.publish_all(_items(tag, 2), api.cfg())
    assert res["splunk_hec"]["sent"] == 2 and res["splunk_hec"]["failed"] == 0, res
    sp.wait_count(f'index={ss.SINK_INDEX} sourcetype="attacklens:incident" {tag}', 2)
