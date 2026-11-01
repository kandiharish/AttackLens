"""LocalStack S3 (community) -> AttackLens aws_cloudtrail connector in S3 mode.

CloudTrail-format files are put where CloudTrail delivers them: AWSLogs/<acct>/CloudTrail/<region>/<y>/<m>/<d>/,
three .json.gz + one plain .json (45 records) and one CloudTrail-Digest file (no Records). Not tested: LookupEvents
(the CloudTrail API is not in LocalStack community; it needs a real AWS account).
`ingest_lag: 0s` in the test config: S3 objects are immutable, and the default 5 min lag would hide the freshly
written objects for 5 minutes (they are counted on the next cycle, not lost).

Run: .venv/Scripts/python -m pytest backend/tests/live -m live -k s3 -v   (needs: pip install -e "backend[cloud]")
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Iterator

import pytest

from .conftest import ApiEnv, assert_accounted, json_docs, vendor, wait_until

import livectl  # noqa: E402  (tools/live, on sys.path via conftest)

import s3_seed  # noqa: E402  (imports boto3 lazily)

pytestmark = pytest.mark.live

AK, SK = "test", "test"   # LocalStack accepts any key pair


@pytest.fixture(scope="module")
def localstack() -> Iterator[dict[str, Any]]:
    pytest.importorskip("boto3", reason='boto3 not installed: pip install -e "backend[cloud]"')

    def prepare(st: livectl.Stack) -> None:
        st.ports = {"edge": livectl.free_port()}
        st.env = {"AL_LS_PORT": str(st.ports["edge"])}

    with vendor("localstack", prepare) as st:
        url = f"http://127.0.0.1:{st.ports['edge']}"
        import vhttp

        def s3_ready() -> bool:
            try:
                r = vhttp.req("GET", f"{url}/_localstack/health", timeout=5)
                return r.status == 200 and r.json().get("services", {}).get("s3") in ("running", "available")
            except OSError:
                return False

        wait_until(s3_ready, 180, "localstack s3", st.logs)
        t0 = time.perf_counter()
        seeded = s3_seed.seed(url, uuid.uuid4().hex[:10])
        st.timings["seed_s"] = round(time.perf_counter() - t0, 1)
        yield {"url": url, "stack": st, **seeded}


def _aws(api: ApiEnv, ls: dict[str, Any], **extra: Any) -> None:
    c = api.ic["connectors"]["aws_cloudtrail"]
    c.update(ingest_lag="0s", min_call_interval_s=0, retries=1, timeout_s=15, **extra)


def _settings(ls: dict[str, Any], prefix: str) -> dict[str, Any]:
    return {"region": s3_seed.REGION, "endpoint_url": ls["url"], "events.source": "s3",
            "events.s3_bucket": ls["bucket"], "events.s3_prefix": prefix, "default_since": "24h"}


def _event_ids(api: ApiEnv) -> list[str]:
    return [d.get("eventID") for d in json_docs(api.spool_lines("aws_cloudtrail"))]


@pytest.mark.parametrize("prefix", ["dated", "awslogs_root"])
def test_s3_mode_connector_pulls_every_record(prefix: str, localstack, api: ApiEnv, record_property) -> None:
    """Connector level with s3_endpoint_url in the config: 45 records, unique eventIDs, digest file yields 0."""
    from attacklens import connectors

    p = f"AWSLogs/{s3_seed.ACCOUNT}/CloudTrail/{s3_seed.REGION}/{{yyyy}}/{{mm}}/{{dd}}/" if prefix == "dated" \
        else "AWSLogs/"
    _aws(api, localstack, s3_endpoint_url=localstack["url"])
    api.client()
    api.put("aws_cloudtrail", _settings(localstack, p), {"access_key_id": AK, "secret_access_key": SK})
    conn = connectors.get("aws_cloudtrail", api.cfg(), "events", int(time.time() * 1000) - 3_600_000)
    st = conn.cycle()
    ids = _event_ids(api)
    record_property("seeded", localstack["records"])
    record_property("pulled", st["pulled"])
    record_property("written", st["written"])
    assert st["ok"], st
    assert st["pulled"] == st["written"] == localstack["records"] and st["failed"] == 0, st
    assert len(ids) == len(set(ids)) == localstack["records"] and None not in ids


def test_s3_mode_endpoint_url_from_the_ui_reaches_s3(localstack, api: ApiEnv, record_property) -> None:
    """The form's `endpoint_url` is the only endpoint field a user can set; in S3 mode it must reach the S3 client.
    Asserted BEFORE any network call so a failure never sends the fake keys to real AWS."""
    from attacklens import connectors

    _aws(api, localstack)
    api.client()
    api.put("aws_cloudtrail", _settings(localstack, "AWSLogs/"), {"access_key_id": AK, "secret_access_key": SK})
    conn = connectors.get("aws_cloudtrail", api.cfg(), "events", int(time.time() * 1000) - 3_600_000)
    endpoint = conn.client("s3").meta.endpoint_url
    assert endpoint.rstrip("/") == localstack["url"], (
        f"S3 mode ignores the UI endpoint_url (S3 client goes to {endpoint}); see connectors/aws_cloudtrail.py "
        "client(): endpoint_url is used for cloudtrail only, S3 reads s3_endpoint_url, which the catalog lacks")
    t = api.test("aws_cloudtrail")
    assert t["ok"] is True, t
    assert api.start("aws_cloudtrail", {"mode": "events", "since": "1h"})["running"] is True
    wait_until(lambda: len(_event_ids(api)) >= localstack["records"], 120, "S3 records in the spool",
               lambda: api.log("aws_cloudtrail"))
    time.sleep(3)
    api.stop("aws_cloudtrail")
    ids = _event_ids(api)
    record_property("spool_rows", len(ids))
    assert len(ids) == len(set(ids)) == localstack["records"]
    assert_accounted(api.status("aws_cloudtrail_events"), localstack["records"])
