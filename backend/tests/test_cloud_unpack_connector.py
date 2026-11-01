"""aws_cloudtrail S3 mode reuses the Stage 0 unpacker (cloud_unpack): streamed objects, any container, failures
counted (never a silent loss, never a stuck cycle), and org-trail prefixes (gap P2-15)."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
import types
from datetime import datetime, timezone

from tests.test_cloud_connectors import T0, accounted, aws, aws_cfg, base_cfg, ct_event, get, spool_docs  # noqa: F401


def _lm(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


def _recs(i: int, n: int = 2) -> list[dict]:
    return [json.loads(ct_event(i * 10 + j, T0)["CloudTrailEvent"]) for j in range(n)]


def _s3_cfg(base_cfg, tmp_path, prefix: str = "AWSLogs/{yyyy}/{mm}/{dd}/"):
    cfg = aws_cfg(base_cfg, tmp_path)
    cfg["integrations"]["connectors"]["aws_cloudtrail"]["events"].update(source="s3", s3_bucket="trail", s3_prefix=prefix)
    return cfg


def test_aws_s3_objects_go_through_the_unpacker(base_cfg, tmp_path, aws) -> None:
    full = gzip.compress(json.dumps({"Records": _recs(100, 300)}).encode())
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w") as tf:                         # a .json.gz inside a tar
        data = gzip.compress(json.dumps({"Records": _recs(400)}).encode())
        ti = tarfile.TarInfo("x.json.gz")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    aws.objects = {
        "AWSLogs/2026/10/24/plain.json": (_lm(T0 + 60_000), json.dumps({"Records": _recs(2)}).encode()),
        "AWSLogs/2026/10/24/cut.json.gz": (_lm(T0 + 120_000), full[: len(full) // 2]),   # truncated delivery
        "AWSLogs/2026/10/24/bad.json": (_lm(T0 + 150_000), b"<html>not cloudtrail</html>"),
        "AWSLogs/2026/10/24/arch.json.gz": (_lm(T0 + 180_000), tbuf.getvalue()),
    }
    st = get("aws_cloudtrail", _s3_cfg(base_cfg, tmp_path)).cycle()
    accounted(st)
    assert st["ok"], st
    ids = [d["eventID"] for _, d in spool_docs(tmp_path)]
    assert ids[:2] == ["e20", "e21"] and ids[-2:] == ["e4000", "e4001"]
    salvaged = len(ids) - 4
    assert 0 < salvaged < 300 and ids[2:2 + salvaged] == [f"e{1000 + j}" for j in range(salvaged)]
    fr = st["failed_reasons"]
    assert fr.get("truncated_or_corrupt_compressed_data (cut.json.gz)") == 1, fr
    assert any(k.startswith("not_a_json_record") and "bad.json" in k for k in fr), fr


def test_aws_s3_org_trail_prefix_and_member_accounts(base_cfg, tmp_path, aws) -> None:
    from attacklens.connectors.aws_cloudtrail import AwsCloudTrailConnector
    cfg = _s3_cfg(base_cfg, tmp_path, "AWSLogs/o-exampleorg1/{account}/CloudTrail/{region}/{yyyy}/{mm}/{dd}/")
    cfg["integrations"]["connectors"]["aws_cloudtrail"]["events"]["account_id"] = ["111122223333", "444455556666"]
    c = AwsCloudTrailConnector(cfg, "events", T0)
    c.client = lambda service: types.SimpleNamespace(get_caller_identity=lambda: {"Account": "999988887777"})
    assert c._prefixes(T0, T0 + 1) == ["AWSLogs/o-exampleorg1/111122223333/CloudTrail/us-east-1/2026/10/24/",
                                       "AWSLogs/o-exampleorg1/444455556666/CloudTrail/us-east-1/2026/10/24/"]
    key = "AWSLogs/o-exampleorg1/444455556666/CloudTrail/us-east-1/2026/10/24/444455556666_CloudTrail_x.json.gz"
    aws.objects = {key: (_lm(T0 + 60_000), gzip.compress(json.dumps({"Records": _recs(5)}).encode())),
                   key.replace("/CloudTrail/", "/CloudTrail-Digest/"): (_lm(T0 + 60_000), b"{}")}
    st = get("aws_cloudtrail", cfg).cycle()
    accounted(st)
    assert st["ok"] and st["written"] == 2 and [d["eventID"] for _, d in spool_docs(tmp_path)] == ["e50", "e51"]
