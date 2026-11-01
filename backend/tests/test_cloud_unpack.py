"""Stage 0 envelope unwrap (attacklens/cloud_unpack.py, gap P0-1): every native cloud delivery wrapper expands to the
same one-record-per-line JSON as the bare records, with nothing lost uncounted."""

from __future__ import annotations

import base64
import copy
import gzip
import io
import json
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from attacklens import cloud_unpack as cu
from attacklens.config import load_config


@pytest.fixture(scope="module")
def ucfg() -> dict[str, Any]:
    return load_config()["unwrap"]


def ct(i: int) -> dict[str, Any]:
    return {"eventVersion": "1.08", "eventTime": f"2026-10-21T11:{i % 60:02d}:00Z", "eventSource": "iam.amazonaws.com",
            "eventName": "ListUsers", "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.11",
            "eventID": f"ev-{i}", "recipientAccountId": "111122223333",
            "userIdentity": {"type": "IAMUser", "userName": "pmehta"}, "requestParameters": {"note": "a\nb \"q\""}}


def az(i: int, typ: str) -> dict[str, Any]:
    return {"TimeGenerated": "2026-10-21T11:00:00Z", "Type": typ, "Id": f"az-{i}", "IPAddress": "192.0.2.11"}


def gcp(i: int) -> dict[str, Any]:
    return {"insertId": f"g{i}", "timestamp": "2026-10-21T11:00:00Z", "labels": {"env": "prod"},
            "protoPayload": {"serviceName": "iam.googleapis.com", "methodName": "SetIamPolicy"}}


def run(tmp: Path, ucfg: dict[str, Any], name: str, data: bytes | str) -> tuple[dict[str, Any], list[Any]]:
    src = tmp / "raw" / name
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_bytes(data.encode() if isinstance(data, str) else data)
    why = cu.classify(src, ucfg)
    assert why, f"{name} must be classified for unwrapping"
    res = cu.unpack_file(src, tmp / "out" / f"{name}.unwrapped", ucfg, why)
    out: list[Any] = []
    for p in res["outputs"]:
        for line in Path(p).read_text(encoding="utf-8").splitlines():
            out.append(json.loads(line) if p.endswith(".jsonl") else line)
    return res, out


def gz(b: bytes | str) -> bytes:
    return gzip.compress(b.encode() if isinstance(b, str) else b)


def tar(members: dict[str, bytes], mode: str = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for n, d in members.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


RECS = [ct(i) for i in range(5)]
DOC = json.dumps({"Records": RECS})


# ----------------------------------------------------------------------------- CloudTrail Records, containers
@pytest.mark.parametrize("name,data", [
    ("ct.json", DOC),
    ("ct_pretty.json", json.dumps({"Records": RECS}, indent=2)),
    ("ct.json.gz", gz(DOC)),
    ("ct_noext", gz(DOC)),                                                           # magic bytes, not extension
    ("ct.tar", tar({"AWSLogs/1/CloudTrail/a.json.gz": gz(DOC), "AWSLogs/1/CloudTrail/b.json": DOC.encode()})),
    ("ct.tar.gz", gz(tar({"a.json": DOC.encode()}))),
])
def test_cloudtrail_records_in_every_container(tmp_path, ucfg, name, data) -> None:
    res, out = run(tmp_path, ucfg, name, data)
    n = 2 if name == "ct.tar" else 1
    assert out == RECS * n and res["records_out"] == 5 * n, res
    assert not res["failed"] and res["envelopes"]["Records"] == n


def test_zip_and_nested_zip_in_tar(tmp_path, ucfg) -> None:
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("x/ct.json", DOC)
        zf.writestr("x/ct2.json.gz", gz(DOC))
    res, out = run(tmp_path, ucfg, "ct.zip", zbuf.getvalue())
    assert out == RECS * 2 and res["containers"]["zip"] == 1 and not res["failed"]
    res, out = run(tmp_path, ucfg, "nested.tar", tar({"inner.zip": zbuf.getvalue()}))
    assert out == RECS * 2 and res["containers"]["zip"] == 1 and res["containers"]["tar"] == 1
    xbuf = io.BytesIO()
    with zipfile.ZipFile(xbuf, "w") as zf:                                        # an .xlsx is a zip too
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("xl/workbook.xml", "<workbook/>")
    res, out = run(tmp_path, ucfg, "book.xlsx", xbuf.getvalue())
    assert out == [] and res["skipped"] == {"office_document": 1}


def test_empty_records_and_digest_are_counted_not_lost(tmp_path, ucfg) -> None:
    res, out = run(tmp_path, ucfg, "empty.json.gz", gz('{"Records": []}'))
    assert out == [] and res["records_out"] == 0 and res["notes"]["empty_envelopes"] == 1 and not res["failed"]
    digest = {"awsAccountId": "1", "digestStartTime": "2026-10-21T10:00:00Z", "digestEndTime": "x",
              "digestS3Bucket": "b", "logFiles": []}
    res, out = run(tmp_path, ucfg, "digest.json.gz", gz(json.dumps(digest)))
    assert out == [] and res["skipped"] == {"cloudtrail_digest": 1}


# ----------------------------------------------------------------------------- other providers / shapes
def test_azure_records_split_by_type(tmp_path, ucfg) -> None:
    lines = "\n".join(json.dumps({"records": [az(i, t) for i, t in enumerate(["SigninLogs", "AuditLogs"] * 2)]})
                      for _ in range(2))
    res, out = run(tmp_path, ucfg, "eventhub.json", lines)
    assert res["records_out"] == 8 and len(out) == 8 and res["envelopes"]["records"] == 2
    files = sorted(Path(p).name for p in res["outputs"])
    assert files == ["auditlogs-0001.jsonl", "signinlogs-0001.jsonl"]          # one source type per file


def test_long_first_line_batch_is_still_classified(tmp_path, ucfg) -> None:
    batch = json.dumps({"records": [az(i, "SigninLogs") for i in range(2000)]})   # one line > sniff_bytes
    p = tmp_path / "hub.json"
    p.write_text(batch + "\n" + batch + "\n", encoding="utf-8")
    assert len(batch) > ucfg["sniff_bytes"] and cu.classify(p, ucfg) == "records"


def test_json_array_and_api_pages(tmp_path, ucfg) -> None:
    _, out = run(tmp_path, ucfg, "arr.json", json.dumps([gcp(i) for i in range(3)], indent=1))
    assert out == [gcp(i) for i in range(3)]                                  # GCP `labels` kept untouched
    _, out = run(tmp_path, ucfg, "page.json", json.dumps({"entries": [gcp(1), gcp(2)], "nextPageToken": "t"}))
    assert out == [gcp(1), gcp(2)]
    page = {"kind": "admin#reports#activities", "items": [{"id": {"time": "t"}, "events": [{"name": "login"}]}]}
    _, out = run(tmp_path, ucfg, "items.json", json.dumps(page))
    assert out == page["items"]


def test_record_with_an_envelope_key_but_foreign_siblings_is_a_record(tmp_path, ucfg) -> None:
    rec = {"eventTime": "t", "items": [{"a": 1}], "eventName": "x"}
    p = tmp_path / "bare.jsonl"
    p.write_text(json.dumps(rec) + "\n", encoding="utf-8")
    assert cu.classify(p, ucfg) is None                                         # passthrough, never unwrapped


def test_eventbridge_detail_lifted(tmp_path, ucfg) -> None:
    ev = [{"version": "0", "id": f"e{i}", "detail-type": "AWS API Call via CloudTrail", "source": "aws.iam",
           "account": "111122223333", "time": "t", "region": "us-east-1", "resources": [], "detail": ct(i)}
          for i in range(3)]
    ev.append({"version": "0", "detail-type": "GuardDuty Finding", "source": "aws.guardduty", "detail": {"id": "f"}})
    ev.append({"version": "0", "detail-type": "Scheduled Event", "source": "aws.events", "detail": {}})
    res, out = run(tmp_path, ucfg, "eb.jsonl", "\n".join(json.dumps(e) for e in ev))
    assert out[:3] == [ct(i) for i in range(3)] and out[3] == {"id": "f"}
    assert res["skipped"] == {"eventbridge_empty_detail": 1}
    assert sorted(Path(p).name for p in res["outputs"]) == ["cloudtrail-0001.jsonl", "eb_aws_guardduty-0001.jsonl"]


def cwl(msgs: list[str], mtype: str = "DATA_MESSAGE") -> dict[str, Any]:
    return {"messageType": mtype, "owner": "111122223333", "logGroup": "aws-cloudtrail-logs", "logStream": "s",
            "subscriptionFilters": ["f"], "logEvents": [{"id": str(i), "timestamp": 0, "message": m}
                                                        for i, m in enumerate(msgs)]}


def test_cloudwatch_subscription_payloads(tmp_path, ucfg) -> None:
    data = cwl([json.dumps(ct(1)), json.dumps(ct(2)), "plain text line"])
    lam = {"awslogs": {"data": base64.b64encode(gz(json.dumps(data))).decode()}}
    res, out = run(tmp_path, ucfg, "lambda.json", json.dumps(lam))
    assert out == [ct(1), ct(2), "plain text line"] and res["records_out"] == 2 and res["text_lines_out"] == 1
    # Firehose -> S3: concatenated gzip members, each a payload document without separators; one CONTROL_MESSAGE
    fire = gz(json.dumps(data)) + gz(json.dumps(cwl(["CWL CONTROL MESSAGE"], "CONTROL_MESSAGE"))) + \
        gz(json.dumps(cwl([json.dumps(ct(3))])))
    res, out = run(tmp_path, ucfg, "firehose", fire)
    assert [o for o in out if isinstance(o, dict)] == [ct(1), ct(2), ct(3)]
    assert res["skipped"] == {"cloudwatch_control_message": 2} and not res["failed"]


def test_pubsub_push_and_pull(tmp_path, ucfg) -> None:
    push = [{"message": {"data": base64.b64encode(json.dumps(gcp(i)).encode()).decode(), "messageId": str(i),
                         "attributes": {"logging.googleapis.com/timestamp": "t"}}, "subscription": "s"}
            for i in range(3)]
    res, out = run(tmp_path, ucfg, "push.jsonl", "\n".join(json.dumps(p) for p in push))
    assert out == [gcp(i) for i in range(3)] and res["envelopes"]["base64:message.data"] == 3
    pull = {"receivedMessages": [{"ackId": "a", "message": push[0]["message"]}]}
    _, out = run(tmp_path, ucfg, "pull.json", json.dumps(pull))
    assert out == [gcp(0)]


def test_lookup_events_string_records(tmp_path, ucfg) -> None:
    page = {"Events": [{"EventId": f"ev-{i}", "EventName": "ListUsers", "CloudTrailEvent": json.dumps(ct(i))}
                       for i in range(3)] + [{"EventId": "bad", "CloudTrailEvent": "{not json"}], "NextToken": "n"}
    res, out = run(tmp_path, ucfg, "lookup.json", json.dumps(page))
    assert out == [ct(i) for i in range(3)] and res["failed"] == {"malformed_json_string": 1}


# ----------------------------------------------------------------------------- malformed / truncated input
def test_bad_line_in_envelope_jsonl_resyncs(tmp_path, ucfg) -> None:
    lines = [json.dumps({"Records": [ct(1)]}), '{"Records": [ {"eventID": oops}]}', json.dumps({"Records": [ct(2)]})]
    res, out = run(tmp_path, ucfg, "lines.json", "\n".join(lines))
    assert out == [ct(1), ct(2)] and res["failed"] == {"malformed_json": 1}, res


def test_truncated_document_salvages_records_before_the_cut(tmp_path, ucfg) -> None:
    doc = json.dumps({"Records": RECS}, indent=2)
    res, out = run(tmp_path, ucfg, "cut.json", doc[: doc.index('"ev-3"')])
    assert out == RECS[:3] and res["failed"] == {"truncated_json": 1} and res["notes"]["documents_cut_short"] == 1


def test_truncated_gzip_is_reported(tmp_path, ucfg) -> None:
    big = json.dumps({"Records": [ct(i) for i in range(3000)]})
    data = gz(big)
    res, out = run(tmp_path, ucfg, "cut.json.gz", data[: len(data) // 2])
    assert 0 < len(out) < 3000 and out == [ct(i) for i in range(len(out))]
    assert res["failed"].get("truncated_or_corrupt_compressed_data") == 1, res


def test_garbage_and_too_deep(tmp_path, ucfg) -> None:
    res, out = run(tmp_path, ucfg, "garbage.json", "[1, 2, {\"a\": }]")
    assert res["failed"] and res["records_out"] == 0
    deep: Any = ct(0)
    for _ in range(10):
        deep = [deep]
    res, out = run(tmp_path, ucfg, "deep.json", json.dumps(deep))
    assert out == [] and res["failed"] == {"nesting_too_deep": 1}


def test_gzip_bomb_guard(tmp_path, ucfg) -> None:
    cfg = {**copy.deepcopy(ucfg), "max_expand_ratio": 5, "min_bomb_bytes": 10_000}
    bomb = gz(b"[" + b" " * 5_000_000 + b"]")
    res, out = run(tmp_path, cfg, "bomb.json.gz", bomb)
    assert out == [] and res["failed"] == {"decompression_limit (zip / gzip bomb guard)": 1}


def test_zip_bomb_declared_size_rejected_before_reading(tmp_path, ucfg) -> None:
    cfg = {**copy.deepcopy(ucfg), "max_expand_ratio": 5, "min_bomb_bytes": 10_000}
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.json", b" " * 2_000_000)
        zf.writestr("ok.json", DOC)
    res, out = run(tmp_path, cfg, "bomb.zip", zbuf.getvalue())
    assert out == RECS and res["failed"] == {"decompression_limit (zip / gzip bomb guard)": 1}


# ----------------------------------------------------------------------------- tree / CLI
def test_unpack_tree_mirrors_and_accounts(tmp_path, ucfg) -> None:
    raw = tmp_path / "raw"
    (raw / "aws").mkdir(parents=True)
    (raw / "ground_truth").mkdir()
    (raw / "aws" / "bare.jsonl").write_text("\n".join(json.dumps(r) for r in RECS) + "\n", encoding="utf-8")
    (raw / "aws" / "trail.json.gz").write_bytes(gz(DOC))
    (raw / "ground_truth" / "attacks.json").write_text('{"attacks": []}', encoding="utf-8")
    out = tmp_path / "unpacked"
    rc = cu.main(["--raw", str(raw), "--out", str(out)])
    assert rc == 0
    assert (out / "aws" / "bare.jsonl").read_bytes() == (raw / "aws" / "bare.jsonl").read_bytes()
    assert (out / "ground_truth" / "attacks.json").exists() and not (out / "aws" / "trail.json.gz").exists()
    acc = json.loads((out / ".unwrap" / "accounting.json").read_text(encoding="utf-8"))
    assert acc["totals"]["records_out"] == 5 and acc["totals"]["files_passthrough"] == 2
    assert [f["path"] for f in acc["files"]] == ["aws/trail.json.gz"]
    assert cu.find_accounting(out, tmp_path / "o") == acc
    assert cu.accounting_entry(acc) is None                                    # nothing failed or skipped
    with pytest.raises(ValueError):
        cu.unpack_tree(raw, raw / "x", ucfg)


def test_failures_reach_ingest_accounting(tmp_path, ucfg) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "lines.json").write_text(json.dumps({"Records": [ct(1)]}) + '\n{"Records": [oops]}\n', encoding="utf-8")
    (raw / "d.json").write_text(json.dumps({"digestStartTime": "t", "digestS3Bucket": "b"}), encoding="utf-8")
    mapping, acc = cu.stage(raw, tmp_path / "stage", ucfg)
    assert set(mapping) == {raw / "lines.json", raw / "d.json"} and mapping[raw / "d.json"] == []
    e = cu.accounting_entry(acc)
    assert e is not None and e["source_type"] == "envelope_unwrap"
    assert (e["rows_in"], e["dropped"], e["drop_reasons"]) == (1, 1, {"malformed_json (envelope unwrap)": 1})
    assert e["notes"]["skipped_cloudtrail_digest (not an event record)"] == 1
    assert e["notes"]["records_out (unwrapped, counted under their source type)"] == 1
    assert sorted(e["files"]) == ["d.json", "lines.json"]


# ----------------------------------------------------------------------------- bounded memory
_MEM_CHILD = """
import json, os, sys
from pathlib import Path
import psutil
from attacklens import cloud_unpack as cu
from attacklens.config import load_config
src, out, n = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
rec = '{"eventTime":"2026-10-21T11:00:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject",' \
      '"requestParameters":{"bucketName":"corp-artifacts","key":"images/layer-%08d","pad":"%s"},"eventID":"%d"}'
with src.open("w", encoding="utf-8") as fh:  # written in slices: the child never holds the document
    fh.write('{"Records": [')
    for i in range(n):
        fh.write(("," if i else "") + rec % (i, "x" * 200, i))
    fh.write("]}")
proc = psutil.Process()
def peak():
    mi = proc.memory_info()
    return getattr(mi, "peak_wset", None) or mi.rss
ucfg = load_config()["unwrap"]
before = peak()
res = cu.unpack_file(src, out, ucfg, "Records")
after = peak()
if not hasattr(proc.memory_info(), "peak_wset"):
    import resource
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
print(json.dumps({"size": src.stat().st_size, "grow": after - before, "records_out": res["records_out"],
                  "failed": res["failed"], "lines": sum(1 for _ in open(res["outputs"][0], encoding="utf-8"))}))
"""


def test_200k_record_document_streams_in_bounded_memory(tmp_path) -> None:
    """A single 75 MB {"Records": [...]} document (200k records) unpacks with peak memory growth far below the
    document size: O(chunk + one record), never O(document). Measured in a child process (peak working set)."""
    import subprocess
    import sys
    n = 200_000
    r = subprocess.run([sys.executable, "-c", _MEM_CHILD, str(tmp_path / "huge.json"), str(tmp_path / "out"), str(n)],
                       capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr[-2000:]
    m = json.loads(r.stdout.strip().splitlines()[-1])
    assert m["records_out"] == n == m["lines"] and not m["failed"], m
    assert m["size"] > 70_000_000 and m["grow"] < 32_000_000, m                 # bounded, not O(document)
