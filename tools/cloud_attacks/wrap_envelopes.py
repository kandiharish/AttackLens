"""Re-wrap a cloud set's one-record-per-line files into the native cloud delivery envelopes (gap P0-1 measurement).

    python tools/cloud_attacks/wrap_envelopes.py --src data/raw/cloud_small --out data/raw/cloud_envelopes

Every source record lands in exactly one envelope (the source set is only read, never modified), so the unwrapped
set must score exactly like the source set. Shapes:
  CloudTrail  org-trail S3 keys AWSLogs/<org>/<acct>/CloudTrail/<region>/yyyy/mm/dd/*.json.gz {"Records"}, a .tar of
              those (flaws.cloud style), EventBridge JSONL (.gz), CloudWatch Logs -> Firehose (concatenated gzip
              subscription payloads incl. CONTROL_MESSAGE), LookupEvents pages (CloudTrailEvent strings), digests,
              an empty {"Records": []}
  Azure       Event Hub JSONL {"records": [...]} batches mixing SignIn / Audit / Activity, diagnostic export
              {"records"} pretty JSON inside a .zip
  GCP         Pub/Sub push JSONL (base64 LogEntry), entries.list pages, a JSON array .json.gz
"""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import json
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Iterator

ORG, ACCT, REGION = "o-exampleorg1", "111122223333", "us-east-1"


def records(path: Path) -> list[str]:
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def chunks(xs: list[Any], n: int) -> Iterator[list[Any]]:
    for i in range(0, len(xs), n):
        yield xs[i:i + n]


def doc(lines: list[str], key: str = "Records") -> str:
    return '{"%s": [%s]}' % (key, ", ".join(lines))  # the records' own text, byte for byte


def cloudtrail(src: Path, out: Path) -> dict[str, int]:
    parts = sorted((src / "aws_cloudtrail").rglob("*.jsonl"))
    lines = [ln for p in parts for ln in records(p)]
    n = len(lines)
    a, b, c, d, e = lines[: n * 4 // 10], lines[n * 4 // 10: n * 6 // 10], lines[n * 6 // 10: n * 75 // 100], \
        lines[n * 75 // 100: n * 9 // 10], lines[n * 9 // 10:]
    s3 = out / "aws" / "AWSLogs" / ORG / ACCT / "CloudTrail" / REGION
    for i, ch in enumerate(chunks(a, 400)):
        day = json.loads(ch[0])["eventTime"][:10].split("-")
        p = s3 / day[0] / day[1] / day[2] / f"{ACCT}_CloudTrail_{REGION}_{i:04d}.json.gz"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(gzip.compress(doc(ch).encode()))
    dg = out / "aws" / "AWSLogs" / ORG / ACCT / "CloudTrail-Digest" / REGION / "2026" / "10" / "21"
    dg.mkdir(parents=True, exist_ok=True)
    (dg / f"{ACCT}_CloudTrail-Digest_{REGION}_0001.json.gz").write_bytes(gzip.compress(json.dumps(
        {"awsAccountId": ACCT, "digestStartTime": "2026-10-21T00:00:00Z", "digestEndTime": "2026-10-21T01:00:00Z",
         "digestS3Bucket": "trail", "digestS3Object": "x", "logFiles": []}).encode()))
    (s3 / "2026" / "10" / "19").mkdir(parents=True, exist_ok=True)
    (s3 / "2026" / "10" / "19" / f"{ACCT}_CloudTrail_{REGION}_empty.json.gz").write_bytes(
        gzip.compress(b'{"Records":[]}'))
    buf = io.BytesIO()                                                    # flaws.cloud-style tar of .json.gz
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for i, ch in enumerate(chunks(b, 500)):
            data = gzip.compress(doc(ch).encode())
            ti = tarfile.TarInfo(f"flaws_cloudtrail_logs/{ACCT}_CloudTrail_{REGION}_{i:04d}.json.gz")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    (out / "aws" / "archive").mkdir(parents=True, exist_ok=True)
    (out / "aws" / "archive" / "flaws_cloudtrail_logs.tar").write_bytes(buf.getvalue())
    eb = [json.dumps({"version": "0", "id": f"eb-{i}", "detail-type": "AWS API Call via CloudTrail",
                      "source": "aws." + json.loads(ln)["eventSource"].split(".")[0], "account": ACCT,
                      "time": json.loads(ln)["eventTime"], "region": REGION, "resources": [],
                      "detail": json.loads(ln)}) for i, ln in enumerate(c)]
    (out / "aws" / "eventbridge").mkdir(parents=True, exist_ok=True)
    (out / "aws" / "eventbridge" / "firehose-eb-0001.jsonl.gz").write_bytes(gzip.compress("\n".join(eb).encode()))
    fire = b""                                                           # CloudWatch Logs -> Firehose -> S3
    for i, ch in enumerate(chunks(d, 250)):
        payload = {"messageType": "DATA_MESSAGE", "owner": ACCT, "logGroup": "aws-cloudtrail-logs-org",
                   "logStream": f"{ACCT}_CloudTrail_{REGION}", "subscriptionFilters": ["to-firehose"],
                   "logEvents": [{"id": str(i * 1000 + j), "timestamp": 0, "message": ln} for j, ln in enumerate(ch)]}
        fire += gzip.compress(json.dumps(payload).encode())
        if i == 0:
            fire += gzip.compress(json.dumps({"messageType": "CONTROL_MESSAGE", "owner": "CloudwatchLogs",
                                              "logGroup": "", "logStream": "", "subscriptionFilters": [],
                                              "logEvents": [{"id": "c", "timestamp": 0,
                                                             "message": "CWL CONTROL MESSAGE: Checking health"}]}
                                             ).encode())
    (out / "aws" / "cwl").mkdir(parents=True, exist_ok=True)
    (out / "aws" / "cwl" / "firehose-cwl-2026-10-21-0001").write_bytes(fire)
    look = out / "aws" / "lookup"
    look.mkdir(parents=True, exist_ok=True)
    for i, ch in enumerate(chunks(e, 50)):
        evs = [{"EventId": json.loads(ln)["eventID"], "EventName": json.loads(ln)["eventName"], "ReadOnly": "true",
                "EventTime": json.loads(ln)["eventTime"], "EventSource": json.loads(ln)["eventSource"],
                "Resources": [], "CloudTrailEvent": ln} for ln in ch]
        (look / f"lookup-events-{i:04d}.json").write_text(json.dumps({"Events": evs, "NextToken": f"t{i}"}, indent=2),
                                                          encoding="utf-8")
    return {"cloudtrail_records": n}


def azure(src: Path, out: Path) -> dict[str, int]:
    base = src / "azure_monitor"
    hub = [ln for b in ("azure_signinlogs", "azure_auditlogs", "azure_azureactivity")
           for p in sorted((base / b).glob("*.jsonl")) for ln in records(p)]
    hub.sort(key=lambda ln: json.loads(ln).get("TimeGenerated", ""))      # one stream, categories interleaved
    (out / "azure" / "eventhub").mkdir(parents=True, exist_ok=True)
    (out / "azure" / "eventhub" / "hub-capture-0001.json").write_text(
        "\n".join(doc(ch, "records") for ch in chunks(hub, 100)) + "\n", encoding="utf-8")
    blob = [json.loads(ln) for p in sorted((base / "azure_storagebloblogs").glob("*.jsonl")) for ln in records(p)]
    zb = io.BytesIO()
    with zipfile.ZipFile(zb, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, ch in enumerate(chunks(blob, 1000)):
            zf.writestr(f"insights-logs-storageread/PT1H-{i:04d}.json", json.dumps({"records": ch}, indent=2))
    (out / "azure" / "export").mkdir(parents=True, exist_ok=True)
    (out / "azure" / "export" / "storage-diagnostics.zip").write_bytes(zb.getvalue())
    return {"azure_records": len(hub) + len(blob)}


def gcp(src: Path, out: Path) -> dict[str, int]:
    lines = [ln for p in sorted((src / "gcp_logging").rglob("*.jsonl")) for ln in records(p)]
    n = len(lines)
    a, b, c = lines[: n // 2], lines[n // 2: n * 3 // 4], lines[n * 3 // 4:]
    (out / "gcp").mkdir(parents=True, exist_ok=True)
    push = [json.dumps({"message": {"data": base64.b64encode(ln.encode()).decode(), "messageId": str(i),
                                    "publishTime": "2026-10-21T00:00:00Z",
                                    "attributes": {"logging.googleapis.com/timestamp": json.loads(ln)["timestamp"]}},
                        "subscription": "projects/corp-prod-1234/subscriptions/attacklens"}) for i, ln in enumerate(a)]
    (out / "gcp" / "pubsub-push-0001.jsonl").write_text("\n".join(push) + "\n", encoding="utf-8")
    for i, ch in enumerate(chunks(b, 1000)):
        (out / "gcp" / f"entries-list-{i:04d}.json").write_text(json.dumps(
            {"entries": [json.loads(ln) for ln in ch], "nextPageToken": f"p{i}"}, indent=2), encoding="utf-8")
    (out / "gcp" / "gcloud-logging-read.json.gz").write_bytes(gzip.compress(("[" + ",\n".join(c) + "]").encode()))
    return {"gcp_records": n}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--src", default="data/raw/cloud_small")
    ap.add_argument("--out", default="data/raw/cloud_envelopes")
    a = ap.parse_args(argv)
    src, out = Path(a.src), Path(a.out)
    if out.resolve() == src.resolve():
        raise SystemExit("--out must differ from --src")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    counts = {**cloudtrail(src, out), **azure(src, out), **gcp(src, out)}
    shutil.copytree(src / "ground_truth", out / "ground_truth")
    shutil.copy2(src / "manifest.json", out / "manifest.json")
    (out / "ground_truth" / "envelopes.json").write_text(json.dumps({"source": src.as_posix(), **counts}, indent=1),
                                                         encoding="utf-8")
    print(json.dumps(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
