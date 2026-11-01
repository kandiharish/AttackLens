"""Seed CloudTrail-format log files into LocalStack S3 (boto3 required: pip install -e "backend[cloud]").

Layout as CloudTrail delivers it: AWSLogs/<account>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/<file>.json.gz, gzip JSON
{"Records": [...]}; plus one plain .json file and one CloudTrail-Digest file (no Records: must yield 0 rows, no error).
"""

from __future__ import annotations

import gzip
import json
import uuid
from datetime import datetime, timezone
from typing import Any

ACCOUNT, REGION, BUCKET = "123456789012", "us-east-1", "al-live-cloudtrail"


def prefix(day: datetime) -> str:
    return f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/{day:%Y/%m/%d}/"


def record(seq: int, ts: datetime, run: str) -> dict[str, Any]:
    return {"eventVersion": "1.09", "eventTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey" if seq % 5 == 0 else "ListUsers", "awsRegion": REGION,
            "sourceIPAddress": f"198.51.100.{seq % 200 + 1}", "userAgent": f"al-live/{run}",
            "userIdentity": {"type": "IAMUser", "userName": f"live-user{seq % 4}", "accountId": ACCOUNT,
                             "arn": f"arn:aws:iam::{ACCOUNT}:user/live-user{seq % 4}"},
            "eventID": str(uuid.UUID(int=seq + 1)), "eventType": "AwsApiCall", "readOnly": seq % 5 != 0,
            "recipientAccountId": ACCOUNT, "requestParameters": {"note": f"al-live seq={seq:05d}"}}


def client(endpoint: str) -> Any:
    import boto3

    return boto3.client("s3", endpoint_url=endpoint, region_name=REGION, aws_access_key_id="test",
                        aws_secret_access_key="test")


def seed(endpoint: str, run: str, files: tuple[int, ...] = (15, 15, 10)) -> dict[str, Any]:
    """-> {bucket, prefix, records, keys}. One gz file per entry of `files` (+ one plain .json of 5 records) + a digest."""
    s3 = client(endpoint)
    s3.create_bucket(Bucket=BUCKET)
    now = datetime.now(timezone.utc)
    p = prefix(now)
    seq, keys = 0, []
    for k, n in enumerate((*files, 5)):
        recs = [record(seq + i, now, run) for i in range(n)]
        seq += n
        body = json.dumps({"Records": recs}).encode()
        gz = k < len(files)
        key = f"{p}{ACCOUNT}_CloudTrail_{REGION}_{now:%Y%m%dT%H%M}Z_al{k:02d}.json" + (".gz" if gz else "")
        s3.put_object(Bucket=BUCKET, Key=key, Body=gzip.compress(body) if gz else body)
        keys.append(key)
    digest = f"AWSLogs/{ACCOUNT}/CloudTrail-Digest/{REGION}/{now:%Y/%m/%d}/{ACCOUNT}_CloudTrail-Digest_x.json.gz"
    s3.put_object(Bucket=BUCKET, Key=digest, Body=gzip.compress(json.dumps(
        {"awsAccountId": ACCOUNT, "digestStartTime": now.isoformat(), "logFiles": []}).encode()))
    return {"bucket": BUCKET, "prefix": p, "records": seq, "keys": keys, "digest": digest}
