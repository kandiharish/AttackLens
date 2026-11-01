"""Mock AWS endpoints for tools/mock_siem.py (stdlib only); state in mock_cloud.CloudState.

  CloudTrail  POST /  X-Amz-Target: com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents
              JSON 1.1 body {StartTime, EndTime (epoch seconds or ISO), MaxResults 1..50, NextToken,
              LookupAttributes (max 1)} -> {"Events": [... CloudTrailEvent = JSON string], "NextToken"?}
              management events only, NEWEST FIRST (as AWS); StartTime/EndTime inclusive; NextToken bound to the query
  S3          GET /{bucket}?list-type=2[&prefix=&continuation-token=&start-after=&max-keys=]  ListObjectsV2 XML
              GET /{bucket}/{key}   gzip {"Records": [...]} (management + data events), one object per 5 minutes,
              key AWSLogs/<acct>/CloudTrail/<region>/YYYY/MM/DD/<acct>_CloudTrail_<region>_YYYYMMDDTHHMMZ_<id>.json.gz
              served as application/x-gzip WITHOUT Content-Encoding: the reader gunzips by the .gz suffix.
SigV4 is NOT verified. Required: `Authorization: AWS4-HMAC-SHA256 Credential=<AKID>/<date>/<region>/<service>/
aws4_request, SignedHeaders=..., Signature=...` with service cloudtrail / s3, plus X-Amz-Date (and for S3
x-amz-content-sha256). The AKID must match only when aws_access_key_id is configured.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

import mock_cloud_seed as seed
from mock_cloud import page_token, read_token
from mock_siem_store import parse_iso_ms

TARGET_PREFIX = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101."
LOOKUP_KEYS = {"EventId": "eventID", "EventName": "eventName", "ReadOnly": "readOnly", "Username": None,
               "EventSource": "eventSource", "AccessKeyId": None, "ResourceType": None, "ResourceName": None}
_SIG = re.compile(r"^AWS4-HMAC-SHA256 Credential=([^/,\s]+)/(\d{8})/([\w-]+)/([\w-]+)/aws4_request,\s*"
                  r"SignedHeaders=[\w;-]+,\s*Signature=[0-9a-f]+$")
FILE_WINDOW_MS = 5 * 60_000


def sigv4_error(h: Any, service: str) -> tuple[int, str, str] | None:
    """(status, code, message) when the request is not SigV4-shaped for `service`, else None."""
    authz = h.headers.get("Authorization", "")
    if not authz:
        return 403 if service == "s3" else 400, "MissingAuthenticationTokenException" if service != "s3" \
            else "AccessDenied", "Missing Authentication Token"
    mm = _SIG.match(authz)
    if not mm:
        return 400, "IncompleteSignatureException", "Authorization header requires 'Credential', " \
            "'Signature' and 'SignedHeaders' parameters with algorithm AWS4-HMAC-SHA256."
    if not h.headers.get("X-Amz-Date"):
        return 400, "IncompleteSignatureException", "Authorization header requires existence of either a " \
            "'X-Amz-Date' or a 'Date' header."
    if mm.group(4) != service:
        return 403, "InvalidSignatureException", f"Credential should be scoped to correct service: '{service}'."
    want = h.m.cloud.aws_access_key_id
    if want is not None and mm.group(1) != want:
        return (403, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.") \
            if service == "s3" else (400, "UnrecognizedClientException",
                                     "The security token included in the request is invalid.")
    if service == "s3" and not h.headers.get("x-amz-content-sha256"):
        return 400, "InvalidRequest", "Missing required header for this request: x-amz-content-sha256"
    return None


def _ct_err(h: Any, status: int, code: str, msg: str) -> None:
    h._send(status, {"__type": code, "message": msg}, ctype="application/x-amz-json-1.1")


def _epoch_ms(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(round(v * 1000))
    return parse_iso_ms(str(v))


def _username(rec: dict[str, Any]) -> str | None:
    ui = rec.get("userIdentity") or {}
    return ui.get("userName") or (ui.get("arn") or "").rsplit("/", 1)[-1] or None


def _resources(rec: dict[str, Any]) -> list[dict[str, str]]:
    rp = rec.get("requestParameters") or {}
    out = []
    if rec.get("eventSource") == "iam.amazonaws.com" and rp.get("userName"):
        out.append({"ResourceType": "AWS::IAM::User", "ResourceName": rp["userName"]})
    if rp.get("policyArn"):
        out.append({"ResourceType": "AWS::IAM::Policy", "ResourceName": rp["policyArn"]})
    if rp.get("bucketName"):
        out.append({"ResourceType": "AWS::S3::Bucket", "ResourceName": rp["bucketName"]})
    return out


def lookup_event(rec: dict[str, Any]) -> dict[str, Any]:
    ev = {"EventId": rec["eventID"], "EventName": rec["eventName"], "ReadOnly": str(rec["readOnly"]).lower(),
          "EventTime": (_epoch_ms(rec["eventTime"]) or 0) / 1000, "EventSource": rec["eventSource"],
          "Username": _username(rec), "Resources": _resources(rec),
          "CloudTrailEvent": json.dumps(rec, separators=(",", ":"))}
    akid = (rec.get("userIdentity") or {}).get("accessKeyId")
    if akid:
        ev["AccessKeyId"] = akid
    return ev


def _attr_ok(rec: dict[str, Any], key: str, val: str) -> bool:
    if key == "Username":
        return _username(rec) == val
    if key == "AccessKeyId":
        return (rec.get("userIdentity") or {}).get("accessKeyId") == val
    if key in ("ResourceType", "ResourceName"):
        return any(r[key] == val for r in _resources(rec))
    got = rec.get(LOOKUP_KEYS[key])
    return (str(got).lower() if isinstance(got, bool) else str(got)) == val


def cloudtrail(h: Any, body: bytes) -> None:
    m, c = h.m, h.m.cloud
    target = h.headers.get("X-Amz-Target", "")
    if h.command != "POST" or not target.startswith(TARGET_PREFIX):
        return _ct_err(h, 400, "UnknownOperationException", f"Unknown operation {target}")
    err = sigv4_error(h, "cloudtrail")
    if err:
        return _ct_err(h, *err)
    if target[len(TARGET_PREFIX):] != "LookupEvents":
        return _ct_err(h, 400, "UnknownOperationException", f"mock: only LookupEvents is served, not {target}")
    try:
        req = json.loads(body or b"{}")
    except ValueError:
        return _ct_err(h, 400, "SerializationException", "invalid JSON body")
    now = m.now_ms()
    hi = _epoch_ms(req["EndTime"]) if req.get("EndTime") is not None else now
    lo = _epoch_ms(req["StartTime"]) if req.get("StartTime") is not None else hi - 90 * 86_400_000
    if lo is None or hi is None:
        return _ct_err(h, 400, "SerializationException", "StartTime/EndTime must be epoch seconds or ISO 8601")
    if lo > hi:
        return _ct_err(h, 400, "InvalidTimeRangeException", "Start time must be before end time.")
    size = req.get("MaxResults", 50)
    if not isinstance(size, int) or not 1 <= size <= 50:
        return _ct_err(h, 400, "InvalidMaxResultsException", "MaxResults must be between 1 and 50.")
    attrs = req.get("LookupAttributes") or []
    if len(attrs) > 1 or any(a.get("AttributeKey") not in LOOKUP_KEYS for a in attrs):
        return _ct_err(h, 400, "InvalidLookupAttributesException",
                       "You can specify at most one lookup attribute, with a supported AttributeKey.")
    qkey = {"lo": lo, "hi": hi, "a": attrs}
    off = 0
    if req.get("NextToken"):
        o = read_token(str(req["NextToken"]), qkey)
        if o is None:
            return _ct_err(h, 400, "InvalidNextTokenException", "Invalid NextToken.")
        off = o
    items = [it for it in c.visible("CloudTrail") if not it.s3_only and lo <= it.ts_ms <= hi
             and all(_attr_ok(it.doc, a["AttributeKey"], str(a.get("AttributeValue", ""))) for a in attrs)]
    items.sort(key=lambda it: (it.ts_ms, it.rid), reverse=True)                 # newest first
    page = items[off:off + size]
    out: dict[str, Any] = {"Events": [lookup_event(it.doc) for it in page]}
    if off + size < len(items):
        out["NextToken"] = page_token(off + size, qkey)
    with m.lock:
        m.served["cloudtrail_lookup"] += len(page)
    h._send(200, out, ctype="application/x-amz-json-1.1")


# ====================================================================== S3 trail files
def trail_objects(c: Any) -> dict[str, bytes]:
    """key -> gzip bytes; one object per 5-minute delivery window of the CloudTrail feed (current visibility)."""
    with c.lock:
        n = c.queries["CloudTrail"]
        items = [it for it in c.seed.feeds["CloudTrail"] if it.visible_after <= n]
    groups: dict[int, list[Any]] = {}
    for it in items:
        groups.setdefault(it.ts_ms // FILE_WINDOW_MS, []).append(it)
    out = {}
    for w, its in sorted(groups.items()):
        d = datetime.fromtimestamp(w * FILE_WINDOW_MS / 1000 + 300, tz=timezone.utc)
        uid = hashlib.sha256(f"{w}".encode()).hexdigest()[:16].upper()
        key = (f"AWSLogs/{seed.ACCOUNT}/CloudTrail/{seed.REGION}/{d:%Y/%m/%d}/"
               f"{seed.ACCOUNT}_CloudTrail_{seed.REGION}_{d:%Y%m%dT%H%M}Z_{uid}.json.gz")
        data = json.dumps({"Records": [it.doc for it in sorted(its, key=lambda x: (x.ts_ms, x.rid))]}).encode()
        out[key] = gzip.compress(data, mtime=0)
    return out


def _key_time(key: str) -> str:
    t = re.search(r"_(\d{8}T\d{4})Z_", key)
    return datetime.strptime(t.group(1), "%Y%m%dT%H%M").strftime("%Y-%m-%dT%H:%M:00.000Z") if t else ""


def _s3_err(h: Any, status: int, code: str, msg: str, resource: str = "") -> None:
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>{code}</Code><Message>{escape(msg)}</Message>'
           f"<Resource>{escape(resource)}</Resource><RequestId>MOCKREQUEST0001</RequestId></Error>")
    h._send(status, xml.encode(), ctype="application/xml")


def s3(h: Any, path: str, params: dict[str, str]) -> None:
    c = h.m.cloud
    err = sigv4_error(h, "s3")
    if err:
        st, code, msg = err
        return _s3_err(h, st, code if code in ("AccessDenied", "InvalidAccessKeyId", "InvalidRequest")
                       else "AuthorizationHeaderMalformed" if st == 400 else "SignatureDoesNotMatch", msg, path)
    if h.command not in ("GET", "HEAD"):
        return _s3_err(h, 405, "MethodNotAllowed", "The specified method is not allowed against this resource.",
                       path)
    bucket, _, key = path.lstrip("/").partition("/")
    if bucket != c.s3_bucket:
        return _s3_err(h, 404, "NoSuchBucket", "The specified bucket does not exist", bucket)
    objs = trail_objects(c)
    if key:
        if key not in objs:
            return _s3_err(h, 404, "NoSuchKey", "The specified key does not exist.", key)
        data = objs[key]
        with h.m.lock:
            h.m.served["s3_objects"] += 1
        return h._send(200, data, ctype="application/x-gzip",
                       headers={"ETag": f'"{hashlib.md5(data).hexdigest()}"'})  # noqa: S324 - S3 ETag is MD5
    if params.get("list-type") != "2":
        return _s3_err(h, 400, "InvalidArgument", "mock: only ListObjectsV2 (list-type=2) is served", bucket)
    prefix = params.get("prefix", "")
    try:
        max_keys = min(int(params.get("max-keys", 1000)), 1000)
    except ValueError:
        return _s3_err(h, 400, "InvalidArgument", "Provided max-keys not an integer or within integer range")
    after = params.get("start-after", "")
    tok = params.get("continuation-token")
    if tok is not None:
        o = read_token(tok, {"b": bucket, "p": prefix})
        if o is None:
            return _s3_err(h, 400, "InvalidArgument", "The continuation token provided is incorrect", bucket)
        keys = sorted(k for k in objs if k.startswith(prefix))[o:]
        base = o
    else:
        keys = sorted(k for k in objs if k.startswith(prefix) and k > after)
        base = len([k for k in objs if k.startswith(prefix) and k <= after])
    page = keys[:max_keys]
    trunc = len(keys) > max_keys
    parts = [f"<Contents><Key>{escape(k)}</Key><LastModified>{_key_time(k)}</LastModified>"
             f"<ETag>&quot;{hashlib.md5(objs[k]).hexdigest()}&quot;</ETag>"  # noqa: S324 - S3 ETag is MD5
             f"<Size>{len(objs[k])}</Size><StorageClass>STANDARD</StorageClass></Contents>" for k in page]
    nxt = f"<NextContinuationToken>{page_token(base + max_keys, {'b': bucket, 'p': prefix})}" \
          f"</NextContinuationToken>" if trunc else ""
    ctok = f"<ContinuationToken>{escape(tok)}</ContinuationToken>" if tok is not None else ""
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="http://s3.amazonaws.com/doc/'
           f'2006-03-01/"><Name>{escape(bucket)}</Name><Prefix>{escape(prefix)}</Prefix>{ctok}'
           f"<KeyCount>{len(page)}</KeyCount><MaxKeys>{max_keys}</MaxKeys>"
           f"<IsTruncated>{'true' if trunc else 'false'}</IsTruncated>{''.join(parts)}{nxt}</ListBucketResult>")
    h._send(200, xml.encode(), ctype="application/xml")


def is_s3(h: Any, path: str) -> bool:
    first = path.lstrip("/").split("/", 1)[0]
    return bool(first) and (first == h.m.cloud.s3_bucket or "x-amz-content-sha256" in h.headers)
