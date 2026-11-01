"""AWS CloudTrail connector (boto3, optional pip extra [cloud]).

source: lookup (default) - CloudTrail LookupEvents API: management events of the last 90 days in one region.
  The window [since, until] is split into `window` slices (default 1h) walked oldest first; each slice is paged
  completely (LookupEvents returns newest first) before the next, so the checkpoint only moves past whole slices.
  LookupEvents allows 2 requests / second per account and region: `min_call_interval_s` (default 0.5) spaces calls.
source: s3 - CloudTrail log files in a bucket / prefix (gzip JSON {"Records": [...]}). Objects are processed in
  LastModified order and the checkpoint is the object's LastModified (S3 objects are immutable), so a file delivered
  late is still read. A prefix may contain {yyyy}/{mm}/{dd}: then only the days of the window are listed.

Auth: access key id + secret (+ session token) from secrets, else a named profile, else the default boto3 chain
(env vars, SSO, instance / task role) when `use_default_chain: true`; optional role_arn is assumed via STS.
Retries / throttling: botocore adaptive retry mode (`retries`), connect / read timeouts from `timeout_s`.
Each CloudTrail record is written as JSON (Stage 0 routes it to `cloudtrail_json`, config/sources.yaml).
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from attacklens import integrations as ig
from attacklens.cloud_unpack_env import RawJson
from attacklens.cloud_unpack_io import Unpacker
from attacklens.connectors import catalog_fields as cf
from attacklens.connectors.base import PAGE_END, AuthError, Connector, Record, require

log = logging.getLogger("attacklens.connect")

AUTH_CODES = {"UnrecognizedClientException", "InvalidClientTokenId", "AccessDenied", "AccessDeniedException",
              "ExpiredToken", "ExpiredTokenException", "SignatureDoesNotMatch", "InvalidAccessKeyId",
              "AuthFailure", "UnauthorizedOperation", "NoCredentialsError", "PartialCredentialsError"}
_sleep = time.sleep  # tests monkeypatch this
DEFAULT_S3_PREFIX = "AWSLogs/{account}/CloudTrail/{region}/{yyyy}/{mm}/{dd}/"
# CloudTrail writes these next to the event files; they are not event records
SKIP_KEY_PARTS = {"digest": "/CloudTrail-Digest/", "insight": "/CloudTrail-Insight/",
                  "network_activity": "/CloudTrail-NetworkActivity/"}

CATALOG: dict[str, Any] = {
    "id": "aws_cloudtrail", "kind": "cloud", "name": "AWS CloudTrail", "modes": ["events"],
    "docs_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    "help": "Minimum permission: cloudtrail:LookupEvents (S3 mode: s3:ListBucket + s3:GetObject on the trail bucket, + kms:Decrypt if the trail uses SSE-KMS).",
    "fields": [
        cf.field("region", "Region", required=True, default="us-east-1", placeholder="us-east-1",
                 help="CloudTrail LookupEvents is regional; the endpoint is derived from the region."),
        cf.secret("access_key_id", "Access key ID", help="Leave empty to use a profile or the default AWS chain."),
        cf.secret("secret_access_key", "Secret access key"),
        cf.field("profile", "AWS profile (instead of keys)", placeholder="security-audit"),
        cf.secret("session_token", "Session token (temporary keys only)", advanced=True),
        cf.advanced("role_arn", "Role to assume", placeholder="arn:aws:iam::123456789012:role/AttackLensRead"),
        cf.advanced("external_id", "External ID for the role"),
        cf.advanced("use_default_chain", "Use the default AWS credential chain", "bool", default=False,
                    help="Environment, SSO, instance or task role."),
        cf.advanced("events.source", "Read from", "select", options=["lookup", "s3"], default="lookup",
                    help="lookup: LookupEvents API (management events, 90 days). s3: CloudTrail log files."),
        cf.advanced("events.s3_bucket", "S3 bucket (s3 mode)", placeholder="my-cloudtrail-logs"),
        cf.advanced("events.s3_prefix", "S3 prefix (s3 mode)",
                    placeholder=DEFAULT_S3_PREFIX),
        cf.advanced("account_id", "Account ID in the S3 path (s3 mode)", placeholder="123456789012",
                    help="Empty = the account of the credentials (STS GetCallerIdentity)."),
        cf.advanced("endpoint_url", "Endpoint URL override", "url",
                    help="Empty = the public regional endpoint (VPC endpoints / GovCloud only)."),
        *cf.common(300, cf.SINCE_OPTIONS + ["90d"], tls=False),
    ],
}


def _dt(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)


def _ms(v: Any) -> int | None:
    if isinstance(v, datetime):
        return int((v if v.tzinfo else v.replace(tzinfo=timezone.utc)).timestamp() * 1000)
    return ig.to_ms(v)


def _aws_error(exc: Exception) -> Exception | None:
    """botocore NoCredentialsError -> PermissionError; ClientError with an auth code -> AuthError (matched by name /
    code, so no botocore import is needed here)."""
    if type(exc).__name__ in ("NoCredentialsError", "PartialCredentialsError"):
        return PermissionError("aws_cloudtrail: no AWS credentials found (access key, profile or default chain)")
    code = ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code") or type(exc).__name__
    if code in AUTH_CODES or type(exc).__name__ in AUTH_CODES:
        return AuthError(f"aws_cloudtrail: authentication / authorization failed ({code}); check the access key, "
                         f"profile or role and its CloudTrail / S3 read permissions",
                         403 if "Denied" in code or "Unauthorized" in code else 401)
    return None


class AwsCloudTrailConnector(Connector):
    name = "aws_cloudtrail"
    AUTH_ENV_KEYS: tuple[str, ...] = ("secret_access_key_env",)

    def __init__(self, cfg: dict[str, Any], mode: str, since_ms: int | None = None, reset: bool = False) -> None:
        super().__init__(cfg, mode, since_ms, reset)
        if mode != "events":
            raise ValueError("aws_cloudtrail supports mode events only")
        self._session: Any = None
        self._role_exp: float | None = None   # epoch s when assumed-role credentials expire (role_arn only)
        self._last_call = 0.0

    # ---- auth / clients ------------------------------------------------------------------------------------------
    def _keys(self) -> tuple[str | None, str | None, str | None]:
        c = self.ccfg
        return (ig.secret(c.get("access_key_id_env")), ig.secret(c.get("secret_access_key_env")),
                ig.secret(c.get("session_token_env")))

    def has_credentials(self) -> bool:
        ak, sk, _ = self._keys()
        return bool((ak and sk) or self.ccfg.get("profile") or self.ccfg.get("use_default_chain"))

    def client(self, service: str) -> Any:
        boto3 = require("boto3")
        bconf = require("botocore.config")
        region = str(self.ccfg.get("region") or "us-east-1")
        t = float(self.ccfg.get("timeout_s") or 30)
        conf = bconf.Config(region_name=region, connect_timeout=t, read_timeout=t,
                            retries={"max_attempts": int(self.ccfg.get("retries", 3)) + 1, "mode": "adaptive"})
        if self._session is not None and self._role_exp is not None and \
                self._role_exp - time.time() < float(self.ccfg.get("token_refresh_skew_s", 300)):
            self._session = None   # assumed-role credentials expire (1 h): assume the role again before they do
        if self._session is None:
            ak, sk, tok = self._keys()
            kw: dict[str, Any] = {"region_name": region}
            if ak and sk:
                kw.update(aws_access_key_id=ak, aws_secret_access_key=sk, aws_session_token=tok)
            elif self.ccfg.get("profile"):
                kw["profile_name"] = str(self.ccfg["profile"])
            sess = boto3.session.Session(**kw)
            if self.ccfg.get("role_arn"):
                args = {"RoleArn": str(self.ccfg["role_arn"]), "RoleSessionName": "attacklens"}
                if self.ccfg.get("external_id"):
                    args["ExternalId"] = str(self.ccfg["external_id"])
                cr = self._call(lambda: sess.client("sts", config=conf).assume_role(**args))["Credentials"]
                sess = boto3.session.Session(aws_access_key_id=cr["AccessKeyId"],
                                             aws_secret_access_key=cr["SecretAccessKey"],
                                             aws_session_token=cr["SessionToken"], region_name=region)
                exp = _ms(cr.get("Expiration"))
                self._role_exp = exp / 1000 if exp is not None else time.time() + 3600
            self._session = sess
        ep = self.ccfg.get("endpoint_url") if service == "cloudtrail" else self.ccfg.get("s3_endpoint_url")
        if service == "s3" and not ep:  # the form's endpoint_url (LocalStack / S3-compatible store in s3 mode)
            ep = self.ccfg.get("endpoint_url")
        # no endpoint_url: boto3 derives the public regional endpoint from the region
        return self._session.client(service, config=conf, **({"endpoint_url": str(ep)} if ep else {}))

    def _call(self, fn: Any) -> Any:
        gap = float(self.ccfg.get("min_call_interval_s", 0.5))
        wait = self._last_call + gap - time.monotonic()
        if wait > 0:
            _sleep(wait)
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - botocore classes are optional; matched by name / code
            ae = _aws_error(exc)
            if ae is not None:
                raise ae from None
            raise
        finally:
            self._last_call = time.monotonic()

    # ---- pull ----------------------------------------------------------------------------------------------------
    def pull(self, since_ms: int) -> Iterator[Record]:
        until = self.until_ms if self.until_ms is not None else ig.now_ms()
        if str(self.mcfg.get("source") or "lookup").lower() == "s3":
            yield from self._pull_s3(since_ms, until)
        else:
            yield from self._pull_lookup(since_ms, until)

    def _pull_lookup(self, since_ms: int, until: int) -> Iterator[Record]:
        ct = self.client("cloudtrail")
        win = max(60_000, ig.parse_duration_ms(self.mcfg.get("window", "1h")))
        lo = max(since_ms, ig.now_ms() - 90 * 86_400_000)  # LookupEvents keeps 90 days
        for _ in range(int(self.ccfg.get("max_windows_per_cycle", 168))):
            if lo > until:
                return
            hi = min(until, lo + win)
            args: dict[str, Any] = {"StartTime": _dt(lo), "EndTime": _dt(hi), "MaxResults": 50}
            attrs = self.mcfg.get("lookup_attributes")
            if attrs:
                args["LookupAttributes"] = attrs
            while True:
                res = self._call(lambda: ct.lookup_events(**args))
                for e in res.get("Events") or []:
                    try:
                        doc = json.loads(e.get("CloudTrailEvent") or "{}")
                    except ValueError:
                        doc = {}
                    rid = e.get("EventId") or (doc.get("eventID") if isinstance(doc, dict) else None)
                    yield Record(_ms(e.get("EventTime")) or ig.to_ms(doc.get("eventTime")),
                                 None if rid is None else str(rid), doc if isinstance(doc, dict) else {}, "cloudtrail")
                tok = res.get("NextToken")
                if not tok:
                    break
                args["NextToken"] = tok
            yield PAGE_END  # slice complete: safe commit point
            lo = hi + 1
        log.info("connect aws_cloudtrail: max_windows_per_cycle reached; continuing next cycle")

    def _account(self) -> str:
        return self._accounts()[0]

    def _accounts(self) -> list[str]:
        """{account} values: account_id (one, a list or comma-separated: an organization trail holds every member
        account under AWSLogs/<org id>/<account>/), else the account of the credentials (STS)."""
        acct = self.ccfg.get("account_id") or self.mcfg.get("account_id")
        items = acct if isinstance(acct, list) else str(acct or "").split(",")
        out = [str(a).strip() for a in items if str(a).strip()]
        bad = [a for a in out if not (a.isdigit() and len(a) == 12)]
        if bad:
            raise ValueError(f"aws_cloudtrail: account_id must be 12-digit AWS account ids ({bad[:3]})")
        if out:
            return list(dict.fromkeys(out))
        ident = self._call(lambda: self.client("sts").get_caller_identity())
        return [str(ident["Account"])]

    def _prefixes(self, since_ms: int, until: int) -> list[str]:
        """Day prefixes of the window (never a full-bucket listing): {account} {region} {yyyy} {mm} {dd}."""
        p = str(self.mcfg.get("s3_prefix") or DEFAULT_S3_PREFIX)
        if "{yyyy}" not in p or "{dd}" not in p:
            raise ValueError("aws_cloudtrail: events.s3_prefix must contain {yyyy}/{mm}/{dd} (only the days of the "
                             "window are listed, never the whole bucket)")
        accounts = self._accounts() if "{account}" in p else [""]
        regions = self.mcfg.get("regions") or [self.ccfg.get("region") or "us-east-1"]
        out = []
        for acct in accounts:
            for region in regions if isinstance(regions, list) else str(regions).split(","):
                rp = p.replace("{account}", acct).replace("{region}", str(region).strip())
                d = _dt(since_ms).date()
                while d <= _dt(until).date():
                    out.append(rp.replace("{yyyy}", f"{d.year:04d}").replace("{mm}", f"{d.month:02d}")
                               .replace("{dd}", f"{d.day:02d}"))
                    d += timedelta(days=1)
        return out

    def _skip_key(self, key: str) -> bool:
        if not key.endswith((".json", ".json.gz", ".gz")):
            return True
        inc = {"insight": bool(self.mcfg.get("include_insight")),
               "network_activity": bool(self.mcfg.get("include_network_activity")), "digest": False}
        return any(part in key and not inc[k] for k, part in SKIP_KEY_PARTS.items())

    def _pull_s3(self, since_ms: int, until: int) -> Iterator[Record]:
        bucket = str(self.mcfg.get("s3_bucket") or "")
        if not bucket:
            raise ValueError("aws_cloudtrail: events.s3_bucket is required for source s3")
        s3 = self.client("s3")
        objs: list[tuple[int, str, int]] = []
        for prefix in self._prefixes(since_ms, until):
            args: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix}
            while True:
                res = self._call(lambda: s3.list_objects_v2(**args))
                for o in res.get("Contents") or []:
                    lm = _ms(o.get("LastModified"))
                    key = str(o.get("Key") or "")
                    if lm is not None and since_ms <= lm <= until and not self._skip_key(key):
                        objs.append((lm, key, int(o.get("Size") or 0)))
                if not res.get("IsTruncated"):
                    break
                args["ContinuationToken"] = res.get("NextContinuationToken")
        objs.sort()
        for lm, key, size in objs[: int(self.mcfg.get("max_objects_per_cycle", 500))]:
            body = self._call(lambda: s3.get_object(Bucket=bucket, Key=key))["Body"]
            yield from self._object_records(lm, key, size, body)
            yield PAGE_END

    def _object_records(self, lm: int, key: str, size: int, body: Any) -> Iterator[Record]:
        """One S3 object streamed through the Stage 0 unpacker (gzip / tar / zip, {"Records"}, digests skipped,
        bomb guard). Failures become failed rows with a reason (counted, never a silently lost or stuck object)."""
        u = Unpacker(self.cfg.get("unwrap") or {}, None, size)
        n = 0
        for _member, _bucket, r in u.iter_items(body):
            doc = json.loads(r) if isinstance(r, RawJson) else r
            n += 1
            if not isinstance(doc, dict):
                yield Record(lm, f"{key}#{n}", None, "cloudtrail", fail=f"not_a_json_record ({key.rsplit('/', 1)[-1]})")
                continue
            rid = doc.get("eventID")
            # ts = object LastModified: the checkpoint walks objects, events keep their own eventTime.
            # id = eventID alone: CloudTrail may deliver the same event again in another file.
            yield Record(lm, str(rid) if rid else None, doc, "cloudtrail")
        for reason, k in u.acct.failed.items():
            for i in range(k):
                yield Record(lm, f"{key}#fail-{reason}-{i}", None, "cloudtrail",
                             fail=f"{reason} ({key.rsplit('/', 1)[-1]})")
