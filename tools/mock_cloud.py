"""Mock cloud log APIs served by tools/mock_siem.py on the same port (stdlib only). Azure + GCP + shared state here;
AWS (CloudTrail LookupEvents, S3 trail files) in mock_cloud_aws.py; seed data in mock_cloud_seed.py.

  Azure  POST /{tenant}/oauth2/v2.0/token          client_credentials -> {"token_type","expires_in","access_token"}
                                                   400 unsupported_grant_type / invalid_scope / unauthorized_client,
                                                   401 invalid_client (bad secret), 400 invalid_request (tenant)
         POST /v1/workspaces/{id}/query            tables AzureActivity, SigninLogs, AuditLogs (tables[0] shape);
                                                   Bearer = a token from the endpoint above (expired -> 401)
  GCP    POST /token (also /oauth2/v4/token)       JWT-bearer grant; JWT structure, alg, aud, iat/exp checked,
                                                   signature NOT verified -> {"access_token","expires_in","token_type"}
         POST /v2/entries:list                     resourceNames, filter (AND of comparisons), orderBy, pageSize,
                                                   pageToken (opaque, bound to the query) -> {entries, nextPageToken}
Auth is always on for these endpoints. Expected credentials are checked only when configured (None = any value).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
import time
from collections import Counter
from typing import Any, Callable
from urllib.parse import parse_qsl, unquote

import mock_cloud_seed as seed
import mock_siem_query as mq
from mock_siem_store import get_path, parse_iso_ms

DYNAMIC_COLS = {"LocationDetails", "DeviceDetail", "Properties_d", "Authorization_d", "InitiatedBy",
                "TargetResources", "AdditionalDetails"}
GCP_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
GCP_MAX_PAGE = 1000


def b64u_json(part: str) -> Any:
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def page_token(offset: int, query: Any) -> str:
    h = hashlib.sha256(json.dumps(query, sort_keys=True, default=str).encode()).hexdigest()[:16]
    return base64.urlsafe_b64encode(json.dumps({"o": offset, "h": h}).encode()).decode().rstrip("=")


def read_token(tok: str, query: Any) -> int | None:
    """Offset of a token issued for exactly this query, else None (a token is bound to its request)."""
    try:
        d = b64u_json(tok)
    except Exception:  # noqa: BLE001 - any garbage token is just invalid
        return None
    want = page_token(0, query)
    if not isinstance(d, dict) or b64u_json(want)["h"] != d.get("h") or not isinstance(d.get("o"), int):
        return None
    return d["o"]


class CloudState:
    def __init__(self, *, now_ms: Callable[[], int], anchor_ms: int = seed.ANCHOR_MS,
                 azure_tenant: str | None = None, azure_client_id: str | None = None,
                 azure_client_secret: str | None = None, azure_token_ttl_s: int = 3599,
                 sentinel_oauth: bool = False, aws_access_key_id: str | None = None,
                 s3_bucket: str = seed.S3_BUCKET, gcp_project: str = seed.PROJECT,
                 gcp_client_email: str | None = None, gcp_token_ttl_s: int = 3599,
                 tie_burst: int = 0, late_after: int = 0, future_row: bool = False) -> None:
        self.now_ms, self.anchor_ms = now_ms, anchor_ms
        self.azure_tenant, self.azure_client_id, self.azure_client_secret = azure_tenant, azure_client_id, \
            azure_client_secret
        self.azure_token_ttl_s, self.sentinel_oauth = azure_token_ttl_s, sentinel_oauth
        self.aws_access_key_id, self.s3_bucket = aws_access_key_id, s3_bucket
        self.gcp_project, self.gcp_client_email, self.gcp_token_ttl_s = gcp_project, gcp_client_email, gcp_token_ttl_s
        self.switches = {"tie_burst": tie_burst, "late_after": late_after, "future_row": future_row,
                         "late_ts_ms": None}
        self._appended = 0
        self.lock = threading.RLock()
        self.tokens: dict[str, tuple[str, float]] = {}          # token -> (vendor, expiry on time.monotonic)
        self.queries: Counter[str] = Counter()
        self.token_requests: Counter[str] = Counter()
        self.seed = self._build()

    # ------------------------------------------------------------------ data
    def _build(self) -> seed.Seed:
        s = self.switches
        return seed.build(self.anchor_ms, tie_burst=int(s["tie_burst"]), late_after=int(s["late_after"]),
                          future_now_ms=self.now_ms() if s["future_row"] else None, late_ts_ms=s["late_ts_ms"])

    def configure(self, **kw: Any) -> dict[str, Any]:
        """Change data switches (tie_burst, late_after, future_row) at runtime; resets the per-feed query counts."""
        with self.lock:
            unknown = set(kw) - set(self.switches)
            if unknown:
                raise ValueError(f"unknown cloud switch {sorted(unknown)}")
            self.switches.update(kw)
            self.queries.clear()
            self.seed = self._build()
            return dict(self.switches)

    def add_rows(self, ts_ms: int, feeds: tuple[str, ...] = seed.FEEDS) -> dict[str, str]:
        """New data arrives: one benign row per feed dated ts_ms; returns {feed: record id}."""
        with self.lock:
            self._appended += 1
            ids = seed._Ids(9_000_000 + self._appended)
            out = {}
            for feed in feeds:
                it = seed.benign_item(feed, ids, ts_ms)
                self.seed.feeds[feed].append(it)
                self.seed.feeds[feed].sort(key=lambda x: (x.ts_ms, x.rid))
                out[feed] = it.rid
            return out

    def ground_truth(self) -> dict[str, Any]:
        return seed.ground_truth(self.anchor_ms)

    def visible(self, feed: str) -> list[seed.Item]:
        """Items of a feed as of this query (late rows appear after N earlier queries of the feed)."""
        with self.lock:
            n = self.queries[feed]
            self.queries[feed] += 1
            return [it for it in self.seed.feeds[feed] if it.visible_after <= n]

    # ------------------------------------------------------------------ tokens
    def issue(self, vendor: str, ttl_s: int, prefix: str) -> str:
        tok = prefix + secrets.token_hex(16)
        with self.lock:
            self.tokens[tok] = (vendor, time.monotonic() + ttl_s)
            self.token_requests[vendor] += 1
        return tok

    def check(self, vendor: str, authz: str) -> str:
        """'ok' | 'missing' | 'invalid' | 'expired' for an `Authorization: Bearer <token>` header."""
        if not authz.startswith("Bearer ") or not authz[7:].strip():
            return "missing"
        with self.lock:
            entry = self.tokens.get(authz[7:].strip())
        if entry is None or entry[0] != vendor:
            return "invalid"
        return "ok" if time.monotonic() < entry[1] else "expired"

    def expire_tokens(self, vendor: str | None = None) -> int:
        with self.lock:
            hit = [t for t, (v, _) in self.tokens.items() if vendor in (None, v)]
            for t in hit:
                self.tokens[t] = (self.tokens[t][0], 0.0)
            return len(hit)


# ====================================================================== Azure
def _aad_error(h: Any, status: int, err: str, code: int, desc: str) -> None:
    h._send(status, {"error": err, "error_description": f"AADSTS{code}: {desc}", "error_codes": [code],
                     "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                     "trace_id": "00000000-0000-0000-0000-000000000000",
                     "correlation_id": "00000000-0000-0000-0000-000000000000"})


def azure_token(h: Any, tenant: str, body: bytes) -> None:
    c: CloudState = h.m.cloud
    if h.command != "POST":
        return h._send(405, {"error": "invalid_request", "error_description": "AADSTS900561: POST required"})
    form = dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
    if c.azure_tenant is not None and tenant not in (c.azure_tenant, "organizations"):
        return _aad_error(h, 400, "invalid_request", 90002, f"Tenant '{tenant}' not found.")
    if form.get("grant_type") != "client_credentials":
        return _aad_error(h, 400, "unsupported_grant_type", 70003,
                          "The app requested an unsupported grant type 'client_credentials' expected.")
    if not form.get("scope", "").endswith("/.default"):
        return _aad_error(h, 400, "invalid_scope", 1002012, "The provided value for scope is not valid. Client "
                          "credential flows must have a scope value with /.default suffixed to the resource "
                          "identifier.")
    cid, sec = form.get("client_id", ""), form.get("client_secret", "")
    if not cid or (c.azure_client_id is not None and cid != c.azure_client_id):
        return _aad_error(h, 400, "unauthorized_client", 700016, f"Application with identifier '{cid}' was not "
                          f"found in the directory '{tenant}'.")
    if not sec or (c.azure_client_secret is not None and sec != c.azure_client_secret):
        return _aad_error(h, 401, "invalid_client", 7000215, "Invalid client secret provided. Ensure the secret "
                          "being sent in the request is the client secret value, not the client secret ID.")
    tok = c.issue("azure", c.azure_token_ttl_s, "mock-aad-")
    h._send(200, {"token_type": "Bearer", "expires_in": c.azure_token_ttl_s, "ext_expires_in": c.azure_token_ttl_s,
                  "access_token": tok})


def azure_auth_error(h: Any) -> bool:
    """Bearer check for Log Analytics; sends the 401 and returns True when it fails."""
    c: CloudState = h.m.cloud
    authz = h.headers.get("Authorization", "")
    static = h.m.tokens.get("sentinel")
    if static is not None and authz == f"Bearer {static}":
        return False
    state = c.check("azure", authz)
    if state == "ok":
        return False
    msg = {"expired": "The provided authentication is not valid for this resource: token expired",
           "missing": "Valid authentication was not provided"}.get(state, "The provided authentication is not valid")
    hdr = 'Bearer authorization_uri="https://login.microsoftonline.com/common", error="invalid_token"'
    if state == "expired":
        hdr += ', error_description="The access token is expired"'
    h._send(401, {"error": {"code": "InvalidAuthenticationToken", "message": msg}},
            headers={"WWW-Authenticate": hdr})
    return True


def la_table(body: bytes) -> str | None:
    """First cloud table named by a Log Analytics query body (`T | ...` or `union T1, T2 | ...` with only cloud tables,
    or `union isfuzzy=true ...` with at least one cloud table), else None (the Sentinel handler serves it)."""
    try:
        q = json.loads(body or b"{}").get("query") or ""
    except (ValueError, AttributeError):
        return None
    first = str(q).split("|")[0].strip()
    fuzzy = re.match(r"^union\s+isfuzzy\s*=\s*true\s+", first) is not None
    head = re.sub(r"^union\s+(isfuzzy\s*=\s*true\s+)?", "", first)
    names = [t.strip() for t in head.split(",")]
    cloud = [t for t in names if t in seed.LA_TABLES]
    # union isfuzzy=true: tables this workspace lacks (e.g. AAD*SignInLogs) are skipped, like Log Analytics does
    return cloud[0] if cloud and (fuzzy or len(cloud) == len(names)) else None


def _col_type(name: str, v: Any) -> str:
    if name in ("TimeGenerated", "ActivityDateTime"):
        return "datetime"
    if name in DYNAMIC_COLS:
        return "dynamic"
    return "bool" if isinstance(v, bool) else "string"


def la_query(h: Any, path: str, body: bytes) -> None:
    m, c = h.m, h.m.cloud
    if azure_auth_error(h):
        return
    segs = [s for s in path.split("/") if s]
    if len(segs) != 4 or segs[3] != "query" or h.command != "POST":
        return h._send(404, {"error": {"code": "PathNotFoundError", "message": path}})
    if m.workspace_id is not None and segs[2] != m.workspace_id:
        return h._send(404, {"error": {"code": "WorkspaceNotFoundError", "message": f"workspace {segs[2]} not found"}})
    req = json.loads(body or b"{}")
    now = m.now_ms()
    kq = mq.parse_kql(req["query"], now)
    kq["tables"] = mq.resolve_tables(kq, c.seed.feeds)   # union isfuzzy=true: tables the workspace lacks are skipped
    t_lo, t_hi_x = mq.timespan_bounds(req.get("timespan"), now)
    preds = list(kq["preds"]) + ([(">=", t_lo), ("<", t_hi_x)] if t_lo is not None else [])
    items = [it for t in kq["tables"] for it in c.visible(t) if mq.kql_pred_ok(it.ts_ms, preds)]
    items.sort(key=lambda it: (it.ts_ms, it.rid), reverse=kq["order"] == "desc")
    pairs = [(it.ts_ms, it.doc) for it in items
             if all((it.doc.get(col) == val if op == "==" else str(it.doc.get(col)).lower() == val.lower()
                     if op == "=~" else it.doc.get(col) != val) for col, op, val in kq["filters"])]
    rows = mq.kql_post(kq, pairs)
    if kq["take"] is not None:
        rows = rows[:kq["take"]]
    out: dict[str, Any] = {}
    if len(rows) > m.sentinel_max_rows:
        rows = rows[:m.sentinel_max_rows]
        out["error"] = {"code": "PartialError", "message": "There were some errors when processing your query.",
                        "details": [{"code": "EngineError", "message": "Query result set has exceeded the internal "
                                     f"record count limit {m.sentinel_max_rows} records."}]}
    proto: dict[str, Any] = {}                       # union isfuzzy: columns of every table, first-seen order
    for t in kq["tables"]:
        for k, v in (c.seed.feeds[t][0].doc if c.seed.feeds[t] else {}).items():
            proto.setdefault(k, v)
    proto.update({k: "" for k in kq["extend"] if k not in proto})
    names = list(proto)
    if kq["project"]:
        unknown = [x for x in kq["project"] if x not in names]
        if unknown:
            raise mq.QueryError(f"Failed to resolve column '{unknown[0]}'")
        names = kq["project"]
    with m.lock:
        m.served["azure_" + "+".join(kq["tables"])] += len(rows)
    h._send(200, {"tables": [{"name": "PrimaryResult",
                              "columns": [{"name": n, "type": _col_type(n, proto.get(n))} for n in names],
                              "rows": [[r.get(n) for n in names] for r in rows]}], **out})


# ====================================================================== GCP
def _oauth_err(h: Any, status: int, err: str, desc: str) -> None:
    h._send(status, {"error": err, "error_description": desc})


def gcp_token(h: Any, body: bytes) -> None:
    c: CloudState = h.m.cloud
    form = dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
    if form.get("grant_type") != GCP_GRANT:
        return _oauth_err(h, 400, "unsupported_grant_type", f"Invalid grant_type: {form.get('grant_type', '')}")
    parts = form.get("assertion", "").split(".")
    try:
        if len(parts) != 3 or not parts[2]:
            raise ValueError("parts")
        hdr, claims = b64u_json(parts[0]), b64u_json(parts[1])
    except Exception:  # noqa: BLE001
        return _oauth_err(h, 400, "invalid_grant", "Invalid JWT Signature.")
    if not isinstance(hdr, dict) or hdr.get("alg") != "RS256" or not isinstance(claims, dict):
        return _oauth_err(h, 400, "invalid_grant", "Invalid JWT: unsupported or missing alg (RS256 required).")
    now_s = time.time()
    iat, exp = claims.get("iat"), claims.get("exp")
    if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)) or exp - iat > 3600 \
            or exp <= iat or exp < now_s - 300 or iat > now_s + 300:
        return _oauth_err(h, 400, "invalid_grant", "Invalid JWT: Token must be a short-lived token (60 minutes) "
                          "and in a reasonable timeframe. Check your iat and exp values in the JWT claim.")
    if not str(claims.get("aud", "")).endswith("/token") or not claims.get("scope") or not claims.get("iss"):
        return _oauth_err(h, 400, "invalid_grant", "Invalid JWT: aud must be the token_uri; iss and scope are "
                          "required.")
    if c.gcp_client_email is not None and claims["iss"] != c.gcp_client_email:
        return _oauth_err(h, 400, "invalid_grant", "Invalid grant: account not found")
    tok = c.issue("gcp", c.gcp_token_ttl_s, "ya29.mock-")
    h._send(200, {"access_token": tok, "expires_in": c.gcp_token_ttl_s, "token_type": "Bearer"})


def _gcp_err(h: Any, status: int, gstatus: str, msg: str) -> None:
    h._send(status, {"error": {"code": status, "message": msg, "status": gstatus}})


_CLAUSE = re.compile(r'^\s*([A-Za-z_@][\w.@]*)\s*(>=|<=|!=|=|>|<|:)\s*("((?:[^"\\]|\\.)*)"|[^\s"]+)\s*$')


def parse_filter(flt: str) -> list[tuple[str, str, str]]:
    """Cloud Logging filter subset: comparisons joined by AND (or newlines). Anything else -> ValueError."""
    out = []
    for cl in re.split(r"\s+AND\s+|\n+", flt.strip()):
        if not cl.strip():
            continue
        mm = _CLAUSE.match(cl)
        if not mm:
            raise ValueError(f"Unparseable filter: {cl.strip()!r}")
        out.append((mm.group(1), mm.group(2), mm.group(4) if mm.group(4) is not None else mm.group(3)))
    return out


def _clause_ok(entry: dict[str, Any], ts: int, f: tuple[str, str, str]) -> bool:
    fld, op, val = f
    if fld == "timestamp" and op in (">=", "<=", ">", "<", "=", "!="):
        t = parse_iso_ms(val)
        if t is None:
            raise ValueError(f"Invalid timestamp {val!r}")
        return {">=": ts >= t, "<=": ts <= t, ">": ts > t, "<": ts < t, "=": ts == t, "!=": ts != t}[op]
    got = get_path(entry, fld)
    if got is None:
        return op == "!="
    a, b = unquote(str(got)), unquote(val)
    if op == ":":
        return b.lower() in a.lower()
    return {"=": a == b, "!=": a != b, ">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b}[op]


def gcp_list(h: Any, body: bytes) -> None:
    m, c = h.m, h.m.cloud
    state = c.check("gcp", h.headers.get("Authorization", ""))
    if state != "ok":
        return _gcp_err(h, 401, "UNAUTHENTICATED", "Request had invalid authentication credentials. Expected OAuth "
                        "2 access token, login cookie or other valid authentication credential."
                        + (" (token expired)" if state == "expired" else ""))
    try:
        req = json.loads(body or b"{}")
    except ValueError:
        return _gcp_err(h, 400, "INVALID_ARGUMENT", "Invalid JSON payload received.")
    names = req.get("resourceNames") or []
    if not names:
        return _gcp_err(h, 400, "INVALID_ARGUMENT", "resourceNames: at least one resource name is required")
    if any(n != f"projects/{c.gcp_project}" for n in names):
        return _gcp_err(h, 403, "PERMISSION_DENIED", "The caller does not have permission")
    order = (req.get("orderBy") or "timestamp asc").strip().lower()
    if order not in ("timestamp asc", "timestamp desc"):
        return _gcp_err(h, 400, "INVALID_ARGUMENT", f"Invalid orderBy: {order}")
    size = int(req.get("pageSize") or 50)
    if size < 0:
        return _gcp_err(h, 400, "INVALID_ARGUMENT", "pageSize must not be negative")
    size = min(size or 50, GCP_MAX_PAGE)
    qkey = {"r": names, "f": req.get("filter") or "", "o": order}
    off = 0
    if req.get("pageToken"):
        o = read_token(str(req["pageToken"]), qkey)
        if o is None:
            return _gcp_err(h, 400, "INVALID_ARGUMENT", "The page token is invalid or does not match the request.")
        off = o
    try:
        flt = parse_filter(req.get("filter") or "")
        items = [it for it in c.visible("GcpLogging") if all(_clause_ok(it.doc, it.ts_ms, f) for f in flt)]
    except ValueError as e:
        return _gcp_err(h, 400, "INVALID_ARGUMENT", str(e))
    items.sort(key=lambda it: (it.ts_ms, it.rid), reverse=order.endswith("desc"))
    page = items[off:off + size]
    out: dict[str, Any] = {"entries": [it.doc for it in page]} if page else {}
    if off + size < len(items):
        out["nextPageToken"] = page_token(off + size, qkey)
    with m.lock:
        m.served["gcp_entries"] += len(page)
    h._send(200, out)
