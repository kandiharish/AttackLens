"""Vendor handlers of tools/mock_saas.py (Okta System Log, Office 365 Management Activity API, Google Reports API).
See mock_saas.py for the endpoint list. Each handler validates like the real API (unsupported input is an error,
never silently ignored) so a connector cannot pass against a lenient mock."""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode

import mock_saas_seed as seed
from mock_saas import (DAY_MS, GWS_APPS, GWS_SCOPE, MANAGE_AUD, bound_token, jwt_parts, jwt_times_ok, parse_ts,
                       read_bound)

_OKTA_FILTER = re.compile(r'^eventType (eq|sw) "([A-Za-z0-9_.]+)"$')
_M365_TIME = re.compile(r"^\d{4}-\d\d-\d\d(T\d\d:\d\d(:\d\d)?)?Z?$")


def route(h: Any, path: str, params: dict[str, str], body: bytes) -> None:
    m = h.mock
    if path == "/_mock/saas/stats":
        return h.send_json(200, {"stats": dict(m.stats), "subscriptions": dict(m.subscriptions),
                                 "publishers": sorted(m.publishers), "counts": seed.counts(m.seed)})
    if path == "/_mock/saas/ground_truth":
        return h.send_json(200, m.ground_truth())
    if path == "/_mock/saas" and h.command == "POST":
        req = json.loads(body or b"{}")
        if "expire_tokens" in req:
            m.expire_tokens(req.pop("expire_tokens"))
        if "fail" in req:
            f = req.pop("fail")
            m.fail(str(f["path"]), int(f["status"]), int(f.get("times", 1)))
        for k in ("okta_rate_limit", "okta_rate_window_s"):
            if k in req:
                setattr(m, k, type(getattr(m, k))(req.pop(k)))
        return h.send_json(200 if not req else 400, {"unknown": sorted(req)} if req else {"ok": True})
    if path == "/oauth2/v1/token":
        return okta_token(h, body)
    if path == "/api/v1/logs":
        return okta_logs(h, params)
    mt = re.match(r"^/([^/]+)/oauth2/v2\.0/token$", path)
    if mt:
        return m365_token(h, mt.group(1), body)
    mf = re.match(r"^/api/v1\.0/([^/]+)/activity/feed/(.+)$", path)
    if mf:
        return m365_feed(h, mf.group(1), mf.group(2), params)
    if path == "/token":
        return gws_token(h, body)
    mg = re.match(r"^/admin/reports/v1/activity/users/all/applications/([^/]+)$", path)
    if mg:
        return gws_list(h, mg.group(1), params)
    h.send_json(404, {"error": {"code": "NotFound", "message": path}})


# ====================================================================== Okta
def _okta_err(h: Any, status: int, code: str, summary: str, headers: dict[str, str] | None = None) -> None:
    h.send_json(status, {"errorCode": code, "errorSummary": summary, "errorLink": code,
                         "errorId": "oaeMock000000000000", "errorCauses": []}, headers)


def okta_token(h: Any, body: bytes) -> None:
    m = h.mock
    form = dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
    if form.get("grant_type") != "client_credentials":
        return h.send_json(400, {"error": "unsupported_grant_type", "error_description": "grant_type"})
    if form.get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
        return h.send_json(401, {"error": "invalid_client", "error_description": "client_assertion_type"})
    parts = jwt_parts(form.get("client_assertion", ""))
    if parts is None:
        return h.send_json(401, {"error": "invalid_client", "error_description": "The client_assertion is invalid."})
    _, c = parts
    cid = c.get("iss")
    if not cid or c.get("sub") != cid or (m.okta_client_id is not None and cid != m.okta_client_id) \
            or not str(c.get("aud", "")).endswith("/oauth2/v1/token") or not jwt_times_ok(c) or not c.get("jti"):
        return h.send_json(401, {"error": "invalid_client",
                                 "error_description": "The client_assertion token is invalid (iss, sub, aud, exp)."})
    with m.lock:
        if c["jti"] in m.jtis:
            return h.send_json(401, {"error": "invalid_client", "error_description": "jti already used"})
        m.jtis.add(c["jti"])
    if "okta.logs.read" not in form.get("scope", "").split():
        return h.send_json(400, {"error": "invalid_scope", "error_description": "The requested scope is invalid."})
    tok = m.issue("okta", scope="okta.logs.read")
    h.send_json(200, {"token_type": "Bearer", "expires_in": m.token_ttl_s, "access_token": tok,
                      "scope": "okta.logs.read"})


def okta_logs(h: Any, params: dict[str, str]) -> None:
    m = h.mock
    authz = h.headers.get("Authorization", "")
    ok = (authz.startswith("SSWS ") and authz[5:].strip() and m.okta_token in (None, authz[5:].strip())) \
        or m.bearer("okta", authz) is not None
    if not ok:
        return _okta_err(h, 401, "E0000011", "Invalid token provided")
    allowed, rl = m.okta_rate()
    if not allowed:
        with m.lock:
            m.stats["okta_429"] += 1
        return _okta_err(h, 429, "E0000047", "API call exceeded rate limit due to too many requests.", rl)
    since, until = params.get("since"), params.get("until")
    lo = parse_ts(since) if since else int(time.time() * 1000) - 7 * DAY_MS
    hi = parse_ts(until) if until else None
    if lo is None or (until and hi is None):
        return _okta_err(h, 400, "E0000001", "Api validation failed: since / until must be ISO 8601 with a zone", rl)
    try:
        limit = int(params.get("limit", "100"))
    except ValueError:
        limit = -1
    if not 1 <= limit <= 1000:
        return _okta_err(h, 400, "E0000001", "Api validation failed: limit", rl)
    order = params.get("sortOrder", "ASCENDING")
    if order not in ("ASCENDING", "DESCENDING"):
        return _okta_err(h, 400, "E0000001", "Api validation failed: sortOrder", rl)
    flt = params.get("filter")
    fm = _OKTA_FILTER.match(flt) if flt else None
    if flt and not fm:
        return _okta_err(h, 400, "E0000031", "Invalid search criteria.", rl)
    qkey = {k: v for k, v in params.items() if k != "after"}
    off = 0
    if params.get("after"):
        o = read_bound(params["after"], qkey)
        if o is None:
            return _okta_err(h, 400, "E0000001", "Api validation failed: after", rl)
        off = o
    now = int(time.time() * 1000)
    rows = [e for e in m.seed.okta if lo <= parse_ts(e["published"]) <= min(hi if hi is not None else now, now)
            and (fm is None or (e["eventType"] == fm.group(2) if fm.group(1) == "eq"
                                else e["eventType"].startswith(fm.group(2))))]
    rows.sort(key=lambda e: (e["published"], e["uuid"]), reverse=order == "DESCENDING")
    page = rows[off:off + limit]
    self_url = f"{m.url}/api/v1/logs?{urlencode(params)}"
    links = [f'<{self_url}>; rel="self"']
    if off + limit < len(rows) or hi is None:                  # polling requests always get a next link
        nxt = f"{m.url}/api/v1/logs?{urlencode({**qkey, 'after': bound_token(off + len(page), qkey)})}"
        links.append(f'<{nxt}>; rel="next"')
    with m.lock:
        m.stats["okta_rows"] += len(page)
        m.stats["okta_pages"] += 1
    h.send_json(200, page, {**rl, "Link": ", ".join(links)})


# ====================================================================== Microsoft 365
def _ms_err(h: Any, status: int, code: str, msg: str) -> None:
    h.send_json(status, {"error": {"code": code, "message": msg}})


def m365_token(h: Any, tenant: str, body: bytes) -> None:
    m = h.mock
    form = dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
    if tenant != m.m365_tenant:
        return h.send_json(400, {"error": "invalid_request", "error_codes": [90002],
                                 "error_description": f"AADSTS90002: Tenant '{tenant}' not found."})
    if form.get("grant_type") != "client_credentials" or not form.get("scope", "").endswith("/.default"):
        return h.send_json(400, {"error": "invalid_request", "error_codes": [1002012],
                                 "error_description": "AADSTS1002012: grant_type / scope"})
    if not form.get("client_id") or (m.m365_client_id is not None and form["client_id"] != m.m365_client_id):
        return h.send_json(400, {"error": "unauthorized_client", "error_codes": [700016],
                                 "error_description": "AADSTS700016: Application not found in the directory."})
    if not form.get("client_secret") or (m.m365_secret is not None and form["client_secret"] != m.m365_secret):
        return h.send_json(401, {"error": "invalid_client", "error_codes": [7000215],
                                 "error_description": "AADSTS7000215: Invalid client secret provided."})
    tok = m.issue("m365", aud=form["scope"], tenant=tenant)
    h.send_json(200, {"token_type": "Bearer", "expires_in": m.token_ttl_s, "ext_expires_in": m.token_ttl_s,
                      "access_token": tok})


def m365_feed(h: Any, tenant: str, rest: str, params: dict[str, str]) -> None:
    m = h.mock
    t = m.bearer("m365", h.headers.get("Authorization", ""))
    if t is None:
        return _ms_err(h, 401, "AF10001", "Authorization has been denied for this request (token missing, invalid "
                                          "or expired).")
    if t.get("aud") != MANAGE_AUD or t.get("tenant") != tenant or tenant != m.m365_tenant:
        return _ms_err(h, 401, "AF10001", "The token audience or tenant does not match this API.")
    if params.get("PublisherIdentifier"):
        with m.lock:
            m.publishers.add(params["PublisherIdentifier"])
    ct = params.get("contentType")
    if rest == "subscriptions/list" and h.command == "GET":
        return h.send_json(200, [{"contentType": c, "status": s, "webhook": None} for c, s in m.subscriptions.items()])
    if rest == "subscriptions/start" and h.command == "POST":
        if ct not in seed.CONTENT_TYPES + ("DLP.All",):
            return _ms_err(h, 400, "AF20012", f"Invalid content type {ct!r}.")
        with m.lock:
            if m.subscriptions.get(ct) == "enabled":
                return _ms_err(h, 400, "AF20024", "The subscription is already enabled. No property change.")
            m.subscriptions[ct] = "enabled"
            m.stats["m365_start"] += 1
        return h.send_json(200, {"contentType": ct, "status": "enabled", "webhook": None})
    if rest == "subscriptions/content" and h.command == "GET":
        return m365_content(h, tenant, ct, params)
    ma = re.match(r"^audit/([^/]+)$", rest)
    if ma and h.command == "GET":
        cid = ma.group(1)
        for blobs in m.seed.m365.values():
            for b in blobs:
                if b["contentId"] == cid:
                    with m.lock:
                        m.stats["m365_blobs"] += 1
                        m.stats["m365_rows"] += len(b["records"])
                    return h.send_json(200, b["records"])
        return _ms_err(h, 404, "AF20051", f"Content requested with the key {cid} has already expired or does not "
                                          f"exist.")
    _ms_err(h, 404, "AF20000", f"Unknown feed path {rest}")


def m365_content(h: Any, tenant: str, ct: str | None, params: dict[str, str]) -> None:
    m = h.mock
    if ct not in m.seed.m365:
        return _ms_err(h, 400, "AF20012", f"Invalid content type {ct!r}.")
    if m.subscriptions.get(ct) != "enabled":
        return _ms_err(h, 400, "AF20022", "No subscription found for the specified content type")
    s, e = params.get("startTime"), params.get("endTime")
    bad = "Start time and end time must both be specified (or both omitted) and must be less than or equal to 24 " \
          "hours apart, with the start time no more than 7 days in the past."
    if bool(s) != bool(e) or any(v and not _M365_TIME.match(v) for v in (s, e)):
        return _ms_err(h, 400, "AF20055", bad)
    now = int(time.time() * 1000)
    lo, hi = (parse_ts(s, strict_z=False), parse_ts(e, strict_z=False)) if s else (now - DAY_MS, now)
    if lo is None or hi is None or hi < lo or hi - lo > DAY_MS or lo < now - 7 * DAY_MS:
        return _ms_err(h, 400, "AF20055", bad)
    blobs = [b for b in m.seed.m365[ct] if lo <= b["created_ms"] <= min(hi, now)]
    qkey = {k: v for k, v in params.items() if k != "nextPage"}
    off = 0
    if params.get("nextPage"):
        o = read_bound(params["nextPage"], qkey)
        if o is None:
            return _ms_err(h, 400, "AF20030", "Invalid nextPage token")
        off = o
    page = blobs[off:off + m.m365_page_size]
    base = f"{m.url}/api/v1.0/{tenant}/activity/feed"
    out = [{"contentType": b["contentType"], "contentId": b["contentId"],
            "contentUri": f"{base}/audit/{b['contentId']}", "contentCreated": b["contentCreated"],
            "contentExpiration": b["contentExpiration"]} for b in page]
    hdr = {}
    if off + len(page) < len(blobs):
        hdr["NextPageUri"] = f"{base}/subscriptions/content?" + urlencode(
            {**qkey, "nextPage": bound_token(off + len(page), qkey)})
    with m.lock:
        m.stats["m365_list"] += 1
    h.send_json(200, out, hdr)


# ====================================================================== Google Workspace
def _g_err(h: Any, status: int, gstatus: str, msg: str) -> None:
    h.send_json(status, {"error": {"code": status, "message": msg, "status": gstatus,
                                   "errors": [{"message": msg, "domain": "global", "reason": gstatus.lower()}]}})


def gws_token(h: Any, body: bytes) -> None:
    m = h.mock
    form = dict(parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True))
    if form.get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer":
        return h.send_json(400, {"error": "unsupported_grant_type", "error_description": "grant_type"})
    parts = jwt_parts(form.get("assertion", ""))
    if parts is None or not jwt_times_ok(parts[1]) or not str(parts[1].get("aud", "")).endswith("/token"):
        return h.send_json(400, {"error": "invalid_grant", "error_description": "Invalid JWT Signature."})
    c = parts[1]
    if m.gws_client_email is not None and c.get("iss") != m.gws_client_email:
        return h.send_json(400, {"error": "invalid_grant", "error_description": "Invalid grant: account not found"})
    if GWS_SCOPE not in str(c.get("scope", "")).split():
        return h.send_json(400, {"error": "invalid_scope", "error_description": "scope"})
    sub = c.get("sub")
    if sub and m.gws_admins is not None and sub not in m.gws_admins:
        return h.send_json(401, {"error": "unauthorized_client", "error_description": "Client is unauthorized to "
                                 "retrieve access tokens using this method, or client not authorized for any of the "
                                 "scopes requested."})
    tok = m.issue("gws", sub=sub)
    h.send_json(200, {"access_token": tok, "expires_in": m.token_ttl_s, "token_type": "Bearer"})


def gws_list(h: Any, app: str, params: dict[str, str]) -> None:
    m = h.mock
    t = m.bearer("gws", h.headers.get("Authorization", ""))
    if t is None:
        return _g_err(h, 401, "UNAUTHENTICATED", "Request had invalid authentication credentials.")
    if not t.get("sub"):
        return _g_err(h, 403, "PERMISSION_DENIED", "Not Authorized to access this resource/api")
    if app not in GWS_APPS:
        return _g_err(h, 400, "INVALID_ARGUMENT", f"Invalid value '{app}'. Values must match the pattern.")
    if params.get("customerId") not in (None, seed.GWS_CUSTOMER):
        return _g_err(h, 403, "PERMISSION_DENIED", "Not Authorized to access this resource/api")
    s, e = params.get("startTime"), params.get("endTime")
    lo, hi = parse_ts(s) if s else 0, parse_ts(e) if e else int(time.time() * 1000)
    if lo is None or hi is None:
        return _g_err(h, 400, "INVALID_ARGUMENT", "Invalid value for startTime / endTime (RFC 3339).")
    try:
        size = int(params.get("maxResults", "1000"))
    except ValueError:
        size = 0
    if not 1 <= size <= 1000:
        return _g_err(h, 400, "INVALID_ARGUMENT", "maxResults must be between 1 and 1000")
    qkey = {k: v for k, v in params.items() if k != "pageToken"}
    qkey["app"] = app
    off = 0
    if params.get("pageToken"):
        o = read_bound(params["pageToken"], qkey)
        if o is None:
            return _g_err(h, 400, "INVALID_ARGUMENT", "Invalid page token")
        off = o
    items = [a for a in m.seed.gws.get(app, []) if lo <= parse_ts(a["id"]["time"]) <= hi]   # newest first
    page = items[off:off + size]
    out: dict[str, Any] = {"kind": "admin#reports#activities", "etag": "\"mock-etag\""}
    if page:
        out["items"] = page
    if off + len(page) < len(items):
        out["nextPageToken"] = bound_token(off + len(page), qkey)
    with m.lock:
        m.stats["gws_rows"] += len(page)
        m.stats["gws_pages"] += 1
    h.send_json(200, out)
