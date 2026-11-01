"""GET /api/integrations/status: enabled connectors / sinks / pivots, last pull, counts. Never returns secrets:
only whether the env var named in the config is set (True/False), never its value or the full config.
Also the integration catalog (GET /api/integrations/catalog): which connectors / sinks exist and their form fields."""

from __future__ import annotations

import importlib
import logging
import os
import re
from typing import Any
from urllib.parse import urlsplit

from attacklens import httpc
from attacklens import integrations as ig
from attacklens import pivots

log = logging.getLogger(__name__)

# Secret env-var names: every config key ending in "_env" (token_env, client_secret_env, secret_access_key_env, ...).


def _no_userinfo(url: Any) -> Any:
    """URL without user:password@ and query string (never echo credentials)."""
    return httpc.safe_url(url) if isinstance(url, str) and url else url


def _auth(c: dict[str, Any]) -> dict[str, bool]:
    """{<key>_env: resolved?} for every configured *_env key (generic: new connectors are covered automatically)."""
    return {k: ig.secret(c.get(k)) is not None for k in sorted(c) if isinstance(k, str) and k.endswith("_env")
            and isinstance(c.get(k), str) and c.get(k)}


def status(cfg: dict[str, Any]) -> dict[str, Any]:
    # same view as GET /api/integrations/{id}: integrations.yaml + the UI overlay (merged copy, cfg untouched)
    cfg = ig.apply_overlay({**cfg, "integrations": cfg.get("integrations")})
    ic = ig.icfg(cfg)
    st = ig.read_status(cfg)
    conn_st = st.get("connectors") or {}
    sink_st = st.get("sinks") or {}
    connectors = {}
    for name, c in (ic.get("connectors") or {}).items():
        c = c or {}
        modes = {}
        for mode in ("events", "alerts"):
            s = conn_st.get(f"{name}_{mode}") or {}
            last = s.get("last_cycle") or {}
            modes[mode] = {"last_pull_at": s.get("last_pull_at"), "last_error": s.get("last_error"),
                           "checkpoint": (s.get("checkpoint") or {}).get("last_ts"),
                           "last_cycle": {k: last.get(k) for k in ("pulled", "written", "skipped", "failed",
                                                                   "skipped_reasons", "failed_reasons", "ok")}
                           if last else None, "totals": s.get("totals")}
        connectors[name] = {"enabled": bool(c.get("enabled")), "base_url": _no_userinfo(c.get("base_url")),
                            "poll_interval_s": c.get("poll_interval_s"), "auth_env_set": _auth(c), "modes": modes}
    sinks = {}
    for name, c in (ic.get("sinks") or {}).items():
        c = c or {}
        s = sink_st.get(name) or {}
        sinks[name] = {"enabled": bool(c.get("enabled")), "target": _no_userinfo(c.get("base_url") or c.get("url")) or
                       (f"{c.get('host')}:{c.get('port')}" if c.get("host") else None),
                       "auth_env_set": _auth(c), "last_publish_at": s.get("last_publish_at"),
                       "last_ok_at": s.get("last_ok_at"), "last_error": s.get("last_error"), "last": s.get("last")}
    ai = ic.get("alert_input") or {}
    return {"connectors": connectors, "sinks": sinks, "pivot_siems": list(pivots.enabled_siems(ic)),
            "alert_input": {"enabled_live": bool(ai.get("enabled")),
                            "alerts_dir": ig.alerts_spool_dir(cfg).as_posix()},
            "spool": {"events_dir": ig.events_spool_dir(cfg).as_posix(),
                      "status_file": ig.status_file(cfg).as_posix()},
            "updated_at": st.get("updated_at")}


# ---- Catalog (GET /api/integrations/catalog) ------------------------------------------------------------------------
# A connector / sink module may define CATALOG (dict) or catalog_entry() -> dict; otherwise the static table below.
# Field: {key, label, type: text|url|secret|number|bool|select, required, placeholder?, help?, options?, default?,
# min?, max?}. A secret field key K is stored as reference "<id>.K" and resolved through the config key K_env
# (override with "env_key"). Dotted keys ("events.index") address nested config.
FIELD_TYPES = ("text", "url", "secret", "number", "bool", "select")
_MODES = ["events", "alerts"]
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")


def _f(key: str, label: str, type_: str = "text", required: bool = False, **kw: Any) -> dict[str, Any]:
    return {"key": key, "label": label, "type": type_, "required": required, **kw}


def _tls() -> dict[str, Any]:
    return _f("verify_tls", "Verify TLS certificate", "bool", default=True)


def _poll(default: int) -> dict[str, Any]:
    return _f("poll_interval_s", "Poll interval (seconds)", "number", default=default, min=1, max=3600)


def _since() -> dict[str, Any]:
    return _f("default_since", "First pull covers", "select", default="24h", options=["1h", "24h", "7d", "30d"],
              help="Used only on the first pull (no checkpoint yet).")


def _secret(key: str, label: str, env_hint: str) -> dict[str, Any]:
    return _f(key, label, "secret", help=f"Stored encrypted for this Windows user. Env var {env_hint} wins if set.")


STATIC_CATALOG: dict[str, dict[str, Any]] = {
    "elastic": {"kind": "siem", "name": "Elastic / OpenSearch", "modes": _MODES,
                "docs_url": "https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html",
                "fields": [_f("base_url", "Elasticsearch URL", "url", True, placeholder="https://es.example:9200"),
                           _f("flavor", "Flavor", "select", options=["elastic", "opensearch"], default="elastic"),
                           _secret("api_key", "API key", "ELASTIC_API_KEY"),
                           _secret("user", "Username (basic auth)", "ELASTIC_USER"),
                           _secret("password", "Password (basic auth)", "ELASTIC_PASSWORD"),
                           _f("events.index", "Events index pattern", default="logs-*"),
                           _f("alerts.index", "Alerts index pattern", default=".alerts-security.alerts-*"),
                           _tls(), _poll(10), _since()]},
    "splunk": {"kind": "siem", "name": "Splunk", "modes": _MODES,
               "docs_url": "https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch",
               "fields": [_f("base_url", "Splunk management URL", "url", True,
                             placeholder="https://splunk.example:8089"),
                          _secret("token", "Auth token (Bearer)", "SPLUNK_TOKEN"),
                          _f("events.search", "Events search", default="search index=main"),
                          _f("alerts.search", "Alerts (notables) search", default="search index=notable"),
                          _tls(), _poll(10), _since()]},
    "sentinel": {"kind": "siem", "name": "Microsoft Sentinel", "modes": _MODES,
                 "docs_url": "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/overview",
                 "fields": [_f("base_url", "Log Analytics API URL", "url", True,
                               default="https://api.loganalytics.io"),
                            _f("workspace_id", "Workspace ID", required=True,
                               placeholder="00000000-0000-0000-0000-000000000000",
                               help="Env var SENTINEL_WORKSPACE_ID wins if set."),
                            _secret("token", "Bearer token", "SENTINEL_TOKEN"),
                            _tls(), _poll(30), _since()]},
    "syslog": {"kind": "siem", "name": "Syslog / CEF listener (QRadar, ArcSight, ...)", "modes": _MODES,
               "fields": [_f("bind", "Listen address", "select", options=["127.0.0.1", "0.0.0.0"],
                             default="127.0.0.1", help="0.0.0.0 only on a trusted network segment."),
                          _f("udp_port", "UDP port", "number", default=5514, min=1, max=65535),
                          _f("tcp_port", "TCP port", "number", default=5514, min=1, max=65535)]},
    "splunk_hec": {"kind": "sink", "name": "Splunk HTTP Event Collector",
                   "docs_url": "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector",
                   "fields": [_f("base_url", "HEC URL", "url", True, placeholder="https://splunk.example:8088"),
                              _secret("token", "HEC token", "SPLUNK_HEC_TOKEN"),
                              _f("index", "Index (optional)"), _tls()]},
    "elastic_bulk": {"kind": "sink", "name": "Elasticsearch index (bulk)",
                     "fields": [_f("base_url", "Elasticsearch URL", "url", True,
                                   placeholder="https://es.example:9200"),
                                _f("index", "Index", required=True, default="attacklens-incidents"),
                                _secret("api_key", "API key", "ELASTIC_API_KEY"),
                                _secret("user", "Username (basic auth)", "ELASTIC_USER"),
                                _secret("password", "Password (basic auth)", "ELASTIC_PASSWORD"), _tls()]},
    "webhook": {"kind": "sink", "name": "Webhook (SOAR, Logic App, Slack, Teams)",
                "fields": [_f("url", "Webhook URL", "url", True, placeholder="https://soar.example/hooks/attacklens"),
                           _secret("token", "Bearer token (optional)", "named in token_env"),
                           _f("payload", "Payload", "select", options=["incident", "summary", "slack"],
                              default="incident"), _tls()]},
    "syslog_cef": {"kind": "sink", "name": "Syslog CEF",
                   "fields": [_f("host", "Host", required=True, placeholder="siem.example"),
                              _f("port", "Port", "number", True, default=5515, min=1, max=65535),
                              _f("protocol", "Protocol", "select", options=["udp", "tcp"], default="udp")]},
}


def _module_entry(mod_name: str) -> dict[str, Any] | None:
    try:
        mod = importlib.import_module(mod_name)
        fn = getattr(mod, "catalog_entry", None)
        entry = fn() if callable(fn) else getattr(mod, "CATALOG", None)
    except Exception as exc:  # noqa: BLE001 - one broken module must not hide the others
        log.warning("catalog: cannot load %s: %s", mod_name, type(exc).__name__)
        return None
    return dict(entry) if isinstance(entry, dict) else None


def _clean_fields(iid: str, fields: Any) -> list[dict[str, Any]]:
    out = []
    for f in fields if isinstance(fields, list) else []:
        if not isinstance(f, dict) or not isinstance(f.get("key"), str) or f.get("type") not in FIELD_TYPES \
                or not _KEY_RE.match(f["key"]) or f["key"] == "enabled":
            log.warning("catalog: %s: ignored a malformed field", iid)
            continue
        out.append({"label": f["key"], "required": False, **f})
    return out


def catalog() -> list[dict[str, Any]]:
    """Every connector of connectors.SOURCES and sink of sinks.SINKS; a module's CATALOG / catalog_entry() wins over
    the static table, so a new connector module shows up without changes here."""
    from attacklens import connectors, sinks

    out: list[dict[str, Any]] = []
    for ids, pkg, is_conn in ((connectors.SOURCES, "attacklens.connectors", True),
                              (sinks.SINKS, "attacklens.sinks", False)):
        for iid in ids:
            entry = _module_entry(f"{pkg}.{iid}") or STATIC_CATALOG.get(iid) or {"name": iid, "fields": []}
            kind = entry.get("kind")
            if kind not in (("siem", "cloud", "identity") if is_conn else ("sink",)):
                kind = ("cloud" if iid not in STATIC_CATALOG else "siem") if is_conn else "sink"
            e: dict[str, Any] = {"id": iid, "kind": kind, "name": str(entry.get("name") or iid)}
            if is_conn:
                e["modes"] = [m for m in entry.get("modes") or _MODES if m in _MODES] or list(_MODES)
            e["fields"] = _clean_fields(iid, entry.get("fields"))
            for k in ("docs_url", "help"):  # help = minimum permission text of the module
                if entry.get(k):
                    e[k] = str(entry[k])
            out.append(e)
    return out


# ---- Validation of PUT /api/integrations/{id} ----------------------------------------------------------------------
class FieldError(ValueError):
    """Invalid PUT body: message + offending field key (None = the body itself)."""

    def __init__(self, msg: str, field: str | None = None) -> None:
        super().__init__(msg)
        self.field = field


_CTRL = {chr(i) for i in range(32)} | {"\x7f"}


def _clean(field: dict[str, Any], v: Any, current: Any) -> Any:
    """Validated value of one non-secret field (None = remove the UI value, fall back to integrations.yaml)."""
    key, t = field["key"], field["type"]
    if v is None or v == "":
        return None
    if t == "bool":
        if isinstance(v, str) and v.lower() in ("true", "false"):
            return v.lower() == "true"
        if not isinstance(v, bool):
            raise FieldError("must be true or false", key)
        return v
    if t == "number":
        try:
            n = float(v) if not isinstance(v, bool) else float("nan")
        except (TypeError, ValueError):
            n = float("nan")
        if n != n or n in (float("inf"), float("-inf")):
            raise FieldError("must be a number", key)
        if ("min" in field and n < field["min"]) or ("max" in field and n > field["max"]):
            raise FieldError(f"must be between {field.get('min')} and {field.get('max')}", key)
        return int(n) if n.is_integer() else n
    if not isinstance(v, str) or len(v) > 2048 or any(c in _CTRL for c in v):
        raise FieldError("must be a single-line string (max 2048 chars)", key)
    v = v.strip()
    if t == "select":
        if v not in [str(o) for o in field.get("options") or []]:
            raise FieldError(f"must be one of {field.get('options')}", key)
    elif t == "url":
        if isinstance(current, str) and v == _no_userinfo(current) and current != v:
            return current  # the masked value shown by GET was sent back unchanged: keep the saved one
        try:
            u = urlsplit(v)
            host = u.hostname
        except ValueError:
            raise FieldError("not a valid URL", key) from None
        if u.scheme not in ("http", "https") or not host or " " in v:
            raise FieldError("must be an http:// or https:// URL with a host", key)
        if u.username is not None or u.password is not None:
            raise FieldError("no credentials in the URL; use the secret fields", key)
    return v


def validate(entry: dict[str, Any], body: Any, merged: dict[str, Any], stored: set[str],
             base: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str | None]]:
    if not isinstance(body, dict):
        raise FieldError("body must be a JSON object")
    settings, secrets = body.get("settings") or {}, body.get("secrets") or {}
    if not isinstance(settings, dict) or not isinstance(secrets, dict):
        raise FieldError("settings and secrets must be objects",
                         "settings" if not isinstance(settings, dict) else "secrets")
    fields = {f["key"]: f for f in entry["fields"]}
    out_s: dict[str, Any] = {}
    for k, v in settings.items():
        f = fields.get(k)
        if f is None:
            raise FieldError("unknown field", str(k)[:64])
        if f["type"] == "secret":
            raise FieldError("secret fields go in `secrets`", k)
        out_s[k] = _clean(f, v, ig.get_dotted(merged, k))
        if out_s[k] is None and f.get("required"):
            raise FieldError("required", k)
    out_x: dict[str, str | None] = {}
    for k, v in secrets.items():
        f = fields.get(k)
        if f is None or f["type"] != "secret":
            raise FieldError("unknown secret field", str(k)[:64])
        if v is not None and (not isinstance(v, str) or not v or len(v) > 8192 or any(c in "\r\n\x00" for c in v)):
            raise FieldError("secret must be a non-empty single-line string or null", k)
        out_x[k] = v
    for k, f in fields.items():
        if not f.get("required"):
            continue
        if f["type"] == "secret":
            ok = out_x.get(k) is not None or (k not in out_x and (f"{entry['id']}.{k}" in stored or
                                                                   env_set(base, f)))
        else:
            v = out_s[k] if k in out_s else ig.get_dotted(merged, k)
            ok = v not in (None, "")
        if not ok:
            raise FieldError("required", k)
    return out_s, out_x


def env_key(f: dict[str, Any]) -> str:
    return str(f.get("env_key") or f"{f['key']}_env")


def env_set(base: dict[str, Any], f: dict[str, Any]) -> bool:
    name = base.get(env_key(f))
    return bool(name) and bool(os.environ.get(str(name)))


# ---- Connection test pre-checks (POST /test steps "dns" and "connect") ----------------------------------------------
# (config key holding a URL override, default URL) per integration; a module may define endpoints(ccfg) -> [url].
_ENDPOINTS: dict[str, list[tuple[str, str | None]]] = {
    "azure_monitor": [("base_url", "https://api.loganalytics.io"), ("login_url", "https://login.microsoftonline.com")],
    "gcp_logging": [("base_url", "https://logging.googleapis.com"), ("token_uri", "https://oauth2.googleapis.com")],
    "aws_cloudtrail": [("endpoint_url", "https://cloudtrail.{region}.amazonaws.com")],
}


def endpoints(entry: dict[str, Any], c: dict[str, Any]) -> list[tuple[str, str, int]]:
    """(scheme, host, port) the integration talks to; [] for a local listener (syslog) or UDP."""
    if entry["id"] == "syslog" or (c.get("host") and str(c.get("protocol", "udp")) != "tcp"):
        return []
    if c.get("host"):
        return [("tcp", str(c["host"]), int(c.get("port") or 0))]
    pkg = "sinks" if entry["kind"] == "sink" else "connectors"
    fn = getattr(importlib.import_module(f"attacklens.{pkg}.{entry['id']}"), "endpoints", None)
    pairs = _ENDPOINTS.get(entry["id"], [("base_url", None), ("url", None)])
    urls = fn(c) if callable(fn) else [c.get(k) or (d.format(region=c.get("region") or "us-east-1") if d else None)
                                       for k, d in pairs]
    out = []
    for u in urls:
        if isinstance(u, str) and u:
            p = urlsplit(u)
            if p.hostname:
                out.append((p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)))
    return list(dict.fromkeys(out))


def proxy_for(scheme: str, host: str) -> tuple[str, int] | None:
    """(host, port) of the env proxy (HTTPS_PROXY / HTTP_PROXY, NO_PROXY honoured) used for this target."""
    import urllib.request

    if scheme not in ("http", "https") or urllib.request.proxy_bypass(host):
        return None
    p = urllib.request.getproxies().get(scheme)
    if not p:
        return None
    u = urlsplit(p if "://" in p else f"http://{p}")
    return (u.hostname, u.port or 8080) if u.hostname else None


def resolve(host: str, port: int) -> None:
    import socket

    socket.getaddrinfo(host, port or None, proto=6)


def handshake(scheme: str, host: str, port: int, verify_tls: bool, ca_file: str | None, timeout: float) -> None:
    """TCP connect, then a TLS handshake for https (with the configured CA file / verification)."""
    import socket
    import ssl

    with socket.create_connection((host, port), timeout=timeout) as s:
        if scheme == "https":
            ctx = ssl.create_default_context(cafile=ca_file or None)
            if not verify_tls:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            ctx.wrap_socket(s, server_hostname=host).close()


# ---- Vendor error detail + fix hints for the connection test (allow-listed codes only) ---------------------------
_CRED_FIX = {"AADSTS7000215": "create a new client secret (App registrations > Certificates & secrets) and paste "
                              "its Value, not its Secret ID",
             "AADSTS7000222": "the client secret expired: create a new one",
             "AADSTS700016": "check the Application (client) ID and that the app exists in this tenant",
             "AADSTS90002": "check the Directory (tenant) ID", "AADSTS900023": "check the Directory (tenant) ID",
             "InvalidClientTokenId": "check the access key ID", "UnrecognizedClient": "check the access key ID",
             "SignatureDoesNotMatch": "check the secret access key", "InvalidSignature": "check the secret access key",
             "ExpiredToken": "the session token expired: paste a fresh one",
             "invalid_grant": "the service account key was revoked or the PC clock is wrong: create a new key"}


def fix_hint(iid: str, c: dict[str, Any], d: str, denied: bool) -> str:
    """Actionable fix for a credential (denied=False) or permission (denied=True) failure."""
    if not denied:
        return next((v for k, v in _CRED_FIX.items() if k in d), "check the key, token or secret")
    if iid in ("sentinel", "azure_monitor"):
        return f"grant the app 'Log Analytics Reader' on workspace {c.get('workspace_id') or '<workspace id>'}"
    if iid == "aws_cloudtrail":
        m = re.search(r"for ([a-z0-9-]+:[A-Za-z0-9]+)", d)
        return f"allow {m.group(1) if m else 'cloudtrail:LookupEvents'} in the IAM policy of this key or role"
    if iid == "gcp_logging":
        return (f"grant roles/logging.viewer (roles/logging.privateLogViewer for Data Access logs) on project(s) "
                f"{c.get('project_ids') or '<project>'}")
    if iid in ("elastic", "elastic_bulk"):
        idx = ig.get_dotted(c, "events.index") or c.get("index") or "the index"
        return f"give the API key or user 'read' and 'view_index_metadata' on {idx}"
    if iid == "splunk":
        return "give the token's role the 'search' capability and access to the searched index"
    return "grant the account read permission for this data"
