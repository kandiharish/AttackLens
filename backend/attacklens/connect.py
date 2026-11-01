"""Pull from a SIEM into the spool (AttackLens on top of an existing SIEM).

    python -m attacklens.connect --source elastic|splunk|sentinel|syslog [--mode events|alerts] [--since 24h]
                                 [--once] [--reset] [--config DIR]   (any id of connectors.SOURCES)

- events: raw events -> <spool.events_dir>/<source>/... (default <live watch_dir>/siem): live mode ingests them.
- alerts: SIEM alerts -> raw_alerts rows in <spool.alerts_dir>/<source>/*.jsonl: read by detect only when
  alert-input mode is on (live: integrations.yaml alert_input.enabled; batch: run.py --siem-alerts).
--since: start point when there is no checkpoint yet (default connectors.<source>.default_since).
--reset: forget the checkpoint (use with --since to re-pull a range).
The connector must be enabled in config/integrations.yaml or from the UI (data/integrations/settings.json,
applied for the default config dir or with ATTACKLENS_INTEGRATIONS_OVERLAY=1). Everything is disabled by default.
Counts per cycle go to connector_status.json; exit code 1 if a --once cycle failed.
"""

from __future__ import annotations

import argparse
import copy
import importlib
import json
import logging
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from attacklens import connectors, httpc
from attacklens import integrations_status as ist
from attacklens.connectors.base import MissingDependency
from attacklens import integrations as ig
from attacklens.config import load_config

log = logging.getLogger("attacklens.connect")


def pull(source: str, mode: str, cfg: dict[str, Any], since: str | int | None = None,
         reset: bool = False) -> dict[str, Any]:
    """One cycle, programmatic. since: '24h' / ms epoch / None (config default_since); used only without a
    checkpoint. Returns the cycle stats (pulled, written, skipped, failed, *_reasons, ok, error) plus the flat
    view fetched / dropped (= skipped + failed) / drop_reasons / errors (0 or 1) / last_error.
    Syslog: listens once_seconds, then flushes."""
    since_ms = None
    if isinstance(since, (int, float)) and not isinstance(since, bool):
        since_ms = int(since)
    elif since:
        since_ms = ig.now_ms() - ig.parse_duration_ms(since)
    conn = connectors.get(source, cfg, mode, since_ms, reset)
    if source == "syslog":
        import time

        conn.start()  # type: ignore[attr-defined]
        try:
            time.sleep(float(conn.ccfg.get("once_seconds", 5)))
            st = conn.flush()  # type: ignore[attr-defined]
        finally:
            conn.stop()  # type: ignore[attr-defined]
    else:
        st = conn.cycle()
    reasons = {**st["skipped_reasons"]}
    for k, v in st["failed_reasons"].items():
        reasons[k] = reasons.get(k, 0) + v
    return {**st, "fetched": st["pulled"], "dropped": st["skipped"] + st["failed"], "drop_reasons": reasons,
            "errors": 0 if st["ok"] else 1, "last_error": st["error"]}


# ---- connection test (POST /api/integrations/{id}/test) -----------------------------------------------------------
TEST_TIMEOUT_S = 10.0
TEST_WINDOW_MS = 300_000  # connectors: at most 1 row from the last 5 minutes


def _target(c: dict[str, Any]) -> str:
    url = c.get("base_url") or c.get("url")
    if isinstance(url, str) and url:
        try:
            p = urllib.parse.urlsplit(url)
            return f"{p.hostname}{f':{p.port}' if p.port else ''}"
        except ValueError:
            return "the configured URL"
    host = c.get("host") or c.get("bind")
    return f"{host}:{c.get('port') or c.get('tcp_port') or c.get('udp_port') or ''}".rstrip(":") if host else "it"


class ProbeFailed(RuntimeError):
    """A module's own test_connection() reported {ok: false, error_code, message}."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.error_code, self.user_message = code, message


def _classify(exc: BaseException, target: str, name: str = "The service", iid: str = "",
              c: dict[str, Any] | None = None) -> tuple[str, str]:
    """(error_code, actionable message) from fixed text plus allow-listed vendor codes only: never the raw
    exception text or response body (either may quote a URL, a header or the request)."""
    code, msg = getattr(exc, "error_code", None), getattr(exc, "user_message", None)
    if isinstance(code, str) and isinstance(msg, str):
        return code, msg  # a connector module's own probe already mapped it
    if isinstance(exc, MissingDependency):  # optional library (pip extra) not installed
        text = str(exc)
        return "missing_dependency", text if "pip install" in text and len(text) < 300 else             'A required library is not installed: run pip install "attacklens[cloud]", then restart AttackLens.'
    if isinstance(exc, PermissionError):
        return "auth_missing", "No credentials set: enter them in the secret fields (or set the env var)."
    status = getattr(exc, "status", None)
    if isinstance(exc, httpc.HttpError) and status is not None:
        d = ig.vendor_detail(str(exc.body or ""))
        det = f" ({d})" if d else ""
        denied = any(k in d for k in ("AccessDenied", "UnauthorizedOperation", "PERMISSION_DENIED",
                                      "AuthorizationFailed"))
        bad_cred = "AADSTS" in d or any(k in d for k in (
            "UnrecognizedClient", "InvalidClientTokenId", "SignatureDoesNotMatch", "InvalidSignature", "ExpiredToken",
            "UNAUTHENTICATED", "InvalidAuthenticationToken", "invalid_client", "invalid_grant"))
        if status == 401 or (bad_cred and not denied) or (iid == "splunk_hec" and status == 403):  # HEC: bad token
            return "auth_failed", f"{name} rejected the credentials (HTTP {status}){det}: {ist.fix_hint(iid, c or {}, d, False)}."
        if status == 403 or denied:
            return "permission_denied", (f"{name} accepted the credentials but denied access (HTTP {status}){det}: "
                                         f"{ist.fix_hint(iid, c or {}, d, True)}.")
        if status == 404:
            return "bad_response", f"Not found on {target} (HTTP 404){det}: check the URL, index, search or workspace."
        if status == 429:
            return "rate_limited", f"{name} is rate-limiting requests (HTTP 429): try again in a minute."
        if status >= 500:
            return "bad_response", f"{name} server error (HTTP {status}){det}: try again later."
        return "bad_response", f"{target} answered HTTP {status}{det}."
    text = str(exc).lower()
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    via = " via the HTTPS_PROXY proxy" if proxy else ""
    if isinstance(exc, (TimeoutError, socket.timeout)) or "timeout" in text or "timed out" in text:
        return "timeout", f"No answer from {target}{via} within {TEST_TIMEOUT_S:g} s: check the address and firewall."
    if isinstance(exc, socket.gaierror) or any(s in text for s in ("getaddrinfo", "name or service", "nodename",
                                                                      "11001", "name resolution")):
        return "not_reachable", f"Host name {target} could not be resolved (DNS): check the URL."
    if "certificate verify failed" in text or "certificate_verify_failed" in text:
        if "hostname mismatch" in text or "match" in text and "hostname" in text:
            return "tls_error", f"{name} certificate is for a different host name than {target}."
        return "tls_error", (f"{name} certificate not trusted ({target}): add a CA file or turn off "
                             f"'Verify TLS certificate'.")
    if "wrong version number" in text or "unknown protocol" in text or "record layer failure" in text:
        return "tls_error", f"{target} does not speak HTTPS on this port: use http:// or the TLS port."
    if isinstance(exc, ssl.SSLError) or any(s in text for s in ("[ssl", "ssl:", "certificate", "tlsv")):
        return "tls_error", f"TLS handshake with {target} failed: check https://, the port and the certificate."
    if isinstance(exc, OSError) or any(s in text for s in ("refused", "10061", "unreachable", "failed:")):
        if isinstance(exc, OSError) and getattr(exc, "errno", None) in (98, 10048):
            return "port_in_use", f"Port {target} is already in use (is the listener already running?)."
        if proxy and "proxy" in text:
            return "not_reachable", "The HTTPS_PROXY proxy refused or failed the connection: check the proxy setting."
        return "not_reachable", f"Cannot connect to {target}{via}: check the host, port and firewall."
    if isinstance(exc, httpc.HttpError) and "not json" in text:
        return "bad_response", f"{target} did not answer with JSON: is this the API URL (not the web UI)?"
    if isinstance(exc, (ValueError, KeyError, TypeError, httpc.HttpError)):
        return "bad_config", "The saved settings are incomplete or invalid for this integration."
    return "error", f"Connection test failed ({type(exc).__name__})."


def _module_result(res: Any) -> tuple[int, int | None]:
    if isinstance(res, dict):
        if res.get("ok") is False:
            raise ProbeFailed(str(res.get("error_code") or "error"), str(res.get("message") or "test failed"))
        return int(res.get("sample_count") or 0), ig.to_ms(res.get("newest"))
    return int(res or 0), None


def _probe_connector(entry: dict[str, Any], cfg: dict[str, Any], c: dict[str, Any]) -> tuple[int, int | None]:
    iid = entry["id"]
    fn = getattr(importlib.import_module(f"attacklens.connectors.{iid}"), "test_connection", None)
    if callable(fn):  # a connector may bring its own probe
        return _module_result(fn(cfg))
    if iid == "syslog":
        bind = str(c.get("bind", "127.0.0.1"))
        for kind, port in ((socket.SOCK_DGRAM, c.get("udp_port")), (socket.SOCK_STREAM, c.get("tcp_port"))):
            if port:
                with socket.socket(socket.AF_INET, kind) as s:
                    s.bind((bind, int(port)))
        return 0, None
    c.update(timeout_s=min(float(c.get("timeout_s") or TEST_TIMEOUT_S), TEST_TIMEOUT_S), page_size=1,
             max_pages_per_cycle=1, use_pit=False)
    mode = "events" if "events" in (entry.get("modes") or ["events"]) else "alerts"
    m = c.get(mode) if isinstance(c.get(mode), dict) else {}
    if iid == "splunk" and isinstance(m.get("search"), str):
        m["search"] = m["search"] + " | head 1"
    since = ig.now_ms() - TEST_WINDOW_MS
    conn = connectors.get(iid, cfg, mode, since)
    conn.check_auth()
    gen = conn.pull(since)
    try:
        end = getattr(importlib.import_module("attacklens.connectors.base"), "PAGE_END", None)
        rec = next((r for r in gen if r is not end), None)  # first real row; page markers are not data
        return (0, None) if rec is None else (1, getattr(rec, "ts_ms", None))
    finally:
        close = getattr(gen, "close", None)
        if callable(close):
            close()


def _hec_code(body: str) -> int | None:
    """Splunk HEC error code of a response body ({"text": ..., "code": n}); None if it is not HEC JSON."""
    try:
        return int(json.loads(body or "")["code"])
    except (ValueError, KeyError, TypeError):  # not JSON / no code: match the vendor text
        low = (body or "").lower()
        return 5 if "no data" in low else 10 if "data channel is missing" in low else None


def _probe_sink(iid: str, c: dict[str, Any], cfg: dict[str, Any]) -> tuple[int, int | None]:
    fn = getattr(importlib.import_module(f"attacklens.sinks.{iid}"), "test_connection", None)
    if callable(fn):
        return _module_result(fn(c, cfg))
    to, tls = min(float(c.get("timeout_s") or TEST_TIMEOUT_S), TEST_TIMEOUT_S), bool(c.get("verify_tls", True))
    ca = str(c.get("ca_file") or "") or None  # same CA bundle as the TLS pre-check and the sink's send()
    if iid == "splunk_hec":  # empty POST: a valid token gets 400 "No data" (code 5), a bad one 401 / 403
        from attacklens.sinks.splunk_hec import channel

        tok = ig.secret(c.get("token_env"))
        # the sink's kept channel, read-only (a test writes no state): with indexer ack on, a POST without one gets
        # code 10 "Data channel is missing"
        headers = {"X-Splunk-Request-Channel": channel(cfg, persist=False),
                   **({"Authorization": f"Splunk {tok}"} if tok else {})}
        try:
            httpc.request_json("POST", httpc.join(str(c["base_url"]), "/services/collector/event"),
                               headers=headers, raw_body=b"", timeout=to, verify_tls=tls, ca_file=ca)
        except httpc.HttpError as exc:
            if exc.status != 400 or _hec_code(exc.body) not in (5, 10):  # 5 "No data", 10 "Data channel is missing"
                raise
    elif iid == "elastic_bulk":
        from attacklens.sinks.elastic_bulk import _headers

        httpc.request_json("GET", httpc.join(str(c["base_url"]), "/"), headers=_headers(c), timeout=to,
                           verify_tls=tls, ca_file=ca)
    elif iid == "webhook":
        tok = ig.secret(c.get("token_env"))
        body = {"text": "AttackLens connection test"} if c.get("payload") == "slack" else \
            {"attacklens": "connection_test"}
        with httpc.open_url("POST", str(c["url"]), json.dumps(body).encode("utf-8"),
                            {"Content-Type": "application/json", **({"Authorization": f"Bearer {tok}"} if tok
                                                                    else {})}, to, tls, ca) as resp:
            resp.read(4096)
    elif iid == "syslog_cef":
        from attacklens.connectors.syslog import send_lines

        send_lines(["CEF:0|Mitigata|AttackLens|0.1|test|AttackLens connection test|1|"], str(c["host"]),
                   int(c["port"]), str(c.get("protocol", "udp")), to)
    else:
        raise ValueError("no connection test for this integration")
    return 0, None


STEPS = ("config", "dns", "connect", "auth", "permission", "data")
_STEP_OF = {"bad_config": "config", "missing_dependency": "auth", "auth_missing": "auth", "auth_failed": "auth",
            "not_reachable": "connect", "timeout": "connect", "tls_error": "connect", "port_in_use": "connect"}


class _Stop(Exception):
    pass


def _diagnose(entry: dict[str, Any], cfg: dict[str, Any], c: dict[str, Any], steps: list[dict[str, Any]]) -> int:
    """Steps config -> dns -> connect -> auth -> permission -> data; appends to `steps`, raises _Stop at the first
    failure. Returns the sample count."""
    iid, name, sink = entry["id"], str(entry.get("name") or entry["id"]), entry["kind"] == "sink"

    def step(n: str, ok: bool, detail: str) -> None:
        steps.append({"name": n, "ok": ok, "detail": detail})
        if not ok:
            raise _Stop

    def fail(exc: BaseException, target: str, at: str | None = None) -> None:
        code, msg = _classify(exc, target, name, iid, c)
        where = at or _STEP_OF.get(code, "permission")
        if where == "permission" and not any(x["name"] == "auth" for x in steps):
            step("auth", True, "Credentials accepted.")
        steps.append({"name": where, "ok": False, "detail": msg, "error_code": code})
        raise _Stop

    missing = [str(f.get("label") or f["key"]) for f in entry["fields"] if f.get("required") and (
        ig.secret(c.get(f.get("env_key") or f"{f['key']}_env")) is None if f["type"] == "secret"
        else ig.get_dotted(c, f["key"]) in (None, ""))]
    step("config", not missing, f"Missing: {', '.join(missing)}. Fill them in and Save." if missing
         else "All required settings are present.")
    eps = ist.endpoints(entry, c)
    to = TEST_TIMEOUT_S
    for scheme, host, port in eps:
        if ist.proxy_for(scheme, host) is None:
            try:
                ist.resolve(host, port)
            except OSError as exc:
                fail(exc, host, "dns")
    step("dns", True, ", ".join(f"{h} resolves" if ist.proxy_for(sc, h) is None else f"{h} via proxy"
                                for sc, h, _ in eps) or "Not needed (local listener or UDP).")
    for scheme, host, port in eps:
        px = ist.proxy_for(scheme, host)
        try:
            if px:
                ist.handshake("tcp", px[0], px[1], True, None, to)
            else:
                ist.handshake(scheme, host, port, bool(c.get("verify_tls", True)), c.get("ca_file"), to)
        except OSError as exc:
            fail(exc, f"{px[0]}:{px[1]} (HTTPS_PROXY)" if px else f"{host}:{port}")
    step("connect", True, ", ".join(f"{h}:{p} {'TLS OK' if sc == 'https' else 'reachable'}" for sc, h, p in eps)
         or "Not needed.")
    try:
        n, newest = _probe_sink(iid, c, cfg) if sink else _probe_connector(entry, cfg, c)
    except Exception as exc:  # noqa: BLE001 - mapped to the failing step
        fail(exc, _target(c))
    step("auth", True, "Credentials accepted." if iid != "syslog" else "Not needed (listener).")
    step("permission", True, "Test message accepted." if sink else
         "Listen ports are free." if iid == "syslog" else "Minimal read call succeeded.")
    step("data", True, "Not applicable (outbound sink)." if sink or iid == "syslog" else
         f"{n} row(s) in the last 5 min, newest {ig.iso_ms(newest) or 'unknown'}." if n else
         "Connected, but no rows in the last 5 min: check the index / query / filter, or wait for new data.")
    return n


def test_connection(entry: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """Step-by-step real check against the saved settings (connectors: <= 1 row of the last 5 min; sinks: an auth
    check or one test message), bounded by TEST_TIMEOUT_S per step. Returns {ok, latency_ms, sample_count, message,
    error_code?, steps: [{name, ok, detail}]}; messages are fixed text plus allow-listed vendor codes, scrubbed of
    every resolved secret value."""
    cfg = copy.deepcopy(cfg)
    sec = "sinks" if entry["kind"] == "sink" else "connectors"
    c = ig.icfg(cfg).setdefault(sec, {}).setdefault(entry["id"], {}) or {}
    ig.icfg(cfg)[sec][entry["id"]] = c
    target = _target(c)
    secrets = [v for v in (ig.secret(c.get(k)) for k in list(c) if k.endswith("_env")) if v]
    box: dict[str, Any] = {}
    steps: list[dict[str, Any]] = []

    def work() -> None:
        try:
            box["n"] = _diagnose(entry, cfg, c, steps)
        except _Stop:
            pass
        except BaseException as exc:  # noqa: BLE001 - reported as an error code
            steps.append({"name": "error", "ok": False, "detail": _classify(exc, target)[1], "error_code": "error"})

    t0 = time.perf_counter()
    th = threading.Thread(target=work, name=f"test-{entry['id']}", daemon=True)
    th.start()
    th.join(TEST_TIMEOUT_S * 3 + 2)
    ms = round((time.perf_counter() - t0) * 1000)
    got = {x["name"]: dict(x) for x in list(steps) if x["name"] in STEPS}
    pending = next((n for n in STEPS if n not in got), None)
    if pending and (th.is_alive() or any(x["name"] == "error" for x in steps)):
        err = next((x for x in steps if x["name"] == "error"), None)
        got[pending] = {"name": pending, "ok": False, "error_code": "timeout" if err is None else "error",
                        "detail": err["detail"] if err else f"No answer from {target} within {TEST_TIMEOUT_S:g} s."}
    out_steps = [got.get(n) or {"name": n, "ok": None, "detail": None} for n in STEPS]
    bad = next((x for x in out_steps if x["ok"] is False), None)
    bad_code = str((bad or {}).get("error_code") or "error")
    for x in out_steps:
        x.pop("error_code", None)
        if x["detail"] is not None:
            for sv in secrets:
                x["detail"] = str(x["detail"]).replace(sv, "***")
    if bad is None:
        n = int(box.get("n") or 0)
        what = "connection test sent" if sec == "sinks" else f"{n} sample row(s) in the last 5 min"
        return {"ok": True, "latency_ms": ms, "sample_count": n, "message": f"Connected to {target}: {what}.",
                "steps": out_steps}
    log.info("connect test %s: %s at step %s (%d ms)", entry["id"], bad_code, bad["name"], ms)
    return {"ok": False, "latency_ms": ms, "sample_count": 0, "message": bad["detail"], "error_code": bad_code,
            "steps": out_steps}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="attacklens.connect", description="Pull from a SIEM into the AttackLens spool")
    ap.add_argument("--source", required=True, choices=connectors.SOURCES)
    ap.add_argument("--mode", default="events", choices=("events", "alerts"))
    ap.add_argument("--since", help="first pull when no checkpoint exists, e.g. 30m, 24h, 7d")
    ap.add_argument("--once", action="store_true", help="one cycle (syslog: listen once_seconds) and exit")
    ap.add_argument("--reset", action="store_true", help="forget the checkpoint of this source+mode")
    ap.add_argument("--config", help="config directory (default <repo>/config)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config(Path(a.config) if a.config else None)
    if a.config is None or os.environ.get(ig.OVERLAY_ENV) == "1":
        ig.apply_overlay(cfg)  # settings saved from the UI (data/integrations/settings.json)
    ccfg = (ig.icfg(cfg).get("connectors") or {}).get(a.source) or {}
    if not ccfg.get("enabled"):
        log.error("connector %s is disabled; set connectors.%s.enabled: true in config/integrations.yaml",
                  a.source, a.source)
        return 2
    try:
        since = ig.now_ms() - ig.parse_duration_ms(a.since) if a.since else None
        conn = connectors.get(a.source, cfg, a.mode, since, a.reset)
    except ValueError as exc:
        log.error("%s", exc)
        return 2
    log.info("connect %s (%s): spool %s, checkpoint %s", a.source, a.mode, conn.spool_root() / a.source,
             ig.iso_ms(conn.checkpoint.last_ts_ms) or "none")
    return conn.run(a.once)


if __name__ == "__main__":
    sys.exit(main())
