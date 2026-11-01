"""Minimal HTTP client on stdlib urllib.request (no third-party dependency).

Headers are never logged (they may carry tokens). Responses can be streamed line by line (bounded memory).
Retries are opt-in (`retries=N`): only 429 / 502 / 503 / 504, exponential backoff with full jitter, a server
Retry-After is honoured (capped). Error messages carry the first 300 characters of the response body, scrubbed of
credentials. `ca_file` adds a private CA bundle next to `verify_tls`.
"""

from __future__ import annotations

import base64
import json
import logging
import random
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from typing import Any, Callable, Iterator, TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")
USER_AGENT = "AttackLens/0.1"
RETRY_STATUS = frozenset({429, 502, 503, 504})
MAX_RETRY_AFTER_S = 60.0
BODY_EXCERPT = 300
_sleep = time.sleep  # tests monkeypatch this (no real waiting)

_SCHEME_RX = re.compile(r"(?i)\b(bearer|basic|apikey|splunk)\s+[A-Za-z0-9._~+/=:-]{6,}")
_KV_RX = re.compile(r"(?i)(\"?(?:access_token|refresh_token|id_token|client_secret|password|secret|token|api_key|"
                    r"apikey|private_key|assertion|signature|sig)\"?\s*[:=]\s*\"?)[^\"&,\s}]+")
_PEM_RX = re.compile(r"-----BEGIN [A-Z ]+-----.*?(?:-----END [A-Z ]+-----|$)", re.S)
_LONG_RX = re.compile(r"[A-Za-z0-9+/_.-]{40,}={0,2}")


class HttpError(RuntimeError):
    """Non-2xx response or transport failure. `status` is None for transport errors."""

    def __init__(self, msg: str, status: int | None = None, body: str = "", retry_after: float | None = None) -> None:
        super().__init__(msg)
        self.status, self.body, self.retry_after = status, body, retry_after


def scrub(text: str, secrets: list[str] | None = None) -> str:
    """Response excerpt without credentials: known secret values, auth-scheme tokens, key=value secrets, PEM blocks
    and long opaque strings (JWTs, keys) are replaced by ***."""
    for v in sorted({s for s in secrets or [] if s and len(s) >= 6}, key=len, reverse=True):
        text = text.replace(v, "***")
    text = _SCHEME_RX.sub(lambda m: m.group(1) + " ***", text)
    text = _KV_RX.sub(lambda m: m.group(1) + "***", text)
    text = _PEM_RX.sub("***", text)
    return _LONG_RX.sub("***", text)


def parse_retry_after(v: str | None) -> float | None:
    """Retry-After: delta seconds or an HTTP date -> seconds (>= 0); None if absent / unparseable."""
    if not v:
        return None
    try:
        return max(0.0, float(v))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        return max(0.0, parsedate_to_datetime(v).timestamp() - time.time())
    except (TypeError, ValueError, IndexError):
        return None


def backoff_s(attempt: int, base_s: float = 1.0, cap_s: float = 30.0, retry_after: float | None = None) -> float:
    """Full-jitter exponential backoff; a server Retry-After wins (capped at MAX_RETRY_AFTER_S)."""
    if retry_after is not None:
        return min(retry_after, MAX_RETRY_AFTER_S)
    return random.uniform(0, min(cap_s, base_s * (2 ** attempt)))


def with_retries(fn: Callable[[], T], retries: int = 0, base_s: float = 1.0, cap_s: float = 30.0,
                 what: str = "") -> T:
    """fn(); an HttpError with status 429/502/503/504 is retried up to `retries` times after a backoff. Anything else
    (401, 500, timeouts, transport errors) is raised at once, so a dead endpoint fails within its own timeout."""
    attempt = 0
    while True:
        try:
            return fn()
        except HttpError as exc:
            if exc.status not in RETRY_STATUS or attempt >= retries:
                raise
            d = backoff_s(attempt, base_s, cap_s, exc.retry_after)
            log.info("http: %s -> HTTP %s; retry %d/%d in %.1f s", what or "request", exc.status, attempt + 1,
                     retries, d)
            _sleep(d)
            attempt += 1


def _ctx(url: str, verify_tls: bool, ca_file: str | None = None) -> ssl.SSLContext | None:
    if not url.lower().startswith("https"):
        return None
    if verify_tls:
        return ssl.create_default_context(cafile=str(ca_file)) if ca_file else ssl.create_default_context()
    log.warning("http: TLS verification disabled for %s", urllib.parse.urlsplit(url).netloc)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def join(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


@contextmanager
def open_url(method: str, url: str, body: bytes | None = None, headers: dict[str, str] | None = None,
             timeout: float = 30.0, verify_tls: bool = True, ca_file: str | None = None) -> Iterator[Any]:
    """Context manager yielding the open response (2xx only; anything else raises HttpError)."""
    url, basic = _split_userinfo(url)
    h = {"User-Agent": USER_AGENT, **basic, **(headers or {})}
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=_ctx(url, verify_tls, ca_file))  # noqa: S310
    except urllib.error.HTTPError as exc:
        text = ""
        try:
            text = exc.read(2000).decode("utf-8", errors="replace")
        except OSError:
            pass
        secrets = [v for hv in h.values() for v in (hv, hv.split(" ", 1)[-1])]
        excerpt = " ".join(scrub(text, secrets).split())[:BODY_EXCERPT]
        ra = parse_retry_after(exc.headers.get("Retry-After") if exc.headers is not None else None)
        raise HttpError(f"{method} {_safe(url)} -> HTTP {exc.code}" + (f": {excerpt}" if excerpt else ""),
                        exc.code, text, ra) from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(exc, TimeoutError) or isinstance(reason, TimeoutError):
            raise HttpError(f"{method} {_safe(url)} failed: timeout after {timeout:g} s") from None
        raise HttpError(f"{method} {_safe(url)} failed: {reason}") from None
    try:
        yield resp
    finally:
        resp.close()


def safe_url(url: str) -> str:
    """URL for messages / status: no user:password@ and no query string (either may carry secrets)."""
    try:
        p = urllib.parse.urlsplit(str(url))
        host = p.hostname or ""
        port = f":{p.port}" if p.port else ""
    except ValueError:
        return "<invalid url>"
    return f"{p.scheme}://{host}{port}{p.path}"


_safe = safe_url


def _split_userinfo(url: str) -> tuple[str, dict[str, str]]:
    """http://user:pw@host/... -> (http://host/..., Basic auth header). The credentials never reach a message."""
    p = urllib.parse.urlsplit(url)
    if p.username is None:
        return url, {}
    netloc = (p.hostname or "") + (f":{p.port}" if p.port else "")
    cred = f"{urllib.parse.unquote(p.username)}:{urllib.parse.unquote(p.password or '')}"
    return urllib.parse.urlunsplit((p.scheme, netloc, p.path, p.query, p.fragment)), \
        {"Authorization": "Basic " + base64.b64encode(cred.encode("utf-8")).decode("ascii")}


def request_json(method: str, url: str, payload: Any = None, headers: dict[str, str] | None = None,
                 timeout: float = 30.0, verify_tls: bool = True, raw_body: bytes | None = None,
                 content_type: str = "application/json", ca_file: str | None = None, retries: int = 0) -> Any:
    """Send JSON (or raw_body) and parse a JSON response ({} for an empty body). retries: see with_retries."""
    if retries:
        return with_retries(lambda: request_json(method, url, payload, headers, timeout, verify_tls, raw_body,
                                                 content_type, ca_file), retries, what=f"{method} {_safe(url)}")
    body = raw_body if raw_body is not None else (None if payload is None else
                                                    json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    h = {"Accept": "application/json", **(headers or {})}
    if body is not None:
        h.setdefault("Content-Type", content_type)
    with open_url(method, url, body, h, timeout, verify_tls, ca_file) as resp:
        data = resp.read()
    if not data.strip():
        return {}
    try:
        return json.loads(data)
    except ValueError as exc:
        raise HttpError(f"{method} {_safe(url)}: response is not JSON ({exc})") from None


def iter_lines(resp: Any) -> Iterator[str]:
    """Decoded lines of a streamed response, one at a time."""
    for raw in resp:
        line = raw.decode("utf-8", errors="replace").strip()
        if line:
            yield line
