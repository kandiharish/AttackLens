"""HTTP helpers for the SaaS audit-log connectors (okta, m365_ual, gws_reports), on top of httpc.

- get_json(): JSON body + response headers (lower-case names). Okta pages with a `Link: <...>; rel="next"` header,
  the Office 365 Management Activity API with a `NextPageUri` header: httpc.request_json drops headers.
- same_origin(): a next-page / content URL handed out by the vendor is followed only when it points at the
  configured host (scheme, host and port), so a credential is never sent to another host.
- RateGate: vendor rate-limit headers (Okta X-Rate-Limit-Limit / -Remaining / -Reset epoch seconds). Before a
  call it waits for the reset when at most `min_remaining` calls are left; a 429 waits for the last known reset
  (or Retry-After, else a jittered backoff) and retries, up to `retries` times.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
from typing import Any, Callable

from attacklens import httpc

log = logging.getLogger("attacklens.connect")

_sleep = time.sleep   # tests monkeypatch this
_clock = time.time
_LINK_RE = re.compile(r'<([^>]+)>\s*;\s*rel="?([A-Za-z]+)"?')


def get_json(method: str, url: str, headers: dict[str, str], timeout: float, verify_tls: bool,
             ca_file: str | None, body: bytes | None = None) -> tuple[Any, dict[str, str]]:
    """One request (no retry): (parsed JSON or {} for an empty body, response headers with lower-case names)."""
    h = {"Accept": "application/json", **headers}
    if body is not None:
        h.setdefault("Content-Type", "application/json")
    with httpc.open_url(method, url, body, h, timeout, verify_tls, ca_file) as resp:
        data = resp.read()
        raw = getattr(resp, "headers", None)
        hdrs = {str(k).lower(): str(v) for k, v in raw.items()} if raw is not None else {}
    if not data.strip():
        return {}, hdrs
    try:
        return json.loads(data), hdrs
    except ValueError as exc:
        raise httpc.HttpError(f"{method} {httpc.safe_url(url)}: response is not JSON ({exc})") from None


def link_next(link_header: str | None) -> str | None:
    """URL of rel="next" in an RFC 8288 Link header (several Link values may be comma-joined)."""
    for m in _LINK_RE.finditer(link_header or ""):
        if m.group(2).lower() == "next":
            return m.group(1)
    return None


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urllib.parse.urlsplit(url)
    port = p.port or (443 if p.scheme == "https" else 80 if p.scheme == "http" else None)
    return p.scheme.lower(), (p.hostname or "").lower(), port


def same_origin(url: str, base: str) -> bool:
    try:
        return _origin(url) == _origin(base) and bool(_origin(base)[1])
    except ValueError:
        return False


def require_same_origin(url: str, base: str, what: str) -> str:
    if not same_origin(url, base):
        raise httpc.HttpError(f"{what}: the API returned a URL on another host ({httpc.safe_url(url)}); not "
                              f"sending credentials there")
    return url


class RateGate:
    """Waits on vendor rate-limit headers. update() after each response; call() wraps one request."""

    def __init__(self, min_remaining: int = 2, max_wait_s: float = 60.0, retries: int = 3, what: str = "") -> None:
        self.min_remaining, self.max_wait_s, self.retries, self.what = int(min_remaining), float(max_wait_s), \
            int(retries), what
        self.remaining: int | None = None
        self.reset_s: float | None = None
        self.waits: list[float] = []
        self.throttled = 0

    def update(self, hdrs: dict[str, str]) -> None:
        try:
            if "x-rate-limit-remaining" in hdrs:
                self.remaining = int(hdrs["x-rate-limit-remaining"])
            if "x-rate-limit-reset" in hdrs:
                self.reset_s = float(hdrs["x-rate-limit-reset"])
        except ValueError:
            pass

    def _wait(self, seconds: float, why: str) -> None:
        d = max(0.0, min(seconds, self.max_wait_s))
        if d > 0:
            log.info("connect %s: %s; waiting %.1f s", self.what, why, d)
            self.waits.append(d)
            _sleep(d)

    def before(self) -> None:
        if self.remaining is not None and self.remaining <= self.min_remaining and self.reset_s is not None:
            self._wait(self.reset_s - _clock() + 0.2, f"{self.remaining} call(s) left until the rate-limit reset")
            self.remaining = None

    def call(self, fn: Callable[[], tuple[Any, dict[str, str]]]) -> tuple[Any, dict[str, str]]:
        attempt = 0
        while True:
            self.before()
            try:
                data, hdrs = fn()
            except httpc.HttpError as exc:
                if exc.status not in httpc.RETRY_STATUS or attempt >= self.retries:
                    raise
                self.throttled += exc.status == 429
                if exc.status == 429 and exc.retry_after is None and self.reset_s is not None \
                        and self.reset_s > _clock():
                    self._wait(self.reset_s - _clock() + 0.2, "HTTP 429 (rate limit)")
                else:
                    self._wait(httpc.backoff_s(attempt, retry_after=exc.retry_after), f"HTTP {exc.status}")
                self.remaining = None
                attempt += 1
                continue
            self.update(hdrs)
            return data, hdrs


def as_list(v: Any) -> list[str]:
    """Config list or comma-separated text -> stripped non-empty strings."""
    items = v if isinstance(v, list) else str(v or "").split(",")
    return [str(x).strip() for x in items if str(x).strip()]
