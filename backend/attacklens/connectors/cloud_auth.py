"""OAuth2 tokens for cloud connectors, over plain HTTPS (httpc), no vendor SDK.

- TokenCache: one access token per connector instance, reused until `skew_s` (default 300 s) before it expires;
  invalidate() after an HTTP 401 forces one refresh.
- azure_client_credentials(): Entra ID client-credentials flow
  (POST {login_url}/{tenant}/oauth2/v2.0/token, scope e.g. https://api.loganalytics.io/.default).
- gcp_service_account(): service-account JSON key -> RS256-signed JWT -> POST token_uri (jwt-bearer grant).
  Signing uses `cryptography` (pip extra [cloud]); without it a MissingDependency names the pip command.

Secret values come only from integrations.secret() (callers pass them in); they never reach a log line or an error
message. Errors name the tenant / client id / service account e-mail and the vendor error code only.
"""

from __future__ import annotations

import base64
import json
import logging
import time
import urllib.parse
from typing import Any, Callable

from attacklens import httpc
from attacklens.connectors.base import AuthError, MissingDependency

log = logging.getLogger("attacklens.connect")

AZURE_LOGIN_URL = "https://login.microsoftonline.com"
GCP_TOKEN_URI = "https://oauth2.googleapis.com/token"
GCP_LOGGING_SCOPE = "https://www.googleapis.com/auth/logging.read"
_clock = time.time  # tests monkeypatch this


class TokenCache:
    """fetch() -> (access_token, expires_in_s). get() returns the cached token until skew_s before expiry."""

    def __init__(self, fetch: Callable[[], tuple[str, float]], skew_s: float = 300.0) -> None:
        self._fetch, self.skew_s = fetch, float(skew_s)
        self._token: str | None = None
        self._exp = 0.0
        self.fetches = 0

    def get(self) -> str:
        if self._token is None or _clock() >= self._exp - self.skew_s:
            tok, ttl = self._fetch()
            self.fetches += 1
            self._token, self._exp = tok, _clock() + float(ttl)
        return self._token

    def invalidate(self) -> None:
        self._token, self._exp = None, 0.0


def _vendor_error(exc: httpc.HttpError) -> str:
    """Vendor error code from a token endpoint error body (never the description text, which may echo input)."""
    try:
        body = json.loads(exc.body or "{}")
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    code = body.get("error")
    codes = body.get("error_codes")
    out = str(code) if isinstance(code, str) else ""
    if isinstance(codes, list) and codes:
        out += f" AADSTS{codes[0]}"
    return out.strip()


def _token_post(url: str, form: dict[str, str], what: str, timeout: float, verify_tls: bool,
                ca_file: str | None, retries: int) -> tuple[str, float]:
    body = urllib.parse.urlencode(form).encode("utf-8")
    try:
        res = httpc.request_json("POST", url, None, {"Content-Type": "application/x-www-form-urlencoded"},
                                 timeout, verify_tls, raw_body=body, ca_file=ca_file, retries=retries)
    except httpc.HttpError as exc:
        if exc.status in (400, 401, 403):
            code = _vendor_error(exc)
            raise AuthError(f"{what}: sign-in rejected (HTTP {exc.status}{' ' + code if code else ''}); "
                            f"check the credentials", 401 if exc.status == 400 else exc.status) from None
        raise
    tok = res.get("access_token") if isinstance(res, dict) else None
    if not tok:
        raise AuthError(f"{what}: token endpoint returned no access_token")
    return str(tok), float(res.get("expires_in") or 3600)


def azure_client_credentials(tenant: str, client_id: str, client_secret: str, scope: str,
                             login_url: str = AZURE_LOGIN_URL, timeout: float = 20.0, verify_tls: bool = True,
                             ca_file: str | None = None, retries: int = 2) -> Callable[[], tuple[str, float]]:
    """Fetcher for TokenCache: Entra ID OAuth2 client-credentials grant."""
    if not (tenant and client_id and client_secret):
        missing = [n for n, v in (("tenant_id", tenant), ("client_id", client_id), ("client_secret", client_secret))
                   if not v]
        raise PermissionError(f"azure: missing {', '.join(missing)}")
    url = httpc.join(login_url, f"/{urllib.parse.quote(tenant, safe='')}/oauth2/v2.0/token")
    form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret,
            "scope": scope}
    what = f"azure tenant {tenant} client {client_id}"
    return lambda: _token_post(url, form, what, timeout, verify_tls, ca_file, retries)


# ---- GCP service account -------------------------------------------------------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_rs256(private_key_pem: str, data: bytes) -> bytes:
    """RS256 signature with `cryptography` (optional dependency, pip extra [cloud])."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        raise MissingDependency('cryptography is not installed (needed to sign the GCP service-account JWT); '
                                'run: pip install "attacklens[cloud]"') from None
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except (ValueError, TypeError):
        raise ValueError("gcp: service-account private_key is not a valid PEM key") from None
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr,call-arg]


def parse_service_account(text: str | None) -> dict[str, Any]:
    """The service-account JSON key (the secret's text). Errors never echo the content."""
    if not text:
        raise PermissionError("gcp: no service-account JSON key (set the secret / env var named in "
                              "service_account_json_env)")
    try:
        info = json.loads(text)
    except ValueError:
        raise ValueError("gcp: the service-account key is not valid JSON") from None
    if not isinstance(info, dict) or info.get("type") != "service_account":
        raise ValueError("gcp: the key is not a service-account JSON key (type != service_account)")
    missing = [k for k in ("client_email", "private_key") if not info.get(k)]
    if missing:
        raise ValueError(f"gcp: service-account key lacks {', '.join(missing)}")
    return info


def rs256_jwt(claims: dict[str, Any], private_key_pem: str, kid: str | None = None) -> str:
    """Compact RS256 JWT (header alg RS256, typ JWT, optional kid)."""
    header = {"alg": "RS256", "typ": "JWT", **({"kid": str(kid)} if kid else {})}
    signing = (_b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
               _b64url(json.dumps(claims, separators=(",", ":")).encode()))
    return signing + "." + _b64url(sign_rs256(private_key_pem, signing.encode("ascii")))


def gcp_jwt(info: dict[str, Any], scope: str, now: float | None = None, subject: str | None = None) -> str:
    """subject: the user impersonated through domain-wide delegation (Google Workspace Admin SDK), else none."""
    iat = int(now if now is not None else _clock())
    claims = {"iss": info["client_email"], "scope": scope, "aud": info.get("token_uri") or GCP_TOKEN_URI,
              "iat": iat, "exp": iat + 3600, **({"sub": str(subject)} if subject else {})}
    return rs256_jwt(claims, str(info["private_key"]), info.get("private_key_id") or None)


def gcp_service_account(info: dict[str, Any], scope: str = GCP_LOGGING_SCOPE, timeout: float = 20.0,
                        verify_tls: bool = True, ca_file: str | None = None, retries: int = 2,
                        token_uri: str | None = None, subject: str | None = None) -> Callable[[], tuple[str, float]]:
    """Fetcher for TokenCache: JWT-bearer grant with a service-account key (subject: delegated user, optional)."""
    uri = token_uri or str(info.get("token_uri") or GCP_TOKEN_URI)
    what = f"gcp service account {info.get('client_email')}" + (f" as {subject}" if subject else "")

    def fetch() -> tuple[str, float]:
        form = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": gcp_jwt(info, scope, subject=subject)}
        return _token_post(uri, form, what, timeout, verify_tls, ca_file, retries)
    return fetch


def private_key_jwt(token_url: str, client_id: str, private_key_pem: str, scope: str, kid: str | None = None,
                    timeout: float = 20.0, verify_tls: bool = True, ca_file: str | None = None,
                    retries: int = 2) -> Callable[[], tuple[str, float]]:
    """Fetcher for TokenCache: OAuth 2.0 client-credentials grant authenticated with a signed client assertion
    (RFC 7523 private_key_jwt; e.g. an Okta API service app). The assertion lives 5 minutes, jti is random."""
    import uuid

    if not (client_id and private_key_pem):
        raise PermissionError("oauth: missing client_id or private key")
    what = f"oauth client {client_id}"

    def fetch() -> tuple[str, float]:
        now = int(_clock())
        claims = {"aud": token_url, "iss": client_id, "sub": client_id, "iat": now, "exp": now + 300,
                  "jti": uuid.uuid4().hex}
        form = {"grant_type": "client_credentials", "scope": scope,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": rs256_jwt(claims, private_key_pem, kid)}
        return _token_post(token_url, form, what, timeout, verify_tls, ca_file, retries)
    return fetch


def normalize_pem(text: str) -> str:
    """A PEM key pasted on one line (the UI secret store refuses line breaks): literal \\n escapes or spaces between
    the base64 lines are turned back into a valid PEM."""
    s = str(text).strip().replace("\\r\\n", "\n").replace("\\n", "\n")
    if "\n" in s:
        return s + "\n"
    import re
    m = re.match(r"^(-----BEGIN [A-Z ]+-----)\s*(.*?)\s*(-----END [A-Z ]+-----)$", s)
    if not m:
        return s
    body = "\n".join(m.group(2).split())
    return f"{m.group(1)}\n{body}\n{m.group(3)}\n"


def call_with_token(cache: TokenCache, call: Callable[[str], Any], what: str) -> Any:
    """call(token); on HTTP 401 refresh the token once and retry; a second 401 / a 403 -> AuthError.
    A failure to obtain the token itself is raised as is (no second sign-in attempt)."""
    tok = cache.get()
    try:
        return call(tok)
    except httpc.HttpError as exc:
        if exc.status == 403:
            raise AuthError(f"{what}: HTTP 403 forbidden; the identity lacks read permission", 403) from None
        if exc.status != 401:
            raise
    cache.invalidate()
    log.info("connect %s: HTTP 401, refreshing the token once", what)
    tok = cache.get()
    try:
        return call(tok)
    except httpc.HttpError as exc:
        if exc.status in (401, 403):
            raise AuthError(f"{what}: HTTP {exc.status} after a token refresh; check the credentials and "
                            f"permissions", exc.status) from None
        raise
