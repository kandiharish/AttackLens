"""Secrets saved from the UI (Integrations page): data/secrets/integrations.json, every value DPAPI-encrypted.

- Windows: CryptProtectData, current-user scope (only this Windows account on this machine can decrypt). The file
  holds base64 ciphertext per reference ("elastic.api_key"); there is never a plaintext secret file.
- Elsewhere (Linux / Docker): no OS secret store without a third-party library, so saving is refused
  (SecretsUnavailable -> HTTP 501) and secrets come from the environment variables named in integrations.yaml.
- Location: $ATTACKLENS_SECRETS_DIR, default <repo>/data/secrets (data/ is gitignored).
- Values never go to logs, exceptions or API responses: errors name the reference only.

Readers go through integrations.secret() (the one resolver); this module is its storage backend.
"""

from __future__ import annotations

import base64
import ctypes
import json
import logging
import os
import re
import sys
import threading
from pathlib import Path

from attacklens.config import REPO_ROOT

log = logging.getLogger(__name__)

DIR_ENV = "ATTACKLENS_SECRETS_DIR"
FILE_NAME = "integrations.json"
SCHEME = "dpapi-user"
REF_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}\.[a-z][a-z0-9_]{0,40}$")
_ENTROPY = b"attacklens-integrations-v1"
_LOCK = threading.Lock()  # serializes read-modify-write within one process (the API)


class SecretsUnavailable(RuntimeError):
    """No supported OS secret protection on this platform."""


def store_dir() -> Path:
    d = os.environ.get(DIR_ENV)
    return Path(d).resolve() if d else REPO_ROOT / "data" / "secrets"


def store_path() -> Path:
    return store_dir() / FILE_NAME


def available() -> bool:
    return sys.platform == "win32"


# ---- DPAPI (ctypes, stdlib only) -----------------------------------------------------------------------------------
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    if not available():
        raise SecretsUnavailable("secret storage needs Windows DPAPI; set the environment variables instead")
    from ctypes import wintypes

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    fn.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.POINTER(_Blob), ctypes.c_void_p,
                   ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
    fn.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    buf = ctypes.create_string_buffer(data, len(data))
    ent = ctypes.create_string_buffer(_ENTROPY, len(_ENTROPY))
    blob_in = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_ent = _Blob(len(_ENTROPY), ctypes.cast(ent, ctypes.POINTER(ctypes.c_char)))
    out = _Blob()
    ui_forbidden = 0x1
    if not fn(ctypes.byref(blob_in), None, ctypes.byref(blob_ent), None, None, ui_forbidden, ctypes.byref(out)):
        raise SecretsUnavailable(f"DPAPI {'protect' if protect else 'unprotect'} failed "
                                 f"(winerror {ctypes.get_last_error()})")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


# ---- file ----------------------------------------------------------------------------------------------------------
def _read() -> dict[str, str]:
    try:
        data = json.loads(store_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        log.warning("secrets: cannot read %s (%s); treating as empty", FILE_NAME, type(exc).__name__)
        return {}
    ent = data.get("entries") if isinstance(data, dict) and data.get("scheme") == SCHEME else None
    return {str(k): str(v) for k, v in ent.items() if isinstance(v, str)} if isinstance(ent, dict) else {}


def _write(entries: dict[str, str]) -> None:
    path = store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"version": 1, "scheme": SCHEME, "entries": entries}, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def refs() -> set[str]:
    """References with a stored value (no decryption)."""
    return set(_read())


def get(ref: str) -> str | None:
    """Decrypted value of `ref` ("<integration id>.<field key>"), None if absent or undecryptable."""
    enc = _read().get(ref)
    if enc is None or not available():
        return None
    try:
        return _dpapi(base64.b64decode(enc), protect=False).decode("utf-8") or None
    except (SecretsUnavailable, ValueError, UnicodeDecodeError):
        log.warning("secrets: cannot decrypt %s (saved by another Windows user?); ignored", ref)
        return None


def update(changes: dict[str, str | None]) -> None:
    """Set (str) or delete (None) references atomically. Raises SecretsUnavailable if a value must be stored on a
    platform without DPAPI (deleting always works)."""
    for ref in changes:
        if not REF_RE.match(ref):
            raise ValueError("bad secret reference")
    with _LOCK:
        entries = _read()
        for ref, value in changes.items():
            if value is None:
                entries.pop(ref, None)
            else:
                entries[ref] = base64.b64encode(_dpapi(value.encode("utf-8"), protect=True)).decode("ascii")
        if entries or store_path().exists():
            _write(entries)


def delete_prefix(integration_id: str) -> int:
    """Remove every reference of one integration; returns how many were removed."""
    with _LOCK:
        entries = _read()
        gone = [r for r in entries if r.split(".", 1)[0] == integration_id]
        for r in gone:
            entries.pop(r)
        if gone:
            _write(entries)
    return len(gone)
