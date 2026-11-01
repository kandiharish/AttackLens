"""Shared helpers for SIEM integrations (config/integrations.yaml): paths, the secret resolver, the UI settings
overlay, time parsing, vendor field paths, label stripping and the connector_status.json file.

Nothing here touches the network.

Secrets: secret() is the ONE resolver every connector / sink uses. The config holds names, never values. A name may
be a chain "ENV_NAME|@<id>.<key>" (built by the overlay): environment variables win, then the value saved from the
UI (secrets_store, DPAPI-encrypted). Values are never logged.

UI overlay: data/integrations/settings.json ($ATTACKLENS_INTEGRATIONS_DIR) holds what the Integrations page saved.
apply_overlay() merges it UNDER the same top-level keys (connectors.<id>, sinks.<id>, alert_input) of
integrations.yaml. It is applied by `attacklens.connect` (default config dir), by the API, and by icfg() in any
process started with ATTACKLENS_INTEGRATIONS_OVERLAY=1 (the connect / live subprocesses the API spawns).
"""

from __future__ import annotations

import copy
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from attacklens import secrets_store
from attacklens.config import REPO_ROOT
from attacklens.live_tail import read_json, write_json

log = logging.getLogger(__name__)

_DUR = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)\s*$")
_DUR_MS = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000, "w": 604_800_000}


OVERLAY_ENV = "ATTACKLENS_INTEGRATIONS_OVERLAY"   # "1": icfg() merges the UI settings overlay
SETTINGS_DIR_ENV = "ATTACKLENS_INTEGRATIONS_DIR"
OVERLAY_MARK = "_ui_overlay_applied"
SECTIONS = ("connectors", "sinks")


def icfg(cfg: dict[str, Any]) -> dict[str, Any]:
    """The integrations section of a load_config() dict ({} when the file is absent). With
    ATTACKLENS_INTEGRATIONS_OVERLAY=1 the UI settings overlay is merged in first (once per cfg dict)."""
    v = cfg.get("integrations")
    if isinstance(v, dict) and not v.get(OVERLAY_MARK) and os.environ.get(OVERLAY_ENV) == "1":
        v = apply_overlay(cfg)["integrations"]
    return v if isinstance(v, dict) else {}


# ---- UI settings overlay -------------------------------------------------------------------------------------------
def settings_dir() -> Path:
    d = os.environ.get(SETTINGS_DIR_ENV)
    return Path(d).resolve() if d else REPO_ROOT / "data" / "integrations"


def settings_path() -> Path:
    return settings_dir() / "settings.json"


def read_overlay() -> dict[str, Any]:
    """{"version": 1, "items": {id: {section, enabled, settings{dotted key: value}, secret_env{key: *_env key}}},
    "alert_input": {...}}; {} shape when absent or unreadable."""
    data = read_json(settings_path(), {})
    if not isinstance(data, dict):
        data = {}
    items = data.get("items")
    data["items"] = items if isinstance(items, dict) else {}
    return data


def write_overlay(data: dict[str, Any]) -> None:
    write_json(settings_path(), {**data, "version": 1})


def set_dotted(d: dict[str, Any], key: str, value: Any) -> None:
    parts = key.split(".")
    for p in parts[:-1]:
        nxt = d.get(p)
        if not isinstance(nxt, dict):
            nxt = d[p] = {}
        d = nxt
    d[parts[-1]] = value


def get_dotted(d: Any, key: str) -> Any:
    for p in key.split("."):
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def merge_overlay(ic: dict[str, Any], overlay: dict[str, Any], stored: set[str]) -> dict[str, Any]:
    """Pure: integrations.yaml dict + overlay -> merged copy. For every secret field of a UI-saved integration the
    *_env key becomes a resolver chain: the YAML env var name if that variable is set (env wins), then the stored
    reference if a value was saved. Neither -> None (no auth header; the SIEM answers 401 if it needs one)."""
    out = copy.deepcopy(ic)
    for iid, item in (overlay.get("items") or {}).items():
        if not isinstance(item, dict) or item.get("section") not in SECTIONS:
            continue
        sec = out.get(item["section"])
        if not isinstance(sec, dict):
            sec = out[item["section"]] = {}
        c = sec.get(iid)
        if not isinstance(c, dict):
            c = sec[iid] = {}
        for k, v in (item.get("settings") or {}).items():
            set_dotted(c, str(k), v)
        if "enabled" in item:
            c["enabled"] = bool(item["enabled"])
        for fkey, env_key in (item.get("secret_env") or {}).items():
            orig = c.get(env_key)
            names = [str(orig)] if orig and "|" not in str(orig) and os.environ.get(str(orig)) else []
            if f"{iid}.{fkey}" in stored:
                names.append(f"@{iid}.{fkey}")
            c[env_key] = "|".join(names) or None
    ai = overlay.get("alert_input")
    if isinstance(ai, dict) and ai:
        out["alert_input"] = {**(out.get("alert_input") or {}), **ai}
    return out


def apply_overlay(cfg: dict[str, Any]) -> dict[str, Any]:
    """Merge the UI overlay into cfg["integrations"] in place (idempotent); returns cfg."""
    ic = cfg.get("integrations")
    ic = ic if isinstance(ic, dict) else {}
    if ic.get(OVERLAY_MARK):
        return cfg
    merged = merge_overlay(ic, read_overlay(), secrets_store.refs())
    merged[OVERLAY_MARK] = True
    cfg["integrations"] = merged
    return cfg


def repo_path(p: str | Path) -> Path:
    p = Path(p)
    return (p if p.is_absolute() else REPO_ROOT / p).resolve()


def events_spool_dir(cfg: dict[str, Any]) -> Path:
    """spool.events_dir, default <live.yaml watch_dir>/siem (so live mode tails it)."""
    d = (icfg(cfg).get("spool") or {}).get("events_dir")
    if d:
        return repo_path(d)
    return repo_path((cfg.get("live") or {}).get("watch_dir", "data/raw/live")) / "siem"


def spool_path(cfg: dict[str, Any], key: str, default: str) -> Path:
    return repo_path((icfg(cfg).get("spool") or {}).get(key) or default)


def alerts_spool_dir(cfg: dict[str, Any]) -> Path:
    return spool_path(cfg, "alerts_dir", "data/spool/siem_alerts")


def state_dir(cfg: dict[str, Any]) -> Path:
    return spool_path(cfg, "state_dir", "data/spool/state")


def status_file(cfg: dict[str, Any]) -> Path:
    return spool_path(cfg, "status_file", "data/spool/connector_status.json")


def secret(name: str | None) -> str | None:
    """THE secret resolver (connectors and sinks call only this). `name` is an env var name or a chain
    "ENV_NAME|@<id>.<key>": the first non-empty wins, so an environment variable beats a value saved from the UI.
    Empty -> None. Never logs a value."""
    if not name:
        return None
    for part in str(name).split("|"):
        part = part.strip()
        if not part:
            continue
        if part.startswith("@"):
            v = secrets_store.get(part[1:]) if secrets_store.REF_RE.match(part[1:]) else None
        else:
            v = os.environ.get(part)
        if v:
            return v
    return None


def parse_duration_ms(s: str | int | float | None, default_ms: int = 86_400_000) -> int:
    """'24h' / '30m' / '7d' / '90s' / plain ms number -> ms."""
    if s is None or s == "":
        return default_ms
    if isinstance(s, (int, float)):
        return int(s)
    m = _DUR.match(str(s))
    if not m:
        raise ValueError(f"bad duration {s!r} (use e.g. 30m, 24h, 7d)")
    return int(float(m.group(1)) * _DUR_MS[m.group(2)])


def now_ms() -> int:
    return int(time.time() * 1000)


def iso_ms(ms: int | None) -> str | None:
    if ms is None:
        return None
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (OverflowError, OSError, ValueError):
        return None


def now_iso() -> str:
    return str(iso_ms(now_ms()))


def to_ms(v: Any) -> int | None:
    """Vendor timestamp -> UTC epoch ms. ISO-8601 (Z / offset / naive = UTC), epoch s or ms numbers."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, list):
        return to_ms(v[0]) if v else None
    if isinstance(v, (int, float)):
        return int(v) if abs(v) >= 1e11 else int(v * 1000)
    s = str(v).strip()
    if not s:
        return None
    if re.fullmatch(r"-?\d+(\.\d+)?", s):
        return to_ms(float(s))
    s = s.replace(" ", "T", 1) if re.match(r"\d{4}-\d\d-\d\d \d", s) else s
    s = s[:-1] + "+00:00" if s.endswith(("Z", "z")) else s
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)\.(\d+)(.*)$", s)  # >6 fraction digits (Sentinel 100 ns) -> micro
    if m:
        s = f"{m.group(1)}.{m.group(2)[:6].ljust(6, '0')}{m.group(3)}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _maybe_json(v: Any) -> Any:
    if isinstance(v, str) and v[:1] in ("{", "["):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def iter_path(obj: Any, path: str) -> Iterator[Any]:
    """All values at a dotted path. Literal keys containing dots win over nesting (Elastic alerts use flattened
    keys like "kibana.alert.rule.name"); lists fan out; JSON-encoded strings are decoded when descending."""
    yield from _walk(obj, path.split(".") if path else [])


def _walk(obj: Any, parts: list[str]) -> Iterator[Any]:
    if not parts:
        if isinstance(obj, list):
            for x in obj:
                yield from _walk(x, [])
        elif obj is not None and obj != "":
            yield obj
        return
    obj = _maybe_json(obj)
    if isinstance(obj, list):
        for x in obj:
            yield from _walk(x, parts)
        return
    if not isinstance(obj, dict):
        return
    for i in range(len(parts), 0, -1):
        key = ".".join(parts[:i])
        if key in obj:
            yield from _walk(obj[key], parts[i:])


def first(obj: Any, paths: list[str] | str | None) -> Any:
    """First non-empty scalar over a list of paths (None if none)."""
    for p in [paths] if isinstance(paths, str) else (paths or []):
        for v in iter_path(obj, p):
            if not isinstance(v, (dict, list)):
                return v
    return None


def all_values(obj: Any, paths: list[str] | str | None) -> list[Any]:
    out: list[Any] = []
    for p in [paths] if isinstance(paths, str) else (paths or []):
        out.extend(iter_path(obj, p))
    return out


# ---- vendor error codes (connection test messages; allow-listed tokens only, never free text) ----------------
_AAD = {"7000215": "invalid client secret", "7000222": "client secret expired", "700016": "unknown client (app) id",
        "90002": "tenant not found", "900023": "invalid tenant id", "7000216": "client assertion missing",
        "50126": "invalid user name or password", "65001": "admin consent missing"}
_VENDOR_CODES = re.compile(r"\b(AccessDenied(?:Exception)?|UnrecognizedClientException|InvalidClientTokenId|"
                           r"SignatureDoesNotMatch|InvalidSignatureException|ExpiredToken(?:Exception)?|"
                           r"UnauthorizedOperation|PERMISSION_DENIED|UNAUTHENTICATED|SERVICE_DISABLED|"
                           r"InvalidAuthenticationToken|AuthorizationFailed|WorkspaceNotFoundError|PathNotFoundError|"
                           r"security_exception|index_not_found_exception|invalid_grant|invalid_client)\b")
_AWS_ACTION = re.compile(r"perform: ([a-z0-9-]{2,30}:[A-Za-z0-9]{2,60})")
_GCP_PERM = re.compile(r"[Pp]ermission '?([a-z]+(?:\.[a-zA-Z]+){2,4})'? (?:denied|is required)")


def vendor_detail(body: str) -> str:
    """Allow-listed error codes / permission names from a response body (never free text: it may echo input)."""
    out: list[str] = []
    m = re.search(r"AADSTS(\d{5,7})", body)
    if m:
        out.append(f"AADSTS{m.group(1)}" + (f": {_AAD[m.group(1)]}" if m.group(1) in _AAD else ""))
    out += list(dict.fromkeys(_VENDOR_CODES.findall(body)))[:2]
    out += list(dict.fromkeys(re.findall(r"\b(E000\d{4}|AF\d{5})\b", body)))[:1]   # Okta errorCode / O365 API code
    for rx, label in ((_AWS_ACTION, "for"), (_GCP_PERM, "missing")):
        m = rx.search(body)
        if m:
            out.append(f"{label} {m.group(1)}")
    return "; ".join(out)


def label_strip_spec(cfg: dict[str, Any]) -> tuple[set[str], dict[str, set[str]]]:
    """Generator / vendor label keys never written to the events spool (sources.yaml + integrations spool)."""
    src = cfg.get("sources") or {}
    sp = icfg(cfg).get("spool") or {}
    top = {str(k) for k in (src.get("label_keys") or [])} | {str(k) for k in (sp.get("strip_keys") or [])}
    nested: dict[str, set[str]] = {}
    for spec in (src.get("label_nested_keys") or {}, sp.get("strip_nested_keys") or {}):
        for parent, kids in spec.items():
            nested.setdefault(str(parent), set()).update(str(k) for k in kids or [])
    return top, nested


def strip_labels(doc: dict[str, Any], top: set[str], nested: dict[str, set[str]]) -> dict[str, Any]:
    """Copy of doc without label keys (nested form and flattened "event.kind" form)."""
    out: dict[str, Any] = {}
    for k, v in doc.items():
        if k in top or k.split(".", 1)[0] in top:
            continue
        head, _, tail = k.partition(".")
        if tail and tail in nested.get(head, set()):
            continue
        if k in nested and isinstance(v, dict):
            v = {ck: cv for ck, cv in v.items() if ck not in nested[k]}
        out[k] = v
    return out


# ---- connector_status.json -----------------------------------------------------------------------------------------
def _lock(path: Path, timeout_s: float = 2.0) -> Path | None:
    lock = path.with_suffix(path.suffix + ".lock")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            return lock
        except FileExistsError:
            try:  # stale lock of a killed process
                if time.time() - lock.stat().st_mtime > 30:
                    lock.unlink(missing_ok=True)
                    continue
            except OSError:
                pass
            if time.monotonic() > deadline:
                log.warning("integrations: %s busy; writing without lock", lock.name)
                return None
            time.sleep(0.02)
        except OSError:
            return None


def update_status(cfg: dict[str, Any], section: str, name: str, entry: dict[str, Any]) -> None:
    """Merge `entry` into connector_status.json[section][name] (read-modify-write under a lock file, atomic)."""
    path = status_file(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = _lock(path)
    try:
        data = read_json(path, {})
        if not isinstance(data, dict):
            data = {}
        sec = data.setdefault(section, {})
        sec[name] = {**(sec.get(name) or {}), **entry}
        data["updated_at"] = now_iso()
        write_json(path, data)
    finally:
        if lock is not None:
            lock.unlink(missing_ok=True)


def read_status(cfg: dict[str, Any]) -> dict[str, Any]:
    data = read_json(status_file(cfg), {})
    return data if isinstance(data, dict) else {}
