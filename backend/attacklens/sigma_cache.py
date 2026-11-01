"""Sigma compile-cache key (used by sigma_rules.load).

The compiled catalogue is cached as <cache_dir>/sigma_<content key[:16]>.json, keyed by a content hash of every rule
file + map + ATT&CK data + compiler / pySigma version. Hashing the content opens ~3800 files: ~1 s on an idle disk,
measured up to ~44 s on a contended disk with on-access AV scanning. So the warm path never opens a rule file:

- one os.scandir walk gives (relative path, size, mtime_ns) of every *.yml (on Windows from the directory listing);
- a hash of that manifest + config is looked up in <cache_dir>/manifest.json (manifest hash -> content key);
- only on a miss (any file added / removed / resized / touched, or the config changed) is the content hashed, and the
  result recorded. An edit that keeps both size and mtime_ns is not seen (not produced by editors or git checkout).
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

MANIFEST = "manifest.json"
MANIFEST_MAX_ENTRIES = 32


def rule_files(sigma_dir: Path) -> list[Path]:
    return sorted(p for p in sigma_dir.rglob("*.yml") if p.is_file())


def walk(root: Path) -> list[tuple[str, int, int]]:
    """[(relative posix path, size, mtime_ns)] of every *.yml under root, sorted. No file is opened."""
    out: list[tuple[str, int, int]] = []
    stack = [(root, "")]
    while stack:
        d, rel = stack.pop()
        with os.scandir(d) as it:
            for e in it:
                r = f"{rel}{e.name}"
                if e.is_dir(follow_symlinks=False):
                    stack.append((Path(e.path), r + "/"))
                elif e.name.endswith(".yml") and e.is_file():
                    st = e.stat()
                    out.append((r, st.st_size, st.st_mtime_ns))
    out.sort()
    return out


@functools.lru_cache(maxsize=1)
def pysigma_version() -> str:
    from importlib.metadata import version
    return version("pysigma")


def content_key(files: list[Path], root: Path, smap: dict[str, Any], attack: dict[str, Any],
                compiler_version: str) -> str:
    h = hashlib.sha256()
    h.update(f"{compiler_version}|{pysigma_version()}|".encode())
    h.update(json.dumps(smap, sort_keys=True, default=str).encode())
    h.update(json.dumps(attack.get("techniques") or {}, sort_keys=True).encode())
    for f in files:
        h.update(f.relative_to(root).as_posix().encode() + b"\0")
        h.update(f.read_bytes())
    return h.hexdigest()


def manifest_hash(root: Path, files: list[tuple[str, int, int]], smap_json: str, attack_json: str,
                  compiler_version: str) -> str:
    mh = hashlib.sha256(f"{compiler_version}|{pysigma_version()}|{root.as_posix()}|".encode())
    mh.update(smap_json.encode() + b"\0" + attack_json.encode() + b"\0")
    mh.update(json.dumps(files).encode())
    return mh.hexdigest()


@functools.lru_cache(maxsize=4)
def key_for(mhash: str, root: str, cache_dir: str, smap_json: str, attack_json: str, compiler_version: str
            ) -> tuple[str, str]:
    """(content key, how): 'manifest' when this exact manifest + config was hashed before and its compiled cache file
    still exists, else 'content' (every rule file read and hashed), then recorded in <cache_dir>/manifest.json."""
    mfile = Path(cache_dir) / MANIFEST
    known: dict[str, str] = {}
    try:
        known = {str(k): str(v) for k, v in json.loads(mfile.read_text(encoding="utf-8")).items()}
    except FileNotFoundError:
        pass
    except (OSError, ValueError, AttributeError) as exc:
        log.warning("sigma: unreadable manifest %s (%s); rehashing rule files", mfile, exc)
    if mhash in known and (Path(cache_dir) / f"sigma_{known[mhash][:16]}.json").exists():
        return known[mhash], "manifest"
    r = Path(root)
    key = content_key(rule_files(r), r, json.loads(smap_json), json.loads(attack_json), compiler_version)
    known = {k: v for k, v in known.items() if v != key}      # one entry per content key (bounded file)
    known[mhash] = key
    try:
        mfile.parent.mkdir(parents=True, exist_ok=True)
        tmp = mfile.with_name(f"manifest.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(dict(list(known.items())[-MANIFEST_MAX_ENTRIES:])), encoding="utf-8")
        tmp.replace(mfile)
    except OSError as exc:
        log.warning("sigma: cannot write manifest %s: %s", mfile, exc)
    return key, "content"
