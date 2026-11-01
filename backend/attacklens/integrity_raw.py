"""Raw-file layer of the integrity engine (attacklens.integrity).

- one streaming pass per file (16 MiB chunks): SHA-256, the seal digest (HMAC-SHA256 when keyed), the search
  for runs of >= nul_min_run NUL bytes (also across chunk boundaries) and the last byte (truncated tail);
- seal manifest build / verify;
- the shared finding helpers (`Skip`, `finding`) used by every check module.

Never holds a whole file in memory. File selection reuses profile._skip (hidden dirs, ground_truth,
manifest.json, *.md), so the integrity engine looks at exactly the files ingest reads.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from attacklens.profile import _skip

log = logging.getLogger(__name__)

SEAL_KEY_ENV = "ATTACKLENS_SEAL_KEY"
SEAL_SCHEMA_VERSION = 1
SEVERITIES = ("low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_NON_NUL = re.compile(rb"[^\x00]")
_BINARY_MAGIC = (b"\x1f\x8b", b"PK\x03\x04", b"PAR1", b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd",
                 b"ElfFile\x00", b"7z\xbc\xaf\x27\x1c", b"SQLite format 3\x00", b"DUCK")


class Skip(Exception):
    """Raised by a check that cannot run; the message becomes the check's `reason`."""


def finding(check: str, severity: str, title: str, *, source_type: str | None = None, host: str | None = None,
            file: str | None = None, start_ts_ms: int | None = None, end_ts_ms: int | None = None,
            count: int = 1, detail: str = "", evidence: list[str] | None = None,
            max_chars: int = 300) -> dict[str, Any]:
    if severity not in SEV_RANK:
        raise ValueError(f"unknown severity {severity!r}")
    h = str(host).strip().lower() if host not in (None, "") else None
    if h is not None and not h.startswith("host:"):
        h = f"host:{h}"
    ev = [str(e)[:max_chars] for e in (evidence or []) if e not in (None, "")][:3]
    return {"check": check, "severity": severity, "title": title, "source_type": source_type, "host": h,
            "file": file, "start_ts_ms": None if start_ts_ms is None else int(start_ts_ms),
            "end_ts_ms": None if end_ts_ms is None else int(end_ts_ms), "count": int(count),
            "detail": detail, "evidence": ev}


def utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def seal_key() -> bytes | None:
    """The seal key from env ATTACKLENS_SEAL_KEY (never logged, never written). Empty -> None."""
    k = os.environ.get(SEAL_KEY_ENV)
    return k.encode("utf-8") if k else None


def list_files(raw_dir: Path, pcfg: dict[str, Any], exclude: set[Path] | None = None) -> list[Path]:
    """Files ingest would read (profile._skip rules), minus `exclude` (e.g. a seal manifest inside raw_dir)."""
    root = Path(raw_dir)
    ex = {p.resolve() for p in (exclude or set())}
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and _skip(p, root, pcfg) is None and p.resolve() not in ex:
            out.append(p)
    return out


@dataclass
class FileScan:
    rel: str
    size: int = 0
    sha256: str = ""
    seal_digest: str = ""
    binary: bool = False
    zeroed_bytes: int = 0
    zero_runs: int = 0
    first_zero_offset: int | None = None
    longest_run: int = 0
    runs_sample: list[tuple[int, int]] = field(default_factory=list)
    truncated_tail: bool = False
    error: str | None = None

    def add_run(self, start: int, length: int) -> None:
        self.zeroed_bytes += length
        self.zero_runs += 1
        self.longest_run = max(self.longest_run, length)
        if self.first_zero_offset is None:
            self.first_zero_offset = start
        if len(self.runs_sample) < 3:
            self.runs_sample.append((start, length))

    def report_entry(self) -> dict[str, Any]:
        return {"file": self.rel, "size": self.size, "sha256": self.sha256, "zeroed_bytes": self.zeroed_bytes,
                "truncated_tail": self.truncated_tail}


class _NulScanner:
    """Finds NUL runs >= min_run in consecutive chunks; a run may span chunk boundaries."""

    def __init__(self, scan: FileScan, min_run: int) -> None:
        self.scan, self.min_run, self.pat = scan, max(1, min_run), b"\x00" * max(1, min_run)
        self.open_start, self.open_len = 0, 0

    def _close(self) -> None:
        if self.open_len >= self.min_run:
            self.scan.add_run(self.open_start, self.open_len)
        self.open_len = 0

    def feed(self, chunk: bytes, base: int) -> None:
        n, pos = len(chunk), 0
        if self.open_len:  # a NUL run touching the end of the previous chunk
            m = _NON_NUL.search(chunk)
            if m is None:
                self.open_len += n
                return
            self.open_len += m.start()
            self._close()
            pos = m.start()
        while True:
            i = chunk.find(self.pat, pos)
            if i == -1:
                break
            m = _NON_NUL.search(chunk, i + self.min_run)
            if m is None:
                self.open_start, self.open_len = base + i, n - i
                return
            self.scan.add_run(base + i, m.start() - i)
            pos = m.start()
        if n and chunk[-1] == 0:  # short trailing NULs may continue in the next chunk
            tail = chunk[max(pos, n - self.min_run):]
            t = len(tail) - len(tail.rstrip(b"\x00"))
            self.open_start, self.open_len = base + n - t, t

    def finish(self) -> None:
        self._close()


def _is_binary(path: Path, head: bytes, binary_suffixes: set[str], min_run: int = 64) -> bool:
    """Suffix / magic number, else profile.first_lines' rule (> 5 % NUL in the first 4 KiB = binary or UTF-16,
    ingest does not read it). NULs inside runs >= min_run are not counted: a text log whose head was wiped stays
    text (and gets flagged); a pcap / etl / legacy evt has NULs scattered through its headers."""
    if path.suffix.lower() in binary_suffixes or any(head.startswith(m) for m in _BINARY_MAGIC):
        return True
    head = head[:4096]
    stripped = re.sub(rb"\x00{%d,}" % max(1, min_run), b"", head)  # drop wiped runs
    return bool(head) and stripped.count(b"\x00") * 20 > len(head)


def scan_file(path: Path, root: Path, *, key: bytes | None = None, nul_scan: bool = True, min_run: int = 64,
              chunk_bytes: int = 16 << 20, binary_suffixes: set[str] | None = None) -> FileScan:
    """One streaming read: SHA-256, seal digest (HMAC if key), NUL runs, tail byte."""
    fs = FileScan(rel=path.relative_to(root).as_posix())
    sha = hashlib.sha256()
    mac = hmac.new(key, digestmod=hashlib.sha256) if key else None
    scanner: _NulScanner | None = None
    last = b""
    off = 0
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_bytes)
                if not chunk:
                    break
                if off == 0:
                    fs.binary = _is_binary(path, chunk[:4096], binary_suffixes or set(), min_run)
                    if nul_scan and not fs.binary:
                        scanner = _NulScanner(fs, min_run)
                sha.update(chunk)
                if mac is not None:
                    mac.update(chunk)
                if scanner is not None:
                    scanner.feed(chunk, off)
                off += len(chunk)
                last = chunk[-1:]
        if scanner is not None:
            scanner.finish()
    except OSError as exc:
        fs.error = f"{type(exc).__name__}: {exc}"
        log.warning("integrity: cannot read %s: %s", fs.rel, fs.error)
        return fs
    fs.size = off
    fs.sha256 = sha.hexdigest()
    fs.seal_digest = mac.hexdigest() if mac is not None else fs.sha256
    fs.truncated_tail = bool(off) and last != b"\n"
    return fs


def scan_files(root: Path, files: list[Path], cfg: dict[str, Any], *, key: bytes | None = None,
               nul_scan: bool = True) -> list[FileScan]:
    """Scan files in a thread pool; results sorted by relative path."""
    if not files:
        return []
    kw = {"key": key, "nul_scan": nul_scan, "min_run": int(cfg.get("nul_min_run", 64)),
          "chunk_bytes": int(cfg.get("raw_chunk_bytes", 16 << 20)),
          "binary_suffixes": {str(s).lower() for s in cfg.get("binary_suffixes") or []}}
    workers = max(1, min(len(files), int(cfg.get("raw_threads", 8)), os.cpu_count() or 4))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="integrity-raw") as pool:
        scans = list(pool.map(lambda p: scan_file(p, root, **kw), files))
    return sorted(scans, key=lambda s: s.rel)


# --- seal manifest ---------------------------------------------------------------------------------------------

def _canonical(files_map: dict[str, Any]) -> bytes:
    return json.dumps(files_map, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_digest(files_map: dict[str, Any], key: bytes | None) -> str:
    data = _canonical(files_map)
    return hmac.new(key, data, hashlib.sha256).hexdigest() if key else hashlib.sha256(data).hexdigest()


def build_manifest(scans: list[FileScan], key: bytes | None) -> dict[str, Any]:
    files = {s.rel: {"size": s.size, "digest": s.seal_digest} for s in scans if s.error is None}
    return {"schema_version": SEAL_SCHEMA_VERSION, "created_at": utc_now_iso(), "keyed": key is not None,
            "algo": "hmac-sha256" if key else "sha256", "files": files,
            "manifest_digest": manifest_digest(files, key)}


def read_manifest(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """(manifest, error). A manifest that does not parse or lacks a files map is an error."""
    try:
        m = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, f"unreadable manifest: {type(exc).__name__}"
    if not isinstance(m, dict) or not isinstance(m.get("files"), dict):
        return None, "manifest has no files map"
    return m, None


def verify_seal(manifest: dict[str, Any] | None, error: str | None, key: bytes | None,
                scans: list[FileScan]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Compare scans (digested with `key` if the manifest is keyed) to the manifest -> (seal section, findings)."""
    current = {s.rel: s for s in scans}
    files = (manifest or {}).get("files") or {}
    keyed = bool((manifest or {}).get("keyed"))
    sealed = set(files)
    missing = sorted(sealed - set(current))
    added = sorted(set(current) - sealed)
    out: list[dict[str, Any]] = []
    invalid = error
    if invalid is None and keyed and key is None:
        invalid = f"manifest is keyed but {SEAL_KEY_ENV} is not set"
    if invalid is None and manifest_digest(files, key if keyed else None) != manifest.get("manifest_digest"):
        invalid = "manifest_digest does not match (manifest edited or wrong key)"
    modified: list[str] = []
    if invalid:
        out.append(finding("seal", "critical", "seal manifest invalid or key mismatch",
                           detail=invalid, count=1))
    else:
        for rel in sorted(sealed & set(current)):
            s, want = current[rel], files[rel] if isinstance(files[rel], dict) else {}
            if s.error is not None or s.size != want.get("size") or s.seal_digest != want.get("digest"):
                modified.append(rel)
        for rel in modified:
            s, want = current[rel], files[rel] if isinstance(files[rel], dict) else {}
            out.append(finding("seal", "critical", "sealed file modified", file=rel,
                               detail=f"size {want.get('size')} -> {s.size}; digest differs",
                               evidence=[f"sealed {str(want.get('digest'))[:16]}...", f"now {s.seal_digest[:16]}..."]))
        for rel in missing:
            out.append(finding("seal", "critical", "sealed file missing", file=rel,
                               detail=f"{rel} was sealed but is no longer in the raw directory"))
        for rel in added:
            out.append(finding("seal", "medium", "file added after seal", file=rel,
                               detail=f"{rel} ({current[rel].size} bytes) is not in the seal manifest"))
    status = "mismatch" if (invalid or modified or missing or added) else "verified"
    section = {"status": status, "keyed": keyed, "files_checked": len(sealed & set(current)),
               "modified": modified, "missing": missing, "added": added}
    return section, out


def raw_findings(scans: list[FileScan], source_of: dict[str, str]) -> tuple[list[dict[str, Any]],
                                                                             list[dict[str, Any]]]:
    """(zeroed_regions findings, truncated_tail findings) from the scans."""
    zeroed, tails = [], []
    for s in scans:
        st = source_of.get(s.rel)
        if s.zeroed_bytes:
            zeroed.append(finding(
                "zeroed_regions", "critical", f"{s.zeroed_bytes} zeroed bytes", source_type=st, file=s.rel,
                count=s.zeroed_bytes,
                detail=(f"first zeroed run at byte offset {s.first_zero_offset}; {s.zero_runs} run(s), longest "
                        f"{s.longest_run} bytes (NUL bytes inside a text log: lines wiped in place)"),
                evidence=[f"offset {o}: {n} NUL bytes" for o, n in s.runs_sample]))
        if s.truncated_tail:
            tails.append(finding("truncated_tail", "low", "file does not end with a newline", source_type=st,
                                 file=s.rel, detail=f"last byte of {s.rel} ({s.size} bytes) is not \\n "
                                                    "(truncated, or still being written)"))
    return zeroed, tails
