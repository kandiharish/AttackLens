"""User data uploads for the API: POST /api/uploads (multipart, streamed), POST /api/uploads/local (hard link),
GET /api/uploads. Config: pipeline.yaml `upload:`.

- Multipart bodies are parsed incrementally (python-multipart's MultipartParser) straight from the request stream:
  nothing is spooled to a temp file and no file is ever held in memory (uploads can be 20+ GB).
- Each upload is written into <root>/.incoming/<id>/ and renamed to <root>/<id>/ only when complete, so a
  partial upload is never listed or analysed; on any error the partial directory is deleted.
- File names: basename only, sanitized to [A-Za-z0-9._-]; '..', absolute paths and empty names are rejected.
- Free disk is checked before (Content-Length / file size) and during the write (every disk_check_every_bytes).
- /api/uploads/local registers a file already on this machine by hard link (no 20 GB copy); copy only as a
  fallback. SECURITY: this lets the caller read any local file the API process can read, which is why the API
  must stay bound to 127.0.0.1 (uvicorn default; docker-compose publishes 127.0.0.1 only). Restrict further with
  upload.local_roots.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import time
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

import anyio
from python_multipart.multipart import MultipartParser, parse_options_header

from attacklens.config import REPO_ROOT

log = logging.getLogger(__name__)

FIELD = "files"
DEFAULT_EXT = (".log", ".txt", ".csv", ".json", ".jsonl", ".ndjson", ".cef", ".syslog")
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_ID_RE = re.compile(r"^up-\d{8}-\d{6}-[0-9a-f]{6}$")
META_DIR, INCOMING_DIR = ".meta", ".incoming"


class UploadError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


@dataclass
class UploadConfig:
    root: Path
    allowed: tuple[str, ...] = DEFAULT_EXT
    max_bytes: int = 64 * 2**30
    min_free_bytes: int = 2 * 2**30
    chunk_bytes: int = 2**20
    check_every: int = 256 * 2**20
    local_roots: list[Path] | None = None

    @classmethod
    def from_pipeline(cls, pipe: dict[str, Any], repo_root: Path = REPO_ROOT) -> UploadConfig:
        u = pipe.get("upload") or {}
        rel = lambda p: (Path(p) if Path(p).is_absolute() else repo_root / p).resolve()  # noqa: E731
        roots = u.get("local_roots")
        return cls(root=rel(u.get("root", "data/raw/uploads")),
                   allowed=tuple(str(e).lower() for e in (u.get("allowed_extensions") or DEFAULT_EXT)),
                   max_bytes=int(u.get("max_bytes", 64 * 2**30)), min_free_bytes=int(u.get("min_free_bytes", 2 * 2**30)),
                   chunk_bytes=int(u.get("chunk_bytes", 2**20)),
                   check_every=int(u.get("disk_check_every_bytes", 256 * 2**20)),
                   local_roots=[rel(r) for r in roots] if roots else None)


def sanitize_name(raw: str | None, allowed: tuple[str, ...]) -> str:
    """Basename only, [A-Za-z0-9._-]; rejects empty names, '..', absolute paths and disallowed extensions."""
    name = (raw or "").strip()
    if not name:
        raise UploadError(400, "empty file name")
    if ".." in name:
        raise UploadError(400, "file name must not contain '..'")
    if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
        raise UploadError(400, "file name must not be an absolute path")
    base = re.split(r"[\\/]", name)[-1]
    base = _UNSAFE.sub("_", base).lstrip(".")
    if not base:
        raise UploadError(400, "empty file name")
    ext = Path(base).suffix.lower()
    if ext not in allowed:
        raise UploadError(415, f"extension {ext or '(none)'} not allowed; allowed: {' '.join(allowed)}")
    return base


_FILENAME_RE = re.compile(rb'(?:^|;)\s*filename\s*=\s*("([^"]*)"|[^;]*)', re.IGNORECASE)


def _raw_filename(disposition: bytes) -> str | None:
    """filename= of a Content-Disposition header exactly as sent (None if the part is not a file)."""
    m = _FILENAME_RE.search(disposition)
    if m is None:
        return None
    raw = m.group(2) if m.group(2) is not None else m.group(1).strip()
    return raw.decode("utf-8", errors="replace")


@dataclass
class _Sink:
    """Writes parts into one upload dir with size cap and free-disk checks."""

    mgr: UploadManager
    dir: Path
    files: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0
    _fh: BinaryIO | None = None
    _cur: dict[str, Any] | None = None
    _since_check: int = 0

    def open(self, raw_name: str | None) -> None:
        name = sanitize_name(raw_name, self.mgr.cfg.allowed)
        taken = {f["name"].casefold() for f in self.files}  # NTFS / APFS: names differing only in case collide
        stem, ext, i = Path(name).stem, Path(name).suffix, 1
        while name.casefold() in taken:
            name, i = f"{stem}-{i}{ext}", i + 1
        self._cur = {"name": name, "bytes": 0}
        self._fh = open(self.dir / name, "wb", buffering=self.mgr.cfg.chunk_bytes)  # noqa: SIM115

    def write(self, data: bytes | memoryview) -> None:
        if self._fh is None or self._cur is None:
            return
        n = len(data)
        self.total += n
        self._cur["bytes"] += n
        if self.total > self.mgr.cfg.max_bytes:
            raise UploadError(413, f"upload exceeds max_bytes ({self.mgr.cfg.max_bytes})")
        self._since_check += n
        if self._since_check >= self.mgr.cfg.check_every:
            self._since_check = 0
            self.mgr.require_free(0)
        self._fh.write(data)

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            assert self._cur is not None
            self.files.append(self._cur)
        self._fh, self._cur = None, None

    def abort(self) -> None:
        if self._fh is not None:
            self._fh.close()
        self._fh = None


class UploadManager:
    def __init__(self, cfg: UploadConfig, repo_root: Path = REPO_ROOT,
                 disk_free: Callable[[Path], int] | None = None) -> None:
        self.cfg, self.repo_root = cfg, repo_root.resolve()
        self._disk_free = disk_free or (lambda p: shutil.disk_usage(p).free)
        # announce() hook: called with a finished upload's info (must not block: it runs on the event loop); its
        # return value becomes the response's "integrity" key (api_integrity: auto-started quick scan).
        self.on_complete: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None

    def upload_dir(self, uid: str) -> Path | None:
        """<root>/<uid> of a completed upload, or None (uid must match the upload id pattern: never a raw path)."""
        if not isinstance(uid, str) or not _ID_RE.match(uid):
            return None
        d = self.cfg.root / uid
        return d if d.is_dir() else None

    # ---- helpers ---------------------------------------------------------------------------------------------
    def require_free(self, incoming: int) -> None:
        self.cfg.root.mkdir(parents=True, exist_ok=True)
        free = self._disk_free(self.cfg.root)
        if free - incoming < self.cfg.min_free_bytes:
            raise UploadError(507, f"not enough free disk: {free} bytes free, need {incoming} + "
                                   f"{self.cfg.min_free_bytes} reserve")

    def _new(self) -> tuple[str, Path]:
        uid = f"up-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"
        tmp = self.cfg.root / INCOMING_DIR / uid
        tmp.mkdir(parents=True)
        return uid, tmp

    def _rel(self, p: Path) -> str:
        try:
            return p.resolve().relative_to(self.repo_root).as_posix()
        except ValueError:
            return p.resolve().as_posix()

    def _finish(self, uid: str, tmp: Path, files: list[dict[str, Any]], mode: str) -> dict[str, Any]:
        if not files:
            raise UploadError(400, f"no files (multipart field '{FIELD}')")
        final = self.cfg.root / uid
        os.replace(tmp, final)
        info = {"upload_id": uid, "raw_dir": self._rel(final), "files": files,
                "total_bytes": sum(f["bytes"] for f in files), "mode": mode,
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        meta = self.cfg.root / META_DIR
        meta.mkdir(parents=True, exist_ok=True)
        (meta / f"{uid}.json").write_text(json.dumps(info), encoding="utf-8")
        log.info("upload %s: %d files, %d bytes (%s)", uid, len(files), info["total_bytes"], mode)
        return info

    def announce(self, info: dict[str, Any]) -> dict[str, Any]:
        """Run the on_complete hook for a finished upload (called by the API endpoints after receive() /
        register_local(), so library callers of those never start background work). Its return value becomes the
        response's "integrity" key; a failing hook never fails the upload."""
        if self.on_complete is None:
            return info
        try:
            extra = self.on_complete(info)
        except Exception:  # noqa: BLE001 - the hook never fails a completed upload
            log.warning("upload %s: on_complete hook failed", info.get("upload_id"), exc_info=True)
            return info
        return info if extra is None else {**info, "integrity": extra}

    # ---- POST /api/uploads -----------------------------------------------------------------------------------
    async def receive(self, content_type: str | None, content_length: int | None,
                      stream: AsyncIterator[bytes]) -> dict[str, Any]:
        ctype, params = parse_options_header(content_type or "")
        boundary = params.get(b"boundary")
        if ctype != b"multipart/form-data" or not boundary:
            raise UploadError(400, "expected multipart/form-data with a boundary")
        if content_length is not None:
            if content_length > self.cfg.max_bytes + 2**20:  # + multipart overhead
                raise UploadError(413, f"upload exceeds max_bytes ({self.cfg.max_bytes})")
            self.require_free(content_length)
        uid, tmp = self._new()
        sink = _Sink(self, tmp)
        headers: dict[bytes, bytes] = {}
        hname: list[bytes] = []
        hval: list[bytes] = []

        def on_header_field(d: bytes, s: int, e: int) -> None:
            hname.append(d[s:e])

        def on_header_value(d: bytes, s: int, e: int) -> None:
            hval.append(d[s:e])

        def on_header_end() -> None:
            headers[b"".join(hname).lower()] = b"".join(hval)
            hname.clear()
            hval.clear()

        def on_headers_finished() -> None:
            disp = headers.get(b"content-disposition", b"")
            _, opts = parse_options_header(disp)
            name = opts.get(b"name", b"").decode()
            headers.clear()
            fname = _raw_filename(disp)  # raw value: the parser silently strips IE-style "C:\..." paths
            if name == FIELD and fname is not None:
                sink.open(fname)

        ended: list[bool] = []  # on_end fires only on the closing boundary (finalize() does not check, 0.0.33)
        callbacks = {"on_header_field": on_header_field, "on_header_value": on_header_value,
                     "on_header_end": on_header_end, "on_headers_finished": on_headers_finished,
                     "on_part_data": lambda d, s, e: sink.write(d[s:e]), "on_part_end": sink.close,
                     "on_end": lambda: ended.append(True)}
        parser = MultipartParser(boundary, callbacks)  # type: ignore[arg-type]
        try:
            buf, size = [], 0
            async for chunk in stream:  # batch ~chunk_bytes per thread hop (a hop per 64 KiB costs ~10x)
                if chunk:
                    buf.append(chunk)
                    size += len(chunk)
                if size >= self.cfg.chunk_bytes:
                    await anyio.to_thread.run_sync(parser.write, b"".join(buf))  # file writes off the event loop
                    buf, size = [], 0
            if buf:
                await anyio.to_thread.run_sync(parser.write, b"".join(buf))
            parser.finalize()
            if not ended:
                raise UploadError(400, "truncated multipart body (closing boundary missing); partial upload removed")
            return self._finish(uid, tmp, sink.files, "upload")
        except BaseException:
            sink.abort()
            shutil.rmtree(tmp, ignore_errors=True)
            raise

    # ---- POST /api/uploads/local -----------------------------------------------------------------------------
    def register_local(self, path: str) -> dict[str, Any]:
        src = Path(path or "")
        if not path or not src.is_absolute():
            raise UploadError(400, "path must be an absolute path on this machine")
        try:
            src = src.resolve(strict=True)
        except (OSError, RuntimeError):
            raise UploadError(404, "file not found") from None
        if not src.is_file():
            raise UploadError(400, "path must be an existing regular file")
        if self.cfg.local_roots is not None and not any(src.is_relative_to(r) for r in self.cfg.local_roots):
            raise UploadError(403, "path is outside upload.local_roots")
        name = sanitize_name(src.name, self.cfg.allowed)
        size = src.stat().st_size
        if size > self.cfg.max_bytes:
            raise UploadError(413, f"file exceeds max_bytes ({self.cfg.max_bytes})")
        uid, tmp = self._new()
        dst = tmp / name
        try:
            try:
                os.link(src, dst)
                mode = "link"
            except OSError as exc:  # other volume, FAT, no permission ... -> streamed copy
                log.info("upload %s: hard link failed (%s); copying", uid, exc)
                self.require_free(size)
                sink = _Sink(self, tmp)
                sink._fh, sink._cur = open(dst, "wb", buffering=self.cfg.chunk_bytes), {"name": name, "bytes": 0}  # noqa: SIM115
                with open(src, "rb") as fh:
                    while block := fh.read(self.cfg.chunk_bytes):
                        sink.write(block)
                sink.close()
                mode = "copy"
            return self._finish(uid, tmp, [{"name": name, "bytes": size}], mode)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise

    # ---- GET /api/uploads ------------------------------------------------------------------------------------
    def list(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        root = self.cfg.root
        if not root.is_dir():
            return out
        for d in root.iterdir():
            if not d.is_dir() or not _ID_RE.match(d.name):
                continue
            meta = root / META_DIR / f"{d.name}.json"
            try:
                info = json.loads(meta.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                files = [{"name": f.name, "bytes": f.stat().st_size} for f in sorted(d.iterdir()) if f.is_file()]
                info = {"upload_id": d.name, "raw_dir": self._rel(d), "files": files,
                        "total_bytes": sum(f["bytes"] for f in files), "mode": "unknown",
                        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(d.stat().st_mtime))}
            out.append(info)
        out.sort(key=lambda i: (str(i.get("created_at") or i.get("created", "")), i["upload_id"]), reverse=True)
        return out
