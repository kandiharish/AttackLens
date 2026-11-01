"""Container layer of cloud_unpack: magic-byte detection (gzip / bzip2 / xz / zip / tar, nested), the
decompression budget guard (zip / gzip bombs) and the per-input-file output writer (rotating one-record-per-line
files per member / bucket). Truncated or corrupt compressed data ends that stream with a counted failure; the data
decompressed before the damage is kept.
"""

from __future__ import annotations

import bz2
import gzip
import io
import json
import logging
import lzma
import os
import shutil
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import IO, Any, Iterator

from attacklens.cloud_unpack_env import Acct, BombError, Budget, RawJson, Unwrapper, slug

log = logging.getLogger("attacklens.cloud_unpack")

_ENC = json.JSONEncoder(ensure_ascii=False).encode  # one encoder (json.dumps with kwargs builds one per call)
GZIP, ZIP, ZIP_EMPTY, BZ2, XZ = b"\x1f\x8b", b"PK\x03\x04", b"PK\x05\x06", b"BZh", b"\xfd7zXZ\x00"


class _Guard(io.RawIOBase):
    """Counts decompressed bytes against the input file's Budget. Truncated / corrupt compressed data ends the
    stream (counted in acct.failed) so everything decompressed before the damage still flows through."""

    def __init__(self, inner: IO[bytes], budget: Budget, acct: Acct) -> None:
        self.inner, self.budget, self.acct, self.dead = inner, budget, acct, False
        self._read = getattr(inner, "read1", inner.read)  # one raw read: never loses data on a late error

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        if self.dead:
            return 0
        try:
            data = self._read(len(b))
        except (EOFError, zlib.error, lzma.LZMAError, gzip.BadGzipFile, zipfile.BadZipFile) as exc:
            log.warning("unwrap: truncated or corrupt compressed data: %s", exc)
            self.acct.failed["truncated_or_corrupt_compressed_data"] += 1
            self.dead = True
            return 0
        n = len(data)
        self.budget.take(n)
        b[:n] = data
        return n


class _Chain(io.RawIOBase):
    """`head` bytes already read, then the rest of `inner` (peek without a seekable stream)."""

    def __init__(self, head: bytes, inner: IO[bytes]) -> None:
        self.head, self.inner = head, inner

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        if self.head:
            n = min(len(b), len(self.head))
            b[:n], self.head = self.head[:n], self.head[n:]
            return n
        data = self.inner.read(len(b))
        b[:len(data)] = data
        return len(data)


def _peek(stream: IO[bytes], n: int = 512) -> tuple[bytes, IO[bytes]]:
    head = b""
    while len(head) < n:
        b = stream.read(n - len(head))
        if not b:
            break
        head += b
    return head, io.BufferedReader(_Chain(head, stream), 1 << 20)


def _is_tar(head: bytes) -> bool:
    return len(head) >= 262 and head[257:262] == b"ustar"


def _is_binary(head: bytes) -> bool:
    return head[:4096].count(b"\x00") * 20 > len(head[:4096])


class Unpacker:
    """Unpacks one input file into `out_dir`; `acct` gets its counters, `outputs` the written files."""

    def __init__(self, ucfg: dict[str, Any], out_dir: Path, size: int) -> None:
        self.ucfg, self.out_dir = ucfg, out_dir
        self.acct, self.budget, self.env = Acct(), Budget(size, ucfg), Unwrapper(ucfg)
        self.max_depth, self.max_members = int(ucfg.get("max_depth", 6)), int(ucfg.get("max_archive_members", 1e5))
        self.max_out = int(float(ucfg.get("max_out_file_bytes", 1e9)))
        self.members = 0
        self._open: dict[tuple[str, str, str], tuple[IO[bytes], Path, int]] = {}
        self._seq: dict[tuple[str, str, str], int] = {}
        self.outputs: list[Path] = []

    # ---- output ------------------------------------------------------------------------------------------------
    def _write(self, member: str, bucket: str, value: Any) -> None:
        if isinstance(value, RawJson):  # the record's own one-line text, byte for byte
            ext, line = "jsonl", str(value)
        elif isinstance(value, str):
            ext, line = "log", value.replace("\r", " ").replace("\n", " ")
        else:
            ext, line = "jsonl", _ENC(value)
        data = (line + "\n").encode("utf-8", errors="replace")
        key = (member, bucket, ext)
        cur = self._open.get(key)
        if cur is not None and cur[2] + len(data) > self.max_out:
            cur[0].close()
            cur = None
        if cur is None:
            if len(self._open) >= 64:  # bounded open handles: close the oldest (a later write opens a new part)
                old = next(iter(self._open))
                self._open.pop(old)[0].close()
            self._seq[key] = self._seq.get(key, 0) + 1
            d = self.out_dir / member if member else self.out_dir
            d.mkdir(parents=True, exist_ok=True)
            p = d / f"{slug(bucket)}-{self._seq[key]:04d}.{ext}"
            cur = (p.open("wb"), p, 0)
            self.outputs.append(p)
        cur[0].write(data)
        self._open[key] = (cur[0], cur[1], cur[2] + len(data))

    def close(self) -> None:
        for fh, _, _ in self._open.values():
            fh.close()
        self._open = {}

    # ---- containers --------------------------------------------------------------------------------------------
    def run(self, path: Path) -> None:
        """Unpack one input file into out_dir (one-record-per-line files)."""
        try:
            with path.open("rb") as fh:
                for member, bucket, v in self.iter_items(fh, path):
                    self._write(member, bucket, v)
        finally:
            self.close()

    def iter_items(self, fh: IO[bytes], path: Path | None = None) -> Iterator[tuple[str, str, Any]]:
        """(member, bucket, record) of one input stream (a file, an S3 object body ...). A record is a dict, a
        RawJson (its own one-line text) or a str (a text line). Errors end the stream with a counted failure."""
        name = path or "stream"
        try:
            yield from self._layer(fh, "", 0, path)
        except BombError as exc:
            log.warning("unwrap %s: %s", name, exc)
            self.acct.failed["decompression_limit (zip / gzip bomb guard)"] += 1
        except (EOFError, zlib.error, lzma.LZMAError, gzip.BadGzipFile) as exc:
            log.warning("unwrap %s: truncated or corrupt compressed data: %s", name, exc)
            self.acct.failed["truncated_or_corrupt_compressed_data"] += 1
        except (tarfile.TarError, zipfile.BadZipFile) as exc:
            log.warning("unwrap %s: bad archive: %s", name, exc)
            self.acct.failed["bad_archive"] += 1

    def _member(self, member: str, name: str) -> str:
        self.members += 1
        if self.members > self.max_members:
            raise tarfile.TarError(f"more than {self.max_members} archive members")
        base = slug(PurePosixPath(name.replace("\\", "/")).name or "member", 40)
        return str(PurePosixPath(member) / f"m{self.members:04d}-{base}") if member else f"m{self.members:04d}-{base}"

    def _layer(self, stream: IO[bytes], member: str, depth: int,
               path: Path | None = None) -> Iterator[tuple[str, str, Any]]:
        if depth > self.max_depth:
            self.acct.failed["nesting_too_deep"] += 1
            return
        head, s = _peek(stream)
        if head[:2] == GZIP:
            self.acct.containers["gzip"] += 1
            yield from self._layer(_buffered(gzip.GzipFile(fileobj=s), self.budget, self.acct), member, depth + 1)
            return
        if head[:3] == BZ2:
            self.acct.containers["bzip2"] += 1
            yield from self._layer(_buffered(bz2.BZ2File(s), self.budget, self.acct), member, depth + 1)
            return
        if head[:6] == XZ:
            self.acct.containers["xz"] += 1
            yield from self._layer(_buffered(lzma.LZMAFile(s), self.budget, self.acct), member, depth + 1)
            return
        if head[:4] in (ZIP, ZIP_EMPTY):
            self.acct.containers["zip"] += 1
            yield from self._zip(path, s, member, depth)
            return
        if _is_tar(head):
            self.acct.containers["tar"] += 1
            with tarfile.open(fileobj=s, mode="r|") as tf:
                for m in tf:
                    if not m.isfile():
                        if not m.isdir():
                            self.acct.skipped["archive_link_or_device_member"] += 1
                        continue
                    ef = tf.extractfile(m)
                    if ef is not None:
                        yield from self._layer(ef, self._member(member, m.name), depth + 1)
            return
        if not head.strip():
            self.acct.notes["empty_members"] += 1
            return
        if _is_binary(head):
            self.acct.skipped["binary_member"] += 1
            return
        text = io.TextIOWrapper(s, encoding="utf-8-sig", errors="replace", newline="")
        if head.lstrip(b" \t\r\n\xef\xbb\xbf")[:1] in (b"{", b"["):
            for bucket, v in self.env.stream(text, self.acct, "", 0):
                yield member, bucket, v
            return
        self.acct.containers["text"] += 1
        for line in text:  # a plain text log inside an archive: copy its lines
            line = line.rstrip("\r\n")
            if line.strip():
                self.acct.text_out += 1
                yield member, "text", line

    def _zip(self, path: Path | None, s: IO[bytes], member: str, depth: int) -> Iterator[tuple[str, str, Any]]:
        tmp = None
        if path is None:  # a zip inside another container: spool it (bounded by the budget) to a seekable file
            tmp = tempfile.NamedTemporaryFile(prefix="unwrap-", suffix=".zip", delete=False,
                                              dir=self.out_dir.parent if self.out_dir else None)
            with tmp:
                shutil.copyfileobj(s, tmp, 1 << 20)
        try:
            with zipfile.ZipFile(tmp.name if tmp else path) as zf:
                if "[Content_Types].xml" in zf.namelist():  # .xlsx / .docx / .pptx: an office document, not logs
                    self.acct.skipped["office_document"] += 1
                    return
                for zi in zf.infolist():
                    if zi.is_dir():
                        continue
                    ratio = float(self.ucfg.get("max_expand_ratio", 200))
                    if zi.file_size > self.budget.limit - self.budget.used or (
                            zi.compress_size and zi.file_size / zi.compress_size > ratio
                            and zi.file_size > int(self.ucfg.get("min_bomb_bytes", 1 << 28))):
                        self.acct.failed["decompression_limit (zip / gzip bomb guard)"] += 1
                        continue
                    if zi.flag_bits & 0x1:
                        self.acct.failed["encrypted_zip_member"] += 1
                        continue
                    with zf.open(zi) as zs:
                        yield from self._layer(_buffered(zs, self.budget, self.acct),
                                               self._member(member, zi.filename), depth + 1)
        finally:
            if tmp:
                os.unlink(tmp.name)


def _buffered(inner: IO[bytes], budget: Budget, acct: Acct) -> IO[bytes]:
    return io.BufferedReader(_Guard(inner, budget, acct), 1 << 20)
