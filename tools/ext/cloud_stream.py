"""Streaming, read-only CloudTrail record reader for the external-data evaluation (tools/ext/cloud_*.py).

Inputs are untrusted data: nothing is executed or extracted to disk. Tar members are streamed, gzip is detected
by magic bytes, and a {"Records": [...]} document is walked one record at a time with json.raw_decode, so a
130 MB single-line file never becomes one Python object. Each record is yielded as its EXACT source text.
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path
from typing import BinaryIO, Iterator

CHUNK = 4 << 20
MAX_RECORD = 64 << 20
_DEC = json.JSONDecoder()


class BadInput(ValueError):
    pass


def _text_chunks(fh: BinaryIO) -> Iterator[str]:
    dec = io.TextIOWrapper(fh, encoding="utf-8", errors="replace", newline="")
    while True:
        s = dec.read(CHUNK)
        if not s:
            return
        yield s


def _ws(buf: str, i: int) -> int:
    n = len(buf)
    while i < n and buf[i] in " \t\r\n,":
        i += 1
    return i


def iter_text_records(fh: BinaryIO) -> Iterator[tuple[str, str]]:
    """Yield (kind, raw_text) with kind in {'record', 'bad'}. Handles JSON lines and {"Records": [...]}
    documents (one or many per file, any line layout)."""
    chunks = _text_chunks(fh)
    buf, eof, i = "", False, 0

    def more() -> bool:
        nonlocal buf, eof, i
        if eof:
            return False
        try:
            s = next(chunks)
        except StopIteration:
            eof = True
            return False
        buf = buf[i:] + s
        i = 0
        return True

    more()
    if buf.startswith("﻿"):
        buf = buf[1:]
    in_records = False
    while True:
        i = _ws(buf, i)
        if i >= len(buf):
            if not more():
                return
            continue
        if in_records:
            if buf[i] == "]":  # end of Records array; skip the closing '}' of the wrapper
                j = buf.find("}", i)
                while j < 0 and more():
                    j = buf.find("}", i)
                i = (j + 1) if j >= 0 else len(buf)
                in_records = False
                continue
        else:
            head = buf[i:i + 200]
            while len(head) < 200 and more():
                head = buf[i:i + 200]
            stripped = head.replace(" ", "").replace("\n", "").replace("\r", "")
            if stripped.startswith('{"Records":['):
                j = buf.find("[", i)
                i = j + 1
                in_records = True
                continue
            if buf[i] != "{":  # junk before the next object: skip to end of line, count as bad
                j = buf.find("\n", i)
                while j < 0 and more():
                    j = buf.find("\n", i)
                yield "bad", buf[i:(j if j >= 0 else len(buf))][:200]
                i = (j + 1) if j >= 0 else len(buf)
                continue
        while True:
            try:
                _, end = _DEC.raw_decode(buf, i)
                break
            except json.JSONDecodeError:
                if len(buf) - i > MAX_RECORD or not more():
                    j = buf.find("\n", i)
                    yield "bad", buf[i:(j if j >= 0 else len(buf))][:200]
                    if j < 0:
                        return
                    i = j + 1
                    end = -1
                    break
        if end < 0:
            continue
        yield "record", buf[i:end]
        i = end


def _open_maybe_gz(fh: BinaryIO) -> BinaryIO:
    peek = fh.read(2)
    rest = io.BufferedReader(_Prefixed(peek, fh))  # type: ignore[arg-type]
    return gzip.GzipFile(fileobj=rest) if peek == b"\x1f\x8b" else rest  # type: ignore[return-value]


class _Prefixed(io.RawIOBase):
    def __init__(self, prefix: bytes, fh: BinaryIO) -> None:
        self._p, self._fh = prefix, fh

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray) -> int:  # type: ignore[override]
        if self._p:
            n = min(len(b), len(self._p))
            b[:n], self._p = self._p[:n], self._p[n:]
            return n
        data = self._fh.read(len(b))
        b[:len(data)] = data
        return len(data)


def input_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out += sorted(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() != ".md"
                          and "ground_truth" not in x.relative_to(p).parts)
        else:
            out.append(p)
    return out


def iter_raw(paths: list[Path]) -> Iterator[tuple[str, str, str]]:
    """Yield (source_name, kind, raw_text) for every record in every input (tar members streamed)."""
    for f in input_files(paths):
        if tarfile.is_tarfile(f):
            with tarfile.open(f, "r:") as tf:
                for m in tf:
                    if not m.isfile() or m.name.startswith("/") or ".." in Path(m.name).parts:
                        continue
                    fh = tf.extractfile(m)
                    if fh is None:
                        continue
                    for kind, raw in iter_text_records(_open_maybe_gz(fh)):
                        yield f"{f.name}:{m.name}", kind, raw
            continue
        with f.open("rb") as fh:
            for kind, raw in iter_text_records(_open_maybe_gz(fh)):
                yield f.name, kind, raw
