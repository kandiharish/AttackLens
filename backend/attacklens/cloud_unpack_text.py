"""Stage 0 text decode (robust item #4): UTF-16 LE/BE, cp1252 fallback, lone-CR line ends, NUL padding, blank lines.

A text log that DuckDB cannot read as UTF-8 lines is rewritten by the unpacker as a UTF-8, LF copy:
  * UTF-16 LE / BE: by BOM, or (no BOM) by the alternating-NUL pattern (`text.utf16_nul_ratio` of the even or odd
    bytes are NUL); transcoded with an incremental decoder in bounded chunks.
  * invalid UTF-8 line: decoded with `text.fallback_encoding` (cp1252), counted per line (`decoded_cp1252_lines`).
  * lone CR (classic Mac / mixed endings) is a line end (`lone_cr_normalised`), CRLF stays one line end.
  * trailing NUL padding (pre-allocated / truncated files) is stripped and counted (`nul_padding_bytes`).
  * whitespace-only lines are dropped and counted (skipped `whitespace_only_line`), empty lines are counted as a note.
Records are counted on decoded lines: a UTF-16 CRLF file with 6 lines gives 6 lines, never 14.

A clean UTF-8 file is never rewritten (classify_text returns None). Memory: O(chunk + longest line).
"""

from __future__ import annotations

import codecs
import io
import re
from pathlib import Path
from typing import IO, Any, Iterator

from attacklens.cloud_unpack_env import Acct

BOM_LE, BOM_BE, BOM_U8 = b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf"
_SEP_B = re.compile(rb"\r\n|\r|\n")
_SEP_S = re.compile(r"\r\n|\r|\n")
_LONE_CR_B = re.compile(rb"\r(?!\n)")
_CTRL = re.compile(rb"[\x01-\x08\x0e-\x1a\x1c-\x1f]")
DEFAULTS: dict[str, Any] = {
    "enabled": True, "utf16_bom": "transcode", "utf16_nul_ratio": 0.3, "fallback_encoding": "cp1252",
    "normalise_lone_cr": True, "strip_nul_tail": True, "drop_whitespace_lines": True, "rewrite_for_blank_lines": False,
    "tail_bytes": 4096, "max_ctrl_ratio": 0.01, "chunk_bytes": 1048576, "max_line_chars": 67108864,
}


def text_cfg(ucfg: dict[str, Any] | None) -> dict[str, Any]:
    return {**DEFAULTS, **((ucfg or {}).get("text") or {})}


def utf16_kind(head: bytes, tcfg: dict[str, Any]) -> str | None:
    """'utf-16-le' / 'utf-16-be' from a BOM or the alternating-NUL pattern; None otherwise."""
    if head[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return None  # UTF-32: not handled (left to profile, reported there)
    if head[:2] == BOM_LE:
        return "utf-16-le"
    if head[:2] == BOM_BE:
        return "utf-16-be"
    s = head[:4096].rstrip(b"\x00")
    s = s[: len(s) // 2 * 2]
    n = len(s) // 2
    if n < 8:
        return None
    even, odd = s[0::2].count(0) / n, s[1::2].count(0) / n
    ratio = float(tcfg.get("utf16_nul_ratio", 0.3))
    if odd >= ratio and even < 0.05:
        return "utf-16-le"
    if even >= ratio and odd < 0.05:
        return "utf-16-be"
    return None


def _looks_text(body: bytes, tcfg: dict[str, Any]) -> bool:
    """Few NULs and control bytes: a text log (a NUL-padded binary file is not decoded as text)."""
    b = body[:65536]
    if not b:
        return False
    if b.count(b"\x00") * 20 > len(b):
        return False
    return len(_CTRL.findall(b)) <= float(tcfg.get("max_ctrl_ratio", 0.01)) * len(b)


def _valid_utf8(b: bytes) -> bool:
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        return e.start >= len(b) - 3 and e.reason == "unexpected end of data"  # a char cut at the sniff boundary


def classify_text(path: Path, head: bytes, ucfg: dict[str, Any] | None) -> str | None:
    """Why this text file must be rewritten before profiling (text_utf16le / text_utf16be / text_cp1252 /
    text_lone_cr / text_nul_tail / text_blank_lines), None = leave it alone. Reads at most the head + `tail_bytes`."""
    tcfg = text_cfg(ucfg)
    if not tcfg.get("enabled", True) or not head:
        return None
    kind = utf16_kind(head, tcfg)
    if kind:
        return "text_utf16le" if kind.endswith("le") else "text_utf16be"
    size = path.stat().st_size
    tail = b""
    if tcfg.get("strip_nul_tail", True):
        if size <= len(head):
            tail = head[-int(tcfg["tail_bytes"]):]
        else:
            with path.open("rb") as fh:
                fh.seek(max(0, size - int(tcfg["tail_bytes"])))
                tail = fh.read()
    nul_tail = tail.endswith(b"\x00")
    body = head.rstrip(b"\x00") if (nul_tail and size <= len(head)) else head
    if not _looks_text(body, tcfg):
        return None
    if nul_tail:
        return "text_nul_tail"
    if not _valid_utf8(body.removeprefix(BOM_U8)):
        return "text_cp1252"
    if tcfg.get("normalise_lone_cr", True) and _LONE_CR_B.search(body[:-1]):
        return "text_lone_cr"
    if tcfg.get("rewrite_for_blank_lines") and re.search(rb"(?m)^[ \t\f\v]+\r?$", body):
        return "text_blank_lines"
    return None


def mode(head: bytes, ucfg: dict[str, Any] | None, hint: str = "") -> str | None:
    """Decoder mode for one stream: 'utf-16-le' / 'utf-16-be' / 'utf-8' (line-normalising), None = plain UTF-8."""
    tcfg = text_cfg(ucfg)
    if not tcfg.get("enabled", True):
        return None
    kind = utf16_kind(head, tcfg)
    if kind:
        return kind
    if hint.startswith("text_"):
        return "utf-8"
    if _looks_text(head, tcfg) and (not _valid_utf8(head.removeprefix(BOM_U8))
                                    or (tcfg.get("normalise_lone_cr", True) and _LONE_CR_B.search(head[:-1]))):
        return "utf-8"
    return None


def lead(head: bytes, m: str | None) -> str:
    """The decoded head, BOM and leading whitespace stripped (to look for '{', '[' or '<')."""
    if m and m.startswith("utf-16"):
        text = codecs.decode(head[: len(head) // 2 * 2], m, errors="replace")
    else:
        text = head.decode("utf-8", errors="replace")
    return text.lstrip("﻿ \t\r\n\x00")


class DecodedText(io.TextIOBase):
    """A UTF-8 text view of `raw` with LF line ends (read(n) / readline() / iteration), counting into acct.notes /
    acct.skipped / acct.failed. Lines are yielded without NUL padding and whitespace-only lines."""

    def __init__(self, raw: IO[bytes], m: str, ucfg: dict[str, Any] | None, acct: Acct) -> None:
        self.raw, self.m, self.acct = raw, m, acct
        self.tcfg = text_cfg(ucfg)
        self.chunk = int(self.tcfg.get("chunk_bytes", 1 << 20))
        self.max_line = int(self.tcfg.get("max_line_chars", 1 << 26))
        self.fallback = str(self.tcfg.get("fallback_encoding") or "cp1252")
        self._gen = self._blocks()
        self._buf, self._pos, self._first = "", 0, True
        if m.startswith("utf-16"):
            acct.notes[f"transcoded_{m.replace('-', '')}"] += 1

    def readable(self) -> bool:
        return True

    def _more(self) -> bool:
        blk = next(self._gen, None)
        if blk is None:
            return False
        self._buf, self._pos = self._buf[self._pos:] + blk, 0
        return True

    def read(self, n: int | None = -1) -> str:
        if n is None or n < 0:
            while self._more():
                pass
            n = len(self._buf) - self._pos
        while len(self._buf) - self._pos < n and self._more():
            pass
        out = self._buf[self._pos:self._pos + n]
        self._pos += len(out)
        return out

    def readline(self, size: int | None = -1) -> str:
        while True:
            i = self._buf.find("\n", self._pos)
            if i >= 0:
                out = self._buf[self._pos:i + 1]
                self._pos = i + 1
                return out
            if not self._more():
                out = self._buf[self._pos:]
                self._pos = len(self._buf)
                return out

    # ---- decoding ----------------------------------------------------------------------------------------------
    def _line(self, s: str) -> str | None:
        """One decoded line -> kept text, or None (counted)."""
        if self._first:
            s, self._first = s.lstrip("﻿"), False
        if self.tcfg.get("strip_nul_tail", True) and s.endswith("\x00"):
            t = s.rstrip("\x00")
            self.acct.notes["nul_padding_bytes"] += len(s) - len(t)
            if not t:
                self.acct.notes["nul_padding_lines"] += 1
                return None
            s = t
        if not s:
            self.acct.notes["empty_lines"] += 1
            return None
        if self.tcfg.get("drop_whitespace_lines", True) and not s.strip():
            self.acct.skipped["whitespace_only_line"] += 1
            return None
        return s

    def _dec_bytes(self, b: bytes) -> str:
        try:
            return b.decode("utf-8")
        except UnicodeDecodeError:
            self.acct.notes[f"decoded_{self.fallback}_lines"] += 1
            return b.decode(self.fallback, errors="replace")

    def _block(self, lines: list[str]) -> str | None:
        kept = [k for k in (self._line(s) for s in lines) if k is not None]
        return "\n".join(kept) + "\n" if kept else None

    def _split(self, buf: Any, sep: re.Pattern[Any], cr: Any, eof: bool) -> tuple[list[Any], Any]:
        """Complete lines of buf and the carried rest (a trailing CR waits for a possible LF)."""
        hold = buf[:0]
        if not eof and buf.endswith(cr):
            buf, hold = buf[:-1], cr
        n_cr = buf.count(cr) - buf.count(cr + (b"\n" if isinstance(buf, bytes) else "\n"))
        if n_cr and self.tcfg.get("normalise_lone_cr", True):
            self.acct.notes["lone_cr_normalised"] += n_cr
        parts = sep.split(buf)
        rest = parts.pop()
        if eof:
            if rest:
                parts.append(rest)
            rest = buf[:0]
        if len(rest) > self.max_line:
            self.acct.failed["text_line_too_long"] += 1
            rest = buf[:0]
        return parts, rest + hold

    def _blocks(self) -> Iterator[str]:
        if self.m.startswith("utf-16"):
            dec = codecs.getincrementaldecoder(self.m)(errors="replace")
            carry = ""
            while True:
                data = self.raw.read(self.chunk)
                eof = not data
                text = carry + dec.decode(data, final=eof)
                if "�" in text:
                    self.acct.notes["utf16_replaced_chars"] += text.count("�")
                lines, carry = self._split(text, _SEP_S, "\r", eof)
                blk = self._block(lines)
                if blk:
                    yield blk
                if eof:
                    return
        carry_b = b""
        while True:
            data = self.raw.read(self.chunk)
            eof = not data
            blines, carry_b = self._split(carry_b + data, _SEP_B, b"\r", eof)
            try:
                lines = b"\n".join(blines).decode("utf-8").split("\n") if blines else []
            except UnicodeDecodeError:
                lines = [self._dec_bytes(b) for b in blines]
            blk = self._block(lines)
            if blk:
                yield blk
            if eof:
                return


def open_text(raw: IO[bytes], m: str, ucfg: dict[str, Any] | None, acct: Acct) -> DecodedText:
    return DecodedText(raw, m, ucfg, acct)
