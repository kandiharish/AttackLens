"""Bounded-memory incremental JSON reader for cloud delivery envelopes (stdlib only, no ijson).

`JsonStream` walks a text stream of top-level JSON values (one document, JSON Lines, or concatenated `{..}{..}`
as Firehose writes them). A value that fits in `inline_max` chars is decoded with `json.raw_decode` (C speed);
a bigger one is walked structurally: a top-level array yields its elements one at a time, a top-level object
yields its keys and streams the array of a configured envelope key (`Records`, `records`, `entries` ...)
element by element. Memory therefore stays O(chunk + largest single record), never O(document).

Errors never pass silently: `Malformed` (bad syntax / truncated) and `TooLarge` (one record > max_record) carry
a reason; the caller counts them. After a bad JSON Lines line the stream resyncs at the next newline; inside a
streamed document it cannot resync, so the rest of that document is reported as unparsed bytes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterator, TextIO

_DEC = json.JSONDecoder()
WS = " \t\r\n\ufeff"
_FIRST_KEY = re.compile(r'\{\s*"([^"\\]{1,64})"\s*:\s*\[')
NL = "\n"
STREAM = object()  # iter_object value marker: the caller must consume iter_array() before the next key


class Malformed(ValueError):
    """Bad or truncated JSON. `reason` is malformed_json or truncated_json."""

    def __init__(self, reason: str, msg: str, offset: int) -> None:
        super().__init__(f"{reason} at char {offset}: {msg}")
        self.reason, self.offset = reason, offset


class TooLarge(ValueError):
    """One value is bigger than the allowed bound (record_too_large)."""


@dataclass
class TopValue:
    """A complete top-level value (`value`), a big one to walk structurally (`walk`: `kind` is [ or {), or a bad
    one (`error`; `skipped` chars were dropped to resync at the next line, or to the end when `fatal`)."""
    value: Any = None
    raw: str | None = None
    kind: str = ""
    walk: bool = False
    error: ValueError | None = None
    skipped: int = 0
    fatal: bool = False
    line_start: bool = False


class JsonStream:
    def __init__(self, fh: TextIO, chunk: int = 1 << 20, inline_max: int = 16 << 20,
                 max_record: int = 64 << 20) -> None:
        self.fh, self.chunk, self.inline_max, self.max_record = fh, chunk, inline_max, max_record
        self.buf, self.pos, self.base, self.eof = "", 0, 0, False
        self._mark, self._mark_nl = -1, False
        self.span = (0, 0)

    # ---- buffer -----------------------------------------------------------------------------------------------
    @property
    def offset(self) -> int:
        return self.base + self.pos

    def _fill(self, n: int) -> bool:
        if self.eof:
            return False
        if self.pos > self.chunk:  # compact: drop consumed text
            if self._mark >= 0 and not self._mark_nl:
                self._mark_nl = NL in self.buf[max(0, self._mark - self.base):self.pos]
            self.base += self.pos
            self.buf, self.pos = self.buf[self.pos:], 0
        s = self.fh.read(n)
        if not s:
            self.eof = True
            return False
        self.buf += s
        return True

    def peek(self) -> str:
        """Next non-whitespace char ("" at end of input); does not consume it."""
        while True:
            n = len(self.buf)
            while self.pos < n and self.buf[self.pos] in WS:
                self.pos += 1
            if self.pos < n:
                return self.buf[self.pos]
            if not self._fill(self.chunk):
                return ""

    def expect(self, chars: str) -> str:
        c = self.peek()
        if c == "" or c not in chars:
            reason = "truncated_json" if c == "" else "malformed_json"
            raise Malformed(reason, f"expected one of {chars!r}, got {c!r}", self.offset)
        self.pos += 1
        return c

    def decode(self, limit: int) -> Any:
        """Decode one value at the cursor (after peek()); grows the buffer geometrically, so a value is parsed
        O(log size) times at most."""
        while True:
            try:
                val, end = _DEC.raw_decode(self.buf, self.pos)
            except json.JSONDecodeError as e:
                if self.eof:  # truncated = the input stops inside the value (nothing structural after the error)
                    tail = self.buf[e.pos:].strip()
                    cut = e.msg.startswith("Unterminated") or (len(tail) < 10 and not any(ch in tail for ch in ",]}"))
                    raise Malformed("truncated_json" if cut else "malformed_json", e.msg, self.base + e.pos) from None
                if not (e.pos >= len(self.buf) - 10 or e.msg.startswith("Unterminated")):
                    raise Malformed("malformed_json", e.msg, self.base + e.pos) from None
                if len(self.buf) - self.pos > limit:
                    raise TooLarge(f"value at char {self.offset} is larger than {limit} chars") from None
                self._fill(max(self.chunk, len(self.buf) - self.pos))
                continue
            if end == len(self.buf) and not self.eof and isinstance(val, (int, float)) and self._fill(self.chunk):
                continue  # a number at the buffer end may continue in the next chunk
            self.span = (self.pos, end)
            self.pos = end
            return val

    def skip_line(self) -> int:
        """Resync after a bad JSON Lines value: drop text up to and including the next newline; returns chars."""
        start = self.offset
        while True:
            i = self.buf.find("\n", self.pos)
            if i >= 0:
                self.pos = i + 1
                return self.offset - start
            self.pos = len(self.buf)
            if not self._fill(self.chunk):
                return self.offset - start

    def drain(self) -> int:
        """Consume the rest of the input (after an unrecoverable error); returns the chars dropped."""
        start = self.offset
        self.pos = len(self.buf)
        while self._fill(self.chunk):
            self.pos = len(self.buf)
        return self.offset - start

    def raw_last(self) -> str:
        """Source text of the value decode() returned last (valid until the next read)."""
        return self.buf[self.span[0]:self.span[1]]

    def one_line_since_mark(self, offset: int) -> bool:
        """True when no newline lies between the start of the walked value and `offset` (a JSON Lines value)."""
        if self._mark < 0 or self._mark_nl:
            return False
        return NL not in self.buf[max(0, self._mark - self.base):max(0, offset - self.base)]

    def _at_line_start(self, i: int) -> bool:
        j = i - 1
        while j >= 0 and self.buf[j] in " \t\ufeff":
            j -= 1
        return j < 0 or self.buf[j] == "\n"

    # ---- structure --------------------------------------------------------------------------------------------
    def _first_key(self) -> str | None:
        """The first key of the object at the cursor when its value is an array (a cheap regex look-ahead)."""
        while len(self.buf) - self.pos < 256 and self._fill(self.chunk):
            pass
        m = _FIRST_KEY.match(self.buf, self.pos, self.pos + 256)
        return m.group(1) if m else None

    def top_values(self, walk_keys: frozenset[str] = frozenset()) -> Iterator[TopValue]:
        """Top-level values. A complete value comes back decoded; an array, an object whose first key is in
        walk_keys (e.g. {"Records": [...]}), or a value bigger than inline_max comes back with walk=True and the
        caller walks it with iter_array() / iter_object(): no prefix of it is ever decoded in one piece."""
        while True:
            c = self.peek()
            if c == "":
                return
            ls = self._at_line_start(self.pos)
            if c == "[" or (c == "{" and self._first_key() in walk_keys):
                self._mark, self._mark_nl = self.offset, False
                yield TopValue(kind=c, walk=True, line_start=ls)
                continue
            try:
                val = self.decode(self.inline_max if c in "[{" else self.max_record)
            except TooLarge as e:
                if c in "[{":
                    self._mark, self._mark_nl = self.offset, False
                    yield TopValue(kind=c, walk=True, line_start=ls)
                    continue
                yield TopValue(error=e, skipped=self.drain(), fatal=True)
                return
            except Malformed as e:
                same_line = "\n" not in self.buf[self.pos:max(self.pos, e.offset - self.base)]
                if c in "[{" and not (ls and same_line):
                    # a multi-line document with an error deep inside: walk it to salvage the records before it
                    self._mark, self._mark_nl = self.offset, False
                    yield TopValue(kind=c, walk=True, line_start=ls)
                    continue
                if ls:  # JSON Lines: drop this line only
                    yield TopValue(error=e, skipped=self.skip_line())
                    continue
                yield TopValue(error=e, skipped=self.drain(), fatal=True)
                return
            yield TopValue(value=val, kind=c, raw=self.raw_last())

    def iter_array(self) -> Iterator[Any]:
        """Elements of the array at the cursor ('[' not yet consumed)."""
        self.expect("[")
        if self.peek() == "]":
            self.pos += 1
            return
        while True:
            self.peek()
            yield self.decode(self.max_record)
            if self.expect(",]") == "]":
                return

    def iter_object(self, stream_keys: frozenset[str]) -> Iterator[tuple[str, Any]]:
        """(key, value) of the object at the cursor; for a key in stream_keys whose value is an array the value is
        STREAM and the caller must consume iter_array() before advancing this iterator."""
        self.expect("{")
        if self.peek() == "}":
            self.pos += 1
            return
        while True:
            if self.peek() != '"':
                raise Malformed("truncated_json" if self.peek() == "" else "malformed_json",
                                "expected a property name", self.offset)
            key = self.decode(self.max_record)
            self.expect(":")
            if key in stream_keys and self.peek() == "[":
                yield key, STREAM
            else:
                self.peek()
                yield key, self.decode(self.max_record)
            if self.expect(",}") == "}":
                return
