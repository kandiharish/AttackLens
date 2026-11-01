"""Envelope rules for cloud_unpack: turn one decoded JSON value (or a streamed document) into records.

Rules (config/unwrap.yaml), tried in this order on every object:
  skip_documents   CloudTrail digest files                             -> skipped
  cloudwatch       {messageType, logEvents[]}: each `message` re-parsed; CONTROL_MESSAGE -> skipped
  array_envelopes  {"Records"|"records"|"entries"|... : [...]} (siblings checked) -> each element, recursively
  eventbridge      {"detail-type", "detail": {...}}                     -> detail
  string_json      LookupEvents {"EventId", "CloudTrailEvent": "<json>"} -> parsed string
  base64           Pub/Sub message.data, Lambda awslogs.data, Kinesis kinesis.data -> decoded (gunzipped) payload
  otherwise        the object is a record.
Items are (bucket, value): value is a dict (JSON record) or str (a text line, e.g. a CloudWatch plain message).
"""

from __future__ import annotations

import base64
import binascii
import gzip
import io
import json
import re
import zlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterator, TextIO

from attacklens.cloud_unpack_json import STREAM, JsonStream, Malformed, TooLarge

_SLUG = re.compile(r"[^a-z0-9]+")
# used when config/unwrap.yaml is absent (e.g. a connector given a partial config): never emit a whole file as a record
DEFAULT_ARRAYS: dict[str, list[str] | None] = {"Records": None, "records": None}
DEFAULT_SKIP = {"cloudtrail_digest": ["digestStartTime", "digestS3Bucket"]}


class RawJson(str):
    """A record's original one-line JSON text (written as-is: same bytes as the bare record would have)."""


def slug(s: str, n: int = 40) -> str:
    return _SLUG.sub("_", str(s).lower()).strip("_")[:n] or "x"


@dataclass
class Acct:
    """Counters of one input file (no silent loss: everything seen is out, skipped or failed)."""
    records_out: int = 0
    text_out: int = 0
    envelopes: Counter[str] = field(default_factory=Counter)
    skipped: Counter[str] = field(default_factory=Counter)
    failed: Counter[str] = field(default_factory=Counter)
    notes: Counter[str] = field(default_factory=Counter)
    containers: Counter[str] = field(default_factory=Counter)
    unparsed_chars: int = 0

    def to_json(self) -> dict[str, Any]:
        return {"records_out": self.records_out, "text_lines_out": self.text_out,
                "envelopes": dict(self.envelopes), "containers": dict(self.containers),
                "skipped": dict(self.skipped), "failed": dict(self.failed), "notes": dict(self.notes),
                "unparsed_chars": self.unparsed_chars}


class Budget:
    """Decompressed-bytes budget of one input file (zip / gzip bomb guard), shared by every nested layer."""

    def __init__(self, compressed: int, ucfg: dict[str, Any]) -> None:
        ratio = float(ucfg.get("max_expand_ratio", 200))
        self.limit = int(min(max(ratio * compressed, float(ucfg.get("min_bomb_bytes", 1 << 28))),
                             float(ucfg.get("max_expanded_bytes", 6.4e10))))
        self.used = 0

    def take(self, n: int) -> None:
        self.used += n
        if self.used > self.limit:
            raise BombError(f"decompressed {self.used} bytes > limit {self.limit}")


class BombError(OSError):
    """Decompressed data over the budget (zip / gzip bomb or a huge archive)."""


def _siblings_ok(obj: dict[str, Any], key: str, allowed: list[str] | None) -> bool:
    if allowed is None:
        return True
    for k in obj:
        if k == key or k in allowed or any(a.endswith("*") and k.startswith(a[:-1]) for a in allowed):
            continue
        return False
    return True


class Unwrapper:
    def __init__(self, ucfg: dict[str, Any]) -> None:
        self.cfg = ucfg
        self.arrays: dict[str, list[str] | None] = dict(ucfg.get("array_envelopes") or DEFAULT_ARRAYS)
        self.stream_keys = frozenset(self.arrays)
        self.walk_keys = frozenset(k for k, v in self.arrays.items() if v is None)  # siblings: any
        self.eb = ucfg.get("eventbridge") or {}
        self.strjson = list(ucfg.get("string_json") or [])
        self.b64 = list(ucfg.get("base64") or [])
        self.cwl_skip = set((ucfg.get("cloudwatch") or {}).get("skip_message_types") or [])
        self.skip_docs = {k: list(v) for k, v in (ucfg.get("skip_documents") or DEFAULT_SKIP).items()}
        self.bucket_fields = list(ucfg.get("bucket_fields") or [])
        self.max_buckets = int(ucfg.get("max_buckets", 64))
        self.max_depth = int(ucfg.get("max_depth", 6))
        self.chunk = int(ucfg.get("chunk_chars", 1 << 20))
        self.inline_max = int(ucfg.get("inline_max_chars", 16 << 20))
        self.max_record = int(ucfg.get("max_record_chars", 64 << 20))
        self._buckets: set[str] = set()
        # an object without any of these keys is a plain record (one C-level set test per record)
        self.trigger = frozenset(self.arrays) | {"logEvents", "detail"} | {r["field"] for r in self.strjson} |             {r["outer"] for r in self.b64} | {k for keys in self.skip_docs.values() for k in keys[:1]}

    # ---- classification (a cheap look at the first lines) ------------------------------------------------------
    def envelope_name(self, obj: Any) -> str | None:
        """Name of the envelope rule an object matches (None: a plain record)."""
        if not isinstance(obj, dict):
            return "json_array" if isinstance(obj, list) else None
        if self.trigger.isdisjoint(obj):
            return None
        for name, keys in self.skip_docs.items():
            if all(k in obj for k in keys):
                return name
        if isinstance(obj.get("logEvents"), list) and "messageType" in obj:
            return "cloudwatch_logs"
        for k, allowed in self.arrays.items():
            if isinstance(obj.get(k), list) and _siblings_ok(obj, k, allowed):
                return k
        if isinstance(obj.get("detail"), dict) and "detail-type" in obj:
            return "eventbridge"
        for r in self.strjson:
            if isinstance(obj.get(r["field"]), str) and (not r.get("require_any") or
                                                         any(k in obj for k in r["require_any"])):
                return f"string_json:{r['field']}"
        for r in self.b64:
            inner = obj.get(r["outer"])
            if isinstance(inner, dict) and isinstance(inner.get(r["field"]), str) and (
                    not r.get("require_any") or any(k in inner or k in obj for k in r["require_any"])):
                return f"base64:{r['outer']}.{r['field']}"
        return None

    def _bucket(self, parent: str, rec: dict[str, Any]) -> str:
        for f in self.bucket_fields:
            v = rec.get(f)
            if isinstance(v, str) and v:
                b = f"{parent}_{slug(v)}" if parent else slug(v)
                if b in self._buckets or len(self._buckets) < self.max_buckets:
                    self._buckets.add(b)
                    return b
                return f"{parent}_other" if parent else "other"
        return parent or "records"

    # ---- complete values ---------------------------------------------------------------------------------------
    def values(self, v: Any, acct: Acct, bucket: str, depth: int,
               raw: str | None = None) -> Iterator[tuple[str, Any]]:
        if depth > self.max_depth:
            acct.failed["nesting_too_deep"] += 1
            return
        if isinstance(v, list):
            acct.envelopes["json_array"] += 1
            if not v:
                acct.notes["empty_envelopes"] += 1
            for el in v:
                yield from self.values(el, acct, bucket, depth + 1)
            return
        if isinstance(v, str):
            acct.text_out += 1
            yield bucket or "text", v
            return
        if not isinstance(v, dict):
            acct.failed["non_object_value"] += 1
            return
        name = self.envelope_name(v)
        if name is None:
            acct.records_out += 1
            ok = raw is not None and "\n" not in raw and "\r" not in raw
            yield self._bucket(bucket, v), RawJson(raw) if ok else v
            return
        if name in self.skip_docs:
            acct.skipped[name] += 1
            return
        acct.envelopes[name] += 1
        if name == "cloudwatch_logs":
            yield from self._cloudwatch(v, acct, depth)
        elif name in self.arrays:
            if not v[name]:
                acct.notes["empty_envelopes"] += 1
            for el in v[name]:
                yield from self.values(el, acct, bucket, depth + 1)
        elif name == "eventbridge":
            yield from self._eventbridge(v, acct, depth)
        elif name.startswith("string_json:"):
            r = next(r for r in self.strjson if name == f"string_json:{r['field']}")
            try:
                doc = json.loads(v[r["field"]])
            except ValueError:
                acct.failed["malformed_json_string"] += 1
                return
            yield from self.values(doc, acct, r.get("bucket") or bucket, depth + 1)
        else:
            r = next(r for r in self.b64 if name == f"base64:{r['outer']}.{r['field']}")
            s = v[r["outer"]][r["field"]]
            if len(s) > self.max_record:
                acct.failed["record_too_large"] += 1
                return
            try:
                data = base64.b64decode(s, validate=True)
            except (binascii.Error, ValueError):
                acct.failed["bad_base64"] += 1
                return
            yield from self.blob(data, acct, r.get("bucket") or bucket, depth + 1)

    def _eventbridge(self, v: dict[str, Any], acct: Acct, depth: int) -> Iterator[tuple[str, Any]]:
        if not v["detail"] and self.eb.get("skip_empty_detail", True):
            acct.skipped["eventbridge_empty_detail"] += 1
            return
        dt = str(v.get("detail-type") or "")
        b = next((bk for sub, bk in (self.eb.get("bucket_by_detail_type") or {}).items() if sub in dt), None)
        yield from self.values(v["detail"], acct, b or f"eb_{slug(v.get('source') or dt)}", depth + 1)

    def _cloudwatch(self, v: dict[str, Any], acct: Acct, depth: int) -> Iterator[tuple[str, Any]]:
        evs = v["logEvents"]
        if v.get("messageType") in self.cwl_skip:
            acct.skipped["cloudwatch_control_message"] += 1 + len(evs)
            return
        b = f"cwl_{slug(v.get('logGroup') or 'logs')}"
        for ev in evs:
            msg = ev.get("message") if isinstance(ev, dict) else None
            if not isinstance(msg, str):
                acct.failed["cloudwatch_event_without_message"] += 1
                continue
            if msg.lstrip().startswith("{"):
                try:
                    doc = json.loads(msg)
                except ValueError:
                    doc = None
                if isinstance(doc, dict):
                    yield from self.values(doc, acct, b, depth + 1)
                    continue
            acct.text_out += 1
            yield f"{b}_text", msg

    def blob(self, data: bytes, acct: Acct, bucket: str, depth: int) -> Iterator[tuple[str, Any]]:
        """A decoded payload: gzip (by magic) -> JSON document(s) or text lines."""
        if data[:2] == b"\x1f\x8b":
            try:
                data = _gunzip_bounded(data, self.max_record)
            except (OSError, EOFError, zlib.error) as exc:
                acct.failed["bad_gzip_payload" if "limit" not in str(exc) else "record_too_large"] += 1
                return
        text = data.decode("utf-8", errors="replace")
        if text.lstrip(" \t\r\n\ufeff")[:1] in ("{", "["):
            yield from self.stream(io.StringIO(text), acct, bucket, depth)
            return
        for line in text.splitlines():
            if line.strip():
                acct.text_out += 1
                yield bucket or "text", line

    # ---- streamed documents ------------------------------------------------------------------------------------
    def stream(self, fh: TextIO, acct: Acct, bucket: str, depth: int) -> Iterator[tuple[str, Any]]:
        js = JsonStream(fh, self.chunk, self.inline_max, self.max_record)
        for tv in js.top_values(self.walk_keys):
            if tv.error is not None:
                reason = tv.error.reason if isinstance(tv.error, Malformed) else "record_too_large"
                acct.failed[reason] += 1
                acct.unparsed_chars += tv.skipped
                continue
            if not tv.walk:
                yield from self.values(tv.value, acct, bucket, depth, tv.raw)
                continue
            try:
                yield from self._walk(js, tv.kind, acct, bucket, depth)
            except (Malformed, TooLarge) as e:
                acct.failed[e.reason if isinstance(e, Malformed) else "record_too_large"] += 1
                acct.notes["documents_cut_short"] += 1
                if tv.line_start and js.one_line_since_mark(e.offset if isinstance(e, Malformed) else js.offset):
                    acct.unparsed_chars += js.skip_line()  # JSON Lines: only this line is lost
                    continue
                acct.unparsed_chars += js.drain()  # cannot resync inside a multi-line document: the rest is unparsed
                return

    def _walk(self, js: JsonStream, kind: str, acct: Acct, bucket: str, depth: int) -> Iterator[tuple[str, Any]]:
        acct.notes["streamed_documents"] += 1
        if kind == "[":
            acct.envelopes["json_array"] += 1
            n = 0
            for el in js.iter_array():
                n += 1
                yield from self.values(el, acct, bucket, depth + 1, js.raw_last())
            if not n:
                acct.notes["empty_envelopes"] += 1
            return
        rest: dict[str, Any] = {}
        streamed = None
        for key, val in js.iter_object(self.stream_keys):
            if val is STREAM:
                if streamed is not None or not _siblings_ok(rest, key, self.arrays.get(key)):
                    acct.notes["envelope_unexpected_siblings"] += 1
                streamed = key
                acct.envelopes[key] += 1
                n = 0
                for el in js.iter_array():
                    n += 1
                    yield from self.values(el, acct, bucket, depth + 1, js.raw_last())
                if not n:
                    acct.notes["empty_envelopes"] += 1
            else:
                rest[key] = val
        if streamed is None:
            yield from self.values(rest, acct, bucket, depth)
        elif not _siblings_ok(rest, streamed, self.arrays.get(streamed)):
            acct.notes["envelope_unexpected_siblings"] += 1


def _gunzip_bounded(data: bytes, limit: int) -> bytes:
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
        while True:
            b = g.read(1 << 20)
            if not b:
                return out.getvalue()
            out.write(b)
            if out.tell() > limit:
                raise OSError(f"payload over limit {limit}")
