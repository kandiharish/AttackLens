"""Stage 0 Windows XML event reader (robust item #5): <Event> records -> the nested win_json shape.

Accepts every common XML export of Windows events: one <Event> per line (wevtutil / Splunk XmlWinEventLog),
Event Viewer "Save as XML" (<?xml?><Events><Event>...), pretty-printed, wevtutil concatenated (no root element),
WEF ForwardedEvents with <RenderingInfo>. The text is split on </Event>, so memory is O(chunk + one event) and one bad
event never loses the rest (counted `malformed_xml_event`). Each event is parsed alone with the stdlib expat parser.

Safety (defused behaviour, stdlib only): any <!DOCTYPE or <!ENTITY rejects the whole document (`xml_doctype_rejected`,
no entity is ever expanded); an event bigger than `xml_events.max_event_chars` is counted `xml_event_too_large`.

Output per event (element names from config/unwrap.yaml `xml_events`, namespaces dropped):
  {"Event": {"System": {"Provider": {"Name": ...}, "EventID": 4624, "TimeCreated": {"SystemTime": ...},
             "Channel": ..., "Computer": ..., ...}, "EventData": {<Data Name>: value}, "UserData": {...},
             "RenderingInfo": {"Message": ...}}}
which is what config/sources.yaml win_json reads ($.Event.System.EventID, $.Event.EventData.<Name> ...).
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Iterator, TextIO

from attacklens.cloud_unpack_env import Acct

START = re.compile(r"<(?:[A-Za-z_][\w.-]*:)?Event[\s/>]")
END = re.compile(r"</(?:[A-Za-z_][\w.-]*:)?Event\s*>")
_DTD = re.compile(r"<!(?:DOCTYPE|ENTITY)", re.I)
# text allowed between events: XML declaration, <Events> wrapper, comments, processing instructions, whitespace
_PROLOG = re.compile(r"<\?.*?\?>|<!--.*?-->|</?(?:[A-Za-z_][\w.-]*:)?Events\b[^>]*>|\s+", re.S)
DEFAULTS: dict[str, Any] = {
    "enabled": True, "max_event_chars": 4194304, "chunk_chars": 1048576, "bucket": "win_xml",
    "int_fields": ["EventID", "Version", "Level", "Task", "Opcode", "EventRecordID"],
    "attr_elements": ["Provider", "TimeCreated", "Execution", "Security", "Correlation"],
    "data_unnamed_key": "Data",
}


def xml_cfg(ucfg: dict[str, Any] | None) -> dict[str, Any]:
    return {**DEFAULTS, **((ucfg or {}).get("xml_events") or {})}


def is_xml(lead: str, ucfg: dict[str, Any] | None = None) -> bool:
    """Decoded head (whitespace / BOM stripped) of a Windows XML event file?"""
    if not xml_cfg(ucfg).get("enabled", True) or not lead.startswith("<"):
        return False
    if START.match(lead):
        return True
    return lead.startswith(("<?xml", "<Events", "<!--")) and START.search(lead) is not None


def _local(tag: Any) -> str:
    t = str(tag)
    return t.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _attrs(el: ET.Element) -> dict[str, Any]:
    return {_local(k): v for k, v in el.attrib.items()}


def _generic(el: ET.Element) -> Any:
    """Element -> value: text for a leaf, dict of children (repeated names -> list) otherwise; attributes merged."""
    kids = list(el)
    if not kids:
        text = (el.text or "").strip()
        if el.attrib:
            d = _attrs(el)
            if text:
                d["#text"] = text
            return d
        return text if text else None
    out: dict[str, Any] = _attrs(el)
    for k in kids:
        name, v = _local(k.tag), _generic(k)
        if name in out:
            out[name] = out[name] if isinstance(out[name], list) else [out[name]]
            out[name].append(v)
        else:
            out[name] = v
    return out


def _num(v: str | None) -> Any:
    return int(v) if v is not None and v.isdigit() and len(v) < 19 else v


def convert(root: ET.Element, xcfg: dict[str, Any]) -> dict[str, Any]:
    """One parsed <Event> element -> {"Event": {...}} in the win_json nested shape."""
    ints, attr_el = set(xcfg["int_fields"]), set(xcfg["attr_elements"])
    ev: dict[str, Any] = {}
    for sec in root:
        name = _local(sec.tag)
        if name == "System":
            sysd: dict[str, Any] = {}
            for el in sec:
                n = _local(el.tag)
                text = (el.text or "").strip()
                if n in attr_el or (el.attrib and not text):
                    sysd[n] = _attrs(el)
                else:
                    sysd[n] = _num(text) if n in ints else (text or None)
            ev["System"] = sysd
        elif name == "EventData":
            data: dict[str, Any] = {}
            unnamed: list[Any] = []
            for el in sec:
                n = el.get("Name")
                v = (el.text or "").strip() or None
                if n:
                    data[n] = v
                elif _local(el.tag) == "Data":
                    unnamed.append(v)
                else:
                    data[_local(el.tag)] = _generic(el)
            if unnamed:
                data[str(xcfg["data_unnamed_key"])] = unnamed if len(unnamed) > 1 else unnamed[0]
            ev["EventData"] = data
        else:  # UserData, RenderingInfo, ProcessingErrorData, DebugData ...
            ev[name] = _generic(sec)
    return {"Event": ev}


def event_from_string(s: str, ucfg: dict[str, Any] | None, acct: Acct) -> dict[str, Any] | None:
    """One <Event>...</Event> string (e.g. a Splunk _raw) -> win_json dict, or None (counted in acct.failed)."""
    xcfg = xml_cfg(ucfg)
    if len(s) > int(xcfg["max_event_chars"]):
        acct.failed["xml_event_too_large"] += 1
        return None
    if _DTD.search(s):
        acct.failed["xml_doctype_rejected"] += 1
        return None
    try:
        root = ET.fromstring(s)
    except ET.ParseError:
        acct.failed["malformed_xml_event"] += 1
        return None
    if _local(root.tag) != "Event":
        acct.failed["xml_not_an_event"] += 1
        return None
    return convert(root, xcfg)


def _interstitial(s: str, acct: Acct) -> bool:
    """Text between events: False (reject the document) on a DTD / entity declaration; other junk is counted."""
    if _DTD.search(s):
        acct.failed["xml_doctype_rejected"] += 1
        return False
    rest = _PROLOG.sub("", s)
    if rest:
        acct.notes["xml_interstitial_chars"] += len(rest)
    return True


def split_events(text: TextIO, ucfg: dict[str, Any] | None, acct: Acct) -> Iterator[dict[str, Any]]:
    """Stream the <Event> records of a decoded text stream; counts records_out / failed / notes into acct."""
    xcfg = xml_cfg(ucfg)
    chunk, max_ev = int(xcfg["chunk_chars"]), int(xcfg["max_event_chars"])
    buf, pos, eof = "", 0, False
    while True:
        m = START.search(buf, pos)
        if m is None:
            keep = max(pos, len(buf) - 64)  # a start tag may be cut at the chunk end
            if not _interstitial(buf[pos:keep], acct):
                acct.unparsed_chars += _drain(text, chunk) + len(buf) - pos
                return
            pos = keep
        else:
            if not _interstitial(buf[pos:m.start()], acct):
                acct.unparsed_chars += _drain(text, chunk) + len(buf) - pos
                return
            pos = m.start()
            e = END.search(buf, m.end())
            if e is not None:
                ev = event_from_string(buf[pos:e.end()], xcfg_wrap(xcfg), acct)
                pos = e.end()
                if ev is not None:
                    acct.records_out += 1
                    yield ev
                elif acct.failed.get("xml_doctype_rejected"):
                    acct.unparsed_chars += _drain(text, chunk) + len(buf) - pos
                    return
                continue
            if len(buf) - pos > max_ev:  # no </Event> within the bound: drop this event, resync at the next start
                acct.failed["xml_event_too_large"] += 1
                nxt = START.search(buf, m.end())
                acct.unparsed_chars += (nxt.start() if nxt else len(buf)) - pos
                pos = nxt.start() if nxt else len(buf)
                continue
        if eof:
            tail = buf[pos:]
            if tail.strip() and START.search(tail):
                acct.failed["truncated_xml_event"] += 1
                acct.unparsed_chars += len(tail)
            elif tail and not _interstitial(tail, acct):
                return
            return
        data = text.read(chunk)
        eof = not data
        buf, pos = buf[pos:] + data, 0


def xcfg_wrap(xcfg: dict[str, Any]) -> dict[str, Any]:
    return {"xml_events": xcfg}


def _drain(text: TextIO, chunk: int) -> int:
    n = 0
    while True:
        d = text.read(chunk)
        if not d:
            return n
        n += len(d)
