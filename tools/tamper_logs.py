"""Copy a raw log dataset and apply chosen tamperings (demo + test data for attacklens.integrity).

Usage:
    python tools/tamper_logs.py --src data/raw/g1 --dst data/raw/g1_tampered --seed 7 \
        --delete-window ws-fin-010:2026-10-24T02:00:00Z:2026-10-24T04:00:00Z \
        --inject-clear part-0.jsonl --zero-bytes part-1.jsonl:4096:512

Ops (all repeatable; FILE is a path relative to --src, posix or native separators):
    --zero-bytes FILE:OFFSET:LEN          overwrite LEN bytes at OFFSET with NUL           (zeroed_regions)
    --delete-window HOST:START_ISO:END_ISO drop lines that mention HOST with start <= ts < end (silence_gap)
    --cut-host-after HOST:ISO             drop lines that mention HOST with ts >= ISO         (went_dark)
    --inject-clear FILE[:FORMAT]          append a 1102 "audit log was cleared" record in the file's format
                                          (win_json | ecs_json | syslog | fortigate | cef; auto-detected)  (log_cleared)
    --duplicate FILE:PCT                  re-append PCT % of the file's lines (replay)       (duplicates)
    --edit-time FILE:PCT:SECONDS          shift the FortiGate header date/time (not eventtime) on PCT % of the
                                          file's FortiGate lines                              (embedded_time_mismatch)
    --truncate FILE                       remove the final newline plus the second half of the last line (truncated_tail)

Writes <dst>/ground_truth/tamper_manifest.json (ingest skips `ground_truth/`) listing exactly what was done.
Per file the order is: host deletions + edit-time (one streaming pass) -> inject-clear -> duplicate -> truncate
-> zero-bytes. Line numbers in the manifest are 1-based; `src_line*` refer to the source file, `dst_line*` to the
written file. Byte offsets refer to the written file. Stdlib only; files are streamed line by line, never loaded
whole. Same --seed + same input -> byte-identical output and manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

log = logging.getLogger("tamper_logs")

FORMATS = ("win_json", "ecs_json", "syslog", "fortigate", "cef")
SKIP_HOST_OPS = ("ground_truth", ".meta")  # path components never touched by host-wide ops
MAX_LISTED_LINES = 10_000                   # manifest line-number lists are capped (count stays exact)
COPY_BUF = 1 << 20

# ------------------------------------------------------------------ timestamp detection
_FGT = re.compile(r'(?:^|\s)date="?(\d{4}-\d{2}-\d{2})"?\s+time="?(\d{2}:\d{2}:\d{2})"?')
_FGT_TZ = re.compile(r'(?:^|\s)tz="?([+-]\d{2}:?\d{2})"?')
_FGT_EVENTTIME = re.compile(r'(?:^|\s)eventtime="?(\d{10,19})"?')
_ISO = re.compile(r'(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?')
_SYSLOG = re.compile(r'^(?:<\d+>)?([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) ')
_MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
_SPLIT_ISO = re.compile(r":(?=\d{4}-\d{2}-\d{2}T)")


def _tz_offset(s: str | None) -> timedelta:
    if not s:
        return timedelta(0)
    s = s.replace(":", "")
    if s == "Z":
        return timedelta(0)
    sign = -1 if s[0] == "-" else 1
    return sign * timedelta(hours=int(s[1:3]), minutes=int(s[3:5]))


def parse_iso(s: str) -> datetime:
    """ISO 8601 -> aware UTC datetime; no zone means UTC."""
    m = _ISO.fullmatch(s.strip())
    if not m:
        raise ValueError(f"not an ISO timestamp: {s!r}")
    return _iso_match_dt(m)


def _iso_match_dt(m: re.Match) -> datetime:
    frac = m.group(3) or ""
    us = int((frac[1:] + "000000")[:6]) if frac else 0
    naive = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S").replace(microsecond=us)
    return naive.replace(tzinfo=timezone.utc) - _tz_offset(m.group(4))


def epoch_ms_from_digits(d: str) -> int | None:
    """FortiGate eventtime: 19 digits ns, 16 us, 13 ms, 10 s."""
    n = int(d)
    return {19: n // 1_000_000, 16: n // 1000, 13: n, 10: n * 1000}.get(len(d))


def line_ts(text: str, syslog_year: int) -> datetime | None:
    """First timestamp found: FortiGate eventtime / date= time= (+tz), then ISO, then syslog. None if absent."""
    m = _FGT.search(text)
    if m:
        et = _FGT_EVENTTIME.search(text)
        if et:
            ms = epoch_ms_from_digits(et.group(1))
            if ms is not None:
                return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        tz = _FGT_TZ.search(text)
        naive = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return naive - _tz_offset(tz.group(1) if tz else None)
    m = _ISO.search(text)
    if m:
        try:
            return _iso_match_dt(m)
        except ValueError:
            pass
    m = _SYSLOG.match(text)
    if m and m.group(1) in _MONTHS:
        try:
            return datetime(syslog_year, _MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)),
                            int(m.group(5)), tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def host_regex(host: str) -> re.Pattern:
    return re.compile(r"(?<![\w.-])" + re.escape(host) + r"(?![\w-])", re.IGNORECASE)


def detect_format(first_line: str) -> str:
    s = first_line.lstrip("﻿").strip()
    if s.startswith("{"):
        if '"TimeCreated"' in s or '"EventID"' in s or '"Computer"' in s:
            return "win_json"
        return "ecs_json"
    if _FGT.search(s) or s.startswith("date="):
        return "fortigate"
    if "CEF:" in s[:200]:
        return "cef"
    return "syslog"


# ------------------------------------------------------------------ op parsing
def _pct(s: str) -> float:
    v = float(s)
    if not 0 <= v <= 100:
        raise ValueError(f"PCT must be 0..100, got {s}")
    return v


def parse_ops(ns: argparse.Namespace) -> list[dict[str, Any]]:
    ops: list[dict[str, Any]] = []
    for a in ns.zero_bytes or []:
        f, off, ln = a.rsplit(":", 2)
        ops.append({"op": "zero_bytes", "file": _rel(f), "offset": int(off), "length": int(ln)})
    for a in ns.delete_window or []:
        host, _, rest = a.partition(":")
        parts = _SPLIT_ISO.split(rest)
        if not host or len(parts) != 2:
            raise ValueError(f"--delete-window expects HOST:START_ISO:END_ISO, got {a!r}")
        start, end = parse_iso(parts[0]), parse_iso(parts[1])
        if end <= start:
            raise ValueError(f"--delete-window end must be after start: {a!r}")
        ops.append({"op": "delete_window", "host": host.lower(), "start": start, "end": end})
    for a in ns.cut_host_after or []:
        host, _, iso = a.partition(":")
        if not host or not iso:
            raise ValueError(f"--cut-host-after expects HOST:ISO, got {a!r}")
        ops.append({"op": "cut_host_after", "host": host.lower(), "start": parse_iso(iso), "end": None})
    for a in ns.inject_clear or []:
        f, fmt = a, None
        head, _, tail = a.rpartition(":")
        if head and tail in FORMATS:
            f, fmt = head, tail
        ops.append({"op": "inject_clear", "file": _rel(f), "format": fmt})
    for a in ns.duplicate or []:
        f, p = a.rsplit(":", 1)
        ops.append({"op": "duplicate", "file": _rel(f), "pct": _pct(p)})
    for a in ns.edit_time or []:
        f, p, sec = a.rsplit(":", 2)
        ops.append({"op": "edit_time", "file": _rel(f), "pct": _pct(p), "seconds": int(sec)})
    for a in ns.truncate or []:
        ops.append({"op": "truncate", "file": _rel(a)})
    return ops


def _rel(f: str) -> str:
    p = Path(f.replace("\\", "/")).as_posix().lstrip("/")
    if p.startswith("../") or "/../" in p or p == "..":
        raise ValueError(f"FILE must stay inside --src: {f!r}")
    return p


# ------------------------------------------------------------------ helpers
def _iter_files(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            yield Path(dirpath) / name


def _host_ops_apply(rel: str) -> bool:
    return not any(part in SKIP_HOST_OPS for part in rel.split("/")) and rel != "manifest.json"


def _rng(seed: int, op: str, rel: str) -> random.Random:
    return random.Random(f"{seed}:{op}:{rel}")


def _select_exact(rng: random.Random, n: int, k: int) -> Iterator[bool]:
    """Knuth algorithm S: yields n booleans with exactly k True, uniformly, O(1) memory."""
    need = k
    for i in range(n):
        take = need > 0 and rng.random() * (n - i) < need
        if take:
            need -= 1
        yield take


def _pre_scan(path: Path, syslog_year: int) -> dict[str, Any]:
    """One streaming pass: line count, FortiGate line count, first non-empty line, last line's timestamp/text."""
    n = fgt = 0
    first = last = ""
    last_ts: datetime | None = None
    with path.open("rb") as fh:
        for raw in fh:
            n += 1
            text = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not text.strip():
                continue
            if not first:
                first = text
            if _FGT.search(text):
                fgt += 1
            ts = line_ts(text, syslog_year)
            if ts is not None:
                last_ts, last = ts, text
    return {"lines": n, "fgt_lines": fgt, "first": first, "last": last, "last_ts": last_ts}


def _shift_fgt_header(text: str, seconds: int) -> str:
    m = _FGT.search(text)
    if not m:
        return text
    t = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S") + timedelta(seconds=seconds)
    return (text[:m.start(1)] + t.strftime("%Y-%m-%d") + text[m.end(1):m.start(2)] + t.strftime("%H:%M:%S")
            + text[m.end(2):])


def _iso_ms(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _kv(text: str, key: str) -> str | None:
    m = re.search(r'(?:^|\s)' + re.escape(key) + r'=("([^"]*)"|[^\s"]+)', text)
    if not m:
        return None
    return m.group(2) if m.group(2) is not None else m.group(1)


def _host_of(text: str, fmt: str) -> str:
    try:
        if fmt == "ecs_json":
            h = (json.loads(text).get("host") or {}).get("name")
            return str(h) if h else "unknown-host"
        if fmt == "win_json":
            return str(json.loads(text).get("Computer") or "unknown-host")
    except (ValueError, AttributeError):
        return "unknown-host"
    if fmt == "fortigate":
        return _kv(text, "devname") or "unknown-fgt"
    if fmt == "cef":
        return _kv(text, "dhost") or _kv(text, "dvchost") or "unknown-host"
    m = _SYSLOG.match(text)
    if m:
        rest = text[m.end():].split(" ", 1)
        return rest[0] if rest and rest[0] else "unknown-host"
    return "unknown-host"


def clear_record(fmt: str, scan: dict[str, Any]) -> tuple[str, datetime, str]:
    """A 1102 'audit log was cleared' record in the file's own format, 1 s after its last timestamp."""
    ref = scan["last"] or scan["first"]
    host = _host_of(ref, fmt) if ref else "unknown-host"
    base = scan["last_ts"] or datetime(2026, 1, 1, tzinfo=timezone.utc)
    ts = base + timedelta(seconds=1)
    if fmt == "ecs_json":
        rec = {"@timestamp": _iso_ms(ts),
               "event": {"action": "audit-log-cleared", "code": "1102", "outcome": "success"},
               "host": {"name": host}, "user": {"name": "administrator"},
               "winlog": {"event_id": 1102, "channel": "Security",
                          "provider_name": "Microsoft-Windows-Eventlog"},
               "message": "The audit log was cleared."}
        line = json.dumps(rec, separators=(",", ":"))
    elif fmt == "win_json":
        rec = {"TimeCreated": _iso_ms(ts), "EventID": 1102, "Computer": host, "Channel": "Security",
               "ProviderName": "Microsoft-Windows-Eventlog", "SubjectUserName": "administrator",
               "Message": "The audit log was cleared."}
        line = json.dumps(rec, separators=(",", ":"))
    elif fmt == "fortigate":
        line = _fgt_clear(ref, host, ts)
    elif fmt == "cef":
        line = (f"CEF:0|Microsoft|Microsoft Windows|10|1102|The audit log was cleared|10|"
                f"rt={int(ts.timestamp() * 1000)} dhost={host} suser=administrator cs1Label=Channel cs1=Security")
    else:
        stamp = f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"
        line = (f"{stamp} {host} sudo:    admin : TTY=pts/0 ; PWD=/root ; USER=root ; "
                f"COMMAND=/usr/bin/wevtutil cl Security")
    return line, ts, host


def _fgt_clear(ref: str, host: str, ts: datetime) -> str:
    """Copies the reference line's header conventions: header date/time and eventtime both advance 1 s."""
    m = _FGT.search(ref) if ref else None
    if m:
        hdr = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S") + timedelta(seconds=1)
    else:
        hdr = ts.replace(tzinfo=None)
    et_raw = _FGT_EVENTTIME.search(ref).group(1) if ref and _FGT_EVENTTIME.search(ref) else None
    if et_raw:
        step = {19: 10**9, 16: 10**6, 13: 1000, 10: 1}.get(len(et_raw), 0)
        et = str(int(et_raw) + step)
    else:
        et = str(int(ts.timestamp()) * 10**9)
    tz = _kv(ref, "tz") if ref else None
    devid = (_kv(ref, "devid") if ref else None) or "FGT00000000000000"
    tz_part = f' tz="{tz}"' if tz else ""
    return (f'date={hdr.strftime("%Y-%m-%d")} time={hdr.strftime("%H:%M:%S")} devname="{host}" devid="{devid}" '
            f'eventtime={et}{tz_part} logid="0100032138" type="event" subtype="system" level="alert" vd="root" '
            f'logdesc="Log cleared" user="admin" ui="cli" action="delete" '
            f'msg="The audit log was cleared (event 1102): all logs deleted by admin"')


# ------------------------------------------------------------------ per-file processing
def _line_pass(src: Path, dst: Path, rel: str, host_ops: list[dict], edit: dict | None, seed: int,
               scan: dict[str, Any], syslog_year: int) -> tuple[list[dict], int]:
    """Stream src -> dst applying host deletions and edit-time. Returns manifest entries and lines written."""
    hosts = [(op, host_regex(op["host"])) for op in host_ops]
    deleted = {id(op): {"count": 0, "first": None, "last": None, "lines": []} for op in host_ops}
    edits: dict[str, Any] = {"count": 0, "lines": []}
    sel = None
    if edit is not None:
        k = round(scan["fgt_lines"] * edit["pct"] / 100)
        sel = _select_exact(_rng(seed, "edit_time", rel), scan["fgt_lines"], k)
    written = 0
    with src.open("rb") as fi, dst.open("wb", buffering=COPY_BUF) as fo:
        for no, raw in enumerate(fi, start=1):
            text = None
            if hosts:
                text = raw.decode("utf-8", "replace")
                drop = None
                for op, rx in hosts:
                    if rx.search(text):
                        ts = line_ts(text.rstrip("\r\n"), syslog_year)
                        if ts is not None and ts >= op["start"] and (op["end"] is None or ts < op["end"]):
                            drop = op
                            break
                if drop is not None:
                    d = deleted[id(drop)]
                    d["count"] += 1
                    d["first"] = d["first"] or no
                    d["last"] = no
                    if len(d["lines"]) < MAX_LISTED_LINES:
                        d["lines"].append(no)
                    if sel is not None and _FGT.search(text):
                        next(sel)  # keep the edit selection aligned with the source's FortiGate lines
                    continue
            if sel is not None:
                text = text if text is not None else raw.decode("utf-8", "replace")
                if _FGT.search(text) and next(sel):
                    body = text.rstrip("\r\n")
                    end = text[len(body):]
                    raw = (_shift_fgt_header(body, edit["seconds"]) + end).encode("utf-8")
                    edits["count"] += 1
                    if len(edits["lines"]) < MAX_LISTED_LINES:
                        edits["lines"].append(written + 1)
            fo.write(raw)
            written += 1
    entries = []
    for op in host_ops:
        d = deleted[id(op)]
        if d["count"]:
            entries.append({"op": op["op"], "file": rel, "host": op["host"],
                            "start": _iso_ms(op["start"]), "end": _iso_ms(op["end"]) if op["end"] else None,
                            "start_ts_ms": int(op["start"].timestamp() * 1000),
                            "end_ts_ms": int(op["end"].timestamp() * 1000) if op["end"] else None,
                            "lines_deleted": d["count"], "src_line_range": [d["first"], d["last"]],
                            "src_lines": d["lines"], "src_lines_truncated": d["count"] > len(d["lines"])})
    if edit is not None:
        entries.append({"op": "edit_time", "file": rel, "pct": edit["pct"], "seconds": edit["seconds"],
                        "fortigate_lines": scan["fgt_lines"], "lines_edited": edits["count"],
                        "dst_lines": edits["lines"], "dst_lines_truncated": edits["count"] > len(edits["lines"])})
    return entries, written


def _ends_with_newline(path: Path) -> bool:
    size = path.stat().st_size
    if size == 0:
        return True
    with path.open("rb") as fh:
        fh.seek(size - 1)
        return fh.read(1) == b"\n"


def _append_line(path: Path, line: str) -> None:
    with path.open("ab") as fo:
        if not _ends_with_newline(path):
            fo.write(b"\n")
        fo.write(line.encode("utf-8") + b"\n")


def _duplicate(path: Path, rel: str, pct: float, seed: int, lines_now: int) -> dict[str, Any]:
    """Re-append exactly round(n * pct / 100) lines, chosen uniformly, in their original order."""
    k = round(lines_now * pct / 100)
    sel = _select_exact(_rng(seed, "duplicate", rel), lines_now, k)
    spool = path.with_name(path.name + ".tamper-dup")
    picked: list[int] = []
    with path.open("rb") as fi, spool.open("wb", buffering=COPY_BUF) as fo:
        for no, raw in enumerate(fi, start=1):
            if next(sel):
                fo.write(raw if raw.endswith(b"\n") else raw + b"\n")
                if len(picked) < MAX_LISTED_LINES:
                    picked.append(no)
    if not _ends_with_newline(path):
        with path.open("ab") as fo:
            fo.write(b"\n")
    with spool.open("rb") as fi, path.open("ab") as fo:
        shutil.copyfileobj(fi, fo, COPY_BUF)
    spool.unlink()
    return {"op": "duplicate", "file": rel, "pct": pct, "lines_before": lines_now, "lines_duplicated": k,
            "dst_line_range": [lines_now + 1, lines_now + k] if k else None,
            "src_lines": picked, "src_lines_truncated": k > len(picked)}


def _truncate(path: Path, rel: str) -> dict[str, Any]:
    """Drop the final newline and the second half of the last line (at least 1 byte of it stays)."""
    size = path.stat().st_size
    if size == 0:
        return {"op": "truncate", "file": rel, "bytes_removed": 0, "new_size": 0, "note": "empty file"}
    with path.open("r+b") as fh:
        tail_len = min(size, 1 << 16)
        fh.seek(size - tail_len)
        tail = fh.read(tail_len)
        body = tail.rstrip(b"\r\n")
        nl = body.rfind(b"\n")
        last = body[nl + 1:]
        keep_in_last = max(1, (len(last) + 1) // 2) if last else 0
        cut_at = size - tail_len + (nl + 1) + keep_in_last
        fh.truncate(cut_at)
    return {"op": "truncate", "file": rel, "bytes_removed": size - cut_at, "new_size": cut_at,
            "offset": cut_at}


def _zero(path: Path, rel: str, offset: int, length: int) -> dict[str, Any]:
    size = path.stat().st_size
    if offset < 0 or length <= 0 or offset >= size:
        raise ValueError(f"--zero-bytes {rel}:{offset}:{length} outside the file (size {size})")
    n = min(length, size - offset)
    with path.open("r+b") as fh:
        fh.seek(offset)
        left = n
        while left:
            chunk = min(left, COPY_BUF)
            fh.write(b"\x00" * chunk)
            left -= chunk
    return {"op": "zero_bytes", "file": rel, "offset": offset, "length": n, "requested_length": length}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(COPY_BUF), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ driver
def tamper(src: Path, dst: Path, ops: list[dict[str, Any]], seed: int = 0, force: bool = False,
           syslog_year: int | None = None) -> dict[str, Any]:
    src, dst = Path(src).resolve(), Path(dst).resolve()
    if not src.is_dir():
        raise FileNotFoundError(f"--src is not a directory: {src}")
    if dst == src or src in dst.parents:
        raise ValueError("--dst must not be --src or inside it")
    if dst.exists() and any(dst.iterdir()):
        if not force:
            raise FileExistsError(f"--dst is not empty (use --force): {dst}")
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)

    host_ops = [o for o in ops if o["op"] in ("delete_window", "cut_host_after")]
    if syslog_year is None:
        syslog_year = host_ops[0]["start"].year if host_ops else datetime.now(timezone.utc).year
    by_file: dict[str, list[dict]] = {}
    for o in ops:
        if "file" in o:
            by_file.setdefault(o["file"], []).append(o)
    files = {p.relative_to(src).as_posix(): p for p in _iter_files(src)}
    missing = sorted(set(by_file) - set(files))
    if missing:
        raise FileNotFoundError(f"op targets not under --src: {missing}")

    entries: list[dict[str, Any]] = []
    matched_hosts: set[int] = set()
    for rel, sp in files.items():
        dp = dst / rel
        dp.parent.mkdir(parents=True, exist_ok=True)
        fops = by_file.get(rel, [])
        hops = host_ops if _host_ops_apply(rel) else []
        edit = next((o for o in fops if o["op"] == "edit_time"), None)
        if not fops and not hops:
            shutil.copyfile(sp, dp)
            continue
        scan = _pre_scan(sp, syslog_year)
        if hops or edit:
            got, lines_now = _line_pass(sp, dp, rel, hops, edit, seed, scan, syslog_year)
            entries += got
            matched_hosts |= {id(o) for o in hops if any(e["op"] == o["op"] and e["host"] == o["host"]
                                                         for e in got)}
        else:
            shutil.copyfile(sp, dp)
            lines_now = scan["lines"]
        for o in fops:
            if o["op"] == "inject_clear":
                fmt = o["format"] or detect_format(scan["first"])
                line, ts, host = clear_record(fmt, scan)
                _append_line(dp, line)
                lines_now += 1
                entries.append({"op": "inject_clear", "file": rel, "format": fmt, "host": host.lower(),
                                "ts_ms": int(ts.timestamp() * 1000), "event_id": 1102, "dst_line": lines_now,
                                "line": line})
        for o in fops:
            if o["op"] == "duplicate":
                e = _duplicate(dp, rel, o["pct"], seed, lines_now)
                lines_now += e["lines_duplicated"]
                entries.append(e)
        for o in fops:
            if o["op"] == "truncate":
                entries.append(_truncate(dp, rel))
        for o in fops:
            if o["op"] == "zero_bytes":
                entries.append(_zero(dp, rel, o["offset"], o["length"]))
    for o in host_ops:
        if id(o) not in matched_hosts:
            log.warning("%s %s matched no lines", o["op"], o["host"])
            entries.append({"op": o["op"], "file": None, "host": o["host"], "start": _iso_ms(o["start"]),
                            "end": _iso_ms(o["end"]) if o["end"] else None, "lines_deleted": 0})

    manifest = {"schema_version": 1, "tool": "tools/tamper_logs.py", "src": src.as_posix(), "seed": seed,
                "ops_requested": [_jsonable(o) for o in ops], "ops": entries,
                "files_out": {rel: {"size": (dst / rel).stat().st_size, "sha256": _sha256(dst / rel)}
                              for rel in sorted(files)}}
    gt = dst / "ground_truth"
    gt.mkdir(parents=True, exist_ok=True)
    (gt / "tamper_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _jsonable(o: dict[str, Any]) -> dict[str, Any]:
    return {k: (_iso_ms(v) if isinstance(v, datetime) else v) for k, v in o.items()}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--src", required=True, type=Path)
    p.add_argument("--dst", required=True, type=Path)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--force", action="store_true", help="delete a non-empty --dst first")
    p.add_argument("--syslog-year", type=int, default=None, help="year for syslog lines (default: window year)")
    p.add_argument("--zero-bytes", action="append", metavar="FILE:OFFSET:LEN")
    p.add_argument("--delete-window", action="append", metavar="HOST:START_ISO:END_ISO")
    p.add_argument("--cut-host-after", action="append", metavar="HOST:ISO")
    p.add_argument("--inject-clear", action="append", metavar="FILE[:FORMAT]")
    p.add_argument("--duplicate", action="append", metavar="FILE:PCT")
    p.add_argument("--edit-time", action="append", metavar="FILE:PCT:SECONDS")
    p.add_argument("--truncate", action="append", metavar="FILE")
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ns = build_parser().parse_args(argv)
    try:
        ops = parse_ops(ns)
        if not ops:
            log.error("no tamper ops given (see --help)")
            return 2
        m = tamper(ns.src, ns.dst, ops, seed=ns.seed, force=ns.force, syslog_year=ns.syslog_year)
    except (ValueError, FileNotFoundError, FileExistsError) as exc:
        log.error("%s", exc)
        return 2
    log.info("tampered %s -> %s: %d op entries, manifest %s", ns.src, ns.dst, len(m["ops"]),
             Path(ns.dst) / "ground_truth" / "tamper_manifest.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
