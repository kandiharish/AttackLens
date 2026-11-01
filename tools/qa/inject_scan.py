"""QA injection, part 1: the background scan and the product's FortiGate timestamp convention (track qa_injection).

`scan()` is one bounded DuckDB pass (memory_limit 1GB, threads 2, TimeZone UTC, temp under data/tmp/, optional
row cap) that returns aggregates only - header key order and quoting, eventtime digits, eventtime local-vs-UTC class,
tz values, an hourly histogram of the timestamp AttackLens computes, and collision counts for probe strings. It never
returns or prints a line. `product_ts()` mirrors attacklens/ingest_sql.kv_select (tests check it against the SQL).
"""
from __future__ import annotations

import calendar
import re
import time
from pathlib import Path
from typing import Any

import duckdb

from attacklens.db import line_reader
from attacklens.ingest_sql import KV_VALUE

MIN, HOUR, DAY = 60_000, 3_600_000, 86_400_000
GEN_HEAD = ("date", "time", "devname", "devid", "eventtime", "tz", "logid", "type", "subtype", "level", "vd")
VALID_LO, VALID_HI = 946_684_800_000, 4_102_444_800_000   # 2000-01-01 .. 2100-01-01 UTC
NS_DIGITS = {19: 1_000_000, 16: 1_000, 13: 1, 10: None}   # eventtime digits -> per-ms divisor (10 = seconds)
HEAD_ROWS = 20_000
NET_MASKS = 8                       # 512 bits: 10.0-255 -> 0-255, 192.168 -> 256, 172.16-31 -> 272-287 (256 + x)
NET_SLOTS = 288                     # /16 slots used by the /24 probe (index * len(thirds) + third position)
PRIV_RX = "'^(?:10[.](?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])|172[.](?:1[6-9]|2[0-9]|3[01])|192[.]168)[.]'"
NET_IDX = ("CASE WHEN starts_with(x, '10.') THEN CAST(split_part(x, '.', 2) AS INTEGER) "
           "WHEN starts_with(x, '192.168.') THEN 256 ELSE 256 + CAST(split_part(x, '.', 2) AS INTEGER) END")


# ---------------------------------------------------------------- product timestamp convention (Python mirror)
def tz_offset_ms(tz: str | None) -> int | None:
    z = (tz or "").replace(":", "")
    if not re.fullmatch(r"[+-]\d{4}", z):
        return None
    return (-1 if z[0] == "-" else 1) * (int(z[1:3]) * HOUR + int(z[3:5]) * MIN)


def eventtime_ms(et: str | None) -> int | None:
    if not et or not et.isdigit() or len(et) not in NS_DIGITS:
        return None
    f = NS_DIGITS[len(et)]
    return int(et) * 1000 if f is None else int(et) // f


def naive_ms(d: str | None, t: str | None) -> int | None:
    try:
        return calendar.timegm(time.strptime(f"{d} {t}", "%Y-%m-%d %H:%M:%S")) * 1000
    except (TypeError, ValueError, OverflowError):
        return None


def product_ts(d: str | None, t: str | None, et: str | None, tz: str | None, et_local: bool) -> int | None:
    e, n, off = eventtime_ms(et), naive_ms(d, t), tz_offset_ms(tz)
    tzm = n - off if n is not None and off is not None else None
    if et_local and e is not None and tzm is not None and abs(e - n) < 1000:
        return tzm + (e - n)
    return next((x for x in (e, tzm, n) if x is not None), None)


def kv(line: str, key: str) -> str | None:
    m = re.search(r'(?:^| )' + re.escape(key) + r'=("(?:[^"\\]|\\.)*"|[^ "][^ ]*|)', line)
    return m.group(1).strip('"') if m else None


def line_ts(line: str, et_local: bool) -> int | None:
    return product_ts(kv(line, "date"), kv(line, "time"), kv(line, "eventtime"), kv(line, "tz"), et_local)


# ---------------------------------------------------------------- bounded scan
def connect(tmp: Path) -> duckdb.DuckDBPyConnection:
    tmp.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    con.execute(f"SET memory_limit='1GB'; SET threads=2; SET TimeZone='UTC'; "
                f"SET temp_directory='{tmp.as_posix()}'; SET preserve_insertion_order=false")
    return con


def _rx(k: str) -> str:
    return "'(?:^| )" + k + "=(" + KV_VALUE.replace("'", "''") + ")'"


def _lit(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


IP_TOKEN = "'(?:^|[ =(\"])([0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(?:$|[ )\"])'"


def _probe_cols(probes: dict[str, Any]) -> tuple[str, str, list[str]]:
    """Collision probes, cheap per line: one IP-token regex + one user regex, then list/equality tests.
    probes = {"ips": [...], "users": [...], "private_nets": True, "private_24": [thirds], "substr": {name: [subs]}}
    private_nets: occupancy bitmask of every 10.x/16, 192.168/16 and 172.16-31.x/16 seen (8 x 64-bit bit_or).
    private_24: occupancy bitmask of the /24s <private /16>.<t> for t in thirds (only lines that have one)."""
    names, aggs = [], []
    for ip in probes.get("ips", []):
        names.append(f"ip:{ip}")
        aggs.append(f"count(*) FILTER (WHERE list_contains(ips, {_lit(ip)}))")
    for u in probes.get("users", []):
        names.append(f"user:{u}")
        aggs.append(f"count(*) FILTER (WHERE usr = {_lit(u)})")
    if probes.get("private_nets"):
        for k in range(NET_MASKS):
            names.append(f"_mask{k}")
            aggs.append(f"bit_or(CAST(list_sum(list_transform(list_filter(nets, lambda n: n // 64 = {k}), "
                        f"lambda n: (1::UBIGINT << (n % 64)))) AS UBIGINT))")
    nt = len(probes.get("private_24") or [])
    for k in range(-(-NET_SLOTS * nt // 64)):
        names.append(f"_n24_{k}")
        aggs.append(f"coalesce(bit_or(CAST(list_sum(list_transform(list_filter(nets24, lambda n: n // 64 = {k}), "
                    f"lambda n: (1::UBIGINT << (n % 64)))) AS UBIGINT)) FILTER (WHERE len(nets24) > 0), 0::UBIGINT)")
    for n, subs in (probes.get("substr") or {}).items():
        names.append(n)
        aggs.append("count(*) FILTER (WHERE " + " OR ".join(f"contains(line, {_lit(x)})" for x in subs) + ")")
    cols = (f"regexp_extract_all(line, {IP_TOKEN}, 1) AS ips, "
            "lower(trim(regexp_extract(line, '(?:^| )user=(\"[^\"]*\"|[^ ]*)', 1), '\"')) AS usr")
    return cols, "".join(", " + a for a in aggs), names


def net_prefix(n: int) -> str:
    return f"10.{n}" if n < 256 else "192.168" if n == 256 else f"172.{n - 256}"


def _or_bits(masks: list[list[int]], width: int) -> list[int]:
    bits = [0] * width
    for m in masks:
        for k, v in enumerate(m):
            bits[k] |= v
    return [k * 64 + b for k in range(width) for b in range(64) if bits[k] >> b & 1]


def _decode_nets(masks: list[list[int]]) -> list[str]:
    """OR of the per-row-group masks -> sorted '10.x' / '192.168' / '172.x' prefixes seen."""
    return sorted(net_prefix(n) for n in _or_bits(masks, NET_MASKS))


def _decode_24(masks: list[list[int]], thirds: list[int]) -> list[str]:
    """OR of the /24 masks -> sorted '<prefix>.<third>' /24s seen (only the probed thirds)."""
    if not thirds:
        return []
    return sorted(f"{net_prefix(c // len(thirds))}.{thirds[c % len(thirds)]}"
                  for c in _or_bits(masks, -(-NET_SLOTS * len(thirds) // 64)))


def _line_ending(p: Path) -> str:
    with open(p, "rb") as f:
        b = f.read(1 << 20)
    return "crlf" if b.count(b"\r\n") * 2 > b.count(b"\n") else "lf"


def scan(log_path: Path, kcfg: dict[str, Any], tmp: Path, max_rows: int | None = None,
         probes: dict[str, Any] | None = None) -> dict[str, Any]:
    t0 = time.perf_counter()
    pcols, paggs, pnames = _probe_cols(probes or {})
    reader = (f"(SELECT line FROM {line_reader([str(log_path)], filename=False)} WHERE line IS NOT NULL"
              + (f" LIMIT {int(max_rows)})" if max_rows else ")"))
    tc = kcfg.get("ts") or {}
    et_local = bool(tc.get("eventtime_is_local", False))
    ex = {n: f"trim(regexp_extract(line, {_rx(tc.get(k, d))}, 1), '\"')"
          for n, k, d in (("d", "date_key", "date"), ("t", "time_key", "time"), ("tz", "tz_key", "tz"),
                          ("et", "epoch_key", "eventtime"))}
    lrx = _lit(kcfg.get("line_regex") or "=")
    thirds = [int(t) for t in ((probes or {}).get("private_24") or [])]
    t24 = "[" + ", ".join(str(t) for t in thirds) + "]::INTEGER[]" if thirds else "[]::INTEGER[]"
    con = connect(tmp)
    try:
        head = con.execute(
            "SELECT list_slice(regexp_extract_all(line, '(?:^| )([a-z_0-9-]+)=', 1), 1, 11) AS ks, "
            + ", ".join(f"avg(CASE WHEN regexp_matches(line, '(?:^| ){k}=\"') THEN 1 ELSE 0 END)" for k in GEN_HEAD)
            + ", avg(CASE WHEN regexp_matches(line, '(?:^| )devname=\"?[^\" ]*[a-z]') THEN 1 ELSE 0 END) "
            f"FROM (SELECT line FROM {reader} LIMIT {HEAD_ROWS}) GROUP BY ks ORDER BY count(*) DESC LIMIT 1").fetchone()
        sql = f"""
        WITH k0 AS (SELECT line, regexp_matches(line, {lrx}) AS ok, {pcols},
                           {', '.join(f'{v} AS {n}' for n, v in ex.items())} FROM {reader}),
        kp AS (SELECT *, list_filter(ips, lambda x: regexp_matches(x, {PRIV_RX})) AS pips FROM k0),
        k AS (SELECT *, list_distinct(list_transform(pips, lambda x: {NET_IDX})) AS nets,
                     list_distinct(list_filter(list_transform(pips, lambda x: CASE WHEN list_contains({t24},
                        TRY_CAST(split_part(x, '.', 3) AS INTEGER)) THEN ({NET_IDX}) * {max(len(thirds), 1)}
                        + list_position({t24}, TRY_CAST(split_part(x, '.', 3) AS INTEGER)) - 1 END),
                        lambda n: n IS NOT NULL)) AS nets24 FROM kp),
        c AS (SELECT ok, line, ips, usr, nets, nets24, tz, length(et) AS etlen,
                     epoch_ms(try_cast(d || ' ' || t AS TIMESTAMP)) AS nv,
                     CASE WHEN regexp_full_match(et, '\\d+') THEN CASE length(et)
                       WHEN 19 THEN CAST(CAST(et AS HUGEINT) // 1000000 AS BIGINT) WHEN 16 THEN CAST(et AS BIGINT) // 1000
                       WHEN 13 THEN CAST(et AS BIGINT) WHEN 10 THEN CAST(et AS BIGINT) * 1000 END END AS em,
                     CASE WHEN regexp_full_match(replace(tz, ':', ''), '[+-]\\d{{4}}') THEN
                       (CASE WHEN starts_with(tz, '-') THEN -1 ELSE 1 END) * (CAST(substr(replace(tz, ':', ''), 2, 2)
                       AS BIGINT) * 3600000 + CAST(substr(replace(tz, ':', ''), 4, 2) AS BIGINT) * 60000) END AS off
              FROM k),
        v AS (SELECT *, CASE WHEN em IS NULL THEN 'none' WHEN nv IS NULL THEN 'no_date'
                             WHEN abs(em - nv) < 1000 THEN 'local'
                             WHEN off IS NOT NULL AND abs(em - (nv - off)) < 1000 THEN 'utc' ELSE 'other' END AS conv,
                     CASE WHEN NOT ok THEN NULL WHEN {str(et_local).lower()} AND em IS NOT NULL AND off IS NOT NULL
                          AND abs(em - nv) < 1000 THEN nv - off + (em - nv) ELSE coalesce(em, nv - off, nv) END AS ts
              FROM c),
        w AS (SELECT *, CASE WHEN ts BETWEEN {VALID_LO} AND {VALID_HI} THEN ts END AS vts FROM v)
        SELECT GROUPING(hr) AS g_hr, hr, etlen, conv, tz, count(*), count(*) FILTER (WHERE ok), count(vts),
               min(vts), max(vts), approx_count_distinct(vts // 1000) {paggs}
        FROM (SELECT *, vts // 3600000 AS hr FROM w) GROUP BY GROUPING SETS ((hr), (etlen, conv, tz))"""
        rows = con.execute(sql).fetchall()
    finally:
        con.close()
    ts_rows = [r for r in rows if r[0] == 0 and r[1] is not None]
    styles = [r for r in rows if r[0] == 1]
    agg: dict[str, dict[str, int]] = {"conventions": {}, "eventtime_digits": {}, "tz_values": {}}
    for r in styles:
        for name, val in (("conventions", r[3]), ("eventtime_digits", str(r[2])), ("tz_values", str(r[4] or ""))):
            agg[name][val] = agg[name].get(val, 0) + int(r[5])
    keys = list(head[0]) if head else []
    return {
        "file": log_path.name, "bytes": log_path.stat().st_size, "max_rows": max_rows,
        "rows_read": sum(int(r[5]) for r in styles), "rows_ok": sum(int(r[6]) for r in styles),
        "rows_valid_ts": sum(int(r[7]) for r in styles),
        "ts_min_ms": min((int(r[8]) for r in ts_rows), default=None),
        "ts_max_ms": max((int(r[9]) for r in ts_rows), default=None),
        "distinct_seconds_approx": sum(int(r[10]) for r in ts_rows), "hours_with_rows": len(ts_rows),
        "header_keys": [k for k in keys if k in GEN_HEAD] if keys[:2] == ["date", "time"] else list(GEN_HEAD),
        "header_quoted": {k: bool(head[1 + i] and head[1 + i] >= 0.5) for i, k in enumerate(GEN_HEAD)} if head else {},
        "devname_lowercase": bool(head and head[-1] and head[-1] >= 0.5), "eventtime_is_local_cfg": et_local,
        **agg, "collisions": {n: sum(int(r[11 + i]) for r in styles) for i, n in enumerate(pnames) if n[0] != "_"},
        "private_nets_seen": _decode_nets([[int(r[11 + i] or 0) for i, n in enumerate(pnames)
                                            if n.startswith("_mask")] for r in styles]),
        "private_24_thirds": thirds,
        "private_24_seen": _decode_24([[int(r[11 + i] or 0) for i, n in enumerate(pnames) if n.startswith("_n24_")]
                                       for r in styles], thirds) if thirds else None,
        "line_ending": _line_ending(log_path), "hist_hours": sorted((int(r[1]), int(r[7])) for r in ts_rows),
        "scan_s": round(time.perf_counter() - t0, 2),
    }


def choose_window(hist: list[tuple[int, int]], ts_min: int | None, ts_max: int | None, window_ms: int,
                  span_ms: int) -> dict[str, Any]:
    """Busiest window_ms window (hour bins) whose schedule [w0, w0 + span_ms] lies inside [ts_min, ts_max].
    fits=false: the background spans less than span_ms; the schedule then starts at the first valid minute."""
    if not hist or ts_min is None or ts_max is None:
        raise SystemExit("background has no valid timestamps; nothing to inject into")
    counts = dict(hist)
    nh = window_ms // HOUR
    best: tuple[int, int] | None = None
    for h, _ in hist:
        w0 = max(h * HOUR, -(-ts_min // MIN) * MIN)
        if w0 + span_ms > ts_max:
            continue
        s = sum(counts.get(h + i, 0) for i in range(nh))
        if best is None or s > best[1]:
            best = (w0, s)
    fits = best is not None
    if best is None:
        w0 = ts_min // MIN * MIN
        best = (w0, sum(c for hh, c in hist if w0 // HOUR <= hh < w0 // HOUR + nh))
    return {"w0_ms": best[0], "w1_ms": best[0] + window_ms, "background_rows_in_window": best[1], "fits": fits}
