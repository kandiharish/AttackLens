"""Event-level checks of the integrity engine, all in DuckDB over the `events` view.

Python receives only aggregates (a few rows per host / source type / pattern). No ORDER BY or window function
over raw events: windows run only on the small per-host bucket table (silence_gap / went_dark) and on the
per-(host, offset group) table (embedded_time_mismatch). Never reads generator label fields.
"""

from __future__ import annotations

import logging
import math
from datetime import UTC, datetime
from typing import Any

import duckdb

from attacklens.db import sql_str
from attacklens.integrity_raw import Skip, finding

log = logging.getLogger(__name__)

TEMP_TABLES = ("integ_hb", "integ_el", "integ_gaps", "integ_off")
_EPOCH_MS = ("CASE length(s) WHEN 19 THEN try_cast(s AS BIGINT) // 1000000 WHEN 16 THEN try_cast(s AS BIGINT) // 1000 "
             "WHEN 13 THEN try_cast(s AS BIGINT) WHEN 10 THEN try_cast(s AS BIGINT) * 1000 END")


def columns(con: duckdb.DuckDBPyConnection) -> set[str] | None:
    """Column names of the `events` view, or None when it does not exist / cannot be read."""
    try:
        return {str(r[0]) for r in con.execute("DESCRIBE events").fetchall()}
    except duckdb.Error:
        return None


def source_counts(con: duckdb.DuckDBPyConnection, cols: set[str]) -> dict[str | None, int]:
    st = "source_type" if "source_type" in cols else "NULL"
    return {r[0]: int(r[1]) for r in con.execute(f"SELECT {st}, count(*) FROM events GROUP BY 1").fetchall()}


def drop_temp(con: duckdb.DuckDBPyConnection) -> None:
    for t in TEMP_TABLES:
        try:
            con.execute(f"DROP TABLE IF EXISTS {t}")
        except duckdb.Error:
            pass


def _need(cols: set[str], *names: str) -> None:
    miss = [n for n in names if n not in cols]
    if miss:
        raise Skip(f"missing columns: {', '.join(miss)}")


def _c(cols: set[str], name: str) -> str:
    return name if name in cols else "NULL"


def _iso(ms: int | None) -> str:
    return "?" if ms is None else datetime.fromtimestamp(ms / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- log_cleared ------------------------------------------------------------------------------------------------

def _pattern_sql(low: str, orig: str, spec: dict[str, Any], like_only: bool = False) -> str:
    """`like` patterns (any-of, case-insensitive: LIKE on the pre-lowered text `low`) AND `regex` patterns (all-of,
    RE2 on the original text `orig`, so case-sensitive patterns such as `auditctl -D` keep working).
    like_only: just the cheap like part (prefilter); falls back to the full condition without likes."""
    likes = [f"{low} LIKE {sql_str(str(p).lower())}" for p in spec.get("like") or []]
    like_sql = "(" + " OR ".join(likes) + ")" if likes else None
    if like_only and like_sql:
        return like_sql
    regs = [f"regexp_matches({orig}, {sql_str(r)})" for r in spec.get("regex") or []]
    parts = ([like_sql] if like_sql else []) + regs
    return "(" + " AND ".join(parts) + ")" if parts else "FALSE"


def _kind(sev: str) -> str:
    return "log cleared" if sev == "critical" else "logging disabled"


def check_log_cleared(con: duckdb.DuckDBPyConnection, cols: set[str], c: dict[str, Any]) -> list[dict[str, Any]]:
    if not cols & {"event_id", "action", "command_line", "raw_line"}:
        raise Skip("missing columns: event_id, action, command_line, raw_line")
    clear = [int(x) for x in c.get("clear_event_ids") or []]
    audit = [int(x) for x in c.get("audit_tamper_event_ids") or []]
    excl = [str(x) for x in c.get("event_id_exclude_source_types") or []]
    st = _c(cols, "source_type")
    eid = "try_cast(event_id AS INTEGER)" if "event_id" in cols else "NULL::INTEGER"
    eid_ok = f"coalesce(st, '') NOT IN ({', '.join(sql_str(x) for x in excl)})" if excl else "TRUE"
    act = _c(cols, "action")
    proc = [f"{act} IN ({', '.join(sql_str(a) for a in c.get('proc_actions') or ['proc_start'])})"]
    if "command_line" in cols:
        proc.append("command_line IS NOT NULL")
    if c.get("command_source_types") and "source_type" in cols:
        proc.append(f"source_type IN ({', '.join(sql_str(s) for s in c['command_source_types'])})")
    proc_sql = "(" + " OR ".join(proc) + ")"
    txt = (f"concat_ws(' ', {_c(cols, 'command_line')}, {_c(cols, 'process_name')}, {_c(cols, 'raw_line')})")
    whens: list[str] = []
    labels: dict[str, tuple[str, str]] = {}   # label key -> (severity, title)
    pre: list[str] = []
    names = {int(k): str(v) for k, v in (c.get("event_id_labels") or {}).items()}
    for ids, sev, prefix in ((clear, "critical", "log cleared"), (audit, "high", "audit tampering")):
        if ids:
            inl = ", ".join(str(i) for i in ids)
            whens.append(f"WHEN eid IN ({inl}) AND {eid_ok} THEN '{sev[0]}eid:' || CAST(eid AS VARCHAR)")
            pre.append(f"(eid IN ({inl}) AND {eid_ok})")
            for i in ids:
                labels[f"{sev[0]}eid:{i}"] = (sev, f"{prefix}: {names.get(i, f'event {i}')}")
    acts = [str(a) for a in c.get("clear_actions") or []]
    if acts and "action" in cols:
        cond = f"action IN ({', '.join(sql_str(a) for a in acts)})"
        whens.append(f"WHEN {cond} THEN 'act:' || action")
        pre.append(cond)
        for a in acts:
            labels[f"act:{a}"] = ("critical", f"log cleared: action={a}")
    for i, spec in enumerate(c.get("command_patterns") or []):
        sev = str(spec.get("severity", "critical"))
        whens.append(f"WHEN ltxt IS NOT NULL AND {_pattern_sql('ltxt', 'otxt', spec)} THEN 'cmd:{i}'")
        pre.append(f"(ltxt IS NOT NULL AND {_pattern_sql('ltxt', 'otxt', spec, like_only=True)})")
        labels[f"cmd:{i}"] = (sev, f"{_kind(sev)}: {spec.get('label')}")
    raw_types = [str(t) for t in (c.get("raw_patterns") or {})] if {"raw_line", "source_type"} <= cols else []
    if raw_types:
        for stype, specs in (c.get("raw_patterns") or {}).items():
            for i, spec in enumerate(specs or []):
                sev = str(spec.get("severity", "critical"))
                key = f"raw:{stype}:{i}"
                cond = f"st = {sql_str(stype)} AND lraw IS NOT NULL"
                whens.append(f"WHEN {cond} AND {_pattern_sql('lraw', 'raw', spec)} THEN {sql_str(key)}")
                pre.append(f"({cond} AND {_pattern_sql('lraw', 'raw', spec, like_only=True)})")
                labels[key] = (sev, f"{_kind(sev)}: {spec.get('label')}")
    if not whens:
        raise Skip("no log-tampering patterns configured")
    ts, raw, host = _c(cols, "ts_ms"), _c(cols, "raw_line"), _c(cols, "host")
    rt = f"{st} IN ({', '.join(sql_str(t) for t in raw_types)})" if raw_types else "FALSE"
    base = [f"({eid} IN ({', '.join(str(i) for i in clear + audit)}))" if clear + audit else "FALSE",
            f"{act} IN ({', '.join(sql_str(a) for a in acts)})" if acts and "action" in cols else "FALSE",
            proc_sql, rt]
    # text is lower-cased once per candidate row; every like pattern is then a plain (fast) LIKE
    rows = con.execute(
        f"WITH b AS (SELECT {host} AS host, {st} AS st, {ts} AS ts, {raw} AS raw, {eid} AS eid, {act} AS action, "
        f"CASE WHEN {proc_sql} THEN {txt} END AS otxt, CASE WHEN {proc_sql} THEN lower({txt}) END AS ltxt, "
        f"CASE WHEN {rt} THEN lower({raw}) END AS lraw FROM events WHERE {' OR '.join(base)}), "
        f"lab AS (SELECT host, st, ts, raw, CASE {' '.join(whens)} END AS label FROM b WHERE {' OR '.join(pre)}) "
        f"SELECT label, lower(host), min(st), count(*), min(ts), max(ts), arg_min(raw, coalesce(ts, 0), 3) "
        f"FROM lab WHERE label IS NOT NULL GROUP BY label, lower(host)").fetchall()
    out = []
    for label, h, s, n, t0, t1, ev in rows:
        sev, title = labels.get(label, ("high", f"log tampering: {label}"))
        out.append(finding("log_cleared", sev, title, source_type=s, host=h, start_ts_ms=t0, end_ts_ms=t1,
                           count=n, detail=f"{n} event(s) matching '{title}' on {h or 'unknown host'} "
                                           f"between {_iso(t0)} and {_iso(t1)}", evidence=list(ev or [])))
    return out


# --- silence_gap / went_dark (small bucket tables) -------------------------------------------------------------

def build_buckets(con: duckdb.DuckDBPyConnection, cols: set[str], c: dict[str, Any]) -> dict[str, Any]:
    """Per-(host, bucket) counts -> integ_hb; eligible hosts with their median bucket gap -> integ_el."""
    _need(cols, "host", "ts_ms")
    bms = int(float(c.get("bucket_minutes", 5)) * 60000)
    tsok = "ts_ok AND " if "ts_ok" in cols else ""
    st = _c(cols, "source_type")
    con.execute(f"CREATE OR REPLACE TEMP TABLE integ_hb AS SELECT lower(host) AS host, ts_ms // {bms} AS b, "
                f"count(*) AS n, min(ts_ms) AS t0, max(ts_ms) AS t1, min({st}) AS st0, max({st}) AS st1 "
                f"FROM events WHERE {tsok}ts_ms IS NOT NULL AND host IS NOT NULL AND host <> '' GROUP BY 1, 2")
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE integ_el AS "
        f"WITH h AS (SELECT host, sum(n) AS total, max(b) AS last_b, max(t1) AS last_ts, "
        f"CASE WHEN min(st0) = max(st1) THEN min(st0) END AS st FROM integ_hb GROUP BY host "
        f"HAVING sum(n) >= {int(c.get('min_host_events', 200))}), "
        f"d AS (SELECT host, b - lag(b) OVER (PARTITION BY host ORDER BY b) AS d FROM integ_hb "
        f"WHERE host IN (SELECT host FROM h)) "
        f"SELECT h.*, coalesce(m.med, 1.0) AS med FROM h LEFT JOIN "
        f"(SELECT host, median(d) AS med FROM d WHERE d IS NOT NULL GROUP BY host) m USING (host)")
    n_el, = con.execute("SELECT count(*) FROM integ_el").fetchone()
    return {"n_eligible": int(n_el), "bucket_ms": bms}


def check_silence_gap(con: duckdb.DuckDBPyConnection, info: dict[str, Any], c: dict[str, Any]) -> list[dict[str, Any]]:
    n_el, bms = info["n_eligible"], info["bucket_ms"]
    if n_el == 0:
        raise Skip(f"no host with >= {int(c.get('min_host_events', 200))} events")
    factor = float(c.get("gap_factor", 10))
    min_gap = int(float(c.get("min_gap_minutes", 60)) * 60000)
    thr = (f"greatest({min_gap}, {factor} * e.med * {bms})" if n_el >= 2
           else str(int(float(c.get("single_host_gap_minutes", 360)) * 60000)))
    # Abrupt-cut test: share of the host's own buckets that logged in the ctx window just before AND just after
    # the gap (cut = the lower side). A deleted window in a steady stream has cut ~1; a bursty or diurnal host
    # drifting into idle has a sparse edge. Fixed denominator, so gaps at the host's edges score conservatively.
    ctx = max(1, round(float(c.get("gap_context_minutes", 60)) * 60000 / bms))
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE integ_gaps AS WITH g AS (SELECT g.host, g.prev_b, g.b, "
        f"g.prev_t1 AS start_ts, g.t0 AS end_ts, {thr} AS thr, e.st FROM (SELECT host, b, t0, lag(b) OVER w AS prev_b, "
        f"lag(t1) OVER w AS prev_t1 FROM integ_hb WHERE host IN (SELECT host FROM integ_el) "
        f"WINDOW w AS (PARTITION BY host ORDER BY b)) g JOIN integ_el e USING (host) "
        f"WHERE g.prev_b IS NOT NULL AND g.t0 - g.prev_t1 > {thr}) "
        f"SELECT g.*, least(count(*) FILTER (WHERE h.b <= g.prev_b), count(*) FILTER (WHERE h.b >= g.b)) / {ctx} "
        f"AS cut FROM g JOIN integ_hb h ON h.host = g.host AND h.b > g.prev_b - {ctx} AND h.b < g.b + {ctx} "
        f"GROUP BY ALL")
    hi_cut = float(c.get("gap_cut_density_high", 0.75))
    md_cut = float(c.get("gap_cut_density_medium", 0.5))
    md_x = float(c.get("gap_medium_factor", 2))
    ctx_min = ctx * bms / 60000
    out = []
    if n_el == 1:
        for h, t0, t1, st, cut in con.execute("SELECT host, start_ts, end_ts, st, cut FROM integ_gaps").fetchall():
            if cut < md_cut:
                continue  # sparse edge: the host wound down to idle, not a cut
            mins = (t1 - t0) / 60000
            out.append(finding("silence_gap", "medium", "long silence on the only host", source_type=st, host=h,
                               start_ts_ms=t0, end_ts_ms=t1, detail=f"no events for {mins:.0f} min "
                               f"({_iso(t0)} -> {_iso(t1)}); only one eligible host, no peer comparison; host "
                               f"logged in >= {cut:.0%} of the {ctx_min:.0f} min on each side"))
        return out
    ratio = float(c.get("peer_active_ratio", 0.5))
    rows = con.execute(
        "SELECT gp.host, gp.start_ts, gp.end_ts, gp.thr, gp.st, gp.cut, count(DISTINCT p.host) FROM integ_gaps gp "
        "LEFT JOIN integ_hb p ON p.host <> gp.host AND p.b > gp.prev_b AND p.b < gp.b "
        "AND p.host IN (SELECT host FROM integ_el) GROUP BY ALL").fetchall()
    idle = 0
    for h, t0, t1, thr_ms, st, cut, peers in rows:
        if peers / (n_el - 1) < ratio:
            continue
        sev = ("high" if cut >= hi_cut else
               "medium" if cut >= md_cut and t1 - t0 > md_x * thr_ms else None)
        if sev is None:
            idle += 1
            continue
        mins = (t1 - t0) / 60000
        out.append(finding("silence_gap", sev, "host silent while peers kept logging", source_type=st,
                           host=h, start_ts_ms=t0, end_ts_ms=t1,
                           detail=f"no events for {mins:.0f} min ({_iso(t0)} -> {_iso(t1)}; threshold "
                                  f"{thr_ms / 60000:.0f} min) while {peers} of {n_el - 1} peer hosts logged; "
                                  f"host logged in >= {cut:.0%} of the {ctx_min:.0f} min on each side (abrupt cut)",
                           evidence=[f"last event before gap {_iso(t0)}", f"first event after gap {_iso(t1)}"]))
    if idle:
        log.debug("silence_gap: %d long gap(s) with sparse edges ignored as idle periods", idle)
    # whole-dataset silence (every host quiet at once) -> one low "collection gap" finding per gap
    for t0, t1 in con.execute(
            f"WITH g AS (SELECT b, min(t0) AS t0, max(t1) AS t1 FROM integ_hb GROUP BY b), "
            f"l AS (SELECT b, t0, lag(b) OVER (ORDER BY b) AS pb, lag(t1) OVER (ORDER BY b) AS pt1 FROM g), "
            f"m AS (SELECT coalesce(median(b - pb), 1) AS med FROM l WHERE pb IS NOT NULL) "
            f"SELECT pt1, t0 FROM l, m WHERE pb IS NOT NULL "
            f"AND t0 - pt1 > greatest({min_gap}, {factor} * m.med * {bms})"
    ).fetchall():
        out.append(finding("silence_gap", "low", "collection gap (all hosts silent)", start_ts_ms=t0, end_ts_ms=t1,
                           detail=f"no host logged for {(t1 - t0) / 60000:.0f} min ({_iso(t0)} -> {_iso(t1)}): "
                                  "collection outage rather than one silenced host"))
    return out


def check_went_dark(con: duckdb.DuckDBPyConnection, info: dict[str, Any], c: dict[str, Any]) -> list[dict[str, Any]]:
    n_el, bms = info["n_eligible"], info["bucket_ms"]
    if n_el < 2:
        raise Skip(f"needs >= 2 hosts with >= {int(c.get('min_host_events', 200))} events (found {n_el})")
    dark = int(float(c.get("dark_minutes", 120)) * 60000)
    factor = float(c.get("gap_factor", 10))
    rows = con.execute(
        f"WITH en AS (SELECT max(t1) AS mt FROM integ_hb), "
        f"dk AS (SELECT e.*, en.mt FROM integ_el e, en "
        f"WHERE en.mt - e.last_ts > greatest({dark}, {factor} * e.med * {bms})) "
        f"SELECT dk.host, dk.last_ts, dk.st, dk.total, dk.mt, count(DISTINCT p.host) FROM dk "
        f"LEFT JOIN integ_hb p ON p.host <> dk.host AND p.b > dk.last_b AND p.host IN (SELECT host FROM integ_el) "
        f"GROUP BY ALL").fetchall()
    out = []
    ratio = float(c.get("peer_active_ratio", 0.5))
    for h, last, st, total, end, peers in rows:
        if peers / (n_el - 1) >= ratio:
            out.append(finding("went_dark", "high", "host stopped logging before the end", source_type=st, host=h,
                               start_ts_ms=last, end_ts_ms=end, count=1,
                               detail=f"last of {total} events at {_iso(last)}, {(end - last) / 60000:.0f} min before "
                                      f"the dataset end ({_iso(end)}) while {peers} of {n_el - 1} peers kept logging"))
    return out


# --- timestamps -------------------------------------------------------------------------------------------------

def check_timestamps(con: duckdb.DuckDBPyConnection, cols: set[str], c: dict[str, Any],
                     now_ms: int) -> list[dict[str, Any]]:
    _need(cols, "ts_ms")
    st, raw = _c(cols, "source_type"), _c(cols, "raw_line")
    bad = "NOT coalesce(ts_ok, false)" if "ts_ok" in cols else "ts_ms IS NULL"
    pile = f"{bad} AND ts_ms IS NOT NULL" + (" AND coalesce(action, '') <> 'malformed'" if "action" in cols else "")
    fut = f"ts_ms > {now_ms + int(float(c.get('future_tolerance_hours', 24)) * 3_600_000)}"
    old = f"ts_ms < {int(datetime(int(c.get('min_valid_year', 2000)), 1, 1, tzinfo=UTC).timestamp() * 1000)}"
    rows = con.execute(
        f"SELECT {st}, count(*), count(*) FILTER (WHERE {bad}), count(*) FILTER (WHERE {pile}), "
        f"count(*) FILTER (WHERE {fut}), min(ts_ms) FILTER (WHERE {fut}), max(ts_ms) FILTER (WHERE {fut}), "
        f"count(*) FILTER (WHERE {old}), min(ts_ms) FILTER (WHERE {old}), max(ts_ms) FILTER (WHERE {old}), "
        f"arg_min({raw}, hash({raw}), 3) FILTER (WHERE {bad}), arg_max({raw}, ts_ms, 3) FILTER (WHERE {fut}), "
        f"arg_min({raw}, ts_ms, 3) FILTER (WHERE {old}) FROM events GROUP BY 1").fetchall()
    warn, high = float(c.get("bad_ts_warn", 0.01)), float(c.get("bad_ts_high", 0.10))
    out = []
    for s, n, nbad, npile, nfut, f0, f1, nold, o0, o1, ev_bad, ev_fut, ev_old in rows:
        r = nbad / n if n else 0.0
        if r > warn:
            note = (f"; {npile} of them carry a timestamp but were quarantined as a pile-up (many rows in one "
                    f"second: frozen clock or bulk re-stamp)") if npile else ""
            out.append(finding("timestamps", "high" if r > high else "medium",
                               f"{r:.1%} of rows without a usable timestamp", source_type=s, count=nbad,
                               detail=f"{nbad} of {n} {s} rows have ts_ok=false{note}", evidence=list(ev_bad or [])))
        if nfut:
            out.append(finding("timestamps", "high", "timestamps in the future", source_type=s, count=nfut,
                               start_ts_ms=f0, end_ts_ms=f1, evidence=list(ev_fut or []),
                               detail=f"{nfut} {s} rows are more than {c.get('future_tolerance_hours', 24)} h after "
                                      f"now (latest {_iso(f1)})"))
        if nold:
            out.append(finding("timestamps", "medium", f"timestamps before {c.get('min_valid_year', 2000)}",
                               source_type=s, count=nold, start_ts_ms=o0, end_ts_ms=o1, evidence=list(ev_old or []),
                               detail=f"{nold} {s} rows dated before {c.get('min_valid_year', 2000)} "
                                      f"(earliest {_iso(o0)})"))
    return out


# --- duplicates -------------------------------------------------------------------------------------------------

def check_duplicates(con: duckdb.DuckDBPyConnection, cols: set[str], c: dict[str, Any],
                     counts: dict[str | None, int]) -> list[dict[str, Any]]:
    _need(cols, "raw_line", "source_type")
    elig = {s: n for s, n in counts.items() if s is not None and n >= int(c.get("dup_min_rows", 1000))}
    if not elig:
        raise Skip(f"no source type with >= {int(c.get('dup_min_rows', 1000))} rows")
    cap = max(1, int(c.get("dup_sample_rows", 2_000_000)))
    k = {s: max(1, math.ceil(n / cap)) for s, n in elig.items()}
    kcase = "CASE source_type " + " ".join(f"WHEN {sql_str(s)} THEN {v}" for s, v in k.items()) + " END"
    # distinct lines ~ distinct-in-sample x k (each distinct line is sampled with p = 1/k whatever its copy count),
    # divided by the exact row total: heavy-hitter lines do not swing the estimate
    rows = con.execute(
        f"WITH s AS (SELECT source_type AS st, hash(raw_line) AS h FROM events WHERE raw_line IS NOT NULL "
        f"AND source_type IN ({', '.join(sql_str(s) for s in elig)})), "
        f"t AS (SELECT st, count(*) AS n FROM s GROUP BY st), "
        f"g AS (SELECT st, h, count(*) AS c FROM s WHERE h % ({kcase.replace('source_type', 'st')}) = 0 GROUP BY ALL) "
        f"SELECT t.st, t.n, count(g.h), arg_max(g.h, g.c, 3) FILTER (WHERE g.c > 1) "
        f"FROM t LEFT JOIN g USING (st) GROUP BY t.st, t.n").fetchall()
    warn, high = float(c.get("dup_warn", 0.05)), float(c.get("dup_high", 0.20))
    out = []
    for s, total, distinct, top in rows:
        ratio = max(0.0, 1 - distinct * k[s] / total) if total else 0.0
        if ratio <= warn:
            continue
        ev = []
        if top:
            hs = ", ".join(str(int(h)) for h in top)
            got = con.execute(f"SELECT h, count(*), any_value(raw_line) FROM (SELECT hash(raw_line) AS h, raw_line "
                              f"FROM events WHERE source_type = {sql_str(s)} AND hash(raw_line) IN ({hs})) "
                              f"GROUP BY h").fetchall()
            ev = [f"{n}x {line}" for _, n, line in sorted(got, key=lambda r: -r[1])]
        est = round(ratio * total)
        how = "exact" if k[s] == 1 else f"distinct lines estimated from a 1/{k[s]} hash sample"
        out.append(finding("duplicates", "high" if ratio > high else "medium",
                           "possible replay / injected copies", source_type=s, count=est, evidence=ev,
                           detail=f"{ratio:.1%} of {total} {s} lines are byte-identical copies ({how})"))
    return out


# --- embedded_time_mismatch -------------------------------------------------------------------------------------

def check_embedded_time(con: duckdb.DuckDBPyConnection, cols: set[str], c: dict[str, Any],
                        counts: dict[str | None, int]) -> list[dict[str, Any]]:
    pats = {str(k): str(v) for k, v in (c.get("embedded_time_source_types") or {}).items()}
    present = [s for s in pats if counts.get(s)]
    if not present:
        raise Skip(f"no {', '.join(pats) or 'configured'} events")
    _need(cols, "raw_line", "ts_ms", "source_type")
    host = "lower(host)" if "host" in cols else "NULL"
    rnd = int(float(c.get("embedded_round_minutes", 15)) * 60000)
    tol = int(float(c.get("time_mismatch_tolerance_s", 300)) * 1000)
    out = []
    for s in present:
        con.execute(
            f"CREATE OR REPLACE TEMP TABLE integ_off AS "
            f"WITH x AS (SELECT coalesce({host}, '') AS host, ts_ms, raw_line, "
            f"NULLIF(regexp_extract(raw_line, {sql_str(pats[s])}, 1), '') AS s FROM events "
            f"WHERE source_type = {sql_str(s)} AND ts_ms IS NOT NULL), "
            f"y AS (SELECT host, ts_ms, raw_line, ts_ms - {_EPOCH_MS} AS off FROM x WHERE s IS NOT NULL) "
            f"SELECT host, round(off / {rnd}) AS g, count(*) AS n, avg(off) AS mean_off, min(ts_ms) AS t0, "
            f"max(ts_ms) AS t1, arg_min(raw_line, ts_ms) AS ex FROM y WHERE off IS NOT NULL GROUP BY 1, 2")
        rows = con.execute(
            f"WITH m AS (SELECT host, arg_max(g, n) AS mg, sum(n) AS tot FROM integ_off GROUP BY host), "
            f"ctr AS (SELECT o.host, o.mean_off AS center FROM integ_off o JOIN m ON o.host = m.host AND o.g = m.mg), "
            f"bad AS (SELECT o.*, ctr.center FROM integ_off o JOIN ctr USING (host) "
            f"WHERE abs(o.mean_off - ctr.center) > {tol}) "
            f"SELECT m.host, m.tot, any_value(bad.center), sum(bad.n), min(bad.t0), max(bad.t1), "
            f"arg_max(bad.ex, bad.n, 3), arg_max(bad.mean_off, bad.n) "
            f"FROM m JOIN bad USING (host) GROUP BY m.host, m.tot").fetchall()
        lo_ratio, lo_rows = float(c.get("mismatch_min_ratio", 0.001)), int(c.get("mismatch_min_rows", 20))
        for h, tot, center, nbad, t0, t1, ev, worst in rows:
            nbad = int(nbad or 0)
            if not nbad or not (nbad / tot > lo_ratio or nbad >= lo_rows):
                continue
            out.append(finding(
                "embedded_time_mismatch", "high", "header timestamp edited / clock tampered", source_type=s,
                host=h or None, start_ts_ms=t0, end_ts_ms=t1, count=nbad, evidence=list(ev or []),
                detail=(f"{nbad} of {tot} rows ({nbad / tot:.2%}) disagree with the embedded event time: normal "
                        f"header-minus-embedded offset {center / 3_600_000:+.2f} h, most common deviant offset "
                        f"{worst / 3_600_000:+.2f} h (tolerance {tol // 1000} s)")))
    return out
