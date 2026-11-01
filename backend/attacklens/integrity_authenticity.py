"""Authenticity heuristics: do these logs look machine-generated / synthetic? (config/authenticity.yaml)

analyze(con, cfg) -> the optional "authenticity" block of integrity_report.json:
    {"label": "natural" | "likely_generated" | "unknown", "score": 0..100 (higher = more machine-like),
     "signals": [{"id", "value", "threshold", "fired", "detail"}], "reason": str | None}
It never changes the integrity verdict or trust score.

Bounded: one GROUP BY (host, hour) over the `events` view into a small temp table; window functions run only on
that table and on one contiguous per-host time slice (<= slice_rows rows per sampled host, one filtered scan);
template diversity reads a hash sample of canonical columns. Reads only canonical schema columns (never the
generator's ground-truth label fields, never raw_line).
"""

from __future__ import annotations

import logging
import math
import statistics
from typing import Any

import duckdb

from attacklens.db import sql_str
from attacklens.schemas import CANONICAL_COLUMNS, PARTITION_COLUMNS

log = logging.getLogger(__name__)

HOUR_MS = 3_600_000
DAY_MS = 86_400_000
_HH = "auth_hh"
DEFAULTS: dict[str, Any] = {"enabled": True, "min_rows": 5000, "min_hours": 24, "min_host_rows": 500,
                            "max_hosts": 2000, "label_min_strong": 2, "label_min_score": 50, "signals": {}}
SIGNAL_IDS = ("flat_hourly_volume", "no_diurnal_cycle", "uniform_host_rate", "periodic_timer",
              "low_template_diversity")
# template columns: canonical schema only (config may list others; they are ignored), raw text excluded
_TEMPLATE_OK = (set(CANONICAL_COLUMNS) | set(PARTITION_COLUMNS)) - {"raw_line", "command_line", "ts_ms", "source_seq"}


def _acfg(cfg: dict[str, Any]) -> dict[str, Any]:
    """Accepts the full config dict (uses cfg["authenticity"]) or the section itself."""
    sec = cfg.get("authenticity") if isinstance(cfg.get("authenticity"), dict) else cfg
    return {**DEFAULTS, **(sec or {})}


def _sig(a: dict[str, Any], sid: str) -> dict[str, Any]:
    s = (a.get("signals") or {}).get(sid)
    return s if isinstance(s, dict) else {}


def _rnd(x: float | None, n: int = 4) -> float | None:
    if x is None or (isinstance(x, float) and not math.isfinite(x)):
        return None
    return round(float(x), n)


def _signal(sid: str, value: float | None, threshold: float | None, fired: bool, detail: str) -> dict[str, Any]:
    return {"id": sid, "value": _rnd(value), "threshold": threshold, "fired": bool(fired), "detail": detail}


def _columns(con: duckdb.DuckDBPyConnection) -> set[str]:
    try:
        return {str(r[0]) for r in con.execute("DESCRIBE events").fetchall()}
    except duckdb.Error:
        return set()


def _host_expr(cols: set[str]) -> str:
    return "coalesce(CAST(host AS VARCHAR), '?')" if "host" in cols else "'?'"


def _ok(cols: set[str]) -> str:
    return "ts_ok AND ts_ms IS NOT NULL" if "ts_ok" in cols else "ts_ms IS NOT NULL"


# --- per host x hour table -----------------------------------------------------------------------------------

def _build_hourly(con: duckdb.DuckDBPyConnection, cols: set[str], a: dict[str, Any]) -> None:
    """auth_hh(host, hr, n): hourly counts of the max_hosts busiest hosts with >= min_host_rows rows."""
    h = _host_expr(cols)
    con.execute(f"""CREATE OR REPLACE TEMP TABLE {_HH}_all AS
        SELECT {h} AS host, ts_ms // {HOUR_MS} AS hr, count(*) AS n FROM events WHERE {_ok(cols)} GROUP BY ALL""")
    con.execute(f"""CREATE OR REPLACE TEMP TABLE {_HH} AS
        WITH tot AS (SELECT host, sum(n) AS t FROM {_HH}_all GROUP BY host HAVING sum(n) >= {int(a['min_host_rows'])}
                     ORDER BY t DESC, host LIMIT {int(a['max_hosts'])})
        SELECT x.* FROM {_HH}_all x SEMI JOIN tot USING (host)""")
    con.execute(f"DROP TABLE IF EXISTS {_HH}_all")


def _flat_volume(con: duckdb.DuckDBPyConnection, a: dict[str, Any], span_h: float) -> dict[str, Any]:
    s, sid = _sig(a, "flat_hourly_volume"), "flat_hourly_volume"
    thr = float(s.get("max_dispersion", 3.0))
    min_h = int(a["min_hours"])
    trim = min(0.49, max(0.0, float(s.get("span_trim_share", 0.01))))
    cap = max(min_h, int(s.get("max_grid_hours", 2160)))
    if span_h < min_h:
        return _signal(sid, None, thr, False, f"dataset spans {span_h:.1f} h < min_hours {min_h}")
    # Grid size depends on the time span, not the data: trim each host's span to its [trim, 1-trim] event-weighted
    # quantile hours (stray 1970/2099 rows drop out), then keep at most `cap` interior hours (the most recent).
    r = con.execute(f"""
        WITH cum AS (SELECT host, hr, n, sum(n) OVER (PARTITION BY host ORDER BY hr) AS c,
                            sum(n) OVER (PARTITION BY host) AS t FROM {_HH}),
        trimmed AS (SELECT host, min(hr) AS a, max(hr) AS b FROM cum
                WHERE c > t * {trim} AND c - n < t * (1 - {trim}) GROUP BY host HAVING max(hr) - min(hr) - 1 >= {min_h}),
        span AS (SELECT host, greatest(a, b - {cap} - 1) AS a, b, b - a - 1 > {cap} AS clipped FROM trimmed),
        grid AS (SELECT s.host, unnest(range(s.a + 1, s.b)) AS hr FROM span s),  -- first/last hour are partial
        dense AS (SELECT g.host, coalesce(h.n, 0) AS n FROM grid g LEFT JOIN {_HH} h USING (host, hr)),
        per AS (SELECT host, var_pop(n) / nullif(avg(n), 0) AS disp, stddev_pop(n) / nullif(avg(n), 0) AS cv
                FROM dense GROUP BY host)
        SELECT count(*), median(disp), median(cv), (SELECT count(*) FILTER (clipped) FROM span)
        FROM per WHERE disp IS NOT NULL""").fetchone()
    hosts, disp, cv, clipped = int(r[0] or 0), r[1], r[2], int(r[3] or 0)
    if not hosts or disp is None:
        return _signal(sid, None, thr, False, f"no host with >= {min_h} h of activity and >= "
                                              f"{a['min_host_rows']} rows")
    fired = float(disp) < thr
    clip = f"; {clipped} host span(s) clipped to the last {cap} h" if clipped else ""
    return _signal(sid, float(disp), thr, fired,
                   f"median hourly dispersion (var/mean) {float(disp):.3g} over {hosts} host(s), median CV "
                   f"{float(cv or 0):.3f}; ~1 = constant-rate emitter, real logs are bursty (>> 1){clip}")


def _diurnal(con: duckdb.DuckDBPyConnection, a: dict[str, Any], span_h: float) -> dict[str, Any]:
    s, sid = _sig(a, "no_diurnal_cycle"), "no_diurnal_cycle"
    thr = float(s.get("max_cv", 0.05))
    min_h = int(a["min_hours"])
    if span_h < min_h:
        return _signal(sid, None, thr, False, f"dataset spans {span_h:.1f} h < min_hours {min_h}")
    r = con.execute(f"""WITH hod AS (SELECT hr % 24 AS h, sum(n) AS n FROM {_HH} GROUP BY 1)
        SELECT count(*), stddev_pop(n) / nullif(avg(n), 0), max(n), min(n) FROM hod""").fetchone()
    hours, cv = int(r[0] or 0), r[1]
    if hours < 24 or cv is None:
        return _signal(sid, None, thr, False, f"only {hours} of 24 UTC hours of day have events")
    fired = float(cv) < thr
    return _signal(sid, float(cv), thr, fired,
                   f"hour-of-day volume CV {float(cv):.4f} (busiest/quietest hour {int(r[2])}/{int(r[3])}); "
                   "near 0 = no day/night cycle")


def _host_rate(con: duckdb.DuckDBPyConnection, a: dict[str, Any]) -> dict[str, Any]:
    s, sid = _sig(a, "uniform_host_rate"), "uniform_host_rate"
    thr, min_hosts = float(s.get("max_cv", 0.10)), int(s.get("min_hosts", 5))
    r = con.execute(f"""WITH h AS (SELECT host, sum(n) * 1.0 / count(*) AS rate FROM {_HH} GROUP BY host)
        SELECT count(*), stddev_pop(rate) / nullif(avg(rate), 0), min(rate), max(rate) FROM h""").fetchone()
    hosts, cv = int(r[0] or 0), r[1]
    if hosts < min_hosts or cv is None:
        return _signal(sid, None, thr, False, f"{hosts} eligible host(s) < min_hosts {min_hosts}")
    fired = float(cv) < thr
    return _signal(sid, float(cv), thr, fired,
                   f"CV {float(cv):.4f} of mean events per active hour across {hosts} hosts "
                   f"(min {float(r[2]):.1f}, max {float(r[3]):.1f}); near 0 = every host emits at the same rate")


def _periodic(con: duckdb.DuckDBPyConnection, cols: set[str], a: dict[str, Any]) -> dict[str, Any]:
    s, sid = _sig(a, "periodic_timer"), "periodic_timer"
    thr, min_dt = float(s.get("min_share", 0.5)), int(s.get("min_delta_ms", 2000))
    min_deltas, slice_rows = int(s.get("min_deltas", 50)), int(s.get("slice_rows", 20000))
    k = int(s.get("sample_hosts", 10))
    # each sampled host's median-volume hour (window function on the small hourly table only)
    picks = con.execute(f"""
        WITH r AS (SELECT host, hr, n, row_number() OVER (PARTITION BY host ORDER BY n, hr) AS rk,
                          count(*) OVER (PARTITION BY host) AS c FROM {_HH}),
        m AS (SELECT host, hr, n FROM r WHERE rk = (c + 1) // 2)
        SELECT host, hr, n FROM m ORDER BY hash(host), host LIMIT {k}""").fetchall()
    conds, days = [], set()
    for host, hr, n in picks:
        lo = int(hr) * HOUR_MS
        width = HOUR_MS if int(n) <= slice_rows else max(1000, HOUR_MS * slice_rows // int(n))
        conds.append(f"(h = {sql_str(str(host))} AND ts_ms >= {lo} AND ts_ms < {lo + width})")
        days.add(lo // DAY_MS)
    if not conds:
        return _signal(sid, None, thr, False, "no eligible host to sample")
    day_f = ""
    if "event_day" in cols:
        day_f = " AND event_day IN (" + ", ".join(f"DATE '1970-01-01' + {d}::INTEGER" for d in sorted(days)) + ")"
    rows = con.execute(f"""
        WITH x AS (SELECT * FROM (SELECT {_host_expr(cols)} AS h, ts_ms FROM events WHERE {_ok(cols)}{day_f})
                   WHERE {' OR '.join(conds)}),
        d AS (SELECT h, ts_ms - lag(ts_ms) OVER (PARTITION BY h ORDER BY ts_ms) AS dt FROM x),
        tot AS (SELECT h, count(dt) AS nd FROM d GROUP BY h),
        mode AS (SELECT h, dt, count(*) AS c FROM d WHERE dt >= {min_dt} GROUP BY h, dt),
        best AS (SELECT h, max(c) AS c, arg_max(dt, c) AS dt FROM mode GROUP BY h)
        SELECT tot.h, tot.nd, coalesce(best.c, 0), best.dt FROM tot LEFT JOIN best USING (h)""").fetchall()
    shares = [(str(h), int(c) / int(nd), dt) for h, nd, c, dt in rows if int(nd) >= min_deltas]
    if not shares:
        return _signal(sid, None, thr, False, f"no sampled host slice with >= {min_deltas} inter-arrival deltas")
    med = statistics.median(v for _, v, _ in shares)
    top = max(shares, key=lambda t: t[1])
    fired = med >= thr
    return _signal(sid, med, thr, fired,
                   f"median share of consecutive deltas equal to the host's modal delta (>= {min_dt} ms) over "
                   f"{len(shares)} sampled host slice(s); highest {top[1]:.3f} (modal delta "
                   f"{'-' if top[2] is None else int(top[2])} ms)")


def _templates(con: duckdb.DuckDBPyConnection, cols: set[str], a: dict[str, Any], rows: int) -> dict[str, Any]:
    s, sid = _sig(a, "low_template_diversity"), "low_template_diversity"
    thr, n = float(s.get("max_distinct_per_1000", 1.0)), int(s.get("sample_rows", 200000))
    use = [c for c in (s.get("columns") or []) if c in cols and c in _TEMPLATE_OK]
    if not use:
        return _signal(sid, None, thr, False, "none of the configured canonical columns exist")
    expr = "concat_ws('|', " + ", ".join(f"coalesce(CAST({c} AS VARCHAR), '')" for c in use) + ")"
    step = max(1, math.ceil(rows / max(1, n)))
    seq = "source_seq" if "source_seq" in cols else "ts_ms"
    samp = f" AND hash({seq}) % {step} = 0" if step > 1 else ""
    r = con.execute(f"""WITH smp AS (SELECT {expr} AS t FROM events WHERE {_ok(cols)}{samp} LIMIT {n})
        SELECT count(*), count(DISTINCT t) FROM smp""").fetchone()
    got, distinct = int(r[0] or 0), int(r[1] or 0)
    if got < min(n, int(a["min_rows"])):
        return _signal(sid, None, thr, False, f"sample of {got} rows too small")
    per_k = distinct * 1000.0 / got
    return _signal(sid, per_k, thr, per_k < thr,
                   f"{distinct} distinct ({', '.join(use)}) tuples in a {got}-row sample = {per_k:.2f} per 1000 rows")


# --- labelling -------------------------------------------------------------------------------------------------

def _label(sigs: list[dict[str, Any]], a: dict[str, Any]) -> tuple[str, int, str | None]:
    spec = {sid: _sig(a, sid) for sid in SIGNAL_IDS}
    w = {s["id"]: float(spec.get(s["id"], {}).get("weight", 0)) for s in sigs}
    computable = [s for s in sigs if s["value"] is not None]
    total = sum(w[s["id"]] for s in computable)
    score = round(100 * sum(w[s["id"]] for s in computable if s["fired"]) / total) if total > 0 else 0
    strong = [s for s in computable if spec.get(s["id"], {}).get("strong")]
    grp = lambda s: str(spec[s["id"]].get("group") or s["id"])  # noqa: E731
    groups = {grp(s) for s in strong}
    fired = {grp(s) for s in strong if s["fired"]}
    need = int(a["label_min_strong"])
    if len(groups) < need:  # score withheld: weak signals alone must not read as "100 % generated"
        return "unknown", 0, (f"only {len(groups)} strong signal group(s) computable "
                                  f"({', '.join(sorted(groups)) or 'none'}); need {need}")
    if len(fired) >= need and score >= int(a["label_min_score"]):
        return "likely_generated", score, (f"{len(fired)} strong signal group(s) fired: {', '.join(sorted(fired))}")
    return "natural", score, None if not fired else f"strong group(s) fired: {', '.join(sorted(fired))} (< {need})"


def analyze(con: duckdb.DuckDBPyConnection, cfg: dict[str, Any]) -> dict[str, Any]:
    """The authenticity block for the registered `events` view (see module docstring)."""
    a = _acfg(cfg)
    if not a.get("enabled", True):
        return {"label": "unknown", "score": 0, "signals": [], "reason": "disabled in config/authenticity.yaml"}
    cols = _columns(con)
    if not {"ts_ms"} <= cols:
        return {"label": "unknown", "score": 0, "signals": [], "reason": "no events view (or no ts_ms column)"}
    r = con.execute(f"SELECT count(*), min(ts_ms), max(ts_ms) FROM events WHERE {_ok(cols)}").fetchone()
    rows = int(r[0] or 0)
    if rows < int(a["min_rows"]):
        return {"label": "unknown", "score": 0, "signals": [],
                "reason": f"{rows} rows with a valid timestamp < min_rows {a['min_rows']}"}
    span_h = (int(r[2]) - int(r[1])) / HOUR_MS
    sigs: list[dict[str, Any]] = []
    try:
        _build_hourly(con, cols, a)
        steps = (("flat_hourly_volume", lambda: _flat_volume(con, a, span_h)),
                 ("no_diurnal_cycle", lambda: _diurnal(con, a, span_h)),
                 ("uniform_host_rate", lambda: _host_rate(con, a)),
                 ("periodic_timer", lambda: _periodic(con, cols, a)),
                 ("low_template_diversity", lambda: _templates(con, cols, a, rows)))
        for sid, fn in steps:
            try:
                sigs.append(fn())
            except duckdb.Error as exc:  # one broken signal never stops the others
                log.warning("authenticity signal %s failed: %s", sid, exc)
                sigs.append(_signal(sid, None, None, False, f"error: {type(exc).__name__}"))
    finally:
        con.execute(f"DROP TABLE IF EXISTS {_HH}")
    label, score, reason = _label(sigs, a)
    log.info("authenticity: %s (score %d) %s", label, score,
             "; ".join(f"{s['id']}={s['value']}{'*' if s['fired'] else ''}" for s in sigs))
    return {"label": label, "score": int(score), "signals": sigs, "reason": reason}
