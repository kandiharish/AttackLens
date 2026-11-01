"""Scale rewrites of brute_force_then_success / password_spray (point-level windows, ASOF success pick) must give
exactly the raw_alerts of the original row-level SQL (kept here as the oracle), including on timestamp pile-ups
(many rows in one ts_ms), duplicate source_seq, window-edge gaps and several source IPs per burst."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import pytest

from attacklens import detect_sql
from attacklens import detect_templates as T
from attacklens.detect_sql import OK, ev_keys, ev_lines, evidence_chars, finish, rule_filter, window_bursts

from .conftest import make_events_parquet
from .test_detect import MIN, S, T0, fail, rule_of, run_template, success, th_of


# ---------------------------------------------------------------- oracle: the pre-rewrite row-level SQL
def _ref_gap_sessions(src: str, part: str, gap: int) -> str:
    return f"""
    gl AS (SELECT *, ts_ms - lag(ts_ms) OVER (PARTITION BY {part} ORDER BY ts_ms, source_seq) AS gap0 FROM {src}),
    gn AS (SELECT *, CASE WHEN gap0 IS NULL OR gap0 > {gap} THEN 1 ELSE 0 END AS nb FROM gl),
    ss AS (SELECT *, sum(nb) OVER (PARTITION BY {part} ORDER BY ts_ms, source_seq ROWS UNBOUNDED PRECEDING) AS sid,
                  CASE WHEN nb = 0 THEN gap0 END AS dt FROM gn)"""


def ref_bf(rule: dict[str, Any], th: dict[str, Any]) -> str:
    n, gap, sw = int(th["bf_min_failures"]), int(th["bf_gap_ms"]), int(th["bf_success_window_ms"])
    need_success = bool(th.get("bf_require_success", False))
    flt = rule_filter(rule)
    emit2 = bool(th.get("emit_t1078_on_bruteforce", True))
    key = T._bf_key(th)
    kc = ", ".join(key)
    nonnull = " AND ".join(f"{k} IS NOT NULL" for k in key)
    on_c = " AND ".join(f"e.{k} = c.{k}" for k in key)
    on_b = " AND ".join(f"b.{k} = sc.{k}" for k in key)
    ip_agg = "" if "src_ip" in key else "al_mode(list(src_ip)) AS src_ip, "
    core = f"""
    WITH f AS (SELECT ts_ms, source_seq, host, target_user, src_ip, raw_line FROM events
               WHERE {OK} AND action = 'login_failed' AND {nonnull}{flt}),
    cand AS (SELECT {kc} FROM f GROUP BY {kc} HAVING count(*) >= {n}),
    fc AS (SELECT f.* FROM f SEMI JOIN cand USING ({kc})),
    {_ref_gap_sessions('fc', kc, gap)},
    b AS (SELECT {kc}, sid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms,
                 min(source_seq) AS source_seq, count(*) AS n, {ip_agg}list(DISTINCT src_ip) AS ips,
                 {ev_lines(th)} AS ev, {ev_keys(th)} AS keys
          FROM ss GROUP BY {kc}, sid HAVING count(*) >= {n}),
    sc AS (SELECT e.ts_ms, e.source_seq, e.host, e.target_user, e.src_ip, e.raw_line
           FROM (SELECT * FROM events WHERE {OK} AND action = 'login_success'{flt}) e
           SEMI JOIN cand c ON {on_c}),
    cs AS (SELECT b.{kc.replace(', ', ', b.')}, b.sid, sc.ts_ms AS s_ts, sc.source_seq AS s_seq, sc.src_ip AS s_ip,
                  sc.raw_line AS s_line, coalesce(list_contains(b.ips, sc.src_ip), FALSE) AS same
           FROM b JOIN sc ON {on_b} AND sc.ts_ms >= b.last_ts_ms AND sc.ts_ms - b.last_ts_ms <= {sw}),
    pick AS (SELECT {kc}, sid, arg_min({{'s_ts': s_ts, 's_seq': s_seq, 's_ip': s_ip, 's_line': s_line}},
                                      {{'p': NOT same, 't': s_ts, 'q': s_seq}}) AS w
             FROM cs GROUP BY {kc}, sid),
    ok AS (SELECT b.*, pk.w.s_ts AS s_ts, pk.w.s_seq AS s_seq, pk.w.s_ip AS s_ip, pk.w.s_line AS s_line,
                  pk.w IS NOT NULL AS has_success
           FROM b LEFT JOIN pick pk USING ({kc}, sid))
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, host AS subject_host,
           NULL AS src_user, target_user, src_ip, NULL AS dst_ip, n AS raw_alert_count, ev AS evidence_lines,
           keys AS source_keys
    FROM ok WHERE {'has_success' if need_success else 'TRUE'}
    UNION ALL
    SELECT 'secondary', NULL, s_ts, s_ts, s_seq, host, host, NULL, target_user, s_ip, NULL, 1,
           [left(s_line, {evidence_chars(th)})], [s_seq]
    FROM ok WHERE has_success AND {'TRUE' if emit2 else 'FALSE'}
    """
    return finish(rule, core)


def ref_spray(rule: dict[str, Any], th: dict[str, Any]) -> str:
    n, win, sw = int(th["spray_min_users"]), int(th["spray_window_ms"]), int(th["bf_success_window_ms"])
    flt = rule_filter(rule)
    emit2 = bool(th.get("emit_t1078_on_bruteforce", True))
    core = f"""
    WITH f AS (SELECT ts_ms, source_seq, host, target_user, src_ip, raw_line FROM events
               WHERE {OK} AND action = 'login_failed' AND src_ip IS NOT NULL AND target_user IS NOT NULL{flt}),
    cand AS (SELECT src_ip FROM f GROUP BY src_ip HAVING count(DISTINCT target_user) >= {n}),
    r AS (SELECT f.* FROM f SEMI JOIN cand USING (src_ip)),
    {window_bursts('src_ip', win, 'count(DISTINCT target_user)', f'wv >= {n}')},
    b AS (SELECT src_ip, bid, min(ts_ms) AS ts_ms, max(ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
                 count(*) AS n, al_mode(list(host)) AS host, {ev_lines(th)} AS ev, {ev_keys(th)} AS keys
          FROM mb GROUP BY src_ip, bid HAVING count(DISTINCT target_user) >= {n}),
    sc AS (SELECT e.ts_ms, e.source_seq, e.host, e.target_user, e.src_ip, e.raw_line
           FROM (SELECT * FROM events WHERE {OK} AND action = 'login_success'{flt}) e
           SEMI JOIN cand c ON e.src_ip = c.src_ip),
    bs AS (SELECT b.*, sc.ts_ms AS s_ts, sc.source_seq AS s_seq, sc.host AS s_host, sc.target_user AS s_user,
                  sc.raw_line AS s_line
           FROM b ASOF LEFT JOIN sc ON b.src_ip = sc.src_ip AND sc.ts_ms >= b.last_ts_ms)
    SELECT 'primary' AS label, NULL AS sub_technique_id, ts_ms, last_ts_ms, source_seq, host, host AS subject_host,
           NULL AS src_user, CASE WHEN s_ts - last_ts_ms <= {sw} THEN s_user END AS target_user, src_ip,
           NULL AS dst_ip, n AS raw_alert_count, ev AS evidence_lines, keys AS source_keys
    FROM bs
    UNION ALL
    SELECT 'secondary', NULL, s_ts, s_ts, s_seq, s_host, s_host, NULL, s_user, src_ip, NULL, 1,
           [left(s_line, {evidence_chars(th)})], [s_seq]
    FROM bs WHERE s_ts IS NOT NULL AND s_ts - last_ts_ms <= {sw} AND {'TRUE' if emit2 else 'FALSE'}
    """
    return finish(rule, core)


REF = {"brute_force_then_success": ref_bf, "password_spray": ref_spray}


def _diff(ctx, rule_id: str, **over: Any) -> tuple[int, int, int]:
    """(rows, new EXCEPT ALL ref, ref EXCEPT ALL new) for one rule on ctx."""
    rule = rule_of(ctx.cfg, rule_id)
    th = th_of(ctx.cfg, **over)
    new = T.TEMPLATES[rule["template"]](ctx.con, rule, th)
    ref = REF[rule["template"]](rule, th)
    con = ctx.con
    n = con.execute(f"SELECT count(*) FROM ({ref})").fetchone()[0]
    a = con.execute(f"SELECT count(*) FROM (({new}) EXCEPT ALL ({ref}))").fetchone()[0]
    b = con.execute(f"SELECT count(*) FROM (({ref}) EXCEPT ALL ({new}))").fetchone()[0]
    return n, a, b


@pytest.fixture
def ev(tmp_path: Path):
    made: list = []

    def _make(rows: list[dict]):
        ctx = make_events_parquet(tmp_path / f"c{len(made)}", rows)
        made.append(ctx)
        detect_sql.prepare(ctx.con, ctx.cfg)
        return ctx

    yield _make
    for c in made:
        c.con.close()


# ---------------------------------------------------------------- pinned semantics on pile-ups
def test_bf_pileup_one_second_is_one_burst(ev) -> None:
    rows = [fail(T0) for _ in range(60)] + [success(T0 + 2 * MIN)]
    ctx = ev(rows)
    assert _diff(ctx, "brute_force_then_success") == (2, 0, 0)


def test_spray_pileup_all_users_one_ts_fires(ev) -> None:
    rows = [fail(T0, user=f"u{i:02d}", host="srv-web-01", ip="192.0.2.88") for i in range(16) for _ in range(5)]
    ctx = ev(rows)
    assert _diff(ctx, "password_spray") == (1, 0, 0)


@pytest.mark.parametrize("gap", [10 * MIN - 1, 10 * MIN, 10 * MIN + 1])
def test_spray_window_edges_match_reference(ev, gap: int) -> None:
    # 14 users at T0, the 15th user exactly gap ms later; one of the 14 repeats at T0 + gap (run merge edge)
    rows = [fail(T0, user=f"u{i:02d}", ip="192.0.2.88") for i in range(14)]
    rows += [fail(T0 + gap, user="u99", ip="192.0.2.88"), fail(T0 + gap, user="u00", ip="192.0.2.88")]
    rows += [fail(T0 + 2 * gap + 1, user=f"u{i:02d}", ip="192.0.2.88") for i in range(15)]
    assert _diff(ev(rows), "password_spray")[1:] == (0, 0)


@pytest.mark.parametrize("gap", [10 * MIN, 10 * MIN + 1])
def test_bf_gap_edges_match_reference(ev, gap: int) -> None:
    rows = [fail(T0 + i * S) for i in range(30)] + [fail(T0 + 29 * S + gap + i * S) for i in range(30)]
    assert _diff(ev(rows), "brute_force_then_success", bf_min_failures=25)[1:] == (0, 0)


def test_bf_success_prefers_burst_ip_then_earliest(ev) -> None:
    f = [fail(T0 + i * S, ip=("203.0.113.5" if i % 2 else "203.0.113.6")) for i in range(50)]
    end = f[-1]["ts_ms"]
    s = [success(end + MIN, ip="198.51.100.9"), success(end + 3 * MIN, ip="203.0.113.6"),
         success(end + 2 * MIN, ip="203.0.113.5"), success(end + 2 * MIN, ip="203.0.113.6")]
    ctx = ev(f + s)
    n, a, b = _diff(ctx, "brute_force_then_success")
    assert (n, a, b) == (2, 0, 0)


# ---------------------------------------------------------------- byte-identical duplicates (same ts_ms + source_seq)
# The old row-level SQL ordered windows by (ts_ms, source_seq), a tie for duplicates: lag() and the running sum()
# could see the copies in different orders, so copies of one line could land in different bursts (the oracle is
# non-deterministic here, measured: 2 copies at t1 + 2 of 3 copies at t1 + 20 min reported as one 4-row burst).
# The point-level SQL keeps every copy of a line in the burst of its ts_ms; these tests pin that.
def _dups(ts: int, k: int, seq: int, **kw: Any) -> list[dict]:
    return [dict(fail(ts, **kw), source_seq=seq, raw_line=f"line-{seq}") for _ in range(k)]


def test_bf_duplicate_lines_never_split_across_bursts(ev) -> None:
    rows = _dups(T0, 2, 11) + _dups(T0 + 20 * MIN, 3, 12)   # 20 min > bf_gap_ms: bursts of 2 and 3
    assert run_template(ev(rows), "brute_force_then_success", bf_min_failures=4) == []
    rows = _dups(T0, 3, 11) + _dups(T0 + MIN, 2, 12)        # one burst of all 5 copies
    out = run_template(ev(rows), "brute_force_then_success", bf_min_failures=4)
    assert [(r["ts_ms"], r["last_ts_ms"], r["raw_alert_count"]) for r in out] == [(T0, T0 + MIN, 5)]


def test_spray_duplicate_lines_never_split_across_bursts(ev) -> None:
    users = [f"u{i:02d}" for i in range(4)]
    rows = [r for i, u in enumerate(users) for r in _dups(T0, 2, 100 + i, user=u, ip="192.0.2.88")]
    rows += [r for i, u in enumerate(users) for r in _dups(T0 + 30 * MIN, 3, 200 + i, user=u, ip="192.0.2.88")]
    out = run_template(ev(rows), "password_spray", spray_min_users=4)
    assert [(r["ts_ms"], r["raw_alert_count"]) for r in out] == [(T0, 8), (T0 + 30 * MIN, 12)]


# ---------------------------------------------------------------- randomized differential (oracle = old SQL)
# Unique source_seq per row (the oracle is only defined without (ts_ms, source_seq) ties); same-ts rows included.
def _random_rows(seed: int) -> list[dict]:
    rnd = random.Random(seed)
    users = [f"u{i:02d}" for i in range(6)]
    ips = ["203.0.113.5", "203.0.113.6", "198.51.100.9", None]
    hosts = ["srv-dc-01", "srv-web-01"]
    rows: list[dict] = []
    t = T0
    for _ in range(rnd.randint(150, 400)):
        t += rnd.choice([0, 0, 0, 1, S, 30 * S, 5 * MIN, 10 * MIN, 10 * MIN + 1, 16 * MIN])
        ip, host = rnd.choice(ips), rnd.choice(hosts)
        if rnd.random() < 0.08:   # successes: unique ts (tied successes have no defined pick in either SQL)
            t += 1
            rows.append(success(t, user=rnd.choice(users), host=host, ip=ip))
            continue
        for _ in range(rnd.choice([1, 1, 1, 3])):     # same-ts rows (pile-up)
            rows.append(fail(t, user=rnd.choice(users), host=host, ip=ip))
    return rows


@pytest.mark.parametrize("seed", range(8))
def test_random_differential_bf_and_spray(ev, seed: int) -> None:
    ctx = ev(_random_rows(seed))
    seen: dict[str, int] = {}
    small = {"bf_min_failures": 4, "spray_min_users": 4, "spray_window_ms": 10 * MIN}
    for rid, over in [("brute_force_then_success", small),
                      ("brute_force_then_success", {**small, "bf_key": ["src_ip", "target_user", "host"]}),
                      ("brute_force_then_success", {**small, "bf_require_success": True}),
                      ("password_spray", small)]:
        n, a, b = _diff(ctx, rid, **over)
        assert (a, b) == (0, 0), f"{rid} {over}: {n} ref rows, {a} new-only, {b} ref-only"
        seen[rid] = seen.get(rid, 0) + n
    assert all(seen.values()), f"seed {seed}: a case produced no alerts, the comparison is vacuous: {seen}"
