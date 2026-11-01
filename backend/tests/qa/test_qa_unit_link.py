"""QA unit / white-box tests for Stage 3 (attacklens.link), track qa_coverage_unit.

Baseline coverage showed these branches never ran: episode_select fallbacks for an older / narrower episodes
schema (merged_alert_count from raw_alert_count, user = coalesce(target_user, src_user), subject_host = host,
absent columns as typed NULL), link.run without episodes.parquet, and the three config switches
r1_ext_ip / r2_ext_ip_session / r3_match_target_user turned off. Each switch: on = exact edge, off = no edge.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from attacklens import link

from ..conftest import make_events_parquet, query, write_episodes

T0 = 1792807200000
MIN = 60_000


@pytest.fixture
def ctx(tmp_path: Path):
    c = make_events_parquet(tmp_path, [{"ts_ms": T0, "action": "other", "host": "h"}])
    yield c
    c.con.close()


def _edges(ctx, eps: list[dict], **switches) -> set[tuple[str, str, str]]:
    p = {**link.link_params(ctx.cfg), **switches}
    write_episodes(ctx, eps)
    out = ctx.work_dir / "edges.parquet"
    link.link_episodes(ctx.con, ctx.work_dir / "episodes.parquet", ctx.work_dir / "background_hubs.parquet", out, p)
    return {(r["i"], r["j"], r["rule"]) for r in query(ctx, f"SELECT * FROM read_parquet('{out.as_posix()}')")}


def ep(eid: str, ts: int, host: str, tactic: str = "Execution", **kw) -> dict:
    return {"episode_id": eid, "ts_ms": ts, "host": host, "tactic": tactic, **kw}


# ---- switches ------------------------------------------------------------------------------------------------------
def test_r3_match_target_user_switch(ctx) -> None:
    eps = [ep("i", T0, "srv-a", "Credential Access", target_user="bob", confidence=85),
           ep("j", T0 + 10 * MIN, "srv-b", "Execution", target_user="bob", confidence=70)]
    assert _edges(ctx, eps) == {("i", "j", "R3")}
    assert _edges(ctx, eps, r3_match_target_user=False) == set()       # j has no src_user: no other R3 key


def test_r3_src_user_still_links_when_switch_off(ctx) -> None:
    eps = [ep("i", T0, "srv-a", "Credential Access", target_user="bob", confidence=85),
           ep("j", T0 + 10 * MIN, "srv-b", "Execution", src_user="bob", confidence=70)]
    assert _edges(ctx, eps, r3_match_target_user=False) == {("i", "j", "R3")}   # near miss: tu -> su stays


def test_r1_ext_ip_switch(ctx) -> None:
    eps = [ep("i", T0, "srv-a", "Initial Access", src_ip="203.0.113.5", target_user="u1"),
           ep("j", T0 + 5 * MIN, "srv-b", "Execution", src_ip="203.0.113.5", target_user="u2")]
    assert _edges(ctx, eps) == {("i", "j", "R1")}
    assert _edges(ctx, eps, r1_ext_ip=False) == set()


def test_r1_ext_ip_internal_ip_near_miss(ctx) -> None:
    eps = [ep("i", T0, "srv-a", "Initial Access", src_ip="10.1.2.3", target_user="u1"),
           ep("j", T0 + 5 * MIN, "srv-b", "Execution", src_ip="10.1.2.3", target_user="u2")]
    assert _edges(ctx, eps) == set()                                     # internal src_ip is not an attacker IP


def test_r2_ext_ip_session_switch(ctx) -> None:
    eps = [ep("i", T0, "srv-a", "Initial Access", src_ip="203.0.113.5", target_user="u1"),
           ep("j", T0 + 5 * MIN, "srv-a", "Execution", src_ip="203.0.113.5", target_user="u2")]
    assert _edges(ctx, eps) == {("i", "j", "R2")}
    assert _edges(ctx, eps, r2_ext_ip_session=False) == set()           # users differ: plain R2 needs one user


# ---- episode_select fallbacks ---------------------------------------------------------------------------------------
def test_episode_select_fallbacks_for_narrow_schema(tmp_path: Path) -> None:
    con = duckdb.connect()
    p = tmp_path / "eps.parquet"
    try:
        con.execute(f"""COPY (SELECT 'e1' AS episode_id, 1000::BIGINT AS ts_ms, 'WS-1' AS host, 'alice' AS src_user,
                           NULL::VARCHAR AS target_user, 7::INTEGER AS raw_alert_count)
                        TO '{p.as_posix()}' (FORMAT PARQUET)""")
        cur = con.execute(link.episode_select(con, p))
        cols = [d[0] for d in cur.description]
        row = dict(zip(cols, cur.fetchone()))
    finally:
        con.close()
    assert cols == list(link.EPISODE_COLUMNS)
    assert (row["merged_alert_count"], row["raw_alert_count"]) == (7, 7)
    assert (row["user"], row["subject_host"], row["host"]) == ("alice", "WS-1", "WS-1")
    assert row["confidence"] is None and row["evidence_lines"] is None and row["is_seed"] is None


def test_episode_select_user_null_without_both_user_columns(tmp_path: Path) -> None:
    con = duckdb.connect()
    p = tmp_path / "eps.parquet"
    try:
        con.execute(f"COPY (SELECT 'e1' AS episode_id, 1::BIGINT AS ts_ms, 'bob' AS src_user) "
                    f"TO '{p.as_posix()}' (FORMAT PARQUET)")
        cur = con.execute(link.episode_select(con, p))
        row = dict(zip([d[0] for d in cur.description], cur.fetchone()))
    finally:
        con.close()
    # only src_user present -> user is NULL (the fallback needs both columns), subject_host NULL (no host)
    assert (row["user"], row["subject_host"], row["merged_alert_count"]) == (None, None, None)


def test_link_run_without_episodes_writes_empty_edges(ctx) -> None:
    stats = link.run(ctx)
    out = ctx.work_dir / "edges.parquet"
    desc = ctx.con.execute(f"DESCRIBE SELECT * FROM read_parquet('{out.as_posix()}')").fetchall()
    n = ctx.con.execute(f"SELECT count(*) FROM read_parquet('{out.as_posix()}')").fetchone()[0]
    assert stats == {"episodes": 0, "edges": 0, "edges_by_rule": {}}
    assert [(r[0], r[1]) for r in desc] == [("i", "VARCHAR"), ("j", "VARCHAR"), ("rule", "VARCHAR"),
                                            ("weight", "DOUBLE"), ("dt_ms", "BIGINT"), ("why_linked", "VARCHAR")]
    assert n == 0


@pytest.mark.parametrize("ms, text", [(0, "0s"), (45_000, "45s"), (59_999, "59s"), (60_000, "1m00s"),
                                      (439_000, "7m19s"), (3_600_000, "1h00m"), (7_500_000, "2h05m"),
                                      (86_400_000, "1d00h"), (97_200_000, "1d03h")])
def test_dt_text_exact(ms: int, text: str) -> None:
    con = duckdb.connect()
    try:
        assert con.execute(f"SELECT {link._dt_text(str(ms))}").fetchone()[0] == text
    finally:
        con.close()


def test_link_params_merge_keeps_rule_defaults() -> None:
    p = link.link_params({"linking": {"link": {"rules": {"R2": {"tau_ms": 5}}, "max_preds_per_rule": 2}}})
    assert p["rules"]["R2"] == {"tau_ms": 5, "mult": 1.0}               # mult kept from defaults
    assert p["rules"]["R1"] == link.DEFAULT_LINK["rules"]["R1"]
    assert p["max_preds_per_rule"] == 2 and p["r1_ext_ip"] is True
    assert link.link_params({}) ["rules"] == link.DEFAULT_LINK["rules"]
