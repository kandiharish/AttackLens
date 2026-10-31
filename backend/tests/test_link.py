"""Stage 3 link tests (TESTING.md §4.4, DEVELOPMENT.md §4 Stage 3 + §15.7). Windows/multipliers are read from
config/linking.yaml via link.link_params, so tuning a window moves the boundary these tests probe."""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from attacklens import link

from .conftest import make_events_parquet, query, write_episodes

T0 = 1792807200000
MIN, H = 60_000, 3_600_000


@pytest.fixture
def ctx(tmp_path: Path):
    c = make_events_parquet(tmp_path, [{"ts_ms": T0, "action": "other", "host": "h"}])
    yield c
    c.con.close()


@pytest.fixture
def p(ctx) -> dict:
    return link.link_params(ctx.cfg)


def edges(ctx, eps: list[dict], hubs: list[str] | None = None, p: dict | None = None) -> list[dict]:
    write_episodes(ctx, eps, hubs)
    out = ctx.work_dir / "edges.parquet"
    link.link_episodes(ctx.con, ctx.work_dir / "episodes.parquet", ctx.work_dir / "background_hubs.parquet", out,
                       p or link.link_params(ctx.cfg))
    return query(ctx, f"SELECT * FROM read_parquet('{out.as_posix()}') ORDER BY i, j")


def pairs(rows: list[dict]) -> set[tuple[str, str, str]]:
    return {(r["i"], r["j"], r["rule"]) for r in rows}


def ep(eid: str, ts: int, host: str, tactic: str = "Execution", **kw) -> dict:
    return {"episode_id": eid, "ts_ms": ts, "host": host, "tactic": tactic, **kw}


# ---------------------------------------------------------------- R1 handoff
def test_r1_dst_host_to_subject_host_inside_window(ctx, p) -> None:
    tau = p["rules"]["R1"]["tau_ms"]
    rows = edges(ctx, [ep("a", T0, "ws-hr-07", dst_host="srv-fs-02", src_user="u1"),
                       ep("b", T0 + tau, "srv-fs-02", src_user="u2")])
    assert pairs(rows) == {("a", "b", "R1")}  # inclusive at exactly tau
    r = rows[0]
    assert r["dt_ms"] == tau
    assert r["weight"] == pytest.approx(round(p["rules"]["R1"]["mult"] * 1.0 * math.exp(-1.0), 6))
    assert r["why_linked"].startswith("Activity moved from ws-hr-07 to srv-fs-02 ")


def test_r1_outside_window_not_linked(ctx, p) -> None:
    tau = p["rules"]["R1"]["tau_ms"]
    rows = edges(ctx, [ep("a", T0, "ws-hr-07", dst_host="srv-fs-02", src_user="u1"),
                       ep("b", T0 + tau + 1, "srv-fs-02", src_user="u2")])
    assert rows == []


def test_r1_src_host_variant_uses_configured_window(ctx, p) -> None:
    r1 = p["rules"]["R1"]
    src_tau = r1.get("src_tau_ms") or r1["tau_ms"]
    base = [ep("a", T0, "ws-hr-07", src_user="u1")]
    inside = edges(ctx, base + [ep("b", T0 + src_tau, "srv-fs-02", src_host="ws-hr-07", src_user="u2")])
    assert pairs(inside) == {("a", "b", "R1")}
    outside = edges(ctx, base + [ep("b", T0 + src_tau + 1, "srv-fs-02", src_host="ws-hr-07", src_user="u2")])
    assert ("a", "b", "R1") not in pairs(outside)


def test_hub_allowed_as_r1_target_chain_stays_linked(ctx) -> None:
    # HR-07 -> FS-02 -> DC-01 with FS-02 a background hub: R1 may still land on it (PRD FR-5 example)
    rows = edges(ctx, [ep("a", T0, "ws-hr-07", dst_host="srv-fs-02", src_user="u1"),
                       ep("b", T0 + H, "srv-fs-02", dst_host="srv-dc-01", src_user="u2"),
                       ep("c", T0 + 2 * H, "srv-dc-01", src_user="u3")], hubs=["host:srv-fs-02"])
    assert pairs(rows) == {("a", "b", "R1"), ("b", "c", "R1")}


# ---------------------------------------------------------------- R2 session
def test_r2_same_host_and_user_inside_window(ctx, p) -> None:
    tau = p["rules"]["R2"]["tau_ms"]
    rows = edges(ctx, [ep("a", T0, "ws-fin-010", src_user="svc_backup"),
                       ep("b", T0 + 10 * MIN, "ws-fin-010", src_user="svc_backup"),
                       ep("c", T0 + tau, "ws-fin-010", src_user="svc_backup")])
    assert {(i, j) for i, j, r in pairs(rows) if r == "R2"} == {("a", "b"), ("a", "c"), ("b", "c")}
    ab = next(r for r in rows if (r["i"], r["j"]) == ("a", "b"))
    assert ab["weight"] == pytest.approx(round(p["rules"]["R2"]["mult"] * math.exp(-10 * MIN / tau), 6))
    assert ab["why_linked"] == "Same session: svc_backup on ws-fin-010, 10m00s apart"


@pytest.mark.parametrize("case", ["outside", "other_user", "other_host"])
def test_r2_near_misses(ctx, p, case: str) -> None:
    tau = p["rules"]["R2"]["tau_ms"]
    b = {"outside": ep("b", T0 + tau + 1, "ws-fin-010", src_user="svc_backup"),
         "other_user": ep("b", T0 + MIN, "ws-fin-010", src_user="pmehta"),
         "other_host": ep("b", T0 + MIN, "ws-fin-011", src_user="svc_backup")}[case]
    assert edges(ctx, [ep("a", T0, "ws-fin-010", src_user="svc_backup"), b]) == []


@pytest.mark.parametrize("hub", ["user:svc_backup", "host:ws-fin-010"])
def test_r2_hub_keys_barred(ctx, hub: str) -> None:
    rows = edges(ctx, [ep("a", T0, "ws-fin-010", src_user="svc_backup"),
                       ep("b", T0 + MIN, "ws-fin-010", src_user="svc_backup")], hubs=[hub])
    assert rows == []


# ---------------------------------------------------------------- R3 account pivot
def r3_pair(src_tactic: str = "Credential Access", conf: float = 85.0, dt: int = H) -> list[dict]:
    return [ep("a", T0, "srv-dc-01", tactic=src_tactic, target_user="svc_backup", confidence=conf),
            ep("b", T0 + dt, "ws-fin-010", tactic="Execution", src_user="svc_backup")]


def test_r3_acquired_account_then_used(ctx, p) -> None:
    rows = edges(ctx, r3_pair())
    assert pairs(rows) == {("a", "b", "R3")}
    assert rows[0]["why_linked"] == "Account svc_backup from step a used in step b"


def test_r3_inclusive_window_and_outside(ctx, p) -> None:
    tau = p["rules"]["R3"]["tau_ms"]
    assert pairs(edges(ctx, r3_pair(dt=tau))) == {("a", "b", "R3")}
    assert edges(ctx, r3_pair(dt=tau + 1)) == []


def test_r3_target_user_to_target_user(ctx, p) -> None:
    if not p.get("r3_match_target_user"):
        pytest.skip("r3_match_target_user disabled")
    rows = edges(ctx, [ep("a", T0, "srv-dc-01", tactic="Persistence", target_user="helpdesk_tmp", confidence=70),
                       ep("b", T0 + H, "srv-file-01", tactic="Lateral Movement", target_user="helpdesk_tmp")])
    assert pairs(rows) == {("a", "b", "R3")}


def test_r3_source_must_be_account_step_with_confidence(ctx, p) -> None:
    assert edges(ctx, r3_pair(src_tactic="Execution")) == []  # §15.7: source tactic filter
    low = float(p["r3_min_source_confidence"]) - 1
    assert edges(ctx, r3_pair(conf=low)) == []                 # §15.7: source confidence filter


def test_r3_hub_user_barred(ctx) -> None:
    assert edges(ctx, r3_pair(), hubs=["user:svc_backup"]) == []


# ---------------------------------------------------------------- R4 egress
def test_r4_collection_then_exfiltration_same_host(ctx, p) -> None:
    tau = p["rules"]["R4"]["tau_ms"]
    rows = edges(ctx, [ep("a", T0, "ws-fin-010", tactic="Collection", src_user="u1"),
                       ep("b", T0 + tau, "ws-fin-010", tactic="Exfiltration", src_user="u2",
                          dst_ip="198.51.100.23")])
    assert pairs(rows) == {("a", "b", "R4")}
    assert rows[0]["why_linked"] == "Data staged on ws-fin-010 sent to 198.51.100.23"


@pytest.mark.parametrize("case", ["reversed", "outside", "other_host"])
def test_r4_near_misses(ctx, p, case: str) -> None:
    tau = p["rules"]["R4"]["tau_ms"]
    a = ep("a", T0, "ws-fin-010", tactic="Collection", src_user="u1")
    b = {"reversed": ep("b", T0 - MIN, "ws-fin-010", tactic="Exfiltration", src_user="u2"),
         "outside": ep("b", T0 + tau + 1, "ws-fin-010", tactic="Exfiltration", src_user="u2"),
         "other_host": ep("b", T0 + MIN, "ws-fin-011", tactic="Exfiltration", src_user="u2")}[case]
    assert edges(ctx, [a, b]) == []


# ---------------------------------------------------------------- ordering, best edge, fan-out
def test_equal_timestamps_tie_break_on_source_seq(ctx) -> None:
    rows = edges(ctx, [ep("z", T0, "ws-fin-010", src_user="u", source_seq=3),
                       ep("y", T0, "ws-fin-010", src_user="u", source_seq=9)])
    assert pairs(rows) == {("z", "y", "R2")}  # lower source_seq first, regardless of id


def test_equal_ts_and_seq_tie_break_on_episode_id(ctx) -> None:
    rows = edges(ctx, [ep("e2", T0, "ws-fin-010", src_user="u", source_seq=5),
                       ep("e1", T0, "ws-fin-010", src_user="u", source_seq=5)])
    assert pairs(rows) == {("e1", "e2", "R2")}


def test_best_edge_per_pair(ctx, p) -> None:
    # a->b satisfies R2 (same host+user) and R3 (acquired account then used); exactly one edge, the heavier
    rows = edges(ctx, [ep("a", T0, "ws-fin-010", tactic="Credential Access", target_user="svc_backup",
                          confidence=85),
                       ep("b", T0 + 10 * MIN, "ws-fin-010", tactic="Execution", src_user="svc_backup",
                          target_user="svc_backup")])
    assert len(rows) == 1
    w = {r: p["rules"][r]["mult"] * math.exp(-10 * MIN / p["rules"][r]["tau_ms"]) for r in ("R2", "R3")}
    best = max(w, key=w.get)
    assert rows[0]["rule"] == best and rows[0]["weight"] == pytest.approx(round(w[best], 6))


def test_at_most_k_predecessors_per_rule(ctx, p) -> None:
    k = int(p["max_preds_per_rule"])
    preds = [ep(f"p{n}", T0 + n * MIN, "ws-fin-010", src_user="u") for n in range(k + 3)]
    j = ep("j", T0 + (k + 3) * MIN, "ws-fin-010", src_user="u")
    rows = [r for r in edges(ctx, preds + [j]) if r["j"] == "j"]
    assert sorted(r["i"] for r in rows) == sorted(f"p{n}" for n in range(3, k + 3))  # the k nearest


def test_rarity_scales_weight(ctx, p) -> None:
    rows = edges(ctx, [ep("a", T0, "ws-fin-010", src_user="u"), ep("b", T0, "ws-fin-010", src_user="u", rarity=0.5,
                                                                    source_seq=10)])
    assert rows[0]["weight"] == pytest.approx(0.5 * p["rules"]["R2"]["mult"])


def test_link_run_writes_edges_schema(ctx) -> None:
    write_episodes(ctx, [ep("a", T0, "ws-fin-010", src_user="u"), ep("b", T0 + MIN, "ws-fin-010", src_user="u")])
    stats = link.run(ctx)
    assert stats["edges"] == 1 and stats["edges_by_rule"] == {"R2": 1}
    desc = query(ctx, f"DESCRIBE SELECT * FROM read_parquet('{(ctx.work_dir / 'edges.parquet').as_posix()}')")
    assert [(d["column_name"], d["column_type"]) for d in desc] == [
        ("i", "VARCHAR"), ("j", "VARCHAR"), ("rule", "VARCHAR"), ("weight", "DOUBLE"), ("dt_ms", "BIGINT"),
        ("why_linked", "VARCHAR")]
