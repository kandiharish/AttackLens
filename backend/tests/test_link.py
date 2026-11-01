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


def test_r1_both_host_variants_match_keeps_k_preds(ctx, p) -> None:
    # nearest source a4 (ws-a -> ws-b) matches j by i.dst_host AND by j.src_host: one candidate, not two top-k slots
    k = int(p["max_preds_per_rule"])
    eps = [ep(f"a{n}", T0 + n * MIN, "ws-a" if n == k - 1 else f"ws-{n:02d}", tactic="Lateral Movement",
              dst_host="ws-b") for n in range(k)]
    eps.append(ep("j", T0 + (k + 5) * MIN, "ws-b", src_host="ws-a"))
    assert sorted(r["i"] for r in edges(ctx, eps) if r["j"] == "j" and r["rule"] == "R1") == \
        [f"a{n}" for n in range(k)]


def test_r1_host_and_ext_ip_variants_match_one_edge(ctx) -> None:
    # same pair by host handoff and by external src_ip: one R1 row, deterministic why_linked (lowest text)
    eps = [ep("a", T0, "ws-a", dst_host="ws-b", src_ip="203.0.113.66"),
           ep("b", T0 + 30 * MIN, "ws-b", src_ip="203.0.113.66")]
    rows = edges(ctx, eps)
    assert [(r["i"], r["j"], r["rule"]) for r in rows] == [("a", "b", "R1")]
    assert rows[0]["why_linked"] == "Activity from 203.0.113.66 moved from ws-a to ws-b 30m00s later"


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


def r3_same_host(dt: int) -> list[dict]:
    return [ep("a", T0, "srv-dc-01", tactic="Credential Access", target_user="svc_backup", confidence=85.0),
            ep("b", T0 + dt, "srv-dc-01", tactic="Execution", src_user="svc_backup")]


def r3_only(rows: list[dict]) -> set[tuple[str, str, str]]:
    return {x for x in pairs(rows) if x[2] == "R3"}  # same-host pairs may also get an R2 edge; this probes R3


def test_r3_cross_host_window_inclusive_and_outside(ctx, p) -> None:
    cross, tau = p["rules"]["R3"]["cross_host_tau_ms"], p["rules"]["R3"]["tau_ms"]
    assert cross < tau                                                   # otherwise the split is untested
    assert pairs(edges(ctx, r3_pair(dt=cross))) == {("a", "b", "R3")}    # srv-dc-01 -> ws-fin-010: cross-host
    assert edges(ctx, r3_pair(dt=cross + 1)) == []
    assert edges(ctx, r3_pair(dt=tau)) == []                             # the 72 h window is NOT used cross-host


def test_r3_same_host_window_inclusive_and_outside(ctx, p) -> None:
    tau = p["rules"]["R3"]["tau_ms"]
    assert r3_only(edges(ctx, r3_same_host(tau))) == {("a", "b", "R3")}
    assert r3_only(edges(ctx, r3_same_host(tau + 1))) == set()


def test_r3_cross_host_falls_back_to_tau_when_absent(ctx, p) -> None:
    q = {**p, "rules": {**p["rules"], "R3": {k: v for k, v in p["rules"]["R3"].items()
                                             if k != "cross_host_tau_ms"}}}
    tau = q["rules"]["R3"]["tau_ms"]
    assert pairs(edges(ctx, r3_pair(dt=tau), p=q)) == {("a", "b", "R3")}
    assert edges(ctx, r3_pair(dt=tau + 1), p=q) == []


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



# ================================================================ R3 fan-out cap per source (linking.yaml r3_max_succs_per_source)
def r3_fan(n: int) -> list[dict]:
    """One Credential Access source on srv-dc-01 and n later uses of its account on the SAME host (72 h R3 window)."""
    src = ep("a", T0, "srv-dc-01", tactic="Credential Access", target_user="svc_backup", confidence=85)
    return [src] + [ep(f"j{k:02d}", T0 + (k + 1) * H, "srv-dc-01", tactic="Execution", src_user="svc_backup")
                    for k in range(n)]


def test_r3_cap_per_source(ctx, p) -> None:
    cap = int(p["r3_max_succs_per_source"])
    assert 0 < cap < 20 and 20 * H <= p["rules"]["R3"]["tau_ms"]   # all 20 inside the same-host window
    rows = [r for r in edges(ctx, r3_fan(20)) if r["i"] == "a" and r["rule"] == "R3"]
    assert sorted(r["j"] for r in rows) == [f"j{k:02d}" for k in range(cap)]  # the cap nearest (heaviest) successors


def test_r3_cap_off_keeps_all_within_window(ctx, p) -> None:
    q = {**p, "r3_max_succs_per_source": 0}
    rows = [r for r in edges(ctx, r3_fan(20), p=q) if r["i"] == "a" and r["rule"] == "R3"]
    assert sorted(r["j"] for r in rows) == [f"j{k:02d}" for k in range(20)]  # same host: 72 h, only the cap limits


def test_r3_cap_applies_to_cross_host_successors_too(ctx, p) -> None:
    cap, cross = int(p["r3_max_succs_per_source"]), p["rules"]["R3"]["cross_host_tau_ms"]
    src = ep("a", T0, "srv-dc-01", tactic="Credential Access", target_user="svc_backup", confidence=85)
    step = cross // (cap + 3)
    eps = [src] + [ep(f"x{k}", T0 + (k + 1) * step, f"ws-{k:02d}", src_user="svc_backup") for k in range(cap + 2)]
    rows = [r for r in edges(ctx, eps) if r["i"] == "a" and r["rule"] == "R3"]
    assert sorted(r["j"] for r in rows) == [f"x{k}" for k in range(cap)]


def test_r3_self_logon_successor_keeps_k_preds(ctx, p) -> None:
    # j with src_user == target_user matches both the j.su and the j.tu variant; one copy each, not two slots
    if not p.get("r3_match_target_user"):
        pytest.skip("r3_match_target_user disabled")
    k = int(p["max_preds_per_rule"])
    eps = [ep(f"a{n}", T0 + n * MIN, f"srv-{n:02d}", tactic="Credential Access", target_user="svc_backup",
              confidence=85) for n in range(k)]
    eps.append(ep("j", T0 + H, "ws-fin-010", src_user="svc_backup", target_user="svc_backup"))
    assert sorted(r["i"] for r in edges(ctx, eps) if r["j"] == "j" and r["rule"] == "R3") == \
        [f"a{n}" for n in range(k)]


def test_r3_cap_counts_self_logon_successor_once(ctx, p) -> None:
    cap = int(p["r3_max_succs_per_source"])
    eps = [{**e, "target_user": e.get("src_user") or e["target_user"]} for e in r3_fan(cap)]  # j: su == tu
    rows = [r for r in edges(ctx, eps) if r["i"] == "a" and r["rule"] == "R3"]
    assert sorted(r["j"] for r in rows) == [f"j{k:02d}" for k in range(cap)]


# ================================================================ log devices and IP sessions (FortiGate entities)
DEV = "fgt-01"


def dev_ep(eid: str, ts: int, **kw) -> dict:
    return ep(eid, ts, DEV, subject_host=kw.pop("subject_host", DEV), **kw)


def test_userless_device_episodes_no_r2(ctx) -> None:
    rows = edges(ctx, [dev_ep(f"d{k:02d}", T0 + k * 3 * MIN) for k in range(30)])  # 30 within 2 h (87 min)
    assert [r for r in rows if r["rule"] == "R2"] == []


def test_device_barred_as_r2_key_even_with_a_user(ctx) -> None:
    eps = [dev_ep(f"d{k:02d}", T0 + k * 3 * MIN, target_user="admin") for k in range(30)]
    eps.append(dev_ep("x", T0 - H, subject_host="10.0.2.37"))  # the devname logs another subject -> a device
    rows = edges(ctx, eps)
    assert [r for r in rows if r["rule"] == "R2"] == []


def test_device_with_user_links_when_not_detected_as_device(ctx, p) -> None:
    # control for the test above: without the device-revealing episode (and auto detection) R2 links them
    q = {**p, "auto_device_hosts": False}
    eps = [dev_ep(f"d{k}", T0 + k * MIN, target_user="admin") for k in range(2)]
    assert pairs(edges(ctx, eps, p=q)) == {("d0", "d1", "R2")}


def test_configured_device_hosts_barred_as_r2_key(ctx, p) -> None:
    # link._prepare inserts device_hosts with one columnar unnest (lower-cased); auto detection off isolates it.
    # The control is test_device_with_user_links_when_not_detected_as_device (same episodes, no device_hosts).
    eps = [dev_ep(f"d{k}", T0 + k * MIN, target_user="admin") for k in range(2)]
    q = {**p, "auto_device_hosts": False, "device_hosts": ["FGT-01", "other-fw", "it's-fw"]}
    assert [r for r in edges(ctx, eps, p=q) if r["rule"] == "R2"] == []
    near = {**p, "auto_device_hosts": False, "device_hosts": ["fgt-02"]}           # near miss: another device
    assert pairs(edges(ctx, eps, p=near)) == {("d0", "d1", "R2")}


IP = "10.0.2.37"


def ip_ep(eid: str, ts: int, rule_id: str, conf: float, **kw) -> dict:
    """User-less episode on IP endpoint IP, logged by the device DEV (FortiGate shape)."""
    return ep(eid, ts, DEV, subject_host=IP, rule_id=rule_id, confidence=conf, **kw)


def ip_cfg(p: dict) -> tuple[float, int]:
    """(min confidence, R2 tau). Fails loudly if linking.yaml stops gating the user-less IP session: the near
    misses below would otherwise pass for the wrong reason (n30: 22 985 of 23 169 R2 edges were this variant)."""
    mc = float(p["r2_ip_session_min_confidence"])
    assert p["r2_ip_session"] is True and p["r2_ip_session_distinct_rules"] is True and mc > 1
    return mc, int(p["rules"]["R2"]["tau_ms"])


def test_userless_ip_session_r2(ctx, p) -> None:
    mc, tau = ip_cfg(p)
    a = lambda: ip_ep("a", T0, "port_scan", mc)  # noqa: E731  exactly at the threshold: inclusive
    rows = edges(ctx, [a(), ip_ep("b", T0 + 30 * MIN, "internal_lateral", 10)])
    assert pairs(rows) == {("a", "b", "R2")}   # one end >= mc is enough (b at 10 is far below)
    assert rows[0]["why_linked"] == "Same session: endpoint on 10.0.2.37, 30m00s apart"
    assert rows[0]["dt_ms"] == 30 * MIN
    assert rows[0]["weight"] == pytest.approx(round(p["rules"]["R2"]["mult"] * math.exp(-30 * MIN / tau), 6))
    late = edges(ctx, [a(), ip_ep("b", T0 + tau + 1, "internal_lateral", 80)])
    assert late == []


def test_userless_ip_session_confident_end_may_be_j(ctx, p) -> None:
    # the threshold is "either end", not "the predecessor": a weak scan followed by a confident lateral step links
    mc, _ = ip_cfg(p)
    rows = edges(ctx, [ip_ep("a", T0, "port_scan", mc - 1), ip_ep("b", T0 + 30 * MIN, "internal_lateral", mc)])
    assert pairs(rows) == {("a", "b", "R2")}


def test_userless_ip_session_same_rule_not_linked(ctx, p) -> None:
    # n30 noise shape: ips_signatures -> ips_signatures on one IP, both confident, zero seconds apart
    ip_cfg(p)
    same = edges(ctx, [ip_ep("a", T0, "ips_signatures", 95), ip_ep("b", T0, "ips_signatures", 95)])
    assert same == []
    control = edges(ctx, [ip_ep("a", T0, "ips_signatures", 95), ip_ep("b", T0, "port_scan", 95)])
    assert pairs(control) == {("a", "b", "R2")}  # only the rule id differs


def test_userless_ip_session_both_ends_below_threshold_not_linked(ctx, p) -> None:
    mc, _ = ip_cfg(p)
    weak = edges(ctx, [ip_ep("a", T0, "port_scan", mc - 1), ip_ep("b", T0 + MIN, "internal_lateral", mc - 1)])
    assert weak == []
    control = edges(ctx, [ip_ep("a", T0, "port_scan", mc), ip_ep("b", T0 + MIN, "internal_lateral", mc - 1)])
    assert pairs(control) == {("a", "b", "R2")}  # one point of confidence on one end flips it


def test_userless_ip_session_window_from_end_of_long_episode(ctx, p) -> None:
    mc, tau = ip_cfg(p)
    assert p["window_from"] == "end"
    i_end = T0 + tau + H                     # i runs longer than the whole R2 window
    j_ts = i_end + 30 * MIN                  # 30 min after i ENDS, tau + 90 min after i STARTS
    eps = [ip_ep("a", T0, "port_scan", mc, last_ts_ms=i_end), ip_ep("b", j_ts, "internal_lateral", 10)]
    rows = edges(ctx, eps)
    assert pairs(rows) == {("a", "b", "R2")}
    assert rows[0]["dt_ms"] == 30 * MIN      # gap measured from i's end, not j.ts - i.ts
    assert rows[0]["why_linked"] == "Same session: endpoint on 10.0.2.37, 30m00s apart"
    assert edges(ctx, eps, p={**p, "window_from": "start"}) == []   # literal start-to-start: outside tau
    late = [eps[0], ip_ep("b", i_end + tau + 1, "internal_lateral", 10)]
    assert edges(ctx, late) == []            # still bounded by tau after i's end


def test_userless_ip_session_distinct_rule_pred_not_crowded_out(ctx, p) -> None:
    # n30 shape: a confident port scan, then an ips_signatures flood on the same IP; j (ips_signatures) must still
    # get its only eligible predecessor, the scan, 10 min earlier and well inside tau
    mc, _ = ip_cfg(p)
    k = int(p["max_preds_per_rule"])
    eps = [ip_ep("ps", T0, "port_scan", mc)]
    eps += [ip_ep(f"s{n}", T0 + (n + 1) * MIN, "ips_signatures", 95) for n in range(k)]
    eps.append(ip_ep("j", T0 + (k + 5) * MIN, "ips_signatures", 95))
    assert {r["i"] for r in edges(ctx, eps) if r["j"] == "j"} == {"ps"}


def test_userless_ip_session_both_confident_keeps_k_preds(ctx, p) -> None:
    mc, _ = ip_cfg(p)
    k = int(p["max_preds_per_rule"])
    eps = [ip_ep(f"p{n}", T0 + n * MIN, f"rule_{n}", mc) for n in range(k)]
    eps.append(ip_ep("j", T0 + (k + 5) * MIN, "rule_j", mc))
    assert sorted(r["i"] for r in edges(ctx, eps) if r["j"] == "j") == [f"p{n}" for n in range(k)]


def test_userless_ip_session_off(ctx, p) -> None:
    mc, _ = ip_cfg(p)
    eps = [ip_ep("a", T0, "port_scan", mc), ip_ep("b", T0 + MIN, "internal_lateral", mc)]
    assert pairs(edges(ctx, eps)) == {("a", "b", "R2")}            # control: the toggle is what removes it
    assert edges(ctx, eps, p={**p, "r2_ip_session": False}) == []


def ext_pair(src_ip: str, dt: int) -> list[dict]:
    return [dev_ep("fw", T0, src_ip=src_ip, target_user="admin", tactic="Credential Access", confidence=40),
            dev_ep("rdp", T0 + dt, subject_host="10.10.20.15", src_ip=src_ip, tactic="Lateral Movement")]


def test_r1_same_external_src_ip_on_device_then_internal_host(ctx, p) -> None:
    rows = edges(ctx, ext_pair("203.0.113.66", 30 * MIN))
    assert pairs(rows) == {("fw", "rdp", "R1")}
    assert rows[0]["why_linked"] == "Activity from 203.0.113.66 moved from fgt-01 to 10.10.20.15 30m00s later"


@pytest.mark.parametrize("case", ["internal_src_ip", "outside_ext_window"])
def test_r1_ext_ip_near_misses(ctx, p, case: str) -> None:
    tau = p["rules"]["R1"].get("ext_ip_tau_ms") or p["rules"]["R1"]["tau_ms"]
    eps = ext_pair("10.0.9.9", 30 * MIN) if case == "internal_src_ip" else ext_pair("203.0.113.66", tau + 1)
    assert edges(ctx, eps) == []


def test_r1_ext_ip_hub_barred(ctx) -> None:
    assert edges(ctx, ext_pair("203.0.113.66", 30 * MIN), hubs=["ip:203.0.113.66"]) == []


def test_link_stats_report_devices(ctx) -> None:
    write_episodes(ctx, [dev_ep("x", T0, subject_host="10.0.2.37"), ep("y", T0, "ws-01", src_user="u")])
    stats = link.run(ctx)
    assert stats["devices"] == [DEV]
