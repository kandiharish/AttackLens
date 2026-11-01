"""qa_mutation: tests that kill the important survivors of the mutation smoke (tools/qa/mutate.py, catalogue in
tools/qa/mutants.py, report reports/qa/qa_mutation.md). Each test names the mutant id(s) it kills. All values are
hand-checked on tiny inputs; every test passes on the real code and fails on its mutant.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from attacklens import config, episodes, incident_gate, link
from attacklens.api_upload import UploadConfig, UploadError, UploadManager
from attacklens.ingest_sql import ts_expr
from attacklens.paths import Edge, Node, best_path
from attacklens.schemas import TACTIC_IDX

from ..conftest import query, run_ingest, write_episodes, make_events_parquet
from ..sigma_fx import rid, rule_doc, run_sigma, sigma_cfg
from ..test_detect import _alert, _episode_ctx

T0 = 1792807200000  # 2026-10-24T02:00:00Z, bucket-aligned
MIN, H = 60_000, 3_600_000


# ================================================================ incident_gate.burst / risk_score
def _p(**kw) -> dict:
    p = incident_gate._params(config.load_config())
    return {**p, "burst_techniques": 3, "burst_rules": 2, "burst_window": 2 * H, "burst_conf": 60,
            "burst_seeds": 0, "burst_tech_conf": 40, **kw}


def _burst_eps(ts: list[int], rules: list[str], confs: list[float]) -> list[dict]:
    techs = ("T1059.001", "T1027", "T1105")
    return [{"episode_id": f"e{i}", "subject_host": "ws-1", "ts_ms": t, "technique_id": techs[i], "rule_id": r,
             "confidence": c} for i, (t, r, c) in enumerate(zip(ts, rules, confs))]


def test_burst_window_is_inclusive_at_exactly_the_window() -> None:  # kills ig07
    p = _p()
    assert incident_gate.burst(_burst_eps([T0, T0 + H, T0 + 2 * H], ["r1", "r2", "r3"], [70, 70, 70]), p) is True
    assert incident_gate.burst(_burst_eps([T0, T0 + H, T0 + 2 * H + 1], ["r1", "r2", "r3"], [70, 70, 70]), p) \
        is False                                                         # 1 ms past the window: 3 techs never meet


def test_burst_needs_exactly_min_rules() -> None:  # kills ig08
    ts = [T0, T0 + MIN, T0 + 2 * MIN]
    assert incident_gate.burst(_burst_eps(ts, ["r1", "r2", "r2"], [70, 70, 70]), _p()) is True    # 2 rules = min
    assert incident_gate.burst(_burst_eps(ts, ["r1", "r1", "r1"], [70, 70, 70]), _p()) is False   # 1 rule


def test_burst_max_confidence_boundary_inclusive() -> None:  # kills ig09
    ts = [T0, T0 + MIN, T0 + 2 * MIN]
    assert incident_gate.burst(_burst_eps(ts, ["r1", "r2", "r3"], [60, 50, 50]), _p()) is True
    assert incident_gate.burst(_burst_eps(ts, ["r1", "r2", "r3"], [59.9, 50, 50]), _p()) is False


def test_burst_off_when_min_distinct_techniques_is_zero() -> None:  # kills ig11
    eps = _burst_eps([T0, T0 + MIN, T0 + 2 * MIN], ["r1", "r2", "r3"], [95, 95, 95])
    assert incident_gate.burst(eps, _p()) is True
    assert incident_gate.burst(eps, _p(burst_techniques=0)) is False    # 0 = burst path disabled


def test_risk_severity_above_100_clamped_to_s_10() -> None:  # kills ig13
    p = _p()
    ep = {"tactic": "Execution", "tactic_idx": TACTIC_IDX["Execution"], "subject_host": "h", "merged_alert_count": 0}
    _, raw100 = incident_gate.risk_score([{**ep, "severity": 100}], p)
    _, raw150 = incident_gate.risk_score([{**ep, "severity": 150}], p)
    assert raw150 == raw100 == pytest.approx((10 + TACTIC_IDX["Execution"]) / 10 * math.log(10.0))


# ================================================================ link (R1 self handoff)
def test_r1_dst_host_equal_to_own_host_is_not_a_handoff(tmp_path: Path) -> None:  # kills lk09
    ctx = make_events_parquet(tmp_path, [{"ts_ms": T0, "action": "other", "host": "h"}])
    try:
        eps = [{"episode_id": "a", "ts_ms": T0, "host": "ws-1", "dst_host": "ws-1", "src_user": "alice",
                "tactic": "Execution"},
               {"episode_id": "b", "ts_ms": T0 + 10 * MIN, "host": "ws-1", "src_user": "bob", "tactic": "Execution"}]
        write_episodes(ctx, eps)
        out = ctx.work_dir / "edges.parquet"
        link.link_episodes(ctx.con, ctx.work_dir / "episodes.parquet", ctx.work_dir / "background_hubs.parquet",
                           out, link.link_params(ctx.cfg))
        rows = query(ctx, f"SELECT i, j, rule FROM read_parquet('{out.as_posix()}')")
    finally:
        ctx.con.close()
    assert rows == []          # different users (no R2), no account (no R3), dst_host = own host (no R1)


# ================================================================ episodes (rarity, confidence, seeds, ASOF, spill)
def _write_parquet(ctx, name: str, sql: str) -> None:
    ctx.con.execute(f"COPY ({sql}) TO '{(ctx.work_dir / name).as_posix()}' (FORMAT PARQUET)")


def _eps_by_rule(ctx) -> dict[str, dict]:
    rows = query(ctx, f"SELECT * FROM read_parquet('{(ctx.work_dir / 'episodes.parquet').as_posix()}')")
    return {r["rule_id"]: r for r in rows}


def _baseline_ctx(tmp: Path, seed_conf: float | None = None):
    """4 hosts in events (N = 4); every rule has base_freq 4 -> rarity = ln(2) / ln(5) = 0.4307."""
    alerts = [_alert(T0, rule="r100", severity=100, seq=1), _alert(T0, rule="r80", severity=80, seq=2),
              _alert(T0, rule="r79", severity=79, seq=3)]
    ctx = _episode_ctx(tmp, alerts)
    _write_parquet(ctx, "rule_host_baseline.parquet",
                   "SELECT * FROM (VALUES ('r100', 4.0), ('r80', 4.0), ('r79', 4.0)) t(rule_id, base_freq)")
    if seed_conf is not None:
        ctx.cfg["rules"]["thresholds"]["seed_confidence"] = seed_conf
    return ctx


def test_rarity_confidence_and_seed_exact_with_baseline(tmp_path: Path) -> None:  # kills ep01 ep03 ep05
    ctx = _baseline_ctx(tmp_path)
    try:
        episodes.run(ctx)
        e = _eps_by_rule(ctx)
    finally:
        ctx.con.close()
    rarity = math.log(1 + 4 / 4) / math.log(1 + 4)
    assert e["r79"]["rarity"] == pytest.approx(rarity)
    assert e["r79"]["confidence"] == pytest.approx(79 * rarity)                   # below 80: no floor
    assert e["r80"]["confidence"] == pytest.approx(80 * 0.65)                     # floor applies AT 80
    assert e["r100"]["confidence"] == pytest.approx(65.0)
    assert (e["r100"]["is_seed"], e["r80"]["is_seed"], e["r79"]["is_seed"]) == (True, False, False)  # 65 >= 65


def test_is_seed_agrees_with_confidence_at_another_threshold(tmp_path: Path) -> None:  # kills ep02
    ctx = _baseline_ctx(tmp_path, seed_conf=50)
    try:
        episodes.run(ctx)
        e = _eps_by_rule(ctx)
    finally:
        ctx.con.close()
    assert {r: (round(x["confidence"], 3), x["is_seed"]) for r, x in e.items()} == {
        "r100": (65.0, True), "r80": (52.0, True), "r79": (round(79 * math.log(2) / math.log(5), 3), False)}
    assert all(x["is_seed"] == (x["confidence"] >= 50) for x in e.values())


def test_src_host_resolved_from_ip_owner_at_its_first_ms(tmp_path: Path) -> None:  # kills ep06
    a = _alert(T0, rule="r1", seq=1, src_ip="10.9.9.9")
    ctx = _episode_ctx(tmp_path, [a])
    _write_parquet(ctx, "host_ip_map.parquet", f"SELECT '10.9.9.9' AS ip, 'ws-owner' AS host, {T0}::BIGINT AS "
                                               f"first_ms, {T0 + H}::BIGINT AS last_ms")
    try:
        episodes.run(ctx)
        e = _eps_by_rule(ctx)["r1"]
    finally:
        ctx.con.close()
    assert e["src_host"] == "ws-owner"


def test_spill_neighbourhood_two_hops_and_inclusive_window(tmp_path: Path) -> None:  # kills ep08 ep09 ep11
    day = 86_400_000
    alerts = [
        _alert(T0, rule="seed", severity=90, src_user="svc_backup", host="srv-dc-01", seq=1),            # seed
        _alert(T0 + day, rule="hop1", severity=40, src_user="svc_backup", host="ws-fin-010", seq=2),     # user, 24 h
        _alert(T0 + day + H, rule="hop2", severity=40, src_user="kiyer", host="ws-fin-010", seq=3),     # host of hop1
        _alert(T0 + 2 * H, rule="other", severity=59, src_user="u9", host="h-9", seq=4),                # unrelated
    ]
    ctx = _episode_ctx(tmp_path, alerts)
    th = ctx.cfg["rules"]["thresholds"]
    th.update(episode_cap=3, spill_hops=2, spill_hop_window_ms=day)
    ctx.cfg["linking"]["spill"]["fill_to_cap"] = False
    try:
        stats = episodes.run(ctx)
        kept = sorted(_eps_by_rule(ctx))
    finally:
        ctx.con.close()
    assert kept == ["hop1", "hop2", "seed"]
    assert stats["spill_by_tier"] == {"kept_seed": 1, "kept_seed_neighbourhood": 2, "kept_fill": 0,
                                      "seed_neighbourhood_total": 3}
    assert stats["spilled"] == 1


# ================================================================ paths (DP)
def _n(i: str, k: int, tactic: str, sev: float) -> Node:
    return Node(i, T0 + k * MIN, k, sev, tactic, TACTIC_IDX[tactic])


def test_self_loop_edge_is_ignored() -> None:  # kills pa04
    res = best_path([_n("a", 0, "Execution", 50)], [Edge("a", "a", "R2", 1.0)])
    assert (res.backbone, res.scores, res.back) == (["a"], {"a": 50}, {"a": None})


def test_zero_gain_predecessor_not_attached() -> None:  # kills pa05
    # S(a) + w = 0 + 0: max(0, 0) adds nothing, so b starts its own chain (a zero-value step never pads the path)
    res = best_path([_n("a", 0, "Execution", 0), _n("b", 1, "Execution", 10)], [Edge("a", "b", "R2", 0.0)])
    assert (res.backbone, res.back["b"], res.scores["b"]) == (["b"], None, 10)


def test_branch_end_at_exactly_ratio_times_top_is_kept() -> None:  # kills pa06 (spec: end score >= 0.5 x max)
    nodes = [_n("a", 0, "Execution", 0), _n("b", 1, "Execution", 39.5), _n("c", 2, "Execution", 19.5)]
    res = best_path(nodes, [Edge("a", "b", "R2", 0.5), Edge("a", "c", "R2", 0.5)], branch_min_ratio=0.5)
    assert res.scores == {"a": 0, "b": 40.0, "c": 20.0}
    assert res.backbone == ["a", "b"] and res.branches == [["c"]]


def test_seed_hangs_off_its_best_shown_predecessor() -> None:  # kills pa13
    # backbone x (Collection) -> y (Exfiltration); seed s (Discovery) is later but tactic-backwards from both, so the
    # DP gives it no predecessor; it hangs off the shown predecessor with the higher S(i) + w (y: 101 + 1).
    nodes = [_n("x", 0, "Collection", 50), _n("y", 1, "Exfiltration", 50), _n("s", 2, "Discovery", 60)]
    edges = [Edge("x", "y", "R4", 1.0), Edge("x", "s", "R2", 1.0), Edge("y", "s", "R2", 1.0)]
    res = best_path(nodes, edges, seeds=["s"])
    assert res.backbone == ["x", "y"] and res.branches == [["s"]]
    assert res.back["s"] == "y"


# ================================================================ sigma_detect (cap accounting, rows_matched)
def _contains(token: str) -> dict:
    return {"sel": {"CommandLine|contains": token}, "condition": "sel"}


@pytest.mark.sigma
def test_rule_at_exactly_the_cap_is_not_reported_capped(tmp_path: Path) -> None:  # kills sd02
    rows = [{"command_line": "tokA", "host": "ws-1"} for _ in range(2)]
    stats, alerts = run_sigma(sigma_cfg(tmp_path, [rule_doc(_contains("tokA"), n=0xA)], max_alerts_per_rule=2), rows)
    assert [a["source_seq"] for a in alerts if a["rule_id"] == rid(0xA)] == [1, 2]
    assert stats["sigma_alerts_capped_by_rule"] == {}


@pytest.mark.sigma
def test_rows_matched_counts_only_matching_rows(tmp_path: Path) -> None:  # kills sd10
    rows = [{"command_line": c, "host": "ws-1"} for c in ("tokA", "nope", "other")]
    stats, alerts = run_sigma(sigma_cfg(tmp_path, [rule_doc(_contains("tokA"), n=0xB)]), rows)
    assert [a["source_seq"] for a in alerts if a["rule_id"] == rid(0xB)] == [1]
    assert stats["rows_matched"] == 1
    assert sum(int(g.get("matched_tuples") or 0) for g in stats["group_tuples"].values()) == 1


# ================================================================ ingest_sql (epoch digits, negative tz offset)
def test_ts_expr_epoch_digit_ranges() -> None:  # kills is05 is06
    import duckdb
    con = duckdb.connect()
    con.execute("SET TimeZone='UTC'")
    vals = ["1792807200000", "17928072000000", "1792807200", "17928072000", "1792807200.5"]
    got = con.execute(f"SELECT {ts_expr('x', [])} FROM (SELECT unnest(?::VARCHAR[]) AS x, "
                      "generate_subscripts(?::VARCHAR[], 1) AS k) ORDER BY k", [vals, vals]).fetchall()
    con.close()
    assert [g[0] for g in got] == [1792807200000, None, 1792807200000, None, 1792807200500]


def test_fortigate_negative_tz_offset(tmp_path: Path) -> None:  # kills is11
    # local 22:00:00 at -0400 on 23 Oct = 02:00:00 UTC on 24 Oct = T0; eventtime = local time "as if UTC" (ns)
    local_as_utc_ns = (T0 - 4 * H) * 1_000_000
    line = (f'date=2026-10-23 time=22:00:00 devname="FGT-SIM-01" devid="FGT60F0000000001" '
            f'eventtime={local_as_utc_ns} tz="-0400" logid="0000000013" type="traffic" subtype="forward" '
            'level="notice" vd="root" srcip=10.0.0.5 srcport=50000 srcintf="internal" srcintfrole="lan" '
            'dstip=198.51.100.7 dstport=443 dstintf="wan1" dstintfrole="wan" sessionid=1001 proto=6 '
            'action="accept" policyid=1 service="HTTPS" duration=12 sentbyte=1200 rcvdbyte=3400\n')
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "fw.txt").write_text(line, encoding="utf-8")
    ctx = run_ingest(raw, tmp_path)
    try:
        rows = query(ctx, "SELECT ts_ms, source_type FROM events")
    finally:
        ctx.con.close()
    assert rows == [{"ts_ms": T0, "source_type": "fortigate_kv"}]


# ================================================================ api_upload (size / disk boundaries, local_roots)
BOUNDARY = "----qa-mutants-boundary"
CTYPE = f"multipart/form-data; boundary={BOUNDARY}"


def _body(name: str, data: bytes) -> bytes:
    return (f"--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{name}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{BOUNDARY}--\r\n".encode()


async def _agen(chunks: list[bytes]) -> AsyncIterator[bytes]:
    for c in chunks:
        yield c


def _mgr(tmp: Path, free: int = 10**15, **cfg) -> UploadManager:
    c = UploadConfig(root=tmp / "uploads", **{"max_bytes": 64 * 2**20, "min_free_bytes": 2**20, "chunk_bytes": 2**20,
                                             "check_every": 256 * 1024, **cfg})
    return UploadManager(c, repo_root=tmp, disk_free=lambda _p: free)


def _receive(mgr: UploadManager, data: bytes, length: int | None = None) -> dict:
    return asyncio.run(mgr.receive(CTYPE, length, _agen([_body("a.log", data)])))


def test_upload_of_exactly_max_bytes_accepted(tmp_path: Path) -> None:  # kills up05 up01 up03 up12
    mgr = _mgr(tmp_path, max_bytes=1000)
    assert _receive(mgr, b"x" * 1000)["files"] == [{"name": "a.log", "bytes": 1000}]
    with pytest.raises(UploadError) as e:
        _receive(mgr, b"x" * 1001)
    assert e.value.status == 413


def test_content_length_at_the_limit_accepted(tmp_path: Path) -> None:  # kills up06
    mgr = _mgr(tmp_path, max_bytes=1000)
    assert _receive(mgr, b"x" * 10, length=1000 + 2**20)["total_bytes"] == 10
    with pytest.raises(UploadError) as e:
        _receive(mgr, b"x" * 10, length=1000 + 2**20 + 1)
    assert e.value.status == 413


def test_disk_checked_at_exactly_check_every_bytes(tmp_path: Path) -> None:  # kills up07
    # no Content-Length -> no pre-check; the only disk check is the in-write one at check_every bytes
    mgr = _mgr(tmp_path, free=0, check_every=4096)
    assert _receive(mgr, b"y" * 4095)["total_bytes"] == 4095
    with pytest.raises(UploadError) as e:
        _receive(mgr, b"y" * 4096)
    assert e.value.status == 507


def test_free_disk_exactly_reserve_plus_upload_accepted(tmp_path: Path) -> None:  # kills up08 up09
    n = 5000
    assert _receive(_mgr(tmp_path / "ok", free=2**20 + n), b"z" * 10, length=n)["total_bytes"] == 10
    with pytest.raises(UploadError) as e:
        _receive(_mgr(tmp_path / "short", free=2**20 + n - 1), b"z" * 10, length=n)
    assert e.value.status == 507


def test_local_file_of_exactly_max_bytes_accepted(tmp_path: Path) -> None:  # kills up10
    src = tmp_path / "src" / "fw.log"
    src.parent.mkdir()
    src.write_bytes(b"x" * 1000)
    assert _mgr(tmp_path, max_bytes=1000).register_local(str(src))["files"] == [{"name": "fw.log", "bytes": 1000}]
    with pytest.raises(UploadError) as e:
        _mgr(tmp_path, max_bytes=999).register_local(str(src))
    assert e.value.status == 413


def test_local_roots_restrict_registration(tmp_path: Path) -> None:  # kills up11
    allowed, other = tmp_path / "allowed", tmp_path / "other"
    for d in (allowed, other):
        d.mkdir()
        (d / "fw.log").write_bytes(b"x\n")
    mgr = _mgr(tmp_path, local_roots=[allowed.resolve()])
    assert mgr.register_local(str(allowed / "fw.log"))["files"] == [{"name": "fw.log", "bytes": 2}]
    with pytest.raises(UploadError) as e:
        mgr.register_local(str(other / "fw.log"))
    assert e.value.status == 403


# ================================================================ second pass: survivors / unresolved timeouts
def test_burst_technique_confidence_floor_is_inclusive() -> None:  # kills ig10
    ts = [T0, T0 + MIN, T0 + 2 * MIN]
    assert incident_gate.burst(_burst_eps(ts, ["r1", "r2", "r3"], [70, 40, 40]), _p()) is True     # 40 = floor
    assert incident_gate.burst(_burst_eps(ts, ["r1", "r2", "r3"], [70, 40, 39.9]), _p()) is False  # 2 techniques


def _edges(tmp: Path, eps: list[dict], **pkw) -> set[tuple[str, str, str]]:
    ctx = make_events_parquet(tmp, [{"ts_ms": T0, "action": "other", "host": "h"}])
    try:
        write_episodes(ctx, eps)
        out = ctx.work_dir / "edges.parquet"
        link.link_episodes(ctx.con, ctx.work_dir / "episodes.parquet", ctx.work_dir / "background_hubs.parquet",
                           out, {**link.link_params(ctx.cfg), **pkw})
        return {(r["i"], r["j"], r["rule"]) for r in query(ctx, f"SELECT i, j, rule FROM read_parquet('{out.as_posix()}')")}
    finally:
        ctx.con.close()


def _r3(conf: float) -> list[dict]:
    return [{"episode_id": "a", "ts_ms": T0, "host": "srv-dc-01", "tactic": "Credential Access",
             "target_user": "svc_backup", "confidence": conf},
            {"episode_id": "b", "ts_ms": T0 + H, "host": "ws-fin-010", "tactic": "Execution", "src_user": "svc_backup"}]


def test_r3_source_confidence_floor_is_inclusive(tmp_path: Path) -> None:  # kills lk08
    floor = float(link.link_params(config.load_config())["r3_min_source_confidence"])
    assert _edges(tmp_path / "at", _r3(floor)) == {("a", "b", "R3")}
    assert _edges(tmp_path / "below", _r3(floor - 0.01)) == set()


def test_r4_needs_an_exfiltration_successor(tmp_path: Path) -> None:  # kills lk10
    eps = [{"episode_id": "a", "ts_ms": T0, "host": "ws-fin-010", "tactic": "Collection", "src_user": "u1"},
           {"episode_id": "b", "ts_ms": T0 + MIN, "host": "ws-fin-010", "tactic": "Command and Control",
            "src_user": "u2"}]
    assert _edges(tmp_path / "c2", eps) == set()
    eps[1]["tactic"] = "Exfiltration"
    assert _edges(tmp_path / "exfil", eps) == {("a", "b", "R4")}


def test_external_vs_internal_src_ip_for_r1_ip_handoff(tmp_path: Path) -> None:  # kills lk13
    def pair(ip: str) -> list[dict]:
        return [{"episode_id": "a", "ts_ms": T0, "host": "ws-1", "src_ip": ip, "src_user": "u1"},
                {"episode_id": "b", "ts_ms": T0 + MIN, "host": "ws-2", "src_ip": ip, "src_user": "u2"}]
    assert _edges(tmp_path / "ext", pair("203.0.113.9")) == {("a", "b", "R1")}
    assert _edges(tmp_path / "int", pair("10.0.0.9")) == set()


def test_spill_never_hops_through_a_hub_entity(tmp_path: Path) -> None:  # kills ep11
    # seed and hop1 share ONLY user svc_backup; with user:svc_backup a background hub, hop1 is not neighbourhood
    alerts = [_alert(T0, rule="seed", severity=90, src_user="svc_backup", host="srv-dc-01", seq=1),
              _alert(T0 + H, rule="hop1", severity=40, src_user="svc_backup", host="ws-fin-010", seq=2),
              _alert(T0 + 2 * H, rule="host", severity=40, src_user="kiyer", host="srv-dc-01", seq=3)]
    ctx = _episode_ctx(tmp_path, alerts)
    ctx.cfg["rules"]["thresholds"].update(episode_cap=2, spill_hops=1, spill_hop_window_ms=86_400_000)
    ctx.cfg["linking"]["spill"]["fill_to_cap"] = False
    _write_parquet(ctx, "background_hubs.parquet", "SELECT 'user:svc_backup' AS entity")
    try:
        stats = episodes.run(ctx)
        kept = sorted(_eps_by_rule(ctx))
    finally:
        ctx.con.close()
    assert kept == ["host", "seed"]          # same host srv-dc-01 (not a hub) carries the hop; the hub user does not
    assert stats["spilled"] == 1


def _fg(dst: str, local: str, tz: str, eventtime: int | str, prefix: str = "") -> str:
    d, t = local.split(" ")
    return (f'{prefix}date={d} time={t} devname="FGT-SIM-01" devid="FGT60F0000000001" eventtime={eventtime} '
            f'tz="{tz}" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
            f'srcip=10.0.0.5 srcport=50000 srcintf="internal" dstip={dst} dstport=443 dstintf="wan1" '
            'sessionid=1001 proto=6 action="accept" policyid=1 service="HTTPS" duration=12 sentbyte=1 rcvdbyte=2\n')


def _ingest_lines(tmp: Path, lines: list[str]) -> list[dict]:
    raw = tmp / "raw"
    raw.mkdir(parents=True)
    (raw / "fw.txt").write_text("".join(lines), encoding="utf-8")
    ctx = run_ingest(raw, tmp)
    try:
        return query(ctx, "SELECT dst_ip, ts_ms, ts_ok, raw_line FROM events ORDER BY source_seq")
    finally:
        ctx.con.close()


def test_fortigate_local_eventtime_tolerance_is_strictly_below_one_second(tmp_path: Path) -> None:  # kills is08
    # local 07:30:00 +0530 = T0. eventtime local-as-UTC +999 ms -> local clock (T0 + 999);
    # +1000 ms is no longer the same wall-clock second -> eventtime is taken as true UTC epoch ms.
    local_ms = T0 + 19_800_000
    rows = _ingest_lines(tmp_path, [_fg("198.51.100.1", "2026-10-24 07:30:00", "+0530", local_ms + 999),
                                    _fg("198.51.100.2", "2026-10-24 07:30:00", "+0530", local_ms + 1000)])
    assert {r["dst_ip"]: r["ts_ms"] for r in rows} == {"198.51.100.1": T0 + 999, "198.51.100.2": local_ms + 1000}


def test_fortigate_malformed_line_never_gets_a_timestamp(tmp_path: Path) -> None:  # kills is04
    good = _fg("198.51.100.1", "2026-10-24 07:30:00", "+0530", T0 + 19_800_000)
    junk = _fg("198.51.100.9", "2026-10-24 07:30:01", "+0530", T0 + 19_801_000, prefix="#! ")  # fails line_regex
    rows = {r["raw_line"]: (r["ts_ms"], r["ts_ok"]) for r in _ingest_lines(tmp_path, [good, junk])}
    assert rows == {good.rstrip("\n"): (T0, True), junk.rstrip("\n"): (None, False)}


def test_blank_and_space_only_lines_are_not_rows(tmp_path: Path) -> None:  # kills is01
    # ingest.py counts rows_in over non-blank lines; the SQL readers must skip the same lines (NONEMPTY)
    from ..conftest import accounting
    lines = [_fg("198.51.100.1", "2026-10-24 07:30:00", "+0530", T0 + 19_800_000), "\n", "   \n",
             _fg("198.51.100.2", "2026-10-24 07:30:01", "+0530", T0 + 19_801_000)]
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "fw.txt").write_text("".join(lines), encoding="utf-8")
    ctx = run_ingest(raw, tmp_path)
    try:
        acc = {k: v for k, v in accounting(ctx).items() if v["rows_in"]}
        n = query(ctx, "SELECT count(*) AS n FROM events")[0]["n"]
    finally:
        ctx.con.close()
    assert acc == {"fortigate_kv": {"rows_in": 2, "rows_ok": 2, "dropped": 0}}
    assert n == 2


def test_sanitize_name_rules_exact() -> None:  # kills up01 up02 up03 up04
    from attacklens.api_upload import DEFAULT_EXT, sanitize_name
    assert sanitize_name("fw.log", DEFAULT_EXT) == "fw.log"
    assert sanitize_name(".hidden.log", DEFAULT_EXT) == "hidden.log"                  # leading dots stripped
    assert sanitize_name("sub/dir\\fw 1.LOG", DEFAULT_EXT) == "fw_1.LOG"
    for bad, status in (("a..b.log", 400), ("/etc/fw.log", 400), ("\\srv\\fw.log", 400), ("C:fw.log", 400),
                        ("fw.exe", 415), ("fw", 415)):
        with pytest.raises(UploadError) as e:
            sanitize_name(bad, DEFAULT_EXT)
        assert e.value.status == status, bad


def _multipart(parts: list[tuple[str, str | None, bytes]], close: bool = True) -> bytes:
    out = b""
    for field_name, fname, data in parts:
        disp = f'form-data; name="{field_name}"' + (f'; filename="{fname}"' if fname is not None else "")
        out += f"--{BOUNDARY}\r\nContent-Disposition: {disp}\r\n\r\n".encode() + data + b"\r\n"
    return out + (f"--{BOUNDARY}--\r\n".encode() if close else b"")


def test_only_file_parts_of_the_files_field_are_stored(tmp_path: Path) -> None:  # kills up13
    body = _multipart([("files", None, b"not a file"), ("other", "x.log", b"wrong field"),
                       ("files", "a.log", b"abc")])
    info = asyncio.run(_mgr(tmp_path).receive(CTYPE, None, _agen([body])))
    assert info["files"] == [{"name": "a.log", "bytes": 3}]


def test_truncated_multipart_rejected_and_removed(tmp_path: Path) -> None:  # kills up12
    mgr = _mgr(tmp_path)
    with pytest.raises(UploadError) as e:
        asyncio.run(mgr.receive(CTYPE, None, _agen([_multipart([("files", "a.log", b"abc")], close=False)])))
    assert e.value.status == 400 and "truncated" in e.value.detail
    assert mgr.list() == [] and list((tmp_path / "uploads" / ".incoming").iterdir()) == []


def test_uploads_listed_newest_first(tmp_path: Path) -> None:  # kills up14
    import json
    mgr = _mgr(tmp_path)
    root = tmp_path / "uploads"
    (root / ".meta").mkdir(parents=True)
    ids = ["up-20261101-000000-aaaaaa", "up-20261101-000100-bbbbbb", "up-20261031-235959-cccccc"]
    for uid, at in zip(ids, ("2026-11-01T00:00:00Z", "2026-11-01T00:01:00Z", "2026-10-31T23:59:59Z")):
        (root / uid).mkdir()
        (root / ".meta" / f"{uid}.json").write_text(json.dumps({"upload_id": uid, "created_at": at}), encoding="utf-8")
    assert [i["upload_id"] for i in mgr.list()] == [ids[1], ids[0], ids[2]]


# ================================================================ product bug found by the harness (sigma cache)
_CACHE_PROBE = r'''
import json, sys
from pathlib import Path
pkg_a, pkg_b, cfg_dir, rules, cache = sys.argv[1:6]
out = []
for pkg in (pkg_a, pkg_b):
    for m in [m for m in sys.modules if m == "attacklens" or m.startswith("attacklens.")]:
        del sys.modules[m]
    sys.path.insert(0, pkg)
    from attacklens import config, sigma_rules
    assert Path(sigma_rules.__file__).resolve().is_relative_to(Path(pkg).resolve()), sigma_rules.__file__
    cfg = config.load_config(Path(cfg_dir))
    cfg["pipeline"]["sigma"] = {**(cfg["pipeline"].get("sigma") or {}), "enabled": True, "dir": rules,
                                "cache_dir": cache, "min_level": "informational"}
    out.append([r["scan"] for r in sigma_rules.load(cfg).rules])
    sys.path.remove(pkg)
print(json.dumps(out))
'''


@pytest.mark.xfail(strict=True, reason="QA-MUT-01: Sigma compile cache key ignores the compiler source; an edit to "
                                       "sigma_compile.py without a COMPILER_VERSION bump serves stale compiled SQL")
def test_sigma_cache_recompiles_when_compiler_source_changes(tmp_path: Path) -> None:
    """Two copies of the package that differ only in sigma_compile.py compile the same rule into the SAME cache dir:
    the second copy must get its own compiler's output, not the first copy's cached SQL."""
    import json
    import shutil
    import subprocess
    import sys

    import attacklens
    from ..sigma_fx import write_rules
    src = Path(attacklens.__file__).resolve().parent
    pkgs = []
    for name in ("a", "b"):
        dst = tmp_path / name / "attacklens"
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
        pkgs.append(str(tmp_path / name))
    f = tmp_path / "b" / "attacklens" / "sigma_compile.py"
    s = f.read_text(encoding="utf-8")
    old = 'return f"contains({col}, {v})"'
    assert s.count(old) == 1
    f.write_text(s.replace(old, 'return f"(contains({col}, {v}) AND TRUE)"'), encoding="utf-8")   # behaviour-visible
    rules = write_rules(tmp_path, [rule_doc(_contains("tokq"), n=0xC)])
    r = subprocess.run([sys.executable, "-c", _CACHE_PROBE, *pkgs, str(config.CONFIG_DIR), str(rules),
                        str(tmp_path / "cache")], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr[-2000:]
    scan_a, scan_b = json.loads(r.stdout.strip().splitlines()[-1])
    assert len(scan_a) == len(scan_b) == 1 and "AND TRUE" not in scan_a[0]
    assert "AND TRUE" in scan_b[0], "copy b was served copy a's cached compile"
