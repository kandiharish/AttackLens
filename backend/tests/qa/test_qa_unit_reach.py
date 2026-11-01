"""QA unit / white-box tests for attacklens.reach (track qa_coverage_unit).

Baseline coverage showed the domain-admin grant in load_graph (membership in a domain admin group = AdminTo every
DC seen in the reach tables, DEVELOPMENT.md §6.7) and the no-events branch of prepare never ran. The BFS itself is
checked on a hand-built ReachGraph (no DuckDB) for exact hops / via_user / ordering and the max_hops boundary.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from attacklens import lookups, reach

from ..conftest import _new_ctx, make_events_parquet

T0 = 1792807200000
MIN = 60_000
IPS = {"ws-a": "10.20.1.1", "srv-dc-01": "10.20.1.2", "srv-dc-02": "10.20.1.3", "srv-app-01": "10.20.1.4"}


def own(host: str) -> dict:
    return {"ts_ms": T0 - 10 * MIN, "action": "other", "host": host, "host_ip": IPS[host]}


def grp(user: str, group: str, host: str = "srv-dc-01") -> dict:
    return {"ts_ms": T0, "action": "group_member_added", "host": host, "host_ip": IPS[host], "target_user": user,
            "group_name": group, "event_id": 4728}


def flow(src: str, dst: str, port: int = 445) -> dict:
    return {"ts_ms": T0 + MIN, "action": "conn_out", "host": src, "host_ip": IPS[src], "src_ip": IPS[src],
            "dst_ip": IPS[dst], "dst_port": port}


def _reach(tmp: Path, rows: list[dict], users: list[str], hosts: list[str]) -> list[tuple]:
    ctx = make_events_parquet(tmp, [own(h) for h in IPS] + rows)
    try:
        lookups.run(ctx)
        reach.prepare(ctx)
        g = reach.load_graph(ctx)
        out = reach.compute(ctx, reach.Frontier(users=users, hosts=hosts), g)
    finally:
        ctx.con.close()
    return [(r.host, r.hops, r.via_user, r.crown_jewel, r.evidence.split(" at ")[0]) for r in out]


def test_domain_admin_grants_every_known_dc(tmp_path: Path) -> None:
    # alice joins Domain Admins on srv-dc-01; srv-dc-02 is known only from a flow -> AdminTo both DCs
    got = _reach(tmp_path, [grp("alice", "Domain Admins"), flow("ws-a", "srv-dc-02")], ["alice"], ["ws-z"])
    assert got == [("srv-dc-01", 1, "alice", "dc", "4728 added to Domain Admins"),
                   ("srv-dc-02", 1, "alice", "dc", "4728 added to Domain Admins")]


def test_local_administrators_near_miss_no_dc_grant(tmp_path: Path) -> None:
    # 'administrators' is an admin group (AdminTo that host) but not a domain admin group -> no other DC
    got = _reach(tmp_path, [grp("alice", "Administrators"), flow("ws-a", "srv-dc-02")], ["alice"], ["ws-z"])
    assert got == [("srv-dc-01", 1, "alice", "dc", "4728 added to Administrators")]


def test_non_admin_group_gives_nothing(tmp_path: Path) -> None:
    got = _reach(tmp_path, [grp("alice", "Backup Operators"), flow("ws-a", "srv-dc-02")], ["alice"], ["ws-z"])
    assert got == []


def test_machine_account_group_add_excluded(tmp_path: Path) -> None:
    got = _reach(tmp_path, [grp("ws-a$", "Domain Admins"), flow("ws-a", "srv-dc-02")], ["ws-a$"], ["ws-z"])
    assert got == []


def test_prepare_without_any_events_writes_empty_tables(tmp_path: Path) -> None:
    ctx = _new_ctx(tmp_path)                       # no events view, no parquet at all
    try:
        stats = reach.prepare(ctx)
        g = reach.load_graph(ctx)
    finally:
        ctx.con.close()
    assert stats["admin_edges"] == 0 and stats["flow_edges"] == 0
    assert all((ctx.work_dir / f).exists() for f in reach.FILES.values())
    assert (g.admin, g.flows, g.ssh) == ({}, {}, {})


@pytest.mark.xfail(strict=True, reason="QA-COV-02: reach.prepare returns {'admin_edges', 'flow_edges'} without "
                                       "'ssh_edges' when there are no events, but {'admin_edges', 'flow_edges', "
                                       "'ssh_edges'} otherwise; incidents.run copies it into stats['reach']")
def test_prepare_stats_keys_stable_without_events(tmp_path: Path) -> None:
    ctx = _new_ctx(tmp_path)
    try:
        stats = reach.prepare(ctx)
    finally:
        ctx.con.close()
    assert set(stats) == {"admin_edges", "flow_edges", "ssh_edges"}


# ---- BFS on a hand-built graph -----------------------------------------------------------------------------------
def _graph() -> reach.ReachGraph:
    return reach.ReachGraph(
        admin={"alice": [("srv-file-01", "ev-admin"), ("ws-01", "ev-self")]},
        flows={"ws-01": [("srv-db-01", 445, "ev-f1")], "srv-db-01": [("srv-dc-01", 3389, "ev-f2")],
               "srv-dc-01": [("ws-99", 22, "ev-f3")], "srv-file-01": [("app-07", 5985, "ev-f4")]},
        ssh={"bob": [("lnx-web-01", "ev-ssh")]})


def _ctx(reach_cfg: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(cfg={"linking": {"reach": reach_cfg or {}}})


def test_bfs_exact_hops_via_and_order() -> None:
    out = reach.compute(_ctx(), reach.Frontier(users=["Alice", "bob", "WS-01$"], hosts=["WS-01"],
                                               touched={"SRV-DB-01"}), _graph())
    got = [(r.host, r.hops, r.via_user, r.crown_jewel, r.touched, r.evidence) for r in out]
    assert got == [
        ("lnx-web-01", 1, "bob", "web", False, "ev-ssh"),        # crown jewels first, then hops, then name
        ("srv-file-01", 1, "alice", "file", False, "ev-admin"),
        ("srv-dc-01", 2, None, "dc", False, "ev-f2"),            # via a flow from the frontier host: no user
        ("app-07", 2, "alice", None, False, "ev-f4"),            # via_user propagates along flows
        ("ws-99", 3, None, None, False, "ev-f3"),
        ("srv-db-01", 1, None, "db", True, "ev-f1"),             # touched hosts sort last
    ]
    assert "ws-01" not in {r.host for r in out}                   # a frontier host is never "next"


def test_bfs_max_hops_boundary() -> None:
    out = reach.compute(_ctx({"max_hops": 2}), reach.Frontier(users=[], hosts=["ws-01"]), _graph())
    assert sorted((r.host, r.hops) for r in out) == [("srv-db-01", 1), ("srv-dc-01", 2)]   # ws-99 (3 hops) cut
    out1 = reach.compute(_ctx({"max_hops": 1}), reach.Frontier(users=[], hosts=["ws-01"]), _graph())
    assert [(r.host, r.hops) for r in out1] == [("srv-db-01", 1)]


def test_bfs_max_results_and_evidence_cap() -> None:
    g = reach.ReachGraph(admin={"u": [(f"h{k:02d}", "x" * 400) for k in range(30)]}, flows={})
    out = reach.compute(_ctx({"max_results": 4}), reach.Frontier(users=["u"], hosts=[]), g)
    assert [r.host for r in out] == ["h00", "h01", "h02", "h03"]
    assert {len(r.evidence) for r in out} == {300}


@pytest.mark.parametrize("host, tag", [("SRV-DC-01", "dc"), ("fileserver", "file"), ("pg-db-2", "db"),
                                       ("web-01", "web"), ("ws-fin-010", None), ("dcfile", "dc")])
def test_crown_jewel_first_match_wins(host: str, tag: str | None) -> None:
    assert reach.crown_jewel(host, reach.DEFAULT_REACH["crown_jewels"]) == tag


def test_lit_quotes_and_ints() -> None:
    assert reach._lit([3, "O'Brien", "Domain Admins"]) == "3, 'o''brien', 'domain admins'"
    assert reach._lit([]) == "NULL"
