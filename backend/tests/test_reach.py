"""Reach-next tests (TESTING.md §4.4, DEVELOPMENT.md §6.7): AdminTo needs 4672 on the same logon id, system logon
ids and machine accounts excluded, CanReach via allowed flows on admin ports, BFS <= max_hops, untouched first."""

from __future__ import annotations

from pathlib import Path

import pytest

from attacklens import lookups, reach

from .conftest import make_events_parquet, query

T0 = 1792807200000
MIN = 60_000
IPS = {"ws-a": "10.10.1.1", "srv-b": "10.10.1.2", "srv-c": "10.10.1.3", "srv-dc-01": "10.10.1.4",
       "srv-e": "10.10.1.5", "srv-file-01": "10.10.1.6", "srv-db-01": "10.10.1.7"}


def own(host: str) -> dict:  # each host's own event -> host_ip_map
    return {"ts_ms": T0 - 10 * MIN, "action": "other", "host": host, "host_ip": IPS[host]}


def admin(user: str, host: str, lid: str, logon_type: int = 3, priv: bool = True, **kw) -> list[dict]:
    rows = [{"ts_ms": T0, "action": "login_success", "host": host, "host_ip": IPS[host], "target_user": user,
             "logon_type": logon_type, "logon_id": lid, "event_id": 4624, **kw}]
    if priv:
        rows.append({"ts_ms": T0 + 5, "action": "priv_assigned", "host": host, "host_ip": IPS[host],
                     "target_user": user, "logon_id": lid, "event_id": 4672})
    return rows


def flow(src: str, dst: str, port: int) -> dict:
    return {"ts_ms": T0 + MIN, "action": "conn_out", "host": src, "host_ip": IPS[src], "src_ip": IPS[src],
            "dst_ip": IPS[dst], "dst_port": port}


ADMIN_ROWS: list = []


def compute(tmp: Path, rows: list[dict], users=(), hosts=(), touched=()) -> list[tuple]:
    ctx = make_events_parquet(tmp, [own(h) for h in IPS] + rows)
    try:
        lookups.run(ctx)
        reach.prepare(ctx)
        ADMIN_ROWS[:] = query(ctx, f"SELECT * FROM read_parquet('{(ctx.work_dir / 'reach_admin.parquet').as_posix()}')")
        out = reach.compute(ctx, reach.Frontier(users=list(users), hosts=list(hosts), touched=set(touched)))
    finally:
        ctx.con.close()
    return [(r.host, r.hops, r.via_user, r.touched, r.crown_jewel) for r in out]


def test_admin_to_with_4672(tmp_path: Path) -> None:
    got = compute(tmp_path, admin("svc_backup", "srv-file-01", "0x8a1"), users=["svc_backup"])
    assert got == [("srv-file-01", 1, "svc_backup", False, "file")]


@pytest.mark.parametrize("case", ["no_4672", "0x3e7", "0x3e4", "0x3e5", "machine", "interactive",
                                  "other_logon_id"])
def test_admin_to_exclusions(tmp_path: Path, case: str) -> None:
    rows = {"no_4672": admin("svc_backup", "srv-file-01", "0x8a1", priv=False),
            "0x3e7": admin("svc_backup", "srv-file-01", "0x3e7"),
            "0x3e4": admin("svc_backup", "srv-file-01", "0x3E4"),
            "0x3e5": admin("svc_backup", "srv-file-01", "0x3e5"),
            "machine": admin("ws-a$", "srv-file-01", "0x8a1"),
            "interactive": admin("svc_backup", "srv-file-01", "0x8a1", logon_type=2),
            "other_logon_id": admin("svc_backup", "srv-file-01", "0x8a1", priv=False)
            + [{"ts_ms": T0, "action": "priv_assigned", "host": "srv-file-01", "target_user": "svc_backup",
                "logon_id": "0x8a2"}]}[case]
    assert compute(tmp_path, rows, users=["svc_backup", "ws-a$"]) == []
    assert ADMIN_ROWS == []  # excluded when the AdminTo table is built, not only at the frontier


def test_ssh_logon_is_admin_to(tmp_path: Path) -> None:
    rows = [{"ts_ms": T0, "action": "login_success", "host": "srv-db-01", "host_ip": IPS["srv-db-01"],
             "target_user": "vreddy", "process_name": "sshd", "dst_port": 22, "logon_type": 10}]
    assert compute(tmp_path, rows, users=["vreddy"]) == [("srv-db-01", 1, "vreddy", False, "db")]


def test_bfs_three_hops_max_and_admin_ports_only(tmp_path: Path) -> None:
    rows = [flow("ws-a", "srv-b", 445), flow("srv-b", "srv-c", 3389), flow("srv-c", "srv-dc-01", 5985),
            flow("srv-dc-01", "srv-e", 22),        # 4th hop: beyond max_hops
            flow("ws-a", "srv-file-01", 80)]       # not an admin port
    got = compute(tmp_path, rows, hosts=["ws-a"])
    assert got == [("srv-dc-01", 3, None, False, "dc"), ("srv-b", 1, None, False, None),
                   ("srv-c", 2, None, False, None)]


def test_untouched_first_then_crown_jewel_then_hops(tmp_path: Path) -> None:
    rows = admin("svc_backup", "srv-file-01", "0x1") + admin("svc_backup", "srv-b", "0x2") + \
        admin("svc_backup", "srv-dc-01", "0x3")
    got = compute(tmp_path, rows, users=["svc_backup"], touched=["srv-file-01"])
    assert [g[0] for g in got] == ["srv-dc-01", "srv-b", "srv-file-01"]
    assert [g[3] for g in got] == [False, False, True]


def test_frontier_machine_account_ignored(tmp_path: Path) -> None:
    rows = admin("svc_backup", "srv-file-01", "0x1")
    assert compute(tmp_path, rows, users=["SVC_BACKUP$"]) == []


def test_frontier_hosts_not_reported_as_reach(tmp_path: Path) -> None:
    rows = admin("svc_backup", "srv-file-01", "0x1") + [flow("srv-file-01", "srv-b", 445)]
    got = compute(tmp_path, rows, users=["svc_backup"], hosts=["srv-file-01"])
    assert got == [("srv-b", 1, None, False, None)]
