"""FortiGate detection pack (DEVELOPMENT.md §15.9): positive + near-miss per firewall rule, entity fallback
(subject_host) on firewall rows, and ECS rows unaffected. Rules run through detect.rule_sql (rule `params` and
`filter` applied exactly as in Stage 2); thresholds pinned in SPEC_FW."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from attacklens import config, detect, detect_sql

from .conftest import make_events_parquet

T0 = 1792807200000  # 2026-10-24T02:00:00Z
S, MIN, H = 1000, 60_000, 3_600_000
EXT, EXT2 = "203.0.113.9", "203.0.113.10"
FW = "fgt-01"

SPEC_FW: dict[str, Any] = {
    "bf_min_failures": 50, "bf_gap_ms": 10 * MIN, "bf_success_window_ms": 15 * MIN, "bf_require_success": False,
    "emit_t1078_on_bruteforce": True, "spray_min_users": 15, "spray_window_ms": 10 * MIN,
    "scan_min_ports": 20, "scan_min_hosts": 20, "scan_window_ms": 60 * S, "scan_horizontal_internal_only": True,
    "lateral_max_triple_seen": 2,
    "lateral_ports": {445: "T1021.002", 3389: "T1021.001", 5985: "T1021.006", 5986: "T1021.006", 22: "T1021.004"},
    "cfg_after_login_window_ms": 2 * H, "vendor_severity_map": {"critical": 90, "high": 80, "medium": 60, "low": 40},
    "vendor_severity_default": 40, "blocked_outcomes": ["failure", "blocked", "dropped", "reset", "deny"],
    "blocked_penalty": 20, "blocked_floor": 30, "entity_fallback_ip": True,
}


def fw(ts: int, action: str, **kw: Any) -> dict:
    return {"ts_ms": ts, "source_type": "fortigate_kv", "host": FW, "action": action, **kw}


def fail(ts: int, user: str = "admin", ip: str = EXT, logon_type: int | None = None) -> dict:
    return fw(ts, "login_failed", outcome="failure", target_user=user, src_ip=ip, logon_type=logon_type)


def ok(ts: int, user: str = "admin", ip: str = EXT, logon_type: int | None = None) -> dict:
    return fw(ts, "login_success", outcome="success", target_user=user, src_ip=ip, logon_type=logon_type)


def conn(ts: int, src: str, dst: str, port: int, action: str = "conn_allowed", **kw: Any) -> dict:
    return fw(ts, action, src_ip=src, dst_ip=dst, dst_port=port, **kw)


@pytest.fixture
def run(tmp_path):
    """run(rows, rule_id, rule_over=None, **th_over) -> alerts (dicts), ordered by ts_ms, technique_id."""
    made = []

    def _run(rows: list[dict], rule_id: str, rule_over: dict | None = None, **th_over: Any) -> list[dict]:
        ctx = make_events_parquet(tmp_path / f"c{len(made)}", rows)
        made.append(ctx)
        cfg = ctx.cfg
        detect_sql.prepare(ctx.con, cfg)
        rules, th = detect.rules_and_thresholds(cfg)
        th = {**th, **SPEC_FW, **th_over}
        rule = copy.deepcopy(next(r for r in rules if r["id"] == rule_id))
        rule.update(rule_over or {})
        if rule["kind"] == "match":
            detect.build_match_hits(ctx.con, [rule], cfg["ioc"], th)
        cur = ctx.con.execute(detect.rule_sql(ctx.con, rule, th) + " ORDER BY ts_ms, technique_id")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    yield _run
    for c in made:
        c.con.close()


def lab(rows: list[dict]) -> list[tuple]:
    return [(r["technique_id"], r["sub_technique_id"], r["tactic"]) for r in rows]


T1110 = ("T1110", "T1110.001", "Credential Access")


# ================================================================ fw_admin_bruteforce
def burst(n: int, start: int = T0, **kw: Any) -> list[dict]:
    return [fail(start + i * S, **kw) for i in range(n)]


def test_fw_bf_50_fires_on_firewall_host(run) -> None:
    rows = run(burst(50), "fw_admin_bruteforce")
    assert lab(rows) == [T1110]
    r = rows[0]
    assert (r["ts_ms"], r["raw_alert_count"], r["host"], r["subject_host"], r["target_user"], r["src_ip"]) == (
        T0, 50, FW, FW, "admin", EXT)


@pytest.mark.parametrize("case", ["49", "internal_src", "vpn_rows", "gap_11_min"])
def test_fw_bf_near_misses(run, case: str) -> None:
    rows = {"49": burst(49), "internal_src": burst(50, ip="10.0.9.9"), "vpn_rows": burst(50, logon_type=10),
            "gap_11_min": burst(25) + burst(25, start=T0 + 24 * S + 11 * MIN)}[case]
    assert run(rows, "fw_admin_bruteforce") == []


def test_fw_bf_success_14_vs_16_min(run) -> None:
    last = T0 + 49 * S
    assert lab(run(burst(50) + [ok(last + 14 * MIN)], "fw_admin_bruteforce")) == [
        T1110, ("T1078", None, "Initial Access")]
    assert lab(run(burst(50) + [ok(last + 16 * MIN)], "fw_admin_bruteforce")) == [T1110]


def test_ecs_and_fortigate_brute_force_rules_disjoint(run) -> None:
    ecs = [{**r, "source_type": "ecs_json", "host": "srv-dc-01"} for r in burst(50)]
    assert run(burst(50), "brute_force_then_success") == []           # firewall rows -> fw_ rule only
    assert run(ecs, "fw_admin_bruteforce") == []
    assert lab(run(ecs, "brute_force_then_success")) == [T1110]


# ================================================================ fw_admin_spray
def spray(n: int, spacing: int = 30 * S, ip: str = EXT, logon_type: int | None = None) -> list[dict]:
    return [fail(T0 + i * spacing, user=f"user{i:02d}", ip=ip, logon_type=logon_type) for i in range(n)]


def test_fw_spray_15_fires(run) -> None:
    rows = run(spray(15), "fw_admin_spray")
    assert lab(rows) == [("T1110", "T1110.003", "Credential Access")]
    assert (rows[0]["src_ip"], rows[0]["raw_alert_count"], rows[0]["subject_host"]) == (EXT, 15, FW)


@pytest.mark.parametrize("case", ["14", "internal_src", "vpn_rows", "over_14_min"])
def test_fw_spray_near_misses(run, case: str) -> None:
    rows = {"14": spray(14), "internal_src": spray(15, ip="10.0.9.9"), "vpn_rows": spray(15, logon_type=10),
            "over_14_min": spray(15, spacing=MIN)}[case]
    assert run(rows, "fw_admin_spray") == []


def test_ecs_password_spray_ignores_firewall_rows(run) -> None:
    assert run(spray(15), "password_spray") == []


# ================================================================ vpn_bruteforce_success
def vpn(n_fail: int, success_after: int | None = 2 * MIN) -> list[dict]:
    rows = [fail(T0 + i * 10 * S, user="vpnuser", ip=EXT, logon_type=10) for i in range(n_fail)]
    if success_after is not None:
        rows.append(ok(T0 + (n_fail - 1) * 10 * S + success_after, user="vpnuser", logon_type=10))
    return rows


def test_vpn_10_failures_then_success(run) -> None:
    rows = run(vpn(10), "vpn_bruteforce_success")
    assert lab(rows) == [T1110, ("T1133", None, "Initial Access")]
    assert rows[0]["raw_alert_count"] == 10 and rows[1]["ts_ms"] == T0 + 90 * S + 2 * MIN
    assert all(r["target_user"] == "vpnuser" for r in rows)


@pytest.mark.parametrize("case", ["no_success", "9_plus_success", "success_16_min", "not_vpn"])
def test_vpn_near_misses(run, case: str) -> None:
    rows = {"no_success": vpn(10, None), "9_plus_success": vpn(9), "success_16_min": vpn(10, 16 * MIN),
            "not_vpn": [{**r, "logon_type": None} for r in vpn(10)]}[case]
    assert run(rows, "vpn_bruteforce_success") == []


# ================================================================ ips_signatures (signature_map)
def ips(sig: str, sev: str = "critical", outcome: str | None = None, src: str = EXT, dst: str = "10.0.1.20") -> dict:
    return fw(T0, "ips_alert", signature=sig, vendor_severity=sev, outcome=outcome, src_ip=src, dst_ip=dst)


@pytest.mark.parametrize("sig,expected", [
    ("Sim.SSLVPN.Portal.Path.Traversal", ("T1190", None, "Initial Access")),
    ("Apache.Log4j.Error.Log.Remote.Code.Execution", ("T1190", None, "Initial Access")),
    ("PHP.CGI.Argument.Injection", ("T1190", None, "Initial Access")),
    ("MS.Windows.HTTP.sys.Request.Handling", ("T1190", None, "Initial Access")),
    ("Sim.Buffer.Overflow", ("T1190", None, "Initial Access")),
    ("SSH.Connection.Brute.Force", ("T1110", None, "Credential Access")),
    ("ssh.login.brute.force", ("T1110", None, "Credential Access")),          # case-insensitive
    ("Mirai.Botnet.Scanner", ("T1071", None, "Command and Control")),
    ("DNS.Zone.Transfer.Attempt", ("T1590", "T1590.002", "Reconnaissance")),
    ("MS.SMB.Server.Information.Disclosure", ("T1210", None, "Lateral Movement")),
    ("Mirai.Remote.Code.Execution", ("T1190", None, "Initial Access")),        # first pattern wins
])
def test_ips_signature_map(run, sig: str, expected: tuple) -> None:
    assert lab(run([ips(sig)], "ips_signatures")) == [expected]


@pytest.mark.parametrize("sig", ["HTTP.URI.SQL.Injection", "Sim.SSLVPN.Portal.Info"])
def test_ips_unmapped_signature_silent(run, sig: str) -> None:
    assert run([ips(sig)], "ips_signatures") == []


def test_ips_other_action_silent(run) -> None:
    assert run([{**ips("Log4j.RCE"), "action": "av_alert"}], "ips_signatures") == []


@pytest.mark.parametrize("sev,outcome,expected", [
    ("critical", None, 90), ("high", "allowed", 80), ("medium", None, 60), ("low", None, 40),
    ("weird", None, 40), ("critical", "allowed", 90), ("high", "pass_session", 80)])
def test_ips_row_severity(run, sev: str, outcome: str | None, expected: int) -> None:
    rows = run([ips("Log4j.RCE", sev, outcome)], "ips_signatures")
    assert [r["severity"] for r in rows] == [expected]


# 'blocked' is what ingest writes for UTM rows the device stopped (primary case); raw verdicts kept for robustness
BLOCKED_OUTCOMES = [("high", "blocked"), ("critical", "dropped"), ("high", "BLOCKED"), ("medium", "reset"),
                    ("low", "deny"), ("critical", "failure")]


@pytest.mark.parametrize("sev,outcome", BLOCKED_OUTCOMES)
def test_ips_blocked_hit_not_an_ips_signatures_alert(run, sev: str, outcome: str) -> None:
    assert run([ips("Log4j.RCE", sev, outcome)], "ips_signatures") == []


@pytest.mark.parametrize("sev,outcome", BLOCKED_OUTCOMES)
def test_ips_blocked_hit_is_one_low_severity_alert(run, sev: str, outcome: str) -> None:
    rows = run([ips("Log4j.RCE", sev, outcome)], "ips_blocked")
    assert lab(rows) == [("T1190", None, "Initial Access")]
    assert (rows[0]["severity"], rows[0]["raw_alert_count"], rows[0]["subject_host"]) == (30, 1, "10.0.1.20")


@pytest.mark.parametrize("src,dst,subject", [(EXT, "10.0.1.20", "10.0.1.20"), ("10.0.1.30", EXT, "10.0.1.30"),
                                             ("10.0.1.30", "10.0.1.20", "10.0.1.30")])
def test_ips_subject_is_internal_endpoint(run, src: str, dst: str, subject: str) -> None:
    assert [r["subject_host"] for r in run([ips("Log4j.RCE", src=src, dst=dst)], "ips_signatures")] == [subject]


# ================================================================ av_malware_download
def test_av_alert_fires(run) -> None:
    rows = run([fw(T0, "av_alert", signature="W32/Sim.Test!tr", src_ip="10.0.2.37", dst_ip=EXT)],
               "av_malware_download")
    assert lab(rows) == [("T1105", None, "Command and Control")]
    assert (rows[0]["severity"], rows[0]["subject_host"]) == (80, "10.0.2.37")


def test_av_web_access_silent(run) -> None:
    assert run([fw(T0, "web_access", src_ip="10.0.2.37", dst_ip=EXT)], "av_malware_download") == []


@pytest.mark.parametrize("outcome,fires", [("allowed", True), (None, True), ("blocked", False), ("DROPPED", False),
                                          ("failure", False), ("reset", False), ("deny", False)])
def test_av_malware_download_allowed_only(run, outcome: str | None, fires: bool) -> None:
    rows = run([fw(T0, "av_alert", signature="W32/Sim.Test!tr", src_ip="10.0.2.37", dst_ip=EXT, outcome=outcome)],
               "av_malware_download")
    assert [r["severity"] for r in rows] == ([80] if fires else [])


# ================================================================ blocked_daily: av_blocked / ips_blocked
DAY = 86_400_000


def av(ts: int, outcome: str | None = "blocked", src: str = "10.0.2.37") -> dict:
    return fw(ts, "av_alert", signature="W32/Sim.Test!tr", src_ip=src, dst_ip="203.0.113.5", outcome=outcome)


def test_av_blocked_one_alert(run) -> None:
    rows = run([av(T0)], "av_blocked")
    assert lab(rows) == [("T1105", None, "Command and Control")]
    r = rows[0]
    assert (r["severity"], r["raw_alert_count"], r["subject_host"], r["src_ip"], r["dst_ip"]) == (
        30, 1, "10.0.2.37", "10.0.2.37", "203.0.113.5")
    assert run([av(T0)], "av_malware_download") == []  # the same row is not an allowed download


@pytest.mark.parametrize("outcome", ["blocked", "dropped", "BLOCKED", "reset", "deny", "failure"])
def test_av_blocked_outcomes(run, outcome: str) -> None:
    assert [r["raw_alert_count"] for r in run([av(T0, outcome)], "av_blocked")] == [1]


def test_av_blocked_daily_bucket_per_subject(run) -> None:
    rows = run([av(T0), av(T0 + 3_600_000, "DROPPED"), av(T0 + DAY), av(T0, src="10.0.2.38")], "av_blocked")
    assert sorted((r["subject_host"], r["ts_ms"], r["raw_alert_count"]) for r in rows) == [
        ("10.0.2.37", T0, 2), ("10.0.2.37", T0 + DAY, 1), ("10.0.2.38", T0, 1)]


@pytest.mark.parametrize("outcome", [None, "allowed", "monitored"])
def test_av_blocked_silent_when_allowed(run, outcome: str | None) -> None:
    assert run([av(T0, outcome)], "av_blocked") == []


def test_ips_blocked_three_hits_one_day(run) -> None:
    hits = [{**ips("Log4j.RCE", "high", o), "ts_ms": T0 + k * 60_000} for k, o in
            enumerate(["blocked", "BLOCKED", "reset"])]
    rows = run(hits, "ips_blocked")
    assert [(r["raw_alert_count"], r["subject_host"], r["ts_ms"], r["last_ts_ms"], r["severity"]) for r in rows] == [
        (3, "10.0.1.20", T0, T0 + 120_000, 30)]
    assert run(hits, "ips_signatures") == []


def test_ips_blocked_two_days_two_alerts(run) -> None:
    hits = [{**ips("Log4j.RCE", "high", "blocked"), "ts_ms": T0 + d * DAY} for d in range(2)]
    assert [r["raw_alert_count"] for r in run(hits, "ips_blocked")] == [1, 1]


def test_ips_blocked_ignores_allowed_hits_and_other_actions(run) -> None:
    rows = [ips("Log4j.RCE", "high", "allowed"), {**av(T0), "ts_ms": T0 + 1}]
    assert run(rows, "ips_blocked") == []


# ================================================================ inbound_remote_service
@pytest.mark.parametrize("port,sub", [(445, "T1021.002"), (3389, "T1021.001"), (5985, "T1021.006"),
                                      (5986, "T1021.006"), (22, "T1021.004")])
def test_inbound_remote_service_fires(run, port: int, sub: str) -> None:
    rows = run([conn(T0, "203.0.113.66", "10.10.20.15", port)], "inbound_remote_service")
    assert lab(rows) == [("T1021", sub, "Lateral Movement")]
    r = rows[0]
    assert (r["severity"], r["subject_host"], r["src_ip"], r["dst_ip"]) == (70, "10.10.20.15", "203.0.113.66",
                                                                             "10.10.20.15")


def test_inbound_remote_service_twice_fires_twice(run) -> None:
    rows = [conn(T0 + i * H, "203.0.113.66", "10.10.20.15", 3389) for i in range(2)]
    assert len(run(rows, "inbound_remote_service")) == 2


@pytest.mark.parametrize("case", ["internal_src", "denied", "external_dst", "triple_3x", "port_80"])
def test_inbound_remote_service_near_misses(run, case: str) -> None:
    rows = {"internal_src": [conn(T0, "10.0.1.5", "10.10.20.15", 3389)],
            "denied": [conn(T0, "203.0.113.66", "10.10.20.15", 3389, "conn_denied")],
            "external_dst": [conn(T0, "203.0.113.66", "49.36.200.10", 3389)],
            "triple_3x": [conn(T0 + i * H, "203.0.113.66", "10.10.20.15", 3389) for i in range(3)],
            "port_80": [conn(T0, "203.0.113.66", "10.10.20.15", 80)]}[case]
    assert run(rows, "inbound_remote_service") == []


def test_internal_lateral_and_inbound_are_disjoint(run) -> None:
    inbound = [conn(T0, "203.0.113.66", "10.10.20.15", 3389)]
    internal = [conn(T0, "10.0.1.5", "10.10.20.15", 3389)]
    assert run(inbound, "internal_lateral") == [] and run(internal, "inbound_remote_service") == []


# ================================================================ firewall beaconing: external C2 only
def fw_beacon(dst: str) -> list[dict]:
    return [conn(T0 + i * 60_000, "10.0.2.37", dst, 443) for i in range(11)]


def test_fw_beacon_to_external_fires(run) -> None:
    rows = run(fw_beacon("203.0.113.50"), "beaconing")
    assert lab(rows) == [("T1071", "T1071.001", "Command and Control")]
    assert (rows[0]["subject_host"], rows[0]["dst_ip"], rows[0]["raw_alert_count"]) == ("10.0.2.37", "203.0.113.50",
                                                                                         11)


def test_fw_beacon_to_internal_silent(run) -> None:
    assert run(fw_beacon("10.0.0.2"), "beaconing") == []


# ================================================================ port_scan
def vscan(n: int, spacing: int = 2 * S, action: str = "conn_denied") -> list[dict]:
    return [conn(T0 + i * spacing, "10.0.9.9", "10.0.1.20", 1000 + i, action) for i in range(n)]


def hscan(n: int, internal: bool = True, port: int = 445) -> list[dict]:
    return [conn(T0 + i * 2 * S, "10.0.9.9", f"10.0.3.{i + 1}" if internal else f"203.0.113.{100 + i}", port,
                 "conn_allowed") for i in range(n)]


def test_vertical_scan_20_ports_fires(run) -> None:
    rows = run(vscan(10) + vscan(20)[10:], "port_scan")
    assert lab(rows) == [("T1046", None, "Discovery")]
    r = rows[0]
    assert (r["raw_alert_count"], r["src_ip"], r["dst_ip"], r["subject_host"], r["ts_ms"]) == (
        20, "10.0.9.9", "10.0.1.20", "10.0.9.9", T0)


def test_scan_mixed_allowed_and_denied_counts(run) -> None:
    rows = vscan(20)
    for r in rows[::3]:
        r["action"] = "conn_allowed"
    assert len(run(rows, "port_scan")) == 1


def test_horizontal_scan_20_internal_hosts_fires(run) -> None:
    rows = run(hscan(20), "port_scan")
    assert lab(rows) == [("T1046", None, "Discovery")] and rows[0]["dst_ip"] is None
    assert rows[0]["raw_alert_count"] == 20


@pytest.mark.parametrize("case", ["19_ports", "20_ports_100_s", "20_external_443", "19_internal_hosts",
                                  "other_action"])
def test_port_scan_near_misses(run, case: str) -> None:
    rows = {"19_ports": vscan(19), "20_ports_100_s": vscan(20, spacing=5263),
            "20_external_443": hscan(20, internal=False, port=443), "19_internal_hosts": hscan(19),
            "other_action": [{**r, "action": "conn_out"} for r in vscan(20)]}[case]
    assert run(rows, "port_scan") == []


# ================================================================ internal_lateral
@pytest.mark.parametrize("port,sub", [(445, "T1021.002"), (3389, "T1021.001"), (5985, "T1021.006"),
                                      (5986, "T1021.006"), (22, "T1021.004")])
def test_internal_lateral_fires_with_sub_technique(run, port: int, sub: str) -> None:
    rows = run([conn(T0, "10.0.1.5", "10.0.2.10", port)], "internal_lateral")
    assert lab(rows) == [("T1021", sub, "Lateral Movement")]
    assert (rows[0]["subject_host"], rows[0]["dst_ip"]) == ("10.0.1.5", "10.0.2.10")


def test_internal_lateral_triple_seen_twice_both_fire(run) -> None:
    assert len(run([conn(T0 + i * H, "10.0.1.5", "10.0.2.10", 445) for i in range(2)], "internal_lateral")) == 2


@pytest.mark.parametrize("case", ["triple_3x", "denied", "to_external", "from_external", "port_80"])
def test_internal_lateral_near_misses(run, case: str) -> None:
    rows = {"triple_3x": [conn(T0 + i * H, "10.0.1.5", "10.0.2.10", 445) for i in range(3)],
            "denied": [conn(T0, "10.0.1.5", "10.0.2.10", 445, "conn_denied")],
            "to_external": [conn(T0, "10.0.1.5", EXT, 445)],
            "from_external": [conn(T0, EXT, "10.0.2.10", 3389)],
            "port_80": [conn(T0, "10.0.1.5", "10.0.2.10", 80)]}[case]
    assert run(rows, "internal_lateral") == []


# ================================================================ fw_config_change_after_login
def cfg_rows(login_ip: str = EXT, dt: int = H, cfg_user: str = "admin") -> list[dict]:
    return [ok(T0, "admin", login_ip), fw(T0 + dt, "config_change", src_user=cfg_user)]


def test_config_change_after_external_login_fires(run) -> None:
    rows = run(cfg_rows(), "fw_config_change_after_login")
    assert lab(rows) == [("T1562", "T1562.004", "Defense Impairment")]
    r = rows[0]
    assert (r["ts_ms"], r["src_user"], r["src_ip"], r["subject_host"], len(r["evidence_lines"])) == (
        T0 + H, "admin", EXT, FW, 2)


def test_config_change_boundary_2h_inclusive(run) -> None:
    assert len(run(cfg_rows(dt=2 * H), "fw_config_change_after_login")) == 1


@pytest.mark.parametrize("case", ["3h_later", "internal_login", "other_user", "before_login", "other_device"])
def test_config_change_near_misses(run, case: str) -> None:
    rows = {"3h_later": cfg_rows(dt=3 * H), "internal_login": cfg_rows(login_ip="10.0.99.10"),
            "other_user": cfg_rows(cfg_user="netops"), "before_login": cfg_rows(dt=-10 * MIN),
            "other_device": [ok(T0), {**fw(T0 + H, "config_change", src_user="admin"), "host": "fgt-02"}]}[case]
    assert run(rows, "fw_config_change_after_login") == []


# ================================================================ tor_or_proxy_app / web_malicious_category
@pytest.mark.parametrize("action,app,fires", [
    ("app_ctrl", "Tor", True), ("app_ctrl", "TOR.BROWSER", True), ("conn_allowed", "psiphon", True),
    ("conn_denied", "Ultrasurf", True), ("app_ctrl", "Freegate", True), ("app_ctrl", "Dropbox", False),
    ("web_access", "Tor", False)])
def test_tor_or_proxy_app(run, action: str, app: str, fires: bool) -> None:
    rows = run([fw(T0, action, app=app, src_ip="10.0.2.37", dst_ip=EXT2, dst_port=9001)], "tor_or_proxy_app")
    assert lab(rows) == ([("T1090", "T1090.003", "Command and Control")] if fires else [])
    if fires:
        assert rows[0]["subject_host"] == "10.0.2.37"


@pytest.mark.parametrize("action,category,fires", [
    ("web_blocked", "Malicious Websites", True), ("web_blocked", "Phishing", True),
    ("web_access", "Malicious Websites", False), ("web_blocked", "Games", False)])
def test_web_malicious_category(run, action: str, category: str, fires: bool) -> None:
    rows = run([fw(T0, action, signature=category, src_ip="10.0.2.37", dst_ip=EXT2)], "web_malicious_category")
    assert lab(rows) == ([("T1189", None, "Initial Access")] if fires else [])


# ================================================================ entity fallback on ECS rows
def ecs_beacon(src_ip: str | None) -> list[dict]:
    return [{"ts_ms": T0 + i * MIN, "source_type": "ecs_json", "action": "conn_out", "host": "ws-hr-012",
             "host_ip": "10.10.4.12", "src_ip": src_ip, "dst_ip": "10.10.0.40", "dst_port": 443, "bytes_out": 500}
            for i in range(11)]


def test_ecs_row_with_mapped_src_ip_keeps_host_name(run) -> None:
    rows = run(ecs_beacon("10.10.4.12"), "beaconing")
    assert [r["subject_host"] for r in rows] == ["ws-hr-012"]


def test_ecs_row_without_src_ip_keeps_reporting_host(run) -> None:
    # regression (fixed by BB-detect): the entity fallback used to give ECS rows the destination IP
    rows = run(ecs_beacon(None), "beaconing")
    assert [r["subject_host"] for r in rows] == ["ws-hr-012"]


def test_fallback_off_restores_literal_behaviour(run) -> None:
    rows = run([conn(T0, "10.0.1.5", "10.0.2.10", 445)], "internal_lateral", entity_fallback_ip=False)
    assert [r["subject_host"] for r in rows] == [FW]


# ================================================================ coverage table for the guards in test_detect.py
FW_MATCH_RULES = {"av_malware_download", "tor_or_proxy_app", "web_malicious_category"}
FW_TEMPLATES = {"signature_map", "port_scan", "internal_lateral", "config_change_after_login", "blocked_daily"}


def test_fw_rules_present_in_config() -> None:
    rules, _ = detect.rules_and_thresholds(config.load_config())
    ids = {r["id"] for r in rules}
    assert {"fw_admin_bruteforce", "fw_admin_spray", "vpn_bruteforce_success", "ips_signatures", "port_scan",
            "internal_lateral", "fw_config_change_after_login"} | FW_MATCH_RULES <= ids


# ================================================================ rarity N for firewall sources (episodes.py)
def _rarity(tmp_path, fallback: bool) -> float:
    import math  # noqa: F401
    from attacklens import episodes
    from .test_detect import _alert, _write_alerts
    from .conftest import query
    ev = [conn(T0 + k, f"10.0.0.{k}", EXT, 443) for k in range(1, 10)]          # 9 internal src IPs
    ev += [conn(T0 + 20, EXT, "10.0.0.50", 443)]                                 # external src: not an entity
    ev += [{"ts_ms": T0 + 30, "source_type": "ecs_json", "action": "proc_start", "host": "ws-1"}]
    ctx = make_events_parquet(tmp_path, ev)
    try:
        ctx.cfg["rules"]["thresholds"]["entity_fallback_ip"] = fallback
        _write_alerts(ctx, [_alert(T0, rule="r_fw", severity=50)])
        ctx.con.execute(f"COPY (SELECT 'r_fw' AS rule_id, 2.0::DOUBLE AS base_freq) TO "
                        f"'{(ctx.work_dir / 'rule_host_baseline.parquet').as_posix()}' (FORMAT PARQUET)")
        episodes.run(ctx)
        return query(ctx, f"SELECT rarity FROM read_parquet('{(ctx.work_dir / 'episodes.parquet').as_posix()}')"
                     )[0]["rarity"]
    finally:
        ctx.con.close()


def test_rarity_n_counts_internal_src_ips_for_firewall_rows(tmp_path) -> None:
    import math
    # N = 9 internal firewall src IPs + 1 ECS host (fgt-01 itself and the external src are not endpoints)
    assert _rarity(tmp_path / "on", True) == pytest.approx(math.log(1 + 10 / 2) / math.log(1 + 10))
    # literal §6.1: N = reporting hosts = {fgt-01, ws-1}
    assert _rarity(tmp_path / "off", False) == pytest.approx(math.log(1 + 2 / 2) / math.log(1 + 2))
