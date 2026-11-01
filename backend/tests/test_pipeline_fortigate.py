"""L3 FortiGate pipeline (code-review finding 8): tools/fortigate_gen.py output -> ingest -> full pipeline, so the
firewall detection pack is proven on INGESTED key=value data, not only on hand-written canonical Parquet.

~3 MB, one worker, seed 42 (~10 s). Step-level asserts check raw_alerts (Stage 2); scorecard asserts depend on
Stage 3/4 linking: the PRD targets are xfail(strict=True) (they turn red the moment they pass, so the marker is
removed), and RATCHET tests pin the level reached so far so a linking regression goes red. Raise the ratchet
whenever the level improves (next: when F2 is rebuilt) — never lower it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

from eval.match import norm_host, technique_ok

# L3 = the shipped configuration end to end, SigmaHQ pack included (conftest: module fixtures follow this)
pytestmark = pytest.mark.sigma
REPO = Path(__file__).resolve().parents[2]
# GT step -> rule expected to produce it (None = known detection gap)
EXPECTED_RULE = {
    ("F1", 1): "fw_admin_bruteforce", ("F1", 2): "fw_admin_bruteforce", ("F1", 3): "fw_config_change_after_login",
    ("F1", 4): "inbound_remote_service", ("F1", 5): "internal_lateral", ("F1", 6): "exfil_volume",
    ("F2", 1): "ips_signatures", ("F2", 2): "vpn_login_context", ("F2", 3): "port_scan", ("F2", 4): "internal_lateral",
    ("F3", 1): "av_malware_download", ("F3", 2): "beaconing", ("F3", 3): "tor_or_proxy_app",
}


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> dict:
    tmp = tmp_path_factory.mktemp("l3fw")
    raw, out = tmp / "raw", tmp / "out"
    g = subprocess.run([sys.executable, str(REPO / "tools" / "fortigate_gen.py"), "--size", "3M", "--workers", "1",
                        "--seed", "42", "--out", str(raw)], capture_output=True, text=True, timeout=120)
    assert g.returncode == 0, g.stderr[-2000:]
    from attacklens.run import run_pipeline
    metrics = run_pipeline(raw, out, parquet=tmp / "pq", ground_truth=raw / "ground_truth" / "attacks.json")
    con = duckdb.connect()
    con.execute("SET TimeZone='UTC'")
    cur = con.execute(f"SELECT * FROM read_parquet('{(out / 'work' / 'raw_alerts.parquet').as_posix()}')")
    cols = [d[0] for d in cur.description]
    alerts = [dict(zip(cols, r)) for r in cur.fetchall()]
    ev = con.execute(f"""SELECT action, count(*) n, count(signature) sig, count(vendor_severity) sev, count(app) app,
                                count(src_zone) zone FROM read_parquet('{(tmp / 'pq' / 'events').as_posix()}/**/*.parquet',
                                hive_partitioning=true) GROUP BY action""").fetchall()
    con.close()
    return {"raw": raw, "out": out, "metrics": metrics, "alerts": alerts,
            "events": {a: {"n": n, "signature": s, "vendor_severity": v, "app": p, "src_zone": z}
                       for a, n, s, v, p, z in ev},
            "manifest": json.loads((raw / "manifest.json").read_text(encoding="utf-8")),
            "gt": json.loads((raw / "ground_truth" / "attacks.json").read_text(encoding="utf-8")),
            "card": json.loads((out / "eval_scorecard.json").read_text(encoding="utf-8")),
            "acc": json.loads((out / "ingest_accounting.json").read_text(encoding="utf-8"))}


def test_run_completes(run: dict) -> None:
    m = json.loads((run["out"] / "run_metrics.json").read_text(encoding="utf-8"))
    assert m.get("error") is None
    assert {"ingest", "detect", "episodes", "link", "incidents", "publish"} <= {s["name"] for s in m["stages"]}


def test_ingest_all_fortigate_zero_drops(run: dict) -> None:
    rows = [a for a in run["acc"] if a["rows_in"]]
    assert [a["source_type"] for a in rows] == ["fortigate_kv"]
    a = rows[0]
    assert a["dropped"] == 0 and a["drop_reasons"] == {}
    assert a["rows_in"] == a["rows_ok"] == run["manifest"]["events"] + run["manifest"]["scenario_events"]


def test_vendor_columns_populated_on_relevant_rows(run: dict) -> None:
    e = run["events"]
    for action in ("ips_alert", "av_alert", "config_change", "conn_allowed", "conn_denied", "app_ctrl",
                   "web_blocked", "login_failed", "login_success"):
        assert e.get(action, {}).get("n", 0) > 0, f"no {action} rows ingested"
    for action in ("ips_alert", "av_alert", "web_blocked", "web_access"):
        assert e[action]["signature"] == e[action]["n"], action          # attack / virus / catdesc
    assert e["ips_alert"]["vendor_severity"] == e["ips_alert"]["n"]
    for action in ("conn_allowed", "conn_denied"):
        assert e[action]["app"] == e[action]["n"] and e[action]["src_zone"] == e[action]["n"], action
    assert e["app_ctrl"]["app"] == e["app_ctrl"]["n"] and e["ips_alert"]["src_zone"] == e["ips_alert"]["n"]


def _steps(run: dict) -> list[tuple[str, dict]]:
    return [(a["id"], s) for a in run["gt"]["attacks"] for s in a["steps"]]


def _hits(run: dict, s: dict, rule: str) -> list[dict]:
    """Raw alerts of `rule` within 10 min of the step, on the step's host, with the step's technique."""
    return [a for a in run["alerts"] if a["rule_id"] == rule and abs(a["ts_ms"] - s["ts_ms"]) <= 600_000
            and norm_host(a["subject_host"]) == norm_host(s["host"])
            and technique_ok(s["technique_id"], a["technique_id"], a["sub_technique_id"])]


@pytest.mark.parametrize("key", [k for k, v in EXPECTED_RULE.items() if v], ids=lambda k: f"{k[0]}-{k[1]}")
def test_planted_step_detected_on_expected_host(run: dict, key: tuple[str, int]) -> None:
    s = next(st for sid, st in _steps(run) if (sid, st["step"]) == key)
    assert _hits(run, s, EXPECTED_RULE[key]), (key, s["technique_id"], s["host"])



def test_ground_truth_covers_every_expected_step(run: dict) -> None:
    assert sorted((sid, s["step"]) for sid, s in _steps(run)) == sorted(EXPECTED_RULE)


def test_f4_decoy_does_not_fire_config_change_rule(run: dict) -> None:
    cfg = [a for a in run["alerts"] if a["rule_id"] == "fw_config_change_after_login"]
    f1 = next(st for sid, st in _steps(run) if (sid, st["step"]) == ("F1", 3))
    assert [a["ts_ms"] for a in cfg] == [f1["ts_ms"]]  # 7 daily routine edits from the admin network stay silent


def test_scorecard_keys(run: dict) -> None:
    for k in ("detection_pct", "labels_pct", "rebuilt_pct", "false_alarms_strict_pct", "false_alarms_lenient_pct",
              "singleton_recall_pct"):
        assert k in run["card"], k
    assert run["card"]["counts"]["attacks"] == 3


def test_detection_at_least_90(run: dict) -> None:
    assert run["card"]["detection_pct"] >= 90.0, run["card"]["per_attack"]


def test_all_attacks_rebuilt(run: dict) -> None:
    assert run["card"]["rebuilt_pct"] == 100.0, [(a["id"], a["lcs_ratio"]) for a in run["card"]["per_attack"]]


def test_strict_false_alarms_below_10(run: dict) -> None:
    assert run["card"]["false_alarms_strict_pct"] < 10.0


# ---------------------------------------------------------------- ratchet: the level reached so far (raise, never lower)
RATCHET = {"detection_pct": 100.0, "labels_pct": 100.0, "false_alarms_strict_pct": 0.0, "rebuilt": {"F1", "F2", "F3"}}


def test_ratchet_detection(run: dict) -> None:
    assert run["card"]["detection_pct"] >= RATCHET["detection_pct"], run["card"]["per_attack"]


def test_ratchet_labels(run: dict) -> None:
    assert run["card"]["labels_pct"] == RATCHET["labels_pct"]


def test_ratchet_false_alarms_strict(run: dict) -> None:
    assert run["card"]["false_alarms_strict_pct"] == RATCHET["false_alarms_strict_pct"], run["card"][
        "unmatched_incidents"]


def test_ratchet_rebuilt_attacks(run: dict) -> None:
    rebuilt = {a["id"] for a in run["card"]["per_attack"] if a["rebuilt"]}
    assert RATCHET["rebuilt"] <= rebuilt, [(a["id"], a["lcs_ratio"], a["steps_in_matched_incident"])
                                            for a in run["card"]["per_attack"]]
