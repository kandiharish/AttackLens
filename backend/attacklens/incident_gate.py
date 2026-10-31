"""Stage 4 gate and risk (DEVELOPMENT.md §6.3, §6.4, §15.7): parameters, the component gate (seed / critical /
hands-on-keyboard burst paths), allowlist entities and the B-1 risk score. Pure Python over episode dicts."""

from __future__ import annotations

import math
from typing import Any

from attacklens.schemas import TACTIC_IDX


def _params(cfg: dict[str, Any]) -> dict[str, Any]:
    lk = cfg.get("linking") or {}
    th = (cfg.get("rules") or {}).get("thresholds") or {}
    gate, risk, path = lk.get("gate") or {}, lk.get("risk") or {}, lk.get("path") or {}
    return {
        "min_tactics": int(gate.get("min_tactics", 2)),
        "tactic_conf": float(gate.get("min_tactic_confidence", 0)),
        "critical_min_merged": int(gate.get("critical_min_merged_alerts", 5)),
        "burst_techniques": int(gate.get("min_distinct_techniques", 0) or 0),
        "burst_rules": int(gate.get("multi_technique_min_rules", 2)),
        "burst_window": int(gate.get("multi_technique_window_ms", 7_200_000)),
        "burst_conf": float(gate.get("multi_technique_min_conf", 60)),
        "burst_seeds": int(gate.get("multi_technique_min_seeds", 0)),
        "burst_risk_floor": int(gate.get("burst_risk_floor", 0)),
        "peel_tails": bool(path.get("peel_standalone_branch_tails", False)),
        "node_score": str(path.get("dp_node_score", "severity")),
        "max_per_comp": int(gate.get("max_incidents_per_component", 20)),
        "seed": float(th.get("seed_confidence", gate.get("seed_confidence", 65))),
        "critical": float(th.get("critical_confidence", gate.get("critical_confidence", 90))),
        "sup_max": int(gate.get("suppressed_max_entries", 5000)), "sup_ids": int(gate.get("suppressed_max_ids", 20)),
        # linking.yaml risk.raw_ref_score wins; rules.yaml thresholds.raw_ref_score is the fallback (§6.4 B-1).
        "raw_ref": float(risk.get("raw_ref_score") or th.get("raw_ref_score") or 15.0),
        "base_points": float(risk.get("base_points", 90)), "bonus_cap": float(risk.get("bonus_cap", 10)),
        "exempt": list(path.get("floor_exempt_tactics", ["Initial Access", "Credential Access", "Lateral Movement"])),
        "branch_ratio": float(path.get("branch_min_ratio", 0.5)), "max_branches": int(path.get("max_branches", 5)),
        "ev_lines": int(path.get("max_evidence_lines", 3)), "ev_chars": int(path.get("max_evidence_chars", 300)),
        "elevated": set((lk.get("reach") or {}).get("elevated_tactics", ["Privilege Escalation"])),
    }


def _round(x: float) -> int:
    return int(math.floor(x + 0.5))


def tactic_idx(e: dict[str, Any]) -> int:
    return int(e.get("tactic_idx") or TACTIC_IDX.get(e.get("tactic") or "", 0))


def entities(e: dict[str, Any]) -> set[str]:
    out = set()
    for typ, cols in (("host", ("subject_host", "src_host", "dst_host")), ("user", ("src_user", "target_user")),
                      ("ip", ("src_ip", "dst_ip"))):
        out |= {f"{typ}:{str(e[c]).lower()}" for c in cols if e.get(c)}
    return out


def allowlist_entities(cfg: dict[str, Any]) -> set[str]:
    al = cfg.get("allowlist") or {}
    if isinstance(al, list):
        return {str(x).lower() for x in al}
    out = {str(x).lower() for x in al.get("entities", []) or []}
    for key, typ in (("hosts", "host"), ("users", "user"), ("ips", "ip")):
        out |= {f"{typ}:{str(x).lower()}" for x in al.get(key, []) or []}
    return out


def burst(ce: list[dict[str, Any]], p: dict[str, Any]) -> bool:
    """Hands-on-keyboard burst: on one subject, within burst_window ms, >= burst_techniques distinct parent
    techniques from >= burst_rules distinct rules, max confidence >= burst_conf and >= burst_seeds seeds."""
    if p.get("burst_techniques", 0) <= 0:
        return False
    by_subject: dict[str, list[dict[str, Any]]] = {}
    for e in ce:
        subj = e.get("subject_host") or e.get("host")
        if subj:
            by_subject.setdefault(str(subj).lower(), []).append(e)
    for evs in by_subject.values():
        evs.sort(key=lambda e: (int(e["ts_ms"]), str(e["episode_id"])))
        lo = 0
        for hi in range(len(evs)):
            while int(evs[hi]["ts_ms"]) - int(evs[lo]["ts_ms"]) > p["burst_window"]:
                lo += 1
            win = evs[lo:hi + 1]
            techs = {str(e.get("technique_id") or "").split(".")[0] for e in win} - {""}
            rules = {e.get("rule_id") for e in win} - {None}
            confs = [float(e.get("confidence") or 0) for e in win]
            if (len(techs) >= p["burst_techniques"] and len(rules) >= p["burst_rules"]
                    and max(confs) >= p["burst_conf"] and sum(c >= p["seed"] for c in confs) >= p["burst_seeds"]):
                return True
    return False


def gate(tactics: set[str], max_conf: float, allowlisted: bool, p: dict[str, Any],
         top_merged: int | None = None, is_burst: bool = False) -> str | None:
    """None = keep. Otherwise the suppression reason.

    A component with fewer than min_tactics counted tactics passes only via the critical path, and then only if its
    top-confidence episode merged at least critical_min_merged_alerts alerts (one stray .locked file is not ransomware).
    top_merged=None skips that check.
    """
    if allowlisted:
        return "allowlisted: every entity is on the allowlist"
    if (len(tactics) >= p["min_tactics"] and max_conf >= p["seed"]) or is_burst:
        return None
    if max_conf >= p["critical"]:
        need = int(p.get("critical_min_merged", 1))
        if len(tactics) >= p["min_tactics"] or top_merged is None or top_merged >= need:
            return None
        return (f"critical single-tactic component: top episode has {top_merged} merged alert(s) < {need}")
    if len(tactics) < p["min_tactics"]:
        return f"fewer than {p['min_tactics']} tactics and max confidence {max_conf:.0f} < {p['critical']:.0f}"
    return f"max confidence {max_conf:.0f} < {p['seed']:.0f}"


def risk_score(path_eps: list[dict[str, Any]], p: dict[str, Any]) -> tuple[int, float]:
    """B-1: raw = sum_t w_t ln(S_t), S_t = max severity at tactic t on 1-10, w_t = (10 + t) / 10."""
    s_t: dict[int, float] = {}
    for e in path_eps:
        t = tactic_idx(e)
        s_t[t] = max(s_t.get(t, 1.0), min(10.0, max(1.0, float(e.get("severity") or 0) / 10.0)))
    raw = sum((10 + t) / 10 * math.log(s) for t, s in s_t.items())
    hosts = {e.get("subject_host") or e.get("host") for e in path_eps} - {None}
    merged = sum(int(e.get("merged_alert_count") or 0) for e in path_eps)
    bonus = min(p["bonus_cap"], _round(2 * math.log(1 + len(hosts)) + math.log(1 + merged)))
    return int(min(100, _round(p["base_points"] * raw / p["raw_ref"]) + bonus)), raw
