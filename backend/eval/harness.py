"""Evaluation harness (TESTING.md §5). `evaluate(out_dir, ground_truth) -> dict` is pure (writes nothing);
`main()` is the CLI that writes out_dir/eval_scorecard.json.

    python -m eval.harness --out data/out/g1 --gt data/raw/g1/ground_truth/attacks.json

Rules are frozen once eval/test_probes.py passes. NEVER tune this file to make a run look better.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import duckdb

from attacklens.models import Incident, Step

from .match import (
    TOLERANCE_MS, Candidate, GTStep, PredStep, candidates, greedy_assign, lcs_len, make_gt_step,
    norm_host, norm_ip, norm_tactic, norm_technique, norm_user, parse_ts_ms, technique_ok,
)

log = logging.getLogger(__name__)

HARNESS_VERSION = "1.0"
# Noise singletons detectable from raw fields alone (TESTING.md §5.2). T1110 singletons are not (count is a label).
DETECTABLE_NOISE = frozenset({"T1059.001", "T1071.001", "T1547.001", "T1486"})
# PRD §4 targets. Detection/labels/FA are strict inequalities; rebuilt "half" / "all".
TARGETS = {
    "detection_pct": {"good": (">", 70.0), "great": (">", 90.0)},
    "labels_pct": {"good": (">", 60.0), "great": (">", 85.0)},
    "rebuilt_pct": {"good": (">=", 50.0), "great": (">=", 100.0)},
    "false_alarms_strict_pct": {"good": ("<", 30.0), "great": ("<", 10.0)},
}


# ---------------------------------------------------------------- loading
def load_ground_truth(path: Path) -> tuple[dict, list[GTStep]]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    steps: list[GTStep] = []
    seen: set[tuple[str, int]] = set()
    for atk in doc.get("attacks", []):
        for s in atk.get("steps", []):
            g = make_gt_step(atk["id"], s)
            if g.key in seen:
                raise ValueError(f"duplicate ground-truth step {g.key}")
            seen.add(g.key)
            steps.append(g)
    return doc, steps


def load_noise(path: Path) -> list[GTStep]:
    out: list[GTStep] = []
    if not path.exists():
        return out
    with path.open(encoding="utf-8-sig") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            d = {**d, "step": i}
            out.append(make_gt_step("noise", d))
    return out


def _step_to_pred(inc_id: str, order: int, s: Step, in_backbone: bool) -> PredStep:
    return PredStep(
        incident_id=inc_id, episode_id=s.episode_id, order=order, ts_ms=parse_ts_ms(s.ts),
        technique=norm_technique(s.technique_id), sub_technique=norm_technique(s.sub_technique_id),
        tactic=norm_tactic(s.tactic), host=norm_host(s.host), user=norm_user(s.user),
        ips=frozenset(x for x in (norm_ip(s.src_ip), norm_ip(s.dst_ip)) if x),
        extra={"rule_id": s.rule_id, "confidence": s.confidence, "severity": s.severity, "ts": s.ts,
               "technique_id": s.technique_id, "tactic": s.tactic, "host": s.host, "user": s.user,
               "merged_alert_count": s.merged_alert_count, "in_backbone": in_backbone, "pos": s.step},
    )


def load_incidents(out_dir: Path) -> tuple[list[Incident], list[PredStep], int]:
    """Predictions = backbone + branch steps, deduped by episode_id (first occurrence wins)."""
    files = sorted((Path(out_dir) / "incidents").glob("*.json"))
    incidents = [Incident.model_validate_json(p.read_text(encoding="utf-8")) for p in files]
    incidents.sort(key=lambda i: i.id)
    ids = [i.id for i in incidents]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate incident ids in incidents/*.json")
    preds: list[PredStep] = []
    seen: set[str] = set()
    dups = 0
    for inc in incidents:
        order = 0
        steps = [(s, True) for s in sorted(inc.backbone, key=lambda x: x.step)]
        steps += [(s, False) for br in inc.branches for s in br]
        for s, in_bb in steps:
            if s.episode_id in seen:
                dups += 1
                continue
            seen.add(s.episode_id)
            preds.append(_step_to_pred(inc.id, order, s, in_bb))
            order += 1
    return incidents, preds, dups


def load_raw_alerts(path: Path) -> tuple[list[PredStep], list[dict]] | None:
    """Raw alerts (Stage 2) for singleton recall + per-rule counts. None if the file is absent."""
    if not path.exists():
        return None
    con = duckdb.connect()
    try:
        con.execute("SET TimeZone='UTC'")
        src = f"read_parquet('{path.as_posix()}')"
        per_rule = [
            {"rule_id": r, "alerts": int(n), "raw_alert_count": int(c or 0)}
            for r, n, c in con.execute(
                f"SELECT rule_id, count(*), sum(raw_alert_count) FROM {src} GROUP BY rule_id ORDER BY rule_id"
            ).fetchall()
        ]
        parents = sorted({t.split(".")[0] for t in DETECTABLE_NOISE})
        rows = con.execute(
            f"SELECT technique_id, sub_technique_id, tactic, ts_ms, coalesce(subject_host, host), src_user, "
            f"target_user, src_ip, dst_ip FROM {src} WHERE split_part(coalesce(sub_technique_id, technique_id), "
            f"'.', 1) IN ({','.join('?' for _ in parents)}) OR split_part(technique_id, '.', 1) IN "
            f"({','.join('?' for _ in parents)})", [*parents, *parents]).fetchall()
    finally:
        con.close()
    preds = []
    for k, (tid, sub, tac, ts, host, su, tu, sip, dip) in enumerate(rows):
        users = [u for u in (norm_user(tu), norm_user(su)) if u]
        preds.append(PredStep(
            incident_id="raw_alerts", episode_id=f"ra{k}", order=k, ts_ms=int(ts),
            technique=norm_technique(tid), sub_technique=norm_technique(sub), tactic=norm_tactic(tac),
            host=norm_host(host), user=users[0] if users else None, alt_users=frozenset(users[1:]),
            ips=frozenset(x for x in (norm_ip(sip), norm_ip(dip)) if x)))
    return preds, per_rule


# ---------------------------------------------------------------- metrics helpers
def _pct(num: int, den: int) -> float | None:
    """0-100 float, None when not computable (empty denominator) — DEVELOPMENT.md §15.6."""
    return round(100.0 * num / den, 2) if den else None


def _passes(metric: str, value: float | None) -> dict[str, bool]:
    """A metric that is not computable passes nothing."""
    ops = {">": lambda a, b: a > b, ">=": lambda a, b: a >= b, "<": lambda a, b: a < b}
    return {lvl: bool(value is not None and ops[op](value, thr)) for lvl, (op, thr) in TARGETS[metric].items()}


def _noise_matches(noise: list[GTStep], preds: list[PredStep]) -> list[Candidate]:
    """One-to-one noise matching; only label-correct pairs count (an alert of another rule is not a detection)."""
    return greedy_assign([c for c in candidates(noise, preds) if c.label])


def _ep_view(p: PredStep) -> dict:
    e = p.extra
    return {"episode_id": p.episode_id, "ts": e.get("ts"), "rule_id": e.get("rule_id"),
            "technique_id": e.get("technique_id"), "tactic": e.get("tactic"), "host": e.get("host"),
            "user": e.get("user"), "confidence": e.get("confidence"), "severity": e.get("severity")}


# ---------------------------------------------------------------- evaluate
def evaluate(out_dir: Path, ground_truth: Path) -> dict[str, Any]:
    out_dir, ground_truth = Path(out_dir), Path(ground_truth)
    gt_doc, gts = load_ground_truth(ground_truth)
    incidents, preds, dup_eps = load_incidents(out_dir)
    noise = load_noise(ground_truth.parent / "noise_alerts.jsonl")
    raw = load_raw_alerts(out_dir / "work" / "raw_alerts.parquet")

    chosen = greedy_assign(candidates(gts, preds))
    by_gt = {c.gt.key: c for c in chosen}

    # incident <-> attack: highest step overlap, one-to-one
    overlap: Counter[tuple[str, str]] = Counter()
    labels_in: Counter[tuple[str, str]] = Counter()
    for c in chosen:
        overlap[(c.pred.incident_id, c.gt.attack_id)] += 1
        labels_in[(c.pred.incident_id, c.gt.attack_id)] += int(c.label)
    inc_of_attack: dict[str, str] = {}
    attack_of_inc: dict[str, str] = {}
    for (inc, atk), n in sorted(overlap.items(), key=lambda kv: (-kv[1], -labels_in[kv[0]], kv[0])):
        if inc in attack_of_inc or atk in inc_of_attack:
            continue
        inc_of_attack[atk], attack_of_inc[inc] = inc, atk

    # per attack
    attacks: dict[str, list[GTStep]] = defaultdict(list)
    for g in gts:
        attacks[g.attack_id].append(g)
    per_attack, rebuilt = [], 0
    for atk_id in [a["id"] for a in gt_doc.get("attacks", [])]:
        steps = sorted(attacks.get(str(atk_id), []), key=lambda g: g.step)
        inc = inc_of_attack.get(str(atk_id))
        in_inc = [by_gt[g.key] for g in steps if g.key in by_gt and by_gt[g.key].pred.incident_id == inc]
        pred_seq = [c.gt.step for c in sorted(in_inc, key=lambda c: (c.pred.ts_ms, c.pred.order))]
        gt_seq = [g.step for g in steps]
        lcs_ratio = round(lcs_len(gt_seq, pred_seq) / len(gt_seq), 4) if gt_seq else 0.0
        # the backbone must also list its matched steps in GT order (a path drawn out of order is wrong)
        bb = sorted((c for c in in_inc if c.pred.extra.get("in_backbone")), key=lambda c: c.pred.extra["pos"])
        bb_seq = [c.gt.step for c in bb]
        backbone_order_ok = bb_seq == sorted(bb_seq)
        is_rebuilt = (bool(steps) and inc is not None and len(in_inc) == len(steps) and lcs_ratio == 1.0
                      and backbone_order_ok)
        rebuilt += int(is_rebuilt)
        per_attack.append({
            "id": str(atk_id), "steps": len(steps),
            "steps_matched": sum(1 for g in steps if g.key in by_gt),
            "steps_in_matched_incident": len(in_inc),
            "labels_correct": sum(1 for g in steps if g.key in by_gt and by_gt[g.key].label),
            "matched_incident": inc, "lcs_ratio": lcs_ratio, "backbone_order_ok": backbone_order_ok,
            "rebuilt": is_rebuilt,
            "step_detail": [{
                "step": g.step, "technique_id": g.technique, "tactic": g.tactic, "host": g.host,
                "matched": g.key in by_gt,
                "incident_id": by_gt[g.key].pred.incident_id if g.key in by_gt else None,
                "episode_id": by_gt[g.key].pred.episode_id if g.key in by_gt else None,
                "pred_technique_id": by_gt[g.key].pred.extra.get("technique_id") if g.key in by_gt else None,
                "pred_tactic": by_gt[g.key].pred.extra.get("tactic") if g.key in by_gt else None,
                "label_ok": by_gt[g.key].label if g.key in by_gt else False,
                "dt_ms": by_gt[g.key].dt_ms if g.key in by_gt else None,
            } for g in steps],
        })

    # false alarms
    preds_by_inc: dict[str, list[PredStep]] = defaultdict(list)
    for p in preds:
        preds_by_inc[p.incident_id].append(p)
    unmatched = [i for i in incidents if i.id not in attack_of_inc]
    noise_only: set[str] = set()
    if noise:
        for inc in unmatched:
            ps = preds_by_inc.get(inc.id, [])
            if ps and len(_noise_matches(noise, ps)) == len(ps):
                noise_only.add(inc.id)
    n_inc = len(incidents)

    # singleton recall
    detectable = [g for g in noise if g.technique in DETECTABLE_NOISE]
    recall_src = "raw_alerts" if raw is not None else "incidents"
    recall_preds = raw[0] if raw is not None else preds
    detected = len(_noise_matches(detectable, recall_preds)) if detectable else 0

    matched_steps = len(chosen)
    labels_correct = sum(1 for c in chosen if c.label)
    tech_only = sum(1 for c in chosen if technique_ok(c.gt.technique, c.pred.technique, c.pred.sub_technique))
    metrics = {
        "detection_pct": _pct(matched_steps, len(gts)),
        "labels_pct": _pct(labels_correct, matched_steps),
        "labels_technique_only_pct": _pct(tech_only, matched_steps),
        "rebuilt_pct": _pct(rebuilt, len(per_attack)),
        "false_alarms_strict_pct": _pct(len(unmatched), n_inc),
        "false_alarms_lenient_pct": _pct(len(unmatched) - len(noise_only), n_inc - len(noise_only)),
        "singleton_recall_pct": _pct(detected, len(detectable)),
    }

    top3 = []
    for inc in unmatched:
        ps = sorted(preds_by_inc.get(inc.id, []),
                    key=lambda p: (-(p.extra.get("confidence") or 0), -(p.extra.get("severity") or 0),
                                   -(p.extra.get("merged_alert_count") or 0), p.order))
        top3.append({"id": inc.id, "risk": inc.risk, "episode_count": inc.episode_count,
                     "noise_only": inc.id in noise_only, "top_episodes": [_ep_view(p) for p in ps[:3]]})

    return {
        "harness_version": HARNESS_VERSION,
        "ground_truth": ground_truth.as_posix(),
        "attack_version": gt_doc.get("attack_version"),
        "rules": {"tolerance_ms": TOLERANCE_MS, "step_match": "dt<=tol AND host AND (user OR ip)",
                  "labels": "technique (parent or exact sub; conflicting sub = wrong) AND tactic",
                  "rebuilt": "all steps in the one matched incident AND LCS ratio == 1.0 (time order) "
                             "AND backbone positions in GT order",
                  "false_alarms_lenient": "(unmatched - noise_only) / (incidents - noise_only)",
                  "null": "a metric whose denominator is 0 is null and passes no target"},
        **metrics,
        "targets": {m: _passes(m, metrics[m]) for m in TARGETS},
        "counts": {
            "attacks": len(per_attack), "gt_steps": len(gts), "incidents": n_inc,
            "predicted_steps": len(preds), "duplicate_episode_ids": dup_eps,
            "steps_matched": matched_steps, "labels_correct": labels_correct, "attacks_rebuilt": rebuilt,
            "incidents_matched": len(attack_of_inc), "incidents_unmatched": len(unmatched),
            "incidents_noise_only": len(noise_only), "noise_alerts": len(noise),
            "noise_detectable": len(detectable), "noise_detected": detected,
        },
        "singleton_recall_source": recall_src if detectable else None,
        "per_attack": per_attack,
        "per_rule_alerts": raw[1] if raw is not None else None,
        "unmatched_incidents": top3,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.harness", description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=Path, help="pipeline output dir (has incidents/)")
    ap.add_argument("--gt", required=True, type=Path, help="ground_truth/attacks.json")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    card = evaluate(a.out, a.gt)
    dest = a.out / "eval_scorecard.json"
    dest.write_text(json.dumps(card, indent=2), encoding="utf-8")
    log.info("detection %s labels %s rebuilt %s FA strict %s lenient %s singleton recall %s -> %s",
             *(card[k] for k in ("detection_pct", "labels_pct", "rebuilt_pct", "false_alarms_strict_pct",
                                 "false_alarms_lenient_pct", "singleton_recall_pct")), dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
