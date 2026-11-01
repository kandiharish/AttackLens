"""sigma_map.yaml options used by sigma_rules.py (split out to keep it < 400 lines; re-exported there):
logsource `keywords` -> keyword column + guard, runtime `level_override`, compile-time `label_override`, and the
coverage report."""

from __future__ import annotations

from collections import Counter
from typing import Any

from attacklens.schemas import TACTIC_IDX
from attacklens.sigma_compile import lit

LEVELS = ("informational", "low", "medium", "high", "critical")
# raw_line keyword search never reads a line whose payload is structured (JSON object / CEF): those are the formats
# the generator writes its ground-truth labels into (threat, rule, labels ...), also when wrapped in a syslog frame.
# Override per logsource with keywords.exclude_regex (sigma_map.yaml); an empty value keeps this default.
RAW_LINE_EXCLUDE = r'\{\s*"|CEF:\s*\d+\|'


def level_overrides(smap: dict[str, Any]) -> dict[str, str]:
    """sigma_map `level_override` [{id, level, reason}] -> {lower-case id or uuid: level}. A bad level is a config
    error (raised), never silently ignored."""
    out: dict[str, str] = {}
    for d in smap.get("level_override") or []:
        level = str(d.get("level") or "").lower()
        if level not in LEVELS or level not in (smap.get("level_severity") or {}):
            raise ValueError(f"sigma_map level_override {d.get('id')}: unknown level {d.get('level')!r}")
        out[str(d["id"]).lower()] = level
    return out


def check_tactic(technique: str, tactic: str, techniques: dict[str, Any], rid: Any = None) -> None:
    """A label_override tactic must be one of the technique's v20 tactics (attack_v20.json); else a config error."""
    t = techniques.get(technique) or {}
    if tactic not in (t.get("tactics") or [t.get("tactic")]):
        raise ValueError(f"sigma_map label_override {rid}: tactic {tactic!r} is not a v20 tactic of {technique}")


def label_overrides(smap: dict[str, Any], attack: dict[str, Any]) -> dict[str, dict[str, str]]:
    """sigma_map `label_override` [{id, technique?, tactic?, reason}] -> {lower-case id or uuid: {technique?,
    tactic?, reason}}. Compile-time (part of the Sigma cache key). Unlike technique_override (used only when a rule
    has no technique tag), `technique` REPLACES the rule's tagged techniques; `tactic` must be one of that
    technique's v20 tactics (checked here when technique is given, at compile against the rule's own technique when
    not). Every problem (unknown technique / tactic, neither given, no reason, duplicate id) raises ValueError."""
    techniques = attack.get("techniques") or {}
    out: dict[str, dict[str, str]] = {}
    for d in smap.get("label_override") or []:
        rid = str(d.get("id") or "").strip().lower()
        tech = str(d.get("technique") or "").strip().upper()
        tactic = str(d.get("tactic") or "").strip()
        if not rid or not (tech or tactic):
            raise ValueError(f"sigma_map label_override {d.get('id')}: needs an id and technique and/or tactic")
        if not str(d.get("reason") or "").strip():
            raise ValueError(f"sigma_map label_override {rid}: a reason is required")
        if rid in out:
            raise ValueError(f"sigma_map label_override {rid}: duplicate id")
        if tech and (tech not in techniques or tech.split(".")[0] not in techniques):
            raise ValueError(f"sigma_map label_override {rid}: technique {tech} not in attack_v20.json")
        if tactic and tactic not in TACTIC_IDX:
            raise ValueError(f"sigma_map label_override {rid}: {tactic!r} is not a v20 tactic")
        if tech and tactic:
            check_tactic(tech, tactic, techniques, rid)
        out[rid] = {k: v for k, v in (("technique", tech), ("tactic", tactic)) if v}
        out[rid]["reason"] = str(d["reason"]).strip()
    return out


def keyword_column(kw: Any) -> tuple[str | None, str | None]:
    """logsource `keywords` -> (column expression, guard predicate or None). Guard: source_type IN (source_types);
    for raw_line also NOT regexp_matches(raw_line, exclude_regex) (RAW_LINE_EXCLUDE by default) so a syslog frame that
    wraps generator JSON / CEF (with its label fields) is never keyword-searched. Config text is quoted via lit().
    exclude_regex: false switches that exclusion off (only with source_types): for label-stripped JSON sources whose
    every line is JSON (cloud audit logs); null / '' keeps the default."""
    if not isinstance(kw, dict):
        return (str(kw) if kw else None), None
    expr = str(kw.get("expr") or "") or None
    conds = []
    if kw.get("source_types"):
        conds.append("source_type IN (" + ", ".join(lit(str(x)) for x in kw["source_types"]) + ")")
    if conds and expr == "raw_line" and kw.get("exclude_regex") is not False:
        conds.append(f"NOT regexp_matches(raw_line, {lit(str(kw.get('exclude_regex') or RAW_LINE_EXCLUDE))})")
    return expr, (" AND ".join(conds) or None)


def coverage(full: dict[str, Any], run: list[dict[str, Any]], filtered: Counter, s: dict[str, Any]
             ) -> dict[str, Any]:
    reasons = Counter(x["reason"].split(":", 1)[0] for x in full["skipped"])
    detail = Counter(x["reason"] for x in full["skipped"] if ":" in x["reason"])
    return {
        "files": full["files"], "parsed": full["parsed"], "compiled": len(full["rules"]), "running": len(run),
        "skipped": len(full["skipped"]), "skipped_by_reason": dict(reasons.most_common()),
        "skipped_top_details": dict(detail.most_common(40)), "filtered_out": dict(filtered),
        "running_by_tactic": dict(Counter(r["tactic"] for r in run).most_common()),
        "running_by_level": dict(Counter(r["level"] for r in run).most_common()),
        "running_by_logsource": dict(Counter(r["logsource"] for r in run).most_common()),
        "label_overridden": sum(1 for r in run if r.get("label_override")),
        "compiled_by_tactic": dict(Counter(r["tactic"] for r in full["rules"]).most_common()),
        "compiled_by_level": dict(Counter(r["level"] for r in full["rules"]).most_common()),
        "defense_evasion_mapped": dict(Counter(r.get("defense_evasion_to") for r in full["rules"]
                                               if r.get("defense_evasion_to")).most_common()),
        "compile_s": full.get("compile_s"), "cache_key": str(full.get("key", ""))[:16],
        "settings": {k: s.get(k) for k in ("dir", "min_level", "status", "batch_size")},
    }
