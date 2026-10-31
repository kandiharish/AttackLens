"""Placeholder map + sanitized facts for the narrative (DEVELOPMENT.md §4 Stage 5).

Facts contain ONLY placeholder tokens ({{HOST_1}}), technique ids/names from the ATT&CK config, tactic enums, counts,
ISO times and risk. Raw log text, evidence lines, command lines and entity values never enter the facts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from attacklens.models import Incident, Step

TOKEN_RE = re.compile(r"\{\{[A-Z]+_\d+\}\}")
TECH_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9 ,()/&'.:\-]{1,80}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
CROWN_JEWELS = {"dc", "file", "db", "web"}
TACTICS = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Stealth", "Defense Impairment", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact", "Defense Evasion",
)
_KINDS = {"host": "HOST", "user": "USER", "ip": "IP", "domain": "DOMAIN"}


def strip_control(text: str) -> str:
    """Remove control / bidi / zero-width chars; newlines become spaces."""
    return CONTROL_RE.sub("", text.replace("\r", " ").replace("\n", " ").replace("\t", " "))


@dataclass
class PlaceholderMap:
    """Deterministic entity -> token map, numbered per type by first appearance."""

    _tokens: dict[tuple[str, str], str] = field(default_factory=dict)
    _values: dict[str, str] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)

    def token(self, kind: str, value: str | None) -> str | None:
        if value is None:
            return None
        clean = strip_control(str(value)).strip()
        if not clean:
            return None
        key = (kind, clean.lower())
        tok = self._tokens.get(key)
        if tok is None:
            prefix = _KINDS[kind]
            n = self._counts.get(prefix, 0) + 1
            self._counts[prefix] = n
            tok = "{{" + f"{prefix}_{n}" + "}}"
            self._tokens[key] = tok
            self._values[tok] = clean
        return tok

    @property
    def values(self) -> dict[str, str]:
        """token -> real value (for substitution after generation)."""
        return dict(self._values)

    def known(self) -> set[str]:
        return set(self._values)


def build_placeholders(incident: Incident) -> PlaceholderMap:
    pm = PlaceholderMap()
    for step in [*incident.backbone, *(s for br in incident.branches for s in br)]:
        pm.token("host", step.host)
        pm.token("user", step.user)
        pm.token("ip", step.src_ip)
        pm.token("ip", step.dst_ip)
    for r in incident.reach_next:
        pm.token("host", r.host)
        pm.token("user", r.via_user)
    for node in incident.graph.nodes:
        value = node.id.split(":", 1)[1] if ":" in node.id else node.label
        pm.token(node.type, value)
    return pm


def _attack_name(cfg: dict[str, Any], tid: str) -> str | None:
    """Technique name from config attack map (tolerant of a few layouts)."""
    attack = cfg.get("attack") or {}
    table: Any = attack.get("techniques", attack) if isinstance(attack, dict) else attack
    entry: Any = None
    if isinstance(table, dict):
        entry = table.get(tid)
    elif isinstance(table, list):
        entry = next((e for e in table if isinstance(e, dict)
                      and tid in (e.get("id"), e.get("technique_id"))), None)
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        name = entry.get("name")
        return name if isinstance(name, str) else None
    return None


def technique_label(step: Step, cfg: dict[str, Any]) -> tuple[str, str]:
    """(display id, display name). Id is sub-technique when valid; name from config, else a safe pipeline name."""
    tid = step.technique_id if TECH_ID_RE.match(step.technique_id or "") else "T0000"
    shown = step.sub_technique_id if step.sub_technique_id and TECH_ID_RE.match(step.sub_technique_id) else tid
    name = _attack_name(cfg, shown) or _attack_name(cfg, tid)
    if name is None and step.technique_name and SAFE_NAME_RE.match(step.technique_name):
        name = step.technique_name
    name = name if name and SAFE_NAME_RE.match(name) else "unnamed technique"
    return shown, name


def safe_tactic(tactic: str | None) -> str:
    return tactic if tactic in TACTICS else "Unknown tactic"


def iso(ts: str | None) -> str:
    """Normalize to 'YYYY-MM-DDTHH:MM:SSZ' (UTC); anything unparsable becomes 'unknown time'."""
    if not ts:
        return "unknown time"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return "unknown time"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_facts(incident: Incident, pm: PlaceholderMap, cfg: dict[str, Any], ncfg: dict[str, Any]) -> dict[str, Any]:
    """Placeholder-only facts for the template and the LLM prompt."""
    max_steps = int(ncfg.get("max_steps_in_prompt", 25))
    max_reach = int(ncfg.get("max_reach_in_text", 5))
    steps: list[dict[str, Any]] = []
    hosts: list[str] = []
    for step in incident.backbone:
        tid, name = technique_label(step, cfg)
        host = pm.token("host", step.host)
        if host and host not in hosts:
            hosts.append(host)
        steps.append({
            "step": int(step.step), "ts": iso(step.ts), "technique_id": tid, "technique_name": name,
            "tech": f"{tid} {name}", "tactic": safe_tactic(step.tactic), "host": host,
            "user": pm.token("user", step.user), "src": pm.token("ip", step.src_ip),
            "dst": pm.token("ip", step.dst_ip), "severity": int(step.severity),
            "confidence": int(step.confidence), "merged_alert_count": int(step.merged_alert_count),
            "_parent": step.technique_id if TECH_ID_RE.match(step.technique_id or "") else None,
        })
    omitted = max(0, len(steps) - max_steps)
    if omitted:  # keep first and last steps, drop the middle
        steps = steps[: max_steps - 1] + steps[-1:]
    required = [p for s in steps if (p := s.pop("_parent"))]
    reach = [{
        "host": pm.token("host", r.host), "hops": int(r.hops), "via_user": pm.token("user", r.via_user),
        "crown_jewel": r.crown_jewel if r.crown_jewel in CROWN_JEWELS else None, "touched": bool(r.touched),
    } for r in incident.reach_next if pm.token("host", r.host)]
    via = {r["via_user"] for r in reach if r["via_user"]}
    return {
        "risk": int(incident.risk), "first_ts": iso(incident.first_ts), "last_ts": iso(incident.last_ts),
        "episode_count": int(incident.episode_count), "merged_alert_count": int(incident.merged_alert_count),
        "tactics": [safe_tactic(t) for t in incident.tactics], "gaps": [t for t in incident.gaps if t in TACTICS],
        "steps": steps, "omitted": omitted, "hosts": hosts,
        "reach": reach[:max_reach], "reach_total": len(reach),
        "reach_user": next(iter(via)) if len(via) == 1 else None,
        "required_technique_ids": sorted(set(required)),
    }
