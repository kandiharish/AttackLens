"""Stage 5: work/incidents.json -> out/incidents/{id}.json + out/incidents_index.json, with narratives."""

from __future__ import annotations

import importlib
import json
import logging
import time
from pathlib import Path
from typing import Any

from attacklens.context import RunContext
from attacklens.models import Incident, IncidentSummary, Narrative, dump

log = logging.getLogger(__name__)


def fallback_narrative(inc: Incident) -> Narrative:
    """Minimal deterministic sentence used when narrative.generate is missing or fails."""
    hosts = list(dict.fromkeys(s.host for s in inc.backbone if s.host))
    text = (f"{len(inc.backbone)} linked steps across {len(hosts)} host(s) "
            f"({', '.join(h.upper() for h in hosts[:4])}) from {inc.first_ts} to {inc.last_ts}: "
            f"{' -> '.join(dict.fromkeys(s.tactic for s in inc.backbone))}. Entry: {inc.entry_point.summary}.")
    return Narrative(text=text, source="template")


def make_narrative(inc: Incident, cfg: dict[str, Any]) -> Narrative:
    try:
        mod = importlib.import_module("attacklens.narrative")
        out = mod.generate(inc, cfg)
        return out if isinstance(out, Narrative) else Narrative.model_validate(out)
    except Exception as exc:  # any problem -> deterministic template (CLAUDE.md "LLM safety")
        log.warning("narrative failed for %s (%s); using fallback", inc.id, exc)
        return fallback_narrative(inc)


def summary(inc: Incident) -> IncidentSummary:
    hosts = list(dict.fromkeys(s.host for s in inc.backbone if s.host))
    return IncidentSummary(id=inc.id, risk=inc.risk, first_ts=inc.first_ts, last_ts=inc.last_ts,
                           merged_alert_count=inc.merged_alert_count, episode_count=inc.episode_count,
                           tactics=inc.tactics, hosts=hosts, entry_summary=inc.entry_point.summary)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(obj, ensure_ascii=False, indent=1))


def push_to_sinks(ctx: RunContext, incidents: list[Incident], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Outbound SIEM / SOAR sinks (config/integrations.yaml). Only when enabled; a failure never fails the run."""
    try:
        from attacklens import sinks

        if not sinks.enabled_sinks(ctx.cfg):
            return {}
        return sinks.publish_all([(dump(i), r) for i, r in zip(incidents, rows)], ctx.cfg)
    except Exception as exc:  # noqa: BLE001
        log.warning("publish: sinks failed: %s", exc)
        return {"error": f"{type(exc).__name__}: {exc}"}


def run(ctx: RunContext) -> dict[str, Any]:
    t0 = time.perf_counter()
    src = ctx.work_dir / "incidents.json"
    raw = json.loads(src.read_text(encoding="utf-8")) if src.exists() else []
    inc_dir = ctx.out_dir / "incidents"
    inc_dir.mkdir(parents=True, exist_ok=True)
    for stale in inc_dir.glob("*.json"):
        stale.unlink()
    incidents = [Incident.model_validate(d) for d in raw]
    sources: dict[str, int] = {}
    for inc in incidents:
        inc.narrative = make_narrative(inc, ctx.cfg)
        sources[inc.narrative.source] = sources.get(inc.narrative.source, 0) + 1
        write_json(inc_dir / f"{inc.id}.json", dump(Incident.model_validate(dump(inc))))
    incidents.sort(key=lambda x: (-x.risk, x.first_ts, x.id))
    rows = [dump(summary(i)) for i in incidents]
    write_json(ctx.out_dir / "incidents_index.json", rows)
    stats = {"published": len(incidents), "narrative_sources": dict(sorted(sources.items())),
             "seconds": round(time.perf_counter() - t0, 3)}
    sink_stats = push_to_sinks(ctx, incidents, rows)
    if sink_stats:
        stats["sinks"] = sink_stats
    log.info("publish: %s", stats)
    return stats
