"""Pivot-back queries (GET /api/incidents/{id}/pivots): per step, a ready-to-run query for every enabled SIEM
(Splunk SPL, Sentinel KQL, Elastic Lucene + query DSL), scoped to the step's host / user / IPs within
ts +- pivots.window_ms, plus a URL when a base URL is configured. Templates live in config/integrations.yaml.

Entity values come from logs (attacker-controlled): they are escaped for each query language, never pasted raw.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any

from attacklens import integrations as ig

log = logging.getLogger(__name__)

ENTITY_ORDER = ("host", "user", "ip")


def escape(value: str, language: str) -> str:
    """Escape a value placed inside double quotes (SPL, KQL, Lucene phrase): backslash and quote are escaped,
    control characters become spaces. `language` is kept for languages that may need more later."""
    v = re.sub(r"[\x00-\x1f]", " ", str(value))
    return v.replace("\\", "\\\\").replace('"', '\\"')


def enabled_siems(icfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """pivots.siems entries that are enabled (enabled: null -> follow connectors.<name>.enabled)."""
    conns = icfg.get("connectors") or {}
    out = {}
    for name, sc in ((icfg.get("pivots") or {}).get("siems") or {}).items():
        sc = sc or {}
        on = sc.get("enabled")
        if on is None:
            on = bool((conns.get(name) or {}).get("enabled"))
        if on:
            out[str(name)] = sc
    return out


def step_entities(step: dict[str, Any]) -> list[tuple[str, str]]:
    ents: list[tuple[str, str]] = []
    if step.get("host"):
        ents.append(("host", str(step["host"])))
    if step.get("user"):
        ents.append(("user", str(step["user"])))
    for k in ("src_ip", "dst_ip"):
        if step.get(k) and ("ip", str(step[k])) not in ents:
            ents.append(("ip", str(step[k])))
    return ents


def _fill(template: str, values: dict[str, str]) -> str:
    """str.format-like substitution of known {names} only (other braces, e.g. KQL / rison, stay as they are)."""
    return re.sub(r"\{([a-z_]+)\}", lambda m: values.get(m.group(1), m.group(0)), template)


def es_dsl(ents: list[tuple[str, str]], sc: dict[str, Any], lo_ms: int, hi_ms: int) -> dict[str, Any]:
    fields = sc.get("dsl_fields") or {"host": ["host.name"], "user": ["user.name"], "ip": ["source.ip"]}
    should = [{"term": {f: v}} for kind, v in ents for f in fields.get(kind, [])]
    return {"query": {"bool": {"filter": [{"range": {str(sc.get("ts_field", "@timestamp")): {
        "gte": ig.iso_ms(lo_ms), "lte": ig.iso_ms(hi_ms), "format": "strict_date_optional_time"}}}],
        "should": should, "minimum_should_match": 1}}, "sort": [{str(sc.get("ts_field", "@timestamp")): "asc"}]}


def build_query(step: dict[str, Any], name: str, sc: dict[str, Any], window_ms: int) -> dict[str, Any] | None:
    ts = ig.to_ms(step.get("ts"))
    ents = step_entities(step)
    if ts is None or not ents:
        return None
    lang = str(sc.get("language", "spl"))
    lo, hi = ts - window_ms, ts + window_ms
    clause = sc.get("clause") or {}
    parts = [str(clause[k]).replace("{v}", escape(v, lang)) for k, v in ents if clause.get(k)]
    if not parts:
        return None
    vals = {"clauses": str(sc.get("join", " OR ")).join(parts), "earliest_iso": str(ig.iso_ms(lo)),
            "latest_iso": str(ig.iso_ms(hi)), "earliest_epoch": str(lo // 1000), "latest_epoch": str(-(-hi // 1000))}
    query = _fill(str(sc.get("template", "{clauses}")), vals)
    out: dict[str, Any] = {"siem": name, "language": lang, "query": " ".join(query.split()),
                           "earliest": vals["earliest_iso"], "latest": vals["latest_iso"],
                           "entities": [f"{k}:{v}" for k, v in ents], "url": None}
    if name == "elastic" or lang == "lucene":
        out["dsl"] = es_dsl(ents, sc, lo, hi)
    base = sc.get("base_url")
    if base and sc.get("url_template"):
        qv = out["query"].replace("!", "!!").replace("'", "!'") if lang == "lucene" else out["query"]  # rison
        out["url"] = _fill(str(sc["url_template"]), {**vals, "base_url": str(base).rstrip("/"),
                                                     "query_url": urllib.parse.quote(qv, safe="")})
    return out


def step_pivots(s: dict[str, Any], siems: dict[str, dict[str, Any]], window: int) -> dict[str, Any]:
    qs: dict[str, Any] = {}
    for name, sc in siems.items():
        try:
            q = build_query(s, name, sc, window)
        except (KeyError, ValueError, TypeError) as exc:  # bad template: skip this SIEM, keep the rest
            log.warning("pivots: %s template error: %s", name, exc)
            q = None
        if q:
            qs[name] = q
    return {"step": s.get("step"), "episode_id": s.get("episode_id"), "ts": s.get("ts"),
            "technique_id": s.get("sub_technique_id") or s.get("technique_id"), "host": s.get("host"),
            "user": s.get("user"), "queries": qs}


def build_pivots(incident: dict[str, Any], icfg: dict[str, Any]) -> dict[str, Any]:
    """{"id", "window_ms", "siems": [names], "steps": [one per backbone step: {step, episode_id, ts,
    technique_id, host, user, queries: {siem: {siem, language, query, url, earliest, latest, entities, dsl?}}}],
    "branches": [[same, per branch step]]}."""
    siems = enabled_siems(icfg)
    window = int((icfg.get("pivots") or {}).get("window_ms", 900_000))
    return {"id": incident.get("id"), "window_ms": window, "siems": list(siems),
            "steps": [step_pivots(s, siems, window) for s in incident.get("backbone") or []],
            "branches": [[step_pivots(s, siems, window) for s in br] for br in incident.get("branches") or []]}
