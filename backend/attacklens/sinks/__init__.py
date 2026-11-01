"""Outbound sinks (config/integrations.yaml `sinks`): push published incidents back to the SIEM / SOAR.

publish_all() is called by publish.py after incidents are written. Every enabled sink is tried independently;
any failure is logged and recorded (returned stats -> run_metrics stage_stats.publish.sinks, and
connector_status.json `sinks`) and NEVER raises. only_changed: an incident is re-sent only when its content hash
changed since the last successful send (state in <spool.state_dir>/sink_<name>.json).
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import time
from typing import Any

from attacklens import integrations as ig
from attacklens.live_tail import read_json, write_json

log = logging.getLogger(__name__)

SINKS = ("splunk_hec", "elastic_bulk", "webhook", "syslog_cef")
Item = tuple[dict[str, Any], dict[str, Any]]  # (incident JSON, index summary row)


class PartialSend(RuntimeError):
    """Some incidents were delivered (sent_ids), others failed (message = first error)."""

    def __init__(self, msg: str, sent_ids: list[str]) -> None:
        super().__init__(msg)
        self.sent_ids = sent_ids


def _digest(inc: dict[str, Any]) -> str:
    return hashlib.sha1(json.dumps(inc, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def enabled_sinks(cfg: dict[str, Any]) -> list[str]:
    sc = ig.icfg(cfg).get("sinks") or {}
    return [n for n in SINKS if (sc.get(n) or {}).get("enabled")]


def publish_one(name: str, items: list[Item], cfg: dict[str, Any]) -> dict[str, Any]:
    scfg = (ig.icfg(cfg).get("sinks") or {}).get(name) or {}
    t0 = time.perf_counter()
    state_path = ig.state_dir(cfg) / f"sink_{name}.json"
    sent_hashes: dict[str, str] = read_json(state_path, {}) if scfg.get("only_changed", True) else {}
    todo = [(inc, row) for inc, row in items if sent_hashes.get(str(inc.get("id"))) != _digest(inc)]
    stats: dict[str, Any] = {"enabled": True, "incidents": len(items), "sent": 0,
                             "skipped_unchanged": len(items) - len(todo), "failed": 0, "error": None}
    if todo:
        try:
            mod = importlib.import_module(f"attacklens.sinks.{name}")
            mod.send(todo, scfg, cfg)
            ok = {str(inc.get("id")) for inc, _ in todo}
        except PartialSend as exc:
            ok = set(exc.sent_ids)
            stats["error"] = f"partial: {exc}"
        except Exception as exc:  # noqa: BLE001 - a sink must never fail the run
            ok = set()
            stats["error"] = f"{type(exc).__name__}: {exc}"
        stats["sent"], stats["failed"] = len(ok), len(todo) - len(ok)
        if stats["error"]:
            log.warning("sink %s: %d of %d incidents not sent: %s", name, stats["failed"], len(todo), stats["error"])
        if ok and scfg.get("only_changed", True):
            for inc, _ in todo:
                if str(inc.get("id")) in ok:
                    sent_hashes[str(inc.get("id"))] = _digest(inc)
            try:
                write_json(state_path, sent_hashes)
            except OSError as exc:
                log.warning("sink %s: cannot write %s: %s", name, state_path.name, exc)
    stats["wall_s"] = round(time.perf_counter() - t0, 3)
    stats["errors"], stats["last_error"] = stats["failed"], stats["error"]
    entry = {"last_publish_at": ig.now_iso(), "last": stats, "last_error": stats["error"]}
    if stats["error"] is None:
        entry["last_ok_at"] = entry["last_publish_at"]
    try:
        ig.update_status(cfg, "sinks", name, entry)
    except OSError as exc:
        log.warning("sink %s: cannot write connector_status.json: %s", name, exc)
    return stats


def summary_row(inc: dict[str, Any]) -> dict[str, Any]:
    """incidents_index-style row of an Incident dict (for webhook payload=summary / CEF)."""
    steps = inc.get("backbone") or []
    return {"id": inc.get("id"), "risk": inc.get("risk"), "first_ts": inc.get("first_ts"),
            "last_ts": inc.get("last_ts"), "merged_alert_count": inc.get("merged_alert_count"),
            "episode_count": inc.get("episode_count"), "tactics": inc.get("tactics") or [],
            "hosts": list(dict.fromkeys(s.get("host") for s in steps if s.get("host"))),
            "entry_summary": (inc.get("entry_point") or {}).get("summary", "")}


def publish(incidents: list[dict[str, Any]], cfg: dict[str, Any]) -> dict[str, Any]:
    """Push Incident dicts to every enabled sink (programmatic entry; publish.py uses publish_all)."""
    return publish_all([(i, summary_row(i)) for i in incidents], cfg)


def publish_all(items: list[Item], cfg: dict[str, Any]) -> dict[str, Any]:
    """{sink name: stats} for every enabled sink ({} when none is enabled). Never raises."""
    out: dict[str, Any] = {}
    try:
        names = enabled_sinks(cfg)
    except Exception as exc:  # noqa: BLE001
        log.warning("sinks: bad integrations config: %s", exc)
        return {"error": str(exc)}
    for name in names:
        out[name] = publish_one(name, items, cfg)
    return out
