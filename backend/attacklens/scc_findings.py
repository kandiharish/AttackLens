"""GCP Security Command Center findings -> SIEM alert spool (alert-input mode ONLY; reports/cloud/log_coverage.md P1-3).

SCC findings are vendor verdicts, not raw evidence: they never feed the scored raw-event detectors (CLAUDE.md "detect
from raw fields only"; as raw events they only route to gcp_scc_json context rows). This module converts them into
raw_alerts rows with siem_alerts.map_alert and writes them to the alert spool, which only `attacklens.run
--siem-alerts` (refused together with --ground-truth) or live alert_input reads.

    python -m attacklens.scc_findings --in findings.jsonl [--in more/] [--out data/spool/siem_alerts/gcp_scc/x.jsonl]

Shapes (by key presence): Pub/Sub notification {notificationConfigName, finding, resource}, ListFindings result
{finding, resource}, Cloud Logging copy {jsonPayload: {finding, resource}}, bare Finding {name, category, ...}.
MITRE enums -> v20 ids: config/scc_map.yaml. Files are streamed line by line (bounded memory); every line is counted
as written or dropped with a reason.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from attacklens import integrations as ig
from attacklens.siem_alerts import map_alert

log = logging.getLogger(__name__)

VENDOR = "gcp_scc"
FIELDS = {"rule_name": ["rule_name"], "technique": ["techniques"], "tactic": ["tactic"], "severity": ["severity"],
          "host": ["host"], "src_user": ["src_user"], "src_ip": ["src_ip"], "id": ["id"]}


def unwrap(rec: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """-> (finding, resource) for every supported shape; (None, {}) when the record is not a finding."""
    for doc in (rec, rec.get("jsonPayload") or {}):
        if isinstance(doc.get("finding"), dict):
            return doc["finding"], doc.get("resource") or {}
    if "category" in rec and "/findings/" in str(rec.get("name", "")):
        return rec, {}
    return None, {}


def _ms(v: Any) -> int | None:
    try:
        return int(datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() * 1000)
    except (TypeError, ValueError):
        return None


def to_doc(finding: dict[str, Any], resource: dict[str, Any], smap: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Flat alert doc for map_alert, or (None, skip reason)."""
    if str(finding.get("state", "")).upper() in {s.upper() for s in smap.get("skip_states") or []}:
        return None, "skipped_state"
    if str(finding.get("mute", "")).upper() in {s.upper() for s in smap.get("skip_mutes") or []}:
        return None, "skipped_muted"
    mitre = finding.get("mitreAttack") or {}
    enums = list(mitre.get("primaryTechniques") or []) + list(mitre.get("additionalTechniques") or [])
    tmap = smap.get("techniques") or {}
    tids = [str(tmap[e]) for e in enums if e in tmap]
    access = finding.get("access") or {}
    project = resource.get("projectDisplayName") or resource.get("project_display_name")
    return {"rule_name": f"SCC {finding.get('category') or 'finding'}", "techniques": tids,
            "tactic": [mitre.get("primaryTactic")] + list(mitre.get("additionalTactics") or []),
            "severity": str(finding.get("severity") or "").lower() or None,
            "host": project or resource.get("displayName") or finding.get("resourceName"),
            "src_user": access.get("principalEmail") or access.get("principalSubject"),
            "src_ip": access.get("callerIp"), "id": finding.get("name")}, ""


def records(paths: list[Path]) -> Iterator[tuple[str, str]]:
    for p in paths:
        files = sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]
        for f in files:
            with f.open(encoding="utf-8-sig") as fh:
                for line in fh:
                    if line.strip():
                        yield f.as_posix(), line


def convert(paths: list[Path], out: Path, cfg: dict[str, Any]) -> dict[str, Any]:
    smap = cfg.get("scc_map") or {}
    stats: dict[str, Any] = {"lines": 0, "written": 0, "dropped": {}}
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for _, line in records(paths):
            stats["lines"] += 1
            reason = ""
            try:
                rec = json.loads(line)
            except ValueError:
                rec, reason = None, "malformed_json"
            if rec is not None:
                finding, resource = unwrap(rec) if isinstance(rec, dict) else (None, {})
                if finding is None:
                    reason = "not_a_finding"
                else:
                    doc, reason = to_doc(finding, resource, smap)
                    if doc is not None:
                        row, reason = map_alert(doc, VENDOR, FIELDS, cfg, _ms(finding.get("eventTime")
                                                                            or finding.get("createTime")))
                        if row is not None:
                            fh.write(json.dumps(row) + "\n")
                            stats["written"] += 1
                            continue
            stats["dropped"][reason] = stats["dropped"].get(reason, 0) + 1
    log.info("scc findings: %s", stats)
    return stats


def main(argv: list[str] | None = None) -> int:
    from attacklens.config import load_config

    ap = argparse.ArgumentParser(description="Convert GCP SCC findings into the SIEM alert spool (alert-input mode).")
    ap.add_argument("--in", dest="inp", action="append", required=True, help="findings JSONL file or directory")
    ap.add_argument("--out", help="output JSONL (default: <integrations spool alerts_dir>/gcp_scc/scc_findings.jsonl)")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    out = Path(a.out) if a.out else ig.alerts_spool_dir(cfg) / VENDOR / "scc_findings.jsonl"
    st = convert([Path(p) for p in a.inp], out, cfg)
    sys.stdout.write(json.dumps({**st, "out": out.as_posix()}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
