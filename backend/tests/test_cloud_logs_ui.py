"""The Connections page "Supported cloud logs" panel (frontend/src/mock/integrations_cloud_logs.json) must match the
backend: every source type exists in config/sources.yaml, every cloud / identity source type of sources.yaml is listed
(no underclaiming), connector rows name a registered cloud / identity connector and only the tables / content types /
applications that connector really pulls by default (no overclaiming), and every cloud / identity connector has a
tile blurb."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
UI_JSON = REPO / "frontend" / "src" / "mock" / "integrations_cloud_logs.json"
SOURCES = REPO / "config" / "sources.yaml"
# source types that are cloud / SaaS-identity logs (by name); every one of them must be in the UI table
CLOUD_NAME = re.compile(r"^(cloudtrail|aws_|azure_|gcp_|gws_|m365_|okta|k8s_|auth0|duo_)")


def _ui() -> dict[str, Any]:
    return json.loads(UI_JSON.read_text(encoding="utf-8"))


def _rows() -> list[dict[str, Any]]:
    return [dict(r, provider=p["provider"]) for p in _ui()["providers"] for r in p["logs"]]


def _source_types() -> dict[str, str]:
    cfg = yaml.safe_load(SOURCES.read_text(encoding="utf-8"))
    out = {k: "json" for k in cfg.get("json_sources") or {}}
    out.update({k: "csv" for k in cfg.get("csv_sources") or {}})
    return out


def test_every_ui_source_type_exists_in_sources_yaml() -> None:
    known = _source_types()
    missing = sorted({r["source_type"] for r in _rows()} - set(known))
    assert not missing, f"UI lists source types that config/sources.yaml does not have: {missing}"


def test_every_cloud_source_type_is_listed_in_the_ui() -> None:
    cloud = {k for k in _source_types() if CLOUD_NAME.match(k)}
    listed = {r["source_type"] for r in _rows()}
    assert cloud - listed == set(), f"add these to {UI_JSON.name}: {sorted(cloud - listed)}"


def test_rows_are_well_formed() -> None:
    rows = _rows()
    assert rows
    for r in rows:
        assert r["log"].strip() and r["provider"].strip()
        assert 0 < len(r["short"].strip()) <= 28, f"{r['log']}: short name for the compact table"
        assert isinstance(r["file"], bool)
        assert r.get("connector") is None or isinstance(r["connector"], str)
        assert r["file"] or r.get("connector"), f"{r['log']}: neither file nor connector ingest"
        assert r.get("detection", "rules") in {"rules", "context"}


def test_connector_rows_name_registered_cloud_or_identity_connectors() -> None:
    from attacklens.connectors import CLOUD_SOURCES, IDENTITY_SOURCES

    allowed = set(CLOUD_SOURCES) | set(IDENTITY_SOURCES)
    used = {r["connector"] for r in _rows() if r.get("connector")}
    assert used <= allowed, f"unknown connectors: {sorted(used - allowed)}"
    tiles = _ui()["connectors"]
    assert set(tiles) == allowed, "every cloud / identity connector needs exactly one tile blurb"
    for cid, t in tiles.items():
        assert t["provider"].strip() and t["pulls"].strip(), cid


def test_connector_scope_is_what_the_connector_pulls() -> None:
    from attacklens.connectors import azure_monitor, gws_reports, m365_ual

    allowed = {
        "azure_monitor": set(azure_monitor.DEFAULT_TABLES) | set(azure_monitor.OPTIONAL_TABLES),
        "m365_ual": set(m365_ual.CONTENT_TYPES),
        "gws_reports": set(gws_reports.DEFAULT_APPLICATIONS),
    }
    for r in _rows():
        scope = r.get("connector_scope") or []
        if r.get("connector") in allowed:
            assert scope, f"{r['log']}: say which {r['connector']} tables / types / apps carry it"
            bad = set(scope) - allowed[r["connector"]]
            assert not bad, f"{r['log']}: {r['connector']} does not pull {sorted(bad)}"
        else:
            assert not scope, f"{r['log']}: connector_scope only for azure_monitor / m365_ual / gws_reports"


def test_findings_are_context_only() -> None:
    """GuardDuty, Security Hub and SCC findings are context rows (sources.yaml): the UI must not show them as rules."""
    by_type = {r["source_type"]: r for r in _rows()}
    for st in ("aws_guardduty_json", "aws_securityhub_json", "gcp_scc_json"):
        assert by_type[st].get("detection") == "context", st
