"""QA track qa_ui: frontend logic that decides what the UI shows, run on the real TypeScript via Node type stripping.

QA-UI-1: the "Detection coverage" card on the Add data page (frontend/src/lib/addData.ts readSigma) reads
run_metrics.sigma_rules_total / sigma_rules_applicable at the top level of run_metrics, but the backend
(sigma_detect.run) writes them to run_metrics.stage_stats.detect (DEVELOPMENT.md section 15.6). The card is
therefore never shown for any real run. Owner: frontend-builder.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
ADD_DATA_TS = REPO / "frontend" / "src" / "lib" / "addData.ts"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None or not ADD_DATA_TS.exists(), reason="node or frontend sources missing")

# Values in the shape DEVELOPMENT.md 15.6 documents (flat Sigma keys under stage_stats.detect), as written by
# sigma_detect.run; numbers are hand-picked, not taken from any organiser log.
DOCUMENTED = {"run_metrics": {"set": "x", "stage_stats": {"detect": {
    "sigma_rules_total": 3779, "sigma_rules_compiled": 1707, "sigma_rules_running": 1691,
    "sigma_rules_applicable": 112, "sigma_rules_fired": 1, "sigma_alerts": 1000}}}}


def read_sigma(metrics: object) -> object:
    """Call the real readSigma() from addData.ts and return its JSON result (None for null)."""
    script = (
        "const m = await import(process.argv[1]);"
        "process.stdout.write(JSON.stringify(m.readSigma(JSON.parse(process.argv[2]))));"
    )
    out = subprocess.run(
        [NODE, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script,
         ADD_DATA_TS.as_uri(), json.dumps(metrics)],
        capture_output=True, text=True, timeout=60, check=True,
    )
    return json.loads(out.stdout)


def test_read_sigma_top_level_keys_exact() -> None:
    """Current reader on top-level keys: exact pass-through of the four numbers."""
    m = {"run_metrics": {"sigma_rules_total": 10, "sigma_rules_applicable": 4, "sigma_rules_compiled": 7, "sigma_alerts": 3}}
    assert read_sigma(m) == {"total": 10, "applicable": 4, "compiled": 7, "alerts": 3}


def test_read_sigma_near_miss_missing_applicable_is_null() -> None:
    """Near miss: total present but applicable missing -> card hidden (null)."""
    assert read_sigma({"run_metrics": {"sigma_rules_total": 10}}) is None


def test_read_sigma_near_miss_non_numeric_is_null() -> None:
    """Near miss: applicable is a string -> not a finite number -> null."""
    assert read_sigma({"run_metrics": {"sigma_rules_total": 10, "sigma_rules_applicable": "4"}}) is None


def test_read_sigma_no_metrics_is_null() -> None:
    assert read_sigma(None) is None


@pytest.mark.xfail(strict=True, reason="QA-UI-1: readSigma reads run_metrics.sigma_* but the backend writes "
                   "run_metrics.stage_stats.detect.sigma_* (DEVELOPMENT.md 15.6); coverage card never shows")
def test_read_sigma_documented_location_shows_card() -> None:
    assert read_sigma(DOCUMENTED) == {"total": 3779, "applicable": 112, "compiled": 1707, "alerts": 1000}


INCIDENT_TS = REPO / "frontend" / "src" / "lib" / "incident.ts"
WORKSPACE_TSX = REPO / "frontend" / "src" / "components" / "Workspace.tsx"
APP_TSX = REPO / "frontend" / "src" / "App.tsx"

# Hand-built incident: backbone 2 steps on 1 host, one branch of 2 steps on 2 other hosts.
_STEP = {"technique_id": "T1110", "tactic": "Credential Access", "evidence": []}
TINY = {"backbone": [{**_STEP, "step": 0, "episode_id": "a", "host": "h1"}, {**_STEP, "step": 1, "episode_id": "b", "host": "h1"}],
        "branches": [[{**_STEP, "step": 2, "episode_id": "c", "host": "h2"}, {**_STEP, "step": 3, "episode_id": "d", "host": "h3"}]]}


def _incident_helpers(inc: object) -> dict[str, object]:
    script = (
        "const m = await import(process.argv[1]); const inc = JSON.parse(process.argv[2]);"
        "process.stdout.write(JSON.stringify({all: m.allSteps(inc).map(s => s.step), hosts: m.hostsOf(inc)}));"
    )
    out = subprocess.run(
        [NODE, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script,
         INCIDENT_TS.as_uri(), json.dumps(inc)],
        capture_output=True, text=True, timeout=60, check=True,
    )
    return json.loads(out.stdout)


def test_incident_helpers_exact() -> None:
    """allSteps flattens branches (list of lists) and sorts by step; hostsOf counts hosts over ALL steps."""
    assert _incident_helpers(TINY) == {"all": [0, 1, 2, 3], "hosts": ["h1", "h2", "h3"]}


def test_incident_helpers_backbone_only_near_miss() -> None:
    assert _incident_helpers({"backbone": TINY["backbone"], "branches": []}) == {"all": [0, 1], "hosts": ["h1"]}


@pytest.mark.xfail(strict=True, reason="QA-UI-3: Workspace header shows backbone.length steps across hostsOf(all "
                   "steps) machines; TINY reads '2 steps across 3 machines' (2 backbone steps touch 1 machine)")
def test_header_step_and_machine_counts_use_one_step_set() -> None:
    src = WORKSPACE_TSX.read_text(encoding="utf-8")
    mixed = "{incident.backbone.length} steps across {hosts.length}" in src and "hostsOf(incident)" in src
    assert not mixed


@pytest.mark.xfail(strict=True, reason="QA-UI-2: status bar 'Data' shows run_metrics.out_dir (path where the run "
                   "wrote, e.g. /app/data/out/demo from Docker) instead of /api/health served_out_dir")
def test_status_bar_data_dir_is_served_out_dir() -> None:
    src = APP_TSX.read_text(encoding="utf-8")
    assert "served_out_dir" in src


def test_backend_writes_sigma_keys_under_stage_stats_detect() -> None:
    """Pins the backend side of QA-UI-1: sigma_detect builds the flat sigma_* dict that run.py stores in
    stage_stats.detect, and run_metrics has no top-level sigma_* writer."""
    src = (REPO / "backend" / "attacklens" / "sigma_detect.py").read_text(encoding="utf-8")
    assert '"sigma_rules_total"' in src and '"sigma_rules_applicable"' in src
    top = [p for p in (REPO / "backend" / "attacklens").glob("*.py")
           if p.name != "sigma_detect.py" and 'metrics["sigma_rules_total"]' in p.read_text(encoding="utf-8")]
    assert top == []
