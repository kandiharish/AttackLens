"""L3 small pipeline (TESTING.md §1): ~30 MB synthetic set with S1-S5 planted, end to end, metrics asserted.

Generation (~1 s) + pipeline (~4 s) run once per module. Targets are the §6.3 pass criteria; asserts that depend on
Stage 3/4 (link, gate, path) and still fail are xfail(strict=False) while BB-graph builds them — never loosened.
Labels / rebuilt already pass on this set, so they are plain asserts (a regression must go red).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from attacklens.models import Incident

REPO = Path(__file__).resolve().parents[2]
SIX = ("detection_pct", "labels_pct", "rebuilt_pct", "false_alarms_strict_pct", "false_alarms_lenient_pct",
       "singleton_recall_pct")
STAGE3_4 = "Stage 3/4 (link/incidents/gate) still in progress by BB-graph"


@pytest.fixture(scope="module")
def run(tmp_path_factory: pytest.TempPathFactory) -> dict:
    tmp = tmp_path_factory.mktemp("l3")
    raw, out = tmp / "raw", tmp / "out"
    g = subprocess.run([sys.executable, str(REPO / "tools" / "gen_dataset.py"), "--size", "30M", "--workers", "1",
                        "--seed", "42", "--out", str(raw)], capture_output=True, text=True, timeout=120)
    assert g.returncode == 0, g.stderr[-2000:]
    from attacklens.run import run_pipeline
    metrics = run_pipeline(raw, out, parquet=tmp / "pq", ground_truth=raw / "ground_truth" / "attacks.json")
    return {"raw": raw, "out": out, "metrics": metrics,
            "card": json.loads((out / "eval_scorecard.json").read_text(encoding="utf-8")),
            "acc": json.loads((out / "ingest_accounting.json").read_text(encoding="utf-8"))}


def test_run_completes_with_metrics(run: dict) -> None:
    m = json.loads((run["out"] / "run_metrics.json").read_text(encoding="utf-8"))
    assert m.get("error") is None
    for k in ("total_wall_s", "peak_rss_mb", "rows_per_s", "stages", "episodes", "episodes_spilled", "incidents",
              "effective_config"):  # DEVELOPMENT.md §15.6
        assert k in m, k
    names = [s["name"] for s in m["stages"]]
    for st in ("profile", "ingest", "lookups", "detect", "episodes"):
        assert st in names, st


def test_ingest_zero_drops(run: dict) -> None:
    rows = [a for a in run["acc"] if a["rows_in"]]
    assert rows and all(a["dropped"] == 0 and a["rows_ok"] == a["rows_in"] for a in rows), rows
    manifest = json.loads((run["raw"] / "manifest.json").read_text(encoding="utf-8"))
    assert sum(a["rows_in"] for a in rows) > 30_000 and manifest


def test_scorecard_has_six_metrics(run: dict) -> None:
    card = run["card"]
    for k in SIX:
        assert k in card, k
        assert card[k] is None or (isinstance(card[k], float) and 0.0 <= card[k] <= 100.0), (k, card[k])
    assert card["counts"]["attacks"] == 5  # S1-S5


def test_detection_at_least_90(run: dict) -> None:
    assert run["card"]["detection_pct"] >= 90.0, run["card"]["per_attack"]


def test_published_incidents_match_contract_and_index_sorted(run: dict) -> None:
    files = sorted((run["out"] / "incidents").glob("*.json"))
    assert files
    for f in files:
        Incident.model_validate_json(f.read_text(encoding="utf-8"))
    index = json.loads((run["out"] / "incidents_index.json").read_text(encoding="utf-8"))
    assert [r["risk"] for r in index] == sorted((r["risk"] for r in index), reverse=True)
    assert {r["id"] for r in index} == {f.stem for f in files}


def test_labels_at_least_85(run: dict) -> None:
    assert run["card"]["labels_pct"] >= 85.0


def test_all_attacks_rebuilt(run: dict) -> None:
    assert run["card"]["rebuilt_pct"] == 100.0, [(a["id"], a["lcs_ratio"]) for a in run["card"]["per_attack"]]


@pytest.mark.xfail(strict=False, reason=STAGE3_4 + "; 30M run: 6 noise-only single-episode T1486 incidents")
def test_strict_false_alarms_below_10(run: dict) -> None:
    card = run["card"]
    assert card["false_alarms_strict_pct"] < 10.0, card["unmatched_incidents"]
