"""QA track qa_contracts, self-check: every contract check in test_qa_contracts.py must FAIL on a tampered copy of
real outputs (data/out/qa_g50m + data/parquet/qa_g50m) and pass on the untampered copy. Guards against vacuous checks.

The checks are referenced through the module alias `C`, so pytest does not collect them a second time here.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import duckdb
import pytest

from tests.qa import test_qa_contracts as C
from tests.qa.test_qa_contracts import con  # noqa: F401  (module-scoped DuckDB fixture)


# ---- self-check: the checks in test_qa_contracts must fail on tampered outputs (never vacuous) -------------------------------
def _tamper_copy(tmp: Path) -> C.SetOut:
    src = C.SetOut("g50m")
    if not (src.out / "run_metrics.json").exists():
        pytest.skip("self-check needs data/out/qa_g50m: bash tools/qa/run_contract_sets.sh g50m")
    shutil.copytree(src.out, tmp / "out")
    shutil.copytree(src.pq, tmp / "pq")
    return C.SetOut("g50m", tmp / "out", tmp / "pq")


def _edit_json(path: Path, fn: Any) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    fn(doc)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _rewrite_parquet(con: duckdb.DuckDBPyConnection, path: Path, select: str) -> None:
    new = path.with_suffix(".new.parquet")
    con.execute(f"COPY ({select.format(src=f'read_parquet({C.db.sql_path(path)})')}) TO {C.db.sql_path(new)} "
                "(FORMAT PARQUET)")
    path.unlink()
    new.rename(path)


def _first_incident(s: C.SetOut) -> Path:
    files = sorted((s.out / "incidents").glob("*.json"))
    if not files:
        pytest.skip("qa_g50m has no incidents")
    return files[0]


def test_selfcheck_untampered_copy_passes(tmp_path: Path, con: duckdb.DuckDBPyConnection) -> None:
    """Positive control: the copy used by the tamper cases passes every check it is used with."""
    s = _tamper_copy(tmp_path)
    for fn in (C.test_ingest_accounting_invariants, C.test_incidents_index_matches_files, C.test_incident_tactics_v20,
               C.test_run_metrics_keys, C.test_incident_internal_consistency, C.test_incident_files_validate):
        fn(s)
    for fn2 in (C.test_episodes_values, C.test_edges_values, C.test_episode_accounting,
                C.test_ingest_accounting_matches_parquet):
        fn2(s, con)
    C.test_work_parquet_schema(s, con, "edges")


def _acc0(**delta: int) -> Any:
    return lambda s, c: _edit_json(s.out / "ingest_accounting.json",
                                   lambda d: d[0].update({k: d[0].get(k, 0) + v for k, v in delta.items()}))


def _inc0(fn: Any) -> Any:
    return lambda s, c: _edit_json(_first_incident(s), fn)


TAMPERS: dict[str, tuple[Any, Any]] = {
    # name: (tamper(s, con), check(s, con)) -- the check must raise AssertionError after the tamper
    "rows_ok_plus_1": (_acc0(rows_ok=1), lambda s, c: C.test_ingest_accounting_invariants(s)),
    "drop_without_reason": (_acc0(rows_in=1, dropped=1), lambda s, c: C.test_ingest_accounting_invariants(s)),
    "quarantine_miscount": (_acc0(quarantined=1), lambda s, c: C.test_ingest_accounting_matches_parquet(s, c)),
    "rows_in_vs_raw_bytes": (_acc0(rows_in=1, dropped=1), lambda s, c: C.test_ingest_rows_in_matches_raw_bytes(s)),
    "incident_file_deleted": (lambda s, c: _first_incident(s).unlink(),
                              lambda s, c: C.test_incidents_index_matches_files(s)),
    "incident_file_deleted_accounting": (lambda s, c: _first_incident(s).unlink(),
                                         lambda s, c: C.test_episode_accounting(s, c)),
    "old_tactic_name": (_inc0(lambda d: d["backbone"][0].update(tactic="Defense Evasion")),
                        lambda s, c: C.test_incident_tactics_v20(s)),
    "tactics_out_of_order": (_inc0(lambda d: d.update(tactics=["Impact", *d["tactics"], "Reconnaissance"])),
                             lambda s, c: C.test_incident_tactics_v20(s)),
    "step_ts_not_z": (_inc0(lambda d: d["backbone"][0].update(ts=d["backbone"][0]["ts"].replace("Z", "+00:00"))),
                      lambda s, c: C.test_incident_internal_consistency(s)),
    "index_risk_changed": (lambda s, c: _edit_json(s.out / "incidents_index.json",
                                                   lambda d: d[0].update(risk=d[0]["risk"] - 1)),
                           lambda s, c: C.test_incidents_index_matches_files(s)),
    "extra_field_in_incident": (_inc0(lambda d: d.update(score=1)), lambda s, c: C.test_incident_files_validate(s)),
    "run_metrics_key_dropped": (lambda s, c: _edit_json(s.out / "run_metrics.json", lambda d: d.pop("peak_rss_mb")),
                                lambda s, c: C.test_run_metrics_keys(s)),
    "stage_missing": (lambda s, c: _edit_json(s.out / "run_metrics.json", lambda d: d["stages"].pop(2)),
                      lambda s, c: C.test_run_metrics_keys(s)),
    "episode_id_wrong": (lambda s, c: _rewrite_parquet(c, s.work / "episodes.parquet",
                                                       "SELECT * REPLACE (CASE WHEN ts_ms = (SELECT min(ts_ms) FROM "
                                                       "{src}) THEN 'e0000000000' ELSE episode_id END AS episode_id) "
                                                       "FROM {src}"),
                         lambda s, c: C.test_episodes_values(s, c)),
    "episode_alert_lost": (lambda s, c: _rewrite_parquet(c, s.work / "episodes.parquet",
                                                         "SELECT * FROM {src} WHERE ts_ms > (SELECT min(ts_ms) "
                                                         "FROM {src})"),
                           lambda s, c: C.test_episodes_values(s, c)),
    "edge_dt_type": (lambda s, c: _rewrite_parquet(c, s.work / "edges.parquet",
                                                   "SELECT * REPLACE (dt_ms::INTEGER AS dt_ms) FROM {src}"),
                     lambda s, c: C.test_work_parquet_schema(s, c, "edges")),
    "edge_dangling": (lambda s, c: _rewrite_parquet(c, s.work / "edges.parquet",
                                                    "SELECT * REPLACE ('enotanepis' AS j) FROM {src}"),
                      lambda s, c: C.test_edges_values(s, c)),
}


@pytest.mark.parametrize("case", sorted(TAMPERS))
def test_selfcheck_tamper_is_caught(case: str, tmp_path: Path, con: duckdb.DuckDBPyConnection) -> None:
    s = _tamper_copy(tmp_path)
    tamper, check = TAMPERS[case]
    if case.startswith("edge_") and C._one(con, f"SELECT count(*) FROM {C._pq(s, 'edges')}") == 0:
        pytest.skip("qa_g50m has no edges")
    tamper(s, con)
    with pytest.raises(AssertionError):
        check(s, con)


TS_MUTANTS = {
    "field_renamed": ("  rule_id: string | null\n", "  ruleId: string | null\n", "Step"),
    "null_dropped": ("  via_user: string | null\n", "  via_user: string\n", "ReachNext"),
    "literal_dropped": ("rule: 'R1' | 'R2' | 'R3' | 'R4'", "rule: 'R1' | 'R2' | 'R3'", "PathEdge"),
    "inline_graph_field": ("graph: { nodes: GraphNode[]; edges: GraphEdge[] }", "graph: { nodes: GraphNode[] }",
                           "Incident"),
    "nested_type": ("  compromised: boolean\n", "  compromised: string\n", "Incident"),
    "order_swapped": ("  host: string | null\n  user: string | null\n",
                      "  user: string | null\n  host: string | null\n", "Step"),
}


@pytest.mark.parametrize("case", sorted(TS_MUTANTS))
def test_selfcheck_ts_drift_is_caught(case: str) -> None:
    old, new, iface = TS_MUTANTS[case]
    text = C.TS_FILE.read_text(encoding="utf-8")
    assert old in text, f"{case}: mutant anchor not in types.ts (update the self-check)"
    assert C.contract_diff(iface, text.replace(old, new, 1)) != {}, f"{case}: drift not detected"
