"""QA track qa_contracts: stage-to-stage contracts on real pipeline outputs (DEVELOPMENT.md §3.1, §7.1, §15.4, §15.6).

Inputs are produced by `tools/qa/run_contract_sets.sh demo f1 smoke_mixed g50m` (small sets only) into
data/out/qa_<set> + data/parquet/qa_<set>. A set whose outputs are absent is skipped with the command to make them.
Override the set list with QA_CONTRACT_SETS="demo,g50m".

What is checked, per set:
- every intermediate Parquet (events, raw_alerts, episodes, episodes_spilled, edges, host_ip_map, background_hubs,
  rule_host_baseline) has every §15.4 / §3.1 column with the exact DuckDB type; plus value invariants
  (episode_id formula, bucket, user, merged-count conservation raw_alerts -> episodes, edge endpoints and dt_ms);
- ingest_accounting: rows_in = rows_ok + dropped, sum(drop_reasons) = dropped, rows_ok / quarantined re-counted
  from Parquet, rows_in re-counted from the raw bytes (independent of the DuckDB reader);
- episode_accounting: in_incidents + in_suppressed = episodes, no missing / duplicated, counts = Parquet rows;
- run_metrics has every §15.6 key with sane types, stage list = run.STAGES (+ eval), totals consistent;
- every incidents/*.json validates against models.Incident; incidents_index.json = the files (ids, summary fields,
  order); every step tactic and incident tactic list is in the 15 v20 tactics, in v20 order;
- models.py field names / nullability / literals = frontend/src/types.ts; every mock incident validates.
"""

from __future__ import annotations

import json
import os
import re
import types
import typing
from pathlib import Path
from typing import Any, Literal, get_args, get_origin

import duckdb
import pytest
from pydantic import BaseModel, ValidationError

from attacklens import db, models
from attacklens.config import load_config
from attacklens.detect_sql import evidence_chars
from attacklens.models import Incident, IncidentSummary
from attacklens.run import STAGES
from attacklens.schemas import CANONICAL_COLUMNS, PARTITION_COLUMNS, TACTIC_IDX, TACTICS_V20

REPO = Path(__file__).resolve().parents[3]
SETS = [s.strip() for s in os.environ.get("QA_CONTRACT_SETS", "demo,f1,smoke_mixed,g50m").split(",") if s.strip()]
# Sets run with --ground-truth (eval stage + eval_scorecard.json expected).
GT_SETS = {"demo", "f1", "g50m"}
TS_FILE = REPO / "frontend" / "src" / "types.ts"
MOCK_DIR = REPO / "frontend" / "src" / "mock"
ISO_Z = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?Z$")

# ---- §15.4 binding schemas (types: §3.1 for shared columns; DuckDB DESCRIBE names) -------------------------------
RAW_ALERTS = {
    "rule_id": "VARCHAR", "technique_id": "VARCHAR", "sub_technique_id": "VARCHAR", "technique_name": "VARCHAR",
    "tactic": "VARCHAR", "tactic_idx": "INTEGER", "severity": "INTEGER", "ts_ms": "BIGINT", "last_ts_ms": "BIGINT",
    "source_seq": "UBIGINT", "host": "VARCHAR", "subject_host": "VARCHAR", "src_host": "VARCHAR",
    "dst_host": "VARCHAR", "src_user": "VARCHAR", "target_user": "VARCHAR", "src_ip": "VARCHAR", "dst_ip": "VARCHAR",
    "raw_alert_count": "BIGINT", "evidence_lines": "VARCHAR[]", "source_keys": "UBIGINT[]",
}
EPISODES = {"episode_id": "VARCHAR", **RAW_ALERTS, "merged_alert_count": "BIGINT", "user": "VARCHAR",
            "rarity": "DOUBLE", "confidence": "DOUBLE", "is_seed": "BOOLEAN"}
EDGES = {"i": "VARCHAR", "j": "VARCHAR", "rule": "VARCHAR", "weight": "DOUBLE", "dt_ms": "BIGINT",
         "why_linked": "VARCHAR"}
WORK_SCHEMAS = {
    "raw_alerts": RAW_ALERTS, "episodes": EPISODES, "episodes_spilled": EPISODES, "edges": EDGES,
    "host_ip_map": {"ip": "VARCHAR", "host": "VARCHAR", "first_ms": "BIGINT", "last_ms": "BIGINT"},
    "background_hubs": {"entity": "VARCHAR"},
    "rule_host_baseline": {"rule_id": "VARCHAR", "base_freq": "DOUBLE"},
}
RUN_METRICS_KEYS = {"total_wall_s": (int, float), "peak_rss_mb": (int, float), "rows_per_s": (int, float),
                    "stages": list, "episodes": int, "episodes_spilled": int, "incidents": int,
                    "effective_config": dict}
SCORECARD_KEYS = ("detection_pct", "labels_pct", "rebuilt_pct", "false_alarms_strict_pct",
                  "false_alarms_lenient_pct", "singleton_recall_pct", "per_attack", "per_rule_alerts",
                  "unmatched_incidents", "targets")


# ---- fixtures --------------------------------------------------------------------------------------------------
class SetOut:
    def __init__(self, name: str, out: Path | None = None, pq: Path | None = None) -> None:
        self.name = name
        self.out = out or REPO / "data" / "out" / f"qa_{name}"
        self.pq = pq or REPO / "data" / "parquet" / f"qa_{name}"
        self.work = self.out / "work"
        self.raw = REPO / "data" / "raw" / name

    def json(self, rel: str) -> Any:
        return json.loads((self.out / rel).read_text(encoding="utf-8"))


@pytest.fixture(scope="module", params=SETS)
def so(request: pytest.FixtureRequest) -> SetOut:
    s = SetOut(request.param)
    if not (s.out / "run_metrics.json").exists():
        pytest.skip(f"no outputs for {s.name}: run `bash tools/qa/run_contract_sets.sh {s.name}` first")
    return s


@pytest.fixture(scope="module")
def con(tmp_path_factory: pytest.TempPathFactory) -> duckdb.DuckDBPyConnection:
    c = duckdb.connect()
    spill = REPO / "data" / "tmp" / "qa_contracts_spill"
    spill.mkdir(parents=True, exist_ok=True)
    c.execute(f"SET TimeZone='UTC'; SET memory_limit='1GB'; SET threads=2; SET temp_directory={db.sql_path(spill)}")
    yield c
    c.close()


def _pq(so: SetOut, name: str) -> str:
    p = so.work / f"{name}.parquet"
    if not p.exists():
        pytest.fail(f"{so.name}: {p.relative_to(REPO)} missing (every stage writes its Parquet, even when empty)")
    return f"read_parquet({db.sql_path(p)})"


def _describe(con: duckdb.DuckDBPyConnection, src: str) -> dict[str, str]:
    return {r[0]: r[1] for r in con.execute(f"DESCRIBE SELECT * FROM {src}").fetchall()}


def _one(con: duckdb.DuckDBPyConnection, sql: str) -> Any:
    return con.execute(sql).fetchone()[0]


def _schema_diff(actual: dict[str, str], want: dict[str, str]) -> dict[str, Any]:
    return {"missing": sorted(set(want) - set(actual)),
            "wrong_type": {c: (actual[c], t) for c, t in want.items() if c in actual and actual[c] != t}}


# ---- Parquet schemas -------------------------------------------------------------------------------------------
@pytest.mark.parametrize("name", sorted(WORK_SCHEMAS))
def test_work_parquet_schema(so: SetOut, con: duckdb.DuckDBPyConnection, name: str) -> None:
    diff = _schema_diff(_describe(con, _pq(so, name)), WORK_SCHEMAS[name])
    assert diff == {"missing": [], "wrong_type": {}}, f"{so.name} {name}.parquet vs §15.4: {diff}"


def test_events_parquet_schema(so: SetOut, con: duckdb.DuckDBPyConnection) -> None:
    events = so.pq / "events"
    files = list(events.rglob("*.parquet"))
    assert files, f"{so.name}: no events Parquet under {events}"
    # Partition directories are exactly source_type=/ts_ok=/event_day= (§4 Stage 1)
    for f in files[:200]:
        parts = [p.split("=")[0] for p in f.relative_to(events).parts[:-1]]
        assert tuple(parts) == PARTITION_COLUMNS, f"{f.relative_to(events)}"
    db.register_events(con, (events / "**" / "*.parquet").as_posix())
    diff = _schema_diff(_describe(con, "events"), CANONICAL_COLUMNS)
    assert diff == {"missing": [], "wrong_type": {}}, f"{so.name} events vs §3.1: {diff}"
    extra = sorted(set(_describe(con, "events")) - set(CANONICAL_COLUMNS))
    assert extra == [], f"{so.name} events has non-canonical columns {extra} (§3.1: exactly these)"


# ---- Parquet value invariants ----------------------------------------------------------------------------------
def _th(so: SetOut) -> dict[str, int]:
    """Evidence / bucket limits from config/rules.yaml thresholds (load_config())."""
    th = (load_config().get("rules", {}) or {}).get("thresholds", {}) or {}
    return {"lines": int(th.get("evidence_max_lines", 3)), "keys": int(th.get("source_keys_max", 50)),
            "bucket": int(th.get("episode_bucket_ms", 300000)),
            # Intermediates deliberately keep evidence_max_chars + 1 chars so the incident clip can show the cut
            # (detect_sql.evidence_chars); documented in §15.4 (<= evidence_max_chars + 1 = 301).
            "chars": evidence_chars(th)}


def _step_evidence_max_chars() -> int:
    """Strict limit for incident step evidence (models.Step.evidence, UI): evidence_max_chars, 300 by default."""
    th = (load_config().get("rules", {}) or {}).get("thresholds", {}) or {}
    return int(th.get("evidence_max_chars", 300))


def _shape_checks(lim: dict[str, int]) -> dict[str, str]:
    v20 = db.sql_list(TACTICS_V20)
    return {
        "null_keys": "rule_id IS NULL OR technique_id IS NULL OR tactic IS NULL OR ts_ms IS NULL",
        "tactic_not_v20": f"NOT list_contains({v20}, tactic)",
        "tactic_idx_mismatch": f"tactic_idx <> list_position({v20}, tactic)",
        "ts_after_last": "last_ts_ms < ts_ms",
        "evidence_too_many": f"len(evidence_lines) > {lim['lines']}",
        "evidence_line_too_long": f"list_max(list_transform(evidence_lines, lambda x: length(x))) > {lim['chars']}",
        "source_keys_too_many": f"len(source_keys) > {lim['keys']}",
        "count_lt_1": "raw_alert_count < 1",
        "severity_out_of_0_100": "severity NOT BETWEEN 0 AND 100",
    }


def test_raw_alerts_values(so: SetOut, con: duckdb.DuckDBPyConnection) -> None:
    src = _pq(so, "raw_alerts")
    bad = _shape_checks(_th(so))
    got = {k: _one(con, f"SELECT count(*) FROM {src} WHERE {w}") for k, w in bad.items()}
    assert got == dict.fromkeys(bad, 0), f"{so.name} raw_alerts violations: {got}"


def test_episodes_values(so: SetOut, con: duckdb.DuckDBPyConnection) -> None:
    both = f"(SELECT * FROM {_pq(so, 'episodes')} UNION ALL SELECT * FROM {_pq(so, 'episodes_spilled')})"
    key = ("'e' || substr(md5(concat_ws('|', rule_id, coalesce(subject_host, ''), coalesce(src_user, ''), "
           "coalesce(target_user, ''), coalesce(dst_host, ''), bucket::VARCHAR, technique_id)), 1, 10)")
    lim = _th(so)
    bad = {
        **_shape_checks(lim),
        "id_not_formula": f"episode_id <> {key}",
        "bucket_not_ts_div": f"bucket <> ts_ms // {lim['bucket']}",
        "user_not_coalesce": "\"user\" IS DISTINCT FROM coalesce(target_user, src_user)",
        "raw_count_ne_merged": "raw_alert_count <> merged_alert_count",
        "confidence_out_of_0_100": "confidence NOT BETWEEN 0 AND 100 OR confidence IS NULL",
        "rarity_out_of_0_1": "rarity < 0 OR rarity > 1.000001 OR rarity IS NULL",
    }
    got = {k: _one(con, f"SELECT count(*) FROM {both} WHERE {w}") for k, w in bad.items()}
    got["duplicate_ids"] = _one(con, f"SELECT count(*) - count(DISTINCT episode_id) FROM {both}")
    assert got == dict.fromkeys(got, 0), f"{so.name} episodes violations: {got}"
    # conservation: every raw alert lands in exactly one episode (kept or spilled)
    raw_sum = _one(con, f"SELECT coalesce(sum(raw_alert_count), 0) FROM {_pq(so, 'raw_alerts')}")
    ep_sum = _one(con, f"SELECT coalesce(sum(merged_alert_count), 0) FROM {both}")
    assert ep_sum == raw_sum, f"{so.name}: sum(merged_alert_count)={ep_sum} != sum(raw_alert_count)={raw_sum}"


def test_edges_values(so: SetOut, con: duckdb.DuckDBPyConnection) -> None:
    e, ep = _pq(so, "edges"), _pq(so, "episodes")
    bad = {
        "rule_not_R1_R4": f"SELECT count(*) FROM {e} WHERE rule NOT IN ('R1','R2','R3','R4') OR rule IS NULL",
        "self_loop": f"SELECT count(*) FROM {e} WHERE i = j",
        "i_not_episode": f"SELECT count(*) FROM {e} WHERE i NOT IN (SELECT episode_id FROM {ep})",
        "j_not_episode": f"SELECT count(*) FROM {e} WHERE j NOT IN (SELECT episode_id FROM {ep})",
        "weight_le_0": f"SELECT count(*) FROM {e} WHERE NOT weight > 0",
        "dt_ne_tj_minus_ti": (f"SELECT count(*) FROM {e} e JOIN {ep} a ON a.episode_id = e.i "
                              f"JOIN {ep} b ON b.episode_id = e.j WHERE e.dt_ms IS DISTINCT FROM b.ts_ms - a.ts_ms"),
        "dt_negative": f"SELECT count(*) FROM {e} WHERE dt_ms < 0",
        "why_linked_empty": f"SELECT count(*) FROM {e} WHERE coalesce(why_linked, '') = ''",
        "duplicate_i_j_rule": f"SELECT count(*) - count(DISTINCT (i, j, rule)) FROM {e}",
    }
    got = {k: _one(con, q) for k, q in bad.items()}
    assert got == dict.fromkeys(bad, 0), f"{so.name} edges violations: {got}"


def test_host_ip_map_values(so: SetOut, con: duckdb.DuckDBPyConnection) -> None:
    src = _pq(so, "host_ip_map")
    got = {
        "first_after_last": _one(con, f"SELECT count(*) FROM {src} WHERE first_ms > last_ms"),
        "loopback_or_dash": _one(con, f"SELECT count(*) FROM {src} WHERE ip LIKE '127.%' OR ip IN ('::1', '-', '')"),
        "null_ip_or_host": _one(con, f"SELECT count(*) FROM {src} WHERE ip IS NULL OR host IS NULL"),
    }
    assert got == dict.fromkeys(got, 0), f"{so.name} host_ip_map violations: {got}"


# ---- ingest accounting -----------------------------------------------------------------------------------------
def _nonempty_lines(path: Path) -> int:
    """Independent of ingest.scan_lines: split on LF / CRLF / lone CR, count lines that are not all spaces."""
    n, carry = 0, b""
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 24):
            buf = carry + chunk
            lines = buf.splitlines(keepends=True)
            carry = lines.pop() if lines and not lines[-1].endswith((b"\n", b"\r")) else b""
            if carry == b"" and buf.endswith(b"\r"):  # a CR at the chunk edge may be half of CRLF: harmless
                pass
            n += sum(1 for ln in lines if ln.rstrip(b"\r\n").strip(b" "))
    if carry.strip(b" "):
        n += 1
    return n


def test_ingest_accounting_invariants(so: SetOut) -> None:
    acc = so.json("ingest_accounting.json")
    assert isinstance(acc, list) and acc, f"{so.name}: ingest_accounting.json empty"
    problems = []
    for a in acc:
        st = a["source_type"]
        if a["rows_in"] != a["rows_ok"] + a["dropped"]:
            problems.append(f"{st}: rows_in {a['rows_in']} != rows_ok {a['rows_ok']} + dropped {a['dropped']}")
        reasons = a.get("drop_reasons")
        if not isinstance(reasons, dict):
            problems.append(f"{st}: drop_reasons missing")
            continue
        if sum(reasons.values()) != a["dropped"]:
            problems.append(f"{st}: sum(drop_reasons)={sum(reasons.values())} != dropped {a['dropped']} {reasons}")
        if min([a["rows_in"], a["rows_ok"], a["dropped"], *reasons.values()]) < 0:
            problems.append(f"{st}: negative count")
    assert problems == [], f"{so.name}: {problems}"
    rm = so.json("run_metrics.json")
    assert rm["rows_in"] == sum(a["rows_in"] for a in acc), f"{so.name}: run_metrics.rows_in != accounting"
    assert rm["rows_ok"] == sum(a["rows_ok"] for a in acc), f"{so.name}: run_metrics.rows_ok != accounting"


def test_ingest_accounting_matches_parquet(so: SetOut, con: duckdb.DuckDBPyConnection) -> None:
    """rows_ok / quarantined re-counted from the written Parquet (not from the accounting code path)."""
    acc = {a["source_type"]: a for a in so.json("ingest_accounting.json")}
    db.register_events(con, (so.pq / "events" / "**" / "*.parquet").as_posix())
    pq = {st: (ok, bad) for st, ok, bad in con.execute(
        "SELECT source_type, count(*) FILTER (WHERE ts_ok), count(*) FILTER (WHERE NOT ts_ok) FROM events "
        "GROUP BY 1").fetchall()}
    got = {st: (a["rows_ok"], a.get("quarantined", 0)) for st, a in acc.items() if st != "unrecognized"
           and (a["rows_ok"] or a.get("quarantined", 0))}
    assert got == pq, f"{so.name}: accounting (rows_ok, quarantined) {got} != Parquet {pq}"


def test_ingest_rows_in_matches_raw_bytes(so: SetOut) -> None:
    """Σ rows_in = non-empty physical lines of every ingested file (CSV: minus one header line per file)."""
    prof = so.json("source_profile.json")
    files = [f for f in prof["files"] if f.get("format") != "unrecognized"]
    unrec = [f for f in prof["files"] if f.get("format") == "unrecognized"]
    want = 0
    for f in files:
        n = _nonempty_lines(Path(f["path"]))
        want += max(n - 1, 0) if f.get("format") == "csv" else n
    acc = so.json("ingest_accounting.json")
    got = sum(a["rows_in"] for a in acc if a["source_type"] != "unrecognized")
    assert got == want, f"{so.name}: Σ rows_in {got} != physical lines {want}"
    unrec_lines = sum(_nonempty_lines(Path(f["path"])) for f in unrec)
    unrec_acc = sum(a["rows_in"] for a in acc if a["source_type"] == "unrecognized")
    assert unrec_acc == unrec_lines, f"{so.name}: unrecognized rows_in {unrec_acc} != lines {unrec_lines}"


# ---- episode accounting ----------------------------------------------------------------------------------------
def test_episode_accounting(so: SetOut, con: duckdb.DuckDBPyConnection) -> None:
    rm = so.json("run_metrics.json")
    st = rm["stage_stats"]["incidents"]
    ea = st["episode_accounting"]
    assert ea["in_incidents"] + ea["in_suppressed"] == ea["episodes"], f"{so.name}: {ea}"
    assert (ea["missing"], ea["duplicated"], ea["ok"]) == (0, 0, True), f"{so.name}: {ea}"
    n_ep = _one(con, f"SELECT count(*) FROM {_pq(so, 'episodes')}")
    n_sp = _one(con, f"SELECT count(*) FROM {_pq(so, 'episodes_spilled')}")
    assert (ea["episodes"], st["episodes_spilled"], st["episodes_total"]) == (n_ep, n_sp, n_ep + n_sp), \
        f"{so.name}: accounting {ea['episodes']}/{st['episodes_spilled']}/{st['episodes_total']} vs Parquet {n_ep}/{n_sp}"
    assert (rm["episodes"], rm["episodes_spilled"]) == (n_ep, n_sp), f"{so.name}: run_metrics episodes"
    incs = _incident_files(so)
    assert sum(i.episode_count for i in incs.values()) == ea["in_incidents"], \
        f"{so.name}: Σ incident.episode_count != in_incidents {ea['in_incidents']}"
    sup = so.json("suppressed.json")
    assert sup["total"] == st["suppressed"] and sum(sup["by_reason"].values()) == sup["total"], f"{so.name}: {sup['by_reason']}"


# ---- run_metrics / scorecard -----------------------------------------------------------------------------------
def test_run_metrics_keys(so: SetOut) -> None:
    rm = so.json("run_metrics.json")
    missing = [k for k in RUN_METRICS_KEYS if k not in rm]
    wrong = {k: type(rm[k]).__name__ for k, t in RUN_METRICS_KEYS.items() if k in rm and not isinstance(rm[k], t)}
    assert (missing, wrong) == ([], {}), f"{so.name}: run_metrics §15.6 missing {missing}, wrong types {wrong}"
    assert rm.get("error") is None, f"{so.name}: run failed: {rm.get('error')}"
    want = list(STAGES) + (["eval"] if so.name in GT_SETS else [])
    assert [s["name"] for s in rm["stages"]] == want, f"{so.name}: stages {[s['name'] for s in rm['stages']]}"
    for s in rm["stages"]:
        assert {"name", "wall_s", "peak_rss_mb"} <= set(s), s
        assert s["wall_s"] >= 0 and s["peak_rss_mb"] > 0, s
    assert rm["peak_rss_mb"] >= max(s["peak_rss_mb"] for s in rm["stages"]), f"{so.name}: peak < a stage peak"
    assert sum(s["wall_s"] for s in rm["stages"]) <= rm["total_wall_s"] + 0.5, f"{so.name}: Σ stage wall > total"
    assert rm["incidents"] == len(so.json("incidents_index.json")), f"{so.name}: run_metrics.incidents"
    assert rm["effective_config"] and "attack" not in rm["effective_config"]


def test_eval_scorecard_keys(so: SetOut) -> None:
    if so.name not in GT_SETS:
        pytest.skip(f"{so.name} is run without ground truth")
    card = so.json("eval_scorecard.json")
    missing = [k for k in SCORECARD_KEYS if k not in card]
    assert missing == [], f"{so.name}: eval_scorecard §15.6 missing {missing}"
    for k in SCORECARD_KEYS[:6]:
        assert card[k] is None or (isinstance(card[k], (int, float)) and 0 <= card[k] <= 100), (k, card[k])


# ---- incidents -------------------------------------------------------------------------------------------------
def _incident_files(so: SetOut) -> dict[str, Incident]:
    out, errors = {}, {}
    for p in sorted((so.out / "incidents").glob("*.json")):
        try:
            out[p.stem] = Incident.model_validate_json(p.read_text(encoding="utf-8"))
        except ValidationError as exc:
            errors[p.name] = str(exc).splitlines()[:4]
    assert errors == {}, f"{so.name}: incidents/*.json not valid models.Incident: {errors}"
    return out


def test_incident_files_validate(so: SetOut) -> None:
    incs = _incident_files(so)
    for stem, inc in incs.items():
        assert stem == inc.id and re.fullmatch(r"inc-[0-9a-f]{8}", inc.id), stem
    work = json.loads((so.work / "incidents.json").read_text(encoding="utf-8"))
    assert sorted(d["id"] for d in work) == sorted(incs), f"{so.name}: work/incidents.json ids != published files"


def _steps(inc: Incident) -> list[models.Step]:
    return list(inc.backbone) + [s for b in inc.branches for s in b]


def test_incident_internal_consistency(so: SetOut) -> None:
    problems: list[str] = []
    ev_max = _step_evidence_max_chars()
    assert ev_max == 300, f"evidence_max_chars is {ev_max}; the UI and §7.1 assume 300"
    for iid, inc in _incident_files(so).items():
        p = lambda m: problems.append(f"{iid}: {m}")  # noqa: E731
        if not inc.backbone:
            p("empty backbone")
            continue
        if [s.step for s in inc.backbone] != list(range(len(inc.backbone))):
            p(f"backbone step numbers {[s.step for s in inc.backbone]}")
        if not 0 <= inc.entry_point.step < len(inc.backbone):
            p(f"entry_point.step {inc.entry_point.step} not a backbone step")
        if not 0 <= inc.risk <= 100:
            p(f"risk {inc.risk}")
        for t in (inc.first_ts, inc.last_ts, *(s.ts for s in _steps(inc))):
            if not ISO_Z.match(t):
                p(f"timestamp not ISO-8601 Z: {t}")
        if inc.first_ts > inc.last_ts:
            p("first_ts > last_ts")
        for s in _steps(inc):
            if not inc.first_ts <= s.ts <= inc.last_ts:
                p(f"step {s.episode_id} ts {s.ts} outside [{inc.first_ts}, {inc.last_ts}]")
            if not (0 <= s.severity <= 100 and 0 <= s.confidence <= 100 and s.merged_alert_count >= 1):
                p(f"step {s.episode_id} severity/confidence/count out of range")
            if len(s.evidence) > 3 or any(len(e) > ev_max for e in s.evidence):
                p(f"step {s.episode_id} evidence > 3 lines or > {ev_max} chars")
        ids = [s.episode_id for s in _steps(inc)]
        if len(ids) != len(set(ids)):
            p("an episode appears twice in backbone + branches")
        if inc.episode_count < len(set(ids)):
            p(f"episode_count {inc.episode_count} < steps {len(set(ids))}")
        if inc.merged_alert_count < sum(s.merged_alert_count for s in _steps(inc)):
            p("merged_alert_count < Σ step merged_alert_count")
        node_ids = {n.id for n in inc.graph.nodes}
        for n in inc.graph.nodes:
            if n.id.split(":", 1)[0] != n.type:
                p(f"graph node {n.id} type {n.type}")
        for e in inc.graph.edges:
            if e.source not in node_ids or e.target not in node_ids:
                p(f"graph edge {e.source}->{e.target} to unknown node")
        for e in inc.edges:
            if e.from_ == e.to:
                p(f"self edge {e.from_}")
    assert problems == [], f"{so.name}: {problems[:20]} ({len(problems)} total)"


def test_incident_tactics_v20(so: SetOut) -> None:
    problems: list[str] = []
    for iid, inc in _incident_files(so).items():
        for s in _steps(inc):
            if s.tactic not in TACTIC_IDX:
                problems.append(f"{iid} step {s.episode_id}: tactic {s.tactic!r} not in v20")
        if any(t not in TACTIC_IDX for t in inc.tactics + inc.gaps):
            problems.append(f"{iid}: tactics/gaps not v20: {inc.tactics} {inc.gaps}")
            continue
        if [TACTIC_IDX[t] for t in inc.tactics] != sorted({TACTIC_IDX[t] for t in inc.tactics}):
            problems.append(f"{iid}: tactics not unique in v20 order: {inc.tactics}")
        if set(inc.tactics) & set(inc.gaps):
            problems.append(f"{iid}: a tactic is both observed and a gap")
        if not {s.tactic for s in inc.backbone} <= set(inc.tactics):
            problems.append(f"{iid}: backbone tactic missing from tactics")
    assert problems == [], f"{so.name}: {problems[:20]}"


def test_v20_tactics_match_attack_data() -> None:
    attack = json.loads((REPO / "config" / "attack_v20.json").read_text(encoding="utf-8"))
    names = [t["name"] for t in sorted(attack["tactics"], key=lambda t: t["idx"])]
    assert names == TACTICS_V20 and len(names) == 15
    assert names[6:8] == ["Stealth", "Defense Impairment"]


def test_incidents_index_matches_files(so: SetOut) -> None:
    rows = [IncidentSummary.model_validate(r) for r in so.json("incidents_index.json")]
    incs = _incident_files(so)
    assert [r.id for r in rows if r.id not in incs] == [], f"{so.name}: index rows without a file"
    assert sorted(incs) == sorted(r.id for r in rows) and len(rows) == len({r.id for r in rows}), so.name
    for r in rows:
        i = incs[r.id]
        hosts = list(dict.fromkeys(s.host for s in i.backbone if s.host))
        want = (i.risk, i.first_ts, i.last_ts, i.merged_alert_count, i.episode_count, i.tactics, hosts,
                i.entry_point.summary)
        got = (r.risk, r.first_ts, r.last_ts, r.merged_alert_count, r.episode_count, r.tactics, r.hosts,
               r.entry_summary)
        assert got == want, f"{so.name} {r.id}: index {got} != file {want}"
    keys = [(-r.risk, r.first_ts, r.id) for r in rows]
    assert keys == sorted(keys), f"{so.name}: index not sorted by risk desc"


# ---- models.py <-> types.ts <-> mock ---------------------------------------------------------------------------
def _ts_split(s: str, sep: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in s:
        depth += ch in "{[(<"
        depth -= ch in "}])>"
        if ch == sep and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    return [x for x in (*out, cur.strip()) if x]


# string literals first (kept verbatim), then /* ... */ (incl. multi-line JSDoc) and // comments (dropped)
_TS_COMMENT = re.compile(r"""('(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`)|/\*.*?\*/|//[^\n]*""", re.S)


def _strip_ts_comments(text: str) -> str:
    return _TS_COMMENT.sub(lambda m: m.group(1) or (" " if m.group(0).startswith("/*") else ""), text)


def _ts_fields(body: str) -> dict[str, str]:
    fields = {}
    for part in _ts_split(_strip_ts_comments(body).replace("\n", ";"), ";"):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r"(\w+)(\??)\s*:\s*(.+)", part, re.S)
        assert m, f"cannot parse TS field {part!r}"
        fields[m.group(1)] = m.group(3).strip() + (" | undefined" if m.group(2) else "")
    return fields


def parse_ts_interfaces(text: str) -> dict[str, dict[str, str]]:
    text = _strip_ts_comments(text)
    out = {}
    for m in re.finditer(r"export\s+interface\s+(\w+)\s*\{", text):
        i, depth = m.end(), 1
        while depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        out[m.group(1)] = _ts_fields(text[m.end():i - 1])
    return out


def _norm_ts(t: str, ifaces: dict[str, dict[str, str]]) -> Any:
    alts = _ts_split(t, "|")
    res = set()
    for a in alts:
        if a.startswith("{"):
            res.add(("object", tuple(sorted((k, _norm_ts(v, ifaces)) for k, v in _ts_fields(a[1:-1]).items()))))
        elif a.endswith("[]"):
            res.add(("list", _norm_ts(a[:-2], ifaces)))
        elif a.startswith("'"):
            res.add(("lit", a.strip("'")))
        elif a in ifaces:
            res.add(("object", tuple(sorted((k, _norm_ts(v, ifaces)) for k, v in ifaces[a].items()))))
        else:
            res.add({"number": "number", "string": "string", "boolean": "boolean", "null": "null"}.get(a, a))
    return frozenset(res) if len(res) > 1 else next(iter(res))


def _norm_py(tp: Any) -> Any:
    origin = get_origin(tp)
    if origin in (typing.Union, types.UnionType):
        return frozenset(_flat(_norm_py(a) for a in get_args(tp)))
    if origin is Literal:
        return frozenset(("lit", v) for v in get_args(tp)) if len(get_args(tp)) > 1 else ("lit", get_args(tp)[0])
    if origin is list:
        return ("list", _norm_py(get_args(tp)[0]))
    if isinstance(tp, type) and issubclass(tp, BaseModel):
        return ("object", tuple(sorted((f.alias or n, _norm_py(f.annotation)) for n, f in tp.model_fields.items())))
    return {str: "string", int: "number", float: "number", bool: "boolean", type(None): "null"}[tp]


def _flat(items: Any) -> list[Any]:
    out = []
    for x in items:
        out.extend(x if isinstance(x, frozenset) else [x])
    return out


CONTRACT_MODELS = ["EntryPoint", "Step", "PathEdge", "GraphNode", "GraphEdge", "ReachNext", "Narrative", "Incident",
                   "IncidentSummary"]


def test_ts_parser_sanity() -> None:
    """The parser itself on a hand-checked snippet (so a parse bug cannot hide a contract drift)."""
    got = parse_ts_interfaces("/** GET /x/{id} */\nexport interface A {\n  x: number\n  /** doc {k}; */\n"
                              "  y?: 'a' | 'b' // c\n  z: { p: string[]; q: B[] }\n}\n"
                              "export interface B { r: string | null }")
    assert got == {"A": {"x": "number", "y": "'a' | 'b' | undefined", "z": "{ p: string[]; q: B[] }"},
                   "B": {"r": "string | null"}}


def test_ts_parser_block_comments_and_literals() -> None:
    """JSDoc (single/multi-line, holding braces, ';' or '//') is dropped; '/*' and '//' inside literals survive."""
    body = ("  /** one-liner (<= 300 chars) */\n  a: string\n  /**\n   * multi {x}; // y\n   */\n  b?: number\n"
            "  c: 'p/*q' | 'r//s' /* tail */\n  d: { e: string /* in */; f: boolean }\n")
    want = {"a": "string", "b": "number | undefined", "c": "'p/*q' | 'r//s'", "d": "{ e: string  ; f: boolean }"}
    assert _ts_fields(body) == want
    assert parse_ts_interfaces("export interface A {\n" + body + "}\n") == {"A": want}
    assert _norm_ts(want["c"], {}) == frozenset({("lit", "p/*q"), ("lit", "r//s")})


def test_ts_contract_still_catches_drift_next_to_jsdoc() -> None:
    """A JSDoc comment alone keeps the contract green; a renamed field beside it still fails it (in memory only)."""
    text = TS_FILE.read_text(encoding="utf-8")
    anchor = "export interface EntryPoint {\n  step: number\n"
    assert anchor in text, "EntryPoint anchor not in types.ts (update this test)"
    doc = "export interface EntryPoint {\n  /**\n   * GET /api/{id} // x\n   */\n  step: number\n"
    assert contract_diff("EntryPoint", text.replace(anchor, doc, 1)) == {}
    renamed = text.replace(anchor, doc.replace("  step: number", "  stepNo: number"), 1)
    assert contract_diff("EntryPoint", renamed)["names"]["types.ts"][0] == "stepNo"


def contract_diff(name: str, ts_text: str) -> dict[str, Any]:
    """{} when models.<name> and the TS interface agree on field names, order, types, nullability and literals."""
    ifaces = parse_ts_interfaces(ts_text)
    if name not in ifaces:
        return {"missing_interface": name}
    model: type[BaseModel] = getattr(models, name)
    py = {f.alias or n: _norm_py(f.annotation) for n, f in model.model_fields.items()}
    ts = {k: _norm_ts(v, ifaces) for k, v in ifaces[name].items()}
    out: dict[str, Any] = {}
    if list(py) != list(ts):
        out["names"] = {"models.py": list(py), "types.ts": list(ts)}
    drift = {k: (py[k], ts[k]) for k in py if k in ts and py[k] != ts[k]}
    if drift:
        out["types"] = drift
    return out


@pytest.mark.parametrize("name", CONTRACT_MODELS)
def test_models_match_types_ts(name: str) -> None:
    assert contract_diff(name, TS_FILE.read_text(encoding="utf-8")) == {}, name


@pytest.mark.parametrize("mock", sorted(p.name for p in MOCK_DIR.glob("incident*.json")))
def test_mock_incidents_validate(mock: str) -> None:
    raw = json.loads((MOCK_DIR / mock).read_text(encoding="utf-8"))
    inc = Incident.model_validate(raw)
    assert models.dump(inc) == {**models.dump(inc), **raw}, f"{mock}: round-trip changes wire fields"
    assert all(s.tactic in TACTIC_IDX for s in _steps(inc)), mock


def test_mock_index_validates() -> None:
    rows = json.loads((MOCK_DIR / "index.json").read_text(encoding="utf-8"))
    ids = [IncidentSummary.model_validate(r).id for r in rows]
    assert ids and len(ids) == len(set(ids))


# ---- product bugs found by this track (strict xfail; the owner removes the marker with the fix) ---------------
@pytest.mark.xfail(strict=True, raises=AttributeError,
                   reason="QA-C1: eval/harness.py:46 load_ground_truth calls doc.get on a bare JSON list "
                          "(data/raw/smoke_mixed/ground_truth/attacks.json is `[]`) -> AttributeError aborts the "
                          "run (rc=1, eval_scorecard.json missing) instead of a clear ValueError naming the file")
def test_qa_c1_ground_truth_bare_list_gives_clear_error(tmp_path: Path) -> None:
    from eval import harness

    gt = tmp_path / "attacks.json"
    gt.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="attacks"):
        harness.load_ground_truth(gt)


def test_qa_c1_ground_truth_object_form_still_loads(tmp_path: Path) -> None:
    """Near-miss control for QA-C1: the §3.3 object form with zero attacks loads to zero steps."""
    from eval import harness

    gt = tmp_path / "attacks.json"
    gt.write_text('{"attack_version": "v20", "attacks": []}', encoding="utf-8")
    doc, steps = harness.load_ground_truth(gt)
    assert (doc["attacks"], steps) == ([], [])
