"""Stage 2 hook: run compiled Sigma rules (sigma_rules.load) over `events` and append their alerts to al_raw.

Execution plan (bounded, no window functions, no ORDER BY over the input):
- rules are grouped by gate (logsource + product, e.g. action = 'proc_start'); rows outside every gate are never tested;
- per group, the DISTINCT tuples of the fields its rules read are collected once (lower-cased copies precomputed);
  first, sigma_prefilter finds from per-field value tables the only field values a matching row can hold and keeps
  just those rows (no candidate value at all: the group is skipped) - exact, for groups with at most
  sigma.prefilter_max_terms field references and at least sigma.prefilter_min_rows gated rows (network groups:
  millions of near-unique tuples, none can match);
  predicates run over those tuples in batches of pipeline.yaml sigma.batch_size (bounded SQL size);
- matching tuples are joined back to the gated events (one scan) into al_sigma_hits (row + matching rule ids);
- a group with keyword rules (raw_line search: every line is its own tuple) skips the DISTINCT and evaluates the
  same predicates directly over the gated events (one scan per batch);
- a batch that fails is retried rule by rule; rules that still fail are counted (sigma_batches_failed,
  sigma_rules_failed, sigma_failed_rule_ids) - never silently dropped;
- al_sigma_hits -> one alert per row x rule (labels from al_sigma_labels, same columns and host resolution as
  `kind: match` rules), then dedupe against native alerts (rules.yaml AND native cloud: detect.py runs the cloud hook
  first), THEN the per-rule cap (overflow counted), then al_raw.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import duckdb

from attacklens import sigma_prefilter, sigma_rules
from attacklens.detect_sql import OK, RAW_ALERT_COLUMNS, evidence_chars, q, sql_list, subject_host_expr
from attacklens.schemas import TACTIC_IDX
from attacklens.sigma_compile import MARK_RE, render

log = logging.getLogger(__name__)

HIT_COLUMNS = ("ts_ms", "source_seq", "source_type", "action", "host", "src_user", "target_user", "src_ip", "dst_ip",
               "src_zone", "dst_zone")
MAX_FAILED_IDS = 50
PREFILTER_MAX_TERMS = 2000   # default for pipeline.yaml sigma.prefilter_max_terms
PREFILTER_MIN_ROWS = 50_000  # default for sigma.prefilter_min_rows (smaller groups: the plain path is cheaper)
PREFILTER_DIRECT_MAX_LEAVES = 4   # default for sigma.prefilter_direct_max_leaves (more leaves: hashing wins)


def enabled(cfg: dict[str, Any]) -> bool:
    return bool(sigma_rules.settings(cfg).get("enabled"))


def _labels_table(con: duckdb.DuckDBPyConnection, rules: list[dict[str, Any]]) -> None:
    """al_sigma_labels: one columnar INSERT (unnest of parallel lists), not one statement per rule."""
    con.execute("""CREATE OR REPLACE TEMP TABLE al_sigma_labels(rule_id VARCHAR, technique_id VARCHAR,
                   sub_technique_id VARCHAR, tactic VARCHAR, tactic_idx INTEGER, severity INTEGER)""")
    if not rules:
        return
    cols = ([r["id"] for r in rules], [r["technique"] for r in rules], [r.get("sub_technique") for r in rules],
            [r["tactic"] for r in rules], [TACTIC_IDX[r["tactic"]] for r in rules],
            [int(r["severity"]) for r in rules])
    con.execute("INSERT INTO al_sigma_labels SELECT unnest($1::VARCHAR[]), unnest($2::VARCHAR[]), "
                "unnest($3::VARCHAR[]), unnest($4::VARCHAR[]), unnest($5::INTEGER[]), unnest($6::INTEGER[])",
                list(cols))


def _group_indices(rules: list[dict[str, Any]]) -> tuple[list[int], set[int]]:
    """(all expression indices the group references, the ones referenced lower-cased)."""
    keys: set[int] = set()
    low: set[int] = set()
    for r in rules:
        for m in MARK_RE.finditer(r["scan"]):
            i = int(m.group(2))
            keys.add(i)
            if m.group(1) == "L":
                low.add(i)
    return sorted(keys), low


def _batches(con: duckdb.DuckDBPyConnection, rules: list[dict[str, Any]], bs: int,
             make_sql: Callable[[list[dict[str, Any]]], str]) -> dict[str, Any]:
    """Run make_sql(batch) per batch; a failing batch is retried rule by rule. Returns failure counts."""
    failed_batches, failed_ids = 0, []
    for i in range(0, len(rules), bs):
        batch = rules[i:i + bs]
        try:
            con.execute(make_sql(batch))
            continue
        except duckdb.Error as exc:   # never let third-party rules stop the run; isolate, count, continue
            failed_batches += 1
            log.error("sigma: batch %s[%d:%d] failed (%s); retrying rule by rule",
                      batch[0].get("logsource"), i, i + len(batch), str(exc).splitlines()[0][:300])
        for r in batch:
            try:
                con.execute(make_sql([r]))
            except duckdb.Error as exc:
                failed_ids.append(str(r["id"]))
                log.error("sigma: rule %s (%s) failed: %s", r["id"], r.get("path"), str(exc).splitlines()[0][:300])
    return {"batches_failed": failed_batches, "rules_failed": len(failed_ids), "failed_rule_ids": failed_ids}


def _id_list(rules: list[dict[str, Any]], exprs: list[str], aliases: dict[int, str]) -> str:
    return ", ".join(f"CASE WHEN {render(r['scan'], exprs, aliases)} THEN {q(r['id'])} END" for r in rules)


def _run_group(con: duckdb.DuckDBPyConnection, gate: str, rules: list[dict[str, Any]], exprs: list[str],
               bs: int, mc: int, max_terms: int = PREFILTER_MAX_TERMS, *, min_rows: int = PREFILTER_MIN_ROWS,
               direct_max_leaves: int = PREFILTER_DIRECT_MAX_LEAVES) -> dict[str, Any]:
    """Rules of one gate: evaluate every predicate once per DISTINCT tuple of the fields they read (events repeat
    the same process/command line/path millions of times), then join the matching tuples back to the events.
    Rows that fail the group prefilter (no rule can match them) never reach the DISTINCT. Keyword groups (raw_line
    search) are evaluated directly over the gated events."""
    keys, low = _group_indices(rules)
    if not keys:
        return {"tuples": 0, "matched_tuples": 0, "batches_failed": 0, "rules_failed": 0, "failed_rule_ids": []}
    sel = ", ".join(f"({exprs[i]}) AS r_{i}" for i in keys)
    lows = "".join(f", lower(CAST(r_{i} AS VARCHAR)) AS l_{i}" for i in sorted(low))
    rcols = ", ".join(f"r_{i}" for i in keys)
    aliases = {i: str(i) for i in keys}
    where = f"{OK} AND ts_ms IS NOT NULL AND ({gate})"
    # lower-case copies are precomputed, so common-subexpression search only costs planning time (~half of the
    # ~3 s it takes to plan 1000 Sigma predicates); switched off for these statements only
    prev = con.execute("SELECT current_setting('disabled_optimizers')").fetchone()[0] or ""
    if any(r.get("keyword_search") for r in rules):
        tuples = int(con.execute(f"SELECT count(*) FROM events WHERE {where}").fetchone()[0])
        if not tuples:
            return {"tuples": 0, "matched_tuples": 0, "batches_failed": 0, "rules_failed": 0,
                    "failed_rule_ids": [], "mode": "direct"}
        hit_cols = ", ".join(HIT_COLUMNS)
        src = (f"(SELECT *{lows} FROM (SELECT {hit_cols}, left(raw_line, {mc}) AS al_ev_line, {sel} "
               f"FROM events WHERE {where}))")
        before = int(con.execute("SELECT count(*) FROM al_sigma_hits").fetchone()[0])

        def direct_sql(batch: list[dict[str, Any]]) -> str:
            return (f"INSERT INTO al_sigma_hits SELECT {hit_cols}, al_ev_line, rule_ids FROM ("
                    f"SELECT *, list_filter([{_id_list(batch, exprs, aliases)}], lambda x: x IS NOT NULL) AS rule_ids "
                    f"FROM {src}) WHERE len(rule_ids) > 0")
        con.execute("SET disabled_optimizers = " + q(",".join(x for x in (prev, "common_subexpressions") if x)))
        try:
            fails = _batches(con, rules, bs, direct_sql)
        finally:
            con.execute("SET disabled_optimizers = " + q(prev))
        matched = int(con.execute("SELECT count(*) FROM al_sigma_hits").fetchone()[0]) - before
        return {"tuples": tuples, "matched_tuples": matched, **fails, "mode": "direct"}

    con.execute("SET disabled_optimizers = " + q(",".join(x for x in (prev, "common_subexpressions") if x)))
    try:
        flt, gated = sigma_prefilter.build(con, rules, exprs, where, max_terms, bs, min_rows, direct_max_leaves)
    finally:
        con.execute("SET disabled_optimizers = " + q(prev))
    mode = {} if flt is None else {"prefilter": True}
    if flt == sigma_prefilter.SKIP:   # no gated row holds a value any rule needs: nothing to scan or plan
        return {"tuples": 0, "matched_tuples": 0, "batches_failed": 0, "rules_failed": 0, "failed_rule_ids": [],
                **mode, **({"gated": True} if gated else {})}
    try:
        rows = (f"SELECT DISTINCT {sel} FROM events WHERE {where}" if flt is None else
                f"SELECT DISTINCT * FROM (SELECT {sel} FROM events WHERE {where}) WHERE {flt}")
        con.execute(f"CREATE OR REPLACE TEMP TABLE al_sg_v AS SELECT *{lows} FROM ({rows})")
    finally:
        sigma_prefilter.cleanup(con, flt)
    con.execute(f"CREATE OR REPLACE TEMP TABLE al_sg_m AS SELECT {rcols}, []::VARCHAR[] AS rule_ids "
                "FROM al_sg_v WHERE false")
    tuples = int(con.execute("SELECT count(*) FROM al_sg_v").fetchone()[0])
    if not tuples:   # no gated rows: skip planning ~1000 predicates for nothing
        con.execute("DROP TABLE IF EXISTS al_sg_v")
        con.execute("DROP TABLE IF EXISTS al_sg_m")
        return {"tuples": 0, "matched_tuples": 0, "batches_failed": 0, "rules_failed": 0, "failed_rule_ids": [],
                **mode, **({"gated": True} if flt is not None else {})}

    def tuple_sql(batch: list[dict[str, Any]]) -> str:
        return (f"INSERT INTO al_sg_m SELECT {rcols}, rule_ids FROM (SELECT {rcols}, "
                f"list_filter([{_id_list(batch, exprs, aliases)}], lambda x: x IS NOT NULL) AS rule_ids "
                "FROM al_sg_v) WHERE len(rule_ids) > 0")
    con.execute("SET disabled_optimizers = " + q(",".join(x for x in (prev, "common_subexpressions") if x)))
    try:
        fails = _batches(con, rules, bs, tuple_sql)
    finally:
        con.execute("SET disabled_optimizers = " + q(prev))
    matched = int(con.execute("SELECT count(*) FROM al_sg_m").fetchone()[0])
    if matched:
        on = " AND ".join(f"({exprs[i]}) IS NOT DISTINCT FROM m.r_{i}" for i in keys)
        hit_cols = ", ".join(f"e.{c}" for c in HIT_COLUMNS)
        con.execute(f"""
            INSERT INTO al_sigma_hits
            SELECT {hit_cols}, left(e.raw_line, {mc}) AS raw_line, m.rule_ids
            FROM events e JOIN (SELECT {rcols}, flatten(list(rule_ids)) AS rule_ids FROM al_sg_m GROUP BY ALL) m
              ON {on}
            WHERE {OK} AND e.ts_ms IS NOT NULL AND ({gate})""")
    con.execute("DROP TABLE IF EXISTS al_sg_v")
    con.execute("DROP TABLE IF EXISTS al_sg_m")
    return {"tuples": tuples, "matched_tuples": matched, **fails, **mode}


def explode(con: duckdb.DuckDBPyConnection) -> None:
    """al_sigma_hits (row x rule list) -> al_sigma_x (row x rule)."""
    con.execute("CREATE OR REPLACE TEMP TABLE al_sigma_x AS "
                "SELECT * EXCLUDE (rule_ids), unnest(rule_ids) AS rid FROM al_sigma_hits")


def cap_alerts(con: duckdb.DuckDBPyConnection, cap: int, table: str = "al_sigma_a") -> dict[str, int]:
    """Keep at most `cap` alerts per rule in `table` (earliest by (ts_ms, source_seq)); returns {rule_id: dropped}.
    Runs AFTER the native dedupe, so covered hits never consume the cap. The window runs only over Sigma alerts."""
    if cap <= 0:
        return {}
    over = {str(r): int(n) - cap for r, n in con.execute(
        f"SELECT rule_id, count(*) FROM {table} GROUP BY rule_id HAVING count(*) > {cap}").fetchall()}
    if over:
        con.execute(f"""CREATE OR REPLACE TEMP TABLE {table} AS SELECT * EXCLUDE (k) FROM (
                        SELECT *, row_number() OVER (PARTITION BY rule_id ORDER BY ts_ms, source_seq) AS k
                        FROM {table}) WHERE k <= {cap}""")
    return over


_NATIVE_COVERS = """EXISTS (SELECT 1 FROM al_sg_native x WHERE x.seq = {s}.source_seq
    AND x.host IS NOT DISTINCT FROM {s}.host AND ({cond}))"""
# rules.yaml natives: same technique OR same tactic. Native cloud (detect_cloud): same technique (parent) with a
# compatible sub-technique only (equal, or one side has none = parent/child); sibling subs / same tactic stay apart
_COND_RULES = "NOT x.cloud AND (x.technique_id = {s}.technique_id OR x.tactic = {s}.tactic)"
_COND_CLOUD = ("x.cloud AND x.technique_id = {s}.technique_id AND (x.sub IS NULL OR {s}.sub_technique_id IS NULL "
               "OR x.sub = {s}.sub_technique_id)")


def _covers(s: str, *conds: str) -> str:
    return _NATIVE_COVERS.format(s=s, cond=" OR ".join(f"({c.format(s=s)})" for c in conds))


def dedupe_against_native(con: duckdb.DuckDBPyConnection, table: str = "al_raw",
                          native_cloud_ids: Iterable[str] = (), counts: dict[str, int] | None = None) -> int:
    """Drop a Sigma alert (in `table`) when a native alert in al_raw already covers the same event (its source_seq
    is in the native alert's source_keys) and host. A config/rules.yaml native covers it with the same technique OR
    the same tactic (a community rule that labels the same event differently within the same tactic is the same
    detection). A native CLOUD alert (rule id in native_cloud_ids: detect_cloud output, already in al_raw) covers it
    only with the same technique and a compatible sub-technique (same, or parent/child): the more specific native
    label and its severity stay, and a distinct technique (other technique, sibling sub-technique) is never lost.
    One alert per detection, the episode counts it once. Native source_keys are unnested only for the source_seq
    values Sigma hit (equi-join, bounded by the hit set). counts (optional) gets {"cloud": n deduped by cloud only}."""
    cloud = sorted({str(i) for i in native_cloud_ids})
    is_cloud = f"rule_id IN {sql_list(cloud)}" if cloud else "false"
    con.execute(f"""CREATE OR REPLACE TEMP TABLE al_sg_native AS
        SELECT DISTINCT seq, host, technique_id, sub, tactic, cloud FROM (
            SELECT unnest(source_keys) AS seq, host, technique_id, sub_technique_id AS sub, tactic,
                   ({is_cloud}) AS cloud FROM al_raw
            WHERE NOT starts_with(rule_id, 'sigma_'))
        WHERE seq IN (SELECT source_seq FROM {table} WHERE starts_with(rule_id, 'sigma_'))""")
    try:
        n = int(con.execute(f"SELECT count(*) FROM {table} s WHERE starts_with(s.rule_id, 'sigma_') AND "
                            + _covers("s", _COND_RULES, _COND_CLOUD)).fetchone()[0])
        if counts is not None:
            counts["cloud"] = int(con.execute(
                f"SELECT count(*) FROM {table} s WHERE starts_with(s.rule_id, 'sigma_') AND "
                + _covers("s", _COND_CLOUD) + " AND NOT " + _covers("s", _COND_RULES)).fetchone()[0]) if cloud else 0
        if n:
            con.execute(f"DELETE FROM {table} WHERE starts_with(rule_id, 'sigma_') AND "
                        + _covers(table, _COND_RULES, _COND_CLOUD))
    finally:
        con.execute("DROP TABLE IF EXISTS al_sg_native")
    return n


def alerts_sql(th: dict[str, Any]) -> str:
    """al_sigma_x (row x rule id) -> raw_alerts columns (§15.4), mirroring detect.rule_sql for match rules."""
    mc = evidence_chars(th)
    return f"""
    WITH h AS (SELECT * FROM al_sigma_x)
    SELECT h.rid::VARCHAR AS rule_id, lb.technique_id::VARCHAR AS technique_id,
           lb.sub_technique_id::VARCHAR AS sub_technique_id, coalesce(a.name, a2.name)::VARCHAR AS technique_name,
           lb.tactic::VARCHAR AS tactic, lb.tactic_idx::INTEGER AS tactic_idx, lb.severity::INTEGER AS severity,
           h.ts_ms::BIGINT AS ts_ms, h.ts_ms::BIGINT AS last_ts_ms, h.source_seq::UBIGINT AS source_seq,
           h.host::VARCHAR AS host, ({subject_host_expr('h', 'm', th)})::VARCHAR AS subject_host,
           m.host::VARCHAR AS src_host, md.host::VARCHAR AS dst_host,
           h.src_user::VARCHAR AS src_user, h.target_user::VARCHAR AS target_user,
           h.src_ip::VARCHAR AS src_ip, h.dst_ip::VARCHAR AS dst_ip, 1::BIGINT AS raw_alert_count,
           [left(h.raw_line, {mc})]::VARCHAR[] AS evidence_lines, [h.source_seq]::UBIGINT[] AS source_keys
    FROM h JOIN al_sigma_labels lb ON lb.rule_id = h.rid
    LEFT JOIN al_attack a ON a.technique_id = lb.sub_technique_id
    LEFT JOIN al_attack a2 ON a2.technique_id = lb.technique_id
    LEFT JOIN al_ip_host m ON m.ip = h.src_ip
    LEFT JOIN al_ip_host md ON md.ip = h.dst_ip"""


def _scan_groups(con: duckdb.DuckDBPyConnection, sset: sigma_rules.SigmaSet, bs: int, mc: int,
                 pf: dict[str, int] | None = None
                 ) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]], dict[str, float]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in sset.rules:
        groups.setdefault(r["gate"], []).append(r)
    secs: dict[str, float] = {}
    tuples: dict[str, dict[str, Any]] = {}
    for gate, rules in groups.items():
        name = str(rules[0].get("logsource"))
        while name in secs:
            name += "+"
        tg = time.perf_counter()
        try:
            tuples[name] = _run_group(con, gate, rules, sset.exprs, bs, mc, **(pf or {}))
        except duckdb.Error as exc:   # a bad gate must not stop Stage 2: record it in the stats
            log.error("sigma: group %s (%d rules) failed: %s", name, len(rules), str(exc).splitlines()[0][:300])
            tuples[name] = {"error": 1, "batches_failed": -(-len(rules) // bs), "rules_failed": len(rules),
                            "failed_rule_ids": [str(r["id"]) for r in rules]}
        secs[name] = round(time.perf_counter() - tg, 3)
    return groups, tuples, secs


def prefilter_settings(s: dict[str, Any]) -> dict[str, int]:
    """pipeline.yaml sigma.prefilter_* (sigma_rules.settings output) -> _run_group keyword arguments."""
    def get(key: str, default: int) -> int:
        v = s.get(key)
        return default if v is None else int(v)
    return {"max_terms": get("prefilter_max_terms", PREFILTER_MAX_TERMS),
            "min_rows": get("prefilter_min_rows", PREFILTER_MIN_ROWS),
            "direct_max_leaves": get("prefilter_direct_max_leaves", PREFILTER_DIRECT_MAX_LEAVES)}


def run(con: duckdb.DuckDBPyConnection, cfg: dict[str, Any], th: dict[str, Any],
        work_dir: Path | None = None, live: bool = False, native_cloud_ids: Iterable[str] = ()) -> dict[str, Any]:
    """Append Sigma alerts to al_raw (which must exist). Returns stats for run_metrics (sigma_* keys); writes
    work/sigma_coverage.json when work_dir is given. live: pipeline.yaml sigma.live / sigma.live_min_level apply.
    native_cloud_ids: rule ids of the native cloud alerts already in al_raw (dedupe_against_native)."""
    s = sigma_rules.settings(cfg)
    if not s.get("enabled") or (live and not s.get("live", True)):
        return {"enabled": False, "live": live, "sigma_alerts": 0, "sigma_wall_s": 0.0}
    t0 = time.perf_counter()
    sset = sigma_rules.load(cfg)
    if live:
        lo = sigma_rules.LEVELS.index(str(s.get("live_min_level") or "high"))
        sset = sigma_rules.SigmaSet([r for r in sset.rules if sigma_rules.LEVELS.index(r["level"]) >= lo],
                                    sset.exprs, sset.coverage)
    t_load = time.perf_counter() - t0
    mc = evidence_chars(th)
    cols = ", ".join(f"{c} {RAW_ALERT_COLUMNS.get(c, 'VARCHAR')}" for c in HIT_COLUMNS)
    con.execute(f"CREATE OR REPLACE TEMP TABLE al_sigma_hits ({cols}, raw_line VARCHAR, rule_ids VARCHAR[])")
    _labels_table(con, sset.rules)
    bs = max(1, int(s.get("batch_size") or 250))
    t_scan = time.perf_counter()
    groups, tuples, secs = _scan_groups(con, sset, bs, mc, prefilter_settings(s))
    t_scan = time.perf_counter() - t_scan
    hits = int(con.execute("SELECT count(*) FROM al_sigma_hits").fetchone()[0])
    explode(con)
    con.execute(f"CREATE OR REPLACE TEMP TABLE al_sigma_a AS {alerts_sql(th)}")
    dd: dict[str, int] = {}
    deduped = dedupe_against_native(con, "al_sigma_a", native_cloud_ids, dd)
    capped = cap_alerts(con, int(s.get("max_alerts_per_rule") or 0), "al_sigma_a")
    con.execute("INSERT INTO al_raw BY NAME SELECT * FROM al_sigma_a")
    for t in ("al_sigma_a", "al_sigma_x"):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    per_rule = {str(k): int(v) for k, v in con.execute(
        "SELECT rule_id, count(*) FROM al_raw WHERE starts_with(rule_id, 'sigma_') GROUP BY 1 ORDER BY 2 DESC, 1"
    ).fetchall()}
    stats = _stats(sset, groups, tuples, secs, per_rule, capped, deduped, hits, bs, live,
                   {"wall": time.perf_counter() - t0, "load": t_load, "scan": t_scan})
    stats["sigma_alerts_deduped_cloud"] = int(dd.get("cloud") or 0)
    if work_dir is not None:
        cov = {**sset.coverage, "run": {k: v for k, v in stats.items() if k != "coverage"},
               "alerts_per_rule": per_rule,
               "titles": {r["id"]: r["title"] for r in sset.rules if r["id"] in per_rule}}
        Path(work_dir).mkdir(parents=True, exist_ok=True)
        (Path(work_dir) / "sigma_coverage.json").write_text(json.dumps(cov, indent=1), encoding="utf-8")
    log.info("sigma: %d rules, %d fired, %d alerts (%d capped, %d deduped, %d rules failed), scan %.2f s "
             "(load %.2f s)", len(sset.rules), len(per_rule), stats["sigma_alerts"], sum(capped.values()), deduped,
             stats["sigma_rules_failed"], t_scan, t_load)
    return stats


def _stats(sset: sigma_rules.SigmaSet, groups: dict[str, list[dict[str, Any]]], tuples: dict[str, dict[str, Any]],
           secs: dict[str, float], per_rule: dict[str, int], capped: dict[str, int], deduped: int, hits: int,
           bs: int, live: bool, t: dict[str, float]) -> dict[str, Any]:
    cov = sset.coverage
    skipped = dict(cov.get("skipped_by_reason") or {})
    for k, v in (cov.get("filtered_out") or {}).items():
        key = "disabled" if k == "disabled" else "status_filtered" if k.startswith("status") else "below_min_level"
        skipped[key] = skipped.get(key, 0) + int(v)
    applicable = sum(len(g) for g in groups.values() if any(
        (tuples.get(n) or {}).get("tuples") or (tuples.get(n) or {}).get("gated")
        for n in tuples if n.rstrip("+") == str(g[0].get("logsource"))))
    failed_ids = [i for g in tuples.values() for i in g.get("failed_rule_ids") or []]
    group_tuples = {n: {k: v for k, v in g.items() if k != "failed_rule_ids"} for n, g in tuples.items()}
    return {"enabled": True, "live": live,
            "sigma_rules_total": int(cov.get("parsed") or 0), "sigma_rules_compiled": int(cov.get("compiled") or 0),
            "sigma_rules_running": len(sset.rules), "sigma_rules_skipped_by_reason": skipped,
            "sigma_rules_applicable": applicable, "sigma_rules_fired": len(per_rule),
            "sigma_alerts": sum(per_rule.values()), "sigma_alerts_capped_by_rule": capped,
            "sigma_alerts_deduped": deduped, "sigma_wall_s": round(t["wall"], 3),
            "sigma_batches_failed": sum(int(g.get("batches_failed") or 0) for g in tuples.values()),
            "sigma_rules_failed": len(failed_ids), "sigma_failed_rule_ids": failed_ids[:MAX_FAILED_IDS],
            "sigma_load_s": round(t["load"], 3),
            "sigma_defense_evasion_mapped": cov.get("defense_evasion_mapped") or {},
            "rows_matched": hits, "load_s": round(t["load"], 3), "scan_s": round(t["scan"], 3), "group_s": secs,
            "load_timing": cov.get("load_timing") or {},
            "group_tuples": group_tuples, "batches": sum(-(-len(g) // bs) for g in groups.values()),
            "top_rules": dict(list(per_rule.items())[:25]), "coverage": cov}
