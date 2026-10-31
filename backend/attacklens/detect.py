"""Stage 2 — detect (DEVELOPMENT.md §4, §5). Rules from config/rules.yaml -> work/raw_alerts.parquet and
work/rule_host_baseline.parquet.

- match rules: all `where` predicates are evaluated in ONE scan of `events` into a small temp table of hits;
  each rule then becomes one SELECT over the hits.
- template rules: one SQL per rule from detect_templates.TEMPLATES.
"""

from __future__ import annotations

import functools
import json
import logging
import re
import time
from typing import Any

import duckdb

from attacklens.context import RunContext
from attacklens.detect_sql import (OK, RAW_ALERT_COLUMNS, create_empty_events, ensure_events, finish, prepare, q,
                                   sql_list, sql_path, subject_host_expr)
from attacklens.detect_templates import TEMPLATES
from attacklens.schemas import TACTIC_IDX

log = logging.getLogger(__name__)

_PLACEHOLDER = re.compile(r"\{ioc\.([a-z_]+)\}")


class RuleError(ValueError):
    """A rule in config/rules.yaml is invalid; the message starts with the rule id."""


def rules_and_thresholds(cfg: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rc = cfg.get("rules") or {}
    return list(rc.get("rules") or []), dict(rc.get("thresholds") or {})


def expand_where(rule: dict[str, Any], ioc: dict[str, Any]) -> str:
    def sub(m: re.Match[str]) -> str:
        key = m.group(1)
        if key not in ioc:
            raise RuleError(f"{rule.get('id')}: unknown placeholder {{ioc.{key}}}")
        return sql_list([str(v).lower() for v in ioc[key] or []])
    return _PLACEHOLDER.sub(sub, str(rule["where"]))


def _check_labels(rule: dict[str, Any], attack: dict[str, Any]) -> None:
    techniques = attack.get("techniques") or {}
    rid = rule.get("id")
    for spec in (rule, rule.get("secondary"), *(rule.get("signatures") or [])):
        if not spec:
            continue
        for key in ("technique", "sub_technique"):
            tid = spec.get(key)
            if key == "technique" and not tid:
                raise RuleError(f"{rid}: missing technique")
            if tid and tid not in techniques:
                raise RuleError(f"{rid}: technique {tid} not in attack_v20.json")
        if spec.get("tactic") not in TACTIC_IDX:
            raise RuleError(f"{rid}: tactic {spec.get('tactic')!r} is not a v20 tactic")


def rule_sql(con: duckdb.DuckDBPyConnection, rule: dict[str, Any], th: dict[str, Any]) -> str:
    """SQL producing the raw_alerts columns for one rule (match rules read the al_match_hits temp table)."""
    if rule.get("kind") == "template":
        fn = TEMPLATES.get(str(rule.get("template")))
        if fn is None:
            raise RuleError(f"{rule.get('id')}: unknown template {rule.get('template')!r}")
        return fn(con, rule, {**th, **(rule.get("params") or {})})
    if rule.get("kind") == "match":
        mc = int(th.get("evidence_max_chars", 300))
        core = f"""
        SELECT 'primary' AS label, NULL AS sub_technique_id, h.ts_ms, h.ts_ms AS last_ts_ms, h.source_seq, h.host,
               {subject_host_expr('h', 'm', th)} AS subject_host, h.src_user, h.target_user, h.src_ip, h.dst_ip,
               1 AS raw_alert_count, [left(h.raw_line, {mc})] AS evidence_lines, [h.source_seq] AS source_keys
        FROM al_match_hits h LEFT JOIN al_ip_host m ON m.ip = h.src_ip
        WHERE list_contains(h.rule_ids, {sql_list([rule['id']])[1:-1]})"""
        return finish(rule, core)
    raise RuleError(f"{rule.get('id')}: unsupported kind {rule.get('kind')!r}")


def build_match_hits(con: duckdb.DuckDBPyConnection, rules: list[dict[str, Any]], ioc: dict[str, Any],
                     th: dict[str, Any]) -> None:
    """One scan of events: rows matching any match rule, with the list of rule ids they match."""
    mrules = [r for r in rules if r.get("kind") == "match"]
    mc = int(th.get("evidence_max_chars", 300))
    if not mrules:
        cond, ids = "FALSE", "[]::VARCHAR[]"
    else:
        preds = [(r["id"], expand_where(r, ioc)) for r in mrules]
        cond = " OR ".join(f"({p})" for _, p in preds)
        ids = "list_filter([" + ", ".join(f"CASE WHEN ({p}) THEN {sql_list([i])[1:-1]} END" for i, p in preds) + \
              "], lambda x: x IS NOT NULL)"
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE al_match_hits AS
        SELECT ts_ms, source_seq, source_type, action, host, src_user, target_user, src_ip, dst_ip, src_zone,
               dst_zone,
               left(raw_line, {mc}) AS raw_line, {ids} AS rule_ids
        FROM events WHERE {OK} AND ts_ms IS NOT NULL AND ({cond})""")


def validate(cfg: dict[str, Any]) -> None:
    """Rule ids unique, labels exist in ATT&CK v20 data, templates exist, every rule's SQL compiles (EXPLAIN
    against an empty events view). Raises RuleError naming the rule. Cached per content of rules/ioc/attack, so
    repeated detect.run calls (live mode) pay for it once."""
    key = json.dumps({k: cfg.get(k) for k in ("rules", "ioc", "attack")}, sort_keys=True, default=str)
    _validate_cached(key)


@functools.lru_cache(maxsize=8)
def _validate_cached(cfg_json: str) -> None:
    """Pure function of the config content (exceptions are not cached, so a bad config fails every time)."""
    _validate_uncached(json.loads(cfg_json))


def _validate_uncached(cfg: dict[str, Any]) -> None:
    rules, th = rules_and_thresholds(cfg)
    attack, ioc = cfg.get("attack") or {}, cfg.get("ioc") or {}
    seen: set[str] = set()
    con = duckdb.connect()
    try:
        con.execute("SET TimeZone='UTC'")
        con.execute("SET threads=1")
        con.execute("SET memory_limit='256MB'")
        create_empty_events(con)
        prepare(con, cfg)
        for r in rules:
            rid = str(r.get("id"))
            if rid in seen:
                raise RuleError(f"{rid}: duplicate rule id")
            seen.add(rid)
            _check_labels(r, attack)
            if r.get("kind") == "match":
                try:
                    con.execute(f"EXPLAIN SELECT * FROM events WHERE {expand_where(r, ioc)}")
                except duckdb.Error as exc:
                    raise RuleError(f"{rid}: where does not compile: {exc}") from exc
        build_match_hits(con, rules, ioc, th)
        for r in rules:
            try:
                con.execute(f"EXPLAIN {rule_sql(con, r, th)}")
            except duckdb.Error as exc:
                raise RuleError(f"{r.get('id')}: SQL does not compile: {exc}") from exc
    finally:
        con.close()


def baseline_sql(max_other_rules: int = 0) -> str:
    """rule_host_baseline: median over event days (zero-padded) of hosts the rule fired on that day where the
    host had at most `max_other_rules` other rules' detections that day (0 = the §4 definition: no other)."""
    return f"""
    WITH a AS (SELECT DISTINCT rule_id, coalesce(subject_host, host) AS h, ts_ms // 86400000 AS d
               FROM al_raw WHERE coalesce(subject_host, host) IS NOT NULL),
    hr AS (SELECT h, d, count(DISTINCT rule_id) AS nr FROM a GROUP BY ALL),
    solo AS (SELECT a.rule_id, a.d, count(*)::DOUBLE AS n FROM a JOIN hr USING (h, d)
             WHERE hr.nr <= 1 + {int(max_other_rules)} GROUP BY ALL),
    nd AS (SELECT greatest(count(DISTINCT event_day), 1) AS n FROM events WHERE {OK}),
    rs AS (SELECT DISTINCT rule_id FROM al_raw)
    SELECT rs.rule_id,
           coalesce(list_aggregate(list_concat(list(s.n) FILTER (WHERE s.n IS NOT NULL),
                                               list_resize([]::DOUBLE[], greatest(any_value(nd.n) - count(s.n), 0),
                                                           0.0)), 'median'), 0.0)::DOUBLE AS base_freq
    FROM rs LEFT JOIN solo s USING (rule_id) CROSS JOIN nd
    GROUP BY rs.rule_id
    """


def relabel_without_context(con: duckdb.DuckDBPyConnection, rule: dict[str, Any],
                            window_ms: int) -> int:
    """Context-specific labelling (§5.3) for rules with `relabel_without_context: true`: a primary alert whose
    account shows no earlier alert on the source host (src_host) within window_ms had no foothold to move from,
    so it is relabelled with the rule's secondary label (new_admin_logon: T1021 -> T1078 Initial Access)."""
    sec = rule.get("secondary")
    if not sec or not rule.get("relabel_without_context"):
        return 0
    tactic = sec["tactic"]
    tech = sec.get("sub_technique") or sec["technique"]
    pred = f"""a.rule_id = {q(rule['id'])} AND a.technique_id = {q(rule['technique'])}
        AND NOT EXISTS (SELECT 1 FROM al_raw b
            WHERE coalesce(b.target_user, b.src_user) = coalesce(a.target_user, a.src_user)
              AND coalesce(b.subject_host, b.host) = a.src_host
              AND b.ts_ms < a.ts_ms AND b.ts_ms >= a.ts_ms - {int(window_ms)})"""
    n = con.execute(f"SELECT count(*) FROM al_raw a WHERE {pred}").fetchone()[0]
    if n:
        con.execute(f"""UPDATE al_raw AS a SET technique_id = {q(sec['technique'])},
            sub_technique_id = {q(sec.get('sub_technique'))}::VARCHAR,
            technique_name = (SELECT name FROM al_attack WHERE technique_id = {q(tech)}),
            tactic = {q(tactic)}, tactic_idx = {TACTIC_IDX[tactic]}, severity = {int(sec.get('severity', 50))}
            WHERE {pred}""")
    return int(n)


def run(ctx: RunContext) -> dict[str, Any]:
    con, cfg = ctx.con, ctx.cfg
    t_val = time.perf_counter()
    validate(cfg)
    t_val = time.perf_counter() - t_val
    ensure_events(con, ctx.events_glob)
    prepare(con, cfg, ctx.work_dir)
    rules, th = rules_and_thresholds(cfg)
    cols = ", ".join(f"{c} {t}" for c, t in RAW_ALERT_COLUMNS.items())
    con.execute(f"CREATE OR REPLACE TEMP TABLE al_raw ({cols})")
    t_scan = time.perf_counter()
    build_match_hits(con, rules, cfg.get("ioc") or {}, th)
    per_rule: dict[str, int] = {}
    secs: dict[str, float] = {"validate": round(t_val, 3), "match_scan": round(time.perf_counter() - t_scan, 3)}
    for r in rules:
        rid = str(r["id"])
        t0 = time.perf_counter()
        try:
            con.execute(f"INSERT INTO al_raw BY NAME {rule_sql(con, r, th)}")
        except duckdb.Error as exc:
            raise RuleError(f"{rid}: execution failed: {exc}") from exc
        secs[rid] = round(time.perf_counter() - t0, 3)
    ctx_ms = int(th.get("lateral_context_window_ms", 86400000))
    relabelled = {str(r["id"]): relabel_without_context(con, r, ctx_ms)
                  for r in rules if r.get("relabel_without_context")}
    for rid, n in con.execute("SELECT rule_id, count(*) FROM al_raw GROUP BY rule_id").fetchall():
        per_rule[str(rid)] = int(n)
    for r in rules:
        per_rule.setdefault(str(r["id"]), 0)
    work = ctx.work_dir
    con.execute(f"COPY (SELECT {', '.join(RAW_ALERT_COLUMNS)} FROM al_raw) TO "
                f"{sql_path(work / 'raw_alerts.parquet')} (FORMAT PARQUET)")
    base_sql = baseline_sql(int(th.get("baseline_max_other_rules", 0)))
    con.execute(f"COPY ({base_sql}) TO {sql_path(work / 'rule_host_baseline.parquet')} (FORMAT PARQUET)")
    total = sum(per_rule.values())
    hits = con.execute("SELECT count(*) FROM al_match_hits").fetchone()[0]
    log.info("detect: %d raw alerts (%d match hits); per rule %s; relabelled %s",
             total, hits, per_rule, relabelled)
    log.debug("detect: seconds per rule %s", secs)
    return {"alerts_per_rule": per_rule, "raw_alerts": total, "match_hits": int(hits), "relabelled": relabelled,
            "rule_seconds": secs}
