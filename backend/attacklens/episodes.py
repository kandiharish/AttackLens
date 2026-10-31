"""Stage 2.5 — episodes (DEVELOPMENT.md §4, §6.1–6.2, §15.4).

raw_alerts -> 5-minute buckets per (rule_id, subject_host, src_user, target_user, dst_host, bucket, technique_id).
src_host / dst_host are re-resolved with an ASOF join on host_ip_map (the IP's owner at alert time).
rarity(r) = ln(1 + N / max(1, BaseFreq(r))) / ln(1 + N), N = distinct hosts in events.
confidence = min(100, severity * max(rarity, 0.65 if severity >= 80 else 0)); is_seed = confidence >= seed_confidence.
Above episode_cap, only episodes within spill_hops hops (shared non-hub entity, spill_hop_window_ms) of a seed
are kept; the rest go to episodes_spilled.parquet.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import duckdb

from attacklens.context import RunContext
from attacklens.detect_sql import OK, RAW_ALERT_COLUMNS, ensure_events, register_macros, sql_path

log = logging.getLogger(__name__)


def _src(path: Path, empty_cols: dict[str, str]) -> str:
    if path.exists():
        return f"read_parquet({sql_path(path)})"
    return "(SELECT " + ", ".join(f"NULL::{t} AS {c}" for c, t in empty_cols.items()) + " WHERE false)"


def _ip_fb(col: str, fallback: bool) -> str:
    """Entity fallback (thresholds.entity_fallback_ip): an internal IP with no host name stands for its host."""
    return f"CASE WHEN {col} IS NOT NULL AND al_is_internal_ip({col}) THEN {col} END" if fallback else "NULL"


def episodes_sql(work: Path, bucket_ms: int, seed_conf: float, fallback: bool = False) -> str:
    raw = _src(work / "raw_alerts.parquet", RAW_ALERT_COLUMNS)
    hip = _src(work / "host_ip_map.parquet", {"ip": "VARCHAR", "host": "VARCHAR", "first_ms": "BIGINT",
                                                "last_ms": "BIGINT"})
    base = _src(work / "rule_host_baseline.parquet", {"rule_id": "VARCHAR", "base_freq": "DOUBLE"})
    return f"""
    WITH r AS (SELECT * FROM {raw}),
    hip AS (SELECT ip, host, first_ms FROM {hip}),
    r1 AS (SELECT r.* REPLACE (coalesce(ms.host, r.src_host, {_ip_fb('r.src_ip', fallback)}) AS src_host)
           FROM r ASOF LEFT JOIN hip ms ON r.src_ip = ms.ip AND r.ts_ms >= ms.first_ms),
    r2 AS (SELECT r1.* REPLACE (coalesce(md.host, r1.dst_host, {_ip_fb('r1.dst_ip', fallback)}) AS dst_host)
           FROM r1 ASOF LEFT JOIN hip md ON r1.dst_ip = md.ip AND r1.ts_ms >= md.first_ms),
    g AS (
        SELECT rule_id, subject_host, src_user, target_user, dst_host, ts_ms // {bucket_ms} AS bucket, technique_id,
               min(sub_technique_id) AS sub_technique_id, min(technique_name) AS technique_name,
               min(tactic) AS tactic, min(tactic_idx) AS tactic_idx, max(severity) AS severity,
               min(ts_ms) AS ts_ms, max(last_ts_ms) AS last_ts_ms, min(source_seq) AS source_seq,
               al_mode(list(host)) AS host, al_mode(list(src_host)) AS src_host,
               al_mode(list(src_ip)) AS src_ip, al_mode(list(dst_ip)) AS dst_ip,
               sum(raw_alert_count)::BIGINT AS merged_alert_count,
               list_slice(flatten(list(evidence_lines ORDER BY ts_ms, source_seq)), 1, 3) AS evidence_lines,
               list_slice(flatten(list(source_keys ORDER BY ts_ms, source_seq)), 1, 50) AS source_keys
        FROM r2 GROUP BY ALL
    ),
    n AS (SELECT greatest(count(DISTINCT host), 1)::DOUBLE AS n FROM events WHERE {OK} AND host IS NOT NULL),
    s AS (
        SELECT g.*, b.base_freq,
               ln(1 + n.n / greatest(1.0, coalesce(b.base_freq, 0.0))) / ln(1 + n.n) AS rarity
        FROM g LEFT JOIN (SELECT rule_id, base_freq FROM {base}) b USING (rule_id) CROSS JOIN n
    )
    SELECT 'e' || substr(md5(concat_ws('|', rule_id, coalesce(subject_host, ''), coalesce(src_user, ''),
                                       coalesce(target_user, ''), coalesce(dst_host, ''), bucket::VARCHAR,
                                       technique_id)), 1, 10) AS episode_id,
           rule_id, technique_id, sub_technique_id, technique_name, tactic, tactic_idx::INTEGER AS tactic_idx,
           severity::INTEGER AS severity, ts_ms::BIGINT AS ts_ms, last_ts_ms::BIGINT AS last_ts_ms,
           source_seq::UBIGINT AS source_seq, host, subject_host, src_host, dst_host, src_user, target_user,
           src_ip, dst_ip, merged_alert_count AS raw_alert_count, merged_alert_count, evidence_lines,
           source_keys::UBIGINT[] AS source_keys, coalesce(target_user, src_user) AS "user", bucket::BIGINT AS bucket,
           rarity::DOUBLE AS rarity,
           least(100.0, severity * greatest(rarity, CASE WHEN severity >= 80 THEN 0.65 ELSE 0.0 END))::DOUBLE
               AS confidence,
           (least(100.0, severity * greatest(rarity, CASE WHEN severity >= 80 THEN 0.65 ELSE 0.0 END))
               >= {float(seed_conf)}) AS is_seed
    FROM s
    """


def _spill(con: duckdb.DuckDBPyConnection, work: Path, cap: int, hops: int, win_ms: int) -> int:
    """Mark al_episodes.keep; returns the number of spilled episodes."""
    hubs = work / "background_hubs.parquet"
    hub_src = f"(SELECT entity FROM read_parquet({sql_path(hubs)}))" if hubs.exists() else \
        "(SELECT NULL::VARCHAR AS entity WHERE false)"
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE al_ent AS
        SELECT episode_id, ts_ms, entity FROM (
            SELECT episode_id, ts_ms, unnest(list_filter(['host:' || subject_host, 'host:' || dst_host,
                   'host:' || src_host, 'user:' || "user", 'ip:' || src_ip, 'ip:' || dst_ip],
                   lambda x: x IS NOT NULL)) AS entity FROM al_episodes)
        WHERE entity NOT IN (SELECT entity FROM {hub_src} WHERE entity IS NOT NULL)""")
    con.execute("CREATE OR REPLACE TEMP TABLE al_keep AS SELECT episode_id FROM al_episodes WHERE is_seed")
    con.execute("CREATE OR REPLACE TEMP TABLE al_front AS SELECT episode_id FROM al_keep")
    for _ in range(hops):
        con.execute(f"""
            CREATE OR REPLACE TEMP TABLE al_next AS
            SELECT DISTINCT b.episode_id FROM al_ent a
            JOIN al_ent b ON a.entity = b.entity AND abs(a.ts_ms - b.ts_ms) <= {win_ms}
            WHERE a.episode_id IN (SELECT episode_id FROM al_front)
              AND b.episode_id NOT IN (SELECT episode_id FROM al_keep)""")
        con.execute("INSERT INTO al_keep SELECT episode_id FROM al_next")
        con.execute("CREATE OR REPLACE TEMP TABLE al_front AS SELECT episode_id FROM al_next")
    kept = con.execute("SELECT count(*) FROM al_keep").fetchone()[0]
    if kept > cap:
        log.warning("episodes: %d seed-reachable episodes exceed cap %d; keeping seeds + top confidence", kept, cap)
        con.execute(f"""
            CREATE OR REPLACE TEMP TABLE al_keep AS
            SELECT episode_id FROM al_episodes WHERE episode_id IN (SELECT episode_id FROM al_keep)
            ORDER BY is_seed DESC, confidence DESC, ts_ms, episode_id LIMIT {max(cap, 0)}""")
        seeds_lost = con.execute("SELECT count(*) FROM al_episodes WHERE is_seed AND episode_id NOT IN "
                                 "(SELECT episode_id FROM al_keep)").fetchone()[0]
        if seeds_lost:
            log.warning("episodes: %d seed episodes spilled (more seeds than the cap)", seeds_lost)
    con.execute("UPDATE al_episodes SET keep = episode_id IN (SELECT episode_id FROM al_keep)")
    return int(con.execute("SELECT count(*) FROM al_episodes WHERE NOT keep").fetchone()[0])


def run(ctx: RunContext) -> dict[str, Any]:
    con = ctx.con
    ensure_events(con, ctx.events_glob)
    register_macros(con)
    th = (ctx.cfg.get("rules") or {}).get("thresholds") or {}
    work = ctx.work_dir
    cap = int(th.get("episode_cap", 25000))
    con.execute("CREATE OR REPLACE TEMP TABLE al_episodes AS SELECT *, TRUE AS keep FROM ("
                + episodes_sql(work, int(th.get("episode_bucket_ms", 300000)), float(th.get("seed_confidence", 65)),
                               bool(th.get("entity_fallback_ip", False)))
                + ")")
    total = int(con.execute("SELECT count(*) FROM al_episodes").fetchone()[0])
    spilled = 0
    if total > cap:
        spilled = _spill(con, work, cap, int(th.get("spill_hops", 2)), int(th.get("spill_hop_window_ms", 86400000)))
    con.execute(f"COPY (SELECT * EXCLUDE (keep) FROM al_episodes WHERE keep) TO "
                f"{sql_path(work / 'episodes.parquet')} (FORMAT PARQUET)")
    con.execute(f"COPY (SELECT * EXCLUDE (keep) FROM al_episodes WHERE NOT keep) TO "
                f"{sql_path(work / 'episodes_spilled.parquet')} (FORMAT PARQUET)")
    seeds = int(con.execute("SELECT count(*) FROM al_episodes WHERE keep AND is_seed").fetchone()[0])
    log.info("episodes: %d total, %d kept, %d spilled, %d seeds", total, total - spilled, spilled, seeds)
    return {"episodes": total - spilled, "spilled": spilled, "episodes_total": total, "seeds": seeds}
