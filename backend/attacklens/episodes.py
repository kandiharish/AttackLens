"""Stage 2.5 — episodes (DEVELOPMENT.md §4, §6.1–6.2, §15.4).

raw_alerts -> 5-minute buckets per (rule_id, subject_host, src_user, target_user, dst_host, bucket, technique_id).
src_host / dst_host are re-resolved with an ASOF join on host_ip_map (the IP's owner at alert time).
rarity(r) = ln(1 + N / max(1, BaseFreq(r))) / ln(1 + N), N = distinct hosts in events.
confidence = min(100, severity * max(rarity, 0.65 if severity >= 80 else 0)); is_seed = confidence >= seed_confidence.
Above episode_cap, exactly episode_cap episodes are kept in a deterministic rank order: seeds, then episodes within
spill_hops hops (shared non-hub entity, spill_hop_window_ms) of a seed, then (linking.yaml spill.fill_to_cap) the
best remaining ones (confidence band, rule/technique round-robin, confidence). The rest go to
episodes_spilled.parquet and are counted.
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


def _entities_sql(fallback: bool, fb_sources: list[str]) -> str:
    """Host entities for N (§6.1): reporting hosts, except that for entity-fallback sources (firewalls) the
    internal source IPs are the hosts (the device name is one box, not N endpoints)."""
    if not fallback:
        return f"SELECT host AS ent FROM events WHERE {OK} AND host IS NOT NULL"
    srcs = ", ".join("'" + x.replace("'", "''") + "'" for x in fb_sources) or "''"
    return (f"SELECT host AS ent FROM events WHERE {OK} AND host IS NOT NULL AND source_type NOT IN ({srcs}) "
            f"UNION ALL SELECT src_ip FROM events WHERE {OK} AND source_type IN ({srcs}) AND src_ip IS NOT NULL "
            f"AND al_is_internal_ip(src_ip)")


def episodes_sql(work: Path, bucket_ms: int, seed_conf: float, fallback: bool = False,
                 fb_sources: list[str] | None = None) -> str:
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
    n AS (SELECT greatest(count(DISTINCT ent), 1)::DOUBLE AS n FROM ({_entities_sql(fallback, fb_sources or [])})),
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


SPILL_DEFAULTS: dict[str, Any] = {
    # true: after the seed neighbourhood, fill up to episode_cap with the best remaining episodes (ranked below).
    # false: literal §4 (keep only the seed neighbourhood).
    "fill_to_cap": True,
    # Ranking inside a hop tier: confidence band (desc), then round-robin over diversity_key, then exact values.
    "confidence_band": 10.0,
    "diversity_key": ["rule_id", "technique_id"],
}


def spill_quota(cfg: dict[str, Any]) -> int:
    """linking.yaml spill.min_per_rule: inside the fill tier, the episodes among each rule's best min_per_rule
    non-seed episodes (by confidence) rank before every other fill episode, so a rare behavioural rule (n30: 2
    port_scan episodes at conf 30) is not crowded out by thousands of higher-band episodes of one noisy rule. A
    no-op when every rule is under the quota. Seeds and the seed neighbourhood keep their tiers. 0 = off."""
    return max(int(((cfg.get("linking") or {}).get("spill") or {}).get("min_per_rule") or 0), 0)


def spill_params(cfg: dict[str, Any]) -> dict[str, Any]:
    """linking.yaml `spill` section over SPILL_DEFAULTS (rules.yaml thresholds keep cap / hops / window)."""
    user = (cfg.get("linking") or {}).get("spill") or {}
    out = {**SPILL_DEFAULTS, **{k: v for k, v in user.items() if k != "min_per_rule"}}  # quota: spill_quota()
    keys = [str(k) for k in out.get("diversity_key") or [] if str(k) in {"rule_id", "technique_id", "tactic",
                                                                          "subject_host"}]
    out["diversity_key"] = keys
    out["confidence_band"] = max(float(out.get("confidence_band") or 0.0), 0.0)
    return out


def _rank_sql(cap: int, sp: dict[str, Any]) -> str:
    """Deterministic keep order, best first (§4 Stage 2.5 spill). Tiers: seeds (hop 0), the seed neighbourhood
    (hop 1..spill_hops), then (fill_to_cap) everything else: first (min_per_rule > 0) the fill episodes within
    their rule's best min_per_rule non-seed episodes, then the rest. Inside a tier: confidence band desc, then the episode's rank within its
    diversity group (rule_id, technique_id) so one noisy rule cannot take every slot, then confidence, severity,
    merged_alert_count desc, ts_ms, episode_id. Output hop: 0 seed, > 0 neighbourhood, -1 fill (the episode's
    own tier, also when it was kept through the quota); in_quota marks the quota episodes."""
    band = float(sp["confidence_band"])
    band_sql = f"floor(c0 / {band})" if band > 0 else "c0"
    part = "".join(f", {k}" for k in sp["diversity_key"])
    quota = int(sp.get("min_per_rule") or 0)
    where = "" if sp["fill_to_cap"] else "WHERE hop0 IS NOT NULL"
    exact = "c0 DESC, sev DESC, mac DESC, ts_ms, episode_id"
    return f"""
        WITH b0 AS (
            SELECT e.episode_id, e.ts_ms, e.rule_id, e.technique_id, e.tactic, e.subject_host, k.hop AS hop0,
                   coalesce(e.confidence, 0.0) AS c0,
                   coalesce(e.severity, 0) AS sev, coalesce(e.merged_alert_count, 0) AS mac
            FROM al_episodes e
            LEFT JOIN (SELECT episode_id, min(hop) AS hop FROM al_keep GROUP BY ALL) k USING (episode_id)),
        q AS (SELECT *, CASE WHEN hop0 = 0 THEN FALSE ELSE row_number() OVER (PARTITION BY rule_id, coalesce(hop0, -1) = 0
                     ORDER BY {exact}) <= {quota} END AS in_quota FROM b0),
        b AS (SELECT *, CASE WHEN hop0 IS NOT NULL THEN hop0::BIGINT WHEN in_quota THEN 2147483646::BIGINT
                             ELSE 2147483647::BIGINT END AS tier
              FROM q {where}),
        r AS (SELECT *, {band_sql} AS band,
                     row_number() OVER (PARTITION BY tier, {band_sql}{part} ORDER BY {exact}) AS div_rank FROM b)
        SELECT episode_id, coalesce(hop0, -1) AS hop, in_quota FROM r
        ORDER BY tier, band DESC, div_rank, {exact}
        LIMIT {max(cap, 0)}"""


def _spill(con: duckdb.DuckDBPyConnection, work: Path, cap: int, hops: int, win_ms: int,
           sp: dict[str, Any] | None = None) -> dict[str, Any]:
    """Mark al_episodes.keep (exactly min(cap, total) kept when fill_to_cap). Returns kept counts per tier
    and the number of spilled episodes. Runs only on the episode table (already aggregated), never raw events."""
    sp = sp or dict(SPILL_DEFAULTS)
    hubs = work / "background_hubs.parquet"
    hub_src = f"(SELECT entity FROM read_parquet({sql_path(hubs)}))" if hubs.exists() else         "(SELECT NULL::VARCHAR AS entity WHERE false)"
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE al_ent AS
        SELECT episode_id, ts_ms, entity FROM (
            SELECT episode_id, ts_ms, unnest(list_filter(['host:' || subject_host, 'host:' || dst_host,
                   'host:' || src_host, 'user:' || "user", 'ip:' || src_ip, 'ip:' || dst_ip],
                   lambda x: x IS NOT NULL)) AS entity FROM al_episodes)
        WHERE entity NOT IN (SELECT entity FROM {hub_src} WHERE entity IS NOT NULL)""")
    con.execute("CREATE OR REPLACE TEMP TABLE al_keep AS SELECT episode_id, 0 AS hop FROM al_episodes WHERE is_seed")
    con.execute("CREATE OR REPLACE TEMP TABLE al_front AS SELECT episode_id FROM al_keep")
    for hop in range(1, hops + 1):
        con.execute(f"""
            CREATE OR REPLACE TEMP TABLE al_next AS
            SELECT DISTINCT b.episode_id FROM al_ent a
            JOIN al_ent b ON a.entity = b.entity AND abs(a.ts_ms - b.ts_ms) <= {win_ms}
            WHERE a.episode_id IN (SELECT episode_id FROM al_front)
              AND b.episode_id NOT IN (SELECT episode_id FROM al_keep)""")
        con.execute(f"INSERT INTO al_keep SELECT episode_id, {hop} FROM al_next")
        con.execute("CREATE OR REPLACE TEMP TABLE al_front AS SELECT episode_id FROM al_next")
    near = int(con.execute("SELECT count(*) FROM al_keep").fetchone()[0])  # seeds (hop 0) included
    if near > cap:
        log.warning("episodes: %d seed-neighbourhood episodes exceed cap %d; keeping the best-ranked", near, cap)
    con.execute(f"CREATE OR REPLACE TEMP TABLE al_sel AS {_rank_sql(cap, sp)}")
    seeds_lost = con.execute("SELECT count(*) FROM al_episodes WHERE is_seed AND episode_id NOT IN "
                             "(SELECT episode_id FROM al_sel)").fetchone()[0]
    if seeds_lost:
        log.warning("episodes: %d seed episodes spilled (more seeds than the cap)", seeds_lost)
    con.execute("UPDATE al_episodes SET keep = episode_id IN (SELECT episode_id FROM al_sel)")
    tiers = dict(con.execute("SELECT CASE WHEN hop = 0 THEN 'seed' WHEN hop > 0 THEN 'seed_neighbourhood' "
                             "ELSE 'fill' END, count(*) FROM al_sel GROUP BY 1").fetchall())
    out: dict[str, Any] = {f"kept_{k}": int(tiers.get(k, 0)) for k in ("seed", "seed_neighbourhood", "fill")}
    out["seed_neighbourhood_total"] = near  # seeds (hop 0) INCLUDED; spill_detail splits it
    n_seeds = int(con.execute("SELECT count(*) FROM al_keep WHERE hop = 0").fetchone()[0])
    quota = con.execute("SELECT count(*) FROM al_sel WHERE in_quota AND hop = -1").fetchone()[0]
    out["detail"] = {"seeds_total": n_seeds, "neighbourhood_only_total": near - n_seeds,
                     "kept_fill_rule_quota": int(quota), "min_per_rule": int(sp.get("min_per_rule") or 0)}
    out["spilled"] = int(con.execute("SELECT count(*) FROM al_episodes WHERE NOT keep").fetchone()[0])
    for t in ("al_ent", "al_keep", "al_front", "al_next", "al_sel"):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    return out


def run(ctx: RunContext) -> dict[str, Any]:
    con = ctx.con
    ensure_events(con, ctx.events_glob)
    register_macros(con)
    th = (ctx.cfg.get("rules") or {}).get("thresholds") or {}
    work = ctx.work_dir
    cap = int(th.get("episode_cap", 25000))
    con.execute("CREATE OR REPLACE TEMP TABLE al_episodes AS SELECT *, TRUE AS keep FROM ("
                + episodes_sql(work, int(th.get("episode_bucket_ms", 300000)), float(th.get("seed_confidence", 65)),
                               bool(th.get("entity_fallback_ip", False)),
                               [str(x) for x in th.get("entity_fallback_source_types") or []])
                + ")")
    total = int(con.execute("SELECT count(*) FROM al_episodes").fetchone()[0])
    spilled, tiers, detail = 0, {}, {}
    if total > cap:
        tiers = _spill(con, work, cap, int(th.get("spill_hops", 2)), int(th.get("spill_hop_window_ms", 86400000)),
                       {**spill_params(ctx.cfg), "min_per_rule": spill_quota(ctx.cfg)})
        spilled = tiers.pop("spilled")
        detail = tiers.pop("detail")
    con.execute(f"COPY (SELECT * EXCLUDE (keep) FROM al_episodes WHERE keep) TO "
                f"{sql_path(work / 'episodes.parquet')} (FORMAT PARQUET)")
    con.execute(f"COPY (SELECT * EXCLUDE (keep) FROM al_episodes WHERE NOT keep) TO "
                f"{sql_path(work / 'episodes_spilled.parquet')} (FORMAT PARQUET)")
    seeds = int(con.execute("SELECT count(*) FROM al_episodes WHERE keep AND is_seed").fetchone()[0])
    log.info("episodes: %d total, %d kept, %d spilled, %d seeds", total, total - spilled, spilled, seeds)
    if tiers:
        log.info("episodes: spill kept by tier %s (cap %d)", tiers, cap)
    return {"episodes": total - spilled, "spilled": spilled, "episodes_total": total, "seeds": seeds,
            "episode_cap": cap, "spill_by_tier": tiers, "spill_detail": detail}
