"""Stage 3: link episodes with four keyed DuckDB equality joins (R1-R4) -> work/edges.parquet (DEVELOPMENT.md §4)."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import duckdb

from attacklens.context import RunContext

log = logging.getLogger(__name__)

# Episode columns (DEVELOPMENT.md §15.4) used downstream, with the type to use when a column is absent.
EPISODE_COLUMNS: dict[str, str] = {
    "episode_id": "VARCHAR", "rule_id": "VARCHAR", "technique_id": "VARCHAR", "sub_technique_id": "VARCHAR",
    "technique_name": "VARCHAR", "tactic": "VARCHAR", "tactic_idx": "INTEGER", "severity": "INTEGER",
    "ts_ms": "BIGINT", "last_ts_ms": "BIGINT", "source_seq": "UBIGINT", "host": "VARCHAR",
    "subject_host": "VARCHAR", "src_host": "VARCHAR", "dst_host": "VARCHAR", "src_user": "VARCHAR",
    "target_user": "VARCHAR", "src_ip": "VARCHAR", "dst_ip": "VARCHAR", "merged_alert_count": "BIGINT",
    "raw_alert_count": "BIGINT", "user": "VARCHAR", "rarity": "DOUBLE", "confidence": "DOUBLE",
    "is_seed": "BOOLEAN", "evidence_lines": "VARCHAR[]",
}

DEFAULT_LINK: dict[str, Any] = {
    "rules": {"R1": {"tau_ms": 86_400_000, "mult": 1.5}, "R2": {"tau_ms": 7_200_000, "mult": 1.0},
              "R3": {"tau_ms": 259_200_000, "mult": 1.3}, "R4": {"tau_ms": 86_400_000, "mult": 1.2}},
    "max_preds_per_rule": 5, "default_rarity": 1.0, "r2_hub_keys": ["host", "user"], "r3_match_target_user": True,
    "r3_source_tactics": ["Credential Access", "Persistence", "Privilege Escalation", "Initial Access"],
    "r3_min_source_confidence": 60.0,
}


def link_params(cfg: dict[str, Any]) -> dict[str, Any]:
    user = (cfg.get("linking") or {}).get("link") or {}
    out = {**DEFAULT_LINK, **{k: v for k, v in user.items() if k != "rules"}}
    out["rules"] = {r: {**DEFAULT_LINK["rules"][r], **((user.get("rules") or {}).get(r) or {})}
                    for r in DEFAULT_LINK["rules"]}
    return out


def sql_path(p: Path) -> str:
    return p.as_posix().replace("'", "''")


def _columns(con: duckdb.DuckDBPyConnection, src: str) -> set[str]:
    return {r[0] for r in con.execute(f"DESCRIBE SELECT * FROM {src}").fetchall()}


def episode_select(con: duckdb.DuckDBPyConnection, path: Path) -> str:
    """SELECT over episodes.parquet with every EPISODE_COLUMNS column present (absent -> typed NULL)."""
    src = f"read_parquet('{sql_path(path)}')"
    have = _columns(con, src)
    parts = []
    for col, typ in EPISODE_COLUMNS.items():
        if col == "merged_alert_count" and col not in have and "raw_alert_count" in have:
            parts.append('CAST("raw_alert_count" AS BIGINT) AS merged_alert_count')
        elif col == "user" and col not in have:
            parts.append('coalesce("target_user", "src_user") AS "user"' if {"target_user", "src_user"} <= have
                         else 'NULL::VARCHAR AS "user"')
        elif col == "subject_host" and col not in have and "host" in have:
            parts.append('"host" AS subject_host')
        elif col in have:
            parts.append(f'CAST("{col}" AS {typ}) AS "{col}"')
        else:
            parts.append(f'NULL::{typ} AS "{col}"')
    return f"SELECT {', '.join(parts)} FROM {src}"


def _hub_table(con: duckdb.DuckDBPyConnection, path: Path) -> None:
    con.execute("CREATE OR REPLACE TEMP TABLE _hubs (entity VARCHAR)")
    if path.exists() and "entity" in _columns(con, f"read_parquet('{sql_path(path)}')"):
        con.execute(f"INSERT INTO _hubs SELECT DISTINCT lower(entity) FROM read_parquet('{sql_path(path)}') "
                    "WHERE entity IS NOT NULL")


def _prepare(con: duckdb.DuckDBPyConnection, ep_path: Path, hubs_path: Path, default_rarity: float) -> None:
    _hub_table(con, hubs_path)
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE _lep AS
        WITH e AS ({episode_select(con, ep_path)})
        SELECT episode_id AS id, ts_ms, coalesce(source_seq, 0::UBIGINT) AS seq, tactic,
               lower(NULLIF(subject_host, '')) AS sh, lower(NULLIF(src_host, '')) AS srch,
               lower(NULLIF(dst_host, '')) AS dsth, lower(NULLIF(src_user, '')) AS su,
               lower(NULLIF(target_user, '')) AS tu,
               lower(NULLIF(coalesce("user", target_user, src_user), '')) AS usr,
               dst_ip, technique_id, coalesce(confidence, 0) AS conf,
               coalesce(rarity, {float(default_rarity)}) AS rar
        FROM e WHERE episode_id IS NOT NULL AND ts_ms IS NOT NULL""")
    con.execute("""
        CREATE OR REPLACE TEMP TABLE _lep_h AS
        SELECT e.*, ('host:' || e.sh) IN (SELECT entity FROM _hubs) AS sh_hub,
               ('user:' || e.usr) IN (SELECT entity FROM _hubs) AS usr_hub,
               ('user:' || e.tu) IN (SELECT entity FROM _hubs) AS tu_hub,
               ('user:' || e.su) IN (SELECT entity FROM _hubs) AS su_hub
        FROM _lep e""")


def _dt_text(dt: str) -> str:
    """SQL expression rendering milliseconds as 45s / 7m19s / 2h05m / 1d03h."""
    s = f"({dt} // 1000)"
    return (f"CASE WHEN {s} < 60 THEN {s}::VARCHAR || 's' "
            f"WHEN {s} < 3600 THEN ({s} // 60)::VARCHAR || 'm' || lpad(({s} % 60)::VARCHAR, 2, '0') || 's' "
            f"WHEN {s} < 86400 THEN ({s} // 3600)::VARCHAR || 'h' || lpad((({s} % 3600) // 60)::VARCHAR, 2, '0') "
            f"|| 'm' ELSE ({s} // 86400)::VARCHAR || 'd' || lpad((({s} % 86400) // 3600)::VARCHAR, 2, '0') || 'h' END")


def _order(tau: int) -> str:
    """i precedes j: 0 <= t_j - t_i <= tau, tie-break (ts_ms, source_seq, episode_id)."""
    return (f"j.ts_ms - i.ts_ms BETWEEN 0 AND {int(tau)} AND (i.ts_ms < j.ts_ms OR (i.ts_ms = j.ts_ms AND "
            "(i.seq < j.seq OR (i.seq = j.seq AND i.id < j.id))))")


def _nearest(i_key: str, i_filter: str, j_key: str, j_filter: str, k: int) -> str:
    """Pairs (i, j) where i is one of the k nearest eligible predecessors of j with i_key = j_key.

    For a fixed (j, rule) the weight M_R * rarity_j * exp(-dt / tau_R) falls as dt grows, so the top-k predecessors
    by weight are exactly the k nearest in (ts_ms, source_seq, episode_id) order. Ranking eligible i rows per key and
    joining on (key, rank) keeps this an equality join of size <= n * (k + 1): no quadratic blow-up on hub keys.
    """
    return f"""
        WITH s AS (SELECT id, ts_ms, seq, {i_key} AS k, 1 AS is_i FROM _lep_h i WHERE ({i_key}) IS NOT NULL
                     AND {i_filter}
                   UNION ALL
                   SELECT id, ts_ms, seq, {j_key} AS k, 0 AS is_i FROM _lep_h j WHERE ({j_key}) IS NOT NULL
                     AND {j_filter}),
        r AS (SELECT id, k, is_i, CAST(sum(is_i) OVER (PARTITION BY k ORDER BY ts_ms, seq, id, is_i DESC
                     ROWS UNBOUNDED PRECEDING) AS BIGINT) AS cnt FROM s),
        ii AS (SELECT id, k, cnt FROM r WHERE is_i = 1),
        jj AS (SELECT r.id, r.k, r.cnt - o.off AS want FROM r CROSS JOIN range(0, {k + 1}) o(off) WHERE r.is_i = 0)
        SELECT ii.id AS i, jj.id AS j FROM jj JOIN ii ON ii.k = jj.k AND ii.cnt = jj.want WHERE ii.id <> jj.id"""


def rule_variants(p: dict[str, Any]) -> list[tuple[str, str, str, str, str, str]]:
    """(rule, i_key, i_filter, j_key, j_filter, why_sql). Every filter is one-sided, so ranking per key is exact."""
    dt = "(j.ts_ms - i.ts_ms)"
    r1_why = f"'Activity moved from ' || i.sh || ' to ' || j.sh || ' ' || {_dt_text(dt)} || ' later'"
    hub_keys = set(p.get("r2_hub_keys") or [])
    r2_filter = " AND ".join(["TRUE"] + (["NOT i.sh_hub"] if "host" in hub_keys else [])
                             + (["NOT i.usr_hub"] if "user" in hub_keys else []))
    r2_why = f"'Same session: ' || i.usr || ' on ' || i.sh || ', ' || {_dt_text(dt)} || ' apart'"
    src_tactics = ", ".join("'" + str(t).replace("'", "''") + "'" for t in p.get("r3_source_tactics") or [])
    r3_filter = " AND ".join(["NOT i.tu_hub", f"i.conf >= {float(p.get('r3_min_source_confidence', 0))}"]
                             + ([f"i.tactic IN ({src_tactics})"] if src_tactics else []))
    r3_why = "'Account ' || i.tu || ' from step ' || i.id || ' used in step ' || j.id"
    r4_why = "'Data staged on ' || i.sh || ' sent to ' || coalesce(j.dsth, j.dst_ip, 'an external destination')"
    out = [
        # R1 handoff: i.dst_host = j.subject_host (a hub may be the target), or i.subject_host = j.src_host.
        ("R1", "i.dsth", "i.sh IS NOT NULL AND i.sh <> i.dsth", "j.sh", "TRUE", r1_why),
        ("R1", "i.sh", "TRUE", "j.srch", "j.sh IS NOT NULL AND j.sh <> j.srch", r1_why),
        # R2 session: same subject_host and user; hubs barred as keys.
        ("R2", "i.sh || '|' || i.usr", r2_filter, "j.sh || '|' || j.usr", "TRUE", r2_why),
        # R3 pivot: account acquired in i (target_user) then used in j; hub users barred.
        ("R3", "i.tu", r3_filter, "j.su", "TRUE", r3_why),
    ]
    if p.get("r3_match_target_user", True):
        out.append(("R3", "i.tu", r3_filter, "j.tu", "TRUE", r3_why))
    # R4 egress: Collection then Exfiltration on the same host.
    out.append(("R4", "i.sh", "i.tactic = 'Collection'", "j.sh", "j.tactic = 'Exfiltration'", r4_why))
    return out


def _rule_queries(p: dict[str, Any]) -> list[str]:
    r, k = p["rules"], int(p.get("max_preds_per_rule", 5))
    out = []
    for rule, ik, ifl, jk, jfl, why in rule_variants(p):
        out.append(f"SELECT i.id AS i, j.id AS j, '{rule}' AS rule, (j.ts_ms - i.ts_ms) AS dt_ms, j.rar AS rar, "
                   f"{why} AS why_linked FROM ({_nearest(ik, ifl, jk, jfl, k)}) np "
                   f"JOIN _lep_h i ON i.id = np.i JOIN _lep_h j ON j.id = np.j WHERE {_order(r[rule]['tau_ms'])}")
    return out


def build_edges_sql(p: dict[str, Any]) -> str:
    """Union of R1-R4 candidates -> weight -> top-k preds per (j, rule) -> best edge per (i, j)."""
    r = p["rules"]
    mult = " ".join(f"WHEN '{k}' THEN {float(v['mult'])}" for k, v in r.items())
    tau = " ".join(f"WHEN '{k}' THEN {float(v['tau_ms'])}" for k, v in r.items())
    k = int(p.get("max_preds_per_rule", 5))
    union = "\nUNION ALL\n".join(_rule_queries(p))
    return f"""
        WITH c AS ({union}),
        w AS (SELECT i, j, rule, dt_ms, why_linked,
                     round((CASE rule {mult} END) * rar * exp(-dt_ms / (CASE rule {tau} END)), 6) AS weight FROM c),
        topk AS (SELECT * FROM w QUALIFY row_number() OVER (PARTITION BY j, rule ORDER BY weight DESC, i) <= {k}),
        best AS (SELECT * FROM topk QUALIFY row_number() OVER (PARTITION BY i, j ORDER BY weight DESC, rule) = 1)
        SELECT i, j, rule, weight, CAST(dt_ms AS BIGINT) AS dt_ms, why_linked FROM best"""


def link_episodes(con: duckdb.DuckDBPyConnection, ep_path: Path, hubs_path: Path, out_path: Path,
                  p: dict[str, Any]) -> dict[str, Any]:
    """Compute edges in DuckDB and write them to out_path. Returns counts per rule."""
    _prepare(con, ep_path, hubs_path, float(p.get("default_rarity", 1.0)))
    con.execute(f"COPY ({build_edges_sql(p)} ORDER BY i, j) TO '{sql_path(out_path)}' (FORMAT PARQUET)")
    by_rule = dict(con.execute(f"SELECT rule, count(*) FROM read_parquet('{sql_path(out_path)}') GROUP BY rule "
                               "ORDER BY rule").fetchall())
    n_ep = con.execute("SELECT count(*) FROM _lep").fetchone()[0]
    n_hubs = con.execute("SELECT count(*) FROM _hubs").fetchone()[0]
    for t in ("_lep_h", "_lep", "_hubs"):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    return {"episodes": int(n_ep), "hubs": int(n_hubs), "edges": int(sum(by_rule.values())),
            "edges_by_rule": {k: int(v) for k, v in by_rule.items()}}


def run(ctx: RunContext) -> dict[str, Any]:
    t0 = time.perf_counter()
    work = ctx.work_dir
    ep_path, out_path = work / "episodes.parquet", work / "edges.parquet"
    p = link_params(ctx.cfg)
    if not ep_path.exists():
        log.warning("link: %s missing, writing empty edges", ep_path)
        ctx.con.execute(f"COPY (SELECT NULL::VARCHAR i, NULL::VARCHAR j, NULL::VARCHAR rule, NULL::DOUBLE weight, "
                        f"NULL::BIGINT dt_ms, NULL::VARCHAR why_linked WHERE FALSE) TO '{sql_path(out_path)}' "
                        "(FORMAT PARQUET)")
        return {"episodes": 0, "edges": 0, "edges_by_rule": {}}
    stats = link_episodes(ctx.con, ep_path, work / "background_hubs.parquet", out_path, p)
    stats["max_preds_per_rule"] = int(p["max_preds_per_rule"])
    stats["seconds"] = round(time.perf_counter() - t0, 3)
    log.info("link: %s", stats)
    return stats
