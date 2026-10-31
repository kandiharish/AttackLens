"""Shared SQL helpers for Stage 1b/2/2.5: macros, lookup temp tables, label finishing, quoting.

Temp objects created on the connection (all prefixed `al_`):
  macro  al_is_internal_ip(ip)   RFC1918 / loopback / link-local / ULA / NULL-safe
  macro  al_mode(list(x))        deterministic mode (highest count, then smallest value)
  table  al_attack(technique_id, name, tactic)            from config/attack_v20.json
  table  al_ip_host(ip, host)                              latest owner of each IP (from host_ip_map)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import duckdb

from attacklens.schemas import CANONICAL_COLUMNS, TACTIC_IDX

log = logging.getLogger(__name__)

NET_ACTIONS = ("conn_out", "conn_allowed", "conn_denied", "dns_query")
LOGON_ACTIONS = ("login_success", "login_failed")

RAW_ALERT_COLUMNS: dict[str, str] = {
    "rule_id": "VARCHAR", "technique_id": "VARCHAR", "sub_technique_id": "VARCHAR", "technique_name": "VARCHAR",
    "tactic": "VARCHAR", "tactic_idx": "INTEGER", "severity": "INTEGER", "ts_ms": "BIGINT", "last_ts_ms": "BIGINT",
    "source_seq": "UBIGINT", "host": "VARCHAR", "subject_host": "VARCHAR", "src_host": "VARCHAR",
    "dst_host": "VARCHAR", "src_user": "VARCHAR", "target_user": "VARCHAR", "src_ip": "VARCHAR",
    "dst_ip": "VARCHAR", "raw_alert_count": "BIGINT", "evidence_lines": "VARCHAR[]", "source_keys": "UBIGINT[]",
}

# Columns every template "core" SELECT must produce (finish() adds labels and host resolution).
CORE_COLUMNS = ("label", "sub_technique_id", "ts_ms", "last_ts_ms", "source_seq", "host", "subject_host",
                "src_user", "target_user", "src_ip", "dst_ip", "raw_alert_count", "evidence_lines", "source_keys")

OK = "CAST(ts_ok AS BOOLEAN)"


def sql_path(p: Path | str) -> str:
    """Path as a complete quoted SQL string literal ('...' with ' doubled) - same contract as db.sql_path."""
    from attacklens import db

    fn = getattr(db, "sql_path", None)
    if fn is not None:
        return str(fn(p))
    return "'" + Path(p).as_posix().replace("'", "''") + "'"


def q(value: Any) -> str:
    """SQL literal for a trusted config value."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return repr(value)
    return "'" + str(value).replace("'", "''") + "'"


def sql_list(values: list[Any]) -> str:
    """('a','b') — never empty (an empty IN list is a parse error), so a sentinel NULL is used."""
    return "(" + ", ".join(q(v) for v in values) + ")" if values else "(NULL)"


TIE_ORDER = "{'t': ts_ms, 's': source_seq}"   # deterministic ordering key: time, then source_seq


def ev_lines(th: dict[str, Any], col: str = "raw_line", order: str = TIE_ORDER) -> str:
    return (f"min_by(left({col}, {int(th.get('evidence_max_chars', 300))}), {order}, "
            f"{int(th.get('evidence_max_lines', 3))})")


def ev_keys(th: dict[str, Any], col: str = "source_seq", order: str = TIE_ORDER) -> str:
    return f"min_by({col}, {order}, {int(th.get('source_keys_max', 50))})"


FALLBACK_ACTIONS = ("conn_out", "conn_allowed", "conn_denied", "dns_query", "ips_alert", "av_alert", "web_blocked",
                    "web_access", "app_ctrl")
FALLBACK_SOURCE_TYPES = ("fortigate_kv", "firewall_csv")


def internal_ip_expr(e: str, th: dict[str, Any] | None = None) -> str:
    """The row's internal endpoint IP: src_ip if internal (RFC1918 or src_zone in entity_internal_zones), else
    dst_ip if internal, else NULL."""
    zones = sql_list([str(z).lower() for z in (th or {}).get("entity_internal_zones", ["lan", "dmz"])])
    return (f"CASE WHEN {e}.src_ip IS NOT NULL AND (al_is_internal_ip({e}.src_ip) OR lower({e}.src_zone) IN {zones}) "
            f"THEN {e}.src_ip "
            f"WHEN {e}.dst_ip IS NOT NULL AND (al_is_internal_ip({e}.dst_ip) OR lower({e}.dst_zone) IN {zones}) "
            f"THEN {e}.dst_ip END")


def subject_host_expr(e: str = "e", m: str = "m", th: dict[str, Any] | None = None) -> str:
    """Network rows: the host owning src_ip (al_ip_host joined as `m`), else the reporting host. With
    thresholds.entity_fallback_ip, rows of entity_fallback_source_types (firewalls: the reporting host is the
    firewall itself) and entity_fallback_actions whose src_ip has no host use the internal endpoint IP. Every
    other source keeps host_ip_map, then host. Needs source_type, src_zone and dst_zone on `e`."""
    th = th or {}
    if th.get("entity_fallback_ip"):
        acts = sql_list(list(th.get("entity_fallback_actions") or FALLBACK_ACTIONS))
        srcs = sql_list([str(x) for x in th.get("entity_fallback_source_types") or FALLBACK_SOURCE_TYPES])
        return (f"CASE WHEN {e}.action IN {acts} AND {e}.source_type IN {srcs} "
                f"THEN coalesce({m}.host, {internal_ip_expr(e, th)}, {e}.host) "
                f"WHEN {e}.action IN {sql_list(list(NET_ACTIONS))} THEN coalesce({m}.host, {e}.host) "
                f"ELSE {e}.host END")
    return (f"CASE WHEN {e}.action IN {sql_list(list(NET_ACTIONS))} THEN coalesce({m}.host, {e}.host) "
            f"ELSE {e}.host END")


def rule_filter(rule: dict[str, Any]) -> str:
    """`AND (<filter>)` for template rules with an optional `filter` predicate on candidate rows (bare column
    names of `events`), else ''."""
    f = rule.get("filter")
    return f" AND ({f})" if f else ""


def ensure_events(con: duckdb.DuckDBPyConnection, events_glob: str) -> None:
    """Register the events view; with no Parquet yet, an empty typed view (rules still compile)."""
    from attacklens import db

    root = Path(events_glob.split("**")[0])
    if root.exists() and any(root.rglob("*.parquet")):
        db.register_events(con, events_glob)  # db.py owns quoting of the glob
        fill_missing_columns(con, events_glob)
        return
    log.warning("no event parquet under %s; using an empty events view", root)
    create_empty_events(con)


def fill_missing_columns(con: duckdb.DuckDBPyConnection, events_glob: str) -> list[str]:
    """Parquet written before a schema addition lacks the new canonical columns: re-create `events` with
    NULL::<type> for each missing one, so rules never hit a binder error. Returns the added column names."""
    from attacklens import db

    have = {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    missing = [(c, t) for c, t in CANONICAL_COLUMNS.items() if c not in have]
    if not missing:
        return []
    extra = ", ".join(f"NULL::{t} AS {c}" for c, t in missing)
    con.execute(f"CREATE OR REPLACE VIEW events AS SELECT *, {extra} FROM read_parquet({sql_path(events_glob)}, "
                f"hive_partitioning=true, union_by_name=true, hive_types={db.HIVE_TYPES})")
    log.info("events: %d canonical column(s) absent from Parquet, read as NULL: %s",
             len(missing), [c for c, _ in missing])
    return [c for c, _ in missing]


def create_empty_events(con: duckdb.DuckDBPyConnection) -> None:
    cols = ", ".join(f"NULL::{t} AS {c}" for c, t in CANONICAL_COLUMNS.items())
    con.execute(f"CREATE OR REPLACE VIEW events AS SELECT {cols} WHERE false")


def register_macros(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("""
        CREATE OR REPLACE TEMP MACRO al_is_internal_ip(ip) AS (
            ip IS NULL
            OR regexp_matches(ip, '^(10\\.|127\\.|192\\.168\\.|169\\.254\\.|0\\.0\\.0\\.0$)')
            OR regexp_matches(ip, '^172\\.(1[6-9]|2[0-9]|3[01])\\.')
            OR lower(ip) = '::1' OR regexp_matches(lower(ip), '^(fc|fd|fe80)')
        )""")
    # deterministic mode over list(x): highest count, then smallest value; NULLs ignored (DuckDB mode() breaks ties
    # in arrival order, which varies with threads and would change subject_host / episode_id)
    con.execute("""
        CREATE OR REPLACE TEMP MACRO al_mode(l) AS (
            list_min(list_transform(map_entries(list_histogram(list_filter(l, lambda v: v IS NOT NULL))),
                                    lambda e: {'c': -(e.value::BIGINT), 'k': e.key})).k
        )""")
    con.execute("""
        CREATE OR REPLACE TEMP MACRO al_is_loopback(ip) AS (
            ip IS NULL OR ip IN ('-', '', '::1') OR starts_with(ip, '127.')
        )""")


def create_attack_table(con: duckdb.DuckDBPyConnection, attack: dict[str, Any]) -> None:
    con.execute("CREATE OR REPLACE TEMP TABLE al_attack(technique_id VARCHAR, name VARCHAR, tactic VARCHAR)")
    rows = [(k, v.get("name"), v.get("tactic")) for k, v in (attack.get("techniques") or {}).items()]
    if rows:
        con.executemany("INSERT INTO al_attack VALUES (?, ?, ?)", rows)


def create_ip_host_table(con: duckdb.DuckDBPyConnection, host_ip_map: Path | None) -> None:
    """al_ip_host(ip, host): the most recent owner per IP. Built from host_ip_map.parquet when present."""
    if host_ip_map is not None and host_ip_map.exists():
        src = f"read_parquet({sql_path(host_ip_map)})"
    else:
        src = ("(SELECT host_ip AS ip, host, max(ts_ms) AS last_ms FROM events "
               f"WHERE {OK} AND host IS NOT NULL AND NOT al_is_loopback(host_ip) GROUP BY ALL)")
    con.execute("CREATE OR REPLACE TEMP TABLE al_ip_host AS "
                "SELECT ip, arg_max(host, {'l': last_ms, 'h': host}) AS host "
                f"FROM {src} GROUP BY ip")


def prepare(con: duckdb.DuckDBPyConnection, cfg: dict[str, Any], work_dir: Path | None = None) -> None:
    """Everything templates rely on: macros, al_attack, al_ip_host. Safe to call repeatedly."""
    register_macros(con)
    create_attack_table(con, cfg.get("attack") or {})
    create_ip_host_table(con, (work_dir / "host_ip_map.parquet") if work_dir else None)


def labels_of(rule: dict[str, Any]) -> list[tuple[str, str, str | None, str, int, int]]:
    """[(label, technique, sub_technique, tactic, tactic_idx, severity)] for primary and optional secondary."""
    out = []
    specs = [("primary", rule), ("secondary", rule.get("secondary"))]
    specs += [(f"sig{i}", sig) for i, sig in enumerate(rule.get("signatures") or [])]
    for label, spec in specs:
        if not spec:
            continue
        tactic = spec["tactic"]
        out.append((label, spec["technique"], spec.get("sub_technique"), tactic, TACTIC_IDX[tactic],
                    int(spec.get("severity", rule.get("severity", 50)))))
    return out


def finish(rule: dict[str, Any], core_sql: str, row_severity: bool = False) -> str:
    """Wrap a core SELECT (CORE_COLUMNS) into the exact raw_alerts columns (§15.4). With row_severity the core
    also has `severity_override` (INTEGER, NULL = the label's severity)."""
    sev_expr = "coalesce(c.severity_override, lb.severity)" if row_severity else "lb.severity"
    vals = ", ".join(f"({q(l)}, {q(t)}, {q(s)}::VARCHAR, {q(ta)}, {ti}, {sev})"
                     for l, t, s, ta, ti, sev in labels_of(rule))
    return f"""
    SELECT {q(rule['id'])}::VARCHAR AS rule_id, lb.technique_id::VARCHAR AS technique_id,
           coalesce(c.sub_technique_id, lb.sub_technique_id)::VARCHAR AS sub_technique_id,
           coalesce(a.name, a2.name)::VARCHAR AS technique_name, lb.tactic::VARCHAR AS tactic,
           lb.tactic_idx::INTEGER AS tactic_idx, {sev_expr}::INTEGER AS severity,
           c.ts_ms::BIGINT AS ts_ms, c.last_ts_ms::BIGINT AS last_ts_ms, c.source_seq::UBIGINT AS source_seq,
           c.host::VARCHAR AS host, c.subject_host::VARCHAR AS subject_host,
           sh.host::VARCHAR AS src_host, dh.host::VARCHAR AS dst_host,
           c.src_user::VARCHAR AS src_user, c.target_user::VARCHAR AS target_user,
           c.src_ip::VARCHAR AS src_ip, c.dst_ip::VARCHAR AS dst_ip,
           c.raw_alert_count::BIGINT AS raw_alert_count,
           c.evidence_lines::VARCHAR[] AS evidence_lines, c.source_keys::UBIGINT[] AS source_keys
    FROM ({core_sql}) c
    JOIN (VALUES {vals}) lb(label, technique_id, sub_technique_id, tactic, tactic_idx, severity) USING (label)
    LEFT JOIN al_attack a ON a.technique_id = coalesce(c.sub_technique_id, lb.sub_technique_id)
    LEFT JOIN al_attack a2 ON a2.technique_id = lb.technique_id
    LEFT JOIN al_ip_host sh ON sh.ip = c.src_ip
    LEFT JOIN al_ip_host dh ON dh.ip = c.dst_ip
    """


def empty_raw_alerts_sql() -> str:
    return "SELECT " + ", ".join(f"NULL::{t} AS {c}" for c, t in RAW_ALERT_COLUMNS.items()) + " WHERE false"


def window_bursts(part: str, win: int, agg: str, cond: str) -> str:
    """CTEs over CTE `r` (ts_ms, source_seq, <part cols>, ...): rows inside any [t, t+win) window whose `agg`
    satisfies `cond` (on column wv), grouped into bursts `bid` (a gap > win starts a new burst). Ends in CTE `mb`."""
    return f"""
    w AS (SELECT *, {agg} OVER (PARTITION BY {part} ORDER BY ts_ms
                               RANGE BETWEEN CURRENT ROW AND {win - 1} FOLLOWING) AS wv FROM r),
    s AS (SELECT *, max(CASE WHEN {cond} THEN ts_ms END) OVER (PARTITION BY {part} ORDER BY ts_ms, source_seq
                                                               ROWS UNBOUNDED PRECEDING) AS ls FROM w),
    m AS (SELECT * FROM s WHERE ls IS NOT NULL AND ts_ms - ls < {win}),
    g AS (SELECT *, CASE WHEN ts_ms - lag(ts_ms) OVER (PARTITION BY {part} ORDER BY ts_ms, source_seq) <= {win}
                         THEN 0 ELSE 1 END AS nb FROM m),
    mb AS (SELECT *, sum(nb) OVER (PARTITION BY {part} ORDER BY ts_ms, source_seq ROWS UNBOUNDED PRECEDING) AS bid
           FROM g)"""
