"""cloud_ev: the one table every cloud rule reads (catalog §2.2 "performance recommendation").

- Reads only rows whose source_type is a cloud type (hive partition pruning), parses raw_line ONCE with a single
  json_extract_string(raw_line, [all paths]) call, maps config/cloud.yaml `columns` and `derived` layers.
- Keeps an evidence line `evl` (summary of raw fields, or the raw_line prefix) instead of the whole raw_line.
- Drops duplicate deliveries (same dedup_id: CloudTrail eventID, GCP insertId, Azure correlation|op|status|id).
- Adds geo columns from detect_cloud_geo (asn, cc, net, hosting, lat, lon, corp_ip, provider).
- Builds cl_hist_<col>(k, day, n, cum_before, first_ts) lazily for cold-start checks (aggregates, never raw rows).
"""

from __future__ import annotations

import logging
import re
from typing import Any

import duckdb

from attacklens.detect_cloud_geo import build_ip_geo
from attacklens.detect_sql import OK, q, sql_list

log = logging.getLogger(__name__)

DAY_MS = 86_400_000
BASE_COLUMNS = ("source_seq", "ts_ms", "source_type", "action", "outcome", "host", "src_user", "target_user",
                "src_ip", "signature", "app", "group_name", "bytes_out", "file_path",
                # network sources (VPC flow, Route 53 Resolver, Network Firewall): canonical columns, no JSON needed
                "dst_ip", "dst_port", "src_port", "dst_domain", "vendor_severity")
_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
_PH = re.compile(r"\{cfg\.([A-Za-z0-9_]+)(:list)?\}")


def sql_value(v: Any) -> str:
    """SQL text for a cloud.yaml value: list -> ('a', 'b') (never empty), scalar -> literal."""
    if isinstance(v, (list, tuple)):
        return sql_list(list(v))
    if isinstance(v, dict):
        raise ValueError("a dict cannot be used inside SQL")
    return q(v)


def sql_array(v: Any) -> str:
    """SQL list literal ['a', 'b'] (typed empty list when empty) for list functions (list_contains, lambdas)."""
    vals = list(v or [])
    if not vals:
        return "[]::VARCHAR[]"
    return "[" + ", ".join(q(x) for x in vals) + "]"


def expand(sql: str, params: dict[str, Any]) -> str:
    """Replace {cfg.<name>} (IN-list / literal) and {cfg.<name>:list} (list literal) placeholders by SQL values
    from cloud.yaml params (unknown name -> ValueError)."""
    def sub(m: re.Match[str]) -> str:
        if m.group(1) not in params:
            raise ValueError(f"unknown placeholder {{cfg.{m.group(1)}}}")
        v = params[m.group(1)]
        return sql_array(v if isinstance(v, list) else [v]) if m.group(2) else sql_value(v)
    return _PH.sub(sub, str(sql))


NEVER_RX = r"[^\s\S]"


def runtime_params(params: dict[str, Any] | None) -> dict[str, Any]:
    """cloud.yaml params plus values derived at runtime: automation_identity_regex = the alternation of
    automation_identity_patterns (each validated as RE2-compatible text; an empty list matches nothing)."""
    out = dict(params or {})
    pats = [str(p) for p in out.get("automation_identity_patterns") or [] if str(p).strip()]
    for p in pats:
        re.compile(p)          # fail fast on a broken pattern (RE2 is stricter, but this catches typos)
    out["automation_identity_regex"] = "|".join(f"(?:{p})" for p in pats) if pats else NEVER_RX
    return out


def automation_table(con: duckdb.DuckDBPyConnection, cc: dict[str, Any]) -> int:
    """cl_auto(source_seq, risky): one row per cloud_ev row of an automation identity (derived column `automation`),
    risky = the identity used a network it had not used in new_network_days, or >= denied_min denied calls within
    +-denied_window_ms, or an attack-tool user agent. Window functions over the rows of automation identities only
    (no self-join, so a chatty CI identity stays linear)."""
    a = cc.get("automation") or {}
    params = runtime_params(cc.get("params"))
    days = int(float(a.get("new_network_days", 14)) * DAY_MS)
    win, dmin = int(a.get("denied_window_ms", 3_600_000)), int(a.get("denied_min", 5))
    ua_rx = q(str(params.get("attack_ua_regex") or NEVER_RX))
    con.execute(f"""CREATE OR REPLACE TEMP TABLE cl_auto AS
        WITH k AS (SELECT DISTINCT actor_key FROM cloud_ev WHERE coalesce(automation, false) AND actor_key IS NOT NULL),
        h AS (SELECT source_seq, ts_ms, actor_key, net, ua, coalesce(automation, false) AS automation,
                     coalesce(denied, false) AS denied FROM cloud_ev SEMI JOIN k USING (actor_key)),
        w AS (SELECT *, ts_ms - lag(ts_ms) OVER (PARTITION BY actor_key, net ORDER BY ts_ms, source_seq) AS gap,
                     count(*) FILTER (WHERE denied) OVER (PARTITION BY actor_key ORDER BY ts_ms
                         RANGE BETWEEN {win} PRECEDING AND {win} FOLLOWING) AS nden FROM h)
        SELECT source_seq, (net IS NOT NULL AND (gap IS NULL OR gap > {days})) OR nden >= {dmin}
                           OR regexp_matches(coalesce(ua, ''), {ua_rx}) AS risky
        FROM w WHERE automation""")
    return int(con.execute("SELECT count(*) FROM cl_auto").fetchone()[0])


def _columns_sql(cols: dict[str, Any]) -> tuple[list[str], list[str]]:
    paths: list[str] = []
    exprs: list[str] = []
    for name, spec in cols.items():
        if not _IDENT.match(name):
            raise ValueError(f"cloud.yaml columns: bad name {name!r}")
        spec = {"paths": spec} if isinstance(spec, list) else dict(spec)
        idx: list[str] = []
        for p in spec.get("paths") or []:
            # "outer|inner": outer is a JSON object OR a string holding JSON (Entra AAD* tables write LocationDetails,
            # Status, DeviceDetail as strings); inner is read from that text, never raising on bad JSON.
            outer, _, inner = str(p).partition("|")
            paths.append(outer)
            idx.append(f"try(json_extract_string(nullif(_v[{len(paths)}], ''), {q(inner)}))" if inner
                       else f"nullif(_v[{len(paths)}], '')")
        val = "coalesce(" + ", ".join(idx) + ")" if idx else "NULL"
        src = spec.get("src")
        exprs.append(f"CAST(CASE WHEN source_type IN {sql_list(list(src))} THEN {val} END AS VARCHAR) AS {name}"
                     if src else f"CAST({val} AS VARCHAR) AS {name}")
    return paths, exprs


def evidence_sql(cc: dict[str, Any], mc: int) -> str:
    ecfg = cc.get("evidence") or {}
    if str(ecfg.get("mode", "summary")) == "raw":
        return f"left(raw_line, {mc})"
    rc = int(ecfg.get("req_chars", 160))
    parts = ["'time=' || coalesce(raw_time, strftime(epoch_ms(ts_ms), '%Y-%m-%dT%H:%M:%SZ'))", "'cloud=' || cloud",
             "'api=' || signature", "'svc=' || app",
             "'actor=' || coalesce(ct_arn, az_caller, au_by_upn, au_by_app, g_principal, actor)",
             "'ip=' || coalesce(ct_ip, src_ip)", "'outcome=' || outcome",
             "'err=' || coalesce(ct_err, g_code, CASE WHEN si_code <> '0' THEN si_code END, az_status_code)",
             "'target=' || target_user",
             "'dst=' || dst_ip || coalesce(':' || dst_port, '')", "'domain=' || dst_domain",
             "'bytes=' || bytes_out", "'action=' || CASE WHEN starts_with(source_type, 'aws_') THEN action END",
             f"'req=' || left(coalesce(ct_rp, az_req, g_req, tr_json, sb_key, "
             f"CASE WHEN source_type IN ('azure_keyvault_json', 'azure_graph_json') THEN file_path END), {rc})"]
    return f"left(concat_ws(' ', {', '.join(parts)}), {mc})"


def build(con: duckdb.DuckDBPyConnection, cc: dict[str, Any], mc: int) -> dict[str, Any]:
    """Create temp table cloud_ev. Returns stats: rows, dedup_removed, geo."""
    params = runtime_params(cc.get("params"))
    stypes = [str(s) for s in cc.get("source_types") or []]
    paths, col_exprs = _columns_sql(cc.get("columns") or {})
    base_cols = ", ".join(BASE_COLUMNS)
    sql = (f"SELECT {base_cols}, raw_line, {', '.join(col_exprs)} FROM ("
           f"SELECT {base_cols}, raw_line, try(json_extract_string(raw_line, {sql_array(paths)})) AS _v FROM ("
           f"SELECT {base_cols}, raw_line FROM events WHERE source_type IN {sql_list(stypes)} AND {OK} "
           f"AND ts_ms IS NOT NULL))")
    for layer in cc.get("derived") or []:
        bad = [k for k in layer if not _IDENT.match(str(k))]
        if bad:
            raise ValueError(f"cloud.yaml derived: bad names {bad}")
        sql = "SELECT *, " + ", ".join(f"({expand(v, params)}) AS {k}" for k, v in layer.items()) + f" FROM ({sql})"
    cloud = ("CASE WHEN source_type = 'cloudtrail_json' OR starts_with(source_type, 'aws_') THEN 'aws' "
             "WHEN starts_with(source_type, 'gcp_') THEN 'gcp' WHEN starts_with(source_type, 'k8s_') THEN 'k8s' "
             "WHEN starts_with(source_type, 'okta_') THEN 'okta' WHEN starts_with(source_type, 'gws_') THEN 'gws' "
             "WHEN starts_with(source_type, 'm365_') THEN 'm365' WHEN starts_with(source_type, 'auth0_') THEN 'auth0' "
             "WHEN starts_with(source_type, 'duo_') THEN 'duo' "
             "ELSE 'azure' END")
    sql = f"SELECT * EXCLUDE (raw_line), {evidence_sql(cc, mc)} AS evl FROM (SELECT *, {cloud} AS cloud FROM ({sql}))"
    con.execute(f"CREATE OR REPLACE TEMP TABLE cl_base AS {sql}")
    removed = 0
    if cc.get("dedupe", True):
        before = con.execute("SELECT count(*) FROM cl_base").fetchone()[0]
        con.execute("""DELETE FROM cl_base USING (
                SELECT dedup_id AS did, min(source_seq) AS keep FROM cl_base WHERE dedup_id IS NOT NULL
                GROUP BY dedup_id HAVING count(*) > 1) d
            WHERE cl_base.dedup_id = d.did AND cl_base.source_seq <> d.keep""")
        removed = int(before - con.execute("SELECT count(*) FROM cl_base").fetchone()[0])
    endpoint_host(con, [str(s) for s in cc.get("endpoint_host_source_types") or []])
    geo = build_ip_geo(con, cc.get("geo") or {}, params)
    hosting_rx = str(params.get("hosting_asn_regex") or "^$")
    con.execute(f"""CREATE OR REPLACE TEMP TABLE cloud_ev AS
        SELECT b.*, coalesce(nullif(b.si_asn, '0'), g.asn) AS asn, upper(coalesce(b.si_cc, g.geo_cc)) AS cc,
               coalesce('as' || coalesce(nullif(b.si_asn, '0'), g.asn), g.prefix) AS net,
               coalesce(coalesce(nullif(b.si_asn, '0'), g.asn) IN {sql_value(params.get('hosting_asns') or [])}
                        OR regexp_matches(lower(coalesce(g.as_desc, '')), {q(hosting_rx)}), false) AS hosting,
               coalesce(TRY_CAST(b.si_lat AS DOUBLE), c.lat) AS lat, coalesce(TRY_CAST(b.si_lon AS DOUBLE), c.lon) AS lon,
               coalesce(g.corp_ip, false) AS corp_ip, g.provider, b.ts_ms // {DAY_MS} AS day
        FROM cl_base b LEFT JOIN cl_ip_geo g ON g.ip = b.src_ip
        LEFT JOIN cl_centroid c ON c.cc = upper(coalesce(b.si_cc, g.geo_cc))""")
    con.execute("DROP TABLE IF EXISTS cl_base")
    rows = int(con.execute("SELECT count(*) FROM cloud_ev").fetchone()[0])
    return {"rows": rows, "dedup_removed": removed, "geo": geo}


def endpoint_host(con: duckdb.DuckDBPyConnection, stypes: list[str]) -> int:
    """Rows of a network device that logs other machines' traffic (cloud.yaml endpoint_host_source_types, e.g. AWS
    Network Firewall): host = the internal endpoint (its owner from al_ip_host, else its IP; src first, then dst)
    instead of the device name, so an alert names the instance it is about. Needs detect_sql.prepare (al_ip_host and
    the al_is_internal_ip macro); without it nothing changes. Returns the rows re-hosted."""
    if not stypes or not con.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name = 'al_ip_host'"
                                     ).fetchone()[0]:
        return 0
    n = con.execute(f"""UPDATE cl_base SET host = x.h FROM (
        SELECT b.source_seq AS s, lower(coalesce(CASE WHEN al_is_internal_ip(b.src_ip) THEN coalesce(hs.host, b.src_ip) END,
                                                 CASE WHEN al_is_internal_ip(b.dst_ip) THEN coalesce(hd.host, b.dst_ip) END)) AS h
        FROM cl_base b LEFT JOIN al_ip_host hs ON hs.ip = b.src_ip LEFT JOIN al_ip_host hd ON hd.ip = b.dst_ip
        WHERE b.source_type IN {sql_list(stypes)}) x
        WHERE cl_base.source_seq = x.s AND cl_base.source_type IN {sql_list(stypes)} AND x.h IS NOT NULL""").fetchone()
    return int(n[0]) if n else 0


def hist_table(con: duckdb.DuckDBPyConnection, col: str, made: set[str]) -> str:
    """cl_hist_<col>(k, day, n, cum_before, first_ts): per key and day, events that day, events on earlier days and
    the key's first event. Built from a GROUP BY (aggregate rows only), once per run per column."""
    if not _IDENT.match(col):
        raise ValueError(f"hist key must be a cloud_ev column, got {col!r}")
    name = f"cl_hist_{col}"
    if name not in made:
        con.execute(f"""CREATE OR REPLACE TEMP TABLE {name} AS
            SELECT k, day, n, coalesce(sum(n) OVER (PARTITION BY k ORDER BY day ROWS BETWEEN UNBOUNDED PRECEDING
                                                     AND 1 PRECEDING), 0) AS cum_before,
                   min(first_ts) OVER (PARTITION BY k) AS first_ts
            FROM (SELECT {col} AS k, day, count(*) AS n, min(ts_ms) AS first_ts FROM cloud_ev
                  WHERE {col} IS NOT NULL GROUP BY ALL)""")
        made.add(name)
    return name


def baseline_ok_sql(h: str, ts: str, key: str, hist: str, min_days: float, min_events: int) -> str:
    """Boolean SQL: key `{h}.{key}` had >= min_days of history before `{ts}` and >= min_events on earlier days."""
    return (f"coalesce((SELECT {ts} - x.first_ts >= {int(min_days * DAY_MS)} AND x.cum_before >= {int(min_events)} "
            f"FROM {hist} x WHERE x.k = {h}.{key} AND x.day = {ts} // {DAY_MS}), false)")
