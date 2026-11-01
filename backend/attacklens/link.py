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
    # R3 fan-out cap per source episode i (= per account, since i has one target_user): top-k by weight. 0 = off.
    "r3_max_succs_per_source": 5,
    # Log devices (a FortiGate logs every flow with host = its devname): barred as R2 keys and as host-name R1 keys.
    "device_hosts": [], "auto_device_hosts": True,
    # R2 for user-less episodes on IP endpoints (§15.9: the entity for an internal endpoint is its IP).
    "r2_ip_session": True,
    # Bar hub IPs as user-less IP-session R2 keys too (a busy server is exactly where the endpoint steps happen).
    "r2_ip_session_bar_hubs": False,
    # User-less IP session (no shared peer) links only when at least ONE end has this confidence (0 = literal:
    # same endpoint IP within R2 tau is enough), and (r2_ip_session_distinct_rules) the two come from different
    # rules. A shared external peer is r2_ext_dst_session.
    "r2_ip_session_min_confidence": 0.0,
    "r2_ip_session_distinct_rules": False,
    # R2 peer session: same subject and same external (non-hub) dst_ip, window rules.R2.ext_dst_tau_ms.
    "r2_ext_dst_session": False,
    # Link window measured from: "end" = gap from i's last alert (last_ts_ms) to j's start (an episode that is
    # still running overlaps its successors: gap 0); "start" = literal start-to-start.
    "window_from": "start",
    # R1 attacker-IP handoff: the same external src_ip acts on host a, then on host b (rules.R1.ext_ip_tau_ms).
    "r1_ext_ip": True,
    # R2 attacker-IP session: same subject and same external src_ip (user may differ or be NULL), window R2 tau.
    "r2_ext_ip_session": True,
    "internal_ip_regex": r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|::1$|f[cd]|fe80:)",
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


IS_IP = r"regexp_full_match({x}, '[0-9]{{1,3}}(\.[0-9]{{1,3}}){{3}}|[0-9a-f:]*:[0-9a-f:]+')"


def _prepare(con: duckdb.DuckDBPyConnection, ep_path: Path, hubs_path: Path, p: dict[str, Any]) -> None:
    _hub_table(con, hubs_path)
    default_rarity = float(p.get("default_rarity", 1.0))
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE _lep AS
        WITH e AS ({episode_select(con, ep_path)})
        SELECT episode_id AS id, ts_ms, coalesce(source_seq, 0::UBIGINT) AS seq, tactic, rule_id AS rid,
               lower(NULLIF(host, '')) AS hst, lower(NULLIF(subject_host, '')) AS sh,
               lower(NULLIF(src_host, '')) AS srch,
               lower(NULLIF(dst_host, '')) AS dsth, lower(NULLIF(src_user, '')) AS su,
               lower(NULLIF(target_user, '')) AS tu,
               lower(NULLIF(coalesce("user", target_user, src_user), '')) AS usr,
               greatest(coalesce(last_ts_ms, ts_ms), ts_ms) AS end_ms,
               lower(NULLIF(dst_ip, '')) AS dst_ip, lower(NULLIF(src_ip, '')) AS sip, technique_id,
               coalesce(confidence, 0) AS conf,
               coalesce(rarity, {float(default_rarity)}) AS rar
        FROM e WHERE episode_id IS NOT NULL AND ts_ms IS NOT NULL""")
    # Devices: configured names, plus (auto) any `host` that logs episodes about other subjects (firewall devname).
    con.execute("CREATE OR REPLACE TEMP TABLE _dev (h VARCHAR)")
    configured = [str(h).lower() for h in p.get("device_hosts") or []]
    if configured:  # one columnar insert, not executemany
        con.execute("INSERT INTO _dev SELECT unnest(?::VARCHAR[])", [configured])
    if p.get("auto_device_hosts", True):
        con.execute("INSERT INTO _dev SELECT DISTINCT hst FROM _lep WHERE hst IS NOT NULL AND sh IS NOT NULL "
                    "AND hst <> sh")
    internal_re = str(p.get("internal_ip_regex") or DEFAULT_LINK["internal_ip_regex"]).replace("'", "''")
    con.execute(f"""
        CREATE OR REPLACE TEMP TABLE _lep_h AS
        SELECT e.*,
               coalesce(('host:' || e.sh) IN (SELECT entity FROM _hubs)
                        OR ('ip:' || e.sh) IN (SELECT entity FROM _hubs), FALSE) AS sh_hub,
               coalesce(e.sh IN (SELECT h FROM _dev), FALSE) AS sh_dev,
               coalesce({IS_IP.format(x="e.sh")}, FALSE) AS sh_ip,
               coalesce({IS_IP.format(x="e.sip")} AND NOT regexp_matches(e.sip, '{internal_re}')
                        AND ('ip:' || e.sip) NOT IN (SELECT entity FROM _hubs), FALSE) AS sip_ext,
               coalesce({IS_IP.format(x="e.dst_ip")} AND NOT regexp_matches(e.dst_ip, '{internal_re}')
                        AND ('ip:' || e.dst_ip) NOT IN (SELECT entity FROM _hubs), FALSE) AS dip_ext,
               coalesce(('user:' || e.usr) IN (SELECT entity FROM _hubs), FALSE) AS usr_hub,
               coalesce(('user:' || e.tu) IN (SELECT entity FROM _hubs), FALSE) AS tu_hub,
               coalesce(('user:' || e.su) IN (SELECT entity FROM _hubs), FALSE) AS su_hub
        FROM _lep e""")


def _dt_text(dt: str) -> str:
    """SQL expression rendering milliseconds as 45s / 7m19s / 2h05m / 1d03h."""
    s = f"({dt} // 1000)"
    return (f"CASE WHEN {s} < 60 THEN {s}::VARCHAR || 's' "
            f"WHEN {s} < 3600 THEN ({s} // 60)::VARCHAR || 'm' || lpad(({s} % 60)::VARCHAR, 2, '0') || 's' "
            f"WHEN {s} < 86400 THEN ({s} // 3600)::VARCHAR || 'h' || lpad((({s} % 3600) // 60)::VARCHAR, 2, '0') "
            f"|| 'm' ELSE ({s} // 86400)::VARCHAR || 'd' || lpad((({s} % 86400) // 3600)::VARCHAR, 2, '0') || 'h' END")


def dt_sql(p: dict[str, Any]) -> str:
    """Link gap in ms: from i's end (window_from: end, never negative) or i's start (literal) to j's start."""
    if str(p.get("window_from", "start")) == "end":
        return "greatest(0, j.ts_ms - i.end_ms)"
    return "(j.ts_ms - i.ts_ms)"


def _order(tau: int, dt: str = "(j.ts_ms - i.ts_ms)") -> str:
    """i precedes j: t_i <= t_j and 0 <= dt <= tau, tie-break (ts_ms, source_seq, episode_id). Order always uses
    start times; only the window / decay gap (dt) may be measured from i's end."""
    return (f"j.ts_ms >= i.ts_ms AND {dt} BETWEEN 0 AND {int(tau)} AND (i.ts_ms < j.ts_ms OR "
            "(i.ts_ms = j.ts_ms AND (i.seq < j.seq OR (i.seq = j.seq AND i.id < j.id))))")


DISTINCT_RULES = "i.rid IS DISTINCT FROM j.rid"


def _nearest(i_key: str, i_filter: str, j_key: str, j_filter: str, k: int, by_rule: bool = False) -> str:
    """Pairs (i, j) where i is one of the k nearest eligible predecessors of j with i_key = j_key.

    For a fixed (j, rule) the weight M_R * rarity_j * exp(-dt / tau_R) falls as dt grows, so the top-k predecessors
    by weight are exactly the k nearest in (ts_ms, source_seq, episode_id) order. Ranking eligible i rows per key and
    joining on (key, rank) keeps this an equality join of size <= n * (k + 1): no quadratic blow-up on hub keys.
    by_rule (pair condition DISTINCT_RULES): rank i per (key, rule) and copy j once per OTHER rule seen on its key,
    so a flood of nearer same-rule episodes cannot take the k slots before the pair condition drops them. Size
    <= n * rules_on_key * (k + 1), cut back to the k nearest per j.
    """
    si = f"SELECT id, ts_ms, seq, {i_key} AS k, rid FROM _lep_h i WHERE ({i_key}) IS NOT NULL AND {i_filter}"
    sj = f"SELECT id, ts_ms, seq, {j_key} AS k, rid FROM _lep_h j WHERE ({j_key}) IS NOT NULL AND {j_filter}"
    if by_rule:
        s_j = ("SELECT sj.id, sj.ts_ms, sj.seq, sj.k, g.g, 0 AS is_i FROM sj JOIN (SELECT DISTINCT k, rid AS g "
               "FROM si) g ON g.k = sj.k AND g.g IS DISTINCT FROM sj.rid")
        cut = f"QUALIFY row_number() OVER (PARTITION BY jj.id ORDER BY ii.ts_ms DESC, ii.seq DESC, ii.id DESC) <= {k}"
    else:
        s_j, cut = "SELECT id, ts_ms, seq, k, NULL::VARCHAR AS g, 0 AS is_i FROM sj", ""
    return f"""
        WITH si AS ({si}), sj AS ({sj}),
        s AS (SELECT id, ts_ms, seq, k, {"rid" if by_rule else "NULL::VARCHAR"} AS g, 1 AS is_i FROM si
              UNION ALL {s_j}),
        r AS (SELECT id, ts_ms, seq, k, g, is_i, CAST(sum(is_i) OVER (PARTITION BY k, g
                     ORDER BY ts_ms, seq, id, is_i DESC ROWS UNBOUNDED PRECEDING) AS BIGINT) AS cnt FROM s),
        ii AS (SELECT id, ts_ms, seq, k, g, cnt FROM r WHERE is_i = 1),
        jj AS (SELECT r.id, r.k, r.g, r.cnt - o.off AS want FROM r CROSS JOIN range(0, {k + 1}) o(off)
               WHERE r.is_i = 0)
        SELECT ii.id AS i, jj.id AS j FROM jj JOIN ii ON ii.k = jj.k AND ii.g IS NOT DISTINCT FROM jj.g
          AND ii.cnt = jj.want WHERE ii.id <> jj.id {cut}"""


def rule_variants(p: dict[str, Any]) -> list[tuple[str, ...]]:
    """(rule, i_key, i_filter, j_key, j_filter, why_sql[, pair_sql]). Every filter is one-sided, so ranking per key
    is exact; an optional pair condition is applied to the k nearest (like _extra_variants), except DISTINCT_RULES,
    which _nearest applies inside the ranking."""
    dt = dt_sql(p)
    r1_why = f"'Activity moved from ' || i.sh || ' to ' || j.sh || ' ' || {_dt_text(dt)} || ' later'"
    hub_keys = set(p.get("r2_hub_keys") or [])
    host_bar = ("NOT i.sh_hub" if p.get("r2_ip_session_bar_hubs", False)
                else "(NOT i.sh_hub OR (i.usr IS NULL AND i.sh_ip))")
    r2_filter = " AND ".join(["NOT i.sh_dev"] + ([host_bar] if "host" in hub_keys else [])
                             + (["NOT i.usr_hub"] if "user" in hub_keys else []))
    # Session user: the account. A user-less episode on an IP endpoint (§15.9) is its own variant below.
    usr = "{a}.usr"
    r2_why_user = "coalesce(i.usr, 'endpoint')"
    r2_why = f"'Same session: ' || {r2_why_user} || ' on ' || i.sh || ', ' || {_dt_text(dt)} || ' apart'"
    src_tactics = ", ".join("'" + str(t).replace("'", "''") + "'" for t in p.get("r3_source_tactics") or [])
    r3_filter = " AND ".join(["NOT i.tu_hub", f"i.conf >= {float(p.get('r3_min_source_confidence', 0))}"]
                             + ([f"i.tactic IN ({src_tactics})"] if src_tactics else []))
    r3_why = "'Account ' || i.tu || ' from step ' || i.id || ' used in step ' || j.id"
    r4_why = "'Data staged on ' || i.sh || ' sent to ' || coalesce(j.dsth, j.dst_ip, 'an external destination')"
    out = [
        # R1 handoff: i.dst_host = j.subject_host (a hub may be the target), or i.subject_host = j.src_host.
        # A log device (devname) is never the join key; it may still take part through an IP handoff (below).
        ("R1", "i.dsth", "i.sh IS NOT NULL AND i.sh <> i.dsth", "j.sh", "NOT j.sh_dev", r1_why),
        ("R1", "i.sh", "NOT i.sh_dev", "j.srch", "j.sh IS NOT NULL AND j.sh <> j.srch", r1_why),
        # R1 IP handoff: i reached IP X, then X (an IP endpoint) acts.
        ("R1", "lower(i.dst_ip)", "i.sh IS NOT NULL AND i.sh <> lower(i.dst_ip)", "j.sh", "j.sh_ip AND NOT j.sh_dev",
         r1_why),
        # R2 session: same subject_host and user; hubs and devices barred as keys.
        ("R2", f"i.sh || '|' || {usr.format(a='i')}", r2_filter, f"j.sh || '|' || {usr.format(a='j')}", "TRUE",
         r2_why),
    ]
    if p.get("r2_ip_session", True):
        # User-less session on an IP endpoint: same endpoint IP only. Without a shared peer this joined unrelated
        # zero-second same-rule IPS pairs (n30: 22 985 of 23 169 R2 edges), so one end must reach
        # r2_ip_session_min_confidence (two one-sided, disjoint variants keep the per-key ranking exact and never
        # emit one (i, j) twice) and the two ends must come from different rules (pair condition, in the ranking).
        mc = float(p.get("r2_ip_session_min_confidence", 0) or 0)
        ip_i = f"{r2_filter} AND i.usr IS NULL AND i.sh_ip"
        ip_j = "j.usr IS NULL AND j.sh_ip"
        pair = DISTINCT_RULES if p.get("r2_ip_session_distinct_rules", False) else "TRUE"
        if mc > 0:
            out.append(("R2", "i.sh", f"{ip_i} AND i.conf >= {mc}", "j.sh", ip_j, r2_why, pair))
            out.append(("R2", "i.sh", f"{ip_i} AND i.conf < {mc}", "j.sh", f"{ip_j} AND j.conf >= {mc}", r2_why,
                        pair))
        else:
            out.append(("R2", "i.sh", ip_i, "j.sh", ip_j, r2_why, pair))
    if p.get("r2_ext_dst_session", False):
        # Peer session: same subject towards the same external, non-hub destination (download from X, beacon to X,
        # exfil to X), any user; window rules.R2.ext_dst_tau_ms. A device subject is barred like plain R2.
        out.append(("R2", "i.sh || '|' || i.dst_ip", "i.dip_ext AND NOT i.sh_dev", "j.sh || '|' || j.dst_ip",
                    "j.dip_ext", f"'Same peer: ' || i.sh || ' to ' || i.dst_ip || ', ' || {_dt_text(dt)} || ' apart'"))
    if p.get("r2_ext_ip_session", True):
        # Keyed by the external IP, so a device subject is fine here (e.g. IPS hit, then VPN login, same remip).
        out.append(("R2", "i.sh || '|' || i.sip", "i.sip_ext", "j.sh || '|' || j.sip", "j.sip_ext",
                    f"'Same session: ' || i.sip || ' on ' || i.sh || ', ' || {_dt_text(dt)} || ' apart'"))
    out += [
        # R3 pivot: account acquired in i (target_user) then used in j; hub users barred.
        ("R3", "i.tu", r3_filter, "j.su", "TRUE", r3_why),
    ]
    if p.get("r3_match_target_user", True):
        # j with src_user == target_user is already keyed by the j.su variant: one candidate, not two top-k slots
        out.append(("R3", "i.tu", r3_filter, "j.tu", "j.su IS DISTINCT FROM j.tu", r3_why))
    # R4 egress: Collection then Exfiltration on the same host.
    out.append(("R4", "i.sh", "i.tactic = 'Collection'", "j.sh", "j.tactic = 'Exfiltration'", r4_why))
    return out


def _extra_variants(p: dict[str, Any]) -> list[tuple[str, str, str, str, str, str, str, str]]:
    """Variants with a pair condition and their own window key: (rule, ik, ifl, jk, jfl, why, pair_sql, tau_key)."""
    if not p.get("r1_ext_ip", True):
        return []
    dt = dt_sql(p)
    why = (f"'Activity from ' || i.sip || ' moved from ' || i.sh || ' to ' || j.sh || ' ' || {_dt_text(dt)} "
           "|| ' later'")
    # Same external, non-hub src_ip on two different subjects (e.g. firewall admin login, then inbound RDP).
    return [("R1", "i.sip", "i.sip_ext AND i.sh IS NOT NULL", "j.sip", "j.sip_ext AND j.sh IS NOT NULL", why,
             "i.sh <> j.sh", "ext_ip_tau_ms")]


def _rule_queries(p: dict[str, Any]) -> list[str]:
    r, k = p["rules"], int(p.get("max_preds_per_rule", 5))
    dt = dt_sql(p)
    plain = []
    for v0 in rule_variants(p):
        v, vpair = v0[:6], (v0[6] if len(v0) > 6 else "TRUE")
        if v[0] == "R3":
            # Same-subject pivots keep tau_ms (72 h); cross-host pivots on a bare user name use the shorter
            # rules.R3.cross_host_tau_ms (a name alone over 72 h glued unrelated hosts into one incident).
            plain += [(*v, "i.sh IS NOT DISTINCT FROM j.sh", "tau_ms"),
                      (*v, "i.sh IS DISTINCT FROM j.sh", "cross_host_tau_ms")]
        elif v[0] == "R2" and "j.dip_ext" in v[4]:
            plain.append((*v, vpair, "ext_dst_tau_ms"))
        else:
            plain.append((*v, vpair, "src_tau_ms" if (v[0], v[3]) == ("R1", "j.srch") else "tau_ms"))
    out = []
    for rule, ik, ifl, jk, jfl, why, pair, tau_key in plain + _extra_variants(p):
        # Variant windows (rules.R1.src_tau_ms / ext_ip_tau_ms) fall back to the rule's tau_ms.
        tau = r[rule].get(tau_key) or r[rule]["tau_ms"]
        out.append(f"SELECT i.id AS i, j.id AS j, '{rule}' AS rule, {dt} AS dt_ms, j.rar AS rar, "
                   f"{why} AS why_linked FROM ({_nearest(ik, ifl, jk, jfl, k, pair == DISTINCT_RULES)}) np "
                   f"JOIN _lep_h i ON i.id = np.i JOIN _lep_h j ON j.id = np.j WHERE {_order(tau, dt)} AND {pair}")
    return out


def build_edges_sql(p: dict[str, Any]) -> str:
    """Union of R1-R4 candidates -> weight -> one row per (i, j, rule) (overlapping variants, e.g. R1 i.dst_host and
    j.src_host, emit the same pair; tie-break why_linked) -> top-k preds per (j, rule) and R3 cap per i -> best edge
    per (i, j)."""
    r = p["rules"]
    mult = " ".join(f"WHEN '{k}' THEN {float(v['mult'])}" for k, v in r.items())
    tau = " ".join(f"WHEN '{k}' THEN {float(v['tau_ms'])}" for k, v in r.items())
    k = int(p.get("max_preds_per_rule", 5))
    k3 = int(p.get("r3_max_succs_per_source", 0) or 0)
    union = "\nUNION ALL\n".join(_rule_queries(p))
    return f"""
        WITH c AS ({union}),
        w AS (SELECT i, j, rule, dt_ms, why_linked,
                     round((CASE rule {mult} END) * rar * exp(-dt_ms / (CASE rule {tau} END)), 6) AS weight FROM c),
        uniq AS (SELECT * FROM w QUALIFY row_number() OVER (PARTITION BY i, j, rule
                 ORDER BY weight DESC, why_linked) = 1),
        topk AS (SELECT * FROM uniq QUALIFY row_number() OVER (PARTITION BY j, rule ORDER BY weight DESC, i) <= {k}),
        capped AS (SELECT * FROM topk QUALIFY rule <> 'R3' OR {k3} <= 0
                   OR row_number() OVER (PARTITION BY i, rule ORDER BY weight DESC, j) <= {k3}),
        best AS (SELECT * FROM capped QUALIFY row_number() OVER (PARTITION BY i, j ORDER BY weight DESC, rule) = 1)
        SELECT i, j, rule, weight, CAST(dt_ms AS BIGINT) AS dt_ms, why_linked FROM best"""


def link_episodes(con: duckdb.DuckDBPyConnection, ep_path: Path, hubs_path: Path, out_path: Path,
                  p: dict[str, Any]) -> dict[str, Any]:
    """Compute edges in DuckDB and write them to out_path. Returns counts per rule."""
    _prepare(con, ep_path, hubs_path, p)
    con.execute(f"COPY ({build_edges_sql(p)} ORDER BY i, j) TO '{sql_path(out_path)}' (FORMAT PARQUET)")
    by_rule = dict(con.execute(f"SELECT rule, count(*) FROM read_parquet('{sql_path(out_path)}') GROUP BY rule "
                               "ORDER BY rule").fetchall())
    n_ep = con.execute("SELECT count(*) FROM _lep").fetchone()[0]
    n_hubs = con.execute("SELECT count(*) FROM _hubs").fetchone()[0]
    devices = [r[0] for r in con.execute("SELECT DISTINCT h FROM _dev ORDER BY 1").fetchall()]
    for t in ("_lep_h", "_lep", "_hubs", "_dev"):
        con.execute(f"DROP TABLE IF EXISTS {t}")
    return {"episodes": int(n_ep), "hubs": int(n_hubs), "devices": devices, "edges": int(sum(by_rule.values())),
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
