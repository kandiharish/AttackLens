"""Native cloud detection (reports/cloud/rule_catalog.md): config/rules_cloud.yaml + config/cloud.yaml ->
work/raw_alerts_cloud.parquet with exactly the raw_alerts columns (detect_sql.RAW_ALERT_COLUMNS).

run_cloud(con, cfg, ctx) -> stats. A no-op when the events hold no cloud rows; never raises (errors are logged and
counted). Rules: one id = one detection with labels; `branches` are match predicates or template calls
(detect_cloud_templates / detect_cloud_behaviour). Severity per hit: template / branch severity -> promote
(first-seen second signal) -> cold-start cap -> allowlist and change-window downgrade -> automation downgrade (rules
with `automation`: a CI/CD / IaC identity without a risk signal, cloud.yaml `automation`) -> context cap (rules with
`context: true`, applied after every rule ran so sequences read the full severity) -> per-rule cap.

CLI (no detect.py hook needed): python -m attacklens.detect_cloud --work data/out/<set>/work [--events <glob>]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from attacklens import detect_cloud_ev as cev
from attacklens.detect_cloud_behaviour import BEHAVIOUR_TEMPLATES
from attacklens.detect_cloud_templates import TEMPLATES as BASE_TEMPLATES, Spec
from attacklens.detect_sql import RAW_ALERT_COLUMNS, q, sql_list, sql_path
from attacklens.schemas import TACTIC_IDX

log = logging.getLogger(__name__)

TEMPLATES = {**BASE_TEMPLATES, **BEHAVIOUR_TEMPLATES}
OUT_NAME = "raw_alerts_cloud.parquet"
CLOUDS = ("aws", "azure", "gcp", "k8s")   # k8s = any Kubernetes audit (generic / EKS / AKS); GKE rows are also gcp
CLOUDS += ("okta", "gws", "m365", "auth0", "duo")   # identity SaaS (gws = Google Workspace, both shapes)
SINGLE_SOURCE = ("match", "distinct_burst", "rate_spike", "first_seen", "geo_velocity", "multi_network_session",
                 "new_source_burst")


def _settings(cfg: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    th = dict((cfg.get("rules") or {}).get("thresholds") or {})
    return dict(cfg.get("cloud") or {}), list((cfg.get("rules_cloud") or {}).get("rules") or []), th


def check_rule(rule: dict[str, Any], attack: dict[str, Any]) -> list[str]:
    """Problems with one rule (empty list = valid): labels exist in ATT&CK v20 with a tactic of the technique,
    clouds known, every branch names a known template."""
    rid, errs = rule.get("id"), []
    tech = attack.get("techniques") or {}
    for spec in (rule, rule.get("secondary")):
        if not spec:
            continue
        for key in ("technique", "sub_technique"):
            t = spec.get(key)
            if key == "technique" and not t:
                errs.append(f"{rid}: missing technique")
            elif t and t not in tech:
                errs.append(f"{rid}: {t} not in attack_v20.json")
            elif t and spec.get("tactic") not in (tech[t].get("tactics") or [tech[t].get("tactic")]):
                errs.append(f"{rid}: tactic {spec.get('tactic')!r} is not a tactic of {t}")
        if spec.get("tactic") not in TACTIC_IDX:
            errs.append(f"{rid}: tactic {spec.get('tactic')!r} is not a v20 tactic")
    if "context" in rule and not isinstance(rule["context"], bool):
        errs.append(f"{rid}: context must be true or false")
    if not isinstance(rule.get("automation", {}), (bool, dict)):
        errs.append(f"{rid}: automation must be true or {{severity: <int>}}")
    if not set(rule.get("clouds") or []) <= set(CLOUDS) or not rule.get("clouds"):
        errs.append(f"{rid}: clouds must be a non-empty subset of {CLOUDS}")
    for i, b in enumerate(rule.get("branches") or [None]):
        t = (b or {}).get("template", "match" if (b or {}).get("match") else None)
        if t not in TEMPLATES:
            errs.append(f"{rid}: branch {i}: unknown template {t!r}")
        if (b or {}).get("label") == "secondary" and not rule.get("secondary"):
            errs.append(f"{rid}: branch {i}: label secondary without a secondary label")
    return errs


def load_rules(cfg: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    _, rules, _ = _settings(cfg)
    ok, errs, seen = [], [], set()
    for r in rules:
        e = check_rule(r, cfg.get("attack") or {})
        if r.get("id") in seen:
            e.append(f"{r.get('id')}: duplicate rule id")
        seen.add(r.get("id"))
        (errs.extend(e) if e else ok.append(r))
    return ok, errs


def _resolve(v: Any, params: dict[str, Any]) -> Any:
    """Template param value: "{cfg.x}" alone -> the typed value; other strings -> placeholders expanded."""
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("{cfg.") and s.endswith("}") and s.count("{") == 1:
            key = s[5:-1]
            if key not in params:
                raise ValueError(f"unknown placeholder {s}")
            return params[key]
        return cev.expand(v, params)
    if isinstance(v, list):
        return [_resolve(x, params) for x in v]
    return v


def _gate(b: dict[str, Any]) -> str:
    oc = str(b.get("outcome", "success"))
    return {"success": " AND ok_row", "failure": " AND outcome = 'failure'"}.get(oc, "")


def _ms(iso: str) -> int:
    return int(datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp() * 1000)


def _downgrades(rule: dict[str, Any], cc: dict[str, Any], params: dict[str, Any]) -> list[tuple[str, int]]:
    """[(SQL predicate over hit h, max severity)]: allowlists then change windows. Never drops a hit."""
    out = []
    d = cc.get("default_allow") or {}
    ra = rule.get("allow") or {}
    for lists, sev in ((d.get("lists") or [], d.get("severity", 45)), (ra.get("lists") or [], ra.get("severity", 35))):
        vals = sorted({str(x).lower() for name in lists for x in params.get(name) or []})
        if vals:
            out.append((f"(lower(h.actor) IN {sql_list(vals)} OR h.actor_key IN {sql_list(vals)})", int(sev)))
    for w in cc.get("change_windows") or []:
        pred = f"h.ts_ms BETWEEN {_ms(w['start'])} AND {_ms(w['end'])}"
        if w.get("principals"):
            pred += f" AND lower(h.actor) IN {sql_list([str(x).lower() for x in w['principals']])}"
        out.append((f"({pred})", int(w.get("severity", 45))))
    return out


def automation_cap(rule: dict[str, Any], b: dict[str, Any], cc: dict[str, Any]) -> int | None:
    """Severity cap for automation hits of this rule / branch (None = the rule has no `automation` key)."""
    spec = b.get("automation", rule.get("automation"))
    if not spec:
        return None
    a = cc.get("automation") or {}
    dflt = int(a.get("severity", cc.get("context_severity", 35)))
    return int(spec.get("severity", dflt)) if isinstance(spec, dict) else dflt


def automation_sql(alias: str) -> str:
    """Boolean SQL over hit `alias`: its first event is an automation identity's (cl_auto) and none of the hit's
    events (keys) carries an automation risk signal."""
    return (f"(EXISTS (SELECT 1 FROM cl_auto z WHERE z.source_seq = {alias}.source_seq) AND NOT EXISTS "
            f"(SELECT 1 FROM cl_auto r WHERE r.risky AND list_contains({alias}.keys, r.source_seq)))")


def wrap(rule: dict[str, Any], b: dict[str, Any], hits: str, cc: dict[str, Any], params: dict[str, Any],
         hist: Any, lines: int, chars: int, keys: int) -> str:
    """Hits -> core columns for detect_sql.finish (with severity_override)."""
    label = "secondary" if b.get("label") == "secondary" else "primary"
    base = int(b.get("severity", (rule.get("secondary") or {}).get("severity", rule.get("severity", 50))
                     if label == "secondary" else rule.get("severity", 50)))
    s = f"coalesce(h.sev, {base})"
    prom = (b.get("promote") or rule.get("promote") or {}).get("first_seen")
    if prom and not b.get("no_promote"):
        bd = int(float((cc.get("promote_first_seen") or {}).get("baseline_days", 14)) * cev.DAY_MS)
        cs = cc.get("cold_start") or {}
        bok = cev.baseline_ok_sql("h", "h.ts_ms", "actor_key", hist("actor_key"),
                                  float(cs.get("min_history_days", 3)), int(cs.get("min_actor_events", 50)))
        fs = (f"NOT coalesce(h.machine, false) AND h.actor_key IS NOT NULL AND NOT EXISTS (SELECT 1 FROM cloud_ev z "
              f"WHERE z.actor_key = h.actor_key AND z.api IS NOT DISTINCT FROM h.api AND z.acct IS NOT DISTINCT FROM "
              f"h.acct AND z.ts_ms < h.ts_ms AND z.ts_ms >= h.ts_ms - {bd}) AND {bok}")
        s = f"CASE WHEN {fs} THEN greatest({s}, {int(prom)}) ELSE {s} END"
    cold = int((cc.get("cold_start") or {}).get("severity", 30))
    s = f"CASE WHEN h.baseline_ok = false THEN least({s}, {cold}) ELSE {s} END"
    for pred, cap in _downgrades(rule, cc, params):
        s = f"CASE WHEN {pred} THEN least({s}, {cap}) ELSE {s} END"
    ev, src = "h.ev", f"({hits})"
    acap = automation_cap(rule, b, cc)
    if acap is not None:   # downgraded, never dropped; the first evidence line says why
        src = f"(SELECT h0.*, {automation_sql('h0')} AS _auto FROM ({hits}) h0)"
        s = f"CASE WHEN h._auto THEN least({s}, {acap}) ELSE {s} END"
        note = (f"automation identity (cloud.yaml automation_identity_patterns), no risk signal (known network, "
                f"no denied burst, no attack tool UA): severity capped at {acap}")
        ev = f"CASE WHEN h._auto THEN list_prepend({q(note)}, h.ev) ELSE h.ev END"
    # Host = the event's ingest host (the resource acted on: Azure _ResourceId, AWS account, GCP project), the same
    # entity a Sigma alert on that event gets; the account / subscription (acct) is only the fallback scope.
    return f"""
    SELECT coalesce(h.lbl, {q(label)}) AS label, NULL AS sub_technique_id, h.ts_ms, coalesce(h.last_ts_ms, h.ts_ms)
           AS last_ts_ms, h.source_seq, coalesce(h.host, h.acct) AS host, coalesce(h.host, h.acct) AS subject_host,
           h.src_user, h.target_user, h.src_ip, NULL::VARCHAR AS dst_ip, greatest(coalesce(h.n, 1), 1) AS raw_alert_count,
           list_transform(list_slice(list_filter({ev}, lambda x: x IS NOT NULL), 1, {lines}), lambda x: left(x, {chars}))
               AS evidence_lines,
           list_slice(list_filter(h.keys, lambda x: x IS NOT NULL), 1, {keys}) AS source_keys,
           greatest(0, least(100, {s}))::INTEGER AS severity_override
    FROM {src} h WHERE h.ts_ms IS NOT NULL"""


def finish_cloud(rule: dict[str, Any], core: str, attack: dict[str, Any]) -> str:
    """Core rows (label, severity_override, ...) -> exactly the raw_alerts columns. Labels and technique names are
    resolved here in Python (CASE on the label), so the only join is src_ip -> al_ip_host (src_host); detect_sql.finish
    would add four more joins per branch, which made planning ~5x slower for 130 branch queries."""
    tech = attack.get("techniques") or {}
    specs = {"primary": rule, "secondary": rule.get("secondary") or rule}

    def case(fn: Any) -> str:
        sec, pri = fn(specs["secondary"]), fn(specs["primary"])
        return f"CASE WHEN c.label = 'secondary' THEN {q(sec)} ELSE {q(pri)} END" if sec != pri else q(pri)

    def name(sp: dict[str, Any]) -> str | None:
        t = sp.get("sub_technique") or sp["technique"]
        return (tech.get(t) or tech.get(sp["technique"]) or {}).get("name")

    sev = case(lambda sp: int(sp.get("severity", rule.get("severity", 50))))
    return f"""
    SELECT {q(rule['id'])}::VARCHAR AS rule_id, {case(lambda sp: sp['technique'])}::VARCHAR AS technique_id,
           {case(lambda sp: sp.get('sub_technique'))}::VARCHAR AS sub_technique_id,
           {case(name)}::VARCHAR AS technique_name, {case(lambda sp: sp['tactic'])}::VARCHAR AS tactic,
           {case(lambda sp: TACTIC_IDX[sp['tactic']])}::INTEGER AS tactic_idx,
           coalesce(c.severity_override, {sev})::INTEGER AS severity, c.ts_ms::BIGINT AS ts_ms,
           c.last_ts_ms::BIGINT AS last_ts_ms, c.source_seq::UBIGINT AS source_seq, c.host::VARCHAR AS host,
           c.subject_host::VARCHAR AS subject_host, sh.host::VARCHAR AS src_host, NULL::VARCHAR AS dst_host,
           c.src_user::VARCHAR AS src_user, c.target_user::VARCHAR AS target_user, c.src_ip::VARCHAR AS src_ip,
           NULL::VARCHAR AS dst_ip, c.raw_alert_count::BIGINT AS raw_alert_count,
           c.evidence_lines::VARCHAR[] AS evidence_lines, c.source_keys::UBIGINT[] AS source_keys
    FROM ({core}) c LEFT JOIN al_ip_host sh ON sh.ip = c.src_ip"""


def branch_sql(rule: dict[str, Any], i: int, b: dict[str, Any], cc: dict[str, Any], th: dict[str, Any],
               hist: Any, attack: dict[str, Any] | None = None, cols: tuple[str, ...] = ()) -> str:
    params = cc.get("params") or {}
    t = b.get("template", "match")
    flt = "true"
    if t in SINGLE_SOURCE:
        flt = cev.expand(b.get("match") or b.get("filter") or "true", params) + _gate(b)
    lines, chars = int(th.get("evidence_max_lines", 3)), int(th.get("evidence_max_chars", 300)) + 1
    keys = int(th.get("source_keys_max", 50))
    spec = Spec(rule_id=str(rule["id"]), filter=flt, p={k: _resolve(v, params) for k, v in (b.get("params") or {}).items()},
                base=int(b.get("severity", rule.get("severity", 50))),
                sev=cev.expand(b["severity_sql"], params) if b.get("severity_sql") else None,
                target=cev.expand(b["target"], params) if b.get("target") else None,
                label=cev.expand(b["label_sql"], params) if b.get("label_sql") else None,
                lines=lines, keys=keys, cold=dict(cc.get("cold_start") or {}), hist=hist, cols=cols)
    hits = TEMPLATES[t](spec)
    return finish_cloud(rule, wrap(rule, b, hits, cc, params, hist, lines, chars, keys), attack or {})


def alert_tables(con: duckdb.DuckDBPyConnection) -> None:
    """Empty al_cloud (raw_alerts columns) and the view cl_alerts_ev that sequence sides with a_rules / b_rules read."""
    cols = ", ".join(f"{c} {t}" for c, t in RAW_ALERT_COLUMNS.items())
    con.execute(f"CREATE OR REPLACE TEMP TABLE al_cloud ({cols})")
    # acct (the default sequence join key) is the scope again: the subscription / tenant id of an Azure resource path.
    con.execute("""CREATE OR REPLACE TEMP VIEW cl_alerts_ev AS
        SELECT rule_id, severity, technique_id, tactic, ts_ms, source_seq, host,
               lower(coalesce(nullif(regexp_extract(subject_host, '^/(?:subscriptions|tenants)/([^/]+)', 1), ''),
                              subject_host)) AS acct,
               coalesce(src_user, target_user) AS actor, coalesce(src_user, target_user) AS actor_key, src_user,
               target_user, src_ip, rule_id AS api, false AS machine, evidence_lines[1] AS evl FROM al_cloud""")


def _has_table(con: duckdb.DuckDBPyConnection, name: str) -> bool:
    return bool(con.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name = ?", [name]).fetchone()[0]
                or con.execute("SELECT count(*) FROM duckdb_views() WHERE view_name = ?", [name]).fetchone()[0])


def run_cloud(con: duckdb.DuckDBPyConnection, cfg: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Run every cloud rule; write work/raw_alerts_cloud.parquet. Never raises."""
    t0 = time.perf_counter()
    stats: dict[str, Any] = {"errors": 0, "error_messages": [], "alerts": 0, "parquet": None}
    out = Path(ctx.work_dir) / OUT_NAME
    try:
        cc, _, th = _settings(cfg)
        if not cc.get("enabled", True):
            out.unlink(missing_ok=True)
            return {**stats, "skipped": "disabled"}
        if not _has_table(con, "events"):
            from attacklens.detect_sql import ensure_events
            ensure_events(con, ctx.events_glob)
        stypes = [str(s) for s in cc.get("source_types") or []]
        if not stypes or not con.execute(f"SELECT 1 FROM events WHERE source_type IN {sql_list(stypes)} LIMIT 1"
                                         ).fetchall():
            out.unlink(missing_ok=True)
            return {**stats, "cloud_rows": 0, "skipped": "no cloud rows", "wall_s": round(time.perf_counter() - t0, 3)}
        stats.update(_run(con, cfg, cc, th, out, stats))
    except Exception as exc:  # noqa: BLE001 - the contract is "never raises"
        log.exception("detect_cloud failed")
        stats["errors"] += 1
        stats["error_messages"].append(f"{type(exc).__name__}: {exc}"[:500])
    stats["wall_s"] = round(time.perf_counter() - t0, 3)
    return stats


def _run(con: duckdb.DuckDBPyConnection, cfg: dict[str, Any], cc: dict[str, Any], th: dict[str, Any], out: Path,
         stats: dict[str, Any]) -> dict[str, Any]:
    if not _has_table(con, "al_attack"):
        from attacklens.detect_sql import prepare
        prepare(con, cfg, out.parent)
    rules, errs = load_rules(cfg)
    stats["errors"] += len(errs)
    stats["error_messages"] += errs
    mc = int(th.get("evidence_max_chars", 300)) + 1
    ev = cev.build(con, cc, mc)
    g = ev["geo"]   # runtime flags rules can test: {cfg.geo_ranges_aws} / {cfg.geo_ranges_gcp} / {cfg.geo_asn}
    cc = {**cc, "params": {**cev.runtime_params(cc.get("params")), "geo_asn": bool(g.get("asn_db")),
                           **{f"geo_ranges_{k}": bool(v) for k, v in (g.get("provider_ranges") or {}).items()}}}
    n_auto = cev.automation_table(con, cc)
    made: set[str] = set()

    def hist(col: str) -> str:
        return cev.hist_table(con, col, made)

    alert_tables(con)
    attack = cfg.get("attack") or {}
    cols = tuple(str(c[0]) for c in con.execute("DESCRIBE cloud_ev").fetchall())
    per_rule: dict[str, int] = {}
    secs: dict[str, float] = {}
    for r in rules:
        rid, t1 = str(r["id"]), time.perf_counter()
        for i, b in enumerate(r.get("branches") or []):
            try:
                con.execute(f"INSERT INTO al_cloud BY NAME {branch_sql(r, i, b, cc, th, hist, attack, cols)}")
            except Exception as exc:  # noqa: BLE001 - one bad branch never stops the others
                log.warning("cloud rule %s branch %d failed: %s", rid, i, exc)
                stats["errors"] += 1
                stats["error_messages"].append(f"{rid}[{i}]: {type(exc).__name__}: {str(exc)[:300]}")
        secs[rid] = round(time.perf_counter() - t1, 3)
    ctx_ids = sorted(str(r["id"]) for r in rules if r.get("context") is True)
    if ctx_ids:   # context rules: capped only now, so sequences above read their full severity
        con.execute(f"UPDATE al_cloud SET severity = least(severity, {int(cc.get('context_severity', 35))}) "
                    f"WHERE rule_id IN {sql_list(ctx_ids)}")
    cap = int(cc.get("max_alerts_per_rule", 1000))
    capped = {str(k): int(n) for k, n in con.execute(
        f"SELECT rule_id, count(*) - {cap} FROM al_cloud GROUP BY rule_id HAVING count(*) > {cap}").fetchall()}
    if capped:
        con.execute(f"""CREATE OR REPLACE TEMP TABLE al_cloud AS SELECT * EXCLUDE (_rn) FROM (
            SELECT *, row_number() OVER (PARTITION BY rule_id ORDER BY severity DESC, ts_ms, source_seq) AS _rn
            FROM al_cloud) WHERE _rn <= {cap}""")
    for rid, n in con.execute("SELECT rule_id, count(*) FROM al_cloud GROUP BY rule_id").fetchall():
        per_rule[str(rid)] = int(n)
    con.execute(f"COPY (SELECT {', '.join(RAW_ALERT_COLUMNS)} FROM al_cloud) TO {sql_path(out)} (FORMAT PARQUET)")
    total = sum(per_rule.values())
    log.info("detect_cloud: %d cloud rows, %d alerts from %d rules, %d errors", ev["rows"], total, len(rules),
             stats["errors"])
    return {"cloud_rows": ev["rows"], "dedup_removed": ev["dedup_removed"], "geo": ev["geo"], "rules": len(rules),
            "automation_rows": n_auto, "context_rules": ctx_ids,
            "alerts": total, "alerts_per_rule": {str(r["id"]): per_rule.get(str(r["id"]), 0) for r in rules},
            "capped_by_rule": capped, "rule_seconds": secs, "parquet": str(out)}


def main(argv: list[str] | None = None) -> int:
    from attacklens import db
    from attacklens.config import REPO_ROOT, load_config
    from attacklens.detect_sql import ensure_events, prepare

    ap = argparse.ArgumentParser(description="Run the native cloud rules on an ingested set.")
    ap.add_argument("--work", required=True, help="data/out/<set>/work (raw_alerts_cloud.parquet goes here)")
    ap.add_argument("--events", help="events Parquet glob (default data/parquet/<set>/events/**/*.parquet)")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    pipe = cfg.get("pipeline") or {}
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    events = a.events or (REPO_ROOT / str(pipe.get("parquet_root", "data/parquet")) / work.parent.name / "events"
                          / "**" / "*.parquet").as_posix()
    tmp = Path(str(pipe.get("temp_directory", "data/spill")))
    con = db.connect(memory_limit=str(pipe.get("memory_limit", "5GB")), threads=pipe.get("threads"),
                     temp_directory=tmp if tmp.is_absolute() else REPO_ROOT / tmp)
    try:
        ensure_events(con, events)
        prepare(con, cfg, work)

        class _Ctx:
            work_dir, events_glob = work, events

        st = run_cloud(con, cfg, _Ctx())
    finally:
        con.close()
    out = json.dumps({k: v for k, v in st.items() if k != "rule_seconds"}, indent=1, default=str)
    sys.stdout.write(out + "\n")
    return 1 if st.get("errors") else 0


if __name__ == "__main__":
    raise SystemExit(main())
