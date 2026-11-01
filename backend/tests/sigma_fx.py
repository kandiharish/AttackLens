"""Sigma test helpers (not a test module).

- rule_doc(detection, ...) -> one Sigma rule as a dict; write_rules() dumps it with yaml.safe_dump, so YAML quoting
  can never change a value under test.
- compile_docs(tmp, docs) -> sigma_rules.compile_dir() output against the shipped config/sigma_map.yaml.
- events_con(rows) -> in-memory DuckDB with a typed `events` table (canonical columns, tiny fixtures).
- matches(out, rows) -> {rule_id: [source_seq, ...]} evaluated through the rule's rendered `where` directly AND the
  production grouped DISTINCT-tuple path (sigma_detect._run_group) in every PREFILTER_MODES mode (plain, and the
  sigma_prefilter row filter forced on with value fields only / direct fields only); all must agree.
- run_sigma(tmp, docs, rows, ...) -> (stats, al_raw rows): sigma_detect.run() end to end on a tiny table.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import duckdb
import yaml

from attacklens import config, detect_sql, sigma_detect, sigma_rules
from attacklens.detect_sql import RAW_ALERT_COLUMNS
from attacklens.schemas import CANONICAL_COLUMNS

from .conftest import insert_rows

T0 = 1792807200000          # 2026-10-24T02:00:00Z
PROC_WIN = {"category": "process_creation", "product": "windows"}
NET_WIN = {"category": "network_connection", "product": "windows"}
SEC_WIN = {"product": "windows", "service": "security"}
LABEL_COLUMNS = frozenset({"threat", "rule", "labels", "labels_extra", "event.kind", "event.severity", "event_kind",
                           "event_severity"})


def rid(n: int) -> str:
    """AttackLens id of rule_doc(n=...): sigma_ + first 8 hex chars of the uuid without dashes."""
    return f"sigma_{n:08x}"


def rule_doc(detection: dict[str, Any], *, n: int = 1, logsource: dict[str, Any] | None = None,
             tags: tuple[str, ...] | list[str] = ("attack.execution", "attack.t1059.001"),
             level: str | None = "high", status: str = "test", title: str | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = {"title": title or f"fx rule {n}", "id": f"{n:08x}-0000-4000-8000-000000000000",
                           "status": status, "logsource": dict(logsource or PROC_WIN), "detection": detection,
                           "tags": list(tags)}
    if level is not None:
        doc["level"] = level
    return doc


def _fresh_dir(base: Path, stem: str) -> Path:
    k = 0
    while (base / f"{stem}{k}").exists():
        k += 1
    d = base / f"{stem}{k}"
    d.mkdir(parents=True)
    return d


def write_rules(base: Path, docs: list[dict[str, Any]]) -> Path:
    d = _fresh_dir(base, "rules")
    for i, doc in enumerate(docs):
        (d / f"r{i:03d}.yml").write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return d


def base_cfg() -> dict[str, Any]:
    return config.load_config()      # conftest caches the parse and hands out deep copies


def shipped_smap() -> dict[str, Any]:
    return {k: v for k, v in base_cfg()["sigma_map"].items() if k != "disable"}


def compile_docs(base: Path, docs: list[dict[str, Any]], smap: dict[str, Any] | None = None,
                 check_batch: int = 400) -> dict[str, Any]:
    return sigma_rules.compile_dir(write_rules(base, docs), smap if smap is not None else shipped_smap(),
                                   base_cfg()["attack"], check_batch)


def compile_one(base: Path, detection: dict[str, Any], smap: dict[str, Any] | None = None,
                **kw: Any) -> dict[str, Any]:
    out = compile_docs(base, [rule_doc(detection, **kw)], smap)
    assert out["skipped"] == [], out["skipped"]
    assert len(out["rules"]) == 1
    return out


def skip_reason(base: Path, doc: dict[str, Any], smap: dict[str, Any] | None = None) -> str:
    out = compile_docs(base, [doc], smap)
    assert out["rules"] == [], [r["where"] for r in out["rules"]]
    assert len(out["skipped"]) == 1, out["skipped"]
    return str(out["skipped"][0]["reason"])


def events_con(rows: list[dict[str, Any]]) -> duckdb.DuckDBPyConnection:
    """rows -> `events` table. Defaults: ts_ms T0 + i s, ts_ok true, source_type ecs_json, source_seq i + 1,
    action proc_start, raw_line 'line <seq>'."""
    unknown = {k for r in rows for k in r} - set(CANONICAL_COLUMNS)
    assert not unknown, f"not canonical columns: {sorted(unknown)}"
    con = duckdb.connect()
    con.execute("SET TimeZone='UTC'")
    con.execute("SET threads=1")
    cols = list(CANONICAL_COLUMNS)
    con.execute("CREATE TABLE events (" + ", ".join(f'"{c}" {t}' for c, t in CANONICAL_COLUMNS.items()) + ")")
    full = []
    for i, r in enumerate(rows):
        r = {"ts_ms": T0 + i * 1000, "ts_ok": True, "source_type": "ecs_json", "source_seq": i + 1,
             "action": "proc_start", **r}
        r.setdefault("raw_line", f"line {r['source_seq']}")
        full.append([r.get(c) for c in cols])
    insert_rows(con, "events", list(CANONICAL_COLUMNS.items()), full)
    detect_sql.register_macros(con)
    return con


def _hits_table(con: duckdb.DuckDBPyConnection) -> None:
    cols = ", ".join(f"{c} {RAW_ALERT_COLUMNS.get(c, 'VARCHAR')}" for c in sigma_detect.HIT_COLUMNS)
    con.execute(f"CREATE OR REPLACE TEMP TABLE al_sigma_hits ({cols}, raw_line VARCHAR, rule_ids VARCHAR[])")


def _direct(con: duckdb.DuckDBPyConnection, out: dict[str, Any]) -> dict[str, list[int]]:
    return {r["id"]: [int(x[0]) for x in con.execute(
        f"SELECT source_seq FROM events WHERE CAST(ts_ok AS BOOLEAN) AND ({r['where']}) ORDER BY 1").fetchall()]
        for r in out["rules"]}


def direct_matches(out: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, list[int]]:
    """Like matches(), through each rule's rendered `where` only (no production cross-check)."""
    con = events_con(rows)
    try:
        return _direct(con, out)
    finally:
        con.close()


# _run_group keyword sets matches() cross-checks: the plain path, then the prefilter forced on (min_rows 0) with
# every field a value field, and with every field a direct field (fixtures are tiny: the defaults would skip it)
PREFILTER_MODES: tuple[dict[str, int], ...] = (
    {"max_terms": 0},
    {"max_terms": 100_000, "min_rows": 0, "direct_max_leaves": 0},
    {"max_terms": 100_000, "min_rows": 0, "direct_max_leaves": 100_000},
)


def grouped_matches(con: duckdb.DuckDBPyConnection, out: dict[str, Any], **kw: int) -> dict[str, list[int]]:
    """{rule_id: sorted source_seq} through the production grouped path (sigma_detect._run_group with kw)."""
    _hits_table(con)
    groups: dict[str, list[dict[str, Any]]] = {}
    for r in out["rules"]:
        groups.setdefault(r["gate"], []).append(r)
    for gate, rules in groups.items():
        sigma_detect._run_group(con, gate, rules, out["exprs"], 250, 301, **kw)
    grouped: dict[str, list[int]] = {r["id"]: [] for r in out["rules"]}
    for seq, ids in con.execute("SELECT source_seq, rule_ids FROM al_sigma_hits").fetchall():
        for i in ids:
            grouped[i].append(int(seq))
    return {k: sorted(v) for k, v in grouped.items()}


def matches(out: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, list[int]]:
    """{rule_id: sorted matching source_seq} for every compiled rule; asserts direct == grouped production path."""
    con = events_con(rows)
    try:
        direct = _direct(con, out)
        for mode in PREFILTER_MODES:
            grouped = grouped_matches(con, out, **mode)
            assert direct == grouped, (mode, direct, grouped)
        return direct
    finally:
        con.close()


def seqs(base: Path, detection: dict[str, Any], rows: list[dict[str, Any]], **kw: Any) -> list[int]:
    """Matching source_seq (1-based row numbers) of one compiled rule over rows."""
    out = compile_one(base, detection, **kw)
    return matches(out, rows)[out["rules"][0]["id"]]


def sigma_cfg(base: Path, docs: list[dict[str, Any]], **sigma: Any) -> dict[str, Any]:
    cfg = base_cfg()
    cfg["pipeline"]["sigma"] = {**(cfg["pipeline"].get("sigma") or {}), "enabled": True,
                                "dir": str(write_rules(base, docs)), "cache_dir": str(base / "cache"), **sigma}
    return cfg


def native_alert(seq: int, technique: str, tactic: str, host: str, rule_id: str = "native_fx") -> dict[str, Any]:
    from attacklens.schemas import TACTIC_IDX
    a = {c: None for c in RAW_ALERT_COLUMNS}
    a.update({"rule_id": rule_id, "technique_id": technique, "technique_name": "fx", "tactic": tactic,
              "tactic_idx": TACTIC_IDX[tactic], "severity": 80, "ts_ms": T0, "last_ts_ms": T0, "source_seq": seq,
              "host": host, "subject_host": host, "raw_alert_count": 1, "evidence_lines": ["fx"],
              "source_keys": [seq]})
    return a


def run_sigma(cfg: dict[str, Any], rows: list[dict[str, Any]], native: list[dict[str, Any]] | tuple = (),
              live: bool = False, work_dir: Path | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """sigma_detect.run over rows, after optional native al_raw rows. Returns (stats, al_raw rows sorted)."""
    con = events_con(rows)
    try:
        detect_sql.prepare(con, cfg)
        cols = list(RAW_ALERT_COLUMNS)
        con.execute("CREATE OR REPLACE TEMP TABLE al_raw (" + ", ".join(f"{c} {t}" for c, t in
                                                                       RAW_ALERT_COLUMNS.items()) + ")")
        for a in native:
            con.execute(f"INSERT INTO al_raw VALUES ({', '.join('?' for _ in cols)})", [a[c] for c in cols])
        stats = sigma_detect.run(con, cfg, dict(cfg["rules"]["thresholds"]), work_dir, live=live)
        cur = con.execute("SELECT * FROM al_raw ORDER BY rule_id, ts_ms, source_seq")
        names = [d[0] for d in cur.description]
        return stats, [dict(zip(names, r)) for r in cur.fetchall()]
    finally:
        con.close()
