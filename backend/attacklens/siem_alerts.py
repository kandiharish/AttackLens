"""Alert-input mode: SIEM alerts -> raw_alerts rows (DEVELOPMENT.md §15.4 columns).

- map_alert(): one vendor alert (dict) -> a raw_alerts row, or a drop reason. Connectors call it and write the
  rows as JSON lines into the alert spool (integrations.yaml spool.alerts_dir); nothing is lost silently.
- union_into(): called by detect.run when ctx.siem_alerts is True; unions the spool into the al_raw temp table
  so episodes / link / incidents work unchanged. rule_id = "siem:<vendor>:<rule name>" tags the origin.

Vendor MITRE labels are read ONLY here (alert-input mode). The scored eval run never enables it: run.py refuses
--siem-alerts together with --ground-truth, and union_into raises if a ground truth is set.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import unicodedata
from typing import Any

import duckdb

from attacklens import integrations as ig
from attacklens.detect_sql import RAW_ALERT_COLUMNS, sql_path
from attacklens.schemas import TACTIC_IDX

log = logging.getLogger(__name__)

TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_TACTIC_KEY = {re.sub(r"[^a-z]", "", t.lower()): t for t in TACTIC_IDX}


class EvalGuardError(RuntimeError):
    """SIEM alert input was requested for a run with ground truth (the eval must stay raw-events-only)."""


def norm_user(v: Any) -> str | None:
    if v is None:
        return None
    s = unicodedata.normalize("NFC", str(v)).strip().lower()
    s = s.rsplit("\\", 1)[-1].split("@", 1)[0]
    return s if s and s not in ("-", "n/a", "none") else None


def norm_host(v: Any) -> str | None:
    s = str(v).strip().lower() if v is not None else ""
    return s if s and s != "-" else None


def norm_ip(v: Any) -> str | None:
    s = str(v).strip() if v is not None else ""
    return s if s and s != "-" else None


def severity_of(v: Any, acfg: dict[str, Any]) -> int:
    default = int(acfg.get("default_severity", 60))
    if v is None or v == "":
        return default
    smap = {str(k).lower(): int(x) for k, x in (acfg.get("severity_map") or {}).items()}
    s = str(v).strip().lower()
    if s in smap:
        return smap[s]
    try:
        n = float(s)
    except ValueError:
        return default
    return int(max(0, min(100, n * 10 if n <= 10 else n)))


def pick_technique(values: list[Any], techniques: dict[str, Any]) -> str | None:
    """Most specific technique id found in the vendor values that exists in attack_v20.json (a sub-technique
    unknown to the subset falls back to its parent)."""
    found: list[str] = []
    for v in values:
        found += TECH_RE.findall(v if isinstance(v, str) else json.dumps(v, default=str))
    for tid in sorted(dict.fromkeys(found), key=lambda t: ("." not in t, found.index(t))):
        if tid in techniques:
            return tid
        if tid.split(".")[0] in techniques:
            return tid.split(".")[0]
    return None


def tactic_for(tid: str, vendor_tactics: list[Any], attack: dict[str, Any]) -> str:
    """The vendor's tactic if it is a v20 tactic of this technique, else the technique's default tactic."""
    info = (attack.get("techniques") or {}).get(tid) or {}
    allowed = set(info.get("tactics") or [info.get("tactic")])
    # Sentinel SecurityAlert writes Tactics as ONE comma-separated string ("InitialAccess, Persistence")
    for v in (p for x in vendor_tactics for p in (str(x).split(",") if isinstance(x, str) else [x])):
        name = _TACTIC_KEY.get(re.sub(r"[^a-z]", "", str(v).lower()))
        if name and name in allowed:
            return name
    return str(info.get("tactic"))


def source_seq(vendor: str, alert_id: Any, doc: dict[str, Any]) -> int:
    key = f"{vendor}|{alert_id}" if alert_id not in (None, "") else \
        f"{vendor}|{json.dumps(doc, sort_keys=True, default=str)}"
    return int(hashlib.sha1(key.encode("utf-8")).hexdigest()[:15], 16)


def map_alert(doc: dict[str, Any], vendor: str, fields: dict[str, Any], cfg: dict[str, Any],
              ts_ms: int | None) -> tuple[dict[str, Any] | None, str | None]:
    """-> (raw_alerts row, None) or (None, drop reason)."""
    acfg = ig.icfg(cfg).get("alert_input") or {}
    attack = cfg.get("attack") or {}
    techniques = attack.get("techniques") or {}
    if ts_ms is None:
        return None, "no_timestamp"
    name = ig.first(doc, fields.get("rule_name"))
    if name is None or not str(name).strip():
        return None, "no_rule_name"
    name = " ".join(str(name).split())[:200]
    tid = pick_technique(ig.all_values(doc, fields.get("technique")), techniques)
    if tid is None:
        low = name.lower()
        for pat, mapped in (acfg.get("rule_technique_map") or {}).items():
            if str(pat).lower() in low:
                tid = str(mapped) if str(mapped) in techniques else None
                break
    if tid is None:
        return None, "no_technique"
    tactic = tactic_for(tid, ig.all_values(doc, fields.get("tactic")), attack)
    if tactic not in TACTIC_IDX:
        return None, "unknown_tactic"
    host = norm_host(ig.first(doc, fields.get("host")))
    src_user, target_user = norm_user(ig.first(doc, fields.get("src_user"))), \
        norm_user(ig.first(doc, fields.get("target_user")))
    src_ip, dst_ip = norm_ip(ig.first(doc, fields.get("src_ip"))), norm_ip(ig.first(doc, fields.get("dst_ip")))
    if not any((host, src_user, target_user, src_ip, dst_ip)):
        return None, "no_entity"
    seq = source_seq(vendor, ig.first(doc, fields.get("id")), doc)
    parts = [f"host={host}" if host else "", f"user={target_user or src_user}" if (target_user or src_user) else "",
             f"src={src_ip}" if src_ip else "", f"dst={dst_ip}" if dst_ip else ""]
    ev = f"{vendor} alert: {name} | {' '.join(p for p in parts if p)}"[: int(acfg.get("evidence_max_chars", 300))]
    tech_name = (techniques.get(tid) or {}).get("name")
    row = {"rule_id": f"siem:{vendor}:{name}", "technique_id": tid.split(".")[0],
           "sub_technique_id": tid if "." in tid else None, "technique_name": tech_name, "tactic": tactic,
           "tactic_idx": TACTIC_IDX[tactic], "severity": severity_of(ig.first(doc, fields.get("severity")), acfg),
           "ts_ms": int(ts_ms), "last_ts_ms": int(ts_ms), "source_seq": seq, "host": host, "subject_host": host,
           "src_host": None, "dst_host": None, "src_user": src_user, "target_user": target_user,
           "src_ip": src_ip, "dst_ip": dst_ip, "raw_alert_count": 1, "evidence_lines": [ev], "source_keys": [seq]}
    return row, None


# ---- detect-stage union ---------------------------------------------------------------------------------------------
def lookback_ms(cfg: dict[str, Any]) -> int:
    from attacklens import live_window as lw

    acfg = ig.icfg(cfg).get("alert_input") or {}
    if acfg.get("lookback_ms"):
        return int(acfg["lookback_ms"])
    return max(lw.longest_ms(cfg.get("rules"), ("_window_ms",)), lw.longest_ms(cfg.get("linking"), ("tau_ms",)))


def union_into(con: duckdb.DuckDBPyConnection, cfg: dict[str, Any], has_ground_truth: bool) -> dict[str, Any]:
    """INSERT the alert spool into al_raw. Window: alerts from the first event in `events` (or, with no events,
    newest alert - lookback) up to now + max_future_skew_s; the rest is counted as outside_window."""
    if has_ground_truth:
        raise EvalGuardError("SIEM alert input is not allowed in a run with ground truth (eval is raw-events-only)")
    d = ig.alerts_spool_dir(cfg)
    stats: dict[str, Any] = {"enabled": True, "dir": d.as_posix(), "rows": 0, "spool_rows": 0, "outside_window": 0,
                             "duplicates_or_malformed": 0}
    files = sorted(p for p in d.rglob("*.jsonl") if not p.name.startswith(".")) if d.is_dir() else []
    stats["files"] = len(files)
    if not files:
        log.info("siem alerts: no spool files under %s", d)
        return stats
    acfg = ig.icfg(cfg).get("alert_input") or {}
    cols = "{" + ", ".join(f"'{c}': '{t}'" for c, t in RAW_ALERT_COLUMNS.items()) + "}"
    glob = sql_path((d / "**" / "*.jsonl").as_posix())
    con.execute(f"CREATE OR REPLACE TEMP TABLE al_siem AS SELECT DISTINCT * FROM read_json({glob}, "
                f"format='newline_delimited', columns={cols}, ignore_errors=true)")
    lines = con.execute(f"SELECT count(*) FROM read_csv({glob}, columns={{'l': 'VARCHAR'}}, header=false, "
                        f"delim='\\0', quote='', escape='', auto_detect=false, ignore_errors=true)").fetchone()[0]
    n_all = con.execute("SELECT count(*) FROM al_siem").fetchone()[0]
    stats["spool_rows"] = int(lines)
    stats["duplicates_or_malformed"] = max(0, int(lines) - int(n_all))
    ev_min = con.execute("SELECT min(ts_ms) FROM events WHERE CAST(ts_ok AS BOOLEAN)").fetchone()[0]
    lo = int(ev_min) if ev_min is not None else \
        int(con.execute("SELECT coalesce(max(ts_ms), 0) FROM al_siem").fetchone()[0]) - lookback_ms(cfg)
    hi = ig.now_ms() + int(float(acfg.get("max_future_skew_s", 300)) * 1000)
    cond = f"ts_ms IS NOT NULL AND rule_id LIKE 'siem:%' AND ts_ms >= {lo} AND ts_ms <= {hi}"
    # entity resolution as in detect_sql.finish(): IP -> host via al_ip_host; subject = host, else src host
    con.execute(f"""INSERT INTO al_raw BY NAME
        SELECT s.* REPLACE (coalesce(s.subject_host, sh.host, s.src_ip) AS subject_host,
                            coalesce(s.src_host, sh.host) AS src_host, coalesce(s.dst_host, dh.host) AS dst_host)
        FROM al_siem s LEFT JOIN al_ip_host sh ON sh.ip = s.src_ip LEFT JOIN al_ip_host dh ON dh.ip = s.dst_ip
        WHERE {cond}""")
    n = con.execute(f"SELECT count(*) FROM al_siem WHERE {cond}").fetchone()[0]
    stats["rows"] = int(n)
    stats["outside_window"] = int(n_all) - int(n)
    con.execute("DROP TABLE IF EXISTS al_siem")
    log.info("siem alerts: %s", stats)
    return stats
