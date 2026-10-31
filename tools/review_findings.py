"""Markdown findings summary for a pipeline output dir (DEVELOPMENT.md §15.9: real tiers have no ground truth).

    python tools/review_findings.py --out data/out/<set> [--md reports/stress/<set>_findings.md] [--top 10] [--redact-ips]

Reads incidents_index.json, incidents/*.json, run_metrics.json, ingest_accounting.json, suppressed.json and
work/raw_alerts.parquet (DuckDB, read only). The per-incident checklist gives HINTS for the human false-alarm review,
never a score.

CONFIDENTIALITY: the report contains entities (hosts, IPs, users), technique ids/names, rule ids, counts and times
only. It never reads evidence lines, raw_line, narratives or entry summaries. --redact-ips replaces every public IP
with a stable placeholder (ext-1, ext-2, ... in order of first appearance) so the report can be shared.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
    "::1/128", "fc00::/7", "fe80::/10")]
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def ip_kind(value: str | None) -> str | None:
    """'internal' / 'external' for an IP literal, None for anything else (host names, users)."""
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return "internal" if any(ip in n for n in INTERNAL_NETS) else "external"


class Redactor:
    """Stable ext-N placeholders for external IPs (identity when disabled)."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.map: dict[str, str] = {}

    def __call__(self, value: Any) -> str:
        s = "" if value is None else str(value)
        if self.enabled and ip_kind(s) == "external":
            s = self.map.setdefault(s, f"ext-{len(self.map) + 1}")
        return s


def cell(value: Any, limit: int = 80) -> str:
    """Safe Markdown table cell: no control chars / newlines, pipes escaped, bounded length."""
    s = _CTRL.sub("", "" if value is None else str(value)).replace("|", "\\|").replace("`", "'")
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _read(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None


def _span(first: str, last: str) -> str:
    try:
        a = datetime.fromisoformat(first.replace("Z", "+00:00"))
        b = datetime.fromisoformat(last.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return f"{first} → {last}"
    mins = int((b - a).total_seconds() // 60)
    return f"{first} → {last} ({mins // 60} h {mins % 60:02d} min)"


def alerts_per_rule(out: Path) -> list[tuple[str, int, int]] | None:
    p = out / "work" / "raw_alerts.parquet"
    if not p.exists():
        return None
    con = duckdb.connect()
    try:
        con.execute("SET TimeZone='UTC'")
        src = "read_parquet('" + p.as_posix().replace("'", "''") + "')"
        rows = con.execute(f"SELECT rule_id, count(*), coalesce(sum(raw_alert_count), 0) FROM {src} "
                           "GROUP BY rule_id ORDER BY 2 DESC, 1").fetchall()
    finally:
        con.close()
    return [(str(r), int(n), int(c)) for r, n, c in rows]


def _steps(inc: dict) -> list[tuple[str, dict]]:
    return [("b", s) for s in inc.get("backbone", [])] + [("br", s) for br in inc.get("branches", []) for s in br]


def checklist(inc: dict, rx: Redactor) -> list[str]:
    steps = _steps(inc)
    tactics = {s.get("tactic") for _, s in steps if s.get("tactic")}
    bb = inc.get("backbone") or []
    entry_ip = (bb[0].get("src_ip") if bb else None)
    ext_entry = ip_kind(entry_ip) == "external"
    by_rule: Counter[str] = Counter()
    for _, s in steps:
        by_rule[str(s.get("rule_id") or s.get("technique_id"))] += int(s.get("merged_alert_count") or 0)
    total = sum(by_rule.values())
    top_rule, top_n = by_rule.most_common(1)[0] if by_rule else ("-", 0)
    share = 100.0 * top_n / total if total else 0.0
    mark = lambda b: "[x]" if b else "[ ]"  # noqa: E731
    return [
        f"- {mark(len(tactics) >= 2)} multi-tactic ({len(tactics)} distinct tactics)",
        f"- {mark(ext_entry)} external-IP entry point"
        + (f" ({cell(rx(entry_ip))})" if ext_entry else (f" (entry src {cell(rx(entry_ip))})" if entry_ip else "")),
        f"- {mark(share > 80.0)} dominated by one rule (> 80 % of alerts): top rule `{cell(top_rule)}` "
        f"{share:.0f} % of {total} alerts",
        f"- reach-next hosts listed: {len(inc.get('reach_next') or [])}",
    ]


def incident_section(k: int, inc: dict, rx: Redactor) -> list[str]:
    steps = _steps(inc)
    chain: list[str] = []
    for s in inc.get("backbone", []):
        t = s.get("tactic")
        if t and (not chain or chain[-1] != t):
            chain.append(t)
    hosts = sorted({rx(s.get("host")) for _, s in steps if s.get("host")})
    ips = sorted({rx(s.get(f)) for _, s in steps for f in ("src_ip", "dst_ip") if s.get(f)})
    users = sorted({str(s.get("user")) for _, s in steps if s.get("user")})
    n_bb = len(inc.get("backbone") or [])
    lines = [
        f"### {k}. {cell(inc.get('id'))} — risk {inc.get('risk')}",
        "",
        f"- Time span: {cell(_span(inc.get('first_ts', ''), inc.get('last_ts', '')), 120)}",
        f"- Tactic chain: {cell(' → '.join(chain), 300)}",
        f"- Steps: {n_bb} on the path + {len(steps) - n_bb} on branches; {inc.get('episode_count')} episodes; "
        f"{inc.get('merged_alert_count')} merged alerts",
        f"- Hosts: {cell(', '.join(hosts), 300) or '-'}",
        f"- IPs: {cell(', '.join(ips), 300) or '-'}",
        f"- Users: {cell(', '.join(users), 300) or '-'}",
        "",
        "| # | time | technique | tactic | rule | host | user | src → dst | alerts |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for kind, s in steps:
        tech = s.get("sub_technique_id") or s.get("technique_id")
        name = f" {s.get('technique_name')}" if s.get("technique_name") else ""
        flow = f"{rx(s.get('src_ip')) or '-'} → {rx(s.get('dst_ip')) or '-'}"
        lines.append(f"| {s.get('step')}{'b' if kind == 'br' else ''} | {cell(s.get('ts'))} | {cell(tech)}{cell(name)} "
                     f"| {cell(s.get('tactic'))} | {cell(s.get('rule_id'))} | {cell(rx(s.get('host')))} "
                     f"| {cell(s.get('user'))} | {cell(flow)} | {s.get('merged_alert_count')} |")
    lines += ["", "Review checklist (hints for the human false-alarm review, not a score):", *checklist(inc, rx), ""]
    return lines


def build_report(out: Path, top: int = 10, redact_ips: bool = False) -> str:
    rx = Redactor(redact_ips)
    rm = _read(out / "run_metrics.json") or {}
    acc = _read(out / "ingest_accounting.json") or []
    sup = _read(out / "suppressed.json") or {}
    index = _read(out / "incidents_index.json") or []
    L = [f"# Findings — {cell(rm.get('set') or out.name)}", "",
         "Entities and technique ids only (no evidence or raw log text)."
         + (" Public IPs redacted as ext-N." if redact_ips else ""), "",
         "## Run", "",
         f"- Total wall time: {rm.get('total_wall_s', 'n/a')} s; peak RSS: {rm.get('peak_rss_mb', 'n/a')} MB; "
         f"rows/s: {rm.get('rows_per_s', 'n/a')}", "",
         "| stage | wall s | peak RSS MB |", "|---|---|---|"]
    L += [f"| {cell(s.get('name'))} | {s.get('wall_s')} | {s.get('peak_rss_mb')} |" for s in rm.get("stages") or []]
    L += ["", "## Ingest accounting", "", "| source | rows in | rows ok | dropped | reasons |", "|---|---|---|---|---|"]
    for a in acc if isinstance(acc, list) else []:
        reasons = "; ".join(f"{cell(k)}: {v}" for k, v in (a.get("drop_reasons") or {}).items())
        L.append(f"| {cell(a.get('source_type'))} | {a.get('rows_in')} | {a.get('rows_ok')} | {a.get('dropped')} "
                 f"| {reasons or '-'} |")
    L += ["", "## Alerts per rule", ""]
    apr = alerts_per_rule(out)
    if apr is None:
        L.append("work/raw_alerts.parquet not found.")
    else:
        L += ["| rule | alert rows | raw alerts |", "|---|---|---|"]
        L += [f"| {cell(r)} | {n} | {c} |" for r, n, c in apr]
    st = (rm.get("stage_stats") or {}).get("incidents") or {}
    L += ["", "## Episodes and components", "",
          f"- Episodes kept: {rm.get('episodes', 'n/a')}; spilled: {rm.get('episodes_spilled', 'n/a')}",
          f"- Components: {st.get('components', 'n/a')}; kept: {st.get('kept', 'n/a')}; "
          f"suppressed: {sup.get('total', st.get('suppressed', 'n/a'))}; incidents: {len(index)}"]
    by_reason = sup.get("by_reason") or st.get("suppressed_by_reason") or {}
    if by_reason:
        L += ["", "| suppression reason | components |", "|---|---|"]
        L += [f"| {cell(k)} | {v} |" for k, v in sorted(by_reason.items(), key=lambda kv: -kv[1])]
    L += ["", f"## Top {min(top, len(index))} incidents (by risk)", ""]
    for k, row in enumerate(index[:top], 1):
        inc = _read(out / "incidents" / f"{row.get('id')}.json")
        L += incident_section(k, inc, rx) if isinstance(inc, dict) else [f"### {k}. {cell(row.get('id'))} — file missing", ""]
    return "\n".join(L).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=Path, help="pipeline output dir (data/out/<set>)")
    ap.add_argument("--md", type=Path, help="markdown file to write (default: <out>/findings.md)")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--redact-ips", action="store_true", help="replace public IPs with ext-N placeholders")
    a = ap.parse_args(argv)
    if not a.out.is_dir():
        print(f"no such output dir: {a.out}", file=sys.stderr)
        return 2
    dest = a.md or a.out / "findings.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        f.write(build_report(a.out, a.top, a.redact_ips))
    print(dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
