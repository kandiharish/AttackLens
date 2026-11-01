"""Vendor query semantics for tools/mock_siem.py (stdlib only).

Each vendor's documented behaviour is reproduced where a connector could get it wrong:
- Elastic: sort values are epoch ms for @timestamp; `search_after` is strictly-greater on the full sort tuple (sorting
  on @timestamp alone therefore SKIPS the rest of a tie group, as in real Elasticsearch); missing values sort last;
  from + size <= 10 000; search_after needs a sort of the same length and from = 0; unsupported query types -> 400.
- Splunk export: the search must start with `search` or `|`; earliest inclusive, latest exclusive; results come
  NEWEST FIRST unless the search sorts ascending (`| sort 0 _time`, `| sort _time`, `| reverse`); `| head N`.
- Sentinel (Log Analytics): `order by` / `sort by` default to DESCENDING; rows are capped (PartialError) like the
  real 500 000-row limit; `timespan` ISO-8601 duration or interval.
Unsupported syntax is an error (400), never silently ignored: a connector must not "pass" against a mock that
returned everything.
"""

from __future__ import annotations

import functools
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from mock_siem_store import LONG_MAX, Cand, duration_ms, get_path, iso_ms, parse_iso_ms

MAX_RESULT_WINDOW = 10_000


class QueryError(Exception):
    def __init__(self, msg: str, status: int = 400, kind: str = "illegal_argument_exception") -> None:
        super().__init__(msg)
        self.status, self.kind = status, kind


# ============================================================================= Elastic
def es_time(v: Any, fmt: str | None, now_ms: int) -> int:
    if isinstance(v, bool):
        raise QueryError(f"failed to parse date field [{v}]", kind="parse_exception")
    if isinstance(v, (int, float)):
        return int(v * 1000) if fmt == "epoch_second" else int(v)
    s = str(v).strip()
    if re.fullmatch(r"-?\d+(\.\d+)?", s):
        return int(float(s) * 1000) if fmt == "epoch_second" else int(float(s))
    m = re.fullmatch(r"now((?:[+-]\d+[smhdw])*)(?:/[smhdw])?", s)
    if m:
        t = now_ms
        for sign, n, u in re.findall(r"([+-])(\d+)([smhdw])", m.group(1)):
            t += (1 if sign == "+" else -1) * duration_ms(n, u)
        return t
    ms = parse_iso_ms(s)
    if ms is None:
        raise QueryError(f"failed to parse date field [{s}]", kind="parse_exception")
    return ms


def _as_list(x: Any) -> list[Any]:
    return x if isinstance(x, list) else ([] if x is None else [x])


def es_ts_bounds(q: dict[str, Any] | None, now_ms: int) -> tuple[int | None, int | None]:
    """Inclusive @timestamp bounds implied by range clauses that every hit must satisfy (prefilter only)."""
    lo: int | None = None
    hi: int | None = None
    if not q:
        return lo, hi
    (kind, body), = q.items()
    if kind == "range" and "@timestamp" in body:
        r = body["@timestamp"]
        fmt = r.get("format")
        for op, v in r.items():
            if op in ("gte", "gt"):
                t = es_time(v, fmt, now_ms) + (1 if op == "gt" else 0)
                lo = t if lo is None else max(lo, t)
            elif op in ("lte", "lt"):
                t = es_time(v, fmt, now_ms) - (1 if op == "lt" else 0)
                hi = t if hi is None else min(hi, t)
    elif kind == "bool":
        for sub in _as_list(body.get("must")) + _as_list(body.get("filter")):
            a, b = es_ts_bounds(sub, now_ms)
            lo = a if lo is None else (lo if a is None else max(lo, a))
            hi = b if hi is None else (hi if b is None else min(hi, b))
    return lo, hi


def _values(doc: dict[str, Any], fld: str) -> list[Any]:
    return _as_list(get_path(doc, fld))


def es_match(q: dict[str, Any] | None, doc: dict[str, Any], c: Cand, now_ms: int) -> bool:
    if not q:
        return True
    if len(q) != 1:
        raise QueryError("query malformed, more than one field in a query clause", kind="parsing_exception")
    (kind, body), = q.items()
    if kind == "match_all":
        return True
    if kind == "range":
        (fld, r), = body.items()
        if fld == "@timestamp":
            v, fmt = c.ts, r.get("format")
            if v is None:
                return False
            conv: Callable[[Any], Any] = lambda x: es_time(x, fmt, now_ms)  # noqa: E731
        else:
            vals = [x for x in _values(doc, fld) if isinstance(x, (int, float))]
            if not vals:
                return False
            v, conv = vals[0], float
        ops = {"gte": lambda a, b: a >= b, "gt": lambda a, b: a > b, "lte": lambda a, b: a <= b,
               "lt": lambda a, b: a < b}
        return all(ops[op](v, conv(x)) for op, x in r.items() if op in ops)
    if kind == "term":
        (fld, v), = body.items()
        v = v.get("value") if isinstance(v, dict) else v
        return v in _values(doc, fld)
    if kind == "terms":
        (fld, vs), = body.items()
        return any(x in vs for x in _values(doc, fld))
    if kind == "match":
        (fld, v), = body.items()
        v = str(v.get("query") if isinstance(v, dict) else v).lower()
        return any(v == str(x).lower() or v in str(x).lower().split() for x in _values(doc, fld))
    if kind == "exists":
        return bool(_values(doc, body["field"]))
    if kind == "ids":
        return c.doc_id in body.get("values", [])
    if kind == "bool":
        must = _as_list(body.get("must")) + _as_list(body.get("filter"))
        if not all(es_match(s, doc, c, now_ms) for s in must):
            return False
        if any(es_match(s, doc, c, now_ms) for s in _as_list(body.get("must_not"))):
            return False
        should = _as_list(body.get("should"))
        need = int(body.get("minimum_should_match", 0 if must else 1 if should else 0))
        return sum(es_match(s, doc, c, now_ms) for s in should) >= need
    raise QueryError(f"mock: unsupported query type [{kind}]", kind="parsing_exception")


def es_needs_doc(q: dict[str, Any] | None) -> bool:
    """False if the query only looks at @timestamp (rows can be selected without parsing them)."""
    if not q:
        return False
    (kind, body), = q.items()
    if kind == "match_all":
        return False
    if kind == "range":
        return "@timestamp" not in body
    if kind == "bool":
        subs = sum((_as_list(body.get(k)) for k in ("must", "filter", "must_not", "should")), [])
        return any(es_needs_doc(s) for s in subs)
    return True


def es_sort_spec(sort: Any) -> list[tuple[str, str]]:
    out = []
    for s in _as_list(sort):
        if isinstance(s, str):
            fld, _, order = s.partition(":")
            out.append((fld, order or ("desc" if fld == "_score" else "asc")))
        elif isinstance(s, dict):
            (fld, o), = s.items()
            out.append((fld, (o.get("order", "asc") if isinstance(o, dict) else str(o)).lower()))
    for fld, order in out:
        if order not in ("asc", "desc"):
            raise QueryError(f"Unknown sort order [{order}]", kind="parsing_exception")
    return out


def es_sort_value(fld: str, c: Cand, doc: dict[str, Any] | None) -> Any:
    if fld == "@timestamp":
        return c.ts
    if fld == "_id":
        return c.doc_id
    if fld in ("_doc", "_shard_doc"):
        return c.seq
    vals = _values(doc or {}, fld)
    return vals[0] if vals else None


def es_after_value(fld: str, v: Any, now_ms: int) -> Any:
    return es_time(v, None, now_ms) if fld == "@timestamp" and v is not None else v


class SortKey:
    """Per-field order; missing values (None) sort last in both directions (Elasticsearch default)."""
    __slots__ = ("vals", "orders")

    def __init__(self, vals: list[Any], orders: list[str]) -> None:
        self.vals, self.orders = vals, orders

    def cmp(self, other: "SortKey") -> int:
        for a, b, o in zip(self.vals, other.vals, self.orders):
            if a == b:
                continue
            if a is None:
                return 1
            if b is None:
                return -1
            r = -1 if a < b else 1
            return r if o == "asc" else -r
        return 0

    def __lt__(self, other: "SortKey") -> bool:
        return self.cmp(other) < 0


def es_hit_sort(fld: str, order: str, v: Any) -> Any:
    if v is None and fld == "@timestamp":
        return LONG_MAX if order == "asc" else -LONG_MAX - 1
    return v


# ============================================================================= Splunk
def splunk_time(v: str | None, now_ms: int) -> int | None:
    """earliest/latest -> epoch ms. Epoch seconds, ISO-8601, %m/%d/%Y:%H:%M:%S, relative -24h[@h], now, 0."""
    if v is None or str(v).strip() == "":
        return None
    s = str(v).strip().strip('"')
    if s in ("0", ""):
        return 0 if s == "0" else None
    if s == "now":
        return now_ms
    m = re.fullmatch(r"([+-])(\d+)(s|sec|m|min|h|hr|d|day|w)s?(?:@\w+)?", s)
    if m:
        unit = {"sec": "s", "min": "m", "hr": "h", "day": "d"}.get(m.group(3), m.group(3))
        return now_ms + (1 if m.group(1) == "+" else -1) * duration_ms(m.group(2), unit)
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return round(float(s) * 1000)
    try:
        return round(datetime.strptime(s, "%m/%d/%Y:%H:%M:%S").replace(tzinfo=timezone.utc).timestamp() * 1000)
    except ValueError:
        pass
    ms = parse_iso_ms(s)
    if ms is None:
        raise QueryError(f"Invalid time value '{s}'")
    return ms


def parse_spl(search: str, params: dict[str, str], now_ms: int) -> dict[str, Any]:
    """-> {feed: events|notable, lo, hi_excl, ascending, head}."""
    s = search.strip()
    if not (s.startswith("search ") or s.startswith("|") or s == "search"):
        first = s.split()[0] if s.split() else ""
        raise QueryError(f"Unknown search command '{first.split('=')[0]}'.")
    feed = "notable" if re.search(r"(index\s*=\s*\"?notable\"?|`notable`)", s) else "events"
    earliest, latest = params.get("earliest_time"), params.get("latest_time")
    m = re.search(r"\bearliest\s*=\s*(\"[^\"]*\"|\S+)", s)
    earliest = m.group(1) if m else earliest
    m = re.search(r"\blatest\s*=\s*(\"[^\"]*\"|\S+)", s)
    latest = m.group(1) if m else latest
    asc = bool(re.search(r"\|\s*(sort\s+(0\s+)?\+?_time\b|reverse\b)", s))
    if re.search(r"\|\s*sort\s+(0\s+)?-_time\b", s):
        asc = False
    m = re.search(r"\|\s*head\s+(\d+)", s)
    return {"feed": feed, "lo": splunk_time(earliest, now_ms), "hi_excl": splunk_time(latest, now_ms),
            "ascending": asc, "head": int(m.group(1)) if m else None}


# ============================================================================= Sentinel (KQL subset)
_KQL_CMP = re.compile(r"^TimeGenerated\s*(>=|>|<=|<|==)\s*(.+)$")


def iso_duration_ms(s: str) -> int:
    m = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?", s.strip())
    if not m or not any(m.groups()):
        raise QueryError(f"invalid timespan '{s}'")
    d, h, mi, sec = m.groups()
    return int(d or 0) * 86_400_000 + int(h or 0) * 3_600_000 + int(mi or 0) * 60_000 + round(float(sec or 0) * 1000)


def kql_time(expr: str, now_ms: int) -> int:
    e = expr.strip()
    m = re.fullmatch(r"datetime\(\s*\"?([^\")]+)\"?\s*\)", e)
    if m:
        ms = parse_iso_ms(m.group(1))
        if ms is None:
            raise QueryError(f"invalid datetime literal {e}")
        return ms
    m = re.fullmatch(r"ago\(\s*(\d+)([smhd])\s*\)", e)
    if m:
        return now_ms - duration_ms(m.group(1), m.group(2))
    if e == "now()":
        return now_ms
    raise QueryError(f"mock: unsupported time expression '{e}'")


def timespan_bounds(ts: str | None, now_ms: int) -> tuple[int | None, int | None]:
    """-> (lo inclusive, hi exclusive)."""
    if not ts:
        return None, None
    if "/" in ts:
        a, b = ts.split("/", 1)
        lo = parse_iso_ms(a) if not a.startswith("P") else None
        hi = parse_iso_ms(b) if not b.startswith("P") else None
        if lo is None and hi is not None:
            lo = hi - iso_duration_ms(a)
        if hi is None and lo is not None:
            hi = lo + iso_duration_ms(b)
        if lo is None or hi is None:
            raise QueryError(f"invalid timespan '{ts}'")
        return lo, hi
    return now_ms - iso_duration_ms(ts), now_ms


_KEYSET = re.compile(r"^TimeGenerated\s*>\s*(datetime\([^)]*\))\s+or\s+\(\s*TimeGenerated\s*==\s*(datetime\([^)]*\))"
                     r"\s+and\s+([A-Za-z_]\w*)\s*>\s*\"((?:[^\"\\]|\\.)*)\"\s*\)$")


def _kql_unescape(v: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "r": "\r"}.get(m.group(1), m.group(1)), v)


def resolve_tables(kq: dict[str, Any], known: Any) -> list[str]:
    """Tables of a parsed query that exist in the workspace. Like Log Analytics: `union isfuzzy=true` skips tables
    that do not resolve (an error only when none does); otherwise any unknown table is an error."""
    have = [t for t in kq["tables"] if t in known]
    missing = [t for t in kq["tables"] if t not in known]
    if missing and (not kq.get("fuzzy") or not have):
        raise QueryError(f"Failed to resolve table or column expression named '{missing[0]}'")
    return have


def parse_kql(query: str, now_ms: int) -> dict[str, Any]:
    """-> {table, tables, preds: [(op, ms)], filters: [(col, op, value)], order: asc|desc|None, order_by:
    [(col, dir)], take, project, extend: {new: source col}, keyset: (ts_ms, col, value) | None}.
    Subset: `T` or `union [isfuzzy=true] T1, T2`; where (TimeGenerated comparisons / between, `col ==|=~|!= "v"`,
    and the keyset clause `TimeGenerated > T or (TimeGenerated == T and Col > "v")`); extend X = tostring(Y);
    order|sort by col [asc|desc], ...; take|limit; project."""
    parts = [p.strip() for p in query.strip().split("|")]
    head = parts[0]
    um = re.fullmatch(r"union\s+(isfuzzy\s*=\s*true\s+)?([A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)", head)
    tables = [t.strip() for t in um.group(2).split(",")] if um else [head]
    if not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", t) for t in tables):
        raise QueryError(f"mock: unsupported table expression '{head}'")
    out: dict[str, Any] = {"table": tables[0], "tables": tables, "fuzzy": bool(um and um.group(1)),
                           "preds": [], "filters": [], "order": None,
                           "order_by": [], "take": None, "project": None, "extend": {}, "keyset": None}
    for p in parts[1:]:
        op, _, rest = p.partition(" ")
        rest = rest.strip()
        if op == "where":
            km = _KEYSET.match(rest)
            if km:
                t1, t2 = kql_time(km.group(1), now_ms), kql_time(km.group(2), now_ms)
                if t1 != t2:
                    raise QueryError("mock: keyset clause must use the same timestamp twice")
                if km.group(3) not in out["extend"]:
                    raise QueryError(f"Failed to resolve scalar expression named '{km.group(3)}'")
                out["keyset"] = (t1, km.group(3), _kql_unescape(km.group(4)))
                continue
            for cond in re.split(r"\s+and\s+", rest):
                cond = cond.strip()
                m = re.fullmatch(r"TimeGenerated\s+between\s*\(\s*(.+?)\s*\.\.\s*(.+?)\s*\)", cond)
                if m:
                    out["preds"] += [(">=", kql_time(m.group(1), now_ms)), ("<=", kql_time(m.group(2), now_ms))]
                    continue
                m = _KQL_CMP.match(cond)
                if m:
                    out["preds"].append((m.group(1), kql_time(m.group(2), now_ms)))
                    continue
                m = re.fullmatch(r"([A-Za-z_]\w*)\s*(==|=~|!=)\s*\"([^\"]*)\"", cond)
                if m:
                    out["filters"].append(m.groups())
                    continue
                raise QueryError(f"mock: unsupported where clause '{cond}'")
        elif op == "extend":
            for asg in rest.split(","):
                m = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*=\s*(?:tostring\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))\s*", asg)
                if not m:
                    raise QueryError(f"mock: unsupported extend '{asg.strip()}'")
                out["extend"][m.group(1)] = m.group(2) or m.group(3)
        elif op in ("order", "sort"):
            if not rest.startswith("by "):
                raise QueryError(f"mock: unsupported '{p}'")
            keys = []
            for k in rest[3:].split(","):
                m = re.fullmatch(r"\s*([A-Za-z_]\w*)(?:\s+(asc|desc))?\s*", k)
                if not m:
                    raise QueryError(f"mock: unsupported '{p}'")
                keys.append((m.group(1), m.group(2) or "desc"))  # KQL default is descending
            if keys[0][0] != "TimeGenerated":
                raise QueryError(f"mock: order must start with TimeGenerated: '{p}'")
            out["order"], out["order_by"] = keys[0][1], keys
        elif op in ("take", "limit"):
            out["take"] = int(rest)
        elif op == "project":
            out["project"] = [c.strip() for c in rest.split(",") if c.strip()]
        else:
            raise QueryError(f"mock: unsupported KQL operator '{op}'")
    return out


def kql_post(kq: dict[str, Any], rows: list[tuple[int | None, dict[str, Any]]]) -> list[dict[str, Any]]:
    """extend, keyset filter and the full `order by` on (ts_ms, row) pairs already filtered by preds/filters."""
    out = []
    for ts, r in rows:
        if kq["extend"]:
            r = {**r, **{new: (None if r.get(src) is None else str(r.get(src))) for new, src in kq["extend"].items()}}
        if kq["keyset"] is not None:
            t, col, v = kq["keyset"]
            if ts is None or not (ts > t or (ts == t and str(r.get(col) or "") > v)):
                continue
        out.append((ts, r))
    for col, d in reversed(kq["order_by"]):                       # stable multi-key sort, last key first
        if col == "TimeGenerated":
            out.sort(key=lambda x: (x[0] is None, x[0] or 0), reverse=d == "desc")
        else:
            out.sort(key=lambda x: str(x[1].get(col) or ""), reverse=d == "desc")
    return [r for _, r in out]


def kql_pred_ok(ts: int | None, preds: list[tuple[str, int]]) -> bool:
    if ts is None:
        return not preds
    ops = {">=": ts.__ge__, ">": ts.__gt__, "<=": ts.__le__, "<": ts.__lt__, "==": ts.__eq__}
    return all(ops[o](v) for o, v in preds)


def kql_bounds(preds: list[tuple[str, int]]) -> tuple[int | None, int | None]:
    lo = max((v + (o == ">") for o, v in preds if o in (">", ">=", "==")), default=None)
    hi = min((v - (o == "<") for o, v in preds if o in ("<", "<=", "==")), default=None)
    return lo, hi


# ============================================================================= alert fixture -> vendor shapes
SENTINEL_TACTIC = {"Initial Access": "InitialAccess", "Execution": "Execution", "Persistence": "Persistence",
                   "Privilege Escalation": "PrivilegeEscalation", "Defense Evasion": "DefenseEvasion",
                   "Credential Access": "CredentialAccess", "Discovery": "Discovery",
                   "Lateral Movement": "LateralMovement", "Collection": "Collection",
                   "Command and Control": "CommandAndControl", "Exfiltration": "Exfiltration", "Impact": "Impact"}
SENTINEL_SEVERITY = {"low": "Low", "medium": "Medium", "high": "High", "critical": "High"}


def elastic_alert(a: dict[str, Any]) -> dict[str, Any]:
    threat = []
    if a.get("technique"):
        tech = {"id": a["technique"], "name": a["technique_name"],
                "reference": f"https://attack.mitre.org/techniques/{a['technique']}/"}
        if a.get("sub_technique"):
            tech["subtechnique"] = [{"id": a["sub_technique"], "name": a["sub_technique_name"],
                                     "reference": "https://attack.mitre.org/techniques/"
                                                  + a["sub_technique"].replace(".", "/") + "/"}]
        threat = [{"framework": "MITRE ATT&CK", "tactic": {"id": a["tactic_id"], "name": a["tactic"],
                   "reference": f"https://attack.mitre.org/tactics/{a['tactic_id']}/"}, "technique": [tech]}]
    d = {"@timestamp": a["ts"], "kibana.alert.uuid": f"mock-alert-{a['id']}",
         "kibana.alert.original_time": a["ts"], "kibana.alert.rule.name": a["name"],
         "kibana.alert.rule.rule_id": f"mock-rule-{a['id']}", "kibana.alert.rule.uuid": f"mock-rule-uuid-{a['id']}",
         "kibana.alert.severity": a["severity"], "kibana.alert.risk_score": a["risk"],
         "kibana.alert.status": "active", "kibana.alert.workflow_status": "open",
         "kibana.alert.rule.threat": threat, "host.name": a["host"], "user.name": a["user"]}
    if a.get("src_ip"):
        d["source.ip"] = a["src_ip"]
    if a.get("dst_ip"):
        d["destination.ip"] = a["dst_ip"]
    return d


def splunk_notable(a: dict[str, Any], ts_ms: int) -> dict[str, Any]:
    r: dict[str, Any] = {"_time": iso_ms(ts_ms, "+00:00"), "event_id": f"mock-notable-{a['id']}",
                         "rule_name": a["name"], "search_name": f"Threat - {a['name']} - Rule",
                         "urgency": a["severity"], "risk_score": str(a["risk"]), "dest": a["host"],
                         "user": a["user"], "index": "notable", "sourcetype": "stash", "status_label": "New"}
    if a.get("technique"):
        ids = [a["technique"]] + ([a["sub_technique"]] if a.get("sub_technique") else [])
        r["annotations.mitre_attack"] = ids
        r["annotations.mitre_attack.mitre_tactic_id"] = [a["tactic_id"]]
        r["annotations.mitre_attack.mitre_tactic"] = [a["tactic"].lower().replace(" ", "-")]
    if a.get("src_ip"):
        r["src"] = a["src_ip"]
    if a.get("dst_ip"):
        r["dest_ip"] = a["dst_ip"]
    r["_raw"] = json.dumps({k: v for k, v in r.items() if not k.startswith("_")}, separators=(",", ":"))
    return r


SECURITY_ALERT_COLUMNS = [
    ("TimeGenerated", "datetime"), ("DisplayName", "string"), ("AlertName", "string"), ("AlertSeverity", "string"),
    ("Description", "string"), ("ProviderName", "string"), ("VendorName", "string"), ("ProductName", "string"),
    ("SystemAlertId", "string"), ("AlertType", "string"), ("CompromisedEntity", "string"), ("Tactics", "string"),
    ("Techniques", "string"), ("SubTechniques", "string"), ("StartTime", "datetime"), ("EndTime", "datetime"),
    ("Entities", "string"), ("ExtendedProperties", "string"), ("Status", "string"), ("Type", "string")]
EVENT_COLUMNS = [("TimeGenerated", "datetime"), ("Computer", "string"), ("RawData", "string"),
                 ("_ItemId", "string"), ("Type", "string")]


def sentinel_alert_row(a: dict[str, Any]) -> dict[str, Any]:
    ents = [{"$id": "1", "Type": "host", "HostName": a["host"]}, {"$id": "2", "Type": "account", "Name": a["user"]}]
    if a.get("src_ip"):
        ents.append({"$id": "3", "Type": "ip", "Address": a["src_ip"]})
    if a.get("dst_ip"):
        ents.append({"$id": "4", "Type": "ip", "Address": a["dst_ip"]})
    return {"TimeGenerated": a["ts"], "DisplayName": a["name"], "AlertName": a["name"],
            "AlertSeverity": SENTINEL_SEVERITY[a["severity"]], "Description": a["name"],
            "ProviderName": "ASI Scheduled Alerts", "VendorName": "Microsoft",
            "ProductName": "Azure Sentinel", "SystemAlertId": f"mock-sa-{a['id']}", "AlertType": f"mock_{a['id']}",
            "CompromisedEntity": a["host"], "Tactics": SENTINEL_TACTIC.get(a["tactic"] or "", ""),
            "Techniques": json.dumps([a["technique"]] if a.get("technique") else []),
            "SubTechniques": json.dumps([a["sub_technique"]] if a.get("sub_technique") else []),
            "StartTime": a["ts"], "EndTime": a["ts"], "Entities": json.dumps(ents),
            "ExtendedProperties": json.dumps({"Query Period": "05:00:00"}), "Status": "New",
            "Type": "SecurityAlert", "_ItemId": f"mock-item-{a['id']}"}   # _ItemId is hidden: not a column


def sort_cands(cands: Iterable[Cand], ascending: bool) -> list[Cand]:
    def key(a: Cand, b: Cand) -> int:
        ka = (a.ts if a.ts is not None else LONG_MAX, a.seq)
        kb = (b.ts if b.ts is not None else LONG_MAX, b.seq)
        return (ka > kb) - (ka < kb)
    return sorted(cands, key=functools.cmp_to_key(key), reverse=not ascending)
