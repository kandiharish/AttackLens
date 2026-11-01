r"""Per-source value maps for JSON sources (config/sources.yaml json_sources.<name>), applied in the source's own
SELECT before the shared normalisation (ingest_sql.normalize_sql). Used by the cloud audit-log sources, whose
outcome and action are encoded differently from Windows / ECS:

  outcome_map:            raw outcome (lower-case, trimmed) -> success | failure | null
    values: {"0": success}
    present: failure      # any other non-null value (omit: the raw value passes through to action_map.outcomes)
    absent: success       # no value at all (omit: NULL)
  action_map:             raw event_action (lower-case) -> canonical action, or {success, failure, default} split on
    consolelogin: {success: login_success, failure: login_failed, default: other}   # the mapped outcome
    createuser: user_created          # unmapped names pass through unchanged (-> 'other' unless globally mapped)
  value_regex:            # field -> regex or list of regexes (RE2, group 1). The first regex that matches replaces
    user: ['^arn:aws[a-z-]*:sts::[0-9]*:assumed-role/[^/]+/([^/]+)$']   # the value by its group 1; else unchanged
    src_ip: ['^(\d{1,3}(?:\.\d{1,3}){3}):\d+$']                          # "ip:port" -> ip
  ip_fields: [src_ip]     # keep only values that look like an IPv4 / IPv6 address (cloud callers can be a service
                          # name such as "iam.amazonaws.com" or "private"); applied after value_regex
  max_len: {command_line: 32768}   # characters kept of a long text field (PowerShell script blocks)
  ts_policy:              # timestamp precedence over the fields.ts aliases (Windows sources, see ts_candidates_sql)
    zones: {'$.UtcTime': utc, '$.EventTime': local}   # per alias; default explicit
    naive_tz: null        # IANA zone for naive values; null = a naive value never counts (ts falls to the next alias)
    naive_formats: ['%m/%d/%Y %I:%M:%S %p']           # strptime formats tried after the ISO cast (naive_tz only)

Everything is SQL over the already-extracted strings: no row reaches Python.
"""

from __future__ import annotations

import re
from typing import Any

from attacklens.db import sql_list, sql_str

IP_RX = r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*$"
# A value that names its own zone: clock time followed by Z / +hh / +hhmm / +hh:mm / UTC / GMT.
TZ_RX = r"\d:\d\d(:\d\d([.,]\d+)?)?\s*([Zz]|[+-]\d\d(:?\d\d)?|UTC|GMT)$"
EPOCH_RX = r"^(\d{12,13}|\d{9,10}(\.\d+)?)$"          # epoch ms / s (what ingest_sql.ts_expr reads as UTC)
DOTNET_RX = r"^/Date\((\d{9,13})([+-]\d{4})?\)/$"     # .NET / PowerShell ConvertTo-Json: UTC epoch ms
TS_ZONES = ("utc", "explicit", "local")
TZ_NAME_RX = re.compile(r"^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$")


def _lit(v: Any) -> str:
    return "CAST(NULL AS VARCHAR)" if v is None else sql_str(str(v))


def ts_policy_of(scfg: dict[str, Any]) -> dict[str, Any] | None:
    """Validated ts_policy of a source (None when the source has none: its aliases are read as before)."""
    pol = scfg.get("ts_policy")
    if not pol:
        return None
    zones = {str(k): str(v) for k, v in (pol.get("zones") or {}).items()}
    bad = {k: v for k, v in zones.items() if v not in TS_ZONES}
    if bad:
        raise ValueError(f"ts_policy.zones: unknown zone class {bad} (allowed: {TS_ZONES})")
    tz = pol.get("naive_tz")
    if tz is not None and not TZ_NAME_RX.match(str(tz)):
        raise ValueError(f"ts_policy.naive_tz: not a time zone name: {tz!r}")
    return {"zones": zones, "naive_tz": None if tz is None else str(tz),
            "naive_formats": [str(f) for f in pol.get("naive_formats") or []],
            "skew_warn_s": float(pol.get("skew_warn_s", 300))}


def naive_sql(x: str, pol: dict[str, Any]) -> str:
    """A naive (zone-less) value: epoch-ms DIGITS when naive_tz is configured (local wall clock in that zone; parsed
    from the string, never from a timestamp rendered as text), else NULL. ingest_sql.ts_expr reads the digits."""
    if not pol["naive_tz"]:
        return "CAST(NULL AS VARCHAR)"
    parse = f"try_cast({x} AS TIMESTAMP)"
    if pol["naive_formats"]:
        parse = f"coalesce({parse}, try_strptime({x}, {sql_list(pol['naive_formats'])}))"
    return f"CAST(epoch_ms(timezone({sql_str(pol['naive_tz'])}, {parse})) AS VARCHAR)"


def ts_value_sql(x: str, zone: str, pol: dict[str, Any]) -> str:
    """One timestamp alias -> a string ts_expr parses as true UTC, or NULL when the value does not qualify.
      utc       UTC by definition (Sysmon UtcTime): taken as is, naive allowed
      explicit  needs its own zone (Z / offset / UTC), epoch digits or /Date(ms)/; naive -> naive_sql
      local     a local wall clock (NXLog EventTime): its own zone if present, else naive_sql"""
    if zone == "utc":
        return x
    own = f"regexp_matches({x}, {sql_str(TZ_RX)})"
    if zone == "local":
        return f"CASE WHEN {own} THEN {x} ELSE {naive_sql(x, pol)} END"
    dotnet = f"nullif(regexp_extract({x}, {sql_str(DOTNET_RX)}, 1), '')"
    return (f"CASE WHEN {x} IS NULL THEN CAST(NULL AS VARCHAR) WHEN {own} OR regexp_matches({x}, {sql_str(EPOCH_RX)}) "
            f"THEN {x} WHEN {dotnet} IS NOT NULL THEN {dotnet} ELSE {naive_sql(x, pol)} END")


def ts_candidates_sql(xs: list[str], paths: list[str], pol: dict[str, Any]) -> list[str]:
    """Per alias (same order as fields.ts): the qualified value expression. ts = the first non-NULL one."""
    return [ts_value_sql(x, pol["zones"].get(p, "explicit"), pol) for x, p in zip(xs, paths)]


def _ts_policy_expr(ts: str, scfg: dict[str, Any], pol: dict[str, Any]) -> str:
    """Rebuild json_select's `coalesce(clean(v[i]), ...)` for the ts aliases with the policy applied per alias."""
    paths = [str(p) for p in (scfg.get("fields") or {}).get("ts") or []]
    xs = re.findall(r"nullif\(nullif\(trim\(v\[\d+\]\), ''\), '-'\)", ts)
    if len(xs) != len(paths):
        raise ValueError(f"ts_policy: expected {len(paths)} ts aliases in the ingest SELECT, found {len(xs)}")
    return "coalesce(" + ", ".join(ts_candidates_sql(xs, paths, pol)) + ")"


def outcome_sql(x: str, spec: dict[str, Any]) -> str:
    vals = {str(k).strip().lower(): v for k, v in (spec.get("values") or {}).items()}
    arms = " ".join(f"WHEN {sql_str(k)} THEN {_lit(v)}" for k, v in vals.items())
    present = _lit(spec["present"]) if "present" in spec else x
    lx = f"lower(trim({x}))"
    hit = f"CASE {lx} {arms} END" if arms else "CAST(NULL AS VARCHAR)"
    known = f"list_contains({'[' + ', '.join(sql_str(k) for k in vals) + ']'}, {lx})" if vals else "false"
    return (f"CASE WHEN {x} IS NULL THEN {_lit(spec.get('absent'))} "
            f"WHEN {known} THEN {hit} ELSE {present} END")


def action_sql(a: str, outcome: str, spec: dict[str, Any]) -> str:
    arms = []
    for k, v in spec.items():
        key = sql_str(str(k).strip().lower())
        if isinstance(v, dict):
            arms.append(f"WHEN {key} THEN CASE {outcome} WHEN 'success' THEN {_lit(v.get('success', 'other'))} "
                        f"WHEN 'failure' THEN {_lit(v.get('failure', 'other'))} "
                        f"ELSE {_lit(v.get('default', 'other'))} END")
        else:
            arms.append(f"WHEN {key} THEN {_lit(v)}")
    return f"CASE lower(trim({a})) {' '.join(arms)} ELSE {a} END" if arms else a


def value_regex_sql(x: str, patterns: Any) -> str:
    """First matching pattern's group 1 (NULLIF '' -> keep the value), else the value unchanged."""
    pats = [patterns] if isinstance(patterns, str) else list(patterns or [])
    arms = " ".join(f"WHEN regexp_matches({x}, {sql_str(p)}) "
                    f"THEN coalesce(nullif(regexp_extract({x}, {sql_str(p)}, 1), ''), {x})" for p in pats)
    return f"CASE {arms} ELSE {x} END" if arms else x


def apply_source_maps(vals: dict[str, str], scfg: dict[str, Any]) -> dict[str, str]:
    """vals: intermediate field -> SQL expression (VARCHAR). Returns a copy with the source's maps applied."""
    out = dict(vals)
    pol = ts_policy_of(scfg)
    if pol and "ts" in out:
        out["ts"] = _ts_policy_expr(out["ts"], scfg, pol)
    for f, pats in (scfg.get("value_regex") or {}).items():
        if f in out:
            out[f] = value_regex_sql(f"trim({out[f]})", pats)
    if scfg.get("outcome_map"):
        out["outcome"] = outcome_sql(out.get("outcome", "CAST(NULL AS VARCHAR)"), scfg["outcome_map"])
    if scfg.get("action_map") and "event_action" in out:
        out["event_action"] = action_sql(out["event_action"], out.get("outcome", "CAST(NULL AS VARCHAR)"),
                                         scfg["action_map"])
    for f in scfg.get("ip_fields") or []:
        if f in out:
            out[f] = f"CASE WHEN regexp_matches(trim({out[f]}), {sql_str(IP_RX)}) THEN {out[f]} END"
    for f, n in (scfg.get("max_len") or {}).items():
        if f in out:
            out[f] = f"left({out[f]}, {int(n)})"
    return out
