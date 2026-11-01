"""Sigma detection -> DuckDB predicate (pySigma parse tree in, SQL text out). Used by sigma_rules.py.

Rule values are third-party text: they only ever reach SQL through `lit()` (single quotes doubled, NUL and the
internal marker byte rejected) and LIKE patterns escape `\\`, `%` and `_` (ESCAPE '\\'). Field names never reach SQL:
a Sigma field is looked up in config/sigma_map.yaml `fields` and the configured (trusted) expression is used.

Field references are emitted as markers `\\x01L<i>\\x01` (lower-case of expression i) and `\\x01R<i>\\x01` (raw
expression i); `render()` turns them into SQL, so the same compiled text can run against `events` directly.

Semantics:
- strings: case-insensitive (Sigma default), `|cased` -> case-sensitive; `*` / `?` wildcards; `contains` /
  `startswith` / `endswith` / `windash` / `base64(offset)` / `wide` arrive from pySigma as wildcard strings /
  expansions.
- `|re`: RE2 via regexp_matches (unanchored search, Sigma flags i/m/s -> inline flags); case-sensitive by default.
- `|cidr` -> pySigma's prefix expansion; numbers; null; `|exists`; `|fieldref` (plain); `|gt/gte/lt/lte/neq` numbers.
- NOT: coalesce(NOT (operand), c) where c follows negation parity: FALSE under an even number of enclosing NOTs, TRUE
  under an odd number (the outer NOT turns it into FALSE). A field the operand needs but that is absent (NULL) therefore
  never creates a match at any nesting depth (a filter on an absent field does not 'pass').
- keyword (field-less) searches are substring searches (Sigma semantics: a plain keyword matches anywhere in the
  event) on the logsource's keyword column; raw_line is only allowed with a guard (source_type list + payload
  exclusion, built by sigma_rules) that becomes part of the keyword EXPRESSION - CASE WHEN <guard> THEN raw_line END -
  so it is evaluated like any other field (also in the grouped DISTINCT-tuple path) and an unguarded row is NULL.
- assume_true: {Field: [values]} - an equality leaf with one of those values is implied by the logsource gate
  (TRUE); any other value / modifier on that field is unknown (unmapped_field:<Field>), never assumed true.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sigma import conditions as sc
from sigma import types as st

MARK = "\x01"
MARK_RE = re.compile("\x01([LR])(\\d+)\x01")
NUMERIC_TYPES = {"INTEGER", "BIGINT", "UBIGINT", "DOUBLE"}


class Unsupported(Exception):
    """The rule cannot be compiled; str(exc) is the skip reason (`<code>` or `<code>:<detail>`)."""


@dataclass(frozen=True)
class FieldSpec:
    expr: str
    type: str = "VARCHAR"
    name: str | None = None      # basename column: endswith '\x' / '/x' also matches name = 'x'
    user: bool = False           # normalize literal values like ingest users


@dataclass
class Compiler:
    """One instance per logsource entry; `exprs` is shared across all rules so marker indices are global."""
    fields: dict[str, FieldSpec]
    exprs: list[str]
    assume_true: dict[str, frozenset[str]] = field(default_factory=dict)   # field -> implied values (lower case)
    keywords: str | None = None
    keyword_guard: str | None = None   # SQL predicate: rows outside it have a NULL keyword column
    policy: str = "skip"         # skip | narrow
    used: set[str] = field(default_factory=set)
    keyword_used: bool = False

    # -- entry -------------------------------------------------------------------------------------------------
    def compile_rule(self, conditions: list[Any]) -> str:
        """conditions: pySigma SigmaCondition list (rule.detection.parsed_condition). Multiple conditions = OR."""
        parts = []
        for cond in conditions:
            try:
                tree = cond.parse()
            except Exception as exc:  # noqa: BLE001 - pySigma raises many types for bad conditions
                raise Unsupported(f"condition_error:{type(exc).__name__}") from exc
            parts.append(self.node(tree, negated=False))
        sql = _or(parts)
        if sql == "FALSE":
            raise Unsupported("unsatisfiable_without_unmapped")
        if sql == "TRUE":
            raise Unsupported("matches_every_gated_row")
        return sql

    # -- tree --------------------------------------------------------------------------------------------------
    def node(self, n: Any, negated: bool) -> str:
        if isinstance(n, sc.ConditionAND):
            return _and([self.node(a, negated) for a in n.args])
        if isinstance(n, sc.ConditionOR):
            return _or([self.node(a, negated) for a in n.args])
        if isinstance(n, sc.ConditionNOT):
            inner = self.node(n.args[0], not negated)
            if inner in ("TRUE", "FALSE"):
                return "FALSE" if inner == "TRUE" else "TRUE"
            # unknown (NULL) -> the constant that can only remove matches at this position's parity
            return f"coalesce(NOT ({inner}), {'TRUE' if negated else 'FALSE'})"
        if isinstance(n, sc.ConditionFieldEqualsValueExpression):
            return self.leaf(n.field, n.value, negated)
        if isinstance(n, sc.ConditionValueExpression):
            return self.keyword(n.value, negated)
        raise Unsupported(f"condition_node:{type(n).__name__}")

    def unknown(self, reason: str, negated: bool) -> str:
        if self.policy != "narrow":
            raise Unsupported(reason)
        return "TRUE" if negated else "FALSE"   # the constant that can only remove matches

    def leaf(self, fname: str | None, value: Any, negated: bool) -> str:
        if fname is None:
            return self.keyword(value, negated)
        if fname in self.assume_true:
            if _implied(value, self.assume_true[fname]):
                return "TRUE"
            return self.unknown(f"unmapped_field:{fname}", negated)
        spec = self.fields.get(fname)
        if spec is None:
            return self.unknown(f"unmapped_field:{fname}", negated)
        self.used.add(fname)
        return self.value(spec, value, negated)

    def keyword(self, value: Any, negated: bool = False) -> str:
        if not self.keywords:
            raise Unsupported("keyword_search_unmapped")
        if self.keywords == "raw_line" and not self.keyword_guard:
            raise Unsupported("keyword_raw_line_unguarded")
        expr = f"CASE WHEN {self.keyword_guard} THEN ({self.keywords}) END" if self.keyword_guard else self.keywords
        self.keyword_used = True
        return self.value(FieldSpec(expr), _as_keyword(value), negated, substring=True)

    # -- values ------------------------------------------------------------------------------------------------
    def ref(self, expr: str, lower: bool) -> str:
        if expr not in self.exprs:
            self.exprs.append(expr)
        return f"{MARK}{'L' if lower else 'R'}{self.exprs.index(expr)}{MARK}"

    def value(self, spec: FieldSpec, v: Any, negated: bool = False, substring: bool = False) -> str:
        if isinstance(v, st.SigmaExpansion):
            return _or([self.value(spec, x, negated, substring) for x in v.values])
        if isinstance(v, st.SigmaString):     # includes SigmaCasedString
            return self.string(spec, v, cased=isinstance(v, st.SigmaCasedString), negated=negated,
                               substring=substring)
        if substring and not isinstance(v, st.SigmaRegularExpression):
            raise Unsupported(f"keyword_value_type:{type(v).__name__}")
        if isinstance(v, st.SigmaNumber):
            return self.number(spec, v.number, "=")
        if isinstance(v, st.SigmaNull):
            return f"({self.ref(spec.expr, False)} IS NULL)"
        if isinstance(v, st.SigmaExists):
            return f"({self.ref(spec.expr, False)} IS {'NOT ' if v.exists else ''}NULL)"
        if isinstance(v, st.SigmaRegularExpression):
            return self.regex(spec, v)
        if isinstance(v, st.SigmaCIDRExpression):
            pats = [st.SigmaString(p) for p in v.expand("*")]
            return _or([self.string(spec, p, cased=False) for p in pats])
        if isinstance(v, st.SigmaCompareExpression):
            ops = {"LT": "<", "LTE": "<=", "GT": ">", "GTE": ">=", "NEQ": "<>"}
            return self.number(spec, v.number.number, ops[v.op.name])
        if isinstance(v, st.SigmaFieldReference):
            other = self.fields.get(v.field)
            if other is None:
                raise Unsupported(f"unmapped_field:{v.field}")
            if v.starts_with or v.ends_with:
                raise Unsupported("modifier:fieldref_partial")
            self.used.add(v.field)
            return f"({self.ref(spec.expr, True)} = {self.ref(other.expr, True)})"
        raise Unsupported(f"value_type:{type(v).__name__}")

    def number(self, spec: FieldSpec, num: Any, op: str) -> str:
        if not isinstance(num, (int, float)) or isinstance(num, bool):
            raise Unsupported("value_type:number")
        if spec.type.upper() in NUMERIC_TYPES:
            return f"({self.ref(spec.expr, False)} {op} {num!r})"
        if op == "=":
            return f"({self.ref(spec.expr, True)} = {lit(str(num))})"
        return f"(TRY_CAST({self.ref(spec.expr, False)} AS DOUBLE) {op} {num!r})"

    def string(self, spec: FieldSpec, s: st.SigmaString, cased: bool, negated: bool = False,
               substring: bool = False) -> str:
        if s.contains_placeholder():
            raise Unsupported("modifier:expand_placeholder")
        parts = _parts(s, lower=not cased)
        if substring:   # Sigma keyword: a search anywhere in the value, i.e. implicit '*' on both ends
            if not any(isinstance(p, str) and p for p in parts):
                raise Unsupported("keyword_empty")
            w = st.SpecialChars.WILDCARD_MULTI
            parts = ([] if parts[0] is w else [w]) + parts + ([] if parts[-1] is w else [w])
        if spec.user:
            parts = _normalize_user(parts)
        numeric = spec.type.upper() in NUMERIC_TYPES
        col = (f"CAST({self.ref(spec.expr, False)} AS VARCHAR)" if numeric
               else self.ref(spec.expr, lower=not cased))
        if numeric and len(parts) == 1 and isinstance(parts[0], str) and re.fullmatch(r"-?\d+", parts[0]):
            return f"({self.ref(spec.expr, False)} = {int(parts[0])})"
        main = _match(col, parts)
        # endswith '\name.exe' / '/name' on a path field also matches the basename column
        if (spec.name and not numeric and len(parts) == 2 and parts[0] is st.SpecialChars.WILDCARD_MULTI
                and isinstance(parts[1], str) and parts[1][:1] in ("\\", "/")
                and not re.search(r"[\\/]", parts[1][1:]) and parts[1][1:]):
            ncol = self.ref(spec.name, lower=not cased)
            return f"({main} OR {ncol} = {lit(parts[1][1:])})"
        if spec.name and not numeric and any(isinstance(p, str) and re.search(r"[\\/]", p) for p in parts):
            # a path pattern tested on a bare name (ECS parent.name) is unknown, not false: resolve it to the
            # constant that can only remove matches, so missing path data never creates an alert
            raw = self.ref(spec.expr, False)
            unk = "TRUE" if negated else "FALSE"
            return (f"(CASE WHEN contains(coalesce({raw}, ''), '\\') OR contains(coalesce({raw}, ''), '/') "
                    f"THEN {main} ELSE {unk} END)")
        return main

    def regex(self, spec: FieldSpec, v: st.SigmaRegularExpression) -> str:
        flags = {f.name for f in (v.flags or set())}
        prefix = "".join(f for k, f in (("IGNORECASE", "i"), ("MULTILINE", "m"), ("DOTALL", "s")) if k in flags)
        pat = (f"(?{prefix})" if prefix else "") + str(v.regexp)
        col = f"CAST({self.ref(spec.expr, False)} AS VARCHAR)" if spec.type.upper() in NUMERIC_TYPES \
            else self.ref(spec.expr, False)
        return f"regexp_matches({col}, {lit(pat)})"


# -- helpers -----------------------------------------------------------------------------------------------------
def lit(value: str) -> str:
    """Safe SQL string literal for untrusted text."""
    if "\x00" in value or MARK in value:
        raise Unsupported("value_control_char")
    return "'" + value.replace("'", "''") + "'"


def _parts(s: st.SigmaString, lower: bool) -> list[Any]:
    """Merged parts: plain strings (lower-cased unless cased) and SpecialChars wildcards."""
    out: list[Any] = []
    for p in s.s:
        if isinstance(p, str):
            p = p.lower() if lower else p
            if out and isinstance(out[-1], str):
                out[-1] += p
            else:
                out.append(p)
        elif isinstance(p, st.SpecialChars):
            out.append(p)
        else:
            raise Unsupported("modifier:expand_placeholder")
    return out


def _implied(value: Any, allowed: frozenset[str]) -> bool:
    """True when value is a plain (wildcard-free, not |cased) string equal, case-insensitively, to one of allowed."""
    if not isinstance(value, st.SigmaString) or isinstance(value, st.SigmaCasedString):
        return False
    if not all(isinstance(p, str) for p in value.s):
        return False
    return "".join(value.s).lower() in allowed


def _as_keyword(value: Any) -> Any:
    """Keyword numbers search their text (Sigma keyword 4625 matches '... 4625 ...')."""
    if isinstance(value, st.SigmaNumber):
        return st.SigmaString(str(value.number))
    return value


def assume_true_spec(raw: Any) -> dict[str, frozenset[str]]:
    """sigma_map.yaml logsource `assume_true` -> {field: implied lower-case values}. Only the mapping form
    {Field: [values]} is accepted: a bare field list would assume ANY value true (a rule that uses the field to
    disambiguate an EventID would then fire for every provider / channel)."""
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("sigma_map assume_true must be a mapping {Field: [implied values]}")
    return {str(k): frozenset(str(x).lower() for x in (v if isinstance(v, list) else [v])) for k, v in raw.items()}


def _normalize_user(parts: list[Any]) -> list[Any]:
    """Literal user names like ingest: 'NT AUTHORITY\\SYSTEM' -> 'system', 'bob@corp.local' -> 'bob'."""
    if len(parts) == 1 and isinstance(parts[0], str):
        u = parts[0].rsplit("\\", 1)[-1]
        return [u.split("@", 1)[0] if "@" in u and not u.startswith("@") else u]
    return parts


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _match(col: str, parts: list[Any]) -> str:
    W, Q = st.SpecialChars.WILDCARD_MULTI, st.SpecialChars.WILDCARD_SINGLE
    if not parts:
        return f"(coalesce({col}, '') = '')"
    if Q not in parts:
        lead, trail = parts[0] is W, parts[-1] is W
        core = parts[int(lead): len(parts) - int(trail)]
        if len(core) == 1 and isinstance(core[0], str):
            v = lit(core[0])
            if lead and trail:
                return f"contains({col}, {v})"
            if lead:
                return f"ends_with({col}, {v})"
            if trail:
                return f"starts_with({col}, {v})"
            return f"({col} = {v})"
        if not core:
            return f"({col} IS NOT NULL)"     # '*' alone: any value
    pat = "".join("%" if p is W else "_" if p is Q else _like_escape(p) for p in parts)
    return f"({col} LIKE {lit(pat)} ESCAPE '\\')"


def _and(xs: list[str]) -> str:
    if "FALSE" in xs:
        return "FALSE"
    xs = [x for x in xs if x != "TRUE"]
    return "TRUE" if not xs else xs[0] if len(xs) == 1 else "(" + " AND ".join(xs) + ")"


def _or(xs: list[str]) -> str:
    if "TRUE" in xs:
        return "TRUE"
    xs = [x for x in xs if x != "FALSE"]
    return "FALSE" if not xs else xs[0] if len(xs) == 1 else "(" + " OR ".join(xs) + ")"


def render(sql: str, exprs: list[str], aliases: dict[int, str] | None = None) -> str:
    """Markers -> SQL. Default: L<i> = lower(expr_i), R<i> = (expr_i). With aliases, i -> column name prefix: L ->
    `l_<alias>`, R -> `r_<alias>` (pre-computed columns)."""
    def sub(m: re.Match[str]) -> str:
        kind, i = m.group(1), int(m.group(2))
        if aliases is not None:
            return f"{kind.lower()}_{aliases[i]}"
        return f"lower({exprs[i]})" if kind == "L" else f"({exprs[i]})"
    return MARK_RE.sub(sub, sql)


def field_spec(raw: Any, column_types: dict[str, str]) -> FieldSpec:
    """config/sigma_map.yaml `fields` value -> FieldSpec."""
    if isinstance(raw, str):
        return FieldSpec(raw, column_types.get(raw, "VARCHAR"))
    expr = str(raw["expr"])
    return FieldSpec(expr, str(raw.get("type") or column_types.get(expr, "VARCHAR")),
                     raw.get("name"), bool(raw.get("user")))


def marker_indices(sql: str) -> set[int]:
    return {int(m.group(2)) for m in MARK_RE.finditer(sql)}
