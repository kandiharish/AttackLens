"""Sigma per-group candidate prefilter (used by sigma_detect for groups that take the DISTINCT-tuple path).

Why: network groups have millions of near-unique tuples (ports, IPs) and no rule can match most of them, yet every
tuple went through a wide DISTINCT and every predicate. The prefilter finds, from small per-field value tables,
the only field values a matching row can have, and keeps just the rows holding one of them.

How (exact - it never removes a row any rule matches):
1. `parse(scan)` weakens a compiled rule (sigma_compile marker text) to its positive AND / OR tree: operands that
   are a negation (`coalesce(NOT (..), c)`) or a `CASE .. ELSE TRUE END` path guard become TRUE (nothing
   required). Only operands of the top-level AND / OR tree change (monotone positions), so rule TRUE => tree TRUE
   in 3-valued logic. Text it cannot parse is one opaque leaf (kept verbatim).
2. One GROUPING SETS scan of the gated rows counts, per leaf, the rows it is TRUE on, on the same r_<i> /
   l_<i> = lower(CAST(r_<i> AS VARCHAR)) values the tuple predicates use. A field with many leaves (domains, paths)
   is grouped by its value and each leaf is then evaluated once per DISTINCT value ("value" field); a field with at
   most direct_max_leaves (<= 62) leaves (IPs, ports: near-unique values, few leaves) is grouped by the bit mask of
   its leaves that are TRUE on the row ("direct" field), so no hash table over millions of distinct values is built.
3. Per rule, an AND keeps ONE operand (the one whose leaves cover the fewest gated rows) and an OR keeps all: a
   disjunction of single-field leaves that is TRUE on every row the rule matches.
4. A row passes iff a kept leaf is TRUE on one of its fields: a value field holds a candidate value (a value a kept
   leaf is TRUE on, NULL included when NULL satisfies it), or a kept leaf of a direct field, inlined in the filter,
   is TRUE. No kept leaf TRUE on any gated row => no gated row of the group can match (SKIP).
A rule that requires nothing or only multi-field leaves, more than max_terms field references, fewer than min_rows
gated rows (the plain path is cheaper there) or any SQL error => no prefilter (the group runs exactly as before).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Union

import duckdb

from attacklens.sigma_compile import MARK_RE, render

log = logging.getLogger(__name__)

_WORD_RE = re.compile(r"[A-Za-z_]+")
_NO_SPLIT = ("BETWEEN",)   # keywords with their own AND: text containing them stays one opaque leaf
_AND, _OR = " AND ", " OR "
SKIP = "FALSE"             # build() result: no gated row of the group can match
MAX_DIRECT_LEAVES = 62     # a direct field's leaves are bits of one BIGINT mask

Tree = Union[tuple, None]  # None = TRUE (nothing required); ("leaf", text, idx | None) | ("and" | "or", [Tree])


def _skip_literal(sql: str, i: int) -> int:
    """sql[i] is the opening quote; returns the index after the closing quote ('' is an escaped quote)."""
    n = len(sql)
    i += 1
    while i < n:
        if sql[i] == "'":
            if i + 1 < n and sql[i + 1] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    raise ValueError("unterminated literal")


class _Weaken:
    """One left-to-right pass (recursive descent) over compiled rule text: OR < AND < (group) | atom."""

    def __init__(self, sql: str) -> None:
        self.s, self.i = sql, 0

    def run(self) -> Tree:
        out = self.or_()
        self._ws()
        if self.i != len(self.s):
            raise ValueError("trailing text")
        return out

    def _ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] == " ":
            self.i += 1

    def or_(self) -> Tree:
        need = [self.and_()]
        while self.s.startswith(_OR, self.i):
            self.i += len(_OR)
            need.append(self.and_())
        if len(need) == 1:
            return need[0]
        return None if any(x is None for x in need) else ("or", need)

    def and_(self) -> Tree:
        need = [self.primary()]
        while self.s.startswith(_AND, self.i):
            self.i += len(_AND)
            need.append(self.primary())
        need = [x for x in need if x is not None]
        return None if not need else need[0] if len(need) == 1 else ("and", need)

    def primary(self) -> Tree:
        self._ws()
        s = self.s
        if self.i < len(s) and s[self.i] == "(":
            self.i += 1
            out = self.or_()
            self._ws()
            if self.i >= len(s) or s[self.i] != ")":
                raise ValueError("unclosed group")
            self.i += 1
            if not (self.i == len(s) or s[self.i] == ")" or s.startswith(_AND, self.i) or s.startswith(_OR, self.i)):
                raise ValueError("group followed by an operator")   # e.g. '(a) = b': not ours to split
            return out
        return self.atom()

    def atom(self) -> Tree:
        s, n, start = self.s, len(self.s), self.i
        depth = case = 0
        while self.i < n:
            c = s[self.i]
            if c == "'":
                self.i = _skip_literal(s, self.i)
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and case == 0 and (s.startswith(_AND, self.i) or s.startswith(_OR, self.i)):
                break
            elif c.isalpha() and (self.i == 0 or not (s[self.i - 1].isalnum() or s[self.i - 1] in "_\x01")):
                w = _WORD_RE.match(s, self.i).group(0)
                u = w.upper()
                if u in _NO_SPLIT:
                    raise ValueError(u)
                case += u == "CASE"
                case -= u == "END" and case > 0
                self.i += len(w)
                continue
            self.i += 1
        if depth or case:
            raise ValueError("unbalanced atom")
        text = s[start:self.i].strip()
        if not text:
            raise ValueError("empty operand")
        if text.startswith("coalesce(NOT (") and text.endswith(")"):
            return None   # the whole atom is one coalesce(...) call: atoms stop at a depth-0 ')'
        if text.startswith("CASE WHEN ") and text.endswith(" ELSE TRUE END"):
            return None
        refs = {int(m.group(2)) for m in MARK_RE.finditer(text)}
        return ("leaf", f"({text})", refs.pop() if len(refs) == 1 else None)


def parse(scan: str) -> Tree:
    """Positive AND / OR tree of a compiled rule (see module doc). Unparseable text -> one opaque leaf (exact)."""
    try:
        return _Weaken(scan).run()
    except (ValueError, RecursionError):
        refs = {int(m.group(2)) for m in MARK_RE.finditer(scan)}
        return ("leaf", f"({scan})", refs.pop() if len(refs) == 1 else None)


def to_sql(t: Tree) -> str:
    """Marker text of a tree ('TRUE' for None)."""
    if t is None:
        return "TRUE"
    if t[0] == "leaf":
        return str(t[1])
    return "(" + (_AND if t[0] == "and" else _OR).join(to_sql(c) for c in t[1]) + ")"


def necessary(scan: str) -> str:
    """Marker text implied by a compiled rule: scan TRUE => necessary(scan) TRUE."""
    return to_sql(parse(scan))


def leaves(t: Tree) -> list[tuple]:
    if t is None:
        return []
    return [t] if t[0] == "leaf" else [x for c in t[1] for x in leaves(c)]


def choose(t: Tree, rows: dict[tuple[int, str], int]) -> list[tuple[int, str]] | None:
    """Single-field leaves (idx, text) whose OR is implied by t; an AND keeps the operand covering the fewest
    gated rows (first on ties). None = not expressible with single-field leaves."""
    if t is None:
        return None
    if t[0] == "leaf":
        return None if t[2] is None else [(int(t[2]), str(t[1]))]
    opts = [choose(c, rows) for c in t[1]]
    if t[0] == "or":
        return None if any(o is None for o in opts) else [x for o in opts if o for x in o]
    ok = [o for o in opts if o is not None]
    return min(ok, key=lambda o: sum(rows.get(x, 0) for x in o)) if ok else None


def _values(i: int) -> str:
    return f"(SELECT r_{i}, lower(CAST(r_{i} AS VARCHAR)) AS l_{i}, n FROM al_sg_d WHERE g_{i} = 0)"


def row_sql(text: str) -> str:
    """Marker text -> SQL over the r_<i> columns of one row: R<i> -> r_<i>, L<i> -> lower(CAST(r_<i> AS VARCHAR))
    (the definition of the l_<i> columns the tuple predicates and value tables read)."""
    return MARK_RE.sub(lambda m: f"r_{m.group(2)}" if m.group(1) == "R" else f"lower(CAST(r_{m.group(2)} AS VARCHAR))",
                       text)


def _hits_mask(texts: list[str], exprs: list[str], aliases: dict[int, str]) -> str:
    """Row expression over r_<i> / l_<i> columns: BIGINT bit mask, bit k set iff leaf texts[k] is TRUE (a direct
    field's grouping key; no per-row list allocation). At most MAX_DIRECT_LEAVES leaves."""
    return "(" + " + ".join(f"(CASE WHEN {render(t, exprs, aliases)} THEN {1 << k} ELSE 0 END)"
                            for k, t in enumerate(texts)) + ")"


def _leaf_rows(con: duckdb.DuckDBPyConnection, lv: list[tuple[int, str]], direct: dict[int, list[str]],
               exprs: list[str], aliases: dict[int, str], batch: int) -> dict[tuple[int, str], int]:
    """Gated rows each single-field leaf is TRUE on. Value fields: leaves in batches as one list of CASE WHEN ..
    THEN k (the tuple-predicate pattern; many FILTER aggregates plan very slowly), summed per k over the value
    table. Direct fields: the row counts per bit mask of TRUE leaves (d_<i>), summed per set bit k."""
    rows: dict[tuple[int, str], int] = {}
    for i, texts in sorted(direct.items()):
        for k, n in con.execute(f"SELECT k, sum(n) FROM al_sg_d, range({len(texts)}) b(k) "
                                f"WHERE gd_{i} = 0 AND (d_{i} >> k) & 1 = 1 GROUP BY k").fetchall():
            rows[(i, texts[int(k)])] = int(n)
    for i in sorted({c for c, _ in lv} - set(direct)):
        mine = [x for x in lv if x[0] == i]
        for b in range(0, len(mine), batch):
            part = mine[b:b + batch]
            ks = ", ".join(f"CASE WHEN {render(t, exprs, aliases)} THEN {b + k} END" for k, (_, t) in enumerate(part))
            for k, n in con.execute(f"""SELECT k, sum(n) FROM (SELECT n, unnest(list_filter([{ks}],
                                        lambda x: x IS NOT NULL)) AS k FROM {_values(i)}) GROUP BY k""").fetchall():
                rows[mine[int(k)]] = int(n)
    return rows


def _scan_counts(con: duckdb.DuckDBPyConnection, exprs: list[str], where: str, cols: list[int],
                 direct: dict[int, list[str]]) -> None:
    """al_sg_d: one GROUPING SETS scan of the gated rows - value fields by value (g_<i>, r_<i>), direct fields by
    the bit mask of their TRUE leaves (gd_<i>, d_<i>) - with row counts n."""
    sel = ", ".join(f"({exprs[i]}) AS r_{i}" for i in cols)
    # lower-cased copies of direct fields computed once per row (common-subexpression search is off here)
    lows = "".join(f", lower(CAST(r_{i} AS VARCHAR)) AS l_{i}" for i in sorted(direct))
    aliases = {i: str(i) for i in cols}
    keys = [f"r_{i}" for i in cols if i not in direct] + [f"d_{i}" for i in sorted(direct)]
    proj = ", ".join([f"r_{i}" for i in cols if i not in direct]
                     + [f"{_hits_mask(direct[i], exprs, aliases)}::BIGINT AS d_{i}" for i in sorted(direct)])
    flags = ", ".join(f"grouping({k}) AS {'g' if k[0] == 'r' else 'gd'}_{k[2:]}" for k in keys)
    con.execute(f"""CREATE OR REPLACE TEMP TABLE al_sg_d AS
        SELECT {flags}, {", ".join(keys)}, count(*) AS n
        FROM (SELECT {proj} FROM (SELECT *{lows} FROM (SELECT {sel} FROM events WHERE {where})))
        GROUP BY GROUPING SETS ({", ".join(f"({k})" for k in keys)})""")


def build(con: duckdb.DuckDBPyConnection, rules: list[dict[str, Any]], exprs: list[str], where: str,
          max_terms: int, batch: int = 250, min_rows: int = 0,
          direct_max_leaves: int = 0) -> tuple[str | None, int | None]:
    """(filter, gated rows). filter: a row filter over r_<i> columns for the group's DISTINCT step, SKIP when no
    gated row can match, or None (no prefilter: run the group unchanged). gated rows: count of the group's gated
    rows when it was taken (None otherwise). Leaves temp tables al_sg_c<i>; drop them with cleanup()."""
    if max_terms <= 0:
        return None, None
    trees = [parse(str(r["scan"])) for r in rules]
    if any(t is None for t in trees):
        return None, None
    lv = sorted({(int(x[2]), str(x[1])) for t in trees for x in leaves(t) if x[2] is not None})
    if not lv or sum(len(MARK_RE.findall(x[1])) for x in lv) > max_terms:
        return None, None
    cols = sorted({i for i, _ in lv})
    per: dict[int, list[str]] = {}
    for i, t in lv:
        per.setdefault(i, []).append(t)
    direct = {i: ts for i, ts in per.items() if len(ts) <= min(direct_max_leaves, MAX_DIRECT_LEAVES)}
    aliases = {i: str(i) for i in cols}
    gated: int | None = None
    try:
        _scan_counts(con, exprs, where, cols, direct)   # the only extra scan of the gated rows (gate evaluated once)
        first = f"g_{cols[0]}" if cols[0] not in direct else f"gd_{cols[0]}"
        gated = int(con.execute(f"SELECT coalesce(sum(n), 0) FROM al_sg_d WHERE {first} = 0").fetchone()[0])
        if not gated:
            return SKIP, 0
        if gated < min_rows:   # small group: planning the leaf queries costs more than the plain path saves
            return None, gated
        rows = _leaf_rows(con, lv, direct, exprs, aliases, batch)
        keep: dict[int, set[str]] = {}
        for t in trees:
            ch = choose(t, rows)
            if ch is None:
                return None, gated
            for x in ch:
                if rows.get(x):
                    keep.setdefault(x[0], set()).add(x[1])
        parts = []
        for i, texts in sorted(keep.items()):
            if i in direct:   # the kept leaves themselves, evaluated on the row
                parts.append("(" + _OR.join(row_sql(t) for t in sorted(texts)) + ")")
                continue
            pred = _OR.join(render(t, exprs, aliases) for t in sorted(texts))
            con.execute(f"CREATE OR REPLACE TEMP TABLE al_sg_c{i} AS SELECT r_{i} FROM {_values(i)} WHERE {pred}")
            nul = con.execute(f"SELECT count(*) FROM al_sg_c{i} WHERE r_{i} IS NULL").fetchone()[0]
            parts.append(f"r_{i} IN (SELECT r_{i} FROM al_sg_c{i})" + (f" OR r_{i} IS NULL" if nul else ""))
        return ("(" + _OR.join(parts) + ")" if parts else SKIP), gated
    except duckdb.Error as exc:   # the prefilter must never change a group's outcome: run it unfiltered
        log.warning("sigma: prefilter for %s not used (%s)", rules[0].get("logsource"),
                    str(exc).splitlines()[0][:300])
        cleanup(con, " ".join(f"al_sg_c{i}" for i in cols))
        return None, gated
    finally:
        con.execute("DROP TABLE IF EXISTS al_sg_d")


def cleanup(con: duckdb.DuckDBPyConnection, flt: str | None) -> None:
    """Drop the al_sg_c<i> tables a build() filter refers to."""
    for i in sorted({int(x) for x in re.findall(r"al_sg_c(\d+)", flt or "")}):
        con.execute(f"DROP TABLE IF EXISTS al_sg_c{i}")
