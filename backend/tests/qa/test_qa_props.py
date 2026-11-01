"""QA track qa_property: hypothesis properties for parsers, timestamps, entity normalization, Sigma escaping and
ingest accounting (qa-tester white-box). Report: reports/qa/qa_property.md.

Every property runs against the PRODUCT code paths (no re-implementation of what is under test):
- FortiGate key=value: ingest_sql.kv_select + normalize_sql with the shipped config/sources.yaml, executed by
  DuckDB over a generated file under data/tmp/qa_props/ (the exact SQL Stage 1 runs).
- timestamps: the same kv SQL (eventtime s/ms/us/ns, date+time+tz, eventtime_is_local) and ingest_sql.ts_expr.
- entities: ingest_sql._user (SQL), siem_alerts.norm_user, sigma_compile._normalize_user, incident_gate.entities /
  allowlist_entities, incidents.build_graph node ids.
- Sigma: sigma_compile.Compiler.value / render / lit evaluated on tiny DuckDB tables vs a Python reference matcher.
- accounting: profile.run + ingest.run end to end on generated FortiGate files.

Reproducible: derandomize=True, database=None. Cheap properties run 200 examples in the fast suite. SQL-heavy
ingest properties compile ~30 KB of regex SQL per example (~0.5 s on a loaded box), so the fast suite runs them on
batches (one file of up to 12 lines per example, 10 examples; accounting 4 runs) and the @stress copies run
200 examples (accounting 100).
Product bugs found here are strict xfail tests with the minimal shrunk example pinned via @example; the id is in
the reason (QA-PROP-n) and in the report.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import unicodedata
from pathlib import Path
from typing import Any

import duckdb
import pytest

pytest.importorskip("hypothesis", reason="dev dependency hypothesis (MPL-2.0) not installed: pip install hypothesis")
from hypothesis import HealthCheck, example, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402
from sigma import types as sgt  # noqa: E402

from attacklens import config, db, incident_gate, ingest, ingest_sql, profile, siem_alerts, sigma_compile  # noqa: E402
from attacklens.context import RunContext  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
# one root per process: two pytest processes (e.g. a fast run next to a @stress run) must never share or delete
# each other's generated files (a shared path was the cause of a spurious KeyError / lost-line failure)
TMP = REPO / "data" / "tmp" / "qa_props" / f"p{os.getpid()}"
B = chr(92)  # one backslash
Q = chr(34)  # one double quote

_HC = [HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much,
       HealthCheck.function_scoped_fixture]
CHEAP = settings(max_examples=200, deadline=None, derandomize=True, database=None, suppress_health_check=_HC)
SQL_FAST = settings(max_examples=10, deadline=None, derandomize=True, database=None, suppress_health_check=_HC)
SQL_FULL = settings(max_examples=200, deadline=None, derandomize=True, database=None, suppress_health_check=_HC)
ACC_FAST = settings(max_examples=4, deadline=None, derandomize=True, database=None, suppress_health_check=_HC)
ACC_FULL = settings(max_examples=100, deadline=None, derandomize=True, database=None, suppress_health_check=_HC)

ZS = "".join(chr(c) for c in range(0x110000) if unicodedata.category(chr(c)) == "Zs")  # what DuckDB trim() strips


# ====================================================================== shared DuckDB / config
# Module globals, not fixtures: hypothesis prints every argument of a failing example (the parsed config is ~50 KB).
_STATE: dict[str, Any] = {}


def _cfg() -> dict[str, Any]:
    if "cfg" not in _STATE:
        _STATE["cfg"] = config.load_config()
    return _STATE["cfg"]


def _con() -> duckdb.DuckDBPyConnection:
    if "con" not in _STATE:
        TMP.mkdir(parents=True, exist_ok=True)
        _STATE["con"] = db.connect(memory_limit="1GB", threads=2, temp_directory=TMP / "spill")
    return _STATE["con"]


@pytest.fixture(scope="module", autouse=True)
def _close_con():
    yield
    c = _STATE.pop("con", None)
    if c is not None:
        c.close()
    shutil.rmtree(TMP, ignore_errors=True)


def kv_rows(lines: list[str], name: str, kcfg: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Run the Stage 1 kv SELECT + normalize_sql over `lines` -> {raw_line: canonical row}."""
    con, cfg = _con(), _cfg()
    d = TMP / name
    d.mkdir(parents=True, exist_ok=True)
    _STATE["n"] = _STATE.get("n", 0) + 1
    f = d / f"batch{_STATE['n']}.txt"   # fresh name per call: never re-read a rewritten path
    f.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    src = cfg["sources"]
    k = kcfg if kcfg is not None else src["kv_sources"]["fortigate_kv"]
    sql = ingest_sql.normalize_sql(ingest_sql.kv_select("fortigate_kv", [f.as_posix()], d.as_posix(), k), src)
    cur = con.execute(sql)
    cols = [x[0] for x in cur.description]
    out = {}
    for r in cur.fetchall():
        row = dict(zip(cols, r))
        out[row["raw_line"]] = row
    f.unlink()
    assert sorted(out) == sorted(lines), "a generated line was lost, duplicated or changed in raw_line"
    return out


# ====================================================================== reference model (§3.1 normalization)
NULLS = ("", "N/A", "n/a", "(null)")   # config/sources.yaml kv_sources.fortigate_kv.null_values


def clean(v: str | None) -> str | None:
    if v is None:
        return None
    t = v.strip(ZS)
    return None if t in ("", "-") else t


def kvval(v: str | None) -> str | None:
    return None if v is None or v in NULLS else v


def low(v: str | None) -> str | None:
    return None if v is None else v.lower()


def ref_user(v: str | None) -> str | None:
    x = clean(kvval(v))
    if x is None:
        return None
    y = unicodedata.normalize("NFC", x.strip(ZS)).lower()
    y = y.rsplit(B, 1)[-1].split("@", 1)[0]
    return clean(y)


def ref_int(v: str | None, bits: int = 32) -> int | None:
    t = clean(kvval(v))
    if t is None or not re.fullmatch(r"[0-9]{1,18}", t):
        return None
    n = int(t)
    return n if n < 2 ** (bits - 1) else None


def ref_ext(path: str | None) -> str | None:
    m = re.search(r"\.([A-Za-z0-9]{1,10})\Z", path) if path else None
    return m.group(1).lower() if m else None


def raw_kv(v: str | None) -> str | None:
    """What the kv path stores: the unquoted value, null_values -> NULL; no trim, no '-' -> NULL (see QA-PROP-6)."""
    return None if v is None or v in NULLS else v


def domain(v: str | None) -> str | None:
    x = low(raw_kv(v))
    return None if x is None else (x.rstrip(".") or None)


# key -> (canonical column, reference function of the intended value)
STR_FIELDS: dict[str, tuple[str, Any]] = {
    "devname": ("host", lambda v: low(raw_kv(v))),
    "srcip": ("src_ip", lambda v: low(raw_kv(v))),
    "dstip": ("dst_ip", lambda v: low(raw_kv(v))),
    "user": ("src_user", ref_user),
    "hostname": ("dst_domain", domain),
    "url": ("file_path", raw_kv),
    "service": ("service_name", lambda v: low(raw_kv(v))),
    "app": ("app", lambda v: low(raw_kv(v))),
    "attack": ("signature", raw_kv),
    "srcintfrole": ("src_zone", lambda v: low(raw_kv(v))),
    "dstintfrole": ("dst_zone", lambda v: low(raw_kv(v))),
    "level": ("vendor_severity", lambda v: low(raw_kv(v))),
}
# Section 3.1 cleaning every other source applies (_clean: trim, '' and '-' -> NULL); QA-PROP-6 checks kv against it
CLEAN_FIELDS: dict[str, tuple[str, Any]] = {
    k: (col, (lambda v, _fn=fn: _fn(clean(v)) if clean(v) is not None else None)) for k, (col, fn) in
    STR_FIELDS.items()}
INT_FIELDS: dict[str, tuple[str, Any]] = {
    "srcport": ("src_port", lambda v: ref_int(v, 32)),
    "dstport": ("dst_port", lambda v: ref_int(v, 32)),
    "sentbyte": ("bytes_out", lambda v: ref_int(v, 54)),   # via DOUBLE: exact below 2**53
    "rcvdbyte": ("bytes_in", lambda v: ref_int(v, 54)),
}
ALL_FIELDS = {**STR_FIELDS, **INT_FIELDS}


def expect_row(fields: dict[str, str], action: str) -> dict[str, Any]:
    exp = {col: fn(fields.get(k)) for k, (col, fn) in ALL_FIELDS.items()}
    exp["file_ext"] = ref_ext(exp["file_path"])
    exp["target_user"] = None
    exp["action"], exp["outcome"] = (("conn_allowed", "success") if action == "accept"
                                     else ("conn_denied", "failure"))
    return exp


def encode(v: str, quoted: bool) -> str:
    """FortiGate writer: quoted values escape '"' as '\\"' (backslashes are written as they are)."""
    if not quoted:
        return v
    return Q + v.replace(Q, B + Q) + Q


# ====================================================================== strategies
SPOOF_KEYS = ["srcip", "dstip", "devname", "user", "srcport", "dstport", "status", "type", "action", "tunnelip",
              "tranip", "trandisp", "sentbyte", "eventtime", "date", "time", "tz", "subtype", "logdesc", "remip"]
FRAGS = [" ", "  ", "=", " = ", "==", "a=b", " srcip=6.6.6.6", " user=evil", " devname=evil", " dstport=6666",
         "N/A", "-", ".", "@", "#", "'", "%", "_", "*", "?", ";", ",", "(", ")", "é", "日本", "😀", "é",
         " ", "　", "CORP", "Ä"]
SAFE_CH = st.characters(blacklist_categories=("Cc", "Cs", "Co", "Cn"),
                        blacklist_characters=Q + B + "\x01İΣ")  # İ, Σ: Python vs DuckDB lower (QA-PROP-3)
safe_text = st.lists(st.one_of(st.sampled_from(FRAGS), SAFE_CH), max_size=12).map("".join)
token = st.from_regex(r"[A-Za-z0-9._:/-]{1,16}", fullmatch=True)


@st.composite
def field_value(draw: Any, key: str) -> tuple[str, bool]:
    """(intended value, quoted?)"""
    if key in INT_FIELDS:
        v = draw(st.one_of(st.integers(0, 2 ** 40).map(str), st.sampled_from(["", "N/A", "-", "x1", "65536"])))
        return v, draw(st.booleans())
    v = draw(st.one_of(safe_text, token, st.sampled_from(list(NULLS) + ["-", " - ", "CORP" + B + "Bob",
                                                                         "Bob@corp.local", "a.example.", "x.PS1"])))
    unq_ok = bool(v) and " " not in v and not v.startswith(Q) and B not in v and Q not in v
    return v, (not unq_ok) or draw(st.booleans())


@st.composite
def kv_line(draw: Any, idx: int, decoys: bool = False, junk: bool = False) -> tuple[str, dict[str, Any]]:
    keys = draw(st.lists(st.sampled_from(sorted(ALL_FIELDS)), unique=True, max_size=len(ALL_FIELDS)))
    action = draw(st.sampled_from(["accept", "deny"]))
    fields: dict[str, str] = {}
    toks = [f"type={draw(st.sampled_from(['traffic', Q + 'traffic' + Q]))}",
            f"action={encode(action, draw(st.booleans()))}", f"qaidx={idx}"]
    for k in keys:
        v, quoted = draw(field_value(k))
        fields[k] = v
        toks.append(f"{k}={encode(v, quoted)}")
    if decoys:
        for j in range(draw(st.integers(1, 3))):
            parts = draw(st.lists(st.one_of(
                st.builds(lambda k, v: f" {k}={v}", st.sampled_from(SPOOF_KEYS),
                          st.sampled_from(["6.6.6.6", "evil", "6666", Q + "evil" + Q, "success", "utm", "dnat"])),
                st.sampled_from([" ", B + Q, B + Q + " ", "=", "x", " " + B + Q + "srcip=6.6.6.6"])),
                min_size=1, max_size=6))
            toks.append(f"{draw(st.sampled_from(['msg', 'reason', 'qa_note', 'logdesc2']))}{j}="
                        + Q + "".join(parts).replace(Q, B + Q).replace(B + B + Q, B + Q) + Q)
    if junk:
        toks.append(draw(st.sampled_from(["Foo=bar", "a.b=c", "x" + Q + "y=z", "k=v=w", "K=" + Q + "v" + Q,
                                          "noeq", "=lead"])))
    order = draw(st.permutations(toks))
    line = "date=2026-10-24 time=07:30:00 " + " ".join(order)
    return line, {"fields": fields, "action": action}


def batch(decoys: bool = False, junk: bool = False) -> Any:
    return st.integers(1, 12).flatmap(lambda n: st.tuples(*[kv_line(i, decoys, junk) for i in range(n)]))


def mapped(row: dict[str, Any]) -> dict[str, Any]:
    cols = [c for c, _ in ALL_FIELDS.values()] + ["file_ext", "target_user", "action", "outcome"]
    return {c: row[c] for c in cols}


# ====================================================================== 1. FortiGate key=value round trip
def _kv_roundtrip(lines) -> None:
    rows = kv_rows([ln for ln, _ in lines], "rt")
    for ln, meta in lines:
        got, exp = mapped(rows[ln]), expect_row(meta["fields"], meta["action"])
        assert got == exp, (ln, {k: (got[k], exp[k]) for k in exp if got[k] != exp[k]})


@SQL_FAST
@given(lines=batch())
def test_kv_roundtrip_mapped_fields(lines) -> None:
    """Quoted / unquoted values with spaces, '=', 'key=' text, unicode, N/A, '-' map exactly (§3.1 normalization)."""
    _kv_roundtrip(lines)


@pytest.mark.stress
@SQL_FULL
@given(lines=batch())
def test_kv_roundtrip_mapped_fields_200(lines) -> None:
    _kv_roundtrip(lines)


def _kv_spoof(lines) -> None:
    rows = kv_rows([ln for ln, _ in lines], "spoof")
    for ln, meta in lines:
        got, exp = mapped(rows[ln]), expect_row(meta["fields"], meta["action"])
        assert got == exp, (ln, {k: (got[k], exp[k]) for k in exp if got[k] != exp[k]})
        assert rows[ln]["ts_ms"] == 1792827000000, ln   # naive 07:30 (no tz key): spoofed date/eventtime/tz never win


@SQL_FAST
@given(lines=batch(decoys=True))
def test_kv_quoted_value_never_spoofs_a_key(lines) -> None:
    """msg="... srcip=6.6.6.6 \\" user=\\"evil\\"" (escaped quotes included) before / after / instead of the real
    key never changes a mapped column; an absent key stays NULL."""
    _kv_spoof(lines)


@pytest.mark.stress
@SQL_FULL
@given(lines=batch(decoys=True))
def test_kv_quoted_value_never_spoofs_a_key_200(lines) -> None:
    _kv_spoof(lines)


SPOOF_JUNK = ('date=2026-10-24 time=07:30:00 type=traffic action=accept qaidx=0 Foo=bar '
              'msg="x srcip=6.6.6.6" srcip=10.0.0.1')


@pytest.mark.xfail(strict=True, reason="QA-PROP-1: one token the spoof-guard token walk cannot parse (key with an "
                   "upper-case letter / dot, or a value with a quote mid-token) before a quoted msg turns the guard "
                   "off, so msg=\"x srcip=6.6.6.6\" wins over the real srcip")
@SQL_FAST
@given(lines=batch(decoys=True, junk=True))
@example(lines=((SPOOF_JUNK, {"fields": {"srcip": "10.0.0.1"}, "action": "accept"}),))
def test_kv_spoof_guard_survives_one_nonconforming_token(lines) -> None:
    _kv_spoof(lines)


ESC_LINE = 'date=2026-10-24 time=07:30:00 type=traffic action=accept qaidx=0 user="a\\"b"'


@pytest.mark.xfail(strict=True, reason="QA-PROP-2: escaped quotes in quoted values are never unescaped; "
                   "user=\"a\\\"b\" becomes src_user '\"b' (the escape backslash is taken as DOMAIN\\) and "
                   "user=\"ab\\\"\" becomes NULL (trim strips the escaped quote, the backslash eats the rest)")
@SQL_FAST
@given(v=st.lists(st.one_of(st.sampled_from([Q, "a", "b", " ", "="]), SAFE_CH), min_size=1, max_size=8)
       .map("".join).filter(lambda s: Q in s))
@example(v='a"b')
def test_kv_escaped_quote_roundtrip(v) -> None:
    for key in ("user", "devname", "url"):
        line = f'date=2026-10-24 time=07:30:00 type=traffic action=accept qaidx=0 {key}={encode(v, True)}'
        row = kv_rows([line], "esc")[line]
        col, fn = STR_FIELDS[key]
        assert row[col] == fn(v), (key, v, row[col])


@pytest.mark.xfail(strict=True, reason="QA-PROP-6: the kv (FortiGate) path skips the cleaning every other source gets "
                   "(ingest_sql._clean: trim, '' / '-' -> NULL; DEVELOPMENT.md 3.1 requires '-' -> NULL for src_ip / "
                   "dst_ip / dst_domain): devname=\" \" stores host ' ', srcip=\"-\" "
                   "stores src_ip '-', devname=\" fgt \" stores host ' fgt ' (entity host: fgt  != host:fgt)")
@SQL_FAST
@given(v=st.sampled_from([" ", "  ", "-", " - ", " ", " fgt-01", "fgt-01 ", "　x"]),
       key=st.sampled_from(sorted(STR_FIELDS)))
@example(v=" ", key="devname")
def test_kv_values_get_the_same_cleaning_as_other_sources(v, key) -> None:
    line = f'date=2026-10-24 time=07:30:00 type=traffic action=accept qaidx=0 {key}={encode(v, True)}'
    col, fn = CLEAN_FIELDS[key]
    got = kv_rows([line], "clean")[line][col]
    assert got == fn(v), (key, v, got)


INJ_USER = "a" + B + Q + " remip=6.6.6.6 x=" + Q   # attacker-chosen VPN login name


def vpn_line(user_value: str) -> str:
    """SSL-VPN login failure; FortiGate writes the attacker-supplied name quoted, '"' escaped as '\\"', backslashes
    as they are (the writer model the parser assumes: KV_VALUE treats backslash + any char as an escape pair)."""
    return (f'date=2026-10-24 time=07:30:00 type="event" subtype="vpn" action="ssl-login-fail" '
            f'user={encode(user_value, True)} remip=203.0.113.9 reason="sslvpn_login_unknown_user" qaidx=0')


@pytest.mark.xfail(strict=True, reason="QA-PROP-7: an attacker-chosen login name containing a backslash before a "
                   "quote (name 'a\\\" remip=6.6.6.6 x=\"' -> user=\"a\\\\\" remip=6.6.6.6 x=\\\"\") closes the quoted "
                   "value early and injects remip=6.6.6.6 as the login source; a name ending in a backslash swallows the "
                   "real remip (src_ip NULL)")
@SQL_FAST
@given(name=st.lists(st.sampled_from([B, Q, " ", "=", "a", "x=", " remip=6.6.6.6 ", " srcip=6.6.6.6 ",
                                       " status=success "]), min_size=1, max_size=8).map("".join))
@example(name=INJ_USER)
@example(name="CORP" + B)
def test_kv_attacker_controlled_value_never_spoofs_a_key(name) -> None:
    ln = vpn_line(name)
    r = kv_rows([ln], "inj")[ln]
    assert (r["action"], r["outcome"], r["src_ip"], r["logon_type"]) == ("login_failed", "failure",
                                                                         "203.0.113.9", 10), (ln, r["src_ip"])


# ====================================================================== 2. timestamps
LO_MS = int(dt.datetime(2002, 1, 1, tzinfo=dt.timezone.utc).timestamp() * 1000)
HI_MS = int(dt.datetime(2099, 12, 31, tzinfo=dt.timezone.utc).timestamp() * 1000)


@st.composite
def ts_case(draw: Any, idx: int) -> tuple[str, int]:
    utc = draw(st.integers(LO_MS, HI_MS))
    off = draw(st.integers(-48, 56)) * 15                       # -12:00 .. +14:00 in minutes
    unit = draw(st.sampled_from(["s", "ms", "us", "ns", "none"]))
    local = draw(st.booleans())                                 # eventtime written as local-as-UTC (real tiers)
    colon = draw(st.booleans())
    wall = dt.datetime.fromtimestamp(utc / 1000, dt.timezone.utc) + dt.timedelta(minutes=off)
    sign = "-" if off < 0 else "+"
    tz = f"{sign}{abs(off) // 60:02d}{':' if colon else ''}{abs(off) % 60:02d}"
    base = utc + off * 60000 if local else utc
    et = {"s": str(base // 1000), "ms": str(base), "us": str(base * 1000 + draw(st.integers(0, 999))),
          "ns": str(base * 1_000_000 + draw(st.integers(0, 999_999))), "none": None}[unit]
    toks = [f"date={wall:%Y-%m-%d}", f"time={wall:%H:%M:%S}", f'tz="{tz}"', "type=traffic", "action=accept",
            f"qaidx={idx}"] + ([f"eventtime={et}"] if et else [])
    exp = utc // 1000 * 1000 if unit in ("s", "none") else utc
    return " ".join(toks[:2] + draw(st.permutations(toks[2:]))), exp


def ts_batch() -> Any:
    return st.integers(1, 12).flatmap(lambda n: st.tuples(*[ts_case(i) for i in range(n)]))


def _kv_ts(cases) -> None:
    rows = kv_rows([ln for ln, _ in cases], "ts")
    got = [(rows[ln]["ts_ms"], exp, ln) for ln, exp in cases]
    for g, e, ln in got:
        assert g == e, (ln, g, e, g - e if g is not None else None)
    for (g1, e1, _), (g2, e2, _) in zip(sorted(got, key=lambda x: x[1]), sorted(got, key=lambda x: x[1])[1:]):
        assert g1 <= g2   # monotonic in the true instant


@SQL_FAST
@given(cases=ts_batch())
def test_kv_eventtime_units_and_tz_offset_applied_once(cases) -> None:
    """eventtime s/ms/us/ns, local-as-UTC or true UTC, any tz offset (+hhmm / +hh:mm): ts_ms == the true UTC instant
    (to the unit's precision), offset applied exactly once, monotonic."""
    _kv_ts(cases)


@pytest.mark.stress
@SQL_FULL
@given(cases=ts_batch())
def test_kv_eventtime_units_and_tz_offset_applied_once_200(cases) -> None:
    _kv_ts(cases)


def test_kv_eventtime_is_local_false_trusts_eventtime() -> None:
    """Near-miss for the property above: with eventtime_is_local=false a local-as-UTC eventtime is off by exactly
    the tz offset (so the property really exercises the local branch)."""
    k = json.loads(json.dumps(_cfg()["sources"]["kv_sources"]["fortigate_kv"]))
    k["ts"]["eventtime_is_local"] = False
    ln = 'date=2026-10-24 time=07:30:00 tz="+0530" eventtime=1792827000123 type=traffic action=accept qaidx=0'
    assert kv_rows([ln], "tsnm", k)[ln]["ts_ms"] == 1792807200123 + 330 * 60000
    assert kv_rows([ln], "tsnm2")[ln]["ts_ms"] == 1792807200123


ts_us = st.integers(LO_MS * 1000, HI_MS * 1000)


def _reprs(us: int, off: int) -> list[tuple[str, int]]:
    """Strings of one instant. Sub-ms ISO fractions are ROUNDED half-up by DuckDB epoch_ms (measured); second forms
    are exact; the epoch-ms string is the instant already truncated to ms."""
    t = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=us)
    w = t + dt.timedelta(minutes=off)
    sgn = "-" if off < 0 else "+"
    o = f"{sgn}{abs(off) // 60:02d}:{abs(off) % 60:02d}"
    ms_round, ms, s_ms = (us + 500) // 1000, us // 1000, us // 1_000_000 * 1000
    return [(f"{t:%Y-%m-%dT%H:%M:%S.%f}Z", ms_round), (f"{w:%Y-%m-%dT%H:%M:%S.%f}{o}", ms_round),
            (f"{t:%Y-%m-%d %H:%M:%S.%f}", ms_round), (f"{w:%d/%b/%Y:%H:%M:%S} {o.replace(':', '')}", s_ms),
            (str(ms), ms), (str(us // 1_000_000), s_ms), (f"{t:%Y-%m-%dT%H:%M:%S}Z", s_ms),
            (f"{w:%Y-%m-%dT%H:%M:%S}{o}", s_ms)]


def _ts_expr_eval(us_list: list[int], offs: list[int]) -> list[tuple[str, int, int | None]]:
    reps = [r for us, off in zip(us_list, offs) for r in _reprs(us, off)]
    expr = ingest_sql.ts_expr("x", list(_cfg()["pipeline"]["ingest"]["ts_formats"]))
    got = dict(_con().execute(f"SELECT x, {expr} FROM (SELECT unnest(?::VARCHAR[]) x)", [[r for r, _ in reps]])
               .fetchall())
    return [(r, e, got[r]) for r, e in reps]


@CHEAP
@given(us=st.lists(ts_us, min_size=1, max_size=20), offs=st.lists(st.integers(-48, 56).map(lambda x: x * 15),
                                                                   min_size=20, max_size=20))
def test_ts_expr_same_instant_every_format(us, offs) -> None:
    """ISO Z / ISO offset / space / apache %z / epoch ms / epoch s strings of one instant -> the same UTC ts_ms
    (offset applied once, never the process TZ)."""
    bad = [x for x in _ts_expr_eval(us, offs[:len(us)]) if x[1] != x[2]]
    assert not bad, bad


def _kv_us(us: int) -> int | None:
    t = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=us)
    ln = f'date={t:%Y-%m-%d} time={t:%H:%M:%S} tz="+0000" eventtime={us} type=traffic action=accept qaidx=0'
    return kv_rows([ln], "tsus")[ln]["ts_ms"]


@pytest.mark.xfail(strict=True, reason="QA-PROP-4: sub-millisecond rounding differs by format: FortiGate eventtime "
                   "(us/ns) is TRUNCATED to ms, ISO fractions are ROUNDED half-up (epoch_ms), fractional epoch "
                   "seconds go through DOUBLE*1000 (rounded, with binary error); one instant can get ts_ms that "
                   "differ by 1 ms across sources")
@SQL_FAST
@given(us=ts_us)
@example(us=1792452847480500)
def test_sub_ms_instant_same_ts_ms_in_every_format(us) -> None:
    t = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=us)
    a, b = f"{t:%Y-%m-%dT%H:%M:%S.%f}Z", f"{us // 1_000_000}.{us % 1_000_000:06d}"
    expr = ingest_sql.ts_expr("x", [])
    ga, gb = (_con().execute(f"SELECT {expr} FROM (SELECT ?::VARCHAR x)", [s]).fetchone()[0] for s in (a, b))
    gk = _kv_us(us)
    assert ga == gb == gk, (a, ga, b, gb, "kv", gk)


def test_connect_is_utc_whatever_the_process_tz(monkeypatch: pytest.MonkeyPatch) -> None:
    import time
    monkeypatch.setenv("TZ", "Asia/Kolkata")
    if hasattr(time, "tzset"):
        time.tzset()
    c = db.connect(memory_limit="1GB", threads=2, temp_directory=TMP / "spill")
    try:
        assert c.execute("SELECT current_setting('TimeZone')").fetchone()[0] == "UTC"
        assert c.execute(f"SELECT {ingest_sql.ts_expr('x', [])} FROM (SELECT '2026-10-24 02:00:00' x)"
                         ).fetchone()[0] == 1792807200000
    finally:
        c.close()


# ====================================================================== 3. entity normalization
any_text = st.text(st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00\n\r"), max_size=24)
real_user = st.from_regex(r"(?:[A-Za-z]{1,6}\\)?[A-Za-z0-9._$-]{1,12}(?:@[a-z]{1,6}\.local)?", fullmatch=True)


def sql_user(values: list[str]) -> list[str | None]:
    sql = f"SELECT i, {ingest_sql._user('x')} FROM (SELECT unnest(?::VARCHAR[]) x, unnest(range(?)) i) ORDER BY i"
    return [r[1] for r in _con().execute(sql, [values, len(values)]).fetchall()]


@CHEAP
@given(vals=st.lists(any_text, min_size=1, max_size=20))
def test_ingest_user_normalization_is_canonical_and_idempotent(vals) -> None:
    """_user(x): NULL or trimmed, lower-case, NFC, no DOMAIN\\ / @domain, never '' or '-'; _user(_user(x)) == _user(x)."""
    once = sql_user(vals)
    twice = sql_user([u for u in once if u is not None])
    assert twice == [u for u in once if u is not None]
    for u in once:
        if u is None:
            continue
        assert u not in ("", "-") and B not in u and "@" not in u and u == u.strip(ZS), u
        assert u == unicodedata.normalize("NFC", u) and u == _con().execute("SELECT lower(?)", [u]).fetchone()[0]


@CHEAP
@given(vals=st.lists(real_user.filter(lambda s: s.lower() not in ("none", "n/a")), min_size=1, max_size=20))
def test_user_normalization_parity_ingest_siem_sigma(vals) -> None:
    """The same account normalizes identically in ingest SQL, SIEM-alert input and Sigma literals
    (CORP\\Bob, bob@corp.local, BOB -> bob), so cross-source joins and Sigma user filters line up."""
    for v, s in zip(vals, sql_user(vals)):
        assert siem_alerts.norm_user(v) == s, (v, s)
        if s is not None:   # a '-' literal is NULL in ingest; a Sigma rule on '-' simply never matches
            assert sigma_compile._normalize_user([v.lower()]) == [s], (v, s)


@CHEAP
@given(v=any_text.filter(lambda s: s.strip()))
def test_python_entity_id_matches_sql_entity_id(v) -> None:
    """Graph / gate ids are built in Python (f'host:{v.lower()}'), hub / reach lists in SQL ('host:' || lower(v)).
    For a value already lower-cased by ingest SQL, both must give the same string (so hubs / compromised marks
    match), and the id is idempotent under re-normalization."""
    lv = _con().execute("SELECT lower(?)", [v]).fetchone()[0]
    sql_id = _con().execute("SELECT 'host:' || ?", [lv]).fetchone()[0]
    ids = incident_gate.entities({"subject_host": lv})
    assert ids == {sql_id}
    (eid,) = ids
    typ, val = eid.split(":", 1)
    assert (typ, val) == ("host", lv) and incident_gate.entities({"subject_host": val}) == ids


@CHEAP
@given(v=st.from_regex(r"[A-Za-z0-9.:_-]{1,20}", fullmatch=True), flips=st.lists(st.booleans(), min_size=20,
                                                                              max_size=20))
def test_allowlist_matches_entity_any_case(v, flips) -> None:
    w = "".join(c.upper() if f else c.lower() for c, f in zip(v, flips))
    for typ, col, key in (("host", "src_host", "hosts"), ("user", "target_user", "users"), ("ip", "dst_ip", "ips")):
        assert incident_gate.entities({col: v}) <= incident_gate.allowlist_entities({"allowlist": {key: [w]}})
        assert incident_gate.allowlist_entities({"allowlist": {"entities": [f"{typ}:{w}"]}}) == \
            incident_gate.entities({col: v})


@pytest.mark.xfail(strict=True, reason="QA-PROP-3: DuckDB lower('İ') = 'i' but Python 'İ'.lower() = 'i̇' (2 code "
                   "points), and Python lowers a word-final 'Σ' to 'ς' where DuckDB gives 'σ': a Sigma literal "
                   "user/host value is lowered in Python, the column in SQL, so a case-insensitive Sigma match on a "
                   "value containing U+0130 or a final capital sigma never fires")
@CHEAP
@given(v=any_text.filter(lambda s: s.strip()))
@example(v="İ")
@example(v="ΑΣ")
def test_python_lower_equals_sql_lower(v) -> None:
    assert v.lower() == _con().execute("SELECT lower(?)", [v]).fetchone()[0]


# ====================================================================== 4. Sigma value escaping
W, Q1 = sgt.SpecialChars.WILDCARD_MULTI, sgt.SpecialChars.WILDCARD_SINGLE
SIG_CH = st.one_of(st.sampled_from(["'", "%", "_", B, "*", "?", "''", "' OR 1=1 --", "a", "A", "é", "日", "😀", " "]),
                   st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters="\x00\x01İΣ"))
lit_chunk = st.lists(SIG_CH, min_size=1, max_size=5).map("".join)


def sig_text(n: int) -> Any:
    return st.lists(SIG_CH, max_size=n).map("".join)


pattern = st.lists(st.one_of(lit_chunk, st.just(W), st.just(Q1)), max_size=6)


def sigma_text(parts: list[Any]) -> str:
    return "".join("*" if p is W else "?" if p is Q1 else re.sub(r"([*?\\])", r"\\\1", p) for p in parts)


def ref_regex(parts: list[Any], cased: bool) -> re.Pattern[str]:
    rx = "".join(".*" if p is W else "." if p is Q1 else re.escape(p if cased else p.lower()) for p in parts)
    return re.compile(rx, re.DOTALL)


@st.composite
def candidates(draw: Any, parts: list[Any]) -> list[str]:
    def inst() -> str:
        return "".join(draw(sig_text(3)) if p is W else (draw(SIG_CH)[:1] or "x") if p is Q1 else p
                       for p in parts)
    out = [inst() for _ in range(3)]
    for s in list(out):
        if s:
            i = draw(st.integers(0, len(s) - 1))
            out += [s[:i] + s[i + 1:], s[:i] + "Z" + s[i:], s.upper(), s.swapcase(), s + "x", "x" + s]
    out += draw(st.lists(sig_text(6), max_size=4)) + [""]
    return out


@st.composite
def sigma_case(draw: Any) -> tuple[list[Any], list[str], bool, bool]:
    parts = draw(pattern)
    return parts, draw(candidates(parts)), draw(st.booleans()), draw(st.booleans())


def sigma_eval(parts, cands, cased, substring) -> tuple[set[int], str]:
    s = sgt.SigmaString(sigma_text(parts))
    assert [p for p in s.s if p != ""] == _merge(parts), "pySigma parsed the escaped text differently"
    s = sgt.SigmaCasedString.from_sigma_string(s) if cased else s
    comp = sigma_compile.Compiler(fields={}, exprs=[])
    sql = sigma_compile.render(comp.value(sigma_compile.FieldSpec("v"), s, substring=substring), comp.exprs)
    c = _con()
    c.execute("CREATE OR REPLACE TEMP TABLE qa_sig AS SELECT unnest(?::VARCHAR[]) v, unnest(range(?)) i",
              [cands, len(cands)])
    before = c.execute("SELECT count(*) FROM duckdb_tables()").fetchone()[0]
    hit = {int(r[0]) for r in c.execute(f"SELECT i FROM qa_sig t WHERE {sql}").fetchall()}
    assert c.execute("SELECT count(*) FROM duckdb_tables()").fetchone()[0] == before   # nothing created / dropped
    assert c.execute("SELECT count(*) FROM qa_sig").fetchone()[0] == len(cands)       # nothing deleted
    return hit, sql


def _merge(parts: list[Any]) -> list[Any]:
    out: list[Any] = []
    for p in parts:
        if isinstance(p, str) and out and isinstance(out[-1], str):
            out[-1] += p
        else:
            out.append(p)
    return out


def _sigma_check(case, ascii_only: bool) -> None:
    parts, cands, cased, substring = case
    if substring and not any(isinstance(p, str) and p for p in parts):
        with pytest.raises(sigma_compile.Unsupported):
            sigma_eval(parts, cands, cased, substring)
        return
    hit, sql = sigma_eval(parts, cands, cased, substring)
    ref_parts = ([W] + parts + [W]) if substring else parts
    rx = ref_regex(ref_parts, cased)
    want = {i for i, cnd in enumerate(cands) if rx.fullmatch(cnd if cased else cnd.lower())}
    assert hit == want, (sigma_text(parts), cased, substring, sql,
                         [(cands[i], i in hit, i in want) for i in sorted(hit ^ want)])


@CHEAP
@given(case=sigma_case())
def test_sigma_value_matches_exact_literal_and_wildcard_semantics(case) -> None:
    """Any Sigma value with ' % _ \\ * ? (escaped or not), unicode, injection text compiles (never raises except
    the documented keyword_empty), never injects, and matches exactly the strings the Sigma reference matches:
    '*' any run, '?' exactly one character, everything else literal; |cased vs case-insensitive; keyword = substring."""
    _sigma_check(case, ascii_only=False)


@CHEAP
@given(s=st.text(st.characters(blacklist_categories=("Cs",)), max_size=40))
def test_lit_roundtrips_or_rejects_control_marker(s) -> None:
    if "\x00" in s or "\x01" in s:
        with pytest.raises(sigma_compile.Unsupported):
            sigma_compile.lit(s)
        return
    assert _con().execute(f"SELECT {sigma_compile.lit(s)}").fetchone()[0] == s


# ====================================================================== 5. ingest accounting
GOOD = ('date=2026-10-24 time=07:30:{s:02d} devname="FGT-QA" eventtime=17928270{s:02d}000000000 tz="+0530" '
        'type="traffic" action="accept" srcip=10.0.0.{n} dstip=198.51.100.7 dstport=443 sentbyte={n}')
KINDS = {  # kind -> (bytes, expected drop reason or None for ok, counted in rows_in?)
    "good": (None, None, True),
    "url": (b"http://192.0.2.1:8000/", "unparseable_line (kept in ts_ok=false, action=malformed)", True),
    "text": ("garbage line without pairs é".encode(), "unparseable_line (kept in ts_ok=false, action=malformed)",
             True),
    "no_ts": (b"a=1 b=2 c=3 type=traffic", "missing_or_unparseable_timestamp (kept in ts_ok=false)", True),
    "bad_ts": (b'date=2026-13-45 time=99:99:99 type="traffic" action="accept"',
               "missing_or_unparseable_timestamp (kept in ts_ok=false)", True),
    "bad_utf8": (b'date=2026-10-24 time=07:30:00 devname="FGT-\xff" type="traffic"',
                 "decode_error (invalid UTF-8, line not readable)", True),
    "blank": (b"", None, False),
    "spaces": (b"    ", None, False),
}
ws_only = st.sampled_from([" ", "　", "   ", "\t"])


def _new_ctx(base: Path) -> RunContext:
    c = db.connect(memory_limit="1GB", threads=2, temp_directory=TMP / "spill")
    return RunContext(set_name="qa_props", raw_dir=base / "raw", parquet_dir=base / "pq", out_dir=base / "out",
                      con=c, cfg=config.load_config())


def _accounting_run(files: list[list[str]], crlf: bool, ws: list[str] | None = None) -> None:
    _STATE["acc"] = _STATE.get("acc", 0) + 1
    base = TMP / "acc" / f"run{_STATE['acc']}"   # unique per example: Windows may still hold the last run's files
    shutil.rmtree(base, ignore_errors=True)
    (base / "raw").mkdir(parents=True)
    exp_in = exp_ok = 0
    exp_reasons: dict[str, int] = {}
    nl = b"\r\n" if crlf else b"\n"
    for fi, kinds in enumerate(files):
        body = []
        for li, k in enumerate(["good"] + kinds):    # first line good: the file is routed as FortiGate
            raw, reason, counted = KINDS[k]
            body.append(GOOD.format(s=li % 60, n=li % 250).encode() if raw is None else raw)
            exp_in += counted
            exp_ok += k == "good"
            if reason:
                exp_reasons[reason] = exp_reasons.get(reason, 0) + 1
        for w in ws or []:
            body.append(w.encode())
        (base / "raw" / f"fw{fi}.log").write_bytes(nl.join(body) + nl)
    ctx = _new_ctx(base)
    try:
        profile.run(ctx)
        ingest.run(ctx)
        acc = json.loads((ctx.out_dir / "ingest_accounting.json").read_text(encoding="utf-8"))
        rows = ctx.con.execute(f"SELECT count(*), count(*) FILTER (WHERE ts_ok) FROM read_parquet("
                               f"{db.sql_path(ctx.events_glob)}, hive_partitioning=true)").fetchone()
    finally:
        ctx.con.close()
    (e,) = [a for a in acc if a["rows_in"]]
    assert e["source_type"] == "fortigate_kv"
    assert e["rows_in"] == e["rows_ok"] + e["dropped"]
    assert sum(e["drop_reasons"].values()) == e["dropped"]
    assert e["rows_ok"] == rows[1]
    if ws:
        assert "decode_error (invalid UTF-8, line not readable)" not in e["drop_reasons"] or \
            exp_reasons.get("decode_error (invalid UTF-8, line not readable)"), e["drop_reasons"]
        return
    assert (e["rows_in"], e["rows_ok"], e["dropped"]) == (exp_in, exp_ok, exp_in - exp_ok)
    assert e["drop_reasons"] == exp_reasons


acc_files = st.lists(st.lists(st.sampled_from(sorted(KINDS)), max_size=25), min_size=1, max_size=3)


@ACC_FAST
@given(files=acc_files, crlf=st.booleans())
def test_accounting_exact_for_random_good_bad_mix(files, crlf) -> None:
    """rows_in == rows_ok + dropped == non-blank lines written; each bad kind lands in its exact drop reason."""
    _accounting_run(files, crlf)


@pytest.mark.stress
@ACC_FULL
@given(files=acc_files, crlf=st.booleans())
def test_accounting_exact_for_random_good_bad_mix_100(files, crlf) -> None:
    _accounting_run(files, crlf)


@pytest.mark.xfail(strict=True, reason="QA-PROP-5: a line of only Unicode whitespace (NBSP / U+3000 / EM SPACE) is "
                   "skipped by the reader filter (DuckDB trim strips Zs) but counted by scan_lines (ASCII space "
                   "only), so the gap is booked as 'decode_error (invalid UTF-8)' on a valid UTF-8 file")
@ACC_FAST
@given(files=acc_files.map(lambda fs: [[k for k in f if k != "bad_utf8"] for f in fs]), crlf=st.booleans(),
       ws=st.lists(ws_only.filter(lambda w: w != "\t"), min_size=1, max_size=2))
@example(files=[[]], crlf=False, ws=[" "])
def test_accounting_unicode_whitespace_line_reason(files, crlf, ws) -> None:
    _accounting_run(files, crlf, ws)
