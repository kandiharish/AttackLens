"""Authenticity block of integrity_report.json ("do these logs look machine-generated?") against the workflow contract:

  "authenticity": {label: "natural"|"likely_generated"|"unknown", score: 0..100 (higher = more machine-generated),
                   signals: [{id, value, threshold, fired, detail}], reason: str|null}
  - NEVER changes verdict or trust_score (generated-looking logs get a separate yellow warning).
  - absent/null on quick scans; top-level "scope": "quick" | "full".
  - generator label fields (threat, rule, labels, labels_extra, event.kind, event.severity) are never read.

Fixtures are small and hand-shaped (≈17 k rows over 48 h, 6 hosts) so the expected label is unambiguous:
  generated = every host emits exactly every 60 s, in lockstep, flat day/night, whole-second timestamps,
              round-robin users/processes
  natural   = per-host rates differ 10x, 10x day/night swing, bursts with exponential gaps, millisecond jitter
Asserted twice: directly on integrity_authenticity.analyze(con, cfg), and through the Integrate hook
(integrity.run / integrity.check), i.e. the report users see. Fixture size scales with config min_rows (>= 2x).
"""

from __future__ import annotations

import json
import math
import random
import re
import time
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

auth_mod = pytest.importorskip("attacklens.integrity_authenticity")

from attacklens import db, integrity  # noqa: E402
from attacklens.config import REPO_ROOT  # noqa: E402

from .conftest import make_events_parquet  # noqa: E402
from .test_integrity import assert_contract  # noqa: E402  (re-derives verdict + trust_score from findings only)

T0 = 1792807200000  # 2026-10-24T02:00:00Z
S, H = 1000, 3_600_000
SPAN_H = 48
HOSTS = ("ws-a", "ws-b", "ws-c", "ws-d", "srv-e", "srv-f")
USERS = ("svc_web", "asharma", "pmehta", "vreddy")
PROCS = ("svchost.exe", "chrome.exe", "outlook.exe", "powershell.exe", "excel.exe")
LABELS = ("natural", "likely_generated", "unknown")
SIGNAL_KEYS = {"id", "value", "threshold", "fired", "detail"}


# ---------------------------------------------------------------- config-aware sizing
@lru_cache(maxsize=1)
def _min_rows() -> int | None:
    """Largest min-rows style threshold in config/authenticity.yaml (if the file exists), else None."""
    p = REPO_ROOT / "config" / "authenticity.yaml"
    if not p.is_file():
        return None
    import yaml
    found: list[int] = []

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool) and re.search(
                        r"min.*(rows|events)", str(k)):
                    found.append(int(v))
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(yaml.safe_load(p.read_text(encoding="utf-8")))
    return max(found) if found else None


GEN_STEP = 60 * S          # 60 events/host/hour: >= 50 inter-arrival deltas in one hour (periodic_timer computable)
GEN_ROWS = len(HOSTS) * SPAN_H * H // GEN_STEP                     # 17 280


def _scale() -> int:
    """Natural-set rate multiplier: about the generated set's size (>= 2x the configured min_rows)."""
    m = _min_rows() or 0
    return max(5, math.ceil(2 * m / 3557))


# ---------------------------------------------------------------- fixture builders
def _iso_ms(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts // 1000)) + f".{ts % 1000:03d}Z"


def _row(ts: int, host: str, i: int, user: str, proc: str, gen_labels: bool = False) -> dict[str, Any]:
    raw: dict[str, Any] = {"@timestamp": _iso_ms(ts), "host": {"name": host}, "user": {"name": user},
                           "event": {"action": "process_created"},
                           "process": {"name": proc, "command_line": f"{proc} /seq {i}"}}
    if gen_labels:  # the generator's ground-truth fields, as they would look if they slipped through
        raw["event"].update(kind="alert", severity=73, module="edr", dataset="edr.process")
        raw.update(threat={"technique": {"id": ["T1059.001"]}, "tactic": {"name": ["Execution"]}},
                   rule={"name": "synthetic-rule"}, labels={"synthetic": "true", "generator": "edr_log_generator"},
                   labels_extra={"n": 1})
    return {"ts_ms": ts, "host": host, "action": "proc_start", "event_id": 4688, "src_user": user,
            "process_name": proc, "command_line": f"{proc} /seq {i}",
            "raw_line": json.dumps(raw, separators=(",", ":"))}


def generated_rows(gen_labels: bool = False, limit: int | None = None) -> list[dict[str, Any]]:
    """Perfectly periodic, flat, identical cadence: every host every 60 s, lockstep, whole seconds."""
    step = GEN_STEP
    rows, i = [], 0
    for k in range(SPAN_H * H // step):
        for h in HOSTS:
            rows.append(_row(T0 + k * step, h, i, USERS[i % len(USERS)], PROCS[i % len(PROCS)], gen_labels))
            i += 1
            if limit is not None and len(rows) >= limit:
                return rows
    return rows


def natural_rows(gen_labels: bool = False, seed: int = 7) -> list[dict[str, Any]]:
    """Bursty, diurnal, jittered: per-host hourly means (60..6) x scale, x10 by day, 70 % of events in 1-3 bursts."""
    rng = random.Random(seed)
    rates = dict(zip(HOSTS, (60, 40, 25, 15, 10, 6)))
    rows, i = [], 0
    for h in HOSTS:
        for hour in range(SPAN_H):
            hod = (2 + hour) % 24
            mean = rates[h] * _scale() * (1.0 if 8 <= hod < 18 else 0.1)
            n = max(0, int(round(rng.gauss(mean, math.sqrt(mean) + 0.5))))
            base = T0 + hour * H
            stamps: list[int] = []
            n_burst = int(n * 0.7)
            n_bursts = rng.randint(1, 3)
            for b in range(n_bursts if n_burst else 0):
                t = base + rng.randrange(H)
                for _ in range(n_burst // n_bursts + (b < n_burst % n_bursts)):
                    t += int(rng.expovariate(1 / 3.0) * S) + rng.randrange(1000)
                    stamps.append(min(t, base + H - 1))
            stamps += [base + rng.randrange(H) for _ in range(n - len(stamps))]
            for ts in sorted(stamps):
                rows.append(_row(ts, h, i, rng.choice(USERS), rng.choices(PROCS, (50, 25, 15, 3, 7))[0], gen_labels))
                i += 1
    return rows


def clean_raw(tag: str = "a", n: int = 40) -> bytes:
    return b"".join(f"2026-10-24T02:{i:02d}:00Z ws-{tag} app[{i}]: heartbeat {tag}-{i}\n".encode() for i in range(n))


def build(tmp_path: Path, rows: list[dict[str, Any]], name: str, raw: bytes | None = None):
    ctx = make_events_parquet(tmp_path / name, rows)
    ctx.raw_dir.mkdir(parents=True, exist_ok=True)
    (ctx.raw_dir / "edr.log").write_bytes(clean_raw() if raw is None else raw)
    return ctx


def run_report(ctx) -> dict[str, Any]:
    """integrity.run(ctx) (full scope); returns the report file, contract-checked (verdict/score from findings)."""
    integrity.run(ctx)
    rep = json.loads((ctx.out_dir / "integrity_report.json").read_text(encoding="utf-8"))
    return assert_contract(rep)


def rerun(ctx, tmp_path: Path, name: str, raw: bytes | None = None) -> dict[str, Any]:
    """integrity.run on the same events (shared connection/Parquet) with a fresh raw dir and out dir."""
    other = replace(ctx, raw_dir=tmp_path / name / "raw", out_dir=tmp_path / name / "out", stats={})
    other.raw_dir.mkdir(parents=True)
    (other.raw_dir / "edr.log").write_bytes(clean_raw() if raw is None else raw)
    return run_report(other)


def check_block(a: Any) -> dict[str, Any]:
    assert isinstance(a, dict), a
    assert set(a) >= {"label", "score", "signals", "reason"}, sorted(a)
    assert a["label"] in LABELS
    assert isinstance(a["score"], int) and not isinstance(a["score"], bool) and 0 <= a["score"] <= 100
    assert isinstance(a["signals"], list)
    for s in a["signals"]:
        assert set(s) >= SIGNAL_KEYS, s
        assert isinstance(s["id"], str) and s["id"] and isinstance(s["fired"], bool)
        assert isinstance(s["detail"], str)
        assert not (s["fired"] and s["value"] is None), f"a signal with no measured value cannot fire: {s}"
    assert a["reason"] is None or isinstance(a["reason"], str)
    assert len({s["id"] for s in a["signals"]}) == len(a["signals"]), "signal ids must be unique"
    return a


def auth_block(rep: dict[str, Any]) -> dict[str, Any]:
    assert "authenticity" in rep, "full-scope report must carry the authenticity block (Integrate hook)"
    return check_block(rep["authenticity"])


def fired(a: dict[str, Any]) -> set[str]:
    return {s["id"] for s in a["signals"] if s["fired"]}


STRONG = {"flat_hourly_volume", "no_diurnal_cycle", "uniform_host_rate", "periodic_timer"}


# ---------------------------------------------------------------- module-scoped data (each set built once)
@pytest.fixture(scope="module")
def sets(tmp_path_factory: pytest.TempPathFactory):
    tmp = tmp_path_factory.mktemp("auth")
    made = {"gen": build(tmp, generated_rows(), "gen"), "nat": build(tmp, natural_rows(), "nat")}
    yield made
    for c in made.values():
        c.con.close()


@pytest.fixture(scope="module")
def direct(sets) -> dict[str, dict[str, Any]]:
    return {k: check_block(auth_mod.analyze(c.con, c.cfg)) for k, c in sets.items()}


@pytest.fixture(scope="module")
def reps(sets) -> dict[str, dict[str, Any]]:
    return {k: run_report(c) for k, c in sets.items()}


# ---------------------------------------------------------------- fixture sanity (the fixtures say what they claim)
def test_fixture_shapes_are_what_the_tests_claim() -> None:
    g, n = generated_rows(), natural_rows()
    assert len(g) == GEN_ROWS == 17280
    m = _min_rows()
    assert m is None or (len(g) >= 2 * m and len(n) >= 2 * m), (len(g), len(n), m)
    gaps = {b["ts_ms"] - a["ts_ms"] for a, b in zip(g[::6], g[6::6])}
    assert gaps == {GEN_STEP}                                   # perfectly periodic per host
    assert all(r["ts_ms"] % 1000 == 0 for r in g)
    assert 0.5 * len(g) < len(n) < 1.6 * len(g)                            # comparable sizes
    day = sum(1 for r in n if 8 <= time.gmtime(r["ts_ms"] // 1000).tm_hour < 18)
    assert day / len(n) > 0.75                                             # strongly diurnal
    assert sum(1 for r in n if r["ts_ms"] % 1000) / len(n) > 0.9           # millisecond jitter
    per_host = {h: sum(1 for r in n if r["host"] == h) for h in HOSTS}
    assert max(per_host.values()) > 5 * min(per_host.values())            # rates differ across hosts


# ---------------------------------------------------------------- labels (direct: analyze)
def test_analyze_periodic_flat_lockstep_is_likely_generated(direct) -> None:
    a = direct["gen"]
    assert a["label"] == "likely_generated", a
    assert STRONG <= fired(a), a
    assert a["score"] >= 90 and a["reason"]


def test_analyze_bursty_diurnal_jittered_is_natural(direct) -> None:
    a = direct["nat"]
    assert a["label"] == "natural", a
    assert not (STRONG & fired(a)), a
    assert a["score"] < 50


def test_analyze_generated_scores_higher_than_natural(direct) -> None:
    g, n = direct["gen"], direct["nat"]
    assert g["score"] > n["score"] and len(fired(g)) > len(fired(n)), (g, n)


def test_analyze_signal_values_are_measured_not_constant(direct) -> None:
    """Measure, never assert: same signal ids for both sets, and the volume/cadence values differ."""
    gv = {s["id"]: s["value"] for s in direct["gen"]["signals"]}
    nv = {s["id"]: s["value"] for s in direct["nat"]["signals"]}
    assert gv and set(gv) == set(nv)
    for k in ("flat_hourly_volume", "no_diurnal_cycle", "uniform_host_rate"):
        assert gv[k] is not None and nv[k] is not None and gv[k] < nv[k], (k, gv[k], nv[k])
    assert gv["no_diurnal_cycle"] == 0 and gv["uniform_host_rate"] == 0       # exactly flat / identical by design


def test_analyze_below_min_rows_is_unknown_with_reason(tmp_path: Path) -> None:
    m = _min_rows()
    n = (m - 1) if m and m > 1 else 10                    # near-miss when the minimum is configured
    ctx = make_events_parquet(tmp_path / "few", generated_rows(limit=n))
    try:
        a = check_block(auth_mod.analyze(ctx.con, ctx.cfg))
    finally:
        ctx.con.close()
    assert a["label"] == "unknown" and a["score"] == 0, a
    assert isinstance(a["reason"], str) and str(n) in a["reason"], a


def test_analyze_leaves_no_temp_tables(sets) -> None:
    c = sets["gen"]
    q = "SELECT table_name FROM duckdb_tables() WHERE temporary"
    before = {r[0] for r in c.con.execute(q).fetchall()}
    auth_mod.analyze(c.con, c.cfg)
    assert {r[0] for r in c.con.execute(q).fetchall()} == before


# ---------------------------------------------------------------- through the Integrate hook (the report users see)
def test_report_carries_same_block_as_analyze(reps, direct) -> None:
    for k in ("gen", "nat"):
        a = auth_block(reps[k])
        assert (a["label"], a["score"], fired(a)) == (direct[k]["label"], direct[k]["score"], fired(direct[k]))
        assert reps[k]["scope"] == "full"


def test_generated_label_never_downgrades_verdict(reps) -> None:
    rep = reps["gen"]                                      # assert_contract already re-derived score + verdict
    assert auth_block(rep)["label"] == "likely_generated"
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 100, (rep["verdict"], rep["trust_score"])
    assert [c["id"] for c in rep["checks"]] == list(integrity.CHECK_IDS)       # no 11th "authenticity" check
    assert all(f["check"] in integrity.CHECK_IDS for f in rep["findings"])
    assert "generat" not in rep["summary"].lower()        # the integrity summary is about tampering only


def test_verdict_identical_when_authenticity_breaks(sets, reps, tmp_path: Path,
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    """Same data, authenticity forced to raise: run still succeeds; verdict, score, checks, findings unchanged."""
    with_block = reps["gen"]
    assert auth_block(with_block)["label"] == "likely_generated"
    monkeypatch.setattr(auth_mod, "analyze", _boom)
    monkeypatch.setattr(auth_mod, "_columns", _boom)      # also caught if the hook bound analyze by name
    without = rerun(sets["gen"], tmp_path, "b")
    assert (without["verdict"], without["trust_score"]) == (with_block["verdict"], with_block["trust_score"])
    assert without["checks"] == with_block["checks"] and without["findings"] == with_block["findings"]
    a = without.get("authenticity")
    assert a is None or a.get("label") == "unknown", a    # a broken assessment never fakes a label


def _boom(*_a: Any, **_k: Any) -> Any:
    raise RuntimeError("forced authenticity failure")


def test_tampered_verdict_unchanged_by_natural_label(sets, reps, tmp_path: Path) -> None:
    """A 64-byte NUL run makes the report tampered (exactly one critical = -40 vs the same events with clean raw
    files) whatever the authenticity label says. (The natural set alone is suspect 60: its quiet low-rate hosts
    trip silence_gap at night - that is the engine measuring, not authenticity.)"""
    data = clean_raw()
    rep = rerun(sets["nat"], tmp_path, "t", raw=data[:200] + b"\x00" * 64 + data[264:])
    clean = reps["nat"]
    assert auth_block(rep)["label"] == auth_block(clean)["label"] == "natural"
    z = [f for f in rep["findings"] if f["check"] == "zeroed_regions"]
    assert [(f["severity"], f["count"]) for f in z] == [("critical", 64)]
    assert rep["verdict"] == "tampered" and rep["trust_score"] == max(0, clean["trust_score"] - 40)
    assert [f for f in rep["findings"] if f["check"] != "zeroed_regions"] == \
        [f for f in clean["findings"] if f["check"] != "zeroed_regions"]


def test_quick_scan_has_no_authenticity_and_scope_quick(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "edr.log").write_bytes(clean_raw())
    rep = integrity.check(raw, tmp_path / "out", parquet_dir=tmp_path / "no_parquet")
    assert rep["scope"] == "quick"
    assert rep.get("authenticity") is None
    assert rep["verdict"] == "trusted" and rep["trust_score"] == 100


# ---------------------------------------------------------------- generator labels never read
class _SpyCon:
    """Records every SQL text sent through execute/sql; delegates everything else to the real connection."""

    def __init__(self, con: Any) -> None:
        self._con, self.sql_log = con, []

    def execute(self, sql: str, *a: Any, **k: Any) -> Any:
        self.sql_log.append(sql)
        return self._con.execute(sql, *a, **k)

    def sql(self, sql: str, *a: Any, **k: Any) -> Any:
        self.sql_log.append(sql)
        return self._con.sql(sql, *a, **k)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._con, name)


LABEL_SQL_RX = re.compile(r"\b(threat|labels|labels_extra|raw_line|event_kind|event_severity)\b|\brule\b"
                          r"|event\.(kind|severity)", re.I)


def test_label_columns_present_but_never_queried(sets) -> None:
    """The events view really has threat/rule/labels/labels_extra/event_kind/event_severity columns (values that
    scream 'synthetic') and the config asks for them as template columns: no SQL ever names them, and the
    natural set stays natural."""
    ctx = sets["nat"]
    try:
        ctx.con.execute("CREATE OR REPLACE VIEW events AS SELECT *, 'T1059.001' AS threat, 'synthetic-rule' AS rule,"
                        " 'synthetic' AS labels, 'generator' AS labels_extra, 'alert' AS event_kind,"
                        f" 73 AS event_severity FROM read_parquet({db.sql_path(ctx.events_glob)}, "
                        f"hive_partitioning=true, union_by_name=true, hive_types={db.HIVE_TYPES})")
        cols = {r[0] for r in ctx.con.execute("DESCRIBE events").fetchall()}
        assert {"threat", "rule", "labels", "labels_extra", "event_kind", "event_severity"} <= cols
        cfg = json.loads(json.dumps(ctx.cfg, default=str))
        tmpl = cfg.setdefault("authenticity", {}).setdefault("signals", {}).setdefault("low_template_diversity", {})
        tmpl["columns"] = list(tmpl.get("columns") or ["action", "process_name"]) + [
            "threat", "rule", "labels", "labels_extra", "event_kind", "event_severity", "raw_line"]
        spy = _SpyCon(ctx.con)
        a = check_block(auth_mod.analyze(spy, cfg))
    finally:
        db.register_events(ctx.con, ctx.events_glob)      # restore the plain view for the other tests
    assert spy.sql_log, "analyze ran no SQL through the connection it was given"
    bad = [q for q in spy.sql_log if LABEL_SQL_RX.search(q)]
    assert not bad, f"authenticity SQL names a label column: {bad[:2]}"
    assert a["label"] == "natural", a


def test_generator_labels_in_raw_lines_change_nothing(direct, tmp_path: Path) -> None:
    """Raw lines that also carry threat/rule/labels/event.kind give the same label, score and fired signals.
    (Natural direction: reading a label would flip it to likely_generated; the SQL spy test covers the rest.)"""
    for k, rows in (("nat", natural_rows(gen_labels=True)),):
        ctx = make_events_parquet(tmp_path / k, rows)
        try:
            a = check_block(auth_mod.analyze(ctx.con, ctx.cfg))
        finally:
            ctx.con.close()
        assert (a["label"], a["score"], fired(a)) == (direct[k]["label"], direct[k]["score"], fired(direct[k])), k


def test_config_never_names_a_label_field() -> None:
    cfg = REPO_ROOT / "config" / "authenticity.yaml"
    if not cfg.is_file():
        pytest.skip("config/authenticity.yaml not present (module defaults only)")
    import yaml
    flat = json.dumps(yaml.safe_load(cfg.read_text(encoding="utf-8")))
    assert not re.search(r"\b(labels_extra|event\.kind|event\.severity|event_kind|event_severity|raw_line)\b"
                         r"|\"(threat|rule|labels)\"", flat), "config/authenticity.yaml names a label field"


# ---------------------------------------------------------------- bounded dense hour grid (flat_hourly_volume)
def _flat(a: dict[str, Any]) -> dict[str, Any]:
    return next(s for s in a["signals"] if s["id"] == "flat_hourly_volume")


def test_flat_volume_ignores_stray_timestamps(direct, tmp_path: Path) -> None:
    """One epoch-0 row per host must not stretch the per-host grid back to 1970 (0-filled hours = huge grid,
    dispersion blown up): the signal is the same as on the clean set."""
    strays = [_row(0, h, 10**6 + j, "svc_web", "svchost.exe") for j, h in enumerate(HOSTS)]
    ctx = make_events_parquet(tmp_path / "stray", generated_rows() + strays)
    try:
        t0 = time.perf_counter()
        a = check_block(auth_mod.analyze(ctx.con, ctx.cfg))
        wall = time.perf_counter() - t0
    finally:
        ctx.con.close()
    clean = _flat(direct["gen"])
    got = _flat(a)
    assert got["value"] is not None and got["fired"] == clean["fired"], got
    assert got["value"] == pytest.approx(clean["value"], rel=0.05), (got, clean)
    assert wall < 10, f"analyze took {wall:.1f} s on {GEN_ROWS} rows (dense grid not bounded)"


def test_flat_volume_grid_capped_per_host(sets) -> None:
    """A host span longer than max_grid_hours is clipped to its most recent max_grid_hours interior hours."""
    c = sets["gen"]
    cfg = json.loads(json.dumps(c.cfg, default=str))
    sec = cfg.setdefault("authenticity", {})
    sig = sec.setdefault("signals", {}).setdefault("flat_hourly_volume", {})
    sig["max_grid_hours"] = 30
    got = _flat(check_block(auth_mod.analyze(c.con, cfg)))
    assert got["value"] is not None, got
    assert "clipped" in got["detail"] and "30" in got["detail"], got
