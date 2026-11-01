"""Stage 2.5 spill above episode_cap (episodes._spill, linking.yaml `spill`) and the columnar (unnest) inserts that
replaced executemany (detect_sql.create_attack_table, incidents._evidence). Tiny hand-checked fixtures: with no
rule_host_baseline.parquet, rarity = 1 and confidence = severity, so every rank below is computed by hand.

Fixture (7 episodes, 1 seed): A seed (conf 90, svc_backup / srv-dc-01); B one hop from A (svc_backup, 1 h later);
fill candidates on unrelated users/hosts: G 59, D 56, C 55 (rule `noisy`), E 50 (rule `other`), F 30 (rule `low`).
fill_to_cap ranking (band 10, round-robin over (rule_id, technique_id)): A, B, G, E, D, C, F.
Pure-confidence order would be A, B, G, D, C, E, F - so cap 4 tells the two apart (E vs D).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attacklens import detect_sql, episodes, incidents, link

from .conftest import query, write_episodes
from .test_detect import H, MIN, T0, _alert, _episode_ctx

SPILL_ALERTS = {
    "A": _alert(T0, rule="seed_rule", severity=90, src_user="svc_backup", host="srv-dc-01", seq=1,
                technique="T1110", tactic="Credential Access"),
    "B": _alert(T0 + H, rule="discovery_system", severity=40, src_user="svc_backup", host="ws-fin-010", seq=2,
                technique="T1082", tactic="Discovery"),
    "C": _alert(T0 + 2 * H, rule="noisy", severity=55, src_user="u1", host="h-1", seq=3),
    "D": _alert(T0 + 2 * H + MIN, rule="noisy", severity=56, src_user="u2", host="h-2", seq=4),
    "G": _alert(T0 + 2 * H + 2 * MIN, rule="noisy", severity=59, src_user="u3", host="h-3", seq=5),
    "E": _alert(T0 + 2 * H + 3 * MIN, rule="other", severity=50, src_user="u4", host="h-4", seq=6,
                technique="T1057", tactic="Discovery"),
    "F": _alert(T0 + 2 * H + 4 * MIN, rule="low", severity=30, src_user="u5", host="h-5", seq=7),
}
RANKED = ["A", "B", "G", "E", "D", "C", "F"]


def _spill_run(tmp: Path, cap: int, fill: bool | None = None) -> tuple[dict, list[str], list[str], dict]:
    """episodes.run with episode_cap = cap -> (stats, kept letters, spilled letters, confidence per letter)."""
    ctx = _episode_ctx(tmp, list(SPILL_ALERTS.values()))
    ctx.cfg["rules"]["thresholds"]["episode_cap"] = cap
    if fill is not None:
        ctx.cfg["linking"]["spill"]["fill_to_cap"] = fill
    by_seq = {a["source_seq"]: k for k, a in SPILL_ALERTS.items()}
    try:
        stats = episodes.run(ctx)
        rd = lambda f: query(ctx, f"SELECT source_seq, confidence FROM read_parquet("  # noqa: E731
                                  f"'{(ctx.work_dir / f).as_posix()}')")
        kept, spilled = rd("episodes.parquet"), rd("episodes_spilled.parquet")
    finally:
        ctx.con.close()
    conf = {by_seq[int(r["source_seq"])]: r["confidence"] for r in kept + spilled}
    return (stats, sorted(by_seq[int(r["source_seq"])] for r in kept),
            sorted(by_seq[int(r["source_seq"])] for r in spilled), conf)


def test_fixture_confidence_is_severity(tmp_path: Path) -> None:
    _, kept, spilled, conf = _spill_run(tmp_path, 100)
    assert (kept, spilled) == (sorted(SPILL_ALERTS), [])
    assert conf == {k: float(a["severity"]) for k, a in SPILL_ALERTS.items()}


@pytest.mark.parametrize("cap, tiers", [
    (1, (1, 0, 0)), (2, (1, 1, 0)), (3, (1, 1, 1)), (4, (1, 1, 2)), (6, (1, 1, 4)),
])
def test_fill_to_cap_keeps_exactly_cap_in_rank_order(tmp_path: Path, cap: int, tiers: tuple) -> None:
    stats, kept, spilled, _ = _spill_run(tmp_path, cap)
    assert kept == sorted(RANKED[:cap]) and spilled == sorted(RANKED[cap:])
    assert (stats["episodes"], stats["spilled"], stats["episodes_total"], stats["episode_cap"]) == \
        (cap, 7 - cap, 7, cap)
    assert stats["seeds"] == 1
    assert stats["spill_by_tier"] == {"kept_seed": tiers[0], "kept_seed_neighbourhood": tiers[1],
                                      "kept_fill": tiers[2], "seed_neighbourhood_total": 2}
    # accounting invariant: kept + spilled = total, disjoint
    assert set(kept) | set(spilled) == set(SPILL_ALERTS) and not set(kept) & set(spilled)


def test_fill_round_robins_over_rules(tmp_path: Path) -> None:
    # cap 4: the fourth slot goes to E (rule `other`, conf 50), not D (third `noisy` episode, conf 56)
    _, kept, _, _ = _spill_run(tmp_path, 4)
    assert "E" in kept and "D" not in kept


def test_cap_at_total_spills_nothing(tmp_path: Path) -> None:
    stats, kept, spilled, _ = _spill_run(tmp_path, 7)
    assert (kept, spilled) == (sorted(SPILL_ALERTS), [])
    assert (stats["episodes"], stats["spilled"], stats["episodes_total"], stats["spill_by_tier"]) == (7, 0, 7, {})


def test_fill_to_cap_false_keeps_only_seed_neighbourhood(tmp_path: Path) -> None:
    stats, kept, spilled, _ = _spill_run(tmp_path, 4, fill=False)
    assert kept == ["A", "B"] and spilled == ["C", "D", "E", "F", "G"]
    assert (stats["episodes"], stats["spilled"], stats["episodes_total"]) == (2, 5, 7)
    assert stats["spill_by_tier"] == {"kept_seed": 1, "kept_seed_neighbourhood": 1, "kept_fill": 0,
                                      "seed_neighbourhood_total": 2}


def test_spill_is_deterministic_under_input_order(tmp_path: Path) -> None:
    got = []
    for k, order in enumerate((list(SPILL_ALERTS.values()), list(reversed(SPILL_ALERTS.values())))):
        ctx = _episode_ctx(tmp_path / f"r{k}", order)
        ctx.cfg["rules"]["thresholds"]["episode_cap"] = 4
        try:
            episodes.run(ctx)
            got.append(sorted(r["episode_id"] for r in query(
                ctx, f"SELECT episode_id FROM read_parquet('{(ctx.work_dir / 'episodes.parquet').as_posix()}')")))
        finally:
            ctx.con.close()
    assert got[0] == got[1] and len(got[0]) == 4


def test_spill_accounting_carries_into_stage4(tmp_path: Path) -> None:
    """episodes_total = in_incidents + in_suppressed + spilled, counted by incidents.run."""
    ctx = _episode_ctx(tmp_path, list(SPILL_ALERTS.values()))
    ctx.cfg["rules"]["thresholds"]["episode_cap"] = 4
    try:
        ep_stats = episodes.run(ctx)
        link.run(ctx)
        st = incidents.run(ctx)
    finally:
        ctx.con.close()
    acc = st["episode_accounting"]
    assert acc["ok"] is True and acc["missing"] == 0 and acc["duplicated"] == 0
    assert acc["episodes"] == acc["in_incidents"] + acc["in_suppressed"] == ep_stats["episodes"] == 4
    assert (st["episodes_spilled"], st["episodes_total"]) == (3, 7)


# ================================================================ columnar inserts: exact rows
def _attack_rows(con, attack: dict) -> list[tuple]:
    detect_sql.create_attack_table(con, attack)
    return con.execute("SELECT * FROM al_attack").fetchall()


def test_attack_table_exact_rows(tmp_path: Path) -> None:
    ctx = _episode_ctx(tmp_path, [])
    try:
        fx = {"techniques": {"T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
                             "T1059.001": {"name": "PowerShell's", "tactic": "Execution"},
                             "T0001": {"name": None}}}
        small = _attack_rows(ctx.con, fx)
        empty = _attack_rows(ctx.con, {})
        types = [(r[0], r[1]) for r in ctx.con.execute("DESCRIBE al_attack").fetchall()]
        full = _attack_rows(ctx.con, ctx.cfg["attack"])
        tech = ctx.cfg["attack"]["techniques"]
    finally:
        ctx.con.close()
    assert small == [("T1059", "Command and Scripting Interpreter", "Execution"),
                     ("T1059.001", "PowerShell's", "Execution"), ("T0001", None, None)]
    assert empty == [] and types == [("technique_id", "VARCHAR"), ("name", "VARCHAR"), ("tactic", "VARCHAR")]
    assert full == [(k, v.get("name"), v.get("tactic")) for k, v in tech.items()] and len(full) == len(tech) > 600


def test_evidence_lookup_exact(tmp_path: Path) -> None:
    ctx = _episode_ctx(tmp_path, [])
    try:
        write_episodes(ctx, [{"episode_id": "e'1", "ts_ms": T0, "host": "h", "tactic": "Execution",
                              "evidence_lines": ["a", "b" * 400, "c", "d"]},
                             {"episode_id": "e2", "ts_ms": T0, "host": "h", "tactic": "Execution"}])
        p = incidents._params(ctx.cfg)
        got = incidents._evidence(ctx, {"e'1", "e2", "missing"}, p)
        left = ctx.con.execute("SELECT count(*) FROM duckdb_tables() WHERE table_name = '_ev_ids'").fetchone()[0]
    finally:
        ctx.con.close()
    n, k = p["ev_chars"], p["ev_lines"]
    assert got == {"e'1": ["a", "b" * (n - 1) + "…", "c", "d"][:k], "e2": ["evidence e2"]}
    assert left == 0


def test_spill_section_shipped() -> None:
    from attacklens import config
    sp = episodes.spill_params(config.load_config())
    assert sp == {"fill_to_cap": True, "confidence_band": 10.0, "diversity_key": ["rule_id", "technique_id"]}
