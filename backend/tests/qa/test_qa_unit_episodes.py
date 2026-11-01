"""QA unit / white-box tests for Stage 2.5 (attacklens.episodes), track qa_coverage_unit.

Baseline coverage: the only unexecuted branch was "more seeds than the cap" (seed episodes spilled, a warning
logged). Exact kept / spilled split by confidence, plus the near miss (cap = number of seeds: nothing lost).
spill_params normalisation is pinned too (unknown diversity keys dropped, negative band clamped to 0).
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from attacklens import episodes

from ..conftest import query
from ..test_detect import H, T0, _alert, _episode_ctx

SEEDS = {
    "S90": _alert(T0, rule="seed_a", severity=90, src_user="u1", host="h-1", seq=1, technique="T1110",
                  tactic="Credential Access"),
    "S80": _alert(T0 + H, rule="seed_b", severity=80, src_user="u2", host="h-2", seq=2, technique="T1059",
                  tactic="Execution"),
    "N30": _alert(T0 + 2 * H, rule="low", severity=30, src_user="u3", host="h-3", seq=3),
}


def _run(tmp: Path, cap: int) -> tuple[dict, list[str], list[str]]:
    ctx = _episode_ctx(tmp, list(SEEDS.values()))
    ctx.cfg["rules"]["thresholds"]["episode_cap"] = cap
    by_seq = {a["source_seq"]: k for k, a in SEEDS.items()}
    try:
        stats = episodes.run(ctx)
        rd = lambda f: sorted(by_seq[int(r["source_seq"])] for r in query(  # noqa: E731
            ctx, f"SELECT source_seq FROM read_parquet('{(ctx.work_dir / f).as_posix()}')"))
        kept, spilled = rd("episodes.parquet"), rd("episodes_spilled.parquet")
    finally:
        ctx.con.close()
    return stats, kept, spilled


def test_more_seeds_than_cap_spills_lowest_seed_and_warns(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="attacklens.episodes"):
        stats, kept, spilled = _run(tmp_path, 1)
    assert (kept, spilled) == (["S90"], ["N30", "S80"])
    assert (stats["episodes"], stats["spilled"], stats["episodes_total"], stats["seeds"]) == (1, 2, 3, 1)
    assert stats["spill_by_tier"]["kept_seed"] == 1
    assert any("1 seed episodes spilled" in r.getMessage() for r in caplog.records)


def test_cap_equal_to_seeds_loses_no_seed(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="attacklens.episodes"):
        stats, kept, spilled = _run(tmp_path, 2)
    assert (kept, spilled) == (["S80", "S90"], ["N30"])
    assert stats["seeds"] == 2
    assert not any("seed episodes spilled" in r.getMessage() for r in caplog.records)


def test_spill_params_normalised() -> None:
    sp = episodes.spill_params({"linking": {"spill": {"diversity_key": ["rule_id", "bogus", "tactic"],
                                                      "confidence_band": -5}}})
    assert sp["diversity_key"] == ["rule_id", "tactic"] and sp["confidence_band"] == 0.0
    d = episodes.spill_params({})
    assert d["diversity_key"] == [k for k in episodes.SPILL_DEFAULTS.get("diversity_key") or []
                                  if k in {"rule_id", "technique_id", "tactic", "subject_host"}]
