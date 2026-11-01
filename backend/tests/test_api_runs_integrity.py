"""GET /api/runs/{id} "integrity" summary: only well-typed reports reach the UI (types.ts RunIntegritySummary)."""

from __future__ import annotations

from typing import Any

import pytest

from attacklens import api_runs as ar

GOOD = {"verdict": "tampered", "trust_score": 60, "summary": "TAMPERED: 1 critical finding(s)", "scope": "full"}


def test_well_typed_report_passes_through() -> None:
    assert ar._typed_summary({**GOOD, "findings": []}) == GOOD


def test_missing_scope_means_full() -> None:
    rep = {k: v for k, v in GOOD.items() if k != "scope"}
    assert ar._typed_summary(rep) == GOOD


@pytest.mark.parametrize("patch", [
    {"verdict": "ok"}, {"verdict": None},
    {"trust_score": None}, {"trust_score": "60"}, {"trust_score": 60.5}, {"trust_score": True},
    {"trust_score": -1}, {"trust_score": 101},
    {"summary": None}, {"summary": 3},
])
def test_malformed_report_is_ignored(patch: dict[str, Any]) -> None:
    assert ar._typed_summary({**GOOD, **patch}) is None


@pytest.mark.parametrize("rep", [None, [], "tampered", 3])
def test_non_object_report_is_ignored(rep: Any) -> None:
    assert ar._typed_summary(rep) is None


def test_unknown_scope_falls_back_to_full() -> None:
    assert ar._typed_summary({**GOOD, "scope": "weird"})["scope"] == "full"
