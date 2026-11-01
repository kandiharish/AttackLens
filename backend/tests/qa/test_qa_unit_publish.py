"""QA unit / white-box tests for Stage 5 (attacklens.publish), track qa_coverage_unit.

Baseline coverage: push_to_sinks' failure branch never ran (a sink failure must never fail the run). Also pinned:
make_narrative accepting a dict from narrative.generate, falling back on an invalid one, fallback_narrative's exact
text, and summary() host de-duplication in backbone order.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from attacklens import narrative, publish
from attacklens.models import EntryPoint, Incident, Narrative, Step


def _step(k: int, host: str | None, tactic: str) -> Step:
    return Step(step=k, episode_id=f"e{k}", ts="2026-10-30T01:00:00Z", technique_id="T1110", tactic=tactic,
                host=host, severity=80, confidence=80, merged_alert_count=1)


def _inc() -> Incident:
    bb = [_step(0, "srv-dc-01", "Credential Access"), _step(1, "ws-fin-010", "Execution"),
          _step(2, "srv-dc-01", "Execution"), _step(3, None, "Exfiltration")]
    return Incident(id="inc-12345678", risk=70, first_ts="2026-10-30T01:00:00Z", last_ts="2026-10-30T02:00:00Z",
                    merged_alert_count=9, episode_count=4, entry_point=EntryPoint(step=0, summary="Brute Force"),
                    tactics=["Credential Access", "Execution", "Exfiltration"], backbone=bb,
                    narrative=Narrative(text="", source="template"))


def test_fallback_narrative_exact_text() -> None:
    n = publish.fallback_narrative(_inc())
    assert n.source == "template"
    assert n.text == ("4 linked steps across 2 host(s) (SRV-DC-01, WS-FIN-010) from 2026-10-30T01:00:00Z to "
                      "2026-10-30T02:00:00Z: Credential Access -> Execution -> Exfiltration. Entry: Brute Force.")


def test_summary_hosts_unique_in_order() -> None:
    s = publish.summary(_inc())
    assert s.hosts == ["srv-dc-01", "ws-fin-010"] and s.entry_summary == "Brute Force" and s.episode_count == 4


def test_make_narrative_accepts_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(narrative, "generate", lambda inc, cfg: {"text": "from llm", "source": "llm"})
    assert publish.make_narrative(_inc(), {}) == Narrative(text="from llm", source="llm")


def test_make_narrative_invalid_dict_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(narrative, "generate", lambda inc, cfg: {"text": "x", "source": "gpt"})   # bad enum
    n = publish.make_narrative(_inc(), {})
    assert n == publish.fallback_narrative(_inc())


def test_push_to_sinks_failure_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from attacklens import sinks

    def boom(cfg):
        raise RuntimeError("collector down")
    monkeypatch.setattr(sinks, "enabled_sinks", boom)
    out = publish.push_to_sinks(SimpleNamespace(cfg={}), [_inc()], [{}])
    assert out == {"error": "RuntimeError: collector down"}


def test_push_to_sinks_disabled_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    from attacklens import sinks
    monkeypatch.setattr(sinks, "enabled_sinks", lambda cfg: [])
    called: list[int] = []
    monkeypatch.setattr(sinks, "publish_all", lambda items, cfg: called.append(1) or {})
    assert publish.push_to_sinks(SimpleNamespace(cfg={}), [_inc()], [{}]) == {} and called == []


def test_push_to_sinks_enabled_passes_dumped_pairs(monkeypatch: pytest.MonkeyPatch) -> None:
    from attacklens import sinks
    seen: list = []
    monkeypatch.setattr(sinks, "enabled_sinks", lambda cfg: ["webhook"])
    monkeypatch.setattr(sinks, "publish_all", lambda items, cfg: seen.extend(items) or {"webhook": {"sent": 1}})
    out = publish.push_to_sinks(SimpleNamespace(cfg={}), [_inc()], [{"id": "inc-12345678"}])
    assert out == {"webhook": {"sent": 1}}
    assert len(seen) == 1 and seen[0][0]["id"] == "inc-12345678" and seen[0][1] == {"id": "inc-12345678"}
