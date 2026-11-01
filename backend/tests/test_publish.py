"""Stage 5 publish tests (DEVELOPMENT.md §4 Stage 5, §15.2): files per incident, index sorted by risk, stale files
removed, narrative failure -> deterministic template."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from attacklens import narrative, publish
from attacklens.models import Incident, IncidentSummary, dump

from .conftest import make_events_parquet

MOCK = Path(__file__).resolve().parents[2] / "frontend" / "src" / "mock" / "incident.json"


@pytest.fixture
def ctx(tmp_path: Path):
    c = make_events_parquet(tmp_path, [{"ts_ms": 1792807200000, "action": "other", "host": "h"}])
    base = json.loads(MOCK.read_text(encoding="utf-8"))
    incs = []
    for inc_id, risk in (("inc-0000aaaa", 40), (base["id"], base["risk"]), ("inc-0000bbbb", 95)):
        d = copy.deepcopy(base)
        d["id"], d["risk"] = inc_id, risk
        d["narrative"] = {"text": "", "source": "template"}
        incs.append(dump(Incident.model_validate(d)))
    (c.work_dir / "incidents.json").write_text(json.dumps(incs), encoding="utf-8")
    (c.out_dir / "incidents").mkdir(parents=True, exist_ok=True)
    (c.out_dir / "incidents" / "inc-deadbeef.json").write_text("{}", encoding="utf-8")  # stale, from an old run
    yield c
    c.con.close()


def _read(ctx, name: str):
    return json.loads((ctx.out_dir / name).read_text(encoding="utf-8"))


def test_publish_files_index_and_stale_removed(ctx, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    stats = publish.run(ctx)
    assert stats["published"] == 3 and stats["narrative_sources"] == {"template": 3}
    files = sorted(p.name for p in (ctx.out_dir / "incidents").glob("*.json"))
    assert files == ["inc-0000aaaa.json", "inc-0000bbbb.json", "inc-3f2a9c1e.json"]  # stale file gone
    index = _read(ctx, "incidents_index.json")
    assert [(r["id"], r["risk"]) for r in index] == [("inc-0000bbbb", 95), ("inc-3f2a9c1e", 86),
                                                    ("inc-0000aaaa", 40)]
    for r in index:
        IncidentSummary.model_validate(r)
    for f in files:
        inc = Incident.model_validate(_read(ctx, f"incidents/{f}"))
        assert inc.narrative.source == "template" and inc.narrative.text
        assert "{{" not in inc.narrative.text


def test_publish_narrative_exception_falls_back(ctx, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a, **k):
        raise RuntimeError("narrative exploded")

    monkeypatch.setattr(narrative, "generate", boom)
    publish.run(ctx)
    inc = Incident.model_validate(_read(ctx, "incidents/inc-3f2a9c1e.json"))
    assert inc.narrative.source == "template"
    assert inc.narrative.text == publish.fallback_narrative(inc).text and inc.narrative.text


def test_publish_rerun_byte_identical(ctx, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    publish.run(ctx)
    first = {p.name: p.read_bytes() for p in (ctx.out_dir / "incidents").glob("*.json")}
    idx = (ctx.out_dir / "incidents_index.json").read_bytes()
    publish.run(ctx)
    assert {p.name: p.read_bytes() for p in (ctx.out_dir / "incidents").glob("*.json")} == first
    assert (ctx.out_dir / "incidents_index.json").read_bytes() == idx


def test_publish_empty_work_writes_empty_index(ctx) -> None:
    (ctx.work_dir / "incidents.json").write_text("[]", encoding="utf-8")
    publish.run(ctx)
    assert _read(ctx, "incidents_index.json") == []
    assert list((ctx.out_dir / "incidents").glob("*.json")) == []


# ================================================================ user-facing evidence bound, end to end
def test_published_evidence_at_most_300_chars_with_ellipsis(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """500-char raw lines -> raw_alerts keep max+1 -> every published Step.evidence line <= 300, cut ones end in
    an ellipsis (299 chars + '…'). Stages run for real: lookups, detect, episodes, link, incidents, publish."""
    from attacklens import config, detect, episodes, incidents, link, lookups
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    T0 = 1792807200000
    pad = lambda i: (f'{{"i":{i},"pad":"' + "z" * 500)[:500]  # noqa: E731  exactly 500 chars
    rows = [{"ts_ms": T0 + i * 1000, "action": "login_failed", "outcome": "failure", "event_id": 4625,
             "logon_type": 3, "host": "srv-dc-01", "target_user": "svc_backup", "src_ip": "203.0.113.57",
             "raw_line": pad(i)} for i in range(60)]
    rows.append({"ts_ms": T0 + 70_000, "action": "login_success", "outcome": "success", "event_id": 4624,
                 "logon_type": 3, "host": "srv-dc-01", "target_user": "svc_backup", "src_ip": "203.0.113.57",
                 "raw_line": pad(99)})
    ctx = make_events_parquet(tmp_path / "e2e", rows)
    try:
        for stage in (lookups, detect, episodes, link, incidents, publish):
            stage.run(ctx)
        files = sorted((ctx.out_dir / "incidents").glob("*.json"))
        incs = [Incident.model_validate_json(f.read_text(encoding="utf-8")) for f in files]
    finally:
        ctx.con.close()
    n = int(config.load_config()["linking"]["path"]["max_evidence_chars"])
    assert n == 300 and incs, "expected the brute force + success incident"
    lines = [x for inc in incs for s in inc.backbone + [y for b in inc.branches for y in b] for x in s.evidence]
    assert lines and all(len(x) <= n for x in lines)
    assert all(len(x) == n and x.endswith("…") and x[:-1] == x[:n - 1] for x in lines)  # every source line was 500
