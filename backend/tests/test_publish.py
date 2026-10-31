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
