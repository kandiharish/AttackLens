"""The mock incident used by the UI must validate against the backend contract (CLAUDE.md "Contract")."""

import json
from pathlib import Path

from attacklens.models import Incident, dump

MOCK = Path(__file__).resolve().parents[2] / "frontend" / "src" / "mock" / "incident.json"


def test_mock_incident_matches_contract() -> None:
    raw = json.loads(MOCK.read_text(encoding="utf-8"))
    inc = Incident.model_validate(raw)
    assert dump(inc)["edges"][0]["from"] == raw["edges"][0]["from"]
    assert [s.step for s in inc.backbone] == list(range(len(inc.backbone)))
