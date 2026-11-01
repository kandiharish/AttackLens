"""P1-21: the UI mock catalog (frontend/src/mock/integrations_catalog.json) equals the backend catalog
(GET /api/integrations/catalog). Regenerate with: .venv/Scripts/python tools/gen_integrations_catalog.py"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
import gen_integrations_catalog as gen  # noqa: E402


def test_mock_catalog_matches_backend_catalog() -> None:
    from attacklens.integrations_status import catalog
    mock = json.loads(gen.MOCK.read_text(encoding="utf-8"))
    backend = catalog()
    assert [e["id"] for e in mock] == [e["id"] for e in backend]
    for m, b in zip(mock, backend):
        assert m == b, f"{b['id']}: mock differs from the backend catalog; run tools/gen_integrations_catalog.py"
    assert gen.build() == gen.MOCK.read_text(encoding="utf-8"), "mock not in generator format"


def test_mock_catalog_lists_identity_connectors() -> None:
    mock = {e["id"]: e for e in json.loads(gen.MOCK.read_text(encoding="utf-8"))}
    assert {mock[i]["kind"] for i in ("okta", "m365_ual", "gws_reports")} == {"identity"}
    assert {e["kind"] for e in mock.values()} == {"siem", "cloud", "identity", "sink"}
