"""Regenerate frontend/src/mock/integrations_catalog.json from the backend catalog (GET /api/integrations/catalog =
attacklens.integrations_status.catalog()), so the UI mock never drifts from the connector modules' CATALOGs.

    .venv/Scripts/python tools/gen_integrations_catalog.py           # rewrite the mock
    .venv/Scripts/python tools/gen_integrations_catalog.py --check   # exit 1 when the mock differs (CI / tests)

Format: a JSON array, one entry per connector / sink, each form field on one line (diff-friendly).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
MOCK = REPO / "frontend" / "src" / "mock" / "integrations_catalog.json"


def render(entries: list[dict[str, Any]]) -> str:
    out = ["["]
    for i, e in enumerate(entries):
        lines = []
        for k, v in e.items():
            if k == "fields":
                body = ",\n".join("      " + json.dumps(f, ensure_ascii=False) for f in v)
                lines.append(f'    "fields": [\n{body}\n    ]' if v else '    "fields": []')
            else:
                lines.append(f"    {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)}")
        out.append("  {\n" + ",\n".join(lines) + "\n  }" + ("," if i < len(entries) - 1 else ""))
    out.append("]")
    return "\n".join(out) + "\n"


def build() -> str:
    sys.path.insert(0, str(REPO / "backend"))
    from attacklens.integrations_status import catalog
    return render(catalog())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="do not write; exit 1 if the mock is out of date")
    a = ap.parse_args(argv)
    text = build()
    cur = MOCK.read_text(encoding="utf-8") if MOCK.exists() else ""
    if a.check:
        if cur != text:
            print(f"{MOCK.relative_to(REPO)} is out of date: run tools/gen_integrations_catalog.py", file=sys.stderr)
            return 1
        return 0
    if cur != text:
        MOCK.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {MOCK.relative_to(REPO)} ({len(json.loads(text))} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
