"""integrity check `ingest_drops`: malformed / dropped lines from out_dir/ingest_accounting.json (Stage 1)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from attacklens.integrity_raw import Skip, finding


def _accounting_entries(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        if isinstance(data.get("sources"), list):
            data = data["sources"]
        else:
            data = [{"source_type": k, **v} for k, v in data.items() if isinstance(v, dict)]
    return [e for e in data if isinstance(e, dict)] if isinstance(data, list) else []


def check_ingest_drops(out_dir: Path, c: dict[str, Any], timestamps_ran: bool) -> list[dict[str, Any]]:
    p = Path(out_dir) / "ingest_accounting.json"
    if not p.is_file():
        raise Skip("no ingest_accounting.json")
    entries = _accounting_entries(json.loads(p.read_text(encoding="utf-8")))
    ignore = tuple(str(r) for r in c.get("drop_ignore_reasons_if_timestamps_ran") or []) if timestamps_ran else ()
    warn, high = float(c.get("drop_warn", 0.001)), float(c.get("drop_high", 0.05))
    out = []
    for e in entries:
        rows_in = int(e.get("rows_in") or e.get("rows") or 0)
        dropped = e.get("dropped")
        dropped = int(dropped) if dropped is not None else max(0, rows_in - int(e.get("rows_ok") or 0))
        reasons = {str(k): int(v) for k, v in (e.get("drop_reasons") or {}).items() if isinstance(v, (int, float))}
        ignored = sum(v for k, v in reasons.items() if ignore and k.startswith(ignore))
        bad = max(0, dropped - ignored)
        if not rows_in or bad / rows_in <= warn:
            continue
        r = bad / rows_in
        kept = sorted(((k, v) for k, v in reasons.items() if not (ignore and k.startswith(ignore))),
                      key=lambda kv: -kv[1])
        st = e.get("source_type")
        out.append(finding("ingest_drops", "high" if r > high else "medium", "malformed/corrupted lines",
                           source_type=None if st is None else str(st), count=bad,
                           evidence=[f"{k}: {v}" for k, v in kept[:3]],
                           detail=f"{bad} of {rows_in} {st} lines ({r:.2%}) were malformed, unreadable or dropped "
                                  "at ingest"))
    return out
