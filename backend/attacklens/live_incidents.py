"""Live mode: incidents that outlive the event window (used by live.py).

"Frozen" incidents ended before the window start, so their events are gone and they cannot be recomputed.
They are kept in live_state.json (not only in out/), so a cycle that fails after publish cannot lose them.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from attacklens.live_tail import read_json, write_json

log = logging.getLogger("attacklens.live")

Frozen = dict[str, dict[str, Any]]  # incident id -> {"row": index row, "inc": incident JSON}


def open_incident_day(out: Path, cutoff_iso: str) -> str | None:
    """Earliest first_ts day of a published incident that is still open (last_ts >= cutoff)."""
    days = [str(r.get("first_ts", ""))[:10] for r in read_json(out / "incidents_index.json", [])
            if isinstance(r, dict) and str(r.get("last_ts", "")) >= cutoff_iso and r.get("first_ts")]
    return min(days) if days else None


def frozen_now(out: Path, store: Frozen, start_iso: str | None, first_batch: bool) -> Frozen:
    """Persisted frozen incidents + published ones that ended before the window start."""
    keep: Frozen = dict(store)
    if start_iso is None or first_batch:  # first batch: an existing index is not ours
        return keep
    for row in read_json(out / "incidents_index.json", []):
        if isinstance(row, dict) and row.get("id") not in keep and str(row.get("last_ts", "")) < start_iso:
            inc = read_json(out / "incidents" / f"{row['id']}.json", None)
            if isinstance(inc, dict):
                keep[str(row["id"])] = {"row": row, "inc": inc}
    return keep


def merge_frozen(out: Path, frozen: Frozen) -> int:
    """Add frozen incidents missing from the freshly published index. Returns the index size."""
    index = read_json(out / "incidents_index.json", [])
    have = {r["id"] for r in index if isinstance(r, dict)}
    added = [v for k, v in frozen.items() if k not in have]
    if added:
        for v in added:
            write_json(out / "incidents" / f"{v['row']['id']}.json", v["inc"])
        index += [v["row"] for v in added]
        index.sort(key=lambda x: (-(x.get("risk") or 0), x.get("first_ts", ""), x["id"]))
        write_json(out / "incidents_index.json", index)
    return len(index)
