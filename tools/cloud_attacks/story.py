"""Story / Step / Decoy containers and their ground-truth form (backend/eval harness schema).

A step owns the exact events that make it up; its ground truth is derived from its FIRST event (ts_ms + entities
as written in that record, TESTING.md §3.3), so GT can never drift from the data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_attacks.common import DAY, HOUR, MIN, START_MS, Ev, iso_s
from cloud_attacks.formats import entity

CONNECTOR = {"cloudtrail": "aws_cloudtrail", "signin": "azure_monitor:SigninLogs", "audit": "azure_monitor:AuditLogs",
             "activity": "azure_monitor:AzureActivity", "blob": "azure_monitor:StorageBlobLogs", "gcp": "gcp_logging"}
_KEEP = object()


def at(day: int, hour: int, minute: int = 0) -> int:
    return START_MS + day * DAY + hour * HOUR + minute * MIN


def first(events: list[Ev]) -> Ev:
    return min(events, key=lambda e: (e.ts, e.rid))


def source_of(ev: Ev) -> str:
    return f"{CONNECTOR[ev.feed]}:{entity(ev)['action']}"


@dataclass
class Step:
    technique_id: str
    tactic: str
    events: list[Ev]
    what: str
    user: Any = _KEEP            # override the anchor's user (e.g. None for a password spray across many users)

    def gt(self, n: int) -> dict[str, Any]:
        a = first(self.events)
        ent = entity(a)
        return {"step": n, "ts_ms": a.ts, "ts": iso_s(a.ts), "technique_id": self.technique_id, "tactic": self.tactic,
                "host": ent["host"], "user": ent["user"] if self.user is _KEEP else self.user,
                "src_ip": ent["src_ip"], "dst_ip": None, "source": source_of(a), "event_id": a.rid,
                "events": len(self.events), "what": self.what}


@dataclass
class Story:
    id: str
    name: str
    clouds: tuple[str, ...]
    refs: tuple[str, ...]
    steps: list[Step]
    extra: list[Ev] = field(default_factory=list)   # attacker activity that is not a scored step
    novel: bool = False

    def events(self) -> list[Ev]:
        return [e for s in self.steps for e in s.events] + self.extra

    def gt(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "clouds": list(self.clouds), "novel": self.novel,
                "refs": list(self.refs), "steps": [s.gt(i + 1) for i, s in enumerate(self.steps)]}


@dataclass
class Decoy:
    id: str
    why: str
    events: list[Ev]
    recurring: bool = False      # events also recur in the baseline (only one instance is listed here)

    def gt(self) -> dict[str, Any]:
        a = first(self.events)
        ent = entity(a)
        return {"id": self.id, "ts_ms": a.ts, "ts": iso_s(a.ts), "source": source_of(a), "host": ent["host"],
                "user": ent["user"], "src_ip": ent["src_ip"], "event_id": a.rid, "events": len(self.events),
                "recurring": self.recurring, "why": self.why}
