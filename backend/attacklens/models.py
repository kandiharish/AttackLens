"""Incident contract (DEVELOPMENT.md §7.1). Mirrors frontend/src/types.ts — change both together."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class EntryPoint(_Model):
    step: int
    summary: str


class Step(_Model):
    step: int
    episode_id: str
    ts: str  # ISO-8601 UTC, "Z" suffix
    technique_id: str
    sub_technique_id: str | None = None
    technique_name: str | None = None
    tactic: str
    rule_id: str | None = None
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    severity: int
    confidence: int
    merged_alert_count: int
    evidence: list[str] = Field(default_factory=list)  # <= 3 lines, each <= 300 chars


class PathEdge(_Model):
    from_: str = Field(alias="from")
    to: str
    rule: Literal["R1", "R2", "R3", "R4"]
    weight: float
    why_linked: str


class GraphNode(_Model):
    id: str  # "type:value", e.g. "host:srv-dc-01"
    type: Literal["host", "user", "ip", "domain"]
    label: str
    compromised: bool = False


class GraphEdge(_Model):
    source: str
    target: str
    label: str  # technique id
    step: int


class Graph(_Model):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class ReachNext(_Model):
    host: str
    hops: int
    via_user: str | None = None
    evidence: str
    crown_jewel: str | None = None  # "dc" | "file" | "db" | "web" | None
    touched: bool = False


class Narrative(_Model):
    text: str
    source: Literal["llm", "template"]


class Incident(_Model):
    id: str  # "inc-<sha1[:8]>"
    risk: int
    first_ts: str
    last_ts: str
    merged_alert_count: int
    episode_count: int
    entry_point: EntryPoint
    tactics: list[str]
    gaps: list[str] = Field(default_factory=list)
    backbone: list[Step]
    branches: list[list[Step]] = Field(default_factory=list)
    edges: list[PathEdge] = Field(default_factory=list)
    graph: Graph = Field(default_factory=Graph)
    reach_next: list[ReachNext] = Field(default_factory=list)
    narrative: Narrative


class IncidentSummary(_Model):
    """One row of incidents_index.json (risk desc)."""

    id: str
    risk: int
    first_ts: str
    last_ts: str
    merged_alert_count: int
    episode_count: int
    tactics: list[str]
    hosts: list[str]
    entry_summary: str


def dump(model: BaseModel) -> dict:
    """JSON-ready dict with wire names ("from", not "from_")."""
    return model.model_dump(mode="json", by_alias=True)
