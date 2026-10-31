// Incident contract (docs/DEVELOPMENT.md §7.1). Mirrors backend/attacklens/models.py — change both together.

export interface EntryPoint {
  step: number
  summary: string
}

export interface Step {
  step: number
  episode_id: string
  ts: string
  technique_id: string
  sub_technique_id: string | null
  technique_name: string | null
  tactic: string
  rule_id: string | null
  host: string | null
  user: string | null
  src_ip: string | null
  dst_ip: string | null
  severity: number
  confidence: number
  merged_alert_count: number
  evidence: string[]
}

export interface PathEdge {
  from: string
  to: string
  rule: 'R1' | 'R2' | 'R3' | 'R4'
  weight: number
  why_linked: string
}

export interface GraphNode {
  id: string
  type: 'host' | 'user' | 'ip' | 'domain'
  label: string
  compromised: boolean
}

export interface GraphEdge {
  source: string
  target: string
  label: string
  step: number
}

export interface ReachNext {
  host: string
  hops: number
  via_user: string | null
  evidence: string
  crown_jewel: string | null
  touched: boolean
}

export interface Narrative {
  text: string
  source: 'llm' | 'template'
}

export interface Incident {
  id: string
  risk: number
  first_ts: string
  last_ts: string
  merged_alert_count: number
  episode_count: number
  entry_point: EntryPoint
  tactics: string[]
  gaps: string[]
  backbone: Step[]
  branches: Step[][]
  edges: PathEdge[]
  graph: { nodes: GraphNode[]; edges: GraphEdge[] }
  reach_next: ReachNext[]
  narrative: Narrative
}

export interface IncidentSummary {
  id: string
  risk: number
  first_ts: string
  last_ts: string
  merged_alert_count: number
  episode_count: number
  tactics: string[]
  hosts: string[]
  entry_summary: string
}

// GET /api/metrics — each part may be null if the file is absent for this run.
export interface Metrics {
  run_metrics: Record<string, unknown> | null
  eval_scorecard: Record<string, unknown> | null
  ingest_accounting: Array<{ source_type: string; rows_in: number; rows_ok: number; dropped: number }> | null
}
