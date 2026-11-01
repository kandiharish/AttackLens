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

// ---------- Log integrity (GET /api/integrity, /api/runs/{id}/integrity, /api/uploads/{id}/integrity) ----------
// Mirrors backend/attacklens/integrity.py integrity_report.json (schema_version 1). Not part of the Incident contract.

export type IntegrityVerdict = 'trusted' | 'suspect' | 'tampered'
export type IntegrityCheckStatus = 'pass' | 'warn' | 'fail' | 'skipped'
export type IntegritySeverity = 'low' | 'medium' | 'high' | 'critical'
export type IntegrityCheckId =
  | 'seal'
  | 'zeroed_regions'
  | 'truncated_tail'
  | 'log_cleared'
  | 'silence_gap'
  | 'went_dark'
  | 'timestamps'
  | 'duplicates'
  | 'embedded_time_mismatch'
  | 'ingest_drops'

export interface IntegrityCheck {
  id: IntegrityCheckId | string
  status: IntegrityCheckStatus
  findings: number
  reason: string | null
}

export interface IntegrityFinding {
  check: IntegrityCheckId | string
  severity: IntegritySeverity
  title: string
  source_type: string | null
  host: string | null
  file: string | null
  start_ts_ms: number | null
  end_ts_ms: number | null
  count: number
  detail: string
  /** Untrusted log text (<= 300 chars each). Rendered as text only. */
  evidence: string[]
}

export interface IntegritySeal {
  status: 'verified' | 'mismatch' | 'absent'
  path: string | null
  keyed: boolean
  files_checked: number
  modified: string[]
  missing: string[]
  added: string[]
}

export interface IntegrityFile {
  file: string
  size: number
  sha256: string | null
  zeroed_bytes: number
  truncated_tail: boolean
}

export interface AuthenticitySignal {
  id: string
  value: number | string | boolean | null
  threshold: number | string | boolean | null
  fired: boolean
  detail: string
}

/** Separate "looks machine-generated" warning. Never changes verdict or trust_score. */
export interface Authenticity {
  label: 'natural' | 'likely_generated' | 'unknown'
  /** 0..100, higher = more machine-generated. */
  score: number
  signals: AuthenticitySignal[]
  reason: string | null
}

export interface IntegrityReport {
  schema_version: number
  set: string
  generated_at: string
  verdict: IntegrityVerdict
  trust_score: number
  summary: string
  checks: IntegrityCheck[]
  findings: IntegrityFinding[]
  seal: IntegritySeal | null
  files: IntegrityFile[]
  inputs: { events_rows: number | null; files: number; bytes: number } | null
  wall_s: number
  /** quick = raw files only (upload scan), full = after a pipeline run. Missing = full. */
  scope?: 'quick' | 'full'
  /** Absent / null on quick scans. */
  authenticity?: Authenticity | null
}

/** GET /api/uploads/{id}/integrity */
export interface UploadIntegrityStatus {
  status: 'pending' | 'running' | 'done' | 'failed'
  report: IntegrityReport | null
  error: string | null
}

/** GET /api/runs/{id} -> "integrity" once the run's report exists. */
export interface RunIntegritySummary {
  verdict: IntegrityVerdict
  trust_score: number
  summary: string
  scope?: 'quick' | 'full'
}
