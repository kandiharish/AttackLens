// SIEM integration endpoints (NOT part of the Incident contract in types.ts).
// Mirrors backend/attacklens/pivots.py build_pivots() and the /api/integrations/* connection endpoints.

/** One SIEM query for one step: GET /api/incidents/{id}/pivots -> steps[].queries[siem]. */
export interface PivotQuery {
  siem: string
  language: string // spl | kql | lucene | ...
  query: string
  earliest: string
  latest: string
  entities: string[]
  /** Only present (non-null) when a SIEM base_url is configured. */
  url: string | null
  /** Elastic only: ES query DSL body. */
  dsl?: Record<string, unknown>
}

export interface StepPivots {
  step: number | null
  episode_id: string | null
  ts: string | null
  technique_id: string | null
  host: string | null
  user: string | null
  queries: Record<string, PivotQuery>
}

export interface IncidentPivots {
  id: string | null
  window_ms: number
  siems: string[]
  steps: StepPivots[]
  branches: StepPivots[][]
}

// ---------- Connections (one-click data sources / sinks) ----------
// GET /api/integrations/catalog, GET|PUT|DELETE /api/integrations/{id}, POST .../{test,start,stop}.
// Secrets are write-only: the API only ever returns secrets_set[key] = true/false, never the value.

/** identity = SaaS identity / productivity audit logs (Okta, Microsoft 365, Google Workspace). */
export type IntegrationKind = 'siem' | 'cloud' | 'identity' | 'sink'
export type IntegrationMode = 'events' | 'alerts'
export type IntegrationFieldType = 'text' | 'url' | 'secret' | 'number' | 'bool' | 'select'
export type IntegrationValue = string | number | boolean | null

/** Select option: a plain value, or {value, label}. */
export type IntegrationOption = string | { value: string; label?: string }

export interface IntegrationField {
  key: string
  label: string
  type: IntegrationFieldType
  required: boolean
  placeholder?: string
  help?: string
  options?: IntegrationOption[]
  default?: IntegrationValue
  /** Rarely needed (e.g. endpoint overrides): rendered inside the collapsed "Advanced" section. */
  advanced?: boolean
}

/** One entry of GET /api/integrations/catalog. */
export interface IntegrationCatalogEntry {
  id: string
  kind: IntegrationKind
  name: string
  /** Pull modes (connectors only); absent for sinks. */
  modes?: IntegrationMode[]
  fields: IntegrationField[]
  docs_url?: string
}

export interface IntegrationRunStatus {
  last_pull: string | null
  pulled: number | null
  written: number | null
  failed: number | null
  last_error: string | null
}

/** GET /api/integrations/{id} (also returned by PUT and POST start). */
export interface IntegrationState {
  id: string
  configured: boolean
  enabled: boolean
  /** Non-secret settings only. */
  settings: Record<string, IntegrationValue>
  /** Whether each secret has a stored value; never the value itself. */
  secrets_set: Record<string, boolean>
  running: boolean
  status: IntegrationRunStatus
}

/** PUT /api/integrations/{id} body. A secret key omitted = keep the stored value; null = clear it. */
export interface IntegrationSave {
  settings: Record<string, IntegrationValue>
  secrets: Record<string, string | null>
}

/** One check of a connection test (config, DNS, TLS, auth, permission, data). ok null/absent = not run. */
export interface IntegrationTestStep {
  name: string
  ok: boolean | null
  detail?: string | null
}

/** POST /api/integrations/{id}/test response. */
export interface IntegrationTestResult {
  ok: boolean
  latency_ms: number | null
  sample_count: number | null
  message: string
  error_code?: string | null
  /** Ordered checks; when absent the UI shows `message` only. */
  steps?: IntegrationTestStep[]
}

/** POST /api/integrations/{id}/start body. `since` is a relative window such as "24h" (config default_since style). */
export interface IntegrationStart {
  mode: IntegrationMode
  since?: string
}

/** 422 body of PUT /api/integrations/{id}. */
export interface IntegrationFieldError {
  error: string
  field: string | null
}

// ---------- Supported cloud logs (static: src/mock/integrations_cloud_logs.json) ----------
// Kept equal to config/sources.yaml and the connector modules by backend/tests/test_cloud_logs_ui.py.

/** rules = scored detection rules read this log; context = timeline / accounting only (vendor verdicts). */
export type CloudLogDetection = 'rules' | 'context'

export interface CloudLogRow {
  log: string
  /** Short name for the compact per-provider table. */
  short: string
  /** config/sources.yaml json_sources / csv_sources key. */
  source_type: string
  /** Ingest by uploading / pointing at exported files. */
  file: boolean
  /** Catalog id of the connector that pulls it, or null (file only). */
  connector: string | null
  /** Tables / content types / applications of that connector that carry this log. */
  connector_scope?: string[]
  detection?: CloudLogDetection
  note?: string
}

export interface CloudLogProvider {
  provider: string
  logs: CloudLogRow[]
}

export interface CloudLogsCatalog {
  /** Tile text per cloud / identity connector id. */
  connectors: Record<string, { provider: string; pulls: string }>
  providers: CloudLogProvider[]
}
