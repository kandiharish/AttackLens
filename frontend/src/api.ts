// API client. Typed with the contract in types.ts.
// Mock mode (VITE_USE_MOCK=true): reads src/mock/*.json, never touches the network.

import type { Incident, IncidentSummary, IntegrityReport, Metrics, RunIntegritySummary, UploadIntegrityStatus } from './types'
import type {
  IncidentPivots,
  IntegrationCatalogEntry,
  IntegrationSave,
  IntegrationStart,
  IntegrationState,
  IntegrationTestResult,
} from './types_integrations'

export const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true'

/** GET /api/incidents/{id}/path — backbone + branches + edges only. */
export type IncidentPath = Pick<Incident, 'backbone' | 'branches' | 'edges'>

/** POST /api/runs -> 202 (backend/attacklens/api.py). */
export interface RunStarted {
  run_id: string
}

/** GET /api/runs/{id} (backend/attacklens/api_runs.py RunManager.status). */
export interface RunStatus {
  run_id: string
  status: 'running' | 'succeeded' | 'failed'
  stage: string | null
  percent: number
  elapsed_s: number
  rss_mb: number
  peak_rss_mb: number
  returncode: number | null
  out_dir: string
  log: string
  /** Optional error text (not in RunManager.status() today; shown if the backend adds it). */
  error?: string | null
  /** Log-integrity summary once the run's integrity_report.json exists (older backend: absent). */
  integrity?: RunIntegritySummary | null
  // ---- progress keys (from <out_dir>/progress.json); all optional so an older backend and mock mode still work ----
  /** Seconds spent in the current stage so far. */
  stage_elapsed_s?: number | null
  /** 0..1 progress inside the current stage, null when the stage cannot measure it. */
  stage_fraction?: number | null
  /** Finished stages in order, with their wall time. */
  stages_done?: { stage: string; wall_s: number }[]
  bytes_total?: number | null
  bytes_done?: number | null
  rows_done?: number | null
  /** Current ingest read rate (MB/s). */
  ingest_mb_s?: number | null
  /** Seconds remaining for the whole run, null while unknown. */
  eta_s?: number | null
  eta_basis?: 'history' | 'live' | 'history+live' | null
  /** Estimated total wall time of the run. */
  eta_total_s?: number | null
}

/** GET /api/live/status: {enabled:false[, error]} or whatever attacklens.live.status() returns. */
export interface LiveStatus {
  enabled: boolean
  error?: string
  [key: string]: unknown
}

export class ApiError extends Error {
  readonly status: number
  /** Parsed JSON error body when there was one (e.g. 422 {error, field}). Never rendered as HTML. */
  readonly body: unknown
  constructor(message: string, status: number, body?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

/** Hint shown when the server gives no usable detail for a status. */
const STATUS_HINT: Record<number, string> = {
  400: 'the request was rejected (bad input or an incomplete/truncated upload); try again',
  403: 'forbidden: the server refused this request (origin not allowed or path outside the allowed folders); open the UI from the same host as the API',
  404: 'not found',
  413: 'too large for the server limit',
  415: 'unsupported file type',
  507: 'not enough free disk on the server',
}

/**
 * Readable error detail from an error body: FastAPI {"detail": "..."} or {"detail": [{msg}]} (422), otherwise
 * the plain-text body (trimmed, 300 chars), otherwise a status hint. Always rendered as text, never HTML.
 */
export function errorDetail(status: number, statusText: string, bodyText: string): string {
  let detail = ''
  try {
    const body: unknown = JSON.parse(bodyText)
    const d = body && typeof body === 'object' && 'detail' in body ? (body as { detail: unknown }).detail : undefined
    const e = body && typeof body === 'object' && 'error' in body ? (body as { error: unknown }).error : undefined
    if (typeof d === 'string') detail = d
    else if (d && typeof d === 'object' && !Array.isArray(d) && typeof (d as { error?: unknown }).error === 'string') detail = (d as { error: string }).error
    else if (typeof e === 'string') detail = e
    else if (Array.isArray(d))
      detail = d
        .map((x) => (x && typeof x === 'object' && 'msg' in x ? String((x as { msg: unknown }).msg) : JSON.stringify(x)))
        .join('; ')
    else if (d !== undefined && d !== null) detail = JSON.stringify(d)
  } catch {
    const t = bodyText.trim()
    if (t && !t.startsWith('<')) detail = t
  }
  if (!detail) detail = STATUS_HINT[status] ?? statusText ?? ''
  if (detail.length > 300) detail = `${detail.slice(0, 300)}…`
  return detail
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      ...init,
      headers: { Accept: 'application/json', ...(init?.body ? { 'Content-Type': 'application/json' } : {}) },
    })
  } catch {
    throw new ApiError(`Backend unreachable (${path}). Start uvicorn on :8000 or set VITE_USE_MOCK=true.`, 0)
  }
  if (!res.ok) {
    let text = ''
    try {
      text = await res.text()
    } catch {
      /* unreadable error body */
    }
    const detail = errorDetail(res.status, res.statusText, text)
    let body: unknown
    try {
      body = text ? JSON.parse(text) : undefined
    } catch {
      body = undefined
    }
    throw new ApiError(`${res.status}${res.statusText ? ` ${res.statusText}` : ''}${detail ? `: ${detail}` : ''} (${path})`, res.status, body)
  }
  // 204 / empty body (e.g. DELETE): no JSON to parse.
  const okText = await res.text()
  return (okText ? JSON.parse(okText) : undefined) as T
}

// ---------- mock loaders (lazy chunks, only fetched in mock mode) ----------
const mockIncidentModules = import.meta.glob<{ default: Incident }>('./mock/incident*.json')

async function mockIndex(): Promise<IncidentSummary[]> {
  const m = await import('./mock/index.json')
  return m.default as IncidentSummary[]
}

async function mockIncident(id: string): Promise<Incident> {
  for (const load of Object.values(mockIncidentModules)) {
    const inc = (await load()).default
    if (inc.id === id) return inc
  }
  throw new ApiError(`Incident ${id} not found in mock data`, 404)
}

// ---------- public API ----------
export async function getIncidents(): Promise<IncidentSummary[]> {
  const rows = USE_MOCK ? await mockIndex() : await request<IncidentSummary[]>('/api/incidents')
  return [...rows].sort((a, b) => b.risk - a.risk)
}

export async function getIncident(id: string): Promise<Incident> {
  if (USE_MOCK) return mockIncident(id)
  return request<Incident>(`/api/incidents/${encodeURIComponent(id)}`)
}

export async function getPath(id: string): Promise<IncidentPath> {
  if (USE_MOCK) {
    const inc = await mockIncident(id)
    return { backbone: inc.backbone, branches: inc.branches, edges: inc.edges }
  }
  return request<IncidentPath>(`/api/incidents/${encodeURIComponent(id)}/path`)
}

export async function getMetrics(): Promise<Metrics> {
  if (USE_MOCK) {
    const m = await import('./mock/metrics.json')
    return m.default as Metrics
  }
  return request<Metrics>('/api/metrics')
}

export async function startRun(raw_dir: string, ground_truth?: string): Promise<RunStarted> {
  if (USE_MOCK) throw new ApiError('Runs are not available in mock mode', 0)
  return request<RunStarted>('/api/runs', {
    method: 'POST',
    body: JSON.stringify(ground_truth ? { raw_dir, ground_truth } : { raw_dir }),
  })
}

export async function getRun(id: string): Promise<RunStatus> {
  if (USE_MOCK) throw new ApiError('Runs are not available in mock mode', 0)
  return request<RunStatus>(`/api/runs/${encodeURIComponent(id)}`)
}

/** GET /api/incidents/{id}/pivots — per-step SIEM queries (mock: src/mock/pivots.json keyed by incident id). */
export async function getPivots(id: string): Promise<IncidentPivots> {
  if (USE_MOCK) {
    const m = await import('./mock/pivots.json')
    const p = (m.default as unknown as Record<string, IncidentPivots>)[id]
    if (!p) throw new ApiError(`No mock pivots for ${id}`, 404)
    return p
  }
  return request<IncidentPivots>(`/api/incidents/${encodeURIComponent(id)}/pivots`)
}

export async function getLiveStatus(): Promise<LiveStatus> {
  if (USE_MOCK) return { enabled: false, mock: true }
  return request<LiveStatus>('/api/live/status')
}

// ---------- uploads (Add data page) ----------

/** POST /api/uploads and /api/uploads/local response. */
export interface UploadResult {
  upload_id: string
  raw_dir: string
  files: { name: string; bytes: number }[]
  total_bytes: number
  /** /api/uploads/local only (e.g. how the file was made available). */
  mode?: string
  created_at?: string
  /** Quick integrity scan auto-started on upload (older backend: absent). */
  integrity?: { status: UploadIntegrityStatus['status'] } | null
  [key: string]: unknown
}

/** GET /api/health (only the fields the UI reads). */
export interface Health {
  status?: string
  served_out_dir?: string | null
  out_dir?: string | null
  [key: string]: unknown
}

function listOf<T>(body: unknown, key: string): T[] {
  if (Array.isArray(body)) return body as T[]
  if (body && typeof body === 'object' && Array.isArray((body as Record<string, unknown>)[key])) return (body as Record<string, T[]>)[key]
  return []
}

export async function getHealth(): Promise<Health> {
  if (USE_MOCK) return { status: 'mock', served_out_dir: 'src/mock' }
  return request<Health>('/api/health')
}

export async function getUploads(): Promise<UploadResult[]> {
  if (USE_MOCK) return []
  return listOf<UploadResult>(await request<unknown>('/api/uploads'), 'uploads')
}

export async function getRuns(): Promise<RunStatus[]> {
  if (USE_MOCK) return []
  return listOf<RunStatus>(await request<unknown>('/api/runs'), 'runs')
}

export async function uploadLocal(path: string): Promise<UploadResult> {
  if (USE_MOCK) throw new ApiError('Uploads are not available in mock mode', 0)
  return request<UploadResult>('/api/uploads/local', { method: 'POST', body: JSON.stringify({ path }) })
}

export interface UploadHandle {
  promise: Promise<UploadResult>
  abort: () => void
}

/**
 * POST /api/uploads (multipart field "files") with XHR so upload progress is observable (fetch has none).
 * onProgress receives bytes sent so far and the total request size.
 */
export function uploadFiles(files: File[], onProgress: (loaded: number, total: number) => void): UploadHandle {
  const xhr = new XMLHttpRequest()
  const promise = new Promise<UploadResult>((resolve, reject) => {
    if (USE_MOCK) {
      reject(new ApiError('Uploads are not available in mock mode', 0))
      return
    }
    const form = new FormData()
    for (const f of files) form.append('files', f, f.name)
    xhr.open('POST', '/api/uploads')
    xhr.setRequestHeader('Accept', 'application/json')
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(e.loaded, e.total)
    }
    xhr.onload = () => {
      let body: unknown = null
      try {
        body = JSON.parse(xhr.responseText)
      } catch {
        /* non-JSON body */
      }
      if (xhr.status >= 200 && xhr.status < 300 && body) resolve(body as UploadResult)
      else {
        const detail = errorDetail(xhr.status, xhr.statusText, xhr.responseText ?? '')
        reject(new ApiError(`Upload failed: ${xhr.status}${detail ? ` ${detail}` : ''}`, xhr.status))
      }
    }
    xhr.onerror = () => reject(new ApiError('Upload failed: backend unreachable', 0))
    xhr.onabort = () => reject(new ApiError('Upload cancelled', 0))
    xhr.send(form)
  })
  return { promise, abort: () => xhr.abort() }
}

// ---------- connections (one-click data sources / sinks) ----------
// Mock mode keeps an in-memory copy of src/mock/integrations_state.json so the form can be exercised offline.
// No network call is ever made in mock mode; secret values are dropped (only secrets_set[key] is kept).

interface MockIntegrations {
  states: Record<string, IntegrationState>
  tests: Record<string, IntegrationTestResult>
}
let mockConn: MockIntegrations | null = null

async function mockCatalog(): Promise<IntegrationCatalogEntry[]> {
  const m = await import('./mock/integrations_catalog.json')
  return m.default as unknown as IntegrationCatalogEntry[]
}

async function mockStore(): Promise<MockIntegrations> {
  if (!mockConn) {
    const m = await import('./mock/integrations_state.json')
    mockConn = structuredClone(m.default as unknown as MockIntegrations)
  }
  return mockConn
}

function emptyState(id: string): IntegrationState {
  return {
    id,
    configured: false,
    enabled: false,
    settings: {},
    secrets_set: {},
    running: false,
    status: { last_pull: null, pulled: null, written: null, failed: null, last_error: null },
  }
}

async function mockState(id: string): Promise<IntegrationState> {
  const cat = await mockCatalog()
  if (!cat.some((c) => c.id === id)) throw new ApiError(`404 Not Found: unknown integration ${id} (mock)`, 404)
  const st = await mockStore()
  return structuredClone(st.states[id] ?? emptyState(id))
}

const connPath = (id: string, tail = '') => `/api/integrations/${encodeURIComponent(id)}${tail}`

/** GET /api/integrations/catalog. A 404 means the backend predates Connections (ApiError.status === 404). */
export async function getIntegrationCatalog(): Promise<IntegrationCatalogEntry[]> {
  if (USE_MOCK) return mockCatalog()
  return listOf<IntegrationCatalogEntry>(await request<unknown>('/api/integrations/catalog'), 'integrations')
}

export async function getIntegration(id: string): Promise<IntegrationState> {
  if (USE_MOCK) return mockState(id)
  return request<IntegrationState>(connPath(id))
}

/** PUT /api/integrations/{id}. 422 -> ApiError whose body is {error, field}. */
export async function saveIntegration(id: string, body: IntegrationSave): Promise<IntegrationState> {
  if (USE_MOCK) {
    const cat = (await mockCatalog()).find((c) => c.id === id)
    if (!cat) throw new ApiError(`404 Not Found: unknown integration ${id} (mock)`, 404)
    const cur = await mockState(id)
    for (const f of cat.fields) {
      if (!f.required) continue
      const sec = body.secrets[f.key]
      const missing =
        f.type === 'secret'
          ? !(typeof sec === 'string' && sec.length > 0) && !(cur.secrets_set[f.key] && sec === undefined)
          : body.settings[f.key] === undefined || body.settings[f.key] === null || body.settings[f.key] === ''
      if (missing) {
        const err = { error: `${f.label} is required`, field: f.key }
        throw new ApiError(`422: ${err.error} (mock)`, 422, err)
      }
    }
    const secrets_set = { ...cur.secrets_set }
    for (const [k, v] of Object.entries(body.secrets)) secrets_set[k] = typeof v === 'string' && v.length > 0
    const next: IntegrationState = { ...cur, configured: true, settings: { ...body.settings }, secrets_set }
    ;(await mockStore()).states[id] = next
    return structuredClone(next)
  }
  return request<IntegrationState>(connPath(id), { method: 'PUT', body: JSON.stringify(body) })
}

/** POST /api/integrations/{id}/test: tests the SAVED settings (the contract has no request body). */
export async function testIntegration(id: string): Promise<IntegrationTestResult> {
  if (USE_MOCK) {
    await mockState(id)
    const t = (await mockStore()).tests[id]
    return t ? { ...t } : { ok: false, latency_ms: null, sample_count: null, message: 'Mock mode: no network call was made.', error_code: 'mock' }
  }
  return request<IntegrationTestResult>(connPath(id, '/test'), { method: 'POST' })
}

export async function startIntegration(id: string, body: IntegrationStart): Promise<IntegrationState> {
  if (USE_MOCK) {
    const cur = await mockState(id)
    if (!cur.configured) throw new ApiError('409: save the settings first (mock)', 409, { error: 'not configured', field: null })
    const next: IntegrationState = { ...cur, enabled: true, running: true, status: { ...cur.status, last_error: null } }
    ;(await mockStore()).states[id] = next
    return structuredClone(next)
  }
  return request<IntegrationState>(connPath(id, '/start'), { method: 'POST', body: JSON.stringify(body) })
}

/** POST /api/integrations/{id}/stop. The contract does not fix the response body, so it is ignored. */
export async function stopIntegration(id: string): Promise<void> {
  if (USE_MOCK) {
    const cur = await mockState(id)
    ;(await mockStore()).states[id] = { ...cur, enabled: false, running: false }
    return
  }
  await request<unknown>(connPath(id, '/stop'), { method: 'POST' })
}

export async function deleteIntegration(id: string): Promise<void> {
  if (USE_MOCK) {
    await mockState(id)
    delete (await mockStore()).states[id]
    return
  }
  await request<unknown>(connPath(id), { method: 'DELETE' })
}

// ---------- log integrity (health of the logs) ----------
// Mock mode: src/mock/integrity.json (a TAMPERED example incl. authenticity), never the network.

async function mockIntegrity(): Promise<IntegrityReport> {
  const m = await import('./mock/integrity.json')
  return structuredClone(m.default as unknown as IntegrityReport)
}

/** GET /api/integrity: report of the dataset the API serves now. ApiError 404 = no report. */
export async function getIntegrity(): Promise<IntegrityReport> {
  if (USE_MOCK) return mockIntegrity()
  return request<IntegrityReport>('/api/integrity')
}

/** GET /api/runs/{id}/integrity: that run's full-scope report. ApiError 404 until it exists. */
export async function getRunIntegrity(runId: string): Promise<IntegrityReport> {
  if (USE_MOCK) return mockIntegrity()
  return request<IntegrityReport>(`/api/runs/${encodeURIComponent(runId)}/integrity`)
}

/** POST /api/uploads/{id}/integrity: (re)start the quick scan. 202 {status:"running"}; 409 if already running. */
export async function startUploadIntegrity(uploadId: string): Promise<{ status: string }> {
  if (USE_MOCK) return { status: 'running' }
  return request<{ status: string }>(`/api/uploads/${encodeURIComponent(uploadId)}/integrity`, { method: 'POST' })
}

/** GET /api/uploads/{id}/integrity: quick-scan status + report when done. */
export async function getUploadIntegrity(uploadId: string): Promise<UploadIntegrityStatus> {
  if (USE_MOCK) return { status: 'done', report: { ...(await mockIntegrity()), scope: 'quick', authenticity: null }, error: null }
  return request<UploadIntegrityStatus>(`/api/uploads/${encodeURIComponent(uploadId)}/integrity`)
}
