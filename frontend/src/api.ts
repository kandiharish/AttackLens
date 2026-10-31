// API client. Typed with the contract in types.ts.
// Mock mode (VITE_USE_MOCK=true): reads src/mock/*.json, never touches the network.

import type { Incident, IncidentSummary, Metrics } from './types'

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
}

/** GET /api/live/status: {enabled:false[, error]} or whatever attacklens.live.status() returns. */
export interface LiveStatus {
  enabled: boolean
  error?: string
  [key: string]: unknown
}

export class ApiError extends Error {
  readonly status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
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
    let detail = ''
    try {
      const body: unknown = await res.json()
      if (body && typeof body === 'object' && 'detail' in body) detail = String((body as { detail: unknown }).detail)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(`${res.status} ${res.statusText}${detail ? `: ${detail}` : ''} (${path})`, res.status)
  }
  return (await res.json()) as T
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

export async function getLiveStatus(): Promise<LiveStatus> {
  if (USE_MOCK) return { enabled: false, mock: true }
  return request<LiveStatus>('/api/live/status')
}
