// Reads numbers out of /api/metrics using the keys pinned in docs/DEVELOPMENT.md §15.6.
// No guessing: a missing or null key shows as "—".

import type { Metrics } from '../types'

type Obj = Record<string, unknown> | null | undefined

function num(obj: Obj, key: string): number | null {
  const v = obj?.[key]
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

export interface Scorecard {
  detection: number | null
  labels: number | null
  rebuilt: number | null
  faStrict: number | null
  faLenient: number | null
  singletonRecall: number | null
}

export interface StageMetric {
  name: string
  wall_s: number | null
  peak_rss_mb: number | null
}

export interface RunSummary {
  totalWallS: number | null
  peakRssMb: number | null
  stages: StageMetric[]
}

export interface IngestSummary {
  rowsIn: number
  rowsOk: number
  dropped: number
  sources: number
}

/** eval_scorecard.json: all *_pct values are 0–100 floats or null. */
export function readScorecard(m: Metrics | null): Scorecard {
  const s = m?.eval_scorecard
  return {
    detection: num(s, 'detection_pct'),
    labels: num(s, 'labels_pct'),
    rebuilt: num(s, 'rebuilt_pct'),
    faStrict: num(s, 'false_alarms_strict_pct'),
    faLenient: num(s, 'false_alarms_lenient_pct'),
    singletonRecall: num(s, 'singleton_recall_pct'),
  }
}

/** run_metrics.json: total_wall_s, peak_rss_mb, stages [{name, wall_s, peak_rss_mb}]. */
export function readRunSummary(m: Metrics | null): RunSummary {
  const r = m?.run_metrics
  const raw = r?.stages
  const stages: StageMetric[] = Array.isArray(raw)
    ? raw
        .filter((x): x is Record<string, unknown> => x !== null && typeof x === 'object')
        .map((x) => ({ name: String(x.name ?? '?'), wall_s: num(x, 'wall_s'), peak_rss_mb: num(x, 'peak_rss_mb') }))
    : []
  return { totalWallS: num(r, 'total_wall_s'), peakRssMb: num(r, 'peak_rss_mb'), stages }
}

export function readIngest(m: Metrics | null): IngestSummary | null {
  const rows = m?.ingest_accounting
  if (!rows || rows.length === 0) return null
  return rows.reduce<IngestSummary>(
    (acc, r) => ({
      rowsIn: acc.rowsIn + (r.rows_in ?? 0),
      rowsOk: acc.rowsOk + (r.rows_ok ?? 0),
      dropped: acc.dropped + (r.dropped ?? 0),
      sources: acc.sources + 1,
    }),
    { rowsIn: 0, rowsOk: 0, dropped: 0, sources: 0 },
  )
}

export function fmtPct(v: number | null, digits = 1): string {
  return v === null ? '—' : `${v.toFixed(digits)} %`
}

export function fmtRss(mb: number | null): string {
  if (mb === null) return '—'
  return mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${Math.round(mb)} MB`
}

export function fmtSeconds(s: number | null): string {
  if (s === null) return '—'
  if (s < 60) return `${s.toFixed(1)} s`
  const m = Math.floor(s / 60)
  return `${m}m ${Math.round(s % 60)}s`
}

export function fmtCount(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} B`
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} M`
  if (n >= 1e4) return `${(n / 1e3).toFixed(1)} k`
  return n.toLocaleString('en-US')
}
