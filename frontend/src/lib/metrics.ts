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

export function fmtSeconds(s: number | null | undefined): string {
  if (s === null || s === undefined || !Number.isFinite(s) || s < 0) return '—'
  if (s < 60) return `${s.toFixed(1)} s`
  const t = Math.round(s)
  if (t < 3600) return `${Math.floor(t / 60)}m ${t % 60}s`
  return `${Math.floor(t / 3600)}h ${String(Math.floor((t % 3600) / 60)).padStart(2, '0')}m`
}

export interface RunTiming {
  /** Rows read (run_metrics.rows_in, else stage_stats.ingest.rows_in, else the ingest_accounting sum). */
  rows: number | null
  /** Wall time of the ingest stage (stages[name=ingest].wall_s, else stage_stats.ingest.wall_s). */
  ingestS: number | null
  /** Whole-run wall time (run_metrics.total_wall_s). */
  totalS: number | null
}

/** Timing of the served run for the footer: every value from run_metrics.json, null when absent. */
export function readRunTiming(m: Metrics | null): RunTiming {
  const r = m?.run_metrics
  const ss = r?.stage_stats
  const ingStats = ss && typeof ss === 'object' ? ((ss as Record<string, unknown>).ingest as Obj) : null
  const ingStage = readRunSummary(m).stages.find((s) => s.name === 'ingest')
  return {
    rows: num(r, 'rows_in') ?? num(ingStats, 'rows_in') ?? readIngest(m)?.rowsIn ?? null,
    ingestS: ingStage?.wall_s ?? num(ingStats, 'wall_s'),
    totalS: num(r, 'total_wall_s'),
  }
}

export function fmtCount(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} B`
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} M`
  if (n >= 1e4) return `${(n / 1e3).toFixed(1)} k`
  return n.toLocaleString('en-US')
}

function obj(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null
}

/** Measured counts for runs without ground truth. Every field is null when its key is absent from run_metrics.json. */
export interface RunCounts {
  /** run_metrics.incidents (else stage_stats.incidents.incidents). */
  incidents: number | null
  /** stage_stats.detect.raw_alerts */
  rawAlerts: number | null
  /** stage_stats.episodes.episodes (kept for linking; run_metrics.episodes as fallback). */
  episodes: number | null
  /** stage_stats.episodes.episodes_total (kept + spilled). */
  episodesTotal: number | null
  /** Custom rules with alerts > 0 (stage_stats.detect.alerts_per_rule, keys not starting with "sigma_"). */
  customRulesFired: number | null
  /** stage_stats.detect.sigma_rules_fired (or detect.sigma.sigma_rules_fired). */
  sigmaRulesFired: number | null
  /** stage_stats.detect.sigma_rules_applicable */
  sigmaApplicable: number | null
  /** stage_stats.detect.sigma_rules_running */
  sigmaRunning: number | null
}

export function readRunCounts(m: Metrics | null): RunCounts {
  const r = m?.run_metrics
  const ss = obj(r?.stage_stats)
  const det = obj(ss?.detect)
  const sig = obj(det?.sigma)
  const eps = obj(ss?.episodes)
  const inc = obj(ss?.incidents)
  const perRule = obj(det?.alerts_per_rule)
  const custom = perRule
    ? Object.entries(perRule).filter(([k, v]) => !k.startsWith('sigma_') && typeof v === 'number' && v > 0).length
    : null
  const sigmaKey = (k: string) => num(det, k) ?? num(sig, k)
  return {
    incidents: num(r, 'incidents') ?? num(inc, 'incidents'),
    rawAlerts: num(det, 'raw_alerts'),
    episodes: num(eps, 'episodes') ?? num(r, 'episodes'),
    episodesTotal: num(eps, 'episodes_total'),
    customRulesFired: custom,
    sigmaRulesFired: sigmaKey('sigma_rules_fired'),
    sigmaApplicable: sigmaKey('sigma_rules_applicable'),
    sigmaRunning: sigmaKey('sigma_rules_running'),
  }
}

/** Distinct ATT&CK tactics across the loaded incident list (null when the list is not loaded). */
export function tacticsCovered(incidents: Array<{ tactics?: string[] | null }> | null | undefined): string[] | null {
  if (!incidents) return null
  const seen = new Map<string, string>()
  for (const i of incidents) for (const t of i?.tactics ?? []) if (typeof t === 'string' && t.trim()) seen.set(t.trim().toLowerCase(), t.trim())
  return [...seen.values()]
}
