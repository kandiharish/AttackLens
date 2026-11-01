// Pure helpers for the "Add data" page. No invented numbers: everything shown comes from the API or the browser's File objects.
import type { Metrics } from '../types'

export const ACCEPTED_EXT = ['.log', '.txt', '.csv', '.json', '.jsonl', '.ndjson', '.cef', '.syslog'] as const

export function isAccepted(name: string): boolean {
  const n = name.toLowerCase()
  return ACCEPTED_EXT.some((e) => n.endsWith(e))
}

/** Minimal File shape the add/dedupe helpers need (real File objects satisfy it). */
export interface FileLike {
  name: string
  size: number
  lastModified: number
}

/** Identity of a chosen file: same name in two folders = two different files unless size and mtime also match. */
export const fileKey = (f: FileLike) => `${f.name}\u0000${f.size}\u0000${f.lastModified}`

export interface Skipped {
  name: string
  reason: string
}

function extOf(name: string): string {
  const i = name.lastIndexOf('.')
  return i > 0 ? name.slice(i).toLowerCase() : '(none)'
}

/**
 * Merge newly chosen files into the current list. Keeps different files that share a name; skips (with a reason)
 * unsupported extensions and exact duplicates (same name + size + last-modified, already listed or repeated).
 */
export function mergeChosen<T extends FileLike>(cur: T[], incoming: T[]): { files: T[]; skipped: Skipped[] } {
  const keys = new Set(cur.map(fileKey))
  const files = [...cur]
  const skipped: Skipped[] = []
  for (const f of incoming) {
    if (!isAccepted(f.name)) skipped.push({ name: f.name, reason: `not a supported type (${extOf(f.name)})` })
    else if (keys.has(fileKey(f))) skipped.push({ name: f.name, reason: 'exact duplicate (already in the list)' })
    else {
      keys.add(fileKey(f))
      files.push(f)
    }
  }
  return { files, skipped }
}

/**
 * Name the server will store each file under, mirroring api_upload.UploadWriter.open: a repeated name gets
 * stem-1.ext, stem-2.ext ... (base name only; the server may also sanitize characters).
 */
export function serverNames(names: string[]): string[] {
  const taken = new Set<string>()
  return names.map((orig) => {
    const base = orig.split(/[\\/]/).pop() ?? orig
    const dot = base.lastIndexOf('.')
    const stem = dot > 0 ? base.slice(0, dot) : base
    const ext = dot > 0 ? base.slice(dot) : ''
    let name = base
    for (let i = 1; taken.has(name); i++) name = `${stem}-${i}${ext}`
    taken.add(name)
    return name
  })
}

export function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '—'
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(2)} GB`
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`
  if (n >= 1024) return `${(n / 1024).toFixed(0)} KB`
  return `${n} B`
}

/** Stepper steps; backend stage names (api_runs.STAGE_PERCENT) map onto them. */
export const RUN_STEPS = [
  { key: 'read', label: 'Reading', hint: 'parsing and normalising the log lines', stages: ['profile', 'ingest', 'lookups'] },
  { key: 'detect', label: 'Detecting', hint: 'custom rules + Sigma rules', stages: ['detect', 'episodes'] },
  { key: 'link', label: 'Linking', hint: 'joining alerts that belong together', stages: ['link'] },
  { key: 'build', label: 'Building attack paths', hint: 'incidents, reach-next, report and log health check', stages: ['incidents', 'publish', 'integrity', 'eval'] },
  { key: 'done', label: 'Done', hint: '', stages: ['done'] },
] as const

/** Index of the active stepper step for a backend stage (null stage = just started = Reading). */
export function stepIndex(stage: string | null | undefined): number {
  const s = (stage ?? '').toLowerCase()
  const i = RUN_STEPS.findIndex((st) => (st.stages as readonly string[]).includes(s))
  return i < 0 ? 0 : i
}

/**
 * Per-file progress from one multipart upload: files are sent in order, so bytes sent map onto cumulative file
 * sizes (multipart headers make this approximate, never ahead of reality by more than a few hundred bytes).
 */
export function perFileProgress(sizes: number[], loaded: number, total: number): number[] {
  const sum = sizes.reduce((a, b) => a + b, 0)
  const overhead = Math.max(0, total - sum)
  let sent = Math.max(0, loaded - overhead / 2)
  return sizes.map((sz) => {
    const done = Math.min(sz, Math.max(0, sent))
    sent -= sz
    return sz === 0 ? 1 : done / sz
  })
}

export interface SigmaCoverage {
  total: number
  compiled: number | null
  applicable: number
  alerts: number | null
}

function num(o: Record<string, unknown> | null | undefined, k: string): number | null {
  const v = o?.[k]
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

/** run_metrics sigma_* keys; null (card hidden) unless total and applicable are both present. */
export function readSigma(m: Metrics | null): SigmaCoverage | null {
  const r = m?.run_metrics ?? null
  const total = num(r, 'sigma_rules_total')
  const applicable = num(r, 'sigma_rules_applicable')
  if (total === null || applicable === null) return null
  return { total, applicable, compiled: num(r, 'sigma_rules_compiled'), alerts: num(r, 'sigma_alerts') }
}

// ---------- run progress (RunStepper) ----------

const finite = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)

/** Per RUN_STEPS index: summed wall_s of that step's finished backend stages, null when none finished (or key absent). */
export function stepTimes(done: readonly { stage: string; wall_s: number }[] | null | undefined): (number | null)[] {
  const out: (number | null)[] = RUN_STEPS.map(() => null)
  for (const d of done ?? []) {
    if (!d || !finite(d.wall_s)) continue
    const i = RUN_STEPS.findIndex((st) => (st.stages as readonly string[]).includes(String(d.stage).toLowerCase()))
    if (i >= 0) out[i] = (out[i] ?? 0) + Math.max(0, d.wall_s)
  }
  return out
}

/** Headline for the remaining time: seconds under a minute (5 s steps), then minutes, then hours + minutes. */
export function fmtEta(eta: number | null | undefined): string {
  if (!finite(eta)) return 'Estimating time…'
  const s = Math.max(0, eta)
  if (s < 10) return 'Finishing…'
  if (s < 60) return `About ${Math.max(10, Math.round(s / 5) * 5)} s remaining`
  if (s < 3570) return `About ${Math.max(1, Math.round(s / 60))} min remaining`
  const m = Math.round(s / 60)
  const h = Math.floor(m / 60)
  return `About ${h} h${m % 60 ? ` ${m % 60} min` : ''} remaining`
}

/** Smoothed ETA state; `at` is the run's own elapsed_s so the clock comes from the API, not the browser. */
export interface EtaState {
  runId: string
  stage: string | null
  at: number
  eta: number
}

/** EMA weight of the newest raw estimate. */
export const ETA_ALPHA = 0.35
/** Max growth of the shown ETA between two polls of the same stage (20 %, at least 3 s so a tiny value can recover). */
export const ETA_MAX_GROWTH = 0.2

/**
 * Smooth eta_s across polls: the previous value counts down by the elapsed time between polls, then is blended with
 * the new raw value (exponential moving average). Within one stage it never grows by more than 20 % per poll;
 * a stage change lifts the cap. Never negative. Null raw (backend has no estimate) -> null ("Estimating time…").
 */
export function smoothEta(prev: EtaState | null, raw: number | null | undefined, runId: string, stage: string | null, elapsedS: number): EtaState | null {
  if (!finite(raw)) return null
  const r = Math.max(0, raw)
  if (!prev || prev.runId !== runId || !finite(elapsedS) || elapsedS < prev.at) return { runId, stage, at: finite(elapsedS) ? elapsedS : 0, eta: r }
  if (elapsedS === prev.at && stage === prev.stage) return prev // same poll seen twice
  const predicted = Math.max(0, prev.eta - (elapsedS - prev.at))
  let eta = ETA_ALPHA * r + (1 - ETA_ALPHA) * predicted
  if (stage === prev.stage) eta = Math.min(eta, Math.max(prev.eta * (1 + ETA_MAX_GROWTH), prev.eta + 3))
  return { runId, stage, at: elapsedS, eta: Math.max(0, eta) }
}

/** "Ingestion: 3.2 GB of 6.5 GB · 31 MB/s" (parts missing from the API are left out); null when bytes_total is absent. */
export function ingestLine(st: { bytes_total?: number | null; bytes_done?: number | null; ingest_mb_s?: number | null } | null): string | null {
  const total = st?.bytes_total
  if (!finite(total) || total <= 0) return null
  const done = st?.bytes_done
  const rate = st?.ingest_mb_s
  const head = finite(done) ? `${fmtBytes(Math.min(done, total))} of ${fmtBytes(total)}` : `${fmtBytes(total)} to read`
  const tail = finite(rate) && rate > 0 ? ` · ${rate < 10 ? rate.toFixed(1) : Math.round(rate)} MB/s` : ''
  return `Ingestion: ${head}${tail}`
}
