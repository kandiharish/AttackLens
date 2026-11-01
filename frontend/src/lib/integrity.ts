// Pure helpers for the log-integrity UI (HealthBadge, TamperDialog, IntegrityPanel). No invented numbers:
// everything shown comes from integrity_report.json.
import type { IntegrityCheckStatus, IntegrityFinding, IntegrityReport, IntegritySeverity, IntegrityVerdict } from '../types'

/** UI state of one integrity report source (served dataset, an upload, a run). */
export type IntegrityState =
  | { status: 'absent' }
  | { status: 'checking' }
  | { status: 'done'; report: IntegrityReport }
  | { status: 'failed'; error: string }

export const VERDICT_RANK: Record<IntegrityVerdict, number> = { trusted: 0, suspect: 1, tampered: 2 }
export const SEVERITY_RANK: Record<IntegritySeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 }

const verdictRank = (v: string | null | undefined): number => (v && v in VERDICT_RANK ? VERDICT_RANK[v as IntegrityVerdict] : -1)

/** true when `next` is a strictly worse verdict than `prev`. */
export function isWorse(next: string | null | undefined, prev: string | null | undefined): boolean {
  return verdictRank(next) > verdictRank(prev)
}

export function isGenerated(r: IntegrityReport | null | undefined): boolean {
  return r?.authenticity?.label === 'likely_generated'
}

/** Report deserves a popup at all: tampered, suspect or likely machine-generated. */
export function isAlarming(r: IntegrityReport): boolean {
  return r.verdict === 'tampered' || r.verdict === 'suspect' || isGenerated(r)
}

/**
 * Popup policy for a report that replaces an earlier one (quick scan -> full scan).
 * No earlier report: popup if alarming. Earlier report: only if the verdict got worse or it newly looks generated.
 */
export function shouldPopup(prev: IntegrityReport | null, next: IntegrityReport): boolean {
  if (!prev) return isAlarming(next)
  return (isWorse(next.verdict, prev.verdict) && next.verdict !== 'trusted') || (isGenerated(next) && !isGenerated(prev))
}

export const reportKey = (r: Pick<IntegrityReport, 'set' | 'generated_at'>) => `${r.set}\u0000${r.generated_at}`

const DISMISS_PREFIX = 'attacklens.integrity.dismissed:'

export function dismissKey(r: Pick<IntegrityReport, 'set' | 'generated_at'>): string {
  return `${DISMISS_PREFIX}${r.set}|${r.generated_at}`
}

export function isDismissed(r: Pick<IntegrityReport, 'set' | 'generated_at'>): boolean {
  try {
    return window.localStorage.getItem(dismissKey(r)) === '1'
  } catch {
    return false
  }
}

export function rememberDismissed(r: Pick<IntegrityReport, 'set' | 'generated_at'>): void {
  try {
    window.localStorage.setItem(dismissKey(r), '1')
  } catch {
    /* storage unavailable (private mode / quota): the dialog may show again, that is acceptable */
  }
}

/** Findings sorted most severe first, then by count (the backend already sorts; this keeps the UI robust). */
export function topFindings(fs: readonly IntegrityFinding[], n: number): IntegrityFinding[] {
  return [...fs].sort((a, b) => (SEVERITY_RANK[b.severity] ?? -1) - (SEVERITY_RANK[a.severity] ?? -1) || (b.count ?? 0) - (a.count ?? 0)).slice(0, n)
}

export const VERDICT_STYLE: Record<IntegrityVerdict, { label: string; pill: string; dot: string; ink: string; bg: string; border: string }> = {
  trusted: { label: 'Trusted', pill: 'border-low/60 bg-low-bg text-low-ink', dot: 'bg-low', ink: 'text-low-ink', bg: 'bg-low-bg', border: 'border-low/50' },
  suspect: { label: 'Suspect', pill: 'border-high/60 bg-high-bg text-high-ink', dot: 'bg-high', ink: 'text-high-ink', bg: 'bg-high-bg', border: 'border-high/50' },
  tampered: { label: 'Tampered', pill: 'border-crit/50 bg-crit-bg text-crit-ink', dot: 'bg-crit', ink: 'text-crit-ink', bg: 'bg-crit-bg', border: 'border-crit/40' },
}

export const verdictStyle = (v: string) => VERDICT_STYLE[(v in VERDICT_STYLE ? v : 'suspect') as IntegrityVerdict]

export const SEVERITY_PILL: Record<IntegritySeverity, string> = {
  critical: 'border-crit/50 bg-crit-bg text-crit-ink',
  high: 'border-high/60 bg-high-bg text-high-ink',
  medium: 'border-med/60 bg-med-bg text-med-ink',
  low: 'border-line-strong bg-subtle text-ink-2',
}

export const severityPill = (s: string) => SEVERITY_PILL[(s in SEVERITY_PILL ? s : 'low') as IntegritySeverity]

export const CHECK_STATUS_STYLE: Record<IntegrityCheckStatus, { label: string; pill: string }> = {
  pass: { label: 'Pass', pill: 'border-low/60 bg-low-bg text-low-ink' },
  warn: { label: 'Warn', pill: 'border-med/60 bg-med-bg text-med-ink' },
  fail: { label: 'Fail', pill: 'border-crit/50 bg-crit-bg text-crit-ink' },
  skipped: { label: 'Skipped', pill: 'border-line-strong bg-subtle text-muted' },
}

export const checkStatusStyle = (s: string) => CHECK_STATUS_STYLE[(s in CHECK_STATUS_STYLE ? s : 'skipped') as IntegrityCheckStatus]

/** Plain-language names of the 10 checks (ids from integrity.CHECK_IDS). Unknown ids fall back to the id. */
export const CHECK_LABEL: Record<string, string> = {
  seal: 'Seal (files unchanged since sealed)',
  zeroed_regions: 'Zeroed (wiped) regions in files',
  truncated_tail: 'Truncated file ends',
  log_cleared: 'Log cleared / audit tampering',
  silence_gap: 'Silence gaps',
  went_dark: 'Hosts that went dark',
  timestamps: 'Timestamp sanity',
  duplicates: 'Duplicate / replayed lines',
  embedded_time_mismatch: 'Embedded time mismatch',
  ingest_drops: 'Malformed / dropped lines',
}

export const checkLabel = (id: string) => CHECK_LABEL[id] ?? id

export function scopeLabel(r: Pick<IntegrityReport, 'scope'>): string {
  return r.scope === 'quick' ? 'Quick check (files only)' : 'Full check (files + events)'
}

const pad = (n: number) => String(n).padStart(2, '0')

/** Epoch ms -> "2026-10-31 14:02:07" (UTC). */
export function fmtUtcMs(ms: number | null | undefined): string | null {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return null
  const d = new Date(ms)
  if (Number.isNaN(d.getTime())) return null
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`
}

/** "2026-10-31 14:02:07 → 14:40:00 UTC" (date repeated only when it changes); null when no time is known. */
export function fmtRangeUtc(start: number | null | undefined, end: number | null | undefined): string | null {
  const a = fmtUtcMs(start)
  const b = fmtUtcMs(end)
  if (!a && !b) return null
  if (!a || !b || a === b) return `${a ?? b} UTC`
  return `${a} → ${a.slice(0, 10) === b.slice(0, 10) ? b.slice(11) : b} UTC`
}

/** "host ws-fin-010 · file sec.log" from a finding's location fields; null when none. */
export function findingWhere(f: Pick<IntegrityFinding, 'host' | 'file' | 'source_type'>): string | null {
  const parts = [f.host ? `host ${f.host}` : null, f.file ? `file ${f.file}` : null, !f.host && !f.file && f.source_type ? `source ${f.source_type}` : null].filter(Boolean)
  return parts.length ? parts.join(' · ') : null
}

/** Evidence line as display text, capped at 300 chars (never rendered as HTML). */
export function clipEvidence(s: unknown, max = 300): string {
  const t = typeof s === 'string' ? s : String(s ?? '')
  return t.length > max ? `${t.slice(0, max)}…` : t
}

/** One line describing the seal block. */
export function sealLine(r: IntegrityReport): string {
  const s = r.seal
  if (!s || s.status === 'absent') return 'No seal: files were not sealed at collection time, so byte-level changes cannot be proven.'
  if (s.status === 'verified') return `Seal verified: ${s.files_checked} file(s) match the ${s.keyed ? 'keyed (HMAC) ' : ''}seal manifest.`
  const parts = [s.modified.length ? `${s.modified.length} modified` : null, s.missing.length ? `${s.missing.length} missing` : null, s.added.length ? `${s.added.length} added` : null].filter(Boolean)
  return `Seal MISMATCH: ${parts.length ? parts.join(', ') : 'manifest invalid'} (of ${s.files_checked} sealed file(s)).`
}
