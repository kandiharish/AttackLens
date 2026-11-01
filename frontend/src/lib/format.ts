// Pure formatting helpers. All timestamps are shown in UTC.

export const EVIDENCE_MAX = 300

export function truncate(s: string, max = EVIDENCE_MAX): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s
}

function pad(n: number): string {
  return String(n).padStart(2, '0')
}

/** "2026-10-24 02:00:00" (UTC). Returns the input unchanged if it does not parse. */
export function fmtTs(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${fmtTime(iso)}`
}

/** "02:00:00" (UTC). */
export function fmtTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`
}

export function fmtDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—'
  const s = Math.round(ms / 1000)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${sec}s`
  return `${sec}s`
}

/** "2026-10-24 02:00:00 → 03:05:00 UTC (1h 5m)"; repeats the date if the span crosses days. */
export function fmtSpan(first: string, last: string): string {
  const a = new Date(first)
  const b = new Date(last)
  if (Number.isNaN(a.getTime()) || Number.isNaN(b.getTime())) return `${first} → ${last}`
  const sameDay = a.toISOString().slice(0, 10) === b.toISOString().slice(0, 10)
  return `${fmtTs(first)} → ${sameDay ? fmtTime(last) : fmtTs(last)} UTC (${fmtDuration(b.getTime() - a.getTime())})`
}

export function fmtInt(n: number): string {
  return Math.round(n).toLocaleString('en-US')
}

export interface RiskStyle {
  label: string
  /** pill: tinted background + AA text + border */
  pill: string
  /** solid left bar / swatch */
  bar: string
  text: string
}

export function riskStyle(risk: number): RiskStyle {
  if (risk >= 80) return { label: 'Critical', pill: 'bg-crit-bg text-crit-ink border-crit/40', bar: 'bg-crit', text: 'text-crit-ink' }
  if (risk >= 60) return { label: 'High', pill: 'bg-high-bg text-high-ink border-high/40', bar: 'bg-high', text: 'text-high-ink' }
  if (risk >= 40) return { label: 'Medium', pill: 'bg-med-bg text-med-ink border-med/40', bar: 'bg-med', text: 'text-med-ink' }
  return { label: 'Low', pill: 'bg-low-bg text-low-ink border-low/40', bar: 'bg-low', text: 'text-low-ink' }
}

export function confidenceColor(c: number): string {
  if (c >= 80) return 'bg-low'
  if (c >= 60) return 'bg-accent'
  if (c >= 40) return 'bg-med'
  return 'bg-muted'
}

/** "02:00–02:54 UTC" (adds dates when the span crosses days). */
export function fmtShortSpan(first: string, last: string): string {
  const a = new Date(first)
  const b = new Date(last)
  if (Number.isNaN(a.getTime()) || Number.isNaN(b.getTime())) return `${first} – ${last}`
  const hm = (d: Date) => `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
  const md = (d: Date) => `${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`
  const same = a.toISOString().slice(0, 10) === b.toISOString().slice(0, 10)
  return same ? `${md(a)} ${hm(a)}–${hm(b)} UTC` : `${md(a)} ${hm(a)} – ${md(b)} ${hm(b)} UTC`
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** "Oct 24, 02:00 UTC" */
export function fmtDay(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}, ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`
}

/** Last path segment of a POSIX or Windows path ("data/out/f1/" -> "f1"). */
export function baseName(p: string): string {
  const parts = p.split(/[\\/]+/).filter(Boolean)
  return parts.length ? parts[parts.length - 1] : p
}
