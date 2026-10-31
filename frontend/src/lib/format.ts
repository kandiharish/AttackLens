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
  badge: string
  bar: string
}

export function riskStyle(risk: number): RiskStyle {
  if (risk >= 80) return { label: 'Critical', badge: 'bg-rose-600 text-white', bar: 'bg-rose-500' }
  if (risk >= 60) return { label: 'High', badge: 'bg-orange-500 text-slate-950', bar: 'bg-orange-400' }
  if (risk >= 40) return { label: 'Medium', badge: 'bg-amber-400 text-slate-950', bar: 'bg-amber-300' }
  return { label: 'Low', badge: 'bg-slate-600 text-slate-100', bar: 'bg-slate-400' }
}

export function confidenceColor(c: number): string {
  if (c >= 80) return 'bg-emerald-400'
  if (c >= 60) return 'bg-sky-400'
  if (c >= 40) return 'bg-amber-400'
  return 'bg-slate-500'
}
