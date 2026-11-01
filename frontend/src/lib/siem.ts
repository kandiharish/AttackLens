// SIEM integration helpers (pure). Labels only; every number comes from the API.
import type { LiveStatus } from '../api'
import type { Metrics, Step } from '../types'
import type { IncidentPivots, StepPivots } from '../types_integrations'

const VENDOR: Record<string, string> = {
  splunk: 'Splunk',
  sentinel: 'Sentinel',
  elastic: 'Elastic',
  opensearch: 'OpenSearch',
  syslog: 'Syslog/CEF',
  cef: 'CEF',
  qradar: 'QRadar',
}

/** Display name of a SIEM / connector / sink key ("splunk_hec" -> "Splunk HEC"). */
export function siemName(key: string): string {
  if (VENDOR[key]) return VENDOR[key]
  const known: Record<string, string> = { splunk_hec: 'Splunk HEC', elastic_bulk: 'Elastic bulk', webhook: 'Webhook', syslog_cef: 'Syslog CEF' }
  if (known[key]) return known[key]
  return key ? key.charAt(0).toUpperCase() + key.slice(1) : key
}

/** "siem:splunk:Brute force" -> "Splunk"; null for AttackLens rules. */
export function siemVendor(ruleId: string | null | undefined): string | null {
  if (!ruleId || !ruleId.startsWith('siem:')) return null
  const vendor = ruleId.split(':')[1] ?? ''
  return vendor ? siemName(vendor.toLowerCase()) : 'SIEM'
}

/** Run fed by the SIEM alert spool (vendor labels): run_metrics.input_mode / inputs, or live_status while live. */
export function isSiemAlertsInput(metrics: Metrics | null, live: LiveStatus | null): boolean {
  const rm = metrics?.run_metrics
  const mode = rm?.input_mode
  if (typeof mode === 'string' && mode.includes('siem_alerts')) return true
  const inputs = rm?.inputs
  if (inputs && typeof inputs === 'object' && (inputs as Record<string, unknown>).siem_alerts === true) return true
  if (live?.enabled === true && typeof live.input_mode === 'string' && live.input_mode.includes('siem_alerts')) return true
  return false
}

/** Pivots of one step: exact (episode_id, step) match first, then episode_id, then step number. */
export function findStepPivots(p: IncidentPivots, s: Step): StepPivots | undefined {
  const all = [...(p.steps ?? []), ...(p.branches ?? []).flat()]
  return (
    all.find((x) => x.episode_id === s.episode_id && x.step === s.step) ??
    all.find((x) => x.episode_id === s.episode_id) ??
    all.find((x) => x.step === s.step)
  )
}

/** Only http(s) links are rendered (the URL is built from config + log-derived values). */
export function safeHttpUrl(url: string | null | undefined): string | null {
  if (!url) return null
  try {
    const u = new URL(url)
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null
  } catch {
    return null
  }
}
