// Log health badge: Trusted / Suspect / Tampered + trust score, "Checking integrity…" while a scan runs,
// "Not checked" when there is no report. A yellow "Looks generated" chip when authenticity says so.
// Text + icon carry the meaning (not colour alone). Numbers come only from the report.
import { isGenerated, scopeLabel, verdictStyle, type IntegrityState } from '../../lib/integrity'

interface Props {
  state: IntegrityState
  /** Open the full health report (only when a report exists). */
  onOpen?: () => void
  /** Header variant: smaller, drops the "Log health" prefix on narrow screens. */
  compact?: boolean
}

function Icon({ verdict }: { verdict: string }) {
  if (verdict === 'trusted')
    return (
      <svg viewBox="0 0 12 12" className="h-3 w-3" aria-hidden="true">
        <path d="M2.5 6.2l2.3 2.3 4.7-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    )
  if (verdict === 'tampered')
    return (
      <svg viewBox="0 0 12 12" className="h-3 w-3" aria-hidden="true">
        <path d="M3 3l6 6M9 3l-6 6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      </svg>
    )
  return (
    <svg viewBox="0 0 12 12" className="h-3 w-3" aria-hidden="true">
      <path d="M6 2.2v4.6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      <circle cx="6" cy="9.4" r="1" fill="currentColor" />
    </svg>
  )
}

export function HealthBadge({ state, onOpen, compact = false }: Props) {
  const h = compact ? 'h-8 text-[12px]' : 'h-8 text-[13px]'
  const prefix = <span className={`font-medium text-muted ${compact ? 'max-lg:hidden' : ''}`}>Log health</span>

  if (state.status === 'checking')
    return (
      <span role="status" className={`inline-flex items-center gap-2 rounded-full border border-line-strong bg-white px-3 ${h} text-ink-2`}>
        <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-line border-t-muted" aria-hidden="true" />
        Checking integrity…
      </span>
    )
  if (state.status === 'absent' || state.status === 'failed') {
    const title = state.status === 'failed' ? `Integrity check failed: ${state.error}` : 'No integrity report for this data yet'
    return (
      <span role="status" title={title} className={`inline-flex items-center gap-2 rounded-full border border-line bg-subtle px-3 ${h} text-muted`}>
        <span className="h-2 w-2 rounded-full bg-line-strong" aria-hidden="true" />
        {compact ? null : prefix}
        {state.status === 'failed' ? 'Check failed' : 'Not checked'}
      </span>
    )
  }

  const r = state.report
  const vs = verdictStyle(r.verdict)
  const gen = isGenerated(r)
  const label = `Log health: ${vs.label}, trust score ${r.trust_score} of 100 (${scopeLabel(r)})${gen ? '; logs look machine-generated' : ''}. Open the health report.`
  return (
    <span className="inline-flex items-center gap-1.5">
      <button
        type="button"
        onClick={onOpen}
        title={`${r.summary}\n${scopeLabel(r)}`}
        aria-label={label}
        className={`focus-ring inline-flex items-center gap-2 rounded-full border px-3 font-semibold ${h} ${vs.pill} hover:brightness-[0.97]`}
      >
        {prefix}
        <Icon verdict={r.verdict} />
        {vs.label}
        <span className="font-mono tabular-nums opacity-80">{r.trust_score}</span>
      </button>
      {gen && (
        <span
          className={`inline-flex items-center gap-1 rounded-full border border-med/70 bg-med-bg px-2.5 font-semibold text-med-ink ${compact ? 'h-7 text-[11px]' : 'h-7 text-[12px]'}`}
          title={`Authenticity score ${r.authenticity?.score ?? '—'} / 100 (higher = more machine-generated). Does not change the verdict.`}
        >
          <svg viewBox="0 0 12 12" className="h-3 w-3" aria-hidden="true">
            <rect x="2" y="3" width="8" height="6.5" rx="1.5" fill="none" stroke="currentColor" strokeWidth="1.4" />
            <path d="M6 1.2V3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
            <circle cx="4.5" cy="6.2" r=".8" fill="currentColor" />
            <circle cx="7.5" cy="6.2" r=".8" fill="currentColor" />
          </svg>
          Looks generated
        </span>
      )}
    </span>
  )
}
