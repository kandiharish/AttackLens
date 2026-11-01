// Popup shown when logs look tampered (red), maybe tampered (amber) or machine-generated (yellow).
// Every string from the report is rendered as text (never HTML); evidence is clipped to 300 chars.
import type { IntegrityReport } from '../../types'
import { clipEvidence, fmtRangeUtc, findingWhere, isGenerated, scopeLabel, sealLine, severityPill, topFindings } from '../../lib/integrity'
import { Button } from '../ui'
import { Modal } from './Modal'

interface Props {
  report: IntegrityReport
  /** "Continue anyway", Esc or backdrop. */
  onClose: () => void
  onViewReport: () => void
}

const HEAD = {
  tampered: { title: 'These logs appear to be TAMPERED', band: 'border-crit/40 bg-crit-bg', ink: 'text-crit-ink', dot: 'bg-crit', border: 'border-crit/50' },
  suspect: { title: 'These logs may have been tampered with', band: 'border-high/50 bg-high-bg', ink: 'text-high-ink', dot: 'bg-high', border: 'border-high/60' },
  generated: { title: 'These logs look machine-generated / synthetic', band: 'border-med/60 bg-med-bg', ink: 'text-med-ink', dot: 'bg-med', border: 'border-med/70' },
} as const

function GeneratedNote({ report, standalone }: { report: IntegrityReport; standalone: boolean }) {
  const a = report.authenticity
  if (!a) return null
  const fired = a.signals.filter((s) => s.fired)
  return (
    <section aria-labelledby={standalone ? undefined : 'tamper-gen-title'} aria-label={standalone ? 'Machine-generated warning' : undefined} className={`rounded-xl border px-4 py-3 ${HEAD.generated.band}`}>
      {!standalone && (
        <h3 id="tamper-gen-title" className={`flex items-center gap-2 text-[14px] font-semibold ${HEAD.generated.ink}`}>
          <span className={`h-2 w-2 rounded-full ${HEAD.generated.dot}`} aria-hidden="true" />
          {HEAD.generated.title}
        </h3>
      )}
      <p className={`text-[13px] leading-relaxed ${HEAD.generated.ink} ${standalone ? '' : 'mt-1'}`}>
        Authenticity score <span className="font-mono font-semibold tabular-nums">{a.score}</span> / 100 (higher = more machine-generated). This is a separate warning: it does not change the trust verdict.
      </p>
      {fired.length > 0 && (
        <ul className={`mt-2 list-disc space-y-0.5 pl-5 text-[12px] ${HEAD.generated.ink}`}>
          {fired.slice(0, 4).map((s) => (
            <li key={s.id} className="break-words">
              {clipEvidence(s.detail || s.id)}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

export function TamperDialog({ report, onClose, onViewReport }: Props) {
  const gen = isGenerated(report)
  const kind = report.verdict === 'tampered' ? 'tampered' : report.verdict === 'suspect' ? 'suspect' : gen ? 'generated' : 'suspect'
  const head = HEAD[kind]
  const showFindings = report.verdict !== 'trusted'
  const findings = showFindings ? topFindings(report.findings ?? [], 5) : []

  return (
    <Modal labelledBy="tamper-title" describedBy="tamper-summary" onClose={onClose} className={head.border}>
      <header className={`flex items-start gap-3 border-b px-6 py-4 ${head.band}`}>
        <span className={`mt-1 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[13px] font-bold text-white ${head.dot}`} aria-hidden="true">
          !
        </span>
        <div className="min-w-0 flex-1">
          <h2 id="tamper-title" className={`headline text-[19px] ${head.ink}`}>
            {head.title}
          </h2>
          <p className={`mt-0.5 text-[12px] font-medium ${head.ink}`}>
            {report.verdict !== 'trusted' && (
              <>
                Trust score <span className="font-mono tabular-nums">{report.trust_score}</span> / 100 ·{' '}
              </>
            )}
            {scopeLabel(report)} · set <span className="font-mono">{report.set}</span>
          </p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close" className="focus-ring -mr-2 flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-ink-2 hover:bg-white/60">
          <svg viewBox="0 0 12 12" className="h-3 w-3" aria-hidden="true">
            <path d="M3 3l6 6M9 3l-6 6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          </svg>
        </button>
      </header>

      <div className="max-h-[60vh] space-y-4 overflow-y-auto px-6 py-5">
        <p id="tamper-summary" className="text-[14px] leading-relaxed break-words text-ink">
          {report.summary}
        </p>

        {findings.length > 0 && (
          <section aria-label="Top findings">
            <div className="section-label mb-2">Top findings</div>
            <ol className="space-y-2.5">
              {findings.map((f, i) => {
                const where = findingWhere(f)
                const when = fmtRangeUtc(f.start_ts_ms, f.end_ts_ms)
                return (
                  <li key={`${f.check}-${i}`} className="rounded-xl border border-line bg-subtle px-3.5 py-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`inline-flex h-5 items-center rounded-full border px-2 text-[10px] font-semibold tracking-[0.08em] uppercase ${severityPill(f.severity)}`}>{f.severity}</span>
                      <span className="text-[13px] font-semibold break-words text-ink">{f.title}</span>
                      {f.count > 1 && <span className="font-mono text-[11px] text-muted tabular-nums">×{f.count.toLocaleString('en-US')}</span>}
                    </div>
                    {(where || when) && (
                      <p className="mt-1 font-mono text-[11px] break-words text-ink-2">
                        {where}
                        {where && when ? ' · ' : ''}
                        {when}
                      </p>
                    )}
                    {f.evidence?.slice(0, 2).map((ev, j) => (
                      <pre key={j} className="mt-1.5 overflow-x-auto rounded-md border border-line bg-white px-2 py-1 font-mono text-[11px] leading-snug whitespace-pre-wrap break-all text-ink-2">
                        {clipEvidence(ev)}
                      </pre>
                    ))}
                  </li>
                )
              })}
            </ol>
            {(report.findings?.length ?? 0) > findings.length && (
              <p className="mt-2 text-[12px] text-muted">
                + {(report.findings.length - findings.length).toLocaleString('en-US')} more in the full health report
              </p>
            )}
          </section>
        )}

        {gen && <GeneratedNote report={report} standalone={kind === 'generated'} />}

        <p className="text-[12px] text-ink-2">
          <span className="section-label mr-2">Seal</span>
          {sealLine(report)}
        </p>
      </div>

      <footer className="flex flex-wrap items-center justify-end gap-2 border-t border-line bg-subtle px-6 py-3.5">
        <Button onClick={onViewReport} variant="primary">
          View full health report
        </Button>
        <Button onClick={onClose}>Continue anyway</Button>
      </footer>
    </Modal>
  )
}
