import { useState } from 'react'
import { fmtInt, fmtSpan } from '../lib/format'
import { allSteps, techniqueOf } from '../lib/incident'
import type { Incident } from '../types'
import { Button } from './ui'

export function ReportTab({ incident }: { incident: Incident }) {
  const [copied, setCopied] = useState<'ok' | 'fail' | null>(null)
  const llm = incident.narrative.source === 'llm'
  const copy = () => {
    const done = (r: 'ok' | 'fail') => {
      setCopied(r)
      window.setTimeout(() => setCopied(null), 1500)
    }
    if (!navigator.clipboard) return done('fail')
    navigator.clipboard.writeText(incident.narrative.text).then(
      () => done('ok'),
      () => done('fail'),
    )
  }
  return (
    <div className="px-6 py-6">
      <article className="mx-auto max-w-3xl rounded-2xl border border-line bg-panel shadow-card">
        <header className="flex items-center gap-3 border-b border-line px-8 py-5">
          <div><div className="section-label">AttackLens</div><h3 className="headline mt-0.5 text-[20px]">Incident report</h3></div>
          <span
            className={`rounded-full border px-2.5 text-[11px] leading-[20px] font-semibold tracking-[0.06em] uppercase ${llm ? 'border-accent/40 bg-accent-tint text-accent' : 'border-line-strong bg-subtle text-ink-2'}`}
            title={llm ? 'Written by the LLM from placeholders and enums only' : 'Deterministic template'}
          >
            {llm ? 'LLM' : 'Template'}
          </span>
          <span className="ml-auto flex items-center gap-2">
            {copied && <span className={`text-[12px] ${copied === 'ok' ? 'text-low-ink' : 'text-crit-ink'}`}>{copied === 'ok' ? 'Copied' : 'Copy failed'}</span>}
            <Button onClick={copy} title="Copy the narrative text">
              Copy
            </Button>
          </span>
        </header>
        <div className="space-y-7 px-8 py-6">
          <dl className="grid grid-cols-[140px_1fr] gap-x-4 gap-y-2 rounded-xl border border-line bg-subtle px-5 py-4 text-[13px]">
            <dt className="text-muted">Incident</dt>
            <dd className="font-mono text-ink">{incident.id}</dd>
            <dt className="text-muted">Risk</dt>
            <dd className="tabular-nums text-ink">{incident.risk} / 100</dd>
            <dt className="text-muted">Time span</dt>
            <dd className="text-ink">{fmtSpan(incident.first_ts, incident.last_ts)}</dd>
            <dt className="text-muted">Alerts merged</dt>
            <dd className="tabular-nums text-ink">
              {fmtInt(incident.merged_alert_count)} alerts in {incident.episode_count} episodes
            </dd>
            <dt className="text-muted">Entry point</dt>
            <dd className="text-ink">{incident.entry_point.summary}</dd>
          </dl>
          <section>
            <h4 className="section-label mb-2">Summary</h4>
            {/* Plain text node; never HTML. */}
            <p className="text-[15px] leading-[1.75] whitespace-pre-wrap text-ink">{incident.narrative.text}</p>
          </section>
          <section>
            <h4 className="section-label mb-2">Steps</h4>
            <ol className="list-decimal space-y-1.5 pl-5 text-[14px] leading-relaxed text-ink marker:text-muted">
              {allSteps(incident).map((s) => (
                <li key={`${s.episode_id}-${s.step}`}>
                  <span className="font-mono text-accent">{techniqueOf(s)}</span> {s.technique_name ?? ''} <span className="text-muted">({s.tactic})</span>
                  {' on '}
                  <span className="font-mono">{s.host ?? '—'}</span>
                  {s.user ? ' as ' : ''}
                  {s.user && <span className="font-mono">{s.user}</span>}
                </li>
              ))}
            </ol>
          </section>
        </div>
      </article>
    </div>
  )
}
