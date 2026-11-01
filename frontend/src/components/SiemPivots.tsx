// "Open in SIEM" per step: ready-to-run SPL / KQL / Lucene from GET /api/incidents/{id}/pivots.
// Query text contains log-derived values (escaped by the backend for each query language); it is rendered as
// React text only, never HTML. "Open" links appear only when the API returns a url (http/https only).
import { useEffect, useRef, useState } from 'react'
import { usePivots } from '../lib/pivots'
import { findStepPivots, safeHttpUrl, siemName, siemVendor } from '../lib/siem'
import type { Step } from '../types'
import type { PivotQuery } from '../types_integrations'

const LANG: Record<string, string> = { spl: 'SPL', kql: 'KQL', lucene: 'Lucene' }

/** Small tag on steps whose rule_id is "siem:<vendor>:<rule>" (episode came from the SIEM's own alert). */
export function SiemTag({ ruleId }: { ruleId: string | null }) {
  const vendor = siemVendor(ruleId)
  if (!vendor) return null
  return (
    <span
      className="inline-flex rounded-full border border-siem/40 bg-siem-bg px-2.5 text-[11px] leading-[20px] font-medium text-siem-ink"
      title={`From SIEM: ${ruleId ?? ''} (vendor label, alert-input mode)`}
    >
      {vendor} alert
    </span>
  )
}

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle')
  const copy = () => {
    const done = (s: 'ok' | 'fail') => {
      setState(s)
      window.setTimeout(() => setState('idle'), 1500)
    }
    if (!navigator.clipboard) return done('fail')
    navigator.clipboard.writeText(text).then(
      () => done('ok'),
      () => done('fail'),
    )
  }
  return (
    <button
      type="button"
      onClick={copy}
      className="focus-ring inline-flex h-7 items-center rounded-full border border-line-strong bg-white px-3 text-[12px] font-medium text-ink hover:bg-subtle"
      title={state === 'fail' ? 'Clipboard unavailable: select the text and copy it' : `${label} to clipboard`}
    >
      {state === 'ok' ? 'Copied' : state === 'fail' ? 'Select text' : label}
    </button>
  )
}

function QueryBlock({ q }: { q: PivotQuery }) {
  const url = safeHttpUrl(q.url)
  const dsl = q.dsl ? JSON.stringify(q.dsl, null, 2) : null
  return (
    <section className="border-b border-line px-4 py-3.5 last:border-b-0">
      <div className="mb-2 flex items-center gap-2">
        <span className="text-[13px] font-semibold text-ink">{siemName(q.siem)}</span>
        <span className="rounded-full border border-line bg-subtle px-2 font-mono text-[10px] leading-[18px] text-ink-2">{LANG[q.language] ?? q.language}</span>
        <span className="ml-auto flex items-center gap-1">
          <CopyButton text={q.query} />
          {dsl && <CopyButton text={dsl} label="Copy DSL" />}
          {url && (
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="focus-ring inline-flex h-7 items-center rounded-full border border-ink bg-ink px-3 text-[12px] font-medium text-white hover:bg-[#262626]"
              title={`Open in ${siemName(q.siem)} (new tab)`}
            >
              Open ↗
            </a>
          )}
        </span>
      </div>
      <pre className="max-h-36 overflow-auto rounded-lg border border-line bg-subtle px-3 py-2 font-mono text-[11.5px] leading-relaxed break-all whitespace-pre-wrap text-ink select-all">{q.query}</pre>
      <p className="mt-1.5 font-mono text-[11px] text-muted" title="Query window (UTC)">
        {q.earliest} → {q.latest}
      </p>
    </section>
  )
}

function PivotBody({ step }: { step: Step }) {
  const { state } = usePivots()
  if (state.status === 'idle' || state.status === 'loading') return <p className="px-4 py-3 text-[13px] text-muted">Loading SIEM queries…</p>
  if (state.status === 'error') return <p className="px-4 py-3 text-[13px] text-muted">Pivots unavailable.</p>
  const sp = findStepPivots(state.data, step)
  const order = state.data.siems ?? []
  const queries = sp ? [...order.filter((n) => sp.queries[n]), ...Object.keys(sp.queries).filter((n) => !order.includes(n))].map((n) => sp.queries[n]) : []
  if (order.length === 0) return <p className="px-4 py-3 text-[13px] text-muted">No SIEM pivots enabled (config/integrations.yaml → pivots).</p>
  if (queries.length === 0) return <p className="px-4 py-3 text-[13px] text-muted">No SIEM query for this step (needs a timestamp and a host, user or IP).</p>
  return (
    <div>
      {queries.map((q) => (
        <QueryBlock key={q.siem} q={q} />
      ))}
    </div>
  )
}

/**
 * popover: compact button + floating panel (attack path rows).
 * inline: button toggles the panel in place (narrow inspector column).
 */
export function SiemPivotMenu({ step, variant = 'popover' }: { step: Step; variant?: 'popover' | 'inline' }) {
  const { ensure } = usePivots()
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open || variant !== 'popover') return
    const onDown = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open, variant])

  const toggle = () => {
    if (!open) ensure()
    setOpen((o) => !o)
  }

  return (
    <div className={variant === 'popover' ? 'relative' : ''} ref={box}>
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        aria-haspopup={variant === 'popover' ? 'dialog' : undefined}
        className={`focus-ring inline-flex h-7 items-center gap-1.5 rounded-full border px-3 text-[12px] font-medium ${
          open ? 'border-accent/40 bg-accent-tint text-accent' : 'border-line-strong bg-white text-ink-2 hover:bg-subtle hover:text-ink'
        }`}
        title="Splunk / Sentinel / Elastic query for this step's host, user and IPs (± window)"
      >
        Open in SIEM
        <svg viewBox="0 0 10 10" className="h-2.5 w-2.5" aria-hidden="true">
          <path d={open ? 'M2 6.5l3-3 3 3' : 'M2 3.5l3 3 3-3'} fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        </svg>
      </button>
      {open && (
        <div
          role={variant === 'popover' ? 'dialog' : 'region'}
          aria-label={`SIEM queries for step ${step.step + 1}`}
          className={
            variant === 'popover'
              ? 'absolute right-0 z-50 mt-2 w-[480px] max-w-[calc(100vw-2rem)] overflow-hidden rounded-2xl border border-line bg-panel text-left shadow-pop'
              : 'mt-2.5 overflow-hidden rounded-xl border border-line bg-panel'
          }
        >
          <PivotBody step={step} />
        </div>
      )}
    </div>
  )
}
