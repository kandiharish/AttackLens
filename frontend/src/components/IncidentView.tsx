import { useCallback, useEffect, useMemo, useState } from 'react'
import { fmtSpan, fmtTs, riskStyle } from '../lib/format'
import type { Incident } from '../types'
import { AttackGraph } from './AttackGraph'
import { KillChainBar } from './KillChainBar'
import { NarrativePanel } from './NarrativePanel'
import { ReachNext } from './ReachNext'
import { StepTimeline } from './StepTimeline'

interface Props {
  incident: Incident
  /** performance.now() at the click that opened this incident. */
  openedAt: number | null
}

export function IncidentView({ incident, openedAt }: Props) {
  const [highlighted, setHighlighted] = useState<number | null>(null)
  const [flashKey, setFlashKey] = useState(0)
  const [renderMs, setRenderMs] = useState<number | null>(null)
  const rs = riskStyle(incident.risk)

  const allSteps = useMemo(() => [...incident.backbone, ...incident.branches.flat()], [incident])
  const entry = allSteps.find((s) => s.step === incident.entry_point.step)

  // Measured, not asserted: click -> data fetched -> DOM committed (child effects incl. Cytoscape layout run first) -> next frame.
  useEffect(() => {
    if (openedAt === null) return
    const raf = requestAnimationFrame(() => setRenderMs(performance.now() - openedAt))
    return () => cancelAnimationFrame(raf)
  }, [incident, openedAt])

  const jumpTo = useCallback((step: number) => {
    setHighlighted(step)
    setFlashKey((k) => k + 1)
    document.getElementById(`step-${step}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [])

  const whyForStep = useCallback(
    (step: number): string | null => {
      const s = allSteps.find((x) => x.step === step)
      if (!s) return null
      const e = incident.edges.find((x) => x.to === s.episode_id)
      if (e) return `${e.rule}: ${e.why_linked}`
      if (step === incident.entry_point.step) return `Entry point: ${incident.entry_point.summary}`
      return null
    },
    [allSteps, incident],
  )

  return (
    <article className="mx-auto max-w-6xl space-y-4 p-4" aria-labelledby="incident-title">
      {/* 1. Header */}
      <header className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className={`flex h-14 w-14 flex-col items-center justify-center rounded-lg ${rs.badge}`} title={`Risk ${incident.risk} / 100`}>
          <span className="font-mono text-2xl font-black leading-none tabular-nums">{incident.risk}</span>
          <span className="text-[9px] font-semibold uppercase">{rs.label}</span>
        </div>
        <div className="min-w-0">
          <h2 id="incident-title" className="text-xl font-bold text-slate-50">
            {incident.merged_alert_count.toLocaleString('en-US')} alerts → 1 incident
            <span className="ml-2 text-sm font-normal text-slate-400">
              {incident.backbone.length} steps{incident.branches.length ? ` + ${incident.branches.length} branch${incident.branches.length === 1 ? '' : 'es'}` : ''} ·{' '}
              {incident.episode_count} episodes
            </span>
          </h2>
          <p className="font-mono text-xs text-slate-400">
            {incident.id} · {fmtSpan(incident.first_ts, incident.last_ts)}
          </p>
        </div>
        {renderMs !== null && (
          <span className="ml-auto self-start font-mono text-[10px] text-slate-500" title="performance.now() from click to rendered incident (includes fetch)">
            rendered in {Math.round(renderMs)} ms
          </span>
        )}
      </header>

      {/* 2. Entry point */}
      <section aria-label="Entry point" className="flex flex-wrap items-center gap-2 rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2">
        <span className="rounded bg-amber-400 px-1.5 py-0.5 text-[10px] font-bold uppercase text-slate-950">Entry point</span>
        <span className="text-sm text-amber-50">{incident.entry_point.summary}</span>
        {entry && (
          <button
            type="button"
            onClick={() => jumpTo(entry.step)}
            className="ml-auto font-mono text-[11px] text-amber-300 underline-offset-2 hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            step {entry.step + 1} · {fmtTs(entry.ts)}Z
          </button>
        )}
      </section>

      {/* 3. Kill chain */}
      <KillChainBar tactics={incident.tactics} gaps={incident.gaps} steps={incident.backbone} onJump={jumpTo} />

      {/* 4. Ordered steps + evidence + why-linked */}
      <StepTimeline
        title="Attack path (ordered steps)"
        steps={incident.backbone}
        edges={incident.edges}
        entryStep={incident.entry_point.step}
        highlighted={highlighted}
        flashKey={flashKey}
        onHover={setHighlighted}
      />
      {incident.branches.map((b, i) => (
        <StepTimeline
          key={i}
          title={`Branch ${i + 1}`}
          steps={b}
          edges={incident.edges}
          entryStep={null}
          highlighted={highlighted}
          flashKey={flashKey}
          onHover={setHighlighted}
        />
      ))}

      {/* 5. Graph */}
      <AttackGraph
        nodes={incident.graph.nodes}
        edges={incident.graph.edges}
        highlighted={highlighted}
        whyForStep={whyForStep}
        onSelectStep={jumpTo}
      />

      {/* 6. Reach next */}
      <ReachNext rows={incident.reach_next} />

      {/* 7. Narrative */}
      <NarrativePanel narrative={incident.narrative} />
    </article>
  )
}
