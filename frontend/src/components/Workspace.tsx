import { useCallback, useEffect, useMemo, useState } from 'react'
import { fmtSpan, riskStyle } from '../lib/format'
import { allSteps, hostsOf } from '../lib/incident'
import { PivotContext, usePivotLoader } from '../lib/pivots'
import { incidentTitle } from '../lib/plain'
import { TAB_LABEL, TABS, type Tab } from '../lib/tabs'
import { grade, TARGETS } from '../lib/targets'
import type { Incident } from '../types'
import { AttackGraph } from './AttackGraph'
import { AttackPathTab } from './AttackPathTab'
import { EvidenceTab } from './EvidenceTab'
import { Inspector } from './Inspector'
import { OverviewTab } from './OverviewTab'
import { ReachTab } from './ReachTab'
import { ReportTab } from './ReportTab'

interface Props {
  incident: Incident
  /** performance.now() at the click that opened this incident (null = background refresh / first load). */
  openedAt: number | null
  tab: Tab
  onTab: (t: Tab) => void
  inspectorOpen: boolean
  onInspector: (open: boolean) => void
}

const TAB_HINT: Record<Tab, string> = {
  overview: 'The story, the attack path in plain words, and what is at risk next',
  steps: 'Every step with MITRE ATT&CK technique, tactic, confidence and why steps are linked',
  graph: 'Machines, users and IPs involved, left to right in attack order',
  evidence: 'The raw log lines behind each step',
  reach: 'Machines the attacker can reach next, with the evidence',
  report: 'The full written report',
}

export function Workspace({ incident, openedAt, tab, onTab, inspectorOpen, onInspector }: Props) {
  const [selected, setSelected] = useState<number | null>(null)
  const [flashKey, setFlashKey] = useState(0)
  const [renderMs, setRenderMs] = useState<number | null>(null)
  const steps = useMemo(() => allSteps(incident), [incident])
  const hosts = useMemo(() => hostsOf(incident), [incident])
  const rs = riskStyle(incident.risk)
  const pivots = usePivotLoader(incident.id)
  const title = useMemo(() => incidentTitle(incident), [incident])

  // Measured, not asserted: click -> fetch -> commit (child effects incl. Cytoscape run first) -> next frame.
  useEffect(() => {
    if (openedAt === null) return
    const raf = requestAnimationFrame(() => setRenderMs(performance.now() - openedAt))
    return () => cancelAnimationFrame(raf)
  }, [incident, openedAt])

  // Level 3 on demand: selecting a step opens the inspector with its raw evidence.
  const select = useCallback(
    (step: number | null) => {
      setSelected(step)
      setFlashKey((k) => k + 1)
      if (step !== null) onInspector(true)
    },
    [onInspector],
  )

  const whyForStep = useCallback(
    (step: number): string | null => {
      const s = steps.find((x) => x.step === step)
      if (!s) return null
      const e = incident.edges.find((x) => x.to === s.episode_id)
      if (e) return `${e.rule}: ${e.why_linked}`
      if (step === incident.entry_point.step) return `Entry point: ${incident.entry_point.summary}`
      return null
    },
    [steps, incident],
  )

  const counts: Partial<Record<Tab, number>> = {
    steps: steps.length,
    evidence: steps.reduce((n, s) => n + s.evidence.length, 0),
    reach: incident.reach_next.length,
  }
  const g = renderMs === null ? 'none' : grade(renderMs, TARGETS.openPathMs)

  return (
    <PivotContext value={pivots}>
      <div className="relative flex min-h-0 min-w-0 flex-1 gap-4">
        <section className="card @container flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden" aria-labelledby="incident-title">
          {/* Incident header */}
          <header className="shrink-0 border-b border-line px-6 pt-5 pb-0 short:pt-4">
            <div className="flex items-start gap-4">
              <div className="min-w-0 flex-1">
                <h2 id="incident-title" className="headline text-[22px] leading-[1.25] short:text-[20px]" title={`${incident.id} · ${incident.entry_point.summary}`}>
                  {title}
                </h2>
                <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1.5 text-[13px] text-ink-2 short:mt-1.5">
                  <span className={`inline-flex h-6 items-center gap-1.5 rounded-full border px-2.5 text-[11px] font-semibold tracking-[0.06em] uppercase ${rs.pill}`} title={`Risk score ${incident.risk} / 100`}>
                    <span className={`h-1.5 w-1.5 rounded-full ${rs.bar}`} aria-hidden="true" />
                    {rs.label} risk
                    <span className="font-mono tracking-normal">{incident.risk}</span>
                  </span>
                  <span>
                    <strong className="font-semibold text-ink tabular-nums">{incident.merged_alert_count.toLocaleString('en-US')}</strong> alerts → <strong className="font-semibold text-ink">1 incident</strong>
                  </span>
                  <span className="text-line-strong" aria-hidden="true">|</span>
                  <span>
                    {incident.backbone.length} steps across {hosts.length} machine{hosts.length === 1 ? '' : 's'}
                  </span>
                  <span className="text-line-strong" aria-hidden="true">|</span>
                  <span className="text-muted">{fmtSpan(incident.first_ts, incident.last_ts)}</span>
                </div>
              </div>
              {renderMs !== null && (
                <span
                  className="shrink-0 rounded-full border border-line bg-subtle px-2.5 py-1 text-[11px] text-muted tabular-nums"
                  title={`Measured with performance.now() from click to rendered incident (includes fetch). Hackathon target: ${TARGETS.openPathMs.text}`}
                >
                  opened in {Math.round(renderMs)} ms{g === 'great' ? ' ✓' : ''}
                </span>
              )}
            </div>
            {/* Tabs (level 2) */}
            <div className="mt-4 flex items-center gap-3 pb-3 short:mt-3">
              <div role="tablist" aria-label="Incident views" className="flex min-w-0 flex-nowrap gap-1 overflow-x-auto rounded-full border border-line bg-subtle p-1">
                {TABS.map((t) => {
                  const active = t === tab
                  return (
                    <button
                      key={t}
                      type="button"
                      role="tab"
                      id={`tab-${t}`}
                      aria-selected={active}
                      aria-controls={`panel-${t}`}
                      onClick={() => onTab(t)}
                      onKeyDown={(e) => {
                        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return
                        const i = TABS.indexOf(t) + (e.key === 'ArrowRight' ? 1 : -1)
                        const next = TABS[(i + TABS.length) % TABS.length]
                        onTab(next)
                        document.getElementById(`tab-${next}`)?.focus()
                      }}
                      tabIndex={active ? 0 : -1}
                      title={TAB_HINT[t]}
                      className={`focus-ring flex h-8 shrink-0 items-center gap-1.5 rounded-full px-3.5 text-[13px] whitespace-nowrap @max-3xl:px-2.5 ${
                        active ? 'bg-white font-semibold text-ink shadow-card' : 'font-medium text-ink-2 hover:bg-white/70 hover:text-ink'
                      }`}
                    >
                      {TAB_LABEL[t]}
                      {counts[t] !== undefined && <span className={`font-mono text-[11px] tabular-nums @max-3xl:hidden ${active ? 'text-accent' : 'text-muted'}`}>{counts[t]}</span>}
                    </button>
                  )
                })}
              </div>
              {!inspectorOpen && selected !== null && (
                <button
                  type="button"
                  onClick={() => onInspector(true)}
                  className="focus-ring ml-auto inline-flex h-8 shrink-0 items-center gap-1.5 rounded-full border border-line-strong bg-white px-3 text-[13px] font-medium text-ink hover:bg-subtle"
                  title="Show the raw details of the selected step"
                >
                  Step {selected + 1} details
                </button>
              )}
            </div>
          </header>

          {/* Tab panel */}
          <div id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`} className={`min-h-0 flex-1 ${tab === 'graph' ? 'p-5' : 'overflow-y-auto'}`}>
            {tab === 'overview' && <OverviewTab incident={incident} selected={selected} onSelect={select} onOpenTab={onTab} />}
            {tab === 'steps' && <AttackPathTab incident={incident} selected={selected} flashKey={flashKey} onSelect={select} />}
            {tab === 'graph' && <AttackGraph nodes={incident.graph.nodes} edges={incident.graph.edges} selected={selected} whyForStep={whyForStep} onSelectStep={select} />}
            {tab === 'evidence' && <EvidenceTab incident={incident} selected={selected} onSelect={select} />}
            {tab === 'reach' && <ReachTab rows={incident.reach_next} />}
            {tab === 'report' && <ReportTab incident={incident} />}
          </div>
        </section>
        {inspectorOpen && (
          // Wide screens: a third column. Below 1440 px: an overlay panel so the work area keeps its width.
          <div className="flex min-h-0 max-[1439px]:absolute max-[1439px]:inset-y-0 max-[1439px]:right-0 max-[1439px]:z-30 max-[1439px]:rounded-2xl max-[1439px]:shadow-pop">
            <Inspector incident={incident} selected={selected} onSelect={select} onClose={() => onInspector(false)} />
          </div>
        )}
      </div>
    </PivotContext>
  )
}
