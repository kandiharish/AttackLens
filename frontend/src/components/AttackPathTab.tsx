import { useEffect } from 'react'
import { isFirewall } from '../lib/entity'
import { confidenceColor, fmtTime, truncate } from '../lib/format'
import { allSteps, linkInto, techniqueOf } from '../lib/incident'
import { stepPlain, tacticTooltip, techniqueTooltip } from '../lib/plain'
import type { Incident, PathEdge, Step } from '../types'
import { KillChainBar } from './KillChainBar'
import { SiemPivotMenu, SiemTag } from './SiemPivots'
import { FirewallTag, TechniqueBadge } from './ui'

interface Props {
  incident: Incident
  selected: number | null
  flashKey: number
  onSelect: (step: number) => void
}

export function AttackPathTab({ incident, selected, flashKey, onSelect }: Props) {
  // When arriving from another tab (or a graph click), bring the selected step into view.
  useEffect(() => {
    if (selected !== null) document.getElementById(`step-${selected}`)?.scrollIntoView({ block: 'nearest' })
  }, [selected, flashKey])

  const groups: { title: string; steps: Step[] }[] = [
    { title: 'Main attack path', steps: [...incident.backbone].sort((a, b) => a.step - b.step) },
    ...incident.branches.map((b, i) => ({ title: `Side branch ${i + 1}`, steps: [...b].sort((a, c) => a.step - c.step) })),
  ]

  return (
    <div className="space-y-6 px-6 py-5">
      <KillChainBar tactics={incident.tactics} gaps={incident.gaps} steps={allSteps(incident)} onJump={onSelect} />
      {groups.map((g, gi) => (
        <section key={g.title} aria-label={g.title}>
          <div className="mb-3 flex items-baseline gap-3">
            <h3 className="headline text-[16px]">{g.title}</h3>
            <span className="text-[13px] text-muted">
              {g.steps.length} step{g.steps.length === 1 ? '' : 's'}
            </span>
            {gi === 0 && <span className="ml-auto text-[12px] text-muted">Times in UTC · click a step for raw details</span>}
          </div>
          <ol>
            {g.steps.map((s, i) => (
              <li key={`${s.episode_id}-${s.step}`}>
                {i > 0 && <Connector link={linkInto(incident.edges, g.steps[i - 1], s)} />}
                <StepRow step={s} isEntry={s.step === incident.entry_point.step} selected={selected === s.step} flashKey={selected === s.step ? flashKey : 0} onSelect={onSelect} />
              </li>
            ))}
          </ol>
        </section>
      ))}
    </div>
  )
}

function Connector({ link }: { link: PathEdge | undefined }) {
  return (
    <div className="grid grid-cols-[72px_1fr]">
      <span />
      <div className="ml-[17px] flex min-h-9 items-center gap-2.5 border-l-2 border-dashed border-line-strong py-2 pl-5 text-[13px]">
        {link ? (
          <>
            <span
              className="shrink-0 rounded-full border border-line bg-subtle px-2 font-mono text-[11px] leading-[18px] text-ink-2"
              title={`Why these two steps are linked. Rule ${link.rule} (R1 = moved between machines, R2 = same session, R3 = same account, R4 = data flow), strength ${link.weight}`}
            >
              {link.rule}
            </span>
            <span className="min-w-0 text-muted italic">{truncate(link.why_linked)}</span>
          </>
        ) : (
          <span className="text-muted italic">no link reason recorded</span>
        )}
      </div>
    </div>
  )
}

function StepRow({ step: s, isEntry, selected, flashKey, onSelect }: { step: Step; isEntry: boolean; selected: boolean; flashKey: number; onSelect: (n: number) => void }) {
  const firstEvidence = s.evidence[0]
  return (
    <div className="grid grid-cols-[72px_1fr] items-start">
      <time dateTime={s.ts} className="pt-4 font-mono text-[12px] text-muted" title={s.ts}>
        {fmtTime(s.ts)}
      </time>
      <div className="relative min-w-0">
        <button
          type="button"
          id={`step-${s.step}`}
          key={flashKey}
          onClick={() => onSelect(s.step)}
          aria-pressed={selected}
          className={`focus-ring flex w-full min-w-0 scroll-mt-4 gap-3.5 rounded-xl border p-4 text-left ${
            selected ? 'step-flash border-brand bg-accent-tint shadow-card' : 'border-line bg-white hover:border-line-strong hover:shadow-card'
          }`}
        >
          <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full font-mono text-[13px] font-semibold tabular-nums ${selected ? 'bg-brand text-ink' : 'bg-ink text-white'}`}>{s.step + 1}</span>
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-2">
              <span className="text-[15px] font-semibold text-ink">{stepPlain(s).short}</span>
              {isEntry && <span className="rounded-full border border-high/60 bg-high-bg px-2 text-[11px] leading-[20px] font-semibold tracking-[0.06em] text-high-ink uppercase">Entry point</span>}
              <SiemTag ruleId={s.rule_id} />
              <span className="ml-auto flex items-center gap-2 text-[12px] text-ink-2" title={`How sure we are this step is real: ${s.confidence}% (severity ${s.severity})`}>
                <span className="text-muted">confidence</span>
                <span className="h-1.5 w-16 overflow-hidden rounded-full bg-unobs" role="meter" aria-valuenow={s.confidence} aria-valuemin={0} aria-valuemax={100} aria-label="confidence">
                  <span className={`block h-1.5 rounded-full ${confidenceColor(s.confidence)}`} style={{ width: `${Math.max(0, Math.min(100, s.confidence))}%` }} />
                </span>
                <span className="w-9 text-right font-medium tabular-nums">{s.confidence}%</span>
              </span>
            </span>
            <span className="mt-2 flex flex-wrap items-center gap-2" title={techniqueTooltip(s)}>
              <TechniqueBadge id={techniqueOf(s)} name={s.technique_name} />
              <span className="inline-flex items-center rounded-full border border-line bg-subtle px-2.5 text-[12px] leading-[22px] text-ink-2" title={tacticTooltip(s.tactic)}>
                {s.tactic}
              </span>
            </span>
            <span className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 pr-32 text-[13px] text-ink-2">
              <span className="min-w-0 font-mono text-[12.5px] text-ink">
                {s.host ?? '—'}
                {isFirewall(s.host) && <FirewallTag />}
                {s.user && (
                  <>
                    <span className="px-1.5 font-sans text-muted">as</span>
                    {s.user}
                  </>
                )}
              </span>
              {(s.src_ip || s.dst_ip) && (
                <span className="font-mono text-[12.5px] text-ink-2">
                  {s.src_ip ?? '?'}
                  {s.dst_ip && <span className="px-1 font-sans text-muted">→</span>}
                  {s.dst_ip}
                </span>
              )}
              <span className="text-muted">
                {s.merged_alert_count.toLocaleString('en-US')} alert{s.merged_alert_count === 1 ? '' : 's'} merged
              </span>
            </span>
            {firstEvidence && (
              // Log-derived text: React text node only (escaped), never HTML.
              <span className="mt-2.5 block truncate rounded-lg bg-subtle px-3 py-1.5 pr-32 font-mono text-[11.5px] text-muted" title={truncate(firstEvidence)}>
                {truncate(firstEvidence)}
              </span>
            )}
          </span>
        </button>
        {/* Sibling of the step button (no nested interactive elements). */}
        <div className="absolute right-4 bottom-4">
          <SiemPivotMenu step={s} />
        </div>
      </div>
    </div>
  )
}
