// Level 1 for judges: what happened (story), the attack path as a few big numbered steps, and what is reachable next.
import { isFirewall } from '../lib/entity'
import { sortReach } from '../lib/incident'
import { plainStory, simplePath, stepPlain, tacticTooltip, techniqueTooltip } from '../lib/plain'
import type { Incident } from '../types'
import { TacticIcon } from './TacticIcon'

interface Props {
  incident: Incident
  selected: number | null
  onSelect: (step: number) => void
  onOpenTab: (t: 'report' | 'reach' | 'steps') => void
}

export function OverviewTab({ incident, selected, onSelect, onOpenTab }: Props) {
  const story = plainStory(incident)
  const { nodes, hidden } = simplePath(incident)
  const reach = sortReach(incident.reach_next).filter((r) => !r.touched)
  const reachShown = (reach.length ? reach : sortReach(incident.reach_next)).slice(0, 3)

  return (
    <div className="space-y-5 px-6 py-5 short:space-y-4 short:py-4">
      {/* What happened */}
      <section aria-labelledby="ov-story" className="rounded-2xl border border-line bg-subtle px-6 py-4 short:py-3">
        <div className="flex items-center gap-3">
          <h3 id="ov-story" className="headline text-[16px]">
            What happened
          </h3>
          <span className="rounded-full border border-line bg-white px-2.5 py-0.5 text-[11px] font-medium text-muted" title="Plain summary generated from this incident's steps; the full written report is in the Report tab">
            Plain summary
          </span>
          <button type="button" onClick={() => onOpenTab('report')} className="focus-ring ml-auto rounded-full px-2 text-[13px] font-medium text-accent hover:underline">
            Full report →
          </button>
        </div>
        {/* Plain text node; never HTML. */}
        <p className="mt-2 max-w-[80ch] text-[15px] leading-[1.65] text-ink short:mt-1.5 short:text-[14px] short:leading-[1.6]">{story}</p>
      </section>

      {/* Simple attack path */}
      <section aria-labelledby="ov-path">
        <div className="mb-3 flex items-baseline gap-3">
          <h3 id="ov-path" className="headline text-[16px]">
            How the attack unfolded
          </h3>
          <span className="text-[13px] text-muted">Click a step for details</span>
          <button type="button" onClick={() => onOpenTab('steps')} className="focus-ring ml-auto rounded-full px-2 text-[13px] font-medium text-accent hover:underline">
            All steps with ATT&CK details →
          </button>
        </div>
        <ol className="flex items-stretch gap-0 overflow-x-auto pb-1">
          {nodes.map((n, i) => {
            const first = n.steps[0]
            const isSel = n.steps.some((s) => s.step === selected)
            const isEntry = n.steps.some((s) => s.step === incident.entry_point.step)
            const showGap = hidden > 0 && i === Math.ceil(nodes.length / 2)
            return (
              <li key={n.key} className="flex min-w-0 flex-1 items-stretch">
                {i > 0 && (
                  <div className="flex w-6 shrink-0 flex-col items-center justify-center" aria-hidden="true">
                    {showGap ? (
                      <span className="rounded-full border border-line bg-white px-1.5 text-[10px] font-medium text-muted" title={`${hidden} more steps in "All steps"`}>
                        +{hidden}
                      </span>
                    ) : (
                      <svg viewBox="0 0 24 12" className="h-3 w-5 text-line-strong">
                        <path d="M0 6h20M15 1.5L20 6l-5 4.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    )}
                  </div>
                )}
                <button
                  type="button"
                  onClick={() => onSelect(first.step)}
                  aria-pressed={isSel}
                  title={`${techniqueTooltip(first)}\n${tacticTooltip(first.tactic)}${n.steps.length > 1 ? `\n${n.steps.length} steps grouped` : ''}`}
                  className={`focus-ring group flex min-w-[104px] flex-1 flex-col items-start gap-3 rounded-2xl border p-4 text-left short:gap-2 short:p-3 ${
                    isSel ? 'border-brand bg-accent-tint shadow-card' : 'border-line bg-white hover:border-line-strong hover:shadow-lift'
                  }`}
                >
                  <span className="flex w-full items-center gap-2">
                    <span className={`flex h-7 w-7 items-center justify-center rounded-full font-mono text-[13px] font-semibold ${isSel ? 'bg-brand text-ink' : 'bg-ink text-white'}`}>{i + 1}</span>
                    <span className={`ml-auto flex h-9 w-9 items-center justify-center rounded-xl ${isEntry ? 'bg-high-bg text-high-ink' : 'bg-subtle text-ink-2'} border border-line`}>
                      <TacticIcon tactic={first.tactic} />
                    </span>
                  </span>
                  <span className="text-[15px] leading-snug font-semibold text-ink @max-4xl:text-[14px]">{stepPlain(first).short}</span>
                  <span className="mt-auto flex w-full min-w-0 items-center gap-1 text-[12px] text-muted">
                    <span className="truncate font-mono" title={n.host ?? undefined}>
                      {n.host ?? 'unknown host'}
                    </span>
                    {isFirewall(n.host) && <span className="shrink-0 text-high-ink">(firewall)</span>}
                  </span>
                  {isEntry && <span className="-mt-1 text-[11px] font-semibold tracking-[0.08em] text-high-ink uppercase short:hidden">Entry point</span>}
                </button>
              </li>
            )
          })}
        </ol>
      </section>

      {/* Reach next */}
      <section aria-labelledby="ov-reach" className="rounded-2xl border border-line bg-white px-6 py-5">
        <div className="flex items-baseline gap-3">
          <h3 id="ov-reach" className="headline text-[16px]">
            What the attacker can reach next
          </h3>
          {incident.reach_next.length > 0 && (
            <button type="button" onClick={() => onOpenTab('reach')} className="focus-ring ml-auto rounded-full px-2 text-[13px] font-medium text-accent hover:underline">
              See why →
            </button>
          )}
        </div>
        {reachShown.length === 0 ? (
          <p className="mt-2 text-[14px] text-muted">No further machines are reachable from what was compromised.</p>
        ) : (
          <ul className="mt-3 flex flex-wrap gap-3">
            {reachShown.map((r) => (
              <li
                key={`${r.host}-${r.hops}`}
                className={`flex items-center gap-3 rounded-xl border px-4 py-3 ${r.crown_jewel ? 'border-crit/30 bg-crit-bg' : 'border-line bg-subtle'}`}
                title={`${r.hops} hop${r.hops === 1 ? '' : 's'} away${r.via_user ? ` using ${r.via_user}` : ''}${r.touched ? ' (already touched)' : ''}`}
              >
                <span className="font-mono text-[14px] font-semibold text-ink">{r.host}</span>
                {r.crown_jewel && (
                  <span className="rounded-full bg-crit px-2 py-0.5 text-[11px] font-semibold tracking-[0.06em] text-white uppercase" title="Crown jewel: a high-value system">
                    {r.crown_jewel}
                  </span>
                )}
                <span className="text-[12px] text-muted">
                  {r.hops} hop{r.hops === 1 ? '' : 's'}
                  {r.via_user ? ` · via ${r.via_user}` : ''}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
