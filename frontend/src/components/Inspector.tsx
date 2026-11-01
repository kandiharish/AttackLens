import { fmtSpan, fmtTs, truncate } from '../lib/format'
import { plainEntities, stepPlain } from '../lib/plain'
import { allSteps, edgesIn, edgesOut, sortReach, stepByEpisode, techniqueOf } from '../lib/incident'
import type { Incident, PathEdge, Step } from '../types'
import { SiemPivotMenu, SiemTag } from './SiemPivots'
import { Button, EntityChip, TacticTag, TechniqueBadge } from './ui'

interface Props {
  incident: Incident
  selected: number | null
  onSelect: (step: number | null) => void
  onClose: () => void
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-b border-line px-5 py-4 last:border-b-0">
      <h4 className="section-label mb-2.5">{title}</h4>
      {children}
    </section>
  )
}

export function Inspector({ incident, selected, onSelect, onClose }: Props) {
  const step = selected === null ? undefined : allSteps(incident).find((s) => s.step === selected)
  return (
    <aside aria-label="Inspector" className="card flex h-full min-h-0 w-[340px] shrink-0 flex-col overflow-hidden">
      <div className="flex shrink-0 items-center gap-2 border-b border-line px-5 py-3.5">
        <div className="min-w-0">
          <div className="section-label">Raw details</div>
          <h3 className="headline mt-0.5 truncate text-[16px]">{step ? `Step ${step.step + 1} · ${stepPlain(step).short}` : 'Incident summary'}</h3>
        </div>
        <span className="ml-auto flex shrink-0 items-center gap-1">
          {step && (
            <Button size="sm" variant="ghost" onClick={() => onSelect(null)} title="Show the incident summary instead">
              Clear
            </Button>
          )}
          <button type="button" onClick={onClose} title="Close details" aria-label="Close details" className="focus-ring flex h-8 w-8 items-center justify-center rounded-full text-ink-2 hover:bg-unobs hover:text-ink">
            <svg viewBox="0 0 12 12" className="h-3 w-3" aria-hidden="true">
              <path d="M2 2l8 8M10 2l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        </span>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">{step ? <StepDetails incident={incident} step={step} onSelect={onSelect} /> : <Summary incident={incident} />}</div>
    </aside>
  )
}

function StepDetails({ incident, step: s, onSelect }: { incident: Incident; step: Step; onSelect: (n: number) => void }) {
  const byEp = stepByEpisode(incident)
  const tech = techniqueOf(s)
  const parent = s.technique_id
  return (
    <>
      <Section title="Technique">
        <TechniqueBadge id={tech} name={s.technique_name} />
        <p className="mt-2 text-[12px] text-ink-2">
          <span className="text-accent underline decoration-accent/40 underline-offset-2" title="Reference label only (offline; no network link)">
            attack.mitre.org/techniques/{parent}
            {s.sub_technique_id && s.sub_technique_id.includes('.') ? `/${s.sub_technique_id.split('.')[1]}` : ''}
          </span>
        </p>
        <dl className="mt-3 grid grid-cols-[88px_1fr] items-center gap-x-3 gap-y-2 text-[13px]">
          <dt className="text-muted">Tactic</dt>
          <dd>
            <TacticTag tactic={s.tactic} />
          </dd>
          <dt className="text-muted">Time</dt>
          <dd className="font-mono text-ink">{fmtTs(s.ts)}Z</dd>
          <dt className="text-muted">Rule</dt>
          <dd className="font-mono break-all text-ink">
            {s.rule_id ?? '—'}
            {s.rule_id?.startsWith('siem:') && (
              <span className="ml-1 font-sans">
                <SiemTag ruleId={s.rule_id} />
              </span>
            )}
          </dd>
          <dt className="text-muted">Confidence</dt>
          <dd className="tabular-nums text-ink">
            {s.confidence}% <span className="text-muted">· severity {s.severity}</span>
          </dd>
          <dt className="text-muted">Merged</dt>
          <dd className="tabular-nums text-ink">
            {s.merged_alert_count.toLocaleString('en-US')} alert{s.merged_alert_count === 1 ? '' : 's'}
          </dd>
          <dt className="text-muted">Episode</dt>
          <dd className="font-mono text-ink">{s.episode_id}</dd>
        </dl>
      </Section>
      <Section title="Entities">
        <div className="flex flex-col items-stretch gap-1.5">
          <EntityChip kind="host" value={s.host} />
          <EntityChip kind="user" value={s.user} />
          <EntityChip kind="src" value={s.src_ip} />
          <EntityChip kind="dst" value={s.dst_ip} />
          {!s.host && !s.user && !s.src_ip && !s.dst_ip && <span className="text-[12px] text-muted">No entities recorded.</span>}
        </div>
      </Section>
      <Section title="Pivot to SIEM">
        <SiemPivotMenu key={`${s.episode_id}-${s.step}`} step={s} variant="inline" />
      </Section>
      <Section title={`Evidence (${s.evidence.length})`}>
        {s.evidence.length === 0 ? (
          <p className="text-[12px] text-muted">No evidence lines.</p>
        ) : (
          <ul className="space-y-2">
            {s.evidence.map((line, i) => (
              // Log-derived text: React text node only (escaped), never HTML.
              <li key={i} className="rounded-lg border border-line bg-subtle px-3 py-2 font-mono text-[11.5px] leading-relaxed break-all whitespace-pre-wrap text-ink">
                {truncate(line)}
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title="Why linked">
        <LinkList label="From" edges={edgesIn(incident, s)} other={(e) => byEp.get(e.from)} onSelect={onSelect} />
        <LinkList label="To" edges={edgesOut(incident, s)} other={(e) => byEp.get(e.to)} onSelect={onSelect} />
      </Section>
    </>
  )
}

function LinkList({ label, edges, other, onSelect }: { label: string; edges: PathEdge[]; other: (e: PathEdge) => Step | undefined; onSelect: (n: number) => void }) {
  if (edges.length === 0) return <p className="mb-1 text-[12px] text-muted">{label}: none</p>
  return (
    <ul className="mb-2 space-y-2.5">
      {edges.map((e) => {
        const o = other(e)
        return (
          <li key={`${e.from}-${e.to}`} className="text-[13px]">
            <span className="text-muted">{label} </span>
            {o ? (
              <button type="button" onClick={() => onSelect(o.step)} className="focus-ring rounded-sm font-semibold text-accent hover:underline">
                step {o.step + 1}
              </button>
            ) : (
              <span className="font-mono">{label === 'From' ? e.from : e.to}</span>
            )}
            <span className="ml-1.5 rounded-full border border-line bg-subtle px-2 font-mono text-[11px] text-ink-2" title={`link rule, strength ${e.weight}`}>
              {e.rule}
            </span>
            <p className="mt-1 text-ink-2 italic">{truncate(e.why_linked)}</p>
          </li>
        )
      })}
    </ul>
  )
}

function Summary({ incident }: { incident: Incident }) {
  const reach = sortReach(incident.reach_next)
  const untouched = reach.filter((r) => !r.touched)
  const text = incident.narrative.text
  return (
    <>
      <Section title="Entry point">
        <p className="text-[14px] leading-relaxed text-ink">{plainEntities(incident.entry_point.summary)}</p>
      </Section>
      <Section title="At a glance">
        <dl className="grid grid-cols-[96px_1fr] gap-x-3 gap-y-2 text-[13px]">
          <dt className="text-muted">Time span</dt>
          <dd className="text-ink">{fmtSpan(incident.first_ts, incident.last_ts)}</dd>
          <dt className="text-muted">Steps</dt>
          <dd className="tabular-nums text-ink">
            {incident.backbone.length}
            {incident.branches.length > 0 && ` + ${incident.branches.flat().length} in ${incident.branches.length} branch${incident.branches.length === 1 ? '' : 'es'}`}
          </dd>
          <dt className="text-muted">Tactics</dt>
          <dd className="tabular-nums text-ink">
            {incident.tactics.length} observed · {incident.gaps.length} gaps
          </dd>
          <dt className="text-muted">Reach next</dt>
          <dd className="tabular-nums text-ink">
            {reach.length} host{reach.length === 1 ? '' : 's'} ({untouched.length} untouched)
          </dd>
        </dl>
        {untouched.length > 0 && (
          <ul className="mt-3 space-y-1.5">
            {untouched.slice(0, 4).map((r) => (
              <li key={r.host} className="flex items-center gap-2 text-[13px]">
                <span className="font-mono text-ink">{r.host}</span>
                <span className="text-muted">
                  {r.hops} hop{r.hops === 1 ? '' : 's'}
                </span>
                {r.crown_jewel && <span className="rounded-full border border-crit/40 bg-crit-bg px-2 text-[10px] leading-[18px] font-semibold uppercase text-crit-ink">{r.crown_jewel}</span>}
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title={`Narrative · ${incident.narrative.source === 'llm' ? 'LLM' : 'Template'}`}>
        <p className="text-[13px] leading-relaxed text-ink-2">{text.length > 420 ? `${text.slice(0, 419)}…` : text}</p>
      </Section>
      <p className="px-5 py-4 text-[12px] text-muted">Click any step to see its raw log lines here.</p>
    </>
  )
}
