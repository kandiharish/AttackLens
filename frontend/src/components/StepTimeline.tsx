import { isFirewall } from '../lib/entity'
import { confidenceColor, fmtTs, truncate } from '../lib/format'
import type { PathEdge, Step } from '../types'

const EVIDENCE_LINES = 3

interface Props {
  title: string
  steps: Step[]
  edges: PathEdge[]
  entryStep: number | null
  highlighted: number | null
  flashKey: number
  onHover: (step: number | null) => void
}

function findLink(edges: PathEdge[], from: Step | undefined, to: Step): PathEdge | undefined {
  return (from && edges.find((e) => e.from === from.episode_id && e.to === to.episode_id)) || edges.find((e) => e.to === to.episode_id)
}

export function StepTimeline({ title, steps, edges, entryStep, highlighted, flashKey, onHover }: Props) {
  const ordered = [...steps].sort((a, b) => a.step - b.step || a.ts.localeCompare(b.ts))
  return (
    <section aria-label={title}>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</h3>
      <ol className="relative space-y-0">
        {ordered.map((s, i) => {
          const prev = i > 0 ? ordered[i - 1] : undefined
          const link = i > 0 ? findLink(edges, prev, s) : undefined
          return (
            <li key={`${s.episode_id}-${s.step}`}>
              {i > 0 && <WhyLinked link={link} />}
              <StepCard
                step={s}
                isEntry={entryStep === s.step}
                highlighted={highlighted === s.step}
                flashKey={highlighted === s.step ? flashKey : 0}
                onHover={onHover}
              />
            </li>
          )
        })}
      </ol>
    </section>
  )
}

function WhyLinked({ link }: { link: PathEdge | undefined }) {
  return (
    <div className="ml-5 flex items-center gap-2 border-l-2 border-dashed border-slate-700 py-1.5 pl-4 text-[11px]">
      {link ? (
        <>
          <span className="rounded bg-slate-800 px-1 font-mono text-[10px] text-violet-300 ring-1 ring-violet-500/40" title={`link rule ${link.rule}, weight ${link.weight}`}>
            {link.rule} · {link.weight.toFixed(2)}
          </span>
          <span className="text-slate-400">
            <span className="text-slate-500">why linked: </span>
            {truncate(link.why_linked)}
          </span>
        </>
      ) : (
        <span className="text-slate-600">no link reason recorded</span>
      )}
    </div>
  )
}

function StepCard({
  step: s,
  isEntry,
  highlighted,
  flashKey,
  onHover,
}: {
  step: Step
  isEntry: boolean
  highlighted: boolean
  flashKey: number
  onHover: (step: number | null) => void
}) {
  const technique = s.sub_technique_id ?? s.technique_id
  const extra = s.evidence.length - EVIDENCE_LINES
  return (
    <article
      id={`step-${s.step}`}
      key={flashKey}
      onMouseEnter={() => onHover(s.step)}
      onMouseLeave={() => onHover(null)}
      className={`scroll-mt-4 rounded-md border bg-slate-900 p-2.5 ${highlighted ? 'step-flash border-sky-500' : 'border-slate-800'}`}
    >
      <header className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-700 font-mono text-xs font-bold text-slate-100" aria-label={`Step ${s.step + 1}`}>
          {s.step + 1}
        </span>
        <time dateTime={s.ts} className="font-mono text-xs text-slate-400">
          {fmtTs(s.ts)}Z
        </time>
        <span className="rounded bg-sky-500/15 px-1.5 py-0.5 font-mono text-xs font-semibold text-sky-200 ring-1 ring-sky-500/40" title={`${technique}${s.technique_name ? ` ${s.technique_name}` : ''}`}>
          {technique}
          {s.technique_name && <span className="ml-1 font-sans font-medium text-sky-100">{s.technique_name}</span>}
        </span>
        <span className="rounded bg-rose-500/15 px-1.5 py-0.5 text-[11px] text-rose-200 ring-1 ring-rose-500/30">{s.tactic}</span>
        {isEntry && <span className="rounded bg-amber-400 px-1.5 py-0.5 text-[10px] font-bold uppercase text-slate-950">entry point</span>}
        <span className="ml-auto flex items-center gap-1.5 text-[11px] text-slate-400" title={`confidence ${s.confidence}, severity ${s.severity}`}>
          conf
          <span className="h-1.5 w-16 rounded bg-slate-800" role="meter" aria-valuenow={s.confidence} aria-valuemin={0} aria-valuemax={100} aria-label="confidence">
            <span className={`block h-1.5 rounded ${confidenceColor(s.confidence)}`} style={{ width: `${Math.max(0, Math.min(100, s.confidence))}%` }} />
          </span>
          <span className="w-6 font-mono tabular-nums text-slate-300">{s.confidence}</span>
        </span>
      </header>

      <dl className="mt-1.5 flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-[11px]">
        <Field k="host" v={s.host} />
        <Field k="user" v={s.user} />
        <Field k="src" v={s.src_ip} />
        <Field k="dst" v={s.dst_ip} />
        <Field k="merged" v={`${s.merged_alert_count.toLocaleString('en-US')} alert${s.merged_alert_count === 1 ? '' : 's'}`} />
        {s.rule_id && <Field k="rule" v={s.rule_id} />}
      </dl>

      {s.evidence.length > 0 && (
        <ul className="mt-1.5 space-y-0.5" aria-label="Evidence">
          {s.evidence.slice(0, EVIDENCE_LINES).map((line, i) => (
            // Log-derived text: rendered as a React text node (auto-escaped), never as HTML.
            <li key={i} className="whitespace-pre-wrap break-all rounded bg-slate-950 px-1.5 py-0.5 font-mono text-[11px] leading-snug text-slate-300 ring-1 ring-slate-800">
              {truncate(line)}
            </li>
          ))}
          {extra > 0 && <li className="text-[10px] text-slate-500">+{extra} more evidence line{extra === 1 ? '' : 's'}</li>}
        </ul>
      )}
    </article>
  )
}

function Field({ k, v }: { k: string; v: string | null }) {
  if (v === null || v === '') return null
  return (
    <div className="flex items-center gap-1">
      <dt className="text-slate-500">{k}</dt>
      <dd className="text-slate-200">
        {v}
        {k === 'host' && isFirewall(v) && <FirewallTag />}
      </dd>
    </div>
  )
}

export function FirewallTag() {
  return (
    <span className="ml-1 rounded bg-orange-900/60 px-1 py-px font-sans text-[9px] font-semibold uppercase text-orange-200 ring-1 ring-orange-500/50" title="Firewall device (devname): the logging device, not the victim endpoint">
      firewall
    </span>
  )
}
