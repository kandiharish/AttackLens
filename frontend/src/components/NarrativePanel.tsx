import type { Narrative } from '../types'

export function NarrativePanel({ narrative }: { narrative: Narrative }) {
  const llm = narrative.source === 'llm'
  return (
    <section aria-label="Narrative" className="rounded-md border border-slate-800 bg-slate-900 p-3">
      <div className="mb-1.5 flex items-center gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">What happened</h3>
        <span
          className={`rounded px-1.5 py-px text-[10px] font-bold uppercase ${llm ? 'bg-violet-500/20 text-violet-200 ring-1 ring-violet-500/50' : 'bg-slate-700 text-slate-200'}`}
          title={llm ? 'Written by the LLM from placeholders and enums only' : 'Deterministic template'}
        >
          {llm ? 'LLM' : 'template'}
        </span>
      </div>
      {/* Plain text node; never HTML. */}
      <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-200">{narrative.text}</p>
    </section>
  )
}
