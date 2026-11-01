import { isFirewall } from '../lib/entity'
import { fmtTime, truncate } from '../lib/format'
import { allSteps, techniqueOf } from '../lib/incident'
import type { Incident } from '../types'
import { EmptyState } from './ui'

interface Props {
  incident: Incident
  selected: number | null
  onSelect: (step: number) => void
}

export function EvidenceTab({ incident, selected, onSelect }: Props) {
  const rows = allSteps(incident).flatMap((s) => s.evidence.map((line, i) => ({ s, line, i })))
  if (rows.length === 0) return <EmptyState title="No evidence lines">The pipeline did not attach raw evidence to this incident.</EmptyState>
  const th = 'sticky top-0 z-10 border-b border-line bg-subtle px-4 py-3 text-left section-label'
  return (
    <div className="px-6 py-5">
      <div className="overflow-hidden rounded-2xl border border-line bg-panel">
        <table className="w-full table-fixed border-collapse text-[13px]">
          <caption className="sr-only">Evidence lines per step (raw log text, clipped to 300 characters)</caption>
          <colgroup>
            <col className="w-12" />
            <col className="w-[72px]" />
            <col className="w-36" />
            <col className="w-24" />
            <col />
          </colgroup>
          <thead>
            <tr>
              <th className={th}>Step</th>
              <th className={th}>Time</th>
              <th className={th}>Host</th>
              <th className={th}>Technique</th>
              <th className={th}>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ s, line, i }) => {
              const sel = s.step === selected
              return (
                <tr
                  key={`${s.episode_id}-${i}`}
                  onClick={() => onSelect(s.step)}
                  className={`cursor-pointer border-b border-line align-top last:border-b-0 ${sel ? 'bg-accent-tint' : 'odd:bg-white even:bg-subtle hover:bg-accent-tint/60'}`}
                >
                  <td className="px-4 py-3 font-semibold tabular-nums text-ink">{i === 0 ? s.step + 1 : ''}</td>
                  <td className="px-4 py-3 font-mono text-ink-2">{i === 0 ? fmtTime(s.ts) : ''}</td>
                  <td className="truncate px-4 py-3 font-mono text-ink" title={s.host ?? ''}>
                    {i === 0 ? (s.host ?? '—') : ''}
                    {i === 0 && isFirewall(s.host) && <span className="text-high-ink"> (fw)</span>}
                  </td>
                  <td className="px-4 py-3 font-mono text-accent">{i === 0 ? techniqueOf(s) : ''}</td>
                  {/* Log-derived text: React text node only (escaped), never HTML. */}
                  <td className="px-4 py-3 font-mono text-[12px] leading-relaxed break-all whitespace-pre-wrap text-ink">{truncate(line)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
