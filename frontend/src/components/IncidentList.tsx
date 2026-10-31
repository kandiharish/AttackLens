import { tacticIndex } from '../lib/attack'
import { isFirewall } from '../lib/entity'
import { fmtSpan, riskStyle } from '../lib/format'
import type { IncidentSummary } from '../types'

const MAX_HOSTS = 6

interface Props {
  incidents: IncidentSummary[] | null
  error: string | null
  selectedId: string | null
  onSelect: (id: string) => void
  onRetry: () => void
}

export function IncidentList({ incidents, error, selectedId, onSelect, onRetry }: Props) {
  return (
    <nav aria-label="Incidents" className="flex h-full flex-col">
      <div className="flex items-baseline justify-between border-b border-slate-800 px-3 py-2">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Incidents</h2>
        <span className="text-[11px] text-slate-500">{incidents ? `${incidents.length} · by risk` : ''}</span>
      </div>

      {error && (
        <div role="alert" className="m-3 rounded border border-rose-800 bg-rose-950/50 p-2 text-xs text-rose-200">
          <p>{error}</p>
          <button type="button" onClick={onRetry} className="mt-2 rounded bg-rose-800 px-2 py-0.5 text-rose-50 hover:bg-rose-700">
            Retry
          </button>
        </div>
      )}
      {!error && incidents === null && <p className="p-3 text-xs text-slate-500">Loading…</p>}
      {incidents && incidents.length === 0 && <p className="p-3 text-xs text-slate-500">No incidents in this run.</p>}

      <ul className="flex-1 space-y-1 overflow-y-auto p-2">
        {incidents?.map((inc) => {
          const rs = riskStyle(inc.risk)
          const active = inc.id === selectedId
          const tactics = [...inc.tactics].sort((a, b) => tacticIndex(a) - tacticIndex(b))
          return (
            <li key={inc.id}>
              <button
                type="button"
                onClick={() => onSelect(inc.id)}
                aria-current={active ? 'true' : undefined}
                className={`w-full rounded-md border p-2 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
                  active ? 'border-sky-500/70 bg-slate-800' : 'border-slate-800 bg-slate-900 hover:border-slate-600'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`rounded px-1.5 py-0.5 font-mono text-xs font-bold tabular-nums ${rs.badge}`} title={`Risk ${inc.risk} (${rs.label})`}>
                    {inc.risk}
                  </span>
                  <span className="truncate font-mono text-[11px] text-slate-400">{inc.id}</span>
                </div>
                <p className="mt-1 text-xs font-medium text-slate-200">
                  {inc.merged_alert_count.toLocaleString('en-US')} alerts → 1 incident
                  <span className="text-slate-500"> · {inc.episode_count} episodes</span>
                </p>
                <p className="mt-0.5 text-[11px] text-slate-500">{fmtSpan(inc.first_ts, inc.last_ts)}</p>
                <p className="mt-1 line-clamp-2 text-[11px] text-slate-400">{inc.entry_summary}</p>
                <div className="mt-1 flex flex-wrap gap-1">
                  {tactics.map((t) => (
                    <span key={t} className="rounded bg-slate-800 px-1 py-px text-[10px] text-sky-200 ring-1 ring-slate-700">
                      {t}
                    </span>
                  ))}
                </div>
                {inc.hosts.length > 0 && (
                  <p className="mt-1 line-clamp-2 font-mono text-[10px] text-slate-500" title={inc.hosts.join(', ')}>
                    {inc.hosts.slice(0, MAX_HOSTS).map((h, i) => (
                      <span key={h}>
                        {i > 0 && ' · '}
                        <span className={isFirewall(h) ? 'text-orange-300' : undefined}>{h}</span>
                        {isFirewall(h) && <span className="text-orange-400"> (fw)</span>}
                      </span>
                    ))}
                    {inc.hosts.length > MAX_HOSTS && <span> · +{inc.hosts.length - MAX_HOSTS} more</span>}
                  </p>
                )}
              </button>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
