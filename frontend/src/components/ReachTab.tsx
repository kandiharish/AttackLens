import { truncate } from '../lib/format'
import { sortReach } from '../lib/incident'
import type { ReachNext } from '../types'
import { EmptyState } from './ui'

export function ReachTab({ rows }: { rows: ReachNext[] }) {
  if (rows.length === 0) return <EmptyState title="No further reachable hosts">No allowed logons or flows from compromised entities were found in the data.</EmptyState>
  const th = 'sticky top-0 z-10 border-b border-line bg-subtle px-4 py-3 text-left section-label'
  return (
    <div className="px-6 py-5">
      <p className="mb-4 max-w-[75ch] text-[14px] text-ink-2">Where the attacker can go next from what is already compromised. Untouched targets are listed first.</p>
      <div className="overflow-hidden rounded-2xl border border-line bg-panel">
        <table className="w-full table-fixed border-collapse text-[13px]">
          <caption className="sr-only">Reach next</caption>
          <colgroup>
            <col className="w-36" />
            <col className="w-14" />
            <col className="w-32" />
            <col className="w-32" />
            <col className="w-24" />
            <col />
          </colgroup>
          <thead>
            <tr>
              <th className={th}>Host</th>
              <th className={th}>Hops</th>
              <th className={th}>Via user</th>
              <th className={th}>Crown jewel</th>
              <th className={th}>Status</th>
              <th className={th}>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {sortReach(rows).map((r) => (
              <tr key={`${r.host}-${r.hops}-${r.via_user ?? ''}`} className="border-b border-line align-top last:border-b-0 odd:bg-white even:bg-subtle hover:bg-accent-tint/60">
                <td className="truncate px-4 py-3 font-mono font-semibold text-ink" title={r.host}>
                  {r.host}
                </td>
                <td className="px-4 py-3 tabular-nums text-ink">{r.hops}</td>
                <td className="truncate px-4 py-3 font-mono text-ink-2">{r.via_user ?? '—'}</td>
                <td className="px-4 py-3">
                  {r.crown_jewel ? (
                    <span className="rounded-full border border-crit/40 bg-crit-bg px-2.5 text-[11px] leading-[20px] font-semibold uppercase tracking-wide text-crit-ink">{r.crown_jewel}</span>
                  ) : (
                    <span className="text-muted">—</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {r.touched ? (
                    <span className="text-muted">Touched</span>
                  ) : (
                    <span className="rounded-full border border-high/60 bg-high-bg px-2.5 text-[11px] leading-[20px] font-semibold text-high-ink">Untouched</span>
                  )}
                </td>
                <td className="px-4 py-3 font-mono break-all whitespace-pre-wrap text-ink">{truncate(r.evidence)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
