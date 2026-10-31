import { truncate } from '../lib/format'
import type { ReachNext as ReachNextRow } from '../types'

export function ReachNext({ rows }: { rows: ReachNextRow[] }) {
  // Untouched targets first (that is where the attacker goes next), then by hop distance, crown jewels first.
  const ordered = [...rows].sort(
    (a, b) =>
      Number(a.touched) - Number(b.touched) ||
      a.hops - b.hops ||
      Number(b.crown_jewel !== null) - Number(a.crown_jewel !== null) ||
      a.host.localeCompare(b.host),
  )
  return (
    <section aria-label="Reach next">
      <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400">
        Reach next <span className="font-normal normal-case text-slate-500">(where the attacker can go from here)</span>
      </h3>
      {ordered.length === 0 ? (
        <p className="text-xs text-slate-500">No further reachable hosts found in the data.</p>
      ) : (
        <ul className="grid gap-1.5 sm:grid-cols-2">
          {ordered.map((r) => (
            <li
              key={`${r.host}-${r.hops}-${r.via_user ?? ''}`}
              className={`rounded-md border p-2 ${r.touched ? 'border-slate-800 bg-slate-900/50 opacity-70' : 'border-amber-500/40 bg-amber-500/5'}`}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-semibold text-slate-100">{r.host}</span>
                <span className="rounded bg-slate-800 px-1.5 py-px font-mono text-[10px] text-slate-300">
                  {r.hops} hop{r.hops === 1 ? '' : 's'}
                </span>
                {r.crown_jewel && (
                  <span className="rounded bg-yellow-400 px-1.5 py-px text-[10px] font-bold uppercase text-slate-950" title="crown jewel">
                    crown jewel · {r.crown_jewel}
                  </span>
                )}
                <span className={`ml-auto text-[10px] uppercase ${r.touched ? 'text-slate-500' : 'text-amber-300'}`}>{r.touched ? 'already touched' : 'untouched'}</span>
              </div>
              {r.via_user && (
                <p className="mt-0.5 font-mono text-[11px] text-slate-400">
                  via <span className="text-violet-300">{r.via_user}</span>
                </p>
              )}
              <p className="mt-1 whitespace-pre-wrap break-all rounded bg-slate-950 px-1.5 py-0.5 font-mono text-[11px] text-slate-300 ring-1 ring-slate-800">
                {truncate(r.evidence)}
              </p>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
