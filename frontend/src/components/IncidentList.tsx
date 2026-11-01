import { useMemo, useRef, useState } from 'react'
import { fmtDay, fmtShortSpan, riskStyle } from '../lib/format'
import { summaryTitle } from '../lib/plain'
import type { IncidentSummary } from '../types'
import { EmptyState, ErrorNote, Spinner } from './ui'

type SortKey = 'risk' | 'time'

interface Props {
  incidents: IncidentSummary[] | null
  error: string | null
  selectedId: string | null
  onSelect: (id: string) => void
  onRetry: () => void
}

export function IncidentList({ incidents, error, selectedId, onSelect, onRetry }: Props) {
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState<SortKey>('risk')
  const listRef = useRef<HTMLUListElement>(null)

  const rows = useMemo(() => {
    if (!incidents) return null
    const q = query.trim().toLowerCase()
    const filtered = q
      ? incidents.filter((r) => [r.id, r.entry_summary, summaryTitle(r), ...r.hosts, ...r.tactics].some((s) => s.toLowerCase().includes(q)))
      : incidents
    return [...filtered].sort((a, b) => (sort === 'risk' ? b.risk - a.risk || b.last_ts.localeCompare(a.last_ts) : b.last_ts.localeCompare(a.last_ts) || b.risk - a.risk))
  }, [incidents, query, sort])

  // ↑/↓ moves the selection through the visible (filtered + sorted) rows.
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!rows || rows.length === 0 || (e.key !== 'ArrowDown' && e.key !== 'ArrowUp')) return
    e.preventDefault()
    const i = rows.findIndex((r) => r.id === selectedId)
    const next = e.key === 'ArrowDown' ? Math.min(rows.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1)
    const id = rows[next].id
    onSelect(id)
    requestAnimationFrame(() => listRef.current?.querySelector<HTMLElement>(`[data-id="${CSS.escape(id)}"]`)?.focus())
  }

  return (
    <nav aria-label="Incidents" className="card flex h-full min-h-0 flex-col overflow-hidden">
      <div className="space-y-3 border-b border-line px-5 pt-4 pb-4">
        <div className="flex items-baseline justify-between">
          <h2 className="headline text-[16px]">Incidents</h2>
          <span className="text-[12px] text-muted tabular-nums">{rows && incidents ? (rows.length === incidents.length ? `${incidents.length} found` : `${rows.length} of ${incidents.length}`) : ''}</span>
        </div>
        <div className="flex gap-2">
          <label className="relative min-w-0 flex-1">
            <span className="sr-only">Search incidents</span>
            <svg viewBox="0 0 16 16" className="pointer-events-none absolute top-1/2 left-3 h-3.5 w-3.5 -translate-y-1/2 text-muted" aria-hidden="true">
              <circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" strokeWidth="1.5" />
              <path d="M10.5 10.5L14 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search host, user…"
              className="focus-ring h-9 w-full rounded-full border border-line-strong bg-white pr-3 pl-8 text-[13px] text-ink placeholder:text-muted"
            />
          </label>
          <label className="shrink-0">
            <span className="sr-only">Sort by</span>
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as SortKey)}
              className="focus-ring h-9 rounded-full border border-line-strong bg-white px-3 text-[13px] text-ink"
              title="Sort incidents"
            >
              <option value="risk">Riskiest</option>
              <option value="time">Latest</option>
            </select>
          </label>
        </div>
      </div>

      {error && <ErrorNote onRetry={onRetry}>{error}</ErrorNote>}
      {!error && incidents === null && <Spinner label="Loading incidents…" />}
      {rows && rows.length === 0 && <EmptyState title={incidents && incidents.length ? 'No matches' : 'No incidents in this run'}>{query ? `Nothing matches “${query}”.` : undefined}</EmptyState>}

      <ul ref={listRef} className="min-h-0 flex-1 space-y-2 overflow-y-auto p-3" onKeyDown={onKeyDown} aria-label="Incident list (use arrow keys)">
        {rows?.map((inc) => {
          const active = inc.id === selectedId
          const rs = riskStyle(inc.risk)
          const title = summaryTitle(inc)
          return (
            <li key={inc.id}>
              <button
                type="button"
                data-id={inc.id}
                onClick={() => onSelect(inc.id)}
                aria-current={active ? 'true' : undefined}
                title={`${inc.id} · ${inc.entry_summary}`}
                className={`focus-ring relative flex w-full flex-col gap-2 overflow-hidden rounded-xl border py-3.5 pr-4 pl-5 text-left ${
                  active ? 'border-brand/60 bg-accent-tint shadow-card' : 'border-line bg-white hover:border-line-strong hover:shadow-card'
                }`}
              >
                <span className={`absolute inset-y-0 left-0 w-1 ${rs.bar}`} aria-hidden="true" />
                <span className="flex items-center gap-2">
                  <span className={`inline-flex h-6 items-center gap-1.5 rounded-full border px-2.5 text-[11px] font-semibold tracking-[0.06em] uppercase ${rs.pill}`}>
                    {rs.label}
                    <span className="font-mono tracking-normal tabular-nums">{inc.risk}</span>
                  </span>
                </span>
                <span className="line-clamp-2 text-[14px] leading-snug font-semibold text-ink">{title}</span>
                <span className="flex items-center gap-2 text-[12px] text-ink-2 tabular-nums">
                  <span>
                    <strong className="font-semibold text-ink">{inc.merged_alert_count.toLocaleString('en-US')}</strong> alerts → 1 incident
                  </span>
                  <span className="ml-auto text-muted" title={fmtShortSpan(inc.first_ts, inc.last_ts)}>
                    {fmtDay(inc.first_ts)}
                  </span>
                </span>
              </button>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
