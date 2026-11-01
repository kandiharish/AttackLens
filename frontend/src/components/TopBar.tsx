// Header: brand, the three nav pills, the log-health badge of the served data and one API/live status dot.
// The advanced "analyse a server folder" form lives on the Add data page (AddDataPage.tsx).
import { USE_MOCK, type LiveStatus } from '../api'
import { fmtTime } from '../lib/format'
import type { IntegrityState } from '../lib/integrity'
import { IntegrityStatus } from './integrity/IntegrityStatus'

type NavKey = 'incidents' | 'add' | 'connections'

interface Props {
  view: NavKey
  onView: (v: NavKey) => void
  /** true = API answered, false = API unreachable, null = still connecting. */
  apiOk: boolean | null
  live: LiveStatus | null
  liveUpdatedAt: string | null
  /** Log health of the dataset the API serves now (GET /api/integrity). */
  integrity: IntegrityState
}

const NAV: { key: NavKey; label: string; hint: string }[] = [
  { key: 'incidents', label: 'Incidents', hint: 'Attack paths found in the current data' },
  { key: 'add', label: 'Add data', hint: 'Upload your own logs and analyse them' },
  { key: 'connections', label: 'Connections', hint: 'Connect a SIEM or cloud account, or send incidents out' },
]

export function TopBar({ view, onView, apiOk, live, liveUpdatedAt, integrity }: Props) {
  return (
    <header className="sticky top-0 z-40 shrink-0 border-b border-line/80 bg-subtle/90 backdrop-blur">
      <div className="mx-auto flex w-full max-w-[1760px] flex-wrap items-center gap-x-3 gap-y-2.5 px-4 py-3 sm:gap-x-6 sm:px-6 md:h-16 md:flex-nowrap md:py-0">
        <div className="order-1 flex shrink-0 items-center gap-3">
          <svg viewBox="0 0 32 32" className="h-8 w-8" aria-hidden="true">
            <rect width="32" height="32" rx="9" fill="#0A0A0A" />
            <circle cx="14" cy="14" r="6" fill="none" stroke="#04DB7F" strokeWidth="2.6" />
            <path d="M18.6 18.6l5.4 5.4" stroke="#04DB7F" strokeWidth="2.6" strokeLinecap="round" />
          </svg>
          <div className="headline text-[18px]">AttackLens</div>
        </div>
        <nav aria-label="Views" className="order-3 flex w-full min-w-0 shrink-0 gap-1 overflow-x-auto rounded-full border border-line bg-white p-1 md:order-2 md:w-auto">
          {NAV.map((n) => (
            <button
              key={n.key}
              type="button"
              onClick={() => onView(n.key)}
              aria-current={view === n.key ? 'page' : undefined}
              title={n.hint}
              className={`focus-ring flex h-8 shrink-0 items-center justify-center gap-1.5 rounded-full px-3.5 text-[13px] whitespace-nowrap max-md:flex-1 max-md:px-2.5 ${
                view === n.key ? 'bg-ink font-semibold text-white' : 'font-medium text-ink-2 hover:bg-unobs hover:text-ink'
              }`}
            >
              {n.key === 'add' && (
                <svg viewBox="0 0 12 12" className="h-3 w-3" aria-hidden="true">
                  <path d="M6 1.5v9M1.5 6h9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                </svg>
              )}
              {n.label}
            </button>
          ))}
        </nav>
        <div className="order-2 ml-auto flex items-center gap-2 md:order-3">
          <IntegrityStatus state={integrity} popup="load" compact />
          <StatusDot apiOk={apiOk} live={live} updatedAt={liveUpdatedAt} />
        </div>
      </div>
    </header>
  )
}

/** One dot: amber = mock data, red = API offline, grey = connecting, green = connected (pulses while live mode refreshes). */
function StatusDot({ apiOk, live, updatedAt }: { apiOk: boolean | null; live: LiveStatus | null; updatedAt: string | null }) {
  const liveOn = live?.enabled === true
  const s = USE_MOCK
    ? { dot: 'bg-med', text: 'Mock data (VITE_USE_MOCK=true): read from src/mock/*.json, no backend' }
    : apiOk === false
      ? { dot: 'bg-crit', text: 'API offline: start uvicorn on :8000' }
      : apiOk === null
        ? { dot: 'bg-line-strong', text: 'Connecting to the API…' }
        : liveOn
          ? { dot: 'animate-pulse bg-brand', text: `API connected · live mode on, list refreshes every 2 s${updatedAt ? ` (last ${fmtTime(updatedAt)} UTC)` : ''}` }
          : { dot: 'bg-brand', text: `API connected · live mode off${live === null ? ' (status unavailable)' : ''}` }
  return (
    <span
      role="status"
      tabIndex={0}
      title={s.text}
      aria-label={s.text}
      className="focus-ring inline-flex h-8 w-8 items-center justify-center rounded-full border border-line bg-white"
    >
      <span className={`h-2.5 w-2.5 rounded-full ${s.dot}`} aria-hidden="true" />
    </span>
  )
}
