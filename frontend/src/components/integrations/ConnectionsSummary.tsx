// Inline summary strip for the Connections page. Derived ONLY from the same per-id states the tiles show
// (GET /api/integrations/{id}), so the strip and the tiles can never disagree. Every number comes from the API.
import { fmtTs } from '../../lib/format'
import type { IntegrationCatalogEntry, IntegrationState } from '../../types_integrations'

interface Props {
  entries: IntegrationCatalogEntry[]
  states: Record<string, IntegrationState | null | undefined>
  checkedAt: string | null
  onJump: (id: string) => void
}

const fmtN = (v: number | null) => (v === null ? '—' : v.toLocaleString('en-US'))

/** Sum of numeric values; null when none of them is a number (shown as "—", never as a made-up 0). */
function sum(vals: (number | null | undefined)[]): number | null {
  const nums = vals.filter((v): v is number => typeof v === 'number' && Number.isFinite(v))
  return nums.length ? nums.reduce((a, b) => a + b, 0) : null
}

function latest(vals: (string | null | undefined)[]): string | null {
  let best: string | null = null
  let bestMs = -Infinity
  for (const v of vals) {
    const ms = v ? new Date(v).getTime() : NaN
    if (Number.isFinite(ms) && ms > bestMs) {
      best = v ?? null
      bestMs = ms
    }
  }
  return best
}

function Stat({ label, value, tone = '' }: { label: string; value: string; tone?: string }) {
  return (
    <div className="min-w-0">
      <dt className="section-label !text-[10px]">{label}</dt>
      <dd className={`headline text-[18px] tabular-nums ${tone}`}>{value}</dd>
    </div>
  )
}

export function ConnectionsSummary({ entries, states, checkedAt, onJump }: Props) {
  const loaded = entries.filter((e) => states[e.id] !== undefined)
  const conf = loaded.filter((e) => states[e.id]?.configured)
  const sources = conf.filter((e) => e.kind !== 'sink')
  const sinks = conf.filter((e) => e.kind === 'sink')
  const connected = conf.filter((e) => states[e.id]?.running)
  const pulling = sources.filter((e) => states[e.id]?.running)
  const errored = conf.filter((e) => states[e.id]?.status?.last_error)
  const st = (e: IntegrationCatalogEntry) => states[e.id]?.status
  const pulled = sum(sources.map((e) => st(e)?.pulled))
  const written = sum(sources.map((e) => st(e)?.written))
  const failed = sum(sources.map((e) => st(e)?.failed))
  const sent = sum(sinks.map((e) => st(e)?.written))
  const sendFailed = sum(sinks.map((e) => st(e)?.failed))
  const lastPull = latest(sources.map((e) => st(e)?.last_pull))
  const lastPush = latest(sinks.map((e) => st(e)?.last_pull))
  const pending = loaded.length < entries.length

  return (
    <section className="card px-5 py-4 sm:px-6" aria-labelledby="conn-summary-title" aria-live="polite">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h3 id="conn-summary-title" className="section-label">
          Summary
        </h3>
        <span className="text-[12px] text-muted" title="Counts are the totals each connection reports (GET /api/integrations/{id})">
          {pending ? 'checking…' : checkedAt ? `checked ${fmtTs(checkedAt).slice(11)} UTC` : ''}
        </span>
      </div>
      <dl className="mt-2 grid grid-cols-2 gap-x-5 gap-y-3 sm:grid-cols-4 lg:grid-cols-7">
        <Stat label="Connected" value={`${connected.length} / ${entries.length}`} />
        <Stat label="Pulling" value={String(pulling.length)} />
        <Stat label="With errors" value={String(errored.length)} tone={errored.length ? 'text-crit-ink' : ''} />
        <Stat label="Pulled" value={fmtN(pulled)} />
        <Stat label="Written" value={fmtN(written)} />
        <Stat label="Failed" value={fmtN(failed)} tone={(failed ?? 0) > 0 ? 'text-crit-ink' : ''} />
        <div className="min-w-0">
          <dt className="section-label !text-[10px]">Last pull</dt>
          <dd className="text-[13px] font-medium text-ink tabular-nums">{lastPull ? `${fmtTs(lastPull)} UTC` : 'never'}</dd>
        </div>
      </dl>
      {sinks.length > 0 && (
        <p className="mt-3 text-[12px] text-ink-2 tabular-nums">
          Incidents sent: {fmtN(sent)} · failed {fmtN(sendFailed)} · last push {lastPush ? `${fmtTs(lastPush)} UTC` : 'never'}
        </p>
      )}
      {errored.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-3">
          <span className="text-[12px] font-medium text-crit-ink">Needs attention:</span>
          {errored.map((e) => (
            <button
              key={e.id}
              type="button"
              onClick={() => onJump(e.id)}
              title={states[e.id]?.status?.last_error ?? undefined}
              className="focus-ring inline-flex h-7 items-center gap-1.5 rounded-full border border-crit/40 bg-crit-bg px-3 text-[12px] font-medium text-crit-ink hover:border-crit"
            >
              <span className="h-1.5 w-1.5 rounded-full bg-crit" aria-hidden="true" />
              {e.name}
              <span className="sr-only">: show the error</span>
            </button>
          ))}
        </div>
      )}
    </section>
  )
}
