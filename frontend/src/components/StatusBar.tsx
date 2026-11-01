// Footer: one quiet line. Status dot + data set name, the served run's timing (from /api/metrics run_metrics), version.
import pkg from '../../package.json'
import { USE_MOCK } from '../api'
import { baseName } from '../lib/format'
import { fmtCount, fmtSeconds, readRunTiming } from '../lib/metrics'
import type { Metrics } from '../types'

interface Props {
  apiOk: boolean | null
  /** Served out dir (full path); the footer shows its last folder name. */
  dataDir: string | null
  metrics: Metrics | null
}

export function StatusBar({ apiOk, dataDir, metrics }: Props) {
  const api = USE_MOCK
    ? { dot: 'bg-med', text: 'Mock data' }
    : apiOk === null
      ? { dot: 'bg-line-strong', text: 'Connecting…' }
      : apiOk
        ? { dot: 'bg-brand', text: 'Connected' }
        : { dot: 'bg-crit', text: 'API offline' }
  const t = readRunTiming(metrics)
  const parts = [
    t.rows !== null ? `${fmtCount(t.rows)} events` : null,
    t.ingestS !== null ? `ingested in ${fmtSeconds(t.ingestS)}` : null,
    t.totalS !== null ? `analysed in ${fmtSeconds(t.totalS)}` : null,
  ].filter((x): x is string => x !== null)
  return (
    <footer className="mt-auto border-t border-line bg-subtle" aria-label="Status">
      <div className="mx-auto flex h-8 w-full max-w-[1760px] items-center gap-3 px-4 text-[12px] text-muted sm:px-6">
        <span className={`h-2 w-2 shrink-0 rounded-full ${api.dot}`} title={api.text} aria-hidden="true" />
        <span className="sr-only">{api.text}</span>
        <span className="max-w-[45%] shrink-0 truncate font-mono text-[11px] text-ink-2" title={dataDir ?? undefined}>
          {/* "src/mock (VITE_USE_MOCK=true)" -> "mock": drop a trailing note in brackets. */}
          {dataDir ? baseName(dataDir).replace(/\s*\(.*\)$/, '') || baseName(dataDir) : '—'}
        </span>
        {parts.length > 0 && (
          <span className="min-w-0 truncate tabular-nums" title="Served run: run_metrics.json (rows_in, ingest stage wall_s, total_wall_s)">
            {parts.join(' · ')}
          </span>
        )}
        <span className="ml-auto shrink-0 text-[11px]" title="Built for the Mitigata CyberForge hackathon">
          AttackLens v{pkg.version}
        </span>
      </div>
    </footer>
  )
}
