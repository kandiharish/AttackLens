import { useEffect, useRef, useState } from 'react'
import { getRun, startRun, USE_MOCK, type LiveStatus, type RunStatus } from '../api'
import { fmtTime } from '../lib/format'
import { fmtCount, fmtPct, fmtRss, fmtSeconds, readIngest, readRunSummary, readScorecard } from '../lib/metrics'
import type { Metrics } from '../types'

interface Props {
  metrics: Metrics | null
  metricsError: string | null
  live: LiveStatus | null
  liveUpdatedAt: string | null
  onRunFinished: () => void
}

function Stat({ label, value, title, tone = 'text-slate-100' }: { label: string; value: string; title?: string; tone?: string }) {
  return (
    <div className="flex flex-col leading-tight" title={title}>
      <span className="text-[10px] uppercase tracking-wider text-slate-500">{label}</span>
      <span className={`font-mono text-sm font-semibold tabular-nums ${tone}`}>{value}</span>
    </div>
  )
}

export function Header({ metrics, metricsError, live, liveUpdatedAt, onRunFinished }: Props) {
  const sc = readScorecard(metrics)
  const run = readRunSummary(metrics)
  const ingest = readIngest(metrics)
  const dropPct = ingest && ingest.rowsIn > 0 ? (ingest.dropped / ingest.rowsIn) * 100 : null

  return (
    <header className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-slate-800 bg-slate-900/80 px-4 py-2">
      <div className="flex items-center gap-2">
        <svg viewBox="0 0 32 32" className="h-6 w-6" aria-hidden="true">
          <circle cx="14" cy="14" r="7" fill="none" stroke="#38bdf8" strokeWidth="3" />
          <path d="M19 19l7 7" stroke="#f43f5e" strokeWidth="3" strokeLinecap="round" />
        </svg>
        <h1 className="text-lg font-bold tracking-tight text-slate-50">AttackLens</h1>
        {USE_MOCK && (
          <span className="rounded border border-amber-500/60 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-amber-300">
            mock data
          </span>
        )}
      </div>

      <section aria-label="Evaluation scorecard" className="flex items-center gap-4 rounded-md border border-slate-800 bg-slate-950/60 px-3 py-1">
        <Stat label="Detection" value={fmtPct(sc.detection)} title="eval_scorecard: planted attacks detected" tone="text-emerald-300" />
        <Stat label="Labels" value={fmtPct(sc.labels)} title="eval_scorecard: ATT&CK labels correct" tone="text-emerald-300" />
        <Stat label="Rebuilt" value={fmtPct(sc.rebuilt)} title="eval_scorecard: attacks fully rebuilt in order" tone="text-sky-300" />
        <Stat
          label="False alarms"
          value={fmtPct(sc.faStrict)}
          title={`eval_scorecard: false_alarms_strict_pct (lenient ${fmtPct(sc.faLenient)})`}
          tone="text-rose-300"
        />
        <Stat label="Singleton recall" value={fmtPct(sc.singletonRecall)} title="eval_scorecard: singleton_recall_pct" tone="text-sky-300" />
      </section>

      <section aria-label="Run metrics" className="flex items-center gap-4">
        <Stat label="Peak RSS" value={fmtRss(run.peakRssMb)} title="run_metrics: peak resident memory" />
        <Stat
          label="Total time"
          value={fmtSeconds(run.totalWallS)}
          title={
            run.stages.length
              ? ['run_metrics.total_wall_s', ...run.stages.map((st) => `${st.name}: ${fmtSeconds(st.wall_s)} · ${fmtRss(st.peak_rss_mb)}`)].join('\n')
              : 'run_metrics.total_wall_s'
          }
        />
        <Stat
          label="Rows ingested"
          value={ingest ? fmtCount(ingest.rowsOk) : '—'}
          title={
            ingest
              ? `ingest_accounting: ${ingest.rowsIn.toLocaleString('en-US')} in, ${ingest.rowsOk.toLocaleString('en-US')} ok, ${ingest.dropped.toLocaleString('en-US')} dropped across ${ingest.sources} source types`
              : 'ingest_accounting.json not available'
          }
        />
        <Stat
          label="Dropped"
          value={dropPct === null ? '—' : `${dropPct.toFixed(dropPct < 0.01 && dropPct > 0 ? 4 : 2)} %`}
          tone={dropPct !== null && dropPct > 0.1 ? 'text-rose-300' : 'text-slate-100'}
          title="ingest_accounting: dropped / rows in"
        />
      </section>

      {metricsError && (
        <span role="alert" className="text-xs text-rose-300">
          metrics unavailable: {metricsError}
        </span>
      )}

      <div className="ml-auto flex items-center gap-3">
        <LiveBadge status={live} updatedAt={liveUpdatedAt} />
        <RunControl onFinished={onRunFinished} />
      </div>
    </header>
  )
}

function LiveBadge({ status, updatedAt }: { status: LiveStatus | null; updatedAt: string | null }) {
  const on = status?.enabled === true
  const label = status === null ? 'live: n/a' : on ? `live · ${updatedAt ? fmtTime(updatedAt) : 'waiting'}` : 'live: off'
  return (
    <span
      className={`flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] ${
        on ? 'border-emerald-500/60 text-emerald-300' : 'border-slate-700 text-slate-500'
      }`}
      title={
        status === null
          ? 'GET /api/live/status unavailable'
          : on
            ? 'Live mode: incident list refreshes every 2 s (time = last refresh, UTC)'
            : 'Live mode off: list is static'
      }
      aria-live="polite"
    >
      <span className={`h-2 w-2 rounded-full ${on ? 'animate-pulse bg-emerald-400' : 'bg-slate-600'}`} aria-hidden="true" />
      {label}
    </span>
  )
}

function RunControl({ onFinished }: { onFinished: () => void }) {
  const [open, setOpen] = useState(false)
  const [rawDir, setRawDir] = useState('data/raw/')
  const [gt, setGt] = useState('')
  const [run, setRun] = useState<RunStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const timer = useRef<number | null>(null)

  useEffect(() => () => {
    if (timer.current !== null) window.clearInterval(timer.current)
  }, [])


  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    try {
      const { run_id: id } = await startRun(rawDir.trim(), gt.trim() || undefined)
      setRun(null)
      if (timer.current !== null) window.clearInterval(timer.current)
      timer.current = window.setInterval(async () => {
        try {
          const s = await getRun(id)
          setRun(s)
          if (s.status !== 'running') {
            if (timer.current !== null) window.clearInterval(timer.current)
            timer.current = null
            if (s.status === 'succeeded') onFinished()
          }
        } catch (err) {
          setError(err instanceof Error ? err.message : String(err))
        }
      }, 1000)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="rounded border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-200 hover:bg-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
      >
        New run
      </button>
      {open && (
        <form
          onSubmit={submit}
          className="absolute right-0 z-20 mt-2 w-80 space-y-2 rounded-md border border-slate-700 bg-slate-900 p-3 text-xs shadow-xl"
        >
          <label className="block">
            <span className="text-slate-400">raw_dir</span>
            <input
              value={rawDir}
              onChange={(e) => setRawDir(e.target.value)}
              className="mt-0.5 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-slate-100"
              required
            />
          </label>
          <label className="block">
            <span className="text-slate-400">ground_truth (optional)</span>
            <input
              value={gt}
              onChange={(e) => setGt(e.target.value)}
              className="mt-0.5 w-full rounded border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-slate-100"
            />
          </label>
          <button type="submit" disabled={USE_MOCK} className="rounded bg-sky-600 px-3 py-1 font-semibold text-white hover:bg-sky-500 disabled:opacity-40">
            Start
          </button>
          {USE_MOCK && <p className="text-amber-300">Runs are disabled in mock mode.</p>}
          {run && (
            <div className="space-y-1 font-mono text-slate-300">
              <div>
                {run.status} · stage {run.stage ?? '—'} · {run.percent.toFixed(0)} %
              </div>
              <div className="h-1.5 w-full rounded bg-slate-800">
                <div className="h-1.5 rounded bg-sky-500" style={{ width: `${Math.max(0, Math.min(100, run.percent))}%` }} />
              </div>
              <div>
                elapsed {fmtSeconds(run.elapsed_s)} · RSS {fmtRss(run.rss_mb)} · peak {fmtRss(run.peak_rss_mb)}
              </div>
              {run.status === 'failed' && <div className="text-rose-300">failed (rc {String(run.returncode)}), log: {run.log}</div>}
            </div>
          )}
          {error && (
            <p role="alert" className="text-rose-300">
              {error}
            </p>
          )}
        </form>
      )}
    </div>
  )
}
