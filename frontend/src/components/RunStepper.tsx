// Step 2 of "Add data": live stage stepper for one pipeline run (GET /api/runs/{id}, polled by the parent).
// Every number comes from RunStatus; the progress keys are optional (older backend / mock: they are simply not shown).
import { useState } from 'react'
import type { RunStatus } from '../api'
import { fmtEta, ingestLine, RUN_STEPS, smoothEta, stepIndex, stepTimes, type EtaState } from '../lib/addData'
import { fmtRss, fmtSeconds } from '../lib/metrics'

const BASIS: Record<string, string> = {
  history: 'stage times of earlier runs, scaled by input size',
  live: 'this run’s measured progress',
  'history+live': 'earlier runs’ stage times blended with this run’s measured progress',
}

/** Friendlier names for backend stages that are not self-explanatory (others are shown as-is). */
const STAGE_LABEL: Record<string, string> = { integrity: 'integrity (log health check)' }
const stageName = (s: string) => STAGE_LABEL[s] ?? s

const frac = (v: number | null | undefined): number | null => (typeof v === 'number' && Number.isFinite(v) ? Math.max(0, Math.min(1, v)) : null)

export function RunStepper({ status }: { status: RunStatus | null }) {
  // Smoothed ETA, updated once per new status object (React "adjust state on prop change" pattern; pure inputs only).
  const [seen, setSeen] = useState<RunStatus | null>(null)
  const [eta, setEta] = useState<EtaState | null>(null)
  if (status !== seen) {
    setSeen(status)
    setEta(status && status.status === 'running' ? smoothEta(eta, status.eta_s, status.run_id, status.stage, status.elapsed_s) : null)
  }

  const failed = status?.status === 'failed'
  const done = status?.status === 'succeeded'
  const running = status?.status === 'running' || status === null
  const active = done ? RUN_STEPS.length - 1 : stepIndex(status?.stage)
  const times = stepTimes(status?.stages_done)
  const stageElapsed = status?.stage_elapsed_s
  const fraction = frac(status?.stage_fraction)
  const ingest = running && active === 0 ? ingestLine(status) : null

  const headline = done
    ? `Finished in ${fmtSeconds(status.elapsed_s)}`
    : failed
      ? `Stopped after ${fmtSeconds(status.elapsed_s)}`
      : status && status.eta_s === undefined
        ? null // older backend without progress keys: no remaining-time headline at all
        : fmtEta(eta?.eta ?? null)
  const etaTitle = running && status?.eta_basis ? `Estimate from ${BASIS[status.eta_basis] ?? status.eta_basis}${typeof status.eta_total_s === 'number' ? ` · estimated total ${fmtSeconds(status.eta_total_s)}` : ''}` : undefined

  return (
    <div>
      {(headline || ingest) && (
        <div className="mb-4 flex flex-wrap items-baseline gap-x-5 gap-y-1">
          {headline && (
            <p className={`headline text-[20px] tabular-nums ${failed ? 'text-crit-ink' : ''}`} title={etaTitle} aria-live="polite">
              {headline}
            </p>
          )}
          {ingest && <p className="font-mono text-[12px] text-ink-2 tabular-nums">{ingest}</p>}
        </div>
      )}
      <ol className="grid grid-cols-1 gap-3 sm:grid-cols-5 sm:gap-2" aria-label="Analysis progress">
        {RUN_STEPS.map((st, i) => {
          const state = done || i < active ? 'done' : i === active ? (failed ? 'failed' : 'active') : 'todo'
          const isActive = state === 'active'
          const showBar = isActive && fraction !== null
          // Active step: finished sub-stages of this step + time in the current stage.
          const activeS = isActive && typeof stageElapsed === 'number' && Number.isFinite(stageElapsed) ? (times[i] ?? 0) + Math.max(0, stageElapsed) : isActive ? times[i] : null
          const timeText = state === 'done' && times[i] !== null ? fmtSeconds(times[i]) : isActive && activeS !== null ? fmtSeconds(activeS) : null
          return (
            <li key={st.key} className="min-w-0" aria-current={isActive ? 'step' : undefined}>
              <div
                className={`h-1.5 overflow-hidden rounded-full ${state === 'done' ? 'bg-brand' : isActive ? (showBar ? 'bg-unobs' : 'animate-pulse bg-brand/60') : state === 'failed' ? 'bg-crit' : 'bg-unobs'}`}
                role={isActive ? 'progressbar' : undefined}
                aria-label={isActive ? `${st.label} progress` : undefined}
                aria-valuemin={showBar ? 0 : undefined}
                aria-valuemax={showBar ? 100 : undefined}
                aria-valuenow={showBar ? Math.round(fraction * 100) : undefined}
              >
                {showBar && <div className="h-1.5 rounded-full bg-brand transition-[width] duration-700" style={{ width: `${fraction * 100}%` }} />}
              </div>
              <div className="mt-2.5 flex items-center gap-2">
                <span
                  className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full font-mono text-[11px] font-semibold ${
                    state === 'done' ? 'bg-brand text-ink' : isActive ? 'bg-ink text-white' : state === 'failed' ? 'bg-crit text-white' : 'border border-line bg-white text-muted'
                  }`}
                  aria-hidden="true"
                >
                  {state === 'done' ? '✓' : state === 'failed' ? '!' : i + 1}
                </span>
                <span className={`truncate text-[13px] ${state === 'todo' ? 'text-muted' : 'font-semibold text-ink'}`}>{st.label}</span>
              </div>
              {(timeText || (isActive && fraction !== null)) && (
                <p className="mt-1 pl-8 font-mono text-[12px] text-ink-2 tabular-nums" title={isActive ? `stage ${status?.stage ?? '—'}${timeText ? `: ${timeText} so far` : ''}` : `${st.label} took ${timeText}`}>
                  {timeText}
                  {isActive && fraction !== null && (
                    <span className="text-muted">
                      {timeText ? ' · ' : ''}
                      {status?.stage ? `${stageName(status.stage)} ` : ''}
                      {Math.round(fraction * 100)} %
                    </span>
                  )}
                </p>
              )}
              {st.hint && <p className="mt-1 pl-8 text-[12px] leading-snug text-muted">{st.hint}</p>}
            </li>
          )
        })}
      </ol>
      <div className="mt-5 flex flex-wrap items-center gap-x-6 gap-y-1 text-[13px] text-ink-2">
        <span>
          <span className="text-muted">Elapsed </span>
          <span className="font-semibold text-ink tabular-nums">{status ? fmtSeconds(status.elapsed_s) : '—'}</span>
        </span>
        <span title="Resident memory of the pipeline process now (peak in brackets)">
          <span className="text-muted">Memory in use </span>
          <span className="font-semibold text-ink tabular-nums">{status && status.status === 'running' ? fmtRss(status.rss_mb) : '—'}</span>
          {status && status.peak_rss_mb > 0 && <span className="text-muted"> (peak {fmtRss(status.peak_rss_mb)})</span>}
        </span>
        {status?.stage && status.status === 'running' && (
          <span>
            <span className="text-muted">Stage </span>
            <span className="font-mono text-[12px] text-ink">{stageName(status.stage)}</span>
          </span>
        )}
        {status && <span className="ml-auto font-mono text-[11px] text-muted">run {status.run_id}</span>}
      </div>
    </div>
  )
}
