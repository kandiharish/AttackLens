// "Add data": upload or point at logs → analyse (stage stepper) → results. Simple first; details below.
import { useCallback, useEffect, useState } from 'react'
import { ApiError, getHealth, getIncidents, getMetrics, getRun, getRuns, getUploads, startRun, USE_MOCK, type RunStatus, type UploadResult } from '../api'
import { fmtBytes, readSigma } from '../lib/addData'
import { fmtDay, riskStyle } from '../lib/format'
import { fmtCount, readIngest } from '../lib/metrics'
import { summaryTitle } from '../lib/plain'
import type { IncidentSummary, Metrics } from '../types'
import { scopeLabel, type IntegrityState } from '../lib/integrity'
import { ChooseLogs } from './ChooseLogs'
import { IntegrityStatus } from './integrity/IntegrityStatus'
import { useRunIntegrity, useUploadIntegrity } from './integrity/useIntegrity'
import { RunStepper } from './RunStepper'
import { Button } from './ui'

const POLL_MS = 2000
const msg = (e: unknown) => (e instanceof Error ? e.message : String(e))

interface Props {
  metrics: Metrics | null
  /** Ask the app to reload incidents + metrics (after a successful run). */
  onDataChanged: () => void
  onOpenIncident: (id: string) => void
}

interface Result {
  count: number
  top: IncidentSummary | null
  rowsIn: number | null
}

function StepCard({ n, title, sub, children, dim = false }: { n: number; title: string; sub?: string; children: React.ReactNode; dim?: boolean }) {
  return (
    <section className={`card px-6 py-5 ${dim ? 'opacity-60' : ''}`} aria-labelledby={`step-${n}-title`}>
      <div className="mb-4 flex items-center gap-3">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-ink font-mono text-[13px] font-semibold text-white">{n}</span>
        <div>
          <h3 id={`step-${n}-title`} className="headline text-[17px]">
            {title}
          </h3>
          {sub && <p className="text-[13px] text-muted">{sub}</p>}
        </div>
      </div>
      {children}
    </section>
  )
}

/** Collapsed advanced form (was the header's "New run"): run the pipeline on a folder that is already on the server. */
function AdvancedFolder({ disabled, onAnalyse }: { disabled: boolean; onAnalyse: (rawDir: string, groundTruth?: string) => void }) {
  const [rawDir, setRawDir] = useState('data/raw/')
  const [gt, setGt] = useState('')
  const input = 'focus-ring mt-1.5 h-9 w-full rounded-lg border border-line-strong bg-white px-3 font-mono text-[13px] text-ink placeholder:text-muted'
  return (
    <details className="group mt-5 rounded-xl border border-line bg-subtle">
      <summary className="focus-ring flex cursor-pointer list-none items-center gap-2 rounded-xl px-4 py-3 text-[13px] font-medium text-ink-2 hover:text-ink [&::-webkit-details-marker]:hidden">
        <svg viewBox="0 0 12 12" className="h-3 w-3 transition-transform group-open:rotate-90" aria-hidden="true">
          <path d="M4 2.5L7.5 6 4 9.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        Advanced: analyse a folder on the server
      </summary>
      <form
        className="grid gap-4 border-t border-line px-4 pt-4 pb-4 sm:grid-cols-[1fr_1fr_auto] sm:items-end"
        onSubmit={(e) => {
          e.preventDefault()
          if (rawDir.trim()) onAnalyse(rawDir.trim(), gt.trim() || undefined)
        }}
      >
        <label className="block min-w-0">
          <span className="section-label">Raw folder (server path)</span>
          <input value={rawDir} onChange={(e) => setRawDir(e.target.value)} className={input} required spellCheck={false} />
        </label>
        <label className="block min-w-0">
          <span className="section-label">Ground truth (optional)</span>
          <input value={gt} onChange={(e) => setGt(e.target.value)} className={input} placeholder="for scoring only" spellCheck={false} />
        </label>
        <Button type="submit" variant="primary" disabled={disabled}>
          Analyse folder
        </Button>
      </form>
    </details>
  )
}

/** Same raw folder? A run reports its resolved absolute path, an upload its path relative to the repo. */
function sameRawDir(runDir: string, uploadDir: string): boolean {
  const norm = (p: string) => p.replace(/\\/g, '/').replace(/\/+$/, '').replace(/^\.\//, '').toLowerCase()
  const r = norm(runDir)
  const u = norm(uploadDir)
  return u !== '' && (r === u || r.endsWith(`/${u}`))
}

/** An upload's card shows a run's full report only when that run analysed this upload's folder. */
function uploadHealth(quick: IntegrityState, full: IntegrityState, runIsUpload: boolean): IntegrityState {
  if (!runIsUpload) return quick
  return full.status === 'done' ? full : quick.status !== 'absent' ? quick : full
}

const folderName = (p: string) => p.replace(/\\/g, '/').replace(/\/+$/, '').split('/').pop() || p

/** Log health of the data on this page: badge + popup (tampered / suspect / looks generated) + full report. */
function HealthCard({ state, dataDir }: { state: IntegrityState; dataDir?: string }) {
  const note =
    state.status === 'checking'
      ? 'Checking the files for signs of tampering (seal, wiped regions, cut-off ends)…'
      : state.status === 'done'
        ? `${scopeLabel(state.report)}${state.report.scope === 'quick' ? ' · the full check (files + events) runs with the analysis' : ''}`
        : state.status === 'failed'
          ? `The integrity check could not finish: ${state.error}`
          : 'No integrity report for this data (the server may not support integrity checks yet).'
  return (
    <section className="card flex flex-wrap items-center gap-x-5 gap-y-2 px-6 py-4" aria-label="Log health">
      <div className="min-w-0">
        <div className="section-label">
          Log health
          {dataDir && (
            <span className="ml-1.5 font-mono normal-case" title={dataDir}>
              · {folderName(dataDir)}
            </span>
          )}
        </div>
        <p className="mt-0.5 text-[13px] break-words text-ink-2">{note}</p>
      </div>
      <div className="ml-auto">
        <IntegrityStatus state={state} popup="alarming" />
      </div>
    </section>
  )
}

export function AddDataPage({ metrics, onDataChanged, onOpenIncident }: Props) {
  const [offline, setOffline] = useState<string | null>(USE_MOCK ? 'Mock mode: uploads and runs need the backend (start uvicorn and unset VITE_USE_MOCK).' : null)
  const [source, setSource] = useState<UploadResult | null>(null)
  const [runId, setRunId] = useState<string | null>(null)
  const [status, setStatus] = useState<RunStatus | null>(null)
  const [runError, setRunError] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)
  const [result, setResult] = useState<Result | null>(null)
  const [uploads, setUploads] = useState<UploadResult[] | null>(null)
  const [fresh, setFresh] = useState<Metrics | null>(null)
  // Last thing analysed (an upload's raw_dir or an advanced server folder), for "Analyse again".
  const [last, setLast] = useState<{ rawDir: string; gt?: string } | null>(null)
  // Log health: quick scan of the chosen upload (files only), then the full report of the finished run.
  // The run's raw_dir decides whose report it is: a run of another folder (advanced form, or a run we followed
  // after a 409) gets its own card and never replaces the upload's report.
  const [doneRun, setDoneRun] = useState<{ id: string; rawDir: string } | null>(null)
  const quick = useUploadIntegrity(source?.upload_id ?? null)
  const full = useRunIntegrity(doneRun?.id ?? null)
  const runIsSource = !!source && !!doneRun && sameRawDir(doneRun.rawDir, source.raw_dir)

  const loadUploads = useCallback(() => {
    getUploads()
      .then(setUploads)
      .catch(() => setUploads([]))
  }, [])

  // Health + recent uploads + re-attach to a run that is already going (e.g. after leaving this page).
  useEffect(() => {
    if (USE_MOCK) return
    getHealth()
      .then(() => setOffline(null))
      .catch((e) => setOffline(`Backend offline: ${msg(e)}`))
    loadUploads()
    getRuns()
      .then((runs) => {
        const running = runs.find((r) => r.status === 'running')
        if (running) setRunId(running.run_id)
      })
      .catch(() => {})
  }, [loadUploads])

  const finish = useCallback(
    async (st: RunStatus) => {
      if (st.status === 'failed') {
        setRunError(st.error || `The analysis stopped (exit code ${st.returncode ?? '?'}). Log: ${st.log}`)
        return
      }
      // RunManager.status() sends raw_dir (resolved path); missing (older backend) -> '' = never the upload's run.
      setDoneRun({ id: st.run_id, rawDir: (st as RunStatus & { raw_dir?: string }).raw_dir ?? '' })
      try {
        const [rows, m] = await Promise.all([getIncidents(), getMetrics().catch(() => null)])
        setFresh(m)
        setResult({ count: rows.length, top: rows[0] ?? null, rowsIn: readIngest(m)?.rowsIn ?? null })
      } catch (e) {
        setRunError(`Analysis finished, but results could not be loaded: ${msg(e)}`)
      }
      onDataChanged()
      loadUploads()
    },
    [onDataChanged, loadUploads],
  )

  // Poll the run every 2 s until it ends.
  useEffect(() => {
    if (!runId) return
    let alive = true
    let timer: number | null = null
    const tick = async () => {
      try {
        const st = await getRun(runId)
        if (!alive) return
        setStatus(st)
        if (st.status !== 'running') {
          if (timer !== null) window.clearInterval(timer)
          timer = null
          void finish(st)
        }
      } catch (e) {
        if (alive) setRunError(msg(e))
      }
    }
    void tick()
    timer = window.setInterval(tick, POLL_MS)
    return () => {
      alive = false
      if (timer !== null) window.clearInterval(timer)
    }
  }, [runId, finish])

  const analyse = async (rawDir: string, groundTruth?: string) => {
    setLast({ rawDir, gt: groundTruth })
    setDoneRun(null)
    setRunError(null)
    setResult(null)
    setStatus(null)
    setStarting(true)
    try {
      const { run_id } = await startRun(rawDir, groundTruth)
      setRunId(run_id)
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        // A run is already going: follow it instead of failing.
        const running = (await getRuns().catch(() => [])).find((r) => r.status === 'running')
        if (running) setRunId(running.run_id)
        else setRunError('Another analysis is already running. Wait for it to finish, then try again.')
      } else setRunError(msg(e))
    } finally {
      setStarting(false)
    }
  }

  const running = status?.status === 'running' || (runId !== null && status === null && !runError)
  const sigma = readSigma(fresh ?? metrics)

  return (
    <div className="mx-auto w-full max-w-[1120px] space-y-5 pb-6">
      <header className="pt-1">
        <h2 className="headline text-[24px]">Add your own logs</h2>
        <p className="mt-1 text-[14px] text-ink-2">Upload logs (or point at a file on this computer), press Analyse, and see the attack paths. No terminal needed.</p>
      </header>

      {offline && (
        <div role="alert" className="flex items-start gap-3 rounded-2xl border border-med/60 bg-med-bg px-5 py-3.5 text-[13px] text-med-ink">
          <span className="mt-0.5 h-2.5 w-2.5 shrink-0 rounded-full bg-med" aria-hidden="true" />
          <span className="break-words">{offline}</span>
        </div>
      )}

      <StepCard n={1} title="Choose logs" sub="Firewall, Windows, EDR, syslog, CEF, CSV or JSON logs">
        <ChooseLogs
          disabled={!!offline || running}
          ready={source}
          onReady={(r) => {
            setSource(r)
            setResult(null)
            setRunError(null)
            setRunId(null)
            setStatus(null)
            setDoneRun(null)
            loadUploads()
          }}
          onReset={() => setSource(null)}
        />
        <AdvancedFolder disabled={!!offline || running || starting} onAnalyse={(dir, gt) => void analyse(dir, gt)} />
      </StepCard>

      {source && <HealthCard key={source.upload_id} state={uploadHealth(quick, full, runIsSource)} dataDir={source.raw_dir} />}
      {doneRun && !runIsSource && <HealthCard key={`run:${doneRun.id}`} state={full} dataDir={doneRun.rawDir || undefined} />}

      <StepCard n={2} title="Analyse" sub="Finds attack steps, links them and builds attack paths" dim={!source && !runId}>
        {!runId || (!running && !status) ? (
          <Button variant="primary" onClick={() => source && analyse(source.raw_dir)} disabled={!source || starting || !!offline}>
            {starting ? 'Starting…' : 'Analyse these logs'}
          </Button>
        ) : (
          <>
            <RunStepper status={status} />
            {!running && last && (
              <div className="mt-5">
                <Button onClick={() => analyse(last.rawDir, last.gt)} disabled={starting || !!offline}>
                  Analyse again
                </Button>
              </div>
            )}
          </>
        )}
        {runError && (
          <p role="alert" className="mt-4 rounded-xl border border-crit/30 bg-crit-bg px-4 py-3 text-[13px] break-words text-crit-ink">
            {runError}
          </p>
        )}
      </StepCard>

      {result && (
        <StepCard n={3} title="Results">
          {result.count > 0 ? (
            <div className="flex flex-wrap items-center gap-5">
              <div>
                <p className="headline text-[28px] tabular-nums">
                  {result.count} attack{result.count === 1 ? '' : 's'} found
                </p>
                {result.top && (
                  <p className="mt-1 text-[14px] text-ink-2">
                    Riskiest:{' '}
                    <span className={`mr-1.5 inline-flex h-6 items-center rounded-full border px-2 text-[11px] font-semibold uppercase ${riskStyle(result.top.risk).pill}`}>
                      {riskStyle(result.top.risk).label} {result.top.risk}
                    </span>
                    {summaryTitle(result.top)}
                  </p>
                )}
              </div>
              {result.top && (
                <span className="ml-auto">
                  <Button variant="brand" onClick={() => result.top && onOpenIncident(result.top.id)}>
                    Open the top incident →
                  </Button>
                </span>
              )}
            </div>
          ) : (
            <div>
              <p className="headline text-[20px]">No attack path found in these logs</p>
              <p className="mt-1 text-[14px] text-ink-2">
                {result.rowsIn !== null ? `${result.rowsIn.toLocaleString('en-US')} log rows were read and checked.` : 'Rows read: not recorded for this run.'}
              </p>
            </div>
          )}
        </StepCard>
      )}

      {sigma && (
        <section className="card flex flex-wrap items-center gap-x-8 gap-y-3 px-6 py-5" aria-label="Detection coverage">
          <div>
            <div className="section-label">Detection coverage</div>
            <p className="headline mt-1 text-[18px]">
              {sigma.applicable.toLocaleString('en-US')} of {sigma.total.toLocaleString('en-US')} Sigma rules active on this data
            </p>
          </div>
          <div className="flex gap-6 text-[13px] text-ink-2">
            {sigma.compiled !== null && (
              <span title="run_metrics.sigma_rules_compiled">
                <span className="font-semibold text-ink tabular-nums">{sigma.compiled.toLocaleString('en-US')}</span> compiled
              </span>
            )}
            {sigma.alerts !== null && (
              <span title="run_metrics.sigma_alerts">
                <span className="font-semibold text-ink tabular-nums">{fmtCount(sigma.alerts)}</span> Sigma alerts
              </span>
            )}
          </div>
        </section>
      )}

      <section className="card overflow-hidden" aria-labelledby="recent-uploads">
        <div className="flex items-baseline gap-3 border-b border-line px-6 py-4">
          <h3 id="recent-uploads" className="headline text-[16px]">
            Recent uploads
          </h3>
          <span className="text-[13px] text-muted">{uploads ? `${uploads.length}` : ''}</span>
        </div>
        {!uploads || uploads.length === 0 ? (
          <p className="px-6 py-5 text-[13px] text-muted">{offline ? 'Unavailable while the backend is offline.' : 'No uploads yet.'}</p>
        ) : (
          <table className="w-full table-fixed border-collapse text-[13px]">
            <thead>
              <tr className="bg-subtle text-left">
                <th className="section-label w-[38%] px-6 py-3">Files</th>
                <th className="section-label w-[14%] px-4 py-3">Size</th>
                <th className="section-label w-[18%] px-4 py-3">Added</th>
                <th className="section-label px-4 py-3">Folder</th>
                <th className="w-[130px] px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {uploads.slice(0, 10).map((u) => (
                <tr key={u.upload_id} className="border-t border-line hover:bg-subtle">
                  <td className="truncate px-6 py-3 text-ink" title={u.files.map((f) => f.name).join(', ')}>
                    {u.files.length ? u.files.map((f) => f.name).join(', ') : u.upload_id}
                  </td>
                  <td className="px-4 py-3 text-ink-2 tabular-nums">{fmtBytes(u.total_bytes)}</td>
                  <td className="px-4 py-3 text-muted">{typeof u.created_at === 'string' ? fmtDay(u.created_at) : '—'}</td>
                  <td className="truncate px-4 py-3 font-mono text-[12px] text-muted" title={u.raw_dir}>
                    {u.raw_dir}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <Button
                      size="sm"
                      onClick={() => {
                        setSource(u)
                        void analyse(u.raw_dir)
                      }}
                      disabled={running || starting || !!offline}
                    >
                      Re-analyse
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  )
}
