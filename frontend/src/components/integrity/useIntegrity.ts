// Data hooks for log integrity: served dataset, one upload's quick scan (polled), one run's full report.
import { useEffect, useState } from 'react'
import { ApiError, getIntegrity, getRunIntegrity, getUploadIntegrity, startUploadIntegrity } from '../../api'
import type { IntegrityState } from '../../lib/integrity'

const POLL_MS = 2000
/** Consecutive network/server errors tolerated while polling before the badge says "Check failed". */
const MAX_ERRORS = 3
/** Polls for a finished run's report before giving up (the stage is non-fatal and may not have written one). */
const RUN_TRIES = 4

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const is404 = (e: unknown) => e instanceof ApiError && e.status === 404

/** GET /api/integrity, re-fetched whenever `version` changes (data reloaded). */
export function useServedIntegrity(version: number): IntegrityState {
  const [state, setState] = useState<IntegrityState>({ status: 'checking' })
  useEffect(() => {
    let alive = true
    getIntegrity()
      .then((report) => alive && setState({ status: 'done', report }))
      .catch((e) => alive && setState(is404(e) ? { status: 'absent' } : { status: 'failed', error: msg(e) }))
    return () => {
      alive = false
    }
  }, [version])
  return state
}

/**
 * Quick scan of one upload: polls GET /api/uploads/{id}/integrity every 2 s until done/failed. A "pending" status
 * (scan never started, e.g. the upload predates the feature) starts it once with POST. 404 = not available -> absent.
 */
export function useUploadIntegrity(uploadId: string | null): IntegrityState {
  const [state, setState] = useState<IntegrityState>({ status: 'absent' })
  const [seen, setSeen] = useState<string | null>(null)
  if (uploadId !== seen) {
    setSeen(uploadId)
    setState(uploadId ? { status: 'checking' } : { status: 'absent' })
  }

  useEffect(() => {
    if (!uploadId) return
    let alive = true
    let timer: number | null = null
    let started = false
    let errors = 0
    const stop = () => {
      if (timer !== null) window.clearTimeout(timer)
      timer = null
    }
    const tick = async () => {
      try {
        const st = await getUploadIntegrity(uploadId)
        if (!alive) return
        errors = 0
        if (st.status === 'done' && st.report) return setState({ status: 'done', report: st.report })
        if (st.status === 'failed') return setState({ status: 'failed', error: st.error || 'integrity scan failed' })
        if (st.status === 'pending' && !started) {
          started = true
          await startUploadIntegrity(uploadId).catch((e) => {
            if (!(e instanceof ApiError && e.status === 409)) throw e
          })
        }
        if (alive) setState({ status: 'checking' })
      } catch (e) {
        if (!alive) return
        if (is404(e)) return setState({ status: 'absent' })
        if (++errors >= MAX_ERRORS) return setState({ status: 'failed', error: msg(e) })
      }
      if (alive) timer = window.setTimeout(tick, POLL_MS)
    }
    void tick()
    return () => {
      alive = false
      stop()
    }
  }, [uploadId])
  return state
}

/** Full-scope report of a finished run (GET /api/runs/{id}/integrity); null runId = nothing to fetch. */
export function useRunIntegrity(runId: string | null): IntegrityState {
  const [state, setState] = useState<IntegrityState>({ status: 'absent' })
  const [seen, setSeen] = useState<string | null>(null)
  if (runId !== seen) {
    setSeen(runId)
    setState(runId ? { status: 'checking' } : { status: 'absent' })
  }

  useEffect(() => {
    if (!runId) return
    let alive = true
    let timer: number | null = null
    let tries = 0
    const tick = async () => {
      try {
        const report = await getRunIntegrity(runId)
        if (alive) setState({ status: 'done', report })
        return
      } catch (e) {
        if (!alive) return
        if (++tries >= RUN_TRIES) return setState(is404(e) ? { status: 'absent' } : { status: 'failed', error: msg(e) })
      }
      if (alive) timer = window.setTimeout(tick, POLL_MS)
    }
    void tick()
    return () => {
      alive = false
      if (timer !== null) window.clearTimeout(timer)
    }
  }, [runId])
  return state
}
