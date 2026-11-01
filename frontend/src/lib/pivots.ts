// Lazy per-incident pivot loading: fetched once, on the first "Open in SIEM" click, shared by every step menu.
import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { getPivots } from '../api'
import type { IncidentPivots } from '../types_integrations'

export type PivotLoad =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'ready'; data: IncidentPivots }
  | { status: 'error' }

export interface PivotSource {
  state: PivotLoad
  /** Starts the fetch if it has not started yet (no-op afterwards, including after an error). */
  ensure: () => void
}

export const PivotContext = createContext<PivotSource>({ state: { status: 'error' }, ensure: () => {} })

export function usePivotLoader(incidentId: string): PivotSource {
  const [state, setState] = useState<PivotLoad>({ status: 'idle' })
  const started = useRef<string | null>(null)
  const alive = useRef(true)
  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
    }
  }, [])
  const ensure = useCallback(() => {
    if (started.current === incidentId) return
    started.current = incidentId
    setState({ status: 'loading' })
    getPivots(incidentId)
      .then((data) => alive.current && started.current === incidentId && setState({ status: 'ready', data }))
      .catch(() => alive.current && started.current === incidentId && setState({ status: 'error' }))
  }, [incidentId])
  return { state, ensure }
}

export function usePivots(): PivotSource {
  return useContext(PivotContext)
}
