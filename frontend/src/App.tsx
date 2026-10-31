import { useCallback, useEffect, useRef, useState } from 'react'
import { getIncident, getIncidents, getMetrics } from './api'
import { Header } from './components/Header'
import { IncidentList } from './components/IncidentList'
import { IncidentView } from './components/IncidentView'
import type { Incident, IncidentSummary, Metrics } from './types'

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e))

function hashId(): string | null {
  const h = decodeURIComponent(window.location.hash.replace(/^#/, ''))
  return h || null
}

export default function App() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [metricsError, setMetricsError] = useState<string | null>(null)
  const [incidents, setIncidents] = useState<IncidentSummary[] | null>(null)
  const [listError, setListError] = useState<string | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [incident, setIncident] = useState<Incident | null>(null)
  const [incidentError, setIncidentError] = useState<string | null>(null)
  const [openedAt, setOpenedAt] = useState<number | null>(null)
  const mainRef = useRef<HTMLElement>(null)
  const reqSeq = useRef(0)

  const loadAll = useCallback(() => {
    getMetrics()
      .then((m) => {
        setMetrics(m)
        setMetricsError(null)
      })
      .catch((e) => setMetricsError(msg(e)))
    getIncidents()
      .then((rows) => {
        setIncidents(rows)
        setListError(null)
        setSelectedId((cur) => {
          if (cur && rows.some((r) => r.id === cur)) return cur
          const fromHash = hashId()
          if (fromHash && rows.some((r) => r.id === fromHash)) return fromHash
          return rows[0]?.id ?? null
        })
      })
      .catch((e) => {
        setIncidents(null)
        setListError(msg(e))
      })
  }, [])

  useEffect(() => {
    loadAll()
  }, [loadAll])

  // Load the selected incident; ignore stale responses if the analyst clicks quickly.
  useEffect(() => {
    if (!selectedId) return
    const seq = ++reqSeq.current
    getIncident(selectedId)
      .then((inc) => {
        if (seq !== reqSeq.current) return
        setIncidentError(null)
        setIncident(inc)
        mainRef.current?.scrollTo({ top: 0 })
      })
      .catch((e) => {
        if (seq !== reqSeq.current) return
        setIncident(null)
        setIncidentError(msg(e))
      })
    if (window.location.hash !== `#${selectedId}`) history.replaceState(null, '', `#${encodeURIComponent(selectedId)}`)
  }, [selectedId])

  const select = useCallback(
    (id: string) => {
      if (id === selectedId) return
      setOpenedAt(performance.now())
      setSelectedId(id)
    },
    [selectedId],
  )

  return (
    <div className="flex h-full flex-col">
      <Header metrics={metrics} metricsError={metricsError} onRunFinished={loadAll} />
      <div className="flex min-h-0 flex-1">
        <aside className="w-72 shrink-0 border-r border-slate-800 bg-slate-900/40 xl:w-80">
          <IncidentList incidents={incidents} error={listError} selectedId={selectedId} onSelect={select} onRetry={loadAll} />
        </aside>
        <main ref={mainRef} className="min-w-0 flex-1 overflow-y-auto" aria-live="polite">
          {incidentError && (
            <div role="alert" className="m-4 rounded border border-rose-800 bg-rose-950/50 p-3 text-sm text-rose-200">
              Could not load incident: {incidentError}
            </div>
          )}
          {!incidentError && !incident && (
            <p className="p-6 text-sm text-slate-500">{incidents && incidents.length === 0 ? 'No incidents.' : 'Select an incident.'}</p>
          )}
          {incident && <IncidentView key={incident.id} incident={incident} openedAt={openedAt} />}
        </main>
      </div>
    </div>
  )
}
