import { useCallback, useEffect, useRef, useState } from 'react'
import { getIncident, getIncidents, getLiveStatus, getMetrics, type LiveStatus } from './api'
import { Header } from './components/Header'
import { IncidentList } from './components/IncidentList'
import { IncidentView } from './components/IncidentView'
import type { Incident, IncidentSummary, Metrics } from './types'

/** Live mode: list refresh period while /api/live/status says enabled; status poll period otherwise. */
const LIVE_REFRESH_MS = 2000
const STATUS_POLL_MS = 5000

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e))

function hashId(): string | null {
  try {
    const h = decodeURIComponent(window.location.hash.replace(/^#/, ''))
    return h || null
  } catch {
    // Malformed hash (e.g. "#%E0"): ignore it and fall back to no selection.
    return null
  }
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
  const [live, setLive] = useState<LiveStatus | null>(null)
  const [liveUpdatedAt, setLiveUpdatedAt] = useState<string | null>(null)
  const mainRef = useRef<HTMLElement>(null)
  const reqSeq = useRef(0)
  const selectedRef = useRef<string | null>(null)
  const incidentRef = useRef<Incident | null>(null)
  useEffect(() => {
    selectedRef.current = selectedId
    incidentRef.current = incident
  })
  const liveOn = live?.enabled === true

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

  // Deep links and back/forward: follow #<incident id> changes made outside the app.
  useEffect(() => {
    const onHash = () => {
      const id = hashId()
      if (id && id !== selectedRef.current) {
        setOpenedAt(performance.now())
        setSelectedId(id)
      }
    }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  // Live status: poll every 2 s while enabled, every 5 s otherwise.
  useEffect(() => {
    let alive = true
    const tick = () =>
      getLiveStatus()
        .then((st) => alive && setLive(st))
        .catch(() => alive && setLive(null))
    tick()
    const t = window.setInterval(tick, liveOn ? LIVE_REFRESH_MS : STATUS_POLL_MS)
    return () => {
      alive = false
      window.clearInterval(t)
    }
  }, [liveOn])

  // Live mode on: refresh the list + metrics every 2 s; re-fetch the open incident only if its summary changed.
  useEffect(() => {
    if (!liveOn) return
    let alive = true
    const refresh = async () => {
      try {
        const [rows, m] = await Promise.all([getIncidents(), getMetrics().catch(() => null)])
        if (!alive) return
        setIncidents(rows)
        setListError(null)
        if (m) setMetrics(m)
        setLiveUpdatedAt(new Date().toISOString())
        if (!selectedRef.current && rows[0]) setSelectedId(rows[0].id)
        const cur = incidentRef.current
        const row = rows.find((r) => r.id === selectedRef.current)
        if (cur && row && (row.last_ts !== cur.last_ts || row.merged_alert_count !== cur.merged_alert_count || row.episode_count !== cur.episode_count || row.risk !== cur.risk)) {
          const inc = await getIncident(row.id)
          if (alive && selectedRef.current === inc.id) {
            setOpenedAt(null) // background refresh: not a click, so no "rendered in" timing
            setIncident(inc)
          }
        }
      } catch (e) {
        if (alive) setListError(msg(e))
      }
    }
    const t = window.setInterval(refresh, LIVE_REFRESH_MS)
    return () => {
      alive = false
      window.clearInterval(t)
    }
  }, [liveOn])

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
      <Header metrics={metrics} metricsError={metricsError} live={live} liveUpdatedAt={liveUpdatedAt} onRunFinished={loadAll} />
      <div className="flex min-h-0 flex-1">
        <aside className="w-72 shrink-0 border-r border-slate-800 bg-slate-900/40 xl:w-80">
          <IncidentList incidents={incidents} error={listError} selectedId={selectedId} onSelect={select} onRetry={loadAll} />
        </aside>
        <main ref={mainRef} className="min-w-0 flex-1 overflow-y-auto">
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
