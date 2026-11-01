import { useCallback, useEffect, useRef, useState } from 'react'
import { getIncident, getIncidents, getLiveStatus, getMetrics, type LiveStatus } from './api'
import { AddDataPage } from './components/AddDataPage'
import { ConnectionsPage } from './components/integrations/ConnectionsPage'
import { IncidentList } from './components/IncidentList'
import { KpiStrip } from './components/KpiStrip'
import { StatusBar } from './components/StatusBar'
import { TopBar } from './components/TopBar'
import { EmptyState, ErrorNote, Spinner } from './components/ui'
import { useServedIntegrity } from './components/integrity/useIntegrity'
import { Workspace } from './components/Workspace'
import { isSiemAlertsInput } from './lib/siem'
import type { Tab } from './lib/tabs'
import type { Incident, IncidentSummary, Metrics } from './types'

/** Live mode: list refresh period while /api/live/status says enabled; status poll period otherwise. */
const LIVE_REFRESH_MS = 2000
const STATUS_POLL_MS = 5000

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** Views: incident analysis (default), the "Add data" page (#add-data) and "Connections" (#connections). */
export type View = 'incidents' | 'add' | 'connections'
const ADD_HASH = 'add-data'
const CONN_HASH = 'connections'

function viewOfHash(hash: string): View {
  return hash === `#${ADD_HASH}` ? 'add' : hash === `#${CONN_HASH}` ? 'connections' : 'incidents'
}

function hashId(): string | null {
  try {
    const h = decodeURIComponent(window.location.hash.replace(/^#/, ''))
    return h && h !== ADD_HASH && h !== CONN_HASH ? h : null
  } catch {
    // Malformed hash (e.g. "#%E0"): ignore it and fall back to no selection.
    return null
  }
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v ? v : null
}

export default function App() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [metricsError, setMetricsError] = useState<string | null>(null)
  const [incidents, setIncidents] = useState<IncidentSummary[] | null>(null)
  const [listError, setListError] = useState<string | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [incident, setIncident] = useState<Incident | null>(null)
  const [incidentError, setIncidentError] = useState<string | null>(null)
  const [loadingIncident, setLoadingIncident] = useState(false)
  const [openedAt, setOpenedAt] = useState<number | null>(null)
  const [live, setLive] = useState<LiveStatus | null>(null)
  const [liveUpdatedAt, setLiveUpdatedAt] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('overview')
  // Level 3 (raw details) opens on demand when a step is clicked; closed by default.
  const [inspectorOpen, setInspectorOpen] = useState(false)
  const [view, setView] = useState<View>(() => viewOfHash(window.location.hash))
  const viewRef = useRef<View>(view)
  const reqSeq = useRef(0)
  const selectedRef = useRef<string | null>(null)
  const incidentRef = useRef<Incident | null>(null)
  useEffect(() => {
    selectedRef.current = selectedId
    incidentRef.current = incident
    viewRef.current = view
  })
  const liveOn = live?.enabled === true
  // Bumped when the Add data page changes the served data, so the header's log-health badge re-fetches GET /api/integrity.
  const [dataVersion, setDataVersion] = useState(0)
  const integrity = useServedIntegrity(dataVersion)

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
        setLoadingIncident(false)
        setIncident(inc)
      })
      .catch((e) => {
        if (seq !== reqSeq.current) return
        setIncident(null)
        setLoadingIncident(false)
        setIncidentError(msg(e))
      })
    if (viewRef.current === 'incidents' && window.location.hash !== `#${selectedId}`) history.replaceState(null, '', `#${encodeURIComponent(selectedId)}`)
  }, [selectedId])

  // Deep links and back/forward: follow #<incident id> changes made outside the app.
  useEffect(() => {
    const onHash = () => {
      const v = viewOfHash(window.location.hash)
      if (v !== 'incidents') {
        setView(v)
        return
      }
      setView('incidents')
      const id = hashId()
      if (id && id !== selectedRef.current) {
        setOpenedAt(performance.now())
        setLoadingIncident(true)
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

  const dataChanged = useCallback(() => {
    setDataVersion((v) => v + 1)
    loadAll()
  }, [loadAll])

  const select = useCallback(
    (id: string) => {
      if (id === selectedId) return
      setOpenedAt(performance.now())
      setLoadingIncident(true)
      setSelectedId(id)
    },
    [selectedId],
  )

  const goView = useCallback((v: View) => {
    setView(v)
    const sel = selectedRef.current
    history.replaceState(null, '', v === 'add' ? `#${ADD_HASH}` : v === 'connections' ? `#${CONN_HASH}` : sel ? `#${encodeURIComponent(sel)}` : window.location.pathname)
  }, [])

  // From the "Add data" results: jump to an incident in the incidents view.
  const openIncident = useCallback(
    (id: string) => {
      setTab('overview')
      goView('incidents')
      history.replaceState(null, '', `#${encodeURIComponent(id)}`)
      if (id !== selectedRef.current) {
        setOpenedAt(performance.now())
        setLoadingIncident(true)
        setSelectedId(id)
      }
    },
    [goView],
  )

  const rm = metrics?.run_metrics
  const dataDir = str(rm?.out_dir) ?? str(rm?.raw_dir)
  const apiOk = listError ? false : incidents ? true : null

  return (
    <div className="flex h-screen min-h-[700px] flex-col">
      <TopBar apiOk={apiOk} live={live} liveUpdatedAt={liveUpdatedAt} view={view} onView={goView} integrity={integrity} />
      {view === 'connections' ? (
        <div className="min-h-0 flex-1 overflow-y-auto px-4 py-6 sm:px-6">
          <ConnectionsPage />
        </div>
      ) : view === 'add' ? (
        <div className="min-h-0 flex-1 overflow-y-auto px-6 py-6">
          <AddDataPage metrics={metrics} onDataChanged={dataChanged} onOpenIncident={openIncident} />
        </div>
      ) : (
      <div className="mx-auto flex min-h-0 w-full max-w-[1760px] flex-1 flex-col gap-5 px-6 py-5 short:gap-4 short:py-4">
        <KpiStrip metrics={metrics} error={metricsError} siemAlerts={isSiemAlertsInput(metrics, live)} incidents={incidents} />
        {/* Work area fills the rest of the viewport; the list and the incident scroll inside their cards. */}
        <div className="flex min-h-0 flex-1 gap-4">
          <aside className="w-[320px] shrink-0">
            <IncidentList incidents={incidents} error={listError} selectedId={selectedId} onSelect={select} onRetry={loadAll} />
          </aside>
          <main className="relative flex min-h-0 min-w-0 flex-1">
            {incidentError && (
              <div className="card flex-1">
                <ErrorNote>Could not load incident: {incidentError}</ErrorNote>
              </div>
            )}
            {!incidentError && !incident && (
              <div className="card flex-1">
                {incidents === null && !listError ? <Spinner label="Loading…" /> : <EmptyState title={incidents && incidents.length === 0 ? 'No incidents in this run' : 'Select an incident'}>Pick an incident on the left to see how the attack unfolded.</EmptyState>}
              </div>
            )}
            {!incidentError && incident && (
              <Workspace key={incident.id} incident={incident} openedAt={openedAt} tab={tab} onTab={setTab} inspectorOpen={inspectorOpen} onInspector={setInspectorOpen} />
            )}
            {loadingIncident && incident && incident.id !== selectedId && (
              <div className="pointer-events-none absolute top-4 right-4 rounded-full border border-line bg-white px-3 py-1 text-[12px] text-muted shadow-card">Loading…</div>
            )}
          </main>
        </div>
      </div>
      )}
      <StatusBar apiOk={apiOk} dataDir={dataDir} metrics={metrics} />
    </div>
  )
}
