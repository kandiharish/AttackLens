// "Connections": one-click data sources (SIEM, cloud) and incident sinks. Tile grid grouped by kind; clicking a tile
// opens a form generated from the catalog. Every status shown comes from GET /api/integrations/{id}.
import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, getIntegration, getIntegrationCatalog, USE_MOCK } from '../../api'
import { KIND_GROUPS, tileStatus } from '../../lib/connections'
import type { IntegrationCatalogEntry, IntegrationState } from '../../types_integrations'
import { Button, EmptyState, ErrorNote, Spinner } from '../ui'
import { ConnectionForm } from './ConnectionForm'
import { ConnectionsSummary } from './ConnectionsSummary'
import { StatusDot } from './StatusDot'

/** Refresh of every tile (and the summary strip) while the page is visible. The open form polls its own id every 5 s. */
const REFRESH_MS = 15_000
const msg = (e: unknown) => (e instanceof Error ? e.message : String(e))

type Catalog = { kind: 'ok'; entries: IntegrationCatalogEntry[] } | { kind: 'missing' } | { kind: 'error'; message: string }

function Tile({
  entry,
  st,
  selected,
  onOpen,
  btnRef,
}: {
  entry: IntegrationCatalogEntry
  st: IntegrationState | null | undefined
  selected: boolean
  onOpen: () => void
  btnRef: (el: HTMLButtonElement | null) => void
}) {
  const s = tileStatus(entry.kind, st)
  return (
    <li>
      <button
        ref={btnRef}
        type="button"
        onClick={onOpen}
        aria-expanded={selected}
        aria-controls={selected ? `conn-form-${entry.id}` : undefined}
        className={`focus-ring flex h-full w-full flex-col items-start gap-1.5 rounded-2xl border px-4 py-3.5 text-left shadow-card ${
          selected ? 'border-ink bg-white ring-1 ring-ink' : 'border-line bg-panel hover:border-line-strong hover:shadow-lift'
        }`}
      >
        <span className="headline text-[15px]">{entry.name}</span>
        <span className="flex items-center gap-2 text-[12px] text-ink-2">
          <StatusDot tone={s.tone} />
          {st === undefined ? 'Checking…' : s.label}
        </span>
        {s.error && (
          // Backend error text (network messages); rendered as text, clipped to one line here, full text in the form.
          <span className="w-full truncate text-[12px] text-crit-ink" title={s.error}>
            {s.error}
          </span>
        )}
      </button>
    </li>
  )
}

export function ConnectionsPage() {
  const [catalog, setCatalog] = useState<Catalog | null>(null)
  // undefined = still loading, null = could not read (shown as not connected).
  const [states, setStates] = useState<Record<string, IntegrationState | null | undefined>>({})
  const [openId, setOpenId] = useState<string | null>(null)
  const [checkedAt, setCheckedAt] = useState<string | null>(null)
  const tiles = useRef(new Map<string, HTMLButtonElement>())

  // Every entry's state in parallel (no list endpoint in the contract). Tiles AND the summary strip read this map.
  const loadStates = useCallback(async (entries: IntegrationCatalogEntry[]) => {
    const results = await Promise.allSettled(entries.map((c) => getIntegration(c.id)))
    setStates(
      Object.fromEntries(
        entries.map((c, i) => {
          const r = results[i]
          return [c.id, r.status === 'fulfilled' ? r.value : null]
        }),
      ),
    )
    setCheckedAt(new Date().toISOString())
  }, [])

  const load = useCallback(
    () =>
      getIntegrationCatalog()
        .then(async (entries) => {
          setCatalog({ kind: 'ok', entries })
          await loadStates(entries)
        })
        .catch((e) => setCatalog(e instanceof ApiError && e.status === 404 ? { kind: 'missing' } : { kind: 'error', message: msg(e) })),
    [loadStates],
  )

  useEffect(() => {
    void load()
  }, [load])

  // Keep tiles + strip current: refresh every 15 s only while the page is visible.
  const loadedEntries = catalog?.kind === 'ok' ? catalog.entries : null
  useEffect(() => {
    if (!loadedEntries?.length) return
    let t: number | null = null
    const tick = () => void loadStates(loadedEntries)
    const start = () => {
      if (t === null && document.visibilityState === 'visible') t = window.setInterval(tick, REFRESH_MS)
    }
    const stop = () => {
      if (t !== null) window.clearInterval(t)
      t = null
    }
    const onVis = () => {
      if (document.visibilityState === 'visible') {
        tick()
        start()
      } else stop()
    }
    start()
    document.addEventListener('visibilitychange', onVis)
    return () => {
      stop()
      document.removeEventListener('visibilitychange', onVis)
    }
  }, [loadedEntries, loadStates])

  // "Needs attention" link: bring the tile into view and focus it.
  const jump = useCallback((id: string) => {
    const el = tiles.current.get(id)
    if (!el) return
    el.scrollIntoView({ block: 'center', behavior: 'smooth' })
    el.focus({ preventScroll: true })
  }, [])

  const retry = () => {
    setCatalog(null)
    void load()
  }

  const onState = useCallback((id: string, st: IntegrationState | null) => setStates((s) => ({ ...s, [id]: st })), [])

  const openRef = useRef<string | null>(null)
  useEffect(() => {
    openRef.current = openId
  })
  // Close the form and return focus to its tile.
  const close = useCallback(() => {
    const cur = openRef.current
    setOpenId(null)
    if (cur) window.setTimeout(() => tiles.current.get(cur)?.focus(), 0)
  }, [])

  const entries = catalog?.kind === 'ok' ? catalog.entries : []
  const open = entries.find((e) => e.id === openId) ?? null

  return (
    <div className="mx-auto w-full max-w-[1120px] space-y-5 pb-6">
      <header className="pt-1">
        <h2 className="headline text-[24px]">Connections</h2>
        <p className="mt-1 text-[14px] text-ink-2">Connect the SIEM or cloud account you already use and AttackLens pulls the logs for you. Send finished incidents back the same way.</p>
      </header>

      {USE_MOCK && (
        <div role="note" className="flex items-start gap-3 rounded-2xl border border-med/60 bg-med-bg px-5 py-3.5 text-[13px] text-med-ink">
          <span className="mt-0.5 h-2.5 w-2.5 shrink-0 rounded-full bg-med" aria-hidden="true" />
          <span>Mock mode: connections are simulated in this browser only. No network call is made and nothing is saved.</span>
        </div>
      )}

      {catalog === null && (
        <div className="card">
          <Spinner label="Loading connections…" />
        </div>
      )}
      {catalog?.kind === 'missing' && (
        <div className="card">
          <EmptyState title="Connections need the updated backend">
            This server does not offer <span className="font-mono">/api/integrations/catalog</span> yet. Update and restart the backend, then try again. File uploads under “Add data” keep working.
            <div className="mt-4">
              <Button size="sm" onClick={retry}>
                Try again
              </Button>
            </div>
          </EmptyState>
        </div>
      )}
      {catalog?.kind === 'error' && (
        <div className="card">
          <ErrorNote onRetry={retry}>Could not load connections: {catalog.message}</ErrorNote>
        </div>
      )}

      {catalog?.kind === 'ok' && entries.length > 0 && <ConnectionsSummary entries={entries} states={states} checkedAt={checkedAt} onJump={jump} />}

      {catalog?.kind === 'ok' && (
        <div className={`grid gap-5 ${open ? 'lg:grid-cols-[minmax(0,1fr)_minmax(0,460px)] lg:items-start' : ''}`}>
          <div className="min-w-0 space-y-5">
            {entries.length === 0 && (
              <div className="card">
                <EmptyState title="No connections available">The server lists no connection types.</EmptyState>
              </div>
            )}
            {KIND_GROUPS.map((g) => {
              const list = entries.filter((e) => e.kind === g.kind)
              if (!list.length) return null
              return (
                <section key={g.kind} aria-labelledby={`conn-group-${g.kind}`}>
                  <div className="mb-2.5">
                    <h3 id={`conn-group-${g.kind}`} className="section-label">
                      {g.title}
                    </h3>
                    <p className="text-[13px] text-ink-2">{g.sub}</p>
                  </div>
                  <ul className={`grid gap-3 ${open ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-4'}`}>
                    {list.map((e) => (
                      <Tile
                        key={e.id}
                        entry={e}
                        st={states[e.id]}
                        selected={openId === e.id}
                        onOpen={() => setOpenId((cur) => (cur === e.id ? null : e.id))}
                        btnRef={(el) => {
                          if (el) tiles.current.set(e.id, el)
                          else tiles.current.delete(e.id)
                        }}
                      />
                    ))}
                  </ul>
                </section>
              )
            })}
          </div>
          {open && (
            <div className="min-w-0 lg:sticky lg:top-0">
              <ConnectionForm key={open.id} entry={open} initial={states[open.id] ?? null} onState={onState} onClose={close} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}
