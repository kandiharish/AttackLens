// "Supported cloud logs": provider -> log types -> how each is ingested (connector / file) and whether detection rules
// read it. Compact one-row-per-provider table, plus a details table on demand. Static data
// (integrations_cloud_logs.json), kept equal to config/sources.yaml and the connectors by test_cloud_logs_ui.py.
import { Fragment, useId, useState } from 'react'
import type { CloudLogProvider, CloudLogRow, IntegrationCatalogEntry } from '../../types_integrations'
import { CLOUD_LOGS, coverageCounts } from './cloudLogs'

interface Props {
  /** Catalog entries by id (connector display names; a connector absent from the server's catalog is plain text). */
  byId: Map<string, IntegrationCatalogEntry>
  /** Open a connector's form (same as clicking its tile). */
  onOpenConnector: (id: string) => void
}

const chip = 'inline-flex items-center rounded-full border px-2 text-[11px] leading-[20px] font-medium whitespace-nowrap'
const shortName = (e: IntegrationCatalogEntry) => e.name.split(' (')[0]

function ConnectorChip({ id, scope, byId, onOpenConnector }: { id: string; scope?: string[] } & Props) {
  const entry = byId.get(id)
  const sc = scope?.length ? ` (${scope.join(', ')})` : ''
  if (!entry)
    return (
      <span className={`${chip} border-accent/40 bg-accent-tint text-accent`} title={`Connector ${id}${sc}`}>
        <span className="sr-only">Connector: </span>
        {id}
      </span>
    )
  return (
    <button
      type="button"
      onClick={() => onOpenConnector(entry.id)}
      title={`Pulled by the ${entry.name} connector${sc}. Open its settings.`}
      className={`${chip} focus-ring border-accent/40 bg-accent-tint text-accent hover:border-accent hover:text-accent-hover`}
    >
      <span className="sr-only">Connector: </span>
      {shortName(entry)}
    </button>
  )
}

/** Comma-separated short names; context-only logs are muted and say so (also to screen readers). */
function LogList({ rows }: { rows: CloudLogRow[] }) {
  if (!rows.length) return <span className="text-muted">—</span>
  return (
    <>
      {rows.map((r, i) => (
        <Fragment key={r.source_type}>
          {i > 0 && ', '}
          <span className={r.detection === 'context' ? 'text-muted' : 'text-ink'} title={r.log}>
            {r.short}
            {r.detection === 'context' && <span className="text-[11px]"> (context)</span>}
          </span>
        </Fragment>
      ))}
    </>
  )
}

function ProviderRow({ p, byId, onOpenConnector }: { p: CloudLogProvider } & Props) {
  const connectorIds = [...new Set(p.logs.map((r) => r.connector).filter((c): c is string => !!c))]
  const fileOnly = p.logs.filter((r) => !r.connector)
  return (
    <tr className="border-b border-line align-top last:border-b-0">
      <th scope="row" className="px-3 py-2 text-left font-semibold text-ink">
        {p.provider}
      </th>
      <td className="px-3 py-2">
        {connectorIds.length === 0 ? (
          <span className="text-muted">—</span>
        ) : (
          <div className="space-y-1">
            {connectorIds.map((id) => (
              <div key={id} className="flex flex-wrap items-baseline gap-x-1.5 gap-y-1">
                <ConnectorChip id={id} byId={byId} onOpenConnector={onOpenConnector} />
                <span>
                  <LogList rows={p.logs.filter((r) => r.connector === id)} />
                </span>
              </div>
            ))}
          </div>
        )}
      </td>
      <td className="px-3 py-2">
        <LogList rows={fileOnly} />
      </td>
    </tr>
  )
}

function DetailsTable({ byId, onOpenConnector }: Props) {
  const th = 'border-b border-line bg-subtle px-3 py-2 text-left section-label !text-[10px]'
  return (
    <table className="w-full min-w-[560px] table-fixed border-collapse text-[12.5px]">
      <caption className="sr-only">Every supported cloud and identity log: source type, how it is ingested and whether detection rules read it</caption>
      <colgroup>
        <col />
        <col className="w-[30%]" />
        <col className="w-[104px]" />
      </colgroup>
      <thead>
        <tr>
          <th scope="col" className={th}>
            Log type
          </th>
          <th scope="col" className={th}>
            Ingest via
          </th>
          <th scope="col" className={th}>
            Detection
          </th>
        </tr>
      </thead>
      {CLOUD_LOGS.providers.map((p) => (
        <tbody key={p.provider}>
          <tr>
            <th scope="rowgroup" colSpan={3} className="px-3 pt-3 pb-1 text-left text-[12px] font-semibold text-ink">
              {p.provider}
            </th>
          </tr>
          {p.logs.map((r) => (
            <tr key={r.source_type} className="border-b border-line align-top last:border-b-0">
              <th scope="row" className="px-3 py-1.5 text-left font-normal text-ink">
                <span className="block">{r.log}</span>
                <span className="block text-[11px] text-muted">
                  <span className="font-mono">{r.source_type}</span>
                  {r.note && <> · {r.note}</>}
                </span>
              </th>
              <td className="px-3 py-1.5">
                <div className="flex flex-wrap items-center gap-1.5">
                  {r.file && <span className={`${chip} border-line-strong bg-subtle text-ink-2`}>File</span>}
                  {r.connector && <ConnectorChip id={r.connector} scope={r.connector_scope} byId={byId} onOpenConnector={onOpenConnector} />}
                </div>
              </td>
              <td className="px-3 py-1.5">
                {r.detection === 'context' ? (
                  <span className={`${chip} border-line bg-unobs text-muted`} title="Shown on the timeline and counted; no scored detection rule reads vendor verdicts.">
                    Context only
                  </span>
                ) : (
                  <span className={`${chip} border-low/50 bg-low-bg text-low-ink`}>Rules</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      ))}
    </table>
  )
}

export function CloudLogsPanel({ byId, onOpenConnector }: Props) {
  const [details, setDetails] = useState(false)
  const headId = useId()
  const detailsId = useId()
  const n = coverageCounts()
  const th = 'border-b border-line bg-subtle px-3 py-2 text-left section-label !text-[10px]'
  return (
    <section aria-labelledby={headId} className="rounded-2xl border border-line bg-panel shadow-card">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 px-4 pt-3">
        <h4 id={headId} className="headline text-[14px]">
          Supported cloud logs
        </h4>
        <span className="text-[12px] text-ink-2">
          {n.logs} log types · {n.providers} providers · {n.viaConnector} pulled by a connector · {n.viaFile === n.logs ? `all ${n.logs}` : n.viaFile} from files
        </span>
      </div>
      <div className="overflow-x-auto px-4 pt-2">
        <table className="w-full min-w-[560px] table-fixed border-collapse text-[12.5px]">
          <caption className="sr-only">Supported cloud and identity logs per provider: pulled by a connector, or ingested from exported files only</caption>
          <colgroup>
            <col className="w-[132px]" />
            <col />
            <col className="w-[40%]" />
          </colgroup>
          <thead>
            <tr>
              <th scope="col" className={th}>
                Provider
              </th>
              <th scope="col" className={th}>
                Connector (or file)
              </th>
              <th scope="col" className={th}>
                File upload only
              </th>
            </tr>
          </thead>
          <tbody>
            {CLOUD_LOGS.providers.map((p) => (
              <ProviderRow key={p.provider} p={p} byId={byId} onOpenConnector={onOpenConnector} />
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-4 py-3 text-[12px] text-ink-2">
        <p className="max-w-[80ch]">
          Files: drop the exported JSON / CSV under “Add data”; gzip, {'{"Records": [...]}'} and EventBridge / Pub/Sub envelopes are unpacked.
          “(context)” = shown on the timeline, not used by detection rules.
        </p>
        <button
          type="button"
          onClick={() => setDetails((d) => !d)}
          aria-expanded={details}
          aria-controls={detailsId}
          className="focus-ring rounded-full border border-line-strong bg-panel px-3 py-1 text-[12px] font-medium text-ink hover:border-ink"
        >
          {details ? 'Hide details' : 'Show details'}
        </button>
      </div>
      <div id={detailsId} hidden={!details} className="overflow-x-auto border-t border-line px-4 pt-1 pb-4">
        {details && <DetailsTable byId={byId} onOpenConnector={onOpenConnector} />}
      </div>
    </section>
  )
}
