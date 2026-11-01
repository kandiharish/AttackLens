// Connections page grouping (cloud + identity first) and the static "Supported cloud logs" data.
// The data file is kept equal to config/sources.yaml and the connector modules by backend/tests/test_cloud_logs_ui.py.
import raw from '../../mock/integrations_cloud_logs.json'
import type { CloudLogsCatalog, IntegrationCatalogEntry, IntegrationKind } from '../../types_integrations'

export const CLOUD_LOGS = raw as unknown as CloudLogsCatalog

export interface PageGroup {
  id: string
  kinds: IntegrationKind[]
  title: string
  sub: string
  featured?: boolean
}

/** Page order: cloud & identity (featured), then SIEM, then sinks. A kind not listed here falls into "Other". */
export const PAGE_GROUPS: PageGroup[] = [
  {
    id: 'cloud',
    kinds: ['cloud', 'identity'],
    title: 'Cloud & identity',
    sub: 'Pull audit and sign-in logs straight from AWS, Azure, Google Cloud, Okta, Microsoft 365 and Google Workspace',
    featured: true,
  },
  { id: 'siem', kinds: ['siem'], title: 'SIEM', sub: 'Pull events or alerts from the SIEM you already run' },
  { id: 'sink', kinds: ['sink'], title: 'Send incidents to', sub: 'Push finished attack paths to a SIEM, SOAR or syslog' },
]

/** Entries of one group; cloud before identity inside the featured group (catalog order otherwise). */
export function groupEntries(entries: IntegrationCatalogEntry[], g: PageGroup): IntegrationCatalogEntry[] {
  return g.kinds.flatMap((k) => entries.filter((e) => e.kind === k))
}

/** Entries whose kind no group lists (a newer backend kind): shown in an "Other" group, never hidden. */
export function ungrouped(entries: IntegrationCatalogEntry[]): IntegrationCatalogEntry[] {
  const known = new Set(PAGE_GROUPS.flatMap((g) => g.kinds))
  return entries.filter((e) => !known.has(e.kind))
}

/** Short "what it pulls" text for a connector tile, or null (non-cloud connectors). */
export function pullsText(id: string): string | null {
  return CLOUD_LOGS.connectors[id]?.pulls ?? null
}

/** Counts for the panel header: providers, log types, log types a connector can pull. */
export function coverageCounts(c: CloudLogsCatalog = CLOUD_LOGS): { providers: number; logs: number; viaConnector: number; viaFile: number } {
  const rows = c.providers.flatMap((p) => p.logs)
  return {
    providers: c.providers.length,
    logs: rows.length,
    viaConnector: rows.filter((r) => r.connector).length,
    viaFile: rows.filter((r) => r.file).length,
  }
}
