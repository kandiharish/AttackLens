export const TABS = ['overview', 'steps', 'graph', 'evidence', 'reach', 'report'] as const
export type Tab = (typeof TABS)[number]
export const TAB_LABEL: Record<Tab, string> = { overview: 'Overview', steps: 'Step by step', graph: 'Graph', evidence: 'Evidence', reach: 'Reach next', report: 'Report' }
