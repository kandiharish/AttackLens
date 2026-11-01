// Badge + popup + full report for one integrity source. Popup policy:
//   'alarming': popup when a report is tampered / suspect / looks generated; a later report of the same lineage
//               (quick -> full) pops again only if the verdict got worse or it newly looks generated.
//   'load':     popup only for the first report received (app load), and only if tampered.
// A dismissed popup is remembered per (set, generated_at) in localStorage.
import { useState } from 'react'
import type { IntegrityReport } from '../../types'
import { isDismissed, rememberDismissed, reportKey, shouldPopup, type IntegrityState } from '../../lib/integrity'
import { HealthBadge } from './HealthBadge'
import { IntegrityPanel } from './IntegrityPanel'
import { TamperDialog } from './TamperDialog'

interface Props {
  state: IntegrityState
  popup: 'alarming' | 'load' | 'off'
  compact?: boolean
}

export function IntegrityStatus({ state, popup, compact = false }: Props) {
  const [dialog, setDialog] = useState<IntegrityReport | null>(null)
  const [panel, setPanel] = useState<IntegrityReport | null>(null)
  const [seenKey, setSeenKey] = useState<string | null>(null)
  const [base, setBase] = useState<IntegrityReport | null>(null)
  const [resolved, setResolved] = useState(false)

  // Decide once per new report (React "adjust state when a prop changes" pattern: no effect, no extra paint).
  const report = state.status === 'done' ? state.report : null
  const key = report ? reportKey(report) : null
  if (key !== seenKey) {
    setSeenKey(key)
    if (report) {
      const want = popup === 'alarming' ? shouldPopup(base, report) : popup === 'load' ? !resolved && report.verdict === 'tampered' : false
      if (want && !isDismissed(report)) setDialog(report)
      setBase(report)
    }
  }
  if (!resolved && (state.status === 'done' || state.status === 'absent' || state.status === 'failed')) setResolved(true)

  const closeDialog = () => {
    if (dialog) rememberDismissed(dialog)
    setDialog(null)
  }

  return (
    <>
      <HealthBadge state={state} compact={compact} onOpen={report ? () => setPanel(report) : undefined} />
      {dialog && (
        <TamperDialog
          report={dialog}
          onClose={closeDialog}
          onViewReport={() => {
            const r = dialog
            closeDialog()
            setPanel(r)
          }}
        />
      )}
      {panel && <IntegrityPanel report={panel} onClose={() => setPanel(null)} />}
    </>
  )
}
