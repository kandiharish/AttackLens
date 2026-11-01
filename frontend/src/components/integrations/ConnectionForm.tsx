// Settings form for one connection, generated from the catalog `fields`. Test / Save & connect / Disconnect / Remove.
// Polls GET /api/integrations/{id} every 5 s only while open and the tab is visible. Secrets are write-only.
import { useCallback, useEffect, useRef, useState } from 'react'
import { deleteIntegration, getIntegration, saveIntegration, startIntegration, stopIntegration, testIntegration } from '../../api'
import {
  DEFAULT_SINCE,
  fieldErrorOf,
  fillFromKeyFile,
  initialValue,
  isKeyFileField,
  missingRequired,
  readTextFile,
  SINCE_OPTIONS,
  tileStatus,
  toSetting,
  type FormValue,
} from '../../lib/connections'
import { fmtTs } from '../../lib/format'
import { safeHttpUrl } from '../../lib/siem'
import type { IntegrationCatalogEntry, IntegrationField, IntegrationMode, IntegrationState, IntegrationTestResult } from '../../types_integrations'
import { Button } from '../ui'
import { FieldInput, inputCls } from './FieldInput'
import { StatusDot } from './StatusDot'
import { TestResult } from './TestResult'

const POLL_MS = 5000
const msg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const fmtN = (v: number | null | undefined) => (typeof v === 'number' && Number.isFinite(v) ? v.toLocaleString('en-US') : '—')

type Busy = null | 'test' | 'save' | 'stop' | 'delete'

interface Props {
  entry: IntegrationCatalogEntry
  initial: IntegrationState | null
  onState: (id: string, st: IntegrationState | null) => void
  onClose: () => void
}

function initValues(entry: IntegrationCatalogEntry, st: IntegrationState | null): Record<string, FormValue> {
  const out: Record<string, FormValue> = {}
  for (const f of entry.fields) if (f.type !== 'secret') out[f.key] = initialValue(f, st?.settings)
  return out
}

export function ConnectionForm({ entry, initial, onState, onClose }: Props) {
  const [st, setSt] = useState<IntegrationState | null>(initial)
  const [values, setValues] = useState<Record<string, FormValue>>(() => initValues(entry, initial))
  const [secrets, setSecrets] = useState<Record<string, string>>({})
  const [replacing, setReplacing] = useState<Record<string, boolean>>({})
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [test, setTest] = useState<IntegrationTestResult | null>(null)
  const [busy, setBusy] = useState<Busy>(null)
  const [confirmRemove, setConfirmRemove] = useState(false)
  const [mode, setMode] = useState<IntegrationMode>(entry.modes?.[0] ?? 'events')
  const [since, setSince] = useState(DEFAULT_SINCE)
  const [keyNote, setKeyNote] = useState<string | null>(null)
  const [advOpen, setAdvOpen] = useState(false)
  const dirty = useRef(false)
  const heading = useRef<HTMLHeadingElement>(null)
  const keyFile = useRef<HTMLInputElement>(null)
  const isSink = entry.kind === 'sink'

  const apply = useCallback(
    (next: IntegrationState) => {
      setSt(next)
      onState(entry.id, next)
      // Fresh state from the server only refills the form while the analyst has not typed anything.
      if (!dirty.current) setValues(initValues(entry, next))
    },
    [entry, onState],
  )

  const refresh = useCallback(() => {
    getIntegration(entry.id)
      .then(apply)
      .catch(() => {
        /* keep the last known state; actions report their own errors */
      })
  }, [entry.id, apply])

  useEffect(() => {
    heading.current?.focus()
  }, [])

  // Poll every 5 s only while open and the page is visible.
  useEffect(() => {
    let t: number | null = null
    const start = () => {
      if (t === null && document.visibilityState === 'visible') t = window.setInterval(refresh, POLL_MS)
    }
    const stop = () => {
      if (t !== null) window.clearInterval(t)
      t = null
    }
    const onVis = () => {
      if (document.visibilityState === 'visible') {
        refresh()
        start()
      } else stop()
    }
    refresh()
    start()
    document.addEventListener('visibilitychange', onVis)
    return () => {
      stop()
      document.removeEventListener('visibilitychange', onVis)
    }
  }, [refresh])

  const touch = () => {
    dirty.current = true
    setNotice(null)
  }
  const setValue = (k: string, v: FormValue) => {
    touch()
    setValues((s) => ({ ...s, [k]: v }))
    setFieldErrors((e) => ({ ...e, [k]: '' }))
  }
  const setSecret = (k: string, v: string) => {
    touch()
    setSecrets((s) => ({ ...s, [k]: v }))
    setFieldErrors((e) => ({ ...e, [k]: '' }))
  }
  const setReplace = (k: string, on: boolean) => {
    touch()
    setReplacing((r) => ({ ...r, [k]: on }))
    if (!on) setSecrets((s) => ({ ...s, [k]: '' }))
  }

  /** PUT the form. Returns the saved state, or null after showing field / form errors. */
  const save = async (): Promise<IntegrationState | null> => {
    const missing = missingRequired(entry.fields, values, secrets, st?.secrets_set ?? {}, replacing)
    if (Object.keys(missing).length) {
      setFieldErrors(missing)
      if (entry.fields.some((f) => f.advanced && missing[f.key])) setAdvOpen(true)
      setFormError('Fill the required fields marked below.')
      return null
    }
    const settings: Record<string, ReturnType<typeof toSetting>> = {}
    const secretBody: Record<string, string | null> = {}
    for (const f of entry.fields) {
      if (f.type === 'secret') {
        // Omitted = keep the stored secret. Only values typed (or loaded) in this form are sent.
        const v = secrets[f.key] ?? ''
        if (v.trim()) secretBody[f.key] = v
      } else settings[f.key] = toSetting(f, values[f.key])
    }
    try {
      const next = await saveIntegration(entry.id, { settings, secrets: secretBody })
      dirty.current = false
      setSecrets({})
      setReplacing({})
      setFieldErrors({})
      apply(next)
      return next
    } catch (e) {
      const fe = fieldErrorOf(e)
      if (fe?.field && entry.fields.some((f) => f.key === fe.field)) {
        setFieldErrors({ [fe.field]: fe.error })
        if (entry.fields.some((f) => f.key === fe.field && f.advanced)) setAdvOpen(true)
        setFormError('Check the highlighted field.')
      } else setFormError(fe ? fe.error : msg(e))
      return null
    }
  }

  const run = async (kind: Exclude<Busy, null>, fn: () => Promise<void>) => {
    setBusy(kind)
    setFormError(null)
    setNotice(null)
    try {
      await fn()
    } catch (e) {
      setFormError(msg(e))
    } finally {
      setBusy(null)
    }
  }

  const onTest = () =>
    run('test', async () => {
      setTest(null)
      // The test endpoint takes no body and tests the SAVED settings, so unsaved edits are saved first.
      if (dirty.current || !st?.configured) {
        if (!(await save())) return
      }
      setTest(await testIntegration(entry.id))
    })

  const onConnect = () =>
    run('save', async () => {
      if (!(await save())) return
      const next = await startIntegration(entry.id, isSink ? { mode } : since ? { mode, since } : { mode })
      apply(next)
      const sinceLabel = SINCE_OPTIONS.find((o) => o.value === since)?.label.toLowerCase() ?? since
      setNotice(isSink ? 'Saved and connected. New incidents will be sent here.' : `Saved and connected. Pulling ${mode} (${since ? sinceLabel : 'new data only'}).`)
    })

  const onStop = () =>
    run('stop', async () => {
      await stopIntegration(entry.id)
      apply(await getIntegration(entry.id))
      setNotice('Disconnected. Settings are kept; press Save & connect to resume.')
    })

  const onRemove = () =>
    run('delete', async () => {
      await deleteIntegration(entry.id)
      setConfirmRemove(false)
      onState(entry.id, null)
      onClose()
    })

  const loadKeyFile = async (file: File | undefined) => {
    if (!file) return
    try {
      const text = await readTextFile(file)
      const fill = fillFromKeyFile(entry, text)
      if (!fill) setKeyNote(`${file.name} is not a JSON object.`)
      else if (!fill.filled.length) setKeyNote(`No matching keys found in ${file.name}.`)
      else {
        touch()
        setValues((s) => ({ ...s, ...fill.settings }))
        setSecrets((s) => ({ ...s, ...fill.secrets }))
        setReplacing((r) => ({ ...r, ...Object.fromEntries(Object.keys(fill.secrets).map((k) => [k, true])) }))
        setKeyNote(`Filled from ${file.name}: ${fill.filled.join(', ')}. Press Save & connect to send them.`)
      }
    } catch (e) {
      setKeyNote(msg(e))
    } finally {
      if (keyFile.current) keyFile.current.value = ''
    }
  }

  const status = tileStatus(entry.kind, st)
  const docs = safeHttpUrl(entry.docs_url)
  const disabled = busy !== null
  const formLoader = (entry.kind === 'cloud' || entry.kind === 'identity') && !entry.fields.some(isKeyFileField)
  const titleId = `conn-${entry.id}-title`
  const basicFields = entry.fields.filter((f) => !f.advanced)
  const advancedFields = entry.fields.filter((f) => f.advanced)
  const advSummary = [
    entry.modes?.length ? `mode ${mode}` : '',
    !isSink ? (since ? `since ${since}` : 'new data only') : '',
    advancedFields.length ? `${advancedFields.length} more setting${advancedFields.length === 1 ? '' : 's'}` : '',
  ]
    .filter(Boolean)
    .join(' · ')
  const renderField = (f: IntegrationField) => (
    <FieldInput
      key={f.key}
      field={f}
      value={values[f.key]}
      secret={secrets[f.key] ?? ''}
      saved={!!st?.secrets_set?.[f.key]}
      replacing={!!replacing[f.key]}
      error={fieldErrors[f.key] || null}
      disabled={disabled}
      onValue={(v) => setValue(f.key, v)}
      onSecret={(v) => setSecret(f.key, v)}
      onReplace={(on) => setReplace(f.key, on)}
    />
  )

  return (
    <section
      id={`conn-form-${entry.id}`}
      className="card overflow-hidden"
      aria-labelledby={titleId}
      onKeyDown={(e) => {
        if (e.key === 'Escape' && !disabled) {
          e.stopPropagation()
          if (confirmRemove) setConfirmRemove(false)
          else onClose()
        }
      }}
    >
      <header className="flex items-start gap-3 border-b border-line px-5 py-4 sm:px-6">
        <div className="min-w-0">
          <div className="section-label">{entry.kind === 'sink' ? 'Send incidents to' : entry.kind === 'cloud' ? 'Cloud source' : entry.kind === 'identity' ? 'Identity / SaaS source' : 'SIEM source'}</div>
          <h3 id={titleId} ref={heading} tabIndex={-1} className="headline mt-0.5 text-[18px] outline-none">
            {entry.name}
          </h3>
          <p className="mt-1 flex items-center gap-2 text-[13px] text-ink-2">
            <StatusDot tone={status.tone} />
            {status.label}
          </p>
          {docs && (
            <a href={docs} target="_blank" rel="noopener noreferrer" className="focus-ring mt-1 inline-block rounded text-[12px] font-medium text-accent underline-offset-2 hover:underline">
              How to get these credentials ↗
            </a>
          )}
        </div>
        <span className="ml-auto">
          <Button size="sm" variant="ghost" onClick={onClose} title="Close (Esc)" disabled={disabled}>
            Close
          </Button>
        </span>
      </header>

      {st?.configured && (
        <div className="border-b border-line bg-subtle px-5 py-3 text-[12px] text-ink-2 sm:px-6" aria-live="polite">
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 sm:grid-cols-4">
            <div>
              <dt className="section-label !text-[10px]">{isSink ? 'Last push' : 'Last pull'}</dt>
              <dd className="tabular-nums">{st.status?.last_pull ? `${fmtTs(st.status.last_pull)} UTC` : 'never'}</dd>
            </div>
            {!isSink && (
              <div>
                <dt className="section-label !text-[10px]">Pulled</dt>
                <dd className="tabular-nums">{fmtN(st.status?.pulled)}</dd>
              </div>
            )}
            <div>
              <dt className="section-label !text-[10px]">{isSink ? 'Sent' : 'Written'}</dt>
              <dd className="tabular-nums">{fmtN(st.status?.written)}</dd>
            </div>
            <div>
              <dt className="section-label !text-[10px]">Failed</dt>
              <dd className={`tabular-nums ${(st.status?.failed ?? 0) > 0 ? 'font-semibold text-crit-ink' : ''}`}>{fmtN(st.status?.failed)}</dd>
            </div>
          </dl>
          {status.error && <p className="mt-2 break-words text-crit-ink">Last error: {status.error}</p>}
        </div>
      )}

      <form
        className="space-y-4 px-5 py-5 sm:px-6"
        noValidate
        onSubmit={(e) => {
          e.preventDefault()
          if (!disabled) void onConnect()
        }}
      >
        {formLoader && (
          <div className="rounded-xl border border-dashed border-line-strong bg-subtle px-4 py-3">
            <p className="text-[13px] text-ink-2">Have a credentials JSON file? Load it to fill the matching fields. It is read in this browser and only sent when you save.</p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <input ref={keyFile} type="file" accept=".json,application/json" className="sr-only" tabIndex={-1} aria-hidden="true" onChange={(e) => void loadKeyFile(e.target.files?.[0])} />
              <Button size="sm" onClick={() => keyFile.current?.click()} disabled={disabled}>
                Load key file…
              </Button>
              {keyNote && (
                <span className="text-[12px] text-muted" role="status">
                  {keyNote}
                </span>
              )}
            </div>
          </div>
        )}

        {basicFields.map(renderField)}

        {(!!entry.modes?.length || !isSink || advancedFields.length > 0) && (
          <details className="group rounded-xl border border-line" open={advOpen} onToggle={(e) => setAdvOpen(e.currentTarget.open)}>
            <summary className="focus-ring cursor-pointer list-none rounded-xl px-4 py-2.5 text-[13px] font-medium text-ink-2 hover:text-ink">
              <span className="mr-1.5 inline-block transition-transform group-open:rotate-90" aria-hidden="true">
                ›
              </span>
              Advanced
              <span className="ml-2 text-[12px] font-normal text-muted">{advSummary}</span>
            </summary>
            {advancedFields.length > 0 && <div className="space-y-4 border-t border-line px-4 py-4">{advancedFields.map(renderField)}</div>}
            {(!!entry.modes?.length || !isSink) && (
            <div className="grid gap-4 border-t border-line px-4 py-4 sm:grid-cols-2">
              {!!entry.modes?.length && (
                <label className="block text-[13px] font-medium text-ink">
                  What to pull
                  <select value={mode} onChange={(e) => setMode(e.target.value as IntegrationMode)} disabled={disabled} className={`${inputCls} mt-1.5 border-line-strong font-normal`}>
                    {entry.modes.map((m) => (
                      <option key={m} value={m}>
                        {m === 'events' ? 'Raw events (AttackLens detects)' : 'SIEM alerts (vendor labels)'}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              {!isSink && (
                <label className="block text-[13px] font-medium text-ink">
                  Start from
                  <select value={since} onChange={(e) => setSince(e.target.value)} disabled={disabled} className={`${inputCls} mt-1.5 border-line-strong font-normal`}>
                    {SINCE_OPTIONS.map((o) => (
                      <option key={o.value || 'now'} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                </label>
              )}
            </div>
            )}
          </details>
        )}

        {formError && (
          <p role="alert" className="rounded-xl border border-crit/30 bg-crit-bg px-4 py-3 text-[13px] break-words text-crit-ink">
            {formError}
          </p>
        )}
        {notice && (
          <p role="status" className="rounded-xl border border-brand/40 bg-accent-tint px-4 py-3 text-[13px] text-accent">
            {notice}
          </p>
        )}
        {test && <TestResult test={test} />}

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <Button type="submit" variant="primary" disabled={disabled}>
            {busy === 'save' ? 'Connecting…' : st?.running ? 'Save & reconnect' : 'Save & connect'}
          </Button>
          <Button onClick={() => void onTest()} disabled={disabled} title="Saves unsaved changes first, then tests the saved settings">
            {busy === 'test' ? 'Testing…' : 'Test connection'}
          </Button>
          {st?.running && (
            <Button variant="ghost" onClick={() => void onStop()} disabled={disabled}>
              {busy === 'stop' ? 'Disconnecting…' : 'Disconnect'}
            </Button>
          )}
          {st?.configured && !confirmRemove && (
            <span className="ml-auto">
              <Button variant="ghost" onClick={() => setConfirmRemove(true)} disabled={disabled}>
                Remove
              </Button>
            </span>
          )}
        </div>

        {confirmRemove && (
          <div role="group" aria-label="Confirm remove" className="flex flex-wrap items-center gap-2 rounded-xl border border-crit/30 bg-crit-bg px-4 py-3">
            <p className="min-w-0 flex-1 text-[13px] text-crit-ink">Remove {entry.name}? This stops it and deletes its saved settings and secrets.</p>
            <button
              type="button"
              autoFocus
              onClick={() => void onRemove()}
              disabled={disabled}
              className="focus-ring inline-flex h-7 items-center rounded-full border border-crit bg-crit px-3 text-[12px] font-medium text-white hover:bg-crit-ink disabled:cursor-not-allowed disabled:opacity-45"
            >
              {busy === 'delete' ? 'Removing…' : 'Yes, remove'}
            </button>
            <Button size="sm" onClick={() => setConfirmRemove(false)} disabled={disabled}>
              Cancel
            </Button>
          </div>
        )}
      </form>
    </section>
  )
}
