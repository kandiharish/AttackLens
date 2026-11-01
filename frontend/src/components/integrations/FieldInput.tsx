// One generated form field (text / url / number / bool / select / secret). All values render as text, never HTML.
import { useId, useRef, useState } from 'react'
import { isKeyFileField, optionList, readTextFile, type FormValue } from '../../lib/connections'
import type { IntegrationField } from '../../types_integrations'
import { Button } from '../ui'

export const inputCls =
  'focus-ring h-9 w-full rounded-lg border bg-white px-3 text-[13px] text-ink placeholder:text-muted disabled:cursor-not-allowed disabled:bg-subtle'

interface Props {
  field: IntegrationField
  value: FormValue | undefined
  secret: string
  /** Secret already stored server-side (secrets_set[key]). */
  saved: boolean
  replacing: boolean
  error: string | null
  disabled: boolean
  onValue: (v: FormValue) => void
  onSecret: (v: string) => void
  onReplace: (on: boolean) => void
}

function Label({ id, field }: { id: string; field: IntegrationField }) {
  return (
    <label htmlFor={id} className="mb-1.5 flex items-center gap-1.5 text-[13px] font-medium text-ink">
      {field.label}
      {field.required ? (
        <span className="text-crit-ink" aria-hidden="true">
          *
        </span>
      ) : (
        <span className="text-[11px] font-normal text-muted">optional</span>
      )}
    </label>
  )
}

export function FieldInput({ field, value, secret, saved, replacing, error, disabled, onValue, onSecret, onReplace }: Props) {
  const id = useId()
  const helpId = `${id}-help`
  const errId = `${id}-err`
  const describedBy = [field.help ? helpId : '', error ? errId : ''].filter(Boolean).join(' ') || undefined
  const border = error ? 'border-crit' : 'border-line-strong'

  const help = field.help && (
    <p id={helpId} className="mt-1 text-[12px] text-muted">
      {field.help}
    </p>
  )
  const err = error && (
    <p id={errId} className="mt-1 text-[12px] font-medium text-crit-ink">
      {error}
    </p>
  )

  if (field.type === 'bool') {
    return (
      <div>
        <label htmlFor={id} className="flex cursor-pointer items-center gap-2.5 text-[13px] font-medium text-ink">
          <input
            id={id}
            type="checkbox"
            checked={value === true}
            onChange={(e) => onValue(e.target.checked)}
            disabled={disabled}
            aria-describedby={describedBy}
            aria-invalid={!!error || undefined}
            className="focus-ring h-4 w-4 rounded accent-[#027a47]"
          />
          {field.label}
        </label>
        {help}
        {err}
      </div>
    )
  }

  if (field.type === 'secret') {
    return (
      <div>
        <Label id={id} field={field} />
        {saved && !replacing ? (
          <div className="flex items-center gap-2">
            <span id={id} className="inline-flex h-9 min-w-0 flex-1 items-center rounded-lg border border-line bg-subtle px-3 font-mono text-[13px] text-ink-2" aria-label={`${field.label}: saved`}>
              •••• saved
            </span>
            <Button size="sm" onClick={() => onReplace(true)} disabled={disabled}>
              Replace
            </Button>
          </div>
        ) : (
          <SecretInput id={id} field={field} value={secret} onChange={onSecret} disabled={disabled} invalid={!!error} describedBy={describedBy} border={border} />
        )}
        {saved && replacing && (
          <button type="button" className="focus-ring mt-1 rounded text-[12px] font-medium text-accent underline-offset-2 hover:underline" onClick={() => onReplace(false)} disabled={disabled}>
            Keep the saved value
          </button>
        )}
        {help}
        {err}
      </div>
    )
  }

  const v = typeof value === 'string' ? value : ''
  return (
    <div>
      <Label id={id} field={field} />
      {field.type === 'select' ? (
        <select
          id={id}
          value={v}
          onChange={(e) => onValue(e.target.value)}
          disabled={disabled}
          aria-describedby={describedBy}
          aria-invalid={!!error || undefined}
          aria-required={field.required || undefined}
          className={`${inputCls} ${border}`}
        >
          {!field.required && <option value="">—</option>}
          {optionList(field.options).map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      ) : (
        <input
          id={id}
          type={field.type === 'number' ? 'number' : field.type === 'url' ? 'url' : 'text'}
          inputMode={field.type === 'number' ? 'numeric' : undefined}
          value={v}
          placeholder={field.placeholder}
          onChange={(e) => onValue(e.target.value)}
          disabled={disabled}
          aria-describedby={describedBy}
          aria-invalid={!!error || undefined}
          aria-required={field.required || undefined}
          autoComplete="off"
          spellCheck={false}
          className={`${inputCls} ${border} ${field.type === 'url' || field.type === 'number' ? 'font-mono' : ''}`}
        />
      )}
      {help}
      {err}
    </div>
  )
}

function SecretInput({
  id,
  field,
  value,
  onChange,
  disabled,
  invalid,
  describedBy,
  border,
}: {
  id: string
  field: IntegrationField
  value: string
  onChange: (v: string) => void
  disabled: boolean
  invalid: boolean
  describedBy: string | undefined
  border: string
}) {
  const [shown, setShown] = useState(false)
  const [fileNote, setFileNote] = useState<string | null>(null)
  const file = useRef<HTMLInputElement>(null)
  const keyFile = isKeyFileField(field)

  const load = async (f: File | undefined) => {
    if (!f) return
    try {
      const text = await readTextFile(f)
      JSON.parse(text) // validate only; the content is never logged or shown
      onChange(text)
      setFileNote(`Loaded ${f.name}`)
    } catch (e) {
      setFileNote(e instanceof SyntaxError ? `${f.name} is not a valid JSON file.` : e instanceof Error ? e.message : 'Could not read the file.')
    } finally {
      if (file.current) file.current.value = ''
    }
  }

  const toggle = (
    <Button size="sm" variant="ghost" onClick={() => setShown((s) => !s)} pressed={shown} disabled={disabled} title={shown ? `Hide ${field.label}` : `Show ${field.label}`}>
      {shown ? 'Hide' : 'Show'}
    </Button>
  )

  if (keyFile) {
    // Multi-line key (service-account JSON). Hidden = blurred-out text so it is not shoulder-surfed.
    return (
      <div>
        <textarea
          id={id}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          rows={4}
          placeholder={field.placeholder ?? 'Paste the JSON key here, or load the file'}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          aria-required={field.required || undefined}
          autoComplete="off"
          spellCheck={false}
          className={`focus-ring w-full rounded-lg border bg-white px-3 py-2 font-mono text-[12px] text-ink placeholder:text-muted ${border} ${shown || !value ? '' : 'text-transparent [text-shadow:0_0_6px_rgba(10,10,10,0.55)]'}`}
        />
        <div className="mt-1.5 flex flex-wrap items-center gap-2">
          <input ref={file} type="file" accept=".json,application/json" className="sr-only" tabIndex={-1} aria-hidden="true" onChange={(e) => void load(e.target.files?.[0])} />
          <Button size="sm" onClick={() => file.current?.click()} disabled={disabled}>
            Load JSON file…
          </Button>
          {toggle}
          {fileNote && (
            <span className="text-[12px] text-muted" role="status">
              {fileNote}
            </span>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2">
      <input
        id={id}
        type={shown ? 'text' : 'password'}
        value={value}
        placeholder={field.placeholder}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        aria-describedby={describedBy}
        aria-invalid={invalid || undefined}
        aria-required={field.required || undefined}
        autoComplete="new-password"
        spellCheck={false}
        className={`${inputCls} ${border} min-w-0 flex-1 font-mono`}
      />
      {toggle}
    </div>
  )
}
