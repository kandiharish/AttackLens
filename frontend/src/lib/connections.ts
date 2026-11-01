// Connections helpers (pure): tile status, form value conversion, 422 parsing, key-file mapping.
// Secrets are never logged, stored in the browser beyond the open form, or echoed in error messages.
import { ApiError } from '../api'
import type {
  IntegrationCatalogEntry,
  IntegrationField,
  IntegrationKind,
  IntegrationOption,
  IntegrationState,
  IntegrationValue,
} from '../types_integrations'

export const KIND_GROUPS: { kind: IntegrationKind; title: string; sub: string }[] = [
  { kind: 'siem', title: 'SIEM', sub: 'Pull events or alerts from the SIEM you already run' },
  { kind: 'cloud', title: 'Cloud', sub: 'Pull audit logs straight from a cloud account' },
  { kind: 'sink', title: 'Send incidents to', sub: 'Push finished attack paths to a SIEM, SOAR or syslog' },
]

/** "Since" choices for the first pull; values follow the config default_since style ("24h"). "" = only new data. */
export const SINCE_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'Only new data from now on' },
  { value: '1h', label: 'Last 1 hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
]
export const DEFAULT_SINCE = '24h'

export type Tone = 'off' | 'idle' | 'ok' | 'err'

export interface TileStatus {
  tone: Tone
  label: string
  error: string | null
}

export function tileStatus(kind: IntegrationKind, st: IntegrationState | null | undefined): TileStatus {
  if (!st || !st.configured) return { tone: 'off', label: 'Not connected', error: null }
  const err = st.status?.last_error || null
  if (err) return { tone: 'err', label: 'Error', error: err }
  if (st.running) return { tone: 'ok', label: kind === 'sink' ? 'Connected · sending' : 'Connected · pulling', error: null }
  return { tone: 'idle', label: 'Saved · stopped', error: null }
}

export function optionList(opts: IntegrationOption[] | undefined): { value: string; label: string }[] {
  return (opts ?? []).map((o) => (typeof o === 'string' ? { value: o, label: o } : { value: String(o.value), label: o.label ?? String(o.value) }))
}

/** Form value of a non-secret field: string for inputs/selects, boolean for checkboxes. */
export type FormValue = string | boolean

export function initialValue(f: IntegrationField, settings: Record<string, IntegrationValue> | undefined): FormValue {
  const has = settings && Object.prototype.hasOwnProperty.call(settings, f.key)
  const v = has ? settings[f.key] : f.default
  if (f.type === 'bool') return v === true || v === 'true'
  if (v === null || v === undefined) {
    if (f.type === 'select' && f.required) return optionList(f.options)[0]?.value ?? ''
    return ''
  }
  return String(v)
}

/** Form value -> JSON setting. Numbers are sent as numbers; empty optional fields as null. */
export function toSetting(f: IntegrationField, v: FormValue | undefined): IntegrationValue {
  if (f.type === 'bool') return v === true
  const s = typeof v === 'string' ? v.trim() : ''
  if (s === '') return null
  if (f.type === 'number') {
    const n = Number(s)
    return Number.isFinite(n) ? n : s // let the server reject non-numbers with a 422 on this field
  }
  return s
}

/** Client-side check of required fields (the server re-validates and may answer 422). */
export function missingRequired(
  fields: IntegrationField[],
  values: Record<string, FormValue>,
  secrets: Record<string, string>,
  secretsSet: Record<string, boolean>,
  replacing: Record<string, boolean>,
): Record<string, string> {
  const out: Record<string, string> = {}
  for (const f of fields) {
    if (!f.required || f.type === 'bool') continue
    if (f.type === 'secret') {
      const kept = secretsSet[f.key] && !replacing[f.key]
      if (!kept && !(secrets[f.key] ?? '').trim()) out[f.key] = `${f.label} is required`
    } else if (toSetting(f, values[f.key]) === null) out[f.key] = `${f.label} is required`
  }
  return out
}

/**
 * Field error from a failed PUT: {error, field} (contract), {detail: {error, field}} (FastAPI HTTPException) or
 * FastAPI's own [{loc, msg}] validation list. field = null when the error is not tied to a field.
 */
export function fieldErrorOf(e: unknown): { field: string | null; error: string } | null {
  if (!(e instanceof ApiError) || e.status !== 422) return null
  const b = e.body as Record<string, unknown> | undefined
  const pick = (o: unknown) => {
    if (!o || typeof o !== 'object') return null
    const r = o as Record<string, unknown>
    if (typeof r.error !== 'string') return null
    return { field: typeof r.field === 'string' && r.field ? r.field : null, error: r.error }
  }
  const direct = pick(b) ?? pick(b?.detail)
  if (direct) return direct
  const d = b?.detail
  if (Array.isArray(d) && d[0] && typeof d[0] === 'object') {
    const first = d[0] as { loc?: unknown; msg?: unknown }
    const loc = Array.isArray(first.loc) ? first.loc : []
    const last = loc.length ? String(loc[loc.length - 1]) : null
    return { field: last, error: typeof first.msg === 'string' ? first.msg : 'Invalid value' }
  }
  return { field: null, error: 'The server rejected these settings.' }
}

/** Secret fields that hold a whole key file (service-account JSON etc.): multi-line input + "Load file". */
export function isKeyFileField(f: IntegrationField): boolean {
  return f.type === 'secret' && /json|credential|service_account|key_file|keyfile/i.test(`${f.key} ${f.label}`)
}

/** Entries that accept a credentials file (cloud kinds, or any entry with a key-file field). */
export function acceptsKeyFile(entry: IntegrationCatalogEntry): boolean {
  return entry.kind === 'cloud' || entry.fields.some(isKeyFileField)
}

const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '')

/** Known aliases in vendor key files (AWS CLI / STS JSON, GCP service-account JSON, Azure SP JSON). */
const ALIASES: Record<string, string[]> = {
  accesskeyid: ['accesskeyid', 'awsaccesskeyid'],
  secretaccesskey: ['secretaccesskey', 'awssecretaccesskey'],
  sessiontoken: ['sessiontoken', 'awssessiontoken'],
  projectid: ['projectid'],
  tenantid: ['tenantid', 'tenant'],
  clientid: ['clientid', 'appid'],
  clientsecret: ['clientsecret', 'password'],
  region: ['region'],
}

export interface KeyFileFill {
  settings: Record<string, string>
  secrets: Record<string, string>
  filled: string[]
}

/**
 * Map a parsed JSON key file onto the form. Whole-file fields (isKeyFileField) get the raw text; other fields
 * get a top-level value whose key matches the field key or a known alias. Returns labels of filled fields only.
 */
export function fillFromKeyFile(entry: IntegrationCatalogEntry, text: string): KeyFileFill | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return null
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null
  // AWS STS output nests the keys under "Credentials".
  const obj = parsed as Record<string, unknown>
  const flat: Record<string, unknown> = { ...obj, ...(obj.Credentials && typeof obj.Credentials === 'object' ? (obj.Credentials as Record<string, unknown>) : {}) }
  const byNorm = new Map(Object.entries(flat).map(([k, v]) => [norm(k), v]))
  const out: KeyFileFill = { settings: {}, secrets: {}, filled: [] }
  for (const f of entry.fields) {
    if (isKeyFileField(f)) {
      out.secrets[f.key] = text
      out.filled.push(f.label)
      continue
    }
    if (f.type === 'bool' || f.type === 'number') continue
    const keys = ALIASES[norm(f.key)] ?? [norm(f.key)]
    const hit = keys.map((k) => byNorm.get(k)).find((v) => typeof v === 'string' && v)
    if (typeof hit !== 'string') continue
    if (f.type === 'secret') out.secrets[f.key] = hit
    else out.settings[f.key] = hit
    out.filled.push(f.label)
  }
  return out
}

/** Max size of a key file read in the browser. */
export const KEY_FILE_MAX_BYTES = 64 * 1024

export function readTextFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    if (file.size > KEY_FILE_MAX_BYTES) {
      reject(new Error(`File is larger than ${KEY_FILE_MAX_BYTES / 1024} KB; a key file is much smaller.`))
      return
    }
    const r = new FileReader()
    r.onload = () => resolve(typeof r.result === 'string' ? r.result : '')
    r.onerror = () => reject(new Error('Could not read the file.'))
    r.readAsText(file)
  })
}
