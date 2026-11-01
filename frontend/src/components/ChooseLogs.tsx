// Step 1 of "Add data": drag-and-drop upload (XHR progress per file) or a path already on this computer.
import { useRef, useState } from 'react'
import { uploadFiles, uploadLocal, type UploadHandle, type UploadResult } from '../api'
import { ACCEPTED_EXT, fileKey, fmtBytes, mergeChosen, perFileProgress, serverNames, type Skipped } from '../lib/addData'
import { Button } from './ui'

interface Props {
  disabled: boolean
  ready: UploadResult | null
  onReady: (r: UploadResult) => void
  onReset: () => void
}

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const LOCAL_EXAMPLE = String.raw`C:\cyberforge\logs\firex-10G.log`

export function ChooseLogs({ disabled, ready, onReady, onReset }: Props) {
  const [files, setFiles] = useState<File[]>([])
  const [skipped, setSkipped] = useState<Skipped[]>([])
  const [drag, setDrag] = useState(false)
  const [progress, setProgress] = useState<{ loaded: number; total: number } | null>(null)
  const [handle, setHandle] = useState<UploadHandle | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [path, setPath] = useState('')
  const [localBusy, setLocalBusy] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const uploading = handle !== null

  const add = (list: FileList | null) => {
    if (!list) return
    // Event handler, so `files` is current; compute once (no side effects inside a state updater).
    const merged = mergeChosen(files, Array.from(list))
    setFiles(merged.files)
    setSkipped(merged.skipped)
    setError(null)
  }

  const startUpload = () => {
    if (!files.length) return
    setError(null)
    setProgress({ loaded: 0, total: files.reduce((a, f) => a + f.size, 0) })
    const h = uploadFiles(files, (loaded, total) => setProgress({ loaded, total }))
    setHandle(h)
    h.promise
      .then((r) => {
        setFiles([])
        setSkipped([])
        onReady(r)
      })
      .catch((e) => setError(msg(e)))
      .finally(() => {
        setHandle(null)
        setProgress(null)
      })
  }

  const useLocal = (e: React.FormEvent) => {
    e.preventDefault()
    if (!path.trim()) return
    setError(null)
    setLocalBusy(true)
    uploadLocal(path.trim())
      .then(onReady)
      .catch((err) => setError(`Could not use this path: ${msg(err)}`))
      .finally(() => setLocalBusy(false))
  }

  if (ready) {
    return (
      <div className="flex flex-wrap items-center gap-4 rounded-2xl border border-brand/40 bg-accent-tint px-5 py-4">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-brand text-ink" aria-hidden="true">
          <svg viewBox="0 0 12 12" className="h-3.5 w-3.5">
            <path d="M2.5 6.3l2.3 2.3 4.7-5" stroke="currentColor" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-[15px] font-semibold text-ink">
            {ready.files.length} file{ready.files.length === 1 ? '' : 's'} ready · {fmtBytes(ready.total_bytes)}
            {ready.mode && <span className="ml-2 text-[12px] font-normal text-muted">({ready.mode})</span>}
          </p>
          <p className="truncate text-[13px] text-ink-2" title={ready.files.map((f) => f.name).join(', ')}>
            {ready.files.map((f) => f.name).join(', ')}
          </p>
        </div>
        <Button variant="ghost" onClick={onReset}>
          Choose other logs
        </Button>
      </div>
    )
  }

  const sizes = files.map((f) => f.size)
  const stored = serverNames(files.map((f) => f.name))
  const renamed = files.map((f, i) => ({ from: f.name, to: stored[i] })).filter((r) => r.from !== r.to)
  const fileProg = progress ? perFileProgress(sizes, progress.loaded, progress.total) : null
  const pct = progress && progress.total > 0 ? Math.min(100, (progress.loaded / progress.total) * 100) : 0

  return (
    <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
      {/* Upload */}
      <div>
        <div
          onDragOver={(e) => {
            e.preventDefault()
            if (!disabled && !uploading) setDrag(true)
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDrag(false)
            if (!disabled && !uploading) add(e.dataTransfer.files)
          }}
          className={`flex flex-col items-center justify-center rounded-2xl border-2 border-dashed px-6 py-8 text-center ${
            drag ? 'border-brand bg-accent-tint' : 'border-line-strong bg-subtle'
          } ${disabled ? 'opacity-60' : ''}`}
        >
          <span className="mb-3 flex h-11 w-11 items-center justify-center rounded-full border border-line bg-white text-ink-2" aria-hidden="true">
            <svg viewBox="0 0 24 24" className="h-5 w-5">
              <path d="M12 15V4M7.5 8.5L12 4l4.5 4.5M5 14v5h14v-5" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <p className="text-[15px] font-semibold text-ink">Drop log files here</p>
          <p className="mt-1 text-[13px] text-muted">or</p>
          <div className="mt-2">
            <Button onClick={() => input.current?.click()} disabled={disabled || uploading}>
              Browse files
            </Button>
          </div>
          <input
            ref={input}
            type="file"
            multiple
            accept={ACCEPTED_EXT.join(',')}
            className="hidden"
            onChange={(e) => {
              add(e.target.files)
              e.target.value = ''
            }}
          />
          <p className="mt-3 text-[12px] text-muted">Accepted: {ACCEPTED_EXT.join(' ')}</p>
        </div>

        {skipped.length > 0 && (
          <div className="mt-2 text-[12px] text-med-ink" role="status">
            <p className="font-medium">
              Skipped {skipped.length} file{skipped.length === 1 ? '' : 's'}:
            </p>
            <ul className="mt-1 max-h-28 list-disc overflow-y-auto pl-5">
              {skipped.map((s, i) => (
                <li key={`${s.name}-${i}`} className="break-all">
                  <span className="font-mono">{s.name}</span> — {s.reason}
                </li>
              ))}
            </ul>
          </div>
        )}

        {renamed.length > 0 && (
          <div className="mt-2 text-[12px] text-ink-2" role="status">
            <p className="font-medium">
              Some different files share a name (e.g. from other folders). All are kept; the server adds -1, -2 to the repeats and
              will save {renamed.length === 1 ? 'it' : 'them'} as:
            </p>
            <ul className="mt-1 max-h-28 list-disc overflow-y-auto pl-5">
              {renamed.map((r, i) => (
                <li key={`${r.to}-${i}`} className="break-all font-mono">
                  {r.from} → {r.to}
                </li>
              ))}
            </ul>
          </div>
        )}

        {files.length > 0 && (
          <div className="mt-4 overflow-hidden rounded-xl border border-line bg-white">
            <ul className="max-h-48 divide-y divide-line overflow-y-auto">
              {files.map((f, i) => (
                <li key={fileKey(f)} className="flex items-center gap-3 px-4 py-2.5 text-[13px]">
                  <span className="min-w-0 flex-1 truncate font-mono text-[12.5px] text-ink" title={f.name}>
                    {f.name}
                    {stored[i] !== f.name && <span className="ml-2 text-[11px] text-muted">→ saved as {stored[i]}</span>}
                  </span>
                  <span className="shrink-0 text-muted tabular-nums">{fmtBytes(f.size)}</span>
                  {fileProg ? (
                    <span className="flex w-28 shrink-0 items-center gap-2">
                      <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-unobs">
                        <span className="block h-1.5 rounded-full bg-brand" style={{ width: `${Math.round(fileProg[i] * 100)}%` }} />
                      </span>
                      <span className="w-9 text-right text-[11px] text-muted tabular-nums">{Math.round(fileProg[i] * 100)}%</span>
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setFiles((cur) => cur.filter((x) => x !== f))}
                      className="focus-ring shrink-0 rounded-full px-2 text-[12px] text-muted hover:bg-unobs hover:text-ink"
                      aria-label={`Remove ${f.name}`}
                    >
                      Remove
                    </button>
                  )}
                </li>
              ))}
            </ul>
            <div className="flex items-center gap-3 border-t border-line bg-subtle px-4 py-3">
              <span className="text-[13px] text-ink-2">
                {files.length} file{files.length === 1 ? '' : 's'} · {fmtBytes(sizes.reduce((a, b) => a + b, 0))}
                {progress && <span className="ml-2 text-muted tabular-nums">uploading {pct.toFixed(0)}%</span>}
              </span>
              <span className="ml-auto flex gap-2">
                {uploading ? (
                  <Button variant="ghost" onClick={() => handle?.abort()}>
                    Cancel
                  </Button>
                ) : (
                  <Button variant="primary" onClick={startUpload} disabled={disabled}>
                    Upload {files.length} file{files.length === 1 ? '' : 's'}
                  </Button>
                )}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Local path */}
      <form onSubmit={useLocal} className="flex flex-col self-start rounded-2xl border border-line bg-white px-5 py-5">
        <h4 className="text-[15px] font-semibold text-ink">Use a file already on this computer</h4>
        <p className="mt-1 text-[13px] leading-relaxed text-muted">Fastest for big logs (10–50 GB): nothing is copied through the browser. Paste the full path of one log file
          (not a folder), e.g. <span className="font-mono text-ink-2">{LOCAL_EXAMPLE}</span>
        </p>
        <label className="mt-4 block">
          <span className="section-label">File path</span>
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder={LOCAL_EXAMPLE}
            disabled={disabled || localBusy}
            className="focus-ring mt-1.5 h-10 w-full rounded-lg border border-line-strong bg-white px-3 font-mono text-[13px] text-ink placeholder:text-muted disabled:opacity-60"
          />
        </label>
        <div className="mt-4">
          <Button type="submit" variant="primary" disabled={disabled || localBusy || !path.trim()}>
            {localBusy ? 'Checking…' : 'Use this file'}
          </Button>
        </div>
      </form>

      {error && (
        <p role="alert" className="rounded-xl border border-crit/30 bg-crit-bg px-4 py-2.5 text-[13px] break-words text-crit-ink lg:col-span-2">
          {error}
        </p>
      )}
    </div>
  )
}
