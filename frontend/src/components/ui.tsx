// Shared UI primitives (premium theme). All text is rendered as React text nodes.
import { useState, type ReactNode } from 'react'
import { isFirewall } from '../lib/entity'
import { riskStyle } from '../lib/format'

export function RiskPill({ risk, showLabel = false, size = 'md' }: { risk: number; showLabel?: boolean; size?: 'md' | 'lg' }) {
  const rs = riskStyle(risk)
  const sz = size === 'lg' ? 'h-7 px-2.5 text-[13px]' : 'h-6 px-2 text-[12px]'
  return (
    <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border font-mono font-semibold tabular-nums ${sz} ${rs.pill}`} title={`Risk ${risk} / 100 (${rs.label})`}>
      <span className={`h-1.5 w-1.5 rounded-full ${rs.bar}`} aria-hidden="true" />
      {risk}
      {showLabel && <span className="font-sans text-[11px] font-semibold tracking-[0.08em] uppercase">{rs.label}</span>}
    </span>
  )
}

export function TechniqueBadge({ id, name }: { id: string; name: string | null }) {
  return (
    <span className="inline-flex max-w-full items-stretch overflow-hidden rounded-md border border-ink/90 text-[12px] leading-[22px]" title={`${id}${name ? ` ${name}` : ''}`}>
      <span className="bg-ink px-2 font-mono font-medium text-brand">{id}</span>
      {name && <span className="truncate bg-white px-2 font-medium text-ink">{name}</span>}
    </span>
  )
}

export function TacticTag({ tactic }: { tactic: string }) {
  return <span className="inline-flex items-center rounded-full border border-line bg-subtle px-2.5 text-[12px] leading-[22px] font-medium text-ink-2">{tactic}</span>
}

export function FirewallTag() {
  return (
    <span className="ml-1.5 inline-flex rounded-full border border-high/60 bg-high-bg px-1.5 font-sans text-[10px] leading-[16px] font-semibold tracking-[0.06em] uppercase text-high-ink" title="Firewall device (devname): the logging device, not the victim endpoint">
      firewall
    </span>
  )
}

/** Mono entity chip with copy-to-clipboard. */
export function EntityChip({ kind, value }: { kind: string; value: string | null }) {
  const [copied, setCopied] = useState(false)
  if (!value) return null
  const copy = () => {
    navigator.clipboard
      ?.writeText(value)
      .then(() => {
        setCopied(true)
        window.setTimeout(() => setCopied(false), 1200)
      })
      .catch(() => {})
  }
  return (
    <button
      type="button"
      onClick={copy}
      title={`Copy ${kind}: ${value}`}
      className="focus-ring group flex w-full max-w-full items-center gap-2.5 rounded-lg border border-line bg-subtle px-3 py-2 text-left hover:border-line-strong hover:bg-white"
    >
      <span className="section-label w-9 shrink-0 !text-[10px]">{kind}</span>
      <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-ink">{value}</span>
      {kind === 'host' && isFirewall(value) && <FirewallTag />}
      <span className={`shrink-0 text-[11px] font-medium ${copied ? 'text-accent' : 'text-muted opacity-0 group-hover:opacity-100 group-focus-visible:opacity-100'}`}>{copied ? 'Copied' : 'Copy'}</span>
    </button>
  )
}

export function Button({
  children,
  onClick,
  variant = 'default',
  size = 'md',
  disabled,
  title,
  type = 'button',
  pressed,
}: {
  children: ReactNode
  onClick?: () => void
  variant?: 'default' | 'primary' | 'ghost' | 'brand'
  size?: 'sm' | 'md'
  disabled?: boolean
  title?: string
  type?: 'button' | 'submit'
  pressed?: boolean
}) {
  const v =
    variant === 'primary'
      ? 'border-ink bg-ink text-white hover:bg-[#262626] hover:border-[#262626]'
      : variant === 'brand'
        ? 'border-brand bg-brand text-ink hover:bg-brand-600 hover:border-brand-600'
        : variant === 'ghost'
          ? 'border-transparent bg-transparent text-ink-2 hover:bg-unobs hover:text-ink'
          : 'border-line-strong bg-white text-ink hover:bg-subtle hover:border-ink/30'
  const sz = size === 'sm' ? 'h-7 px-3 text-[12px]' : 'h-9 px-4 text-[13px]'
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      title={title}
      aria-pressed={pressed}
      className={`focus-ring inline-flex shrink-0 items-center justify-center gap-1.5 rounded-full border font-medium whitespace-nowrap disabled:cursor-not-allowed disabled:opacity-45 ${sz} ${v}`}
    >
      {children}
    </button>
  )
}

/** Card section header: mono eyebrow + optional title + right-side slot. */
export function CardHeader({ eyebrow, title, right }: { eyebrow?: string; title?: ReactNode; right?: ReactNode }) {
  return (
    <header className="flex items-center gap-3 border-b border-line px-5 py-3.5">
      <div className="min-w-0">
        {eyebrow && <div className="section-label">{eyebrow}</div>}
        {title && <div className="headline mt-0.5 truncate text-[15px]">{title}</div>}
      </div>
      {right && <div className="ml-auto flex shrink-0 items-center gap-2">{right}</div>}
    </header>
  )
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex h-full min-h-40 flex-col items-center justify-center px-8 py-10 text-center">
      <span className="mb-3 flex h-10 w-10 items-center justify-center rounded-full border border-line bg-subtle" aria-hidden="true">
        <svg viewBox="0 0 20 20" className="h-4 w-4 text-muted">
          <circle cx="9" cy="9" r="5.5" fill="none" stroke="currentColor" strokeWidth="1.6" />
          <path d="M13 13l4 4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
        </svg>
      </span>
      <p className="headline text-[14px]">{title}</p>
      {children && <div className="mt-1 max-w-sm text-[13px] leading-relaxed text-muted">{children}</div>}
    </div>
  )
}

export function ErrorNote({ children, onRetry }: { children: ReactNode; onRetry?: () => void }) {
  return (
    <div role="alert" className="m-4 rounded-xl border border-crit/30 bg-crit-bg px-4 py-3 text-[13px] text-crit-ink">
      <div className="flex items-start gap-2.5">
        <span className="mt-[3px] flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-crit text-[11px] font-bold text-white" aria-hidden="true">
          !
        </span>
        <div className="min-w-0 break-words">{children}</div>
      </div>
      {onRetry && (
        <div className="mt-3 pl-6">
          <Button size="sm" onClick={onRetry}>
            Retry
          </Button>
        </div>
      )}
    </div>
  )
}

export function Spinner({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2.5 px-5 py-6 text-[13px] text-muted" role="status">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-line border-t-brand" aria-hidden="true" />
      {label}
    </div>
  )
}

/** Small "Copy" pill used by SIEM pivots and the report. */
export function CopyPill({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle')
  const copy = () => {
    const done = (s: 'ok' | 'fail') => {
      setState(s)
      window.setTimeout(() => setState('idle'), 1500)
    }
    if (!navigator.clipboard) return done('fail')
    navigator.clipboard.writeText(text).then(
      () => done('ok'),
      () => done('fail'),
    )
  }
  return (
    <Button size="sm" onClick={copy} title={state === 'fail' ? 'Clipboard unavailable: select the text and copy it' : `${label} to clipboard`}>
      {state === 'ok' ? 'Copied' : state === 'fail' ? 'Select text' : label}
    </Button>
  )
}
