import type { Tone } from '../../lib/connections'

const TONE: Record<Tone, string> = {
  off: 'bg-line-strong',
  idle: 'bg-med',
  ok: 'bg-brand',
  err: 'bg-crit',
}

/** Decorative status dot; the status text next to it carries the meaning. */
export function StatusDot({ tone }: { tone: Tone }) {
  return <span className={`h-2 w-2 shrink-0 rounded-full ${TONE[tone]} ${tone === 'ok' ? 'animate-pulse' : ''}`} aria-hidden="true" />
}
