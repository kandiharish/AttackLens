// Simple line icons per ATT&CK tactic (inline SVG, no icon font / CDN).
const P = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round', strokeLinejoin: 'round' } as const

export function TacticIcon({ tactic, className = 'h-[18px] w-[18px]' }: { tactic: string; className?: string }) {
  const t = tactic.toLowerCase()
  let d: React.ReactNode
  if (t.includes('credential'))
    d = (
      <>
        <circle cx="7" cy="12" r="3.5" {...P} />
        <path d="M10.5 12H20M17 12v3M14 12v2" {...P} />
      </>
    )
  else if (t.includes('initial'))
    d = (
      <>
        <path d="M14 4h5v16h-5" {...P} />
        <path d="M4 12h10M10 8l4 4-4 4" {...P} />
      </>
    )
  else if (t.includes('execution'))
    d = (
      <>
        <rect x="3.5" y="5" width="17" height="14" rx="2" {...P} />
        <path d="M7 10l3 2-3 2M12 15h4" {...P} />
      </>
    )
  else if (t.includes('persistence'))
    d = <path d="M12 3v14M7 12a5 5 0 0 0 10 0M9 6h6" {...P} />
  else if (t.includes('privilege'))
    d = <path d="M12 19V6M6.5 11.5L12 6l5.5 5.5M6 20h12" {...P} />
  else if (t.includes('stealth') || t.includes('defense') || t.includes('evasion'))
    d = (
      <>
        <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z" {...P} />
        <path d="M9 12h6" {...P} />
      </>
    )
  else if (t.includes('discovery') || t.includes('reconnaissance'))
    d = (
      <>
        <circle cx="10.5" cy="10.5" r="5.5" {...P} />
        <path d="M15 15l5 5" {...P} />
      </>
    )
  else if (t.includes('lateral'))
    d = (
      <>
        <rect x="3" y="4" width="7" height="6" rx="1.5" {...P} />
        <rect x="14" y="14" width="7" height="6" rx="1.5" {...P} />
        <path d="M6.5 10v3.5a2 2 0 0 0 2 2H14" {...P} />
      </>
    )
  else if (t.includes('collection'))
    d = (
      <>
        <path d="M4 8l8-4 8 4-8 4z" {...P} />
        <path d="M4 8v8l8 4 8-4V8M12 12v8" {...P} />
      </>
    )
  else if (t.includes('command'))
    d = (
      <>
        <path d="M12 13v8M8.5 9.5a5 5 0 0 1 7 0M6 7a8.5 8.5 0 0 1 12 0" {...P} />
        <circle cx="12" cy="12.5" r="1" {...P} />
      </>
    )
  else if (t.includes('exfiltration'))
    d = <path d="M12 15V4M7.5 8.5L12 4l4.5 4.5M5 14v5h14v-5" {...P} />
  else if (t.includes('impact'))
    d = (
      <>
        <rect x="5" y="10.5" width="14" height="9.5" rx="2" {...P} />
        <path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5" {...P} />
      </>
    )
  else d = <circle cx="12" cy="12" r="7" {...P} />
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden="true">
      {d}
    </svg>
  )
}
