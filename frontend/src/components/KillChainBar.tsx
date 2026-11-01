import { sameTactic, TACTICS_V20 } from '../lib/attack'
import type { Step } from '../types'

interface Props {
  tactics: string[]
  gaps: string[]
  steps: Step[]
  onJump: (step: number) => void
}

const SHORT: Record<string, string> = {
  Reconnaissance: 'Recon',
  'Resource Development': 'Res. Dev',
  'Initial Access': 'Initial Access',
  Execution: 'Exec',
  Persistence: 'Persist',
  'Privilege Escalation': 'Priv Esc',
  Stealth: 'Stealth',
  'Defense Impairment': 'Def Impair',
  'Credential Access': 'Cred Access',
  Discovery: 'Discov',
  'Lateral Movement': 'Lateral',
  Collection: 'Collect',
  'Command and Control': 'C2',
  Exfiltration: 'Exfil',
  Impact: 'Impact',
}

/** 15-segment ATT&CK v20 strip: observed = accent fill, gap = dashed red border, other = grey. */
export function KillChainBar({ tactics, gaps, steps, onJump }: Props) {
  return (
    <section aria-label="Kill chain" className="@container rounded-2xl border border-line bg-subtle px-5 py-4">
      <div className="mb-3 flex flex-wrap items-center gap-x-5 gap-y-1">
        <h3 className="headline text-[15px]" title="The 15 stages of an attack in MITRE ATT&CK v20, in order. Filled = seen in this incident; dashed = an expected stage we did not see.">
          Attack stages <span className="font-normal text-muted">· MITRE ATT&CK kill chain</span>
        </h3>
        <span className="flex items-center gap-4 text-[12px] text-muted">
          <span className="flex items-center gap-1.5"><span className="h-3 w-4 rounded bg-brand" />seen</span>
          <span className="flex items-center gap-1.5"><span className="h-3 w-4 rounded border border-dashed border-crit bg-white" />gap</span>
          <span className="flex items-center gap-1.5"><span className="h-3 w-4 rounded border border-line bg-white" />not seen</span>
        </span>
      </div>
      <ol className="grid grid-cols-15 gap-1">
        {TACTICS_V20.map((t, i) => {
          const tSteps = steps.filter((s) => sameTactic(s.tactic, t))
          const observed = tSteps.length > 0 || tactics.some((x) => sameTactic(x, t))
          const gap = !observed && gaps.some((x) => sameTactic(x, t))
          const state = observed ? 'observed' : gap ? 'gap (expected, not seen)' : 'not observed'
          const label = `${i + 1}. ${t}: ${state}${tSteps.length ? `, steps ${tSteps.map((s) => s.step + 1).join(', ')}` : ''}`
          const seg = observed
            ? 'bg-brand text-ink border-brand hover:bg-brand-600 hover:border-brand-600'
            : gap
              ? 'bg-white text-crit-ink border-dashed border-crit'
              : 'bg-white text-muted border-line'
          return (
            <li key={t} className="min-w-0">
              <button
                type="button"
                disabled={tSteps.length === 0}
                onClick={() => tSteps.length && onJump(tSteps[0].step)}
                title={label}
                aria-label={label}
                className={`focus-ring flex h-14 w-full flex-col items-center justify-center overflow-hidden rounded-lg border px-1 text-center ${seg} ${tSteps.length ? 'cursor-pointer' : 'cursor-default'}`}
              >
                <span className="hidden @4xl:block">
                  <span className="line-clamp-2 text-[11px] leading-[13px] font-medium">{t}</span>
                </span>
                <span className="block @4xl:hidden">
                  <span className="line-clamp-2 text-[11px] leading-[13px] font-medium">{SHORT[t] ?? t}</span>
                </span>
                {tSteps.length > 0 && <span className="mt-1 font-mono text-[10px] leading-none font-semibold tabular-nums">×{tSteps.length}</span>}
                {gap && <span className="mt-1 text-[9px] leading-none font-semibold tracking-[0.08em] uppercase">gap</span>}
              </button>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
