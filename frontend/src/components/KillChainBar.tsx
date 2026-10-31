import { sameTactic, TACTICS_V20 } from '../lib/attack'
import type { Step } from '../types'

interface Props {
  tactics: string[]
  gaps: string[]
  steps: Step[]
  onJump: (step: number) => void
}

/** All 15 ATT&CK v20 tactics in order: observed = filled, gap = dashed, others dim. */
export function KillChainBar({ tactics, gaps, steps, onJump }: Props) {
  return (
    <section aria-label="Kill chain">
      <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-slate-400">
        Kill chain <span className="font-normal normal-case text-slate-500">(ATT&CK v20 · filled = observed · dashed = gap)</span>
      </h3>
      <ol className="grid grid-cols-15 gap-1">
        {TACTICS_V20.map((t, i) => {
          const tSteps = steps.filter((s) => sameTactic(s.tactic, t))
          const observed = tSteps.length > 0 || tactics.some((x) => sameTactic(x, t))
          const gap = !observed && gaps.some((x) => sameTactic(x, t))
          const cls = observed
            ? 'border-rose-400 bg-rose-500/80 text-white'
            : gap
              ? 'border-dashed border-amber-400/80 bg-amber-400/5 text-amber-200'
              : 'border-slate-800 bg-slate-900 text-slate-600'
          const state = observed ? 'observed' : gap ? 'gap (expected, not seen)' : 'not observed'
          const label = `${i + 1}. ${t}: ${state}${tSteps.length ? `, steps ${tSteps.map((s) => s.step + 1).join(', ')}` : ''}`
          return (
            <li key={t} className="min-w-0">
              <button
                type="button"
                disabled={tSteps.length === 0}
                onClick={() => tSteps.length && onJump(tSteps[0].step)}
                title={label}
                aria-label={label}
                className={`flex h-12 w-full flex-col items-center justify-center rounded border-2 px-0.5 text-center text-[10px] leading-tight focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${cls} ${
                  tSteps.length ? 'cursor-pointer hover:brightness-110' : 'cursor-default'
                }`}
              >
                <span className="line-clamp-2 break-words">{t}</span>
                {tSteps.length > 0 && <span className="mt-0.5 font-mono text-[9px] opacity-90">×{tSteps.length}</span>}
                {gap && <span className="mt-0.5 text-[9px] uppercase">gap</span>}
              </button>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
