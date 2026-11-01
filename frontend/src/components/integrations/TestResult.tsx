// Result of POST /api/integrations/{id}/test: summary + step checklist (config → DNS → TLS → auth → permission → data).
// Steps are shown exactly as the API returns them (no step is invented); ok null/absent = "not run".
// Without steps, the API `message` is shown instead. All text renders as text, never HTML.
import type { IntegrationTestResult, IntegrationTestStep } from '../../types_integrations'

const fmtN = (v: number | null | undefined) => (typeof v === 'number' && Number.isFinite(v) ? v.toLocaleString('en-US') : '—')

function StepRow({ s }: { s: IntegrationTestStep }) {
  const state = s.ok === true ? 'pass' : s.ok === false ? 'fail' : 'skip'
  const icon = state === 'pass' ? '✓' : state === 'fail' ? '✗' : '–'
  const iconCls =
    state === 'pass' ? 'border-brand/50 bg-accent-tint text-accent' : state === 'fail' ? 'border-crit bg-crit text-white' : 'border-line-strong bg-white text-muted'
  return (
    <li className="flex items-start gap-2.5 py-1">
      <span className={`mt-[1px] flex h-5 w-5 shrink-0 items-center justify-center rounded-full border text-[11px] font-bold ${iconCls}`} aria-hidden="true">
        {icon}
      </span>
      <div className="min-w-0 flex-1">
        <p className={`text-[13px] ${state === 'fail' ? 'font-semibold text-crit-ink' : state === 'skip' ? 'text-muted' : 'text-ink'}`}>
          {s.name}
          <span className="sr-only">: {state === 'pass' ? 'passed' : state === 'fail' ? 'failed' : 'not run'}</span>
          {state === 'skip' && <span className="ml-2 text-[11px]" aria-hidden="true">not run</span>}
        </p>
        {s.detail && <p className={`mt-0.5 text-[12px] break-words ${state === 'fail' ? 'text-crit-ink' : 'text-muted'}`}>{s.detail}</p>}
      </div>
    </li>
  )
}

export function TestResult({ test }: { test: IntegrationTestResult }) {
  const steps = Array.isArray(test.steps) && test.steps.length > 0 ? test.steps : null
  const failed = steps?.find((s) => s.ok === false) ?? null
  return (
    <div role="status" className={`rounded-xl border px-4 py-3 text-[13px] break-words ${test.ok ? 'border-brand/40 bg-accent-tint text-accent' : 'border-crit/30 bg-crit-bg text-crit-ink'}`}>
      <p className="font-semibold">{test.ok ? 'Connection works' : failed ? `Connection failed at: ${failed.name}` : 'Connection failed'}</p>
      {test.ok && (
        <p className="mt-0.5 tabular-nums">
          {test.latency_ms !== null && test.latency_ms !== undefined ? `${fmtN(test.latency_ms)} ms` : 'latency —'} · {fmtN(test.sample_count)} sample{test.sample_count === 1 ? '' : 's'}
        </p>
      )}
      {steps ? (
        <ol className="mt-2 rounded-lg border border-line bg-white px-3 py-1.5" aria-label="Connection test steps">
          {steps.map((s, i) => (
            <StepRow key={`${i}-${s.name}`} s={s} />
          ))}
        </ol>
      ) : (
        test.message && <p className="mt-0.5">{test.message}</p>
      )}
      {!test.ok && test.error_code && <p className="mt-1 font-mono text-[12px]">code: {test.error_code}</p>}
    </div>
  )
}
