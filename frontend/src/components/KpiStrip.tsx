import { useState } from 'react'
import { TACTICS_V20, tacticIndex } from '../lib/attack'
import { fmtCount, fmtPct, fmtRss, fmtSeconds, readIngest, readRunCounts, readRunSummary, readScorecard, tacticsCovered } from '../lib/metrics'
import { grade, TARGETS, type Grade } from '../lib/targets'
import type { IncidentSummary, Metrics } from '../types'

interface Props {
  metrics: Metrics | null
  error: string | null
  /** Run fed by SIEM alerts (vendor labels): accuracy tiles are not shown (scored on raw-event runs only). */
  siemAlerts?: boolean
  /** Loaded incident list: used for the tactics-covered count when the run has no answer key. */
  incidents?: IncidentSummary[] | null
}

const ACC_NOTE = 'accuracy is scored on raw-event runs only'

function GradeChip({ g, target }: { g: Grade; target: string }) {
  if (g === 'none') return null
  const label = g === 'great' ? 'Great' : g === 'good' ? 'Good' : 'Below target'
  const cls = g === 'great' ? 'border-brand/50 bg-accent-tint text-accent' : g === 'good' ? 'border-med/60 bg-med-bg text-med-ink' : 'border-crit/40 bg-crit-bg text-crit-ink'
  return (
    <span className={`inline-flex h-6 shrink-0 items-center gap-1.5 rounded-full border px-2.5 text-[12px] font-semibold ${cls}`} title={`${label} against the hackathon target: ${target}`}>
      {g === 'great' ? (
        <svg viewBox="0 0 10 10" className="h-2.5 w-2.5" aria-hidden="true">
          <path d="M2 5.3l2 2 4-4.3" stroke="currentColor" strokeWidth="1.7" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      ) : (
        <span className={`h-1.5 w-1.5 rounded-full ${g === 'good' ? 'bg-med' : 'bg-crit'}`} aria-hidden="true" />
      )}
      {label}
    </span>
  )
}

function BigCard({ label, value, sub, g = 'none', target, title, off = false }: { label: string; value: string; sub: string; g?: Grade; target?: string; title: string; off?: boolean }) {
  return (
    <div className="card flex min-w-0 flex-col gap-1 px-5 py-3 short:py-2.5" title={off ? `${title}: not shown, ${ACC_NOTE}` : target ? `${title}\nHackathon target: ${target}` : title}>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-[13px] font-medium text-ink-2">{label}</span>
        {!off && target && <GradeChip g={g} target={target} />}
      </div>
      {off ? (
        <span className="text-[14px] leading-8 text-muted italic">n/a for SIEM alerts</span>
      ) : (
        <span className={`headline truncate text-[26px] leading-8 tabular-nums short:text-[23px] short:leading-7 ${value === '—' ? '!text-muted' : ''}`}>{value}</span>
      )}
      <span className="truncate text-[12px] text-muted short:hidden">{sub}</span>
    </div>
  )
}

function Detail({ label, value, g, target, note }: { label: string; value: string; g?: Grade; target?: string; note?: string }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <span className="section-label">{label}</span>
      <span className="flex flex-wrap items-center gap-2">
        <span className="headline text-[17px] tabular-nums">{value}</span>
        {g && target && <GradeChip g={g} target={target} />}
      </span>
      {note && <span className="text-[12px] text-muted">{note}</span>}
    </div>
  )
}

const int = (n: number) => n.toLocaleString('en-US')

/** Shown instead of the accuracy cards when the run has no eval_scorecard (no ground truth). */
function NoKeyCard() {
  return (
    <div className="card flex min-w-0 flex-col gap-1 border-dashed px-5 py-3 short:py-2.5" title="eval_scorecard.json is absent for this run: there was no ground truth to score against">
      <span className="truncate text-[13px] font-semibold text-ink">No answer key for this data</span>
      <span className="line-clamp-3 text-[12px] leading-4 text-ink-2">Accuracy can only be scored on data with ground truth: see the benchmark (attack injection into these logs).</span>
    </div>
  )
}

export function KpiStrip({ metrics, error, siemAlerts = false, incidents = null }: Props) {
  const [open, setOpen] = useState(false)
  const sc = readScorecard(metrics)
  const run = readRunSummary(metrics)
  const ing = readIngest(metrics)
  const drop = ing && ing.rowsIn > 0 ? (ing.dropped / ing.rowsIn) * 100 : null
  const rows = ing ? fmtCount(ing.rowsOk) : '—'
  // No answer key: metrics loaded but eval_scorecard is null. Show measured counts, never accuracy.
  const noKey = !!metrics && (metrics?.eval_scorecard ?? null) === null
  const cnt = readRunCounts(metrics)
  const incCount = cnt.incidents ?? incidents?.length ?? null
  const tactics = tacticsCovered(incidents)?.sort((a, b) => tacticIndex(a) - tacticIndex(b)) ?? null
  const rulesFired = cnt.customRulesFired === null && cnt.sigmaRulesFired === null ? null : (cnt.customRulesFired ?? 0) + (cnt.sigmaRulesFired ?? 0)
  const funnel = [cnt.rawAlerts !== null ? `${fmtCount(cnt.rawAlerts)} alerts` : null, cnt.episodes !== null ? `${fmtCount(cnt.episodes)} episodes` : null]
    .filter(Boolean)
    .join(' → ')
  const processed = (
    <BigCard
      label="Processed"
      value={rows === '—' ? '—' : `${rows} rows`}
      sub={run.totalWallS === null ? 'run time not recorded' : `in ${fmtSeconds(run.totalWallS)}, end to end`}
      g={grade(run.totalWallS, TARGETS.runTimeS)}
      target={TARGETS.runTimeS.text}
      title="ingest_accounting rows ok · run_metrics.total_wall_s"
    />
  )
  const topCards = noKey
    ? [
        <NoKeyCard key="nokey" />,
        incCount !== null && (
          <BigCard
            key="inc"
            label="Incidents found"
            value={int(incCount)}
            sub={funnel ? `from ${funnel}` : 'linked attack paths'}
            title="run_metrics.incidents (else the incident list length) · stage_stats.detect.raw_alerts · stage_stats.episodes.episodes"
          />
        ),
        tactics !== null && (
          <BigCard
            key="tac"
            label="ATT&CK tactics covered"
            value={`${tactics.length} of ${TACTICS_V20.length}`}
            sub={tactics.length > 0 ? tactics.join(' · ') : 'no tactics in the incidents'}
            title={`Distinct ATT&CK tactics across the incident list${tactics.length > 0 ? `:\n${tactics.join('\n')}` : ''}`}
          />
        ),
        <div key="proc" className="contents">
          {processed}
        </div>,
      ].filter(Boolean)
    : null
  const detailItems = noKey
    ? [
        cnt.rawAlerts !== null && <Detail key="ra" label="Raw alerts" value={int(cnt.rawAlerts)} note="rule hits before grouping" />,
        cnt.episodes !== null && (
          <Detail
            key="ep"
            label="Episodes"
            value={int(cnt.episodes)}
            note={cnt.episodesTotal !== null && cnt.episodesTotal > cnt.episodes ? `kept of ${int(cnt.episodesTotal)} built` : 'alerts grouped by entity and time'}
          />
        ),
        rulesFired !== null && (
          <Detail
            key="rf"
            label="Rules fired"
            value={int(rulesFired)}
            note={[cnt.customRulesFired !== null ? `${int(cnt.customRulesFired)} custom` : null, cnt.sigmaRulesFired !== null ? `${int(cnt.sigmaRulesFired)} Sigma` : null].filter(Boolean).join(' · ')}
          />
        ),
        cnt.sigmaApplicable !== null && cnt.sigmaRunning !== null && (
          <Detail key="sa" label="Sigma rules active" value={`${int(cnt.sigmaApplicable)} of ${int(cnt.sigmaRunning)}`} note="match the log sources in this data" />
        ),
      ].filter(Boolean)
    : null
  return (
    <section aria-label="Run scorecard" className="shrink-0">
      <div className="flex items-stretch gap-4">
        {topCards ? (
          <div className="grid min-w-0 flex-1 gap-4" style={{ gridTemplateColumns: `repeat(${topCards.length}, minmax(0, 1fr))` }}>
            {topCards}
          </div>
        ) : (
        <div className="grid min-w-0 flex-1 grid-cols-4 gap-4">
          <BigCard
            label="Attacks found"
            off={siemAlerts}
            value={fmtPct(sc.rebuilt)}
            sub="planted attacks rebuilt end to end"
            g={grade(sc.rebuilt, TARGETS.rebuilt)}
            target={TARGETS.rebuilt.text}
            title="eval_scorecard.rebuilt_pct: attacks rebuilt with the right steps in the right order"
          />
          <BigCard
            label="Steps detected"
            off={siemAlerts}
            value={fmtPct(sc.detection)}
            sub="of all attack steps in the logs"
            g={grade(sc.detection, TARGETS.detection)}
            target={TARGETS.detection.text}
            title="eval_scorecard.detection_pct: share of planted attack steps found"
          />
          <BigCard
            label="False alarms"
            off={siemAlerts}
            value={fmtPct(sc.faStrict)}
            sub="incidents that were not real attacks"
            g={grade(sc.faStrict, TARGETS.falseAlarms)}
            target={TARGETS.falseAlarms.text}
            title="eval_scorecard.false_alarms_strict_pct (lower is better)"
          />
          {processed}
        </div>
        )}
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          aria-controls="kpi-details"
          className="focus-ring card flex w-[88px] shrink-0 flex-col items-center justify-center gap-1.5 text-[13px] font-medium text-ink-2 hover:border-line-strong hover:text-ink"
          title={noKey ? 'More run metrics: alerts, episodes, rules, memory, per-stage times' : 'More run metrics: labels, memory, recall, per-stage times'}
        >
          <svg viewBox="0 0 16 16" className={`h-4 w-4 ${open ? 'rotate-180' : ''}`} aria-hidden="true">
            <path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          Details
        </button>
      </div>

      {error && (
        <div role="alert" className="mt-3 rounded-xl border border-crit/30 bg-crit-bg px-4 py-2.5 text-[13px] text-crit-ink" title={error}>
          Metrics unavailable: {error}
        </div>
      )}
      {siemAlerts && (
        <p className="mt-3 text-[12px] text-muted" title="run_metrics.input_mode / live_status.input_mode includes siem_alerts: steps may carry the SIEM vendor's MITRE labels">
          <span className="mr-2 rounded-full border border-siem/40 bg-siem-bg px-2 py-0.5 text-[11px] font-semibold text-siem-ink">SIEM alerts input</span>
          {ACC_NOTE}
        </p>
      )}

      {open && (
        <div id="kpi-details" className="card mt-4 px-6 py-5">
          <div className={`grid grid-cols-3 gap-x-8 gap-y-5 ${detailItems && detailItems.length > 3 ? 'xl:grid-cols-7' : 'xl:grid-cols-6'}`}>
            {detailItems ?? (
              <>
                <Detail label="Correct labels" value={siemAlerts ? 'n/a' : fmtPct(sc.labels)} g={siemAlerts ? undefined : grade(sc.labels, TARGETS.labels)} target={TARGETS.labels.text} note="right ATT&CK technique" />
                <Detail label="False alarms (lenient)" value={siemAlerts ? 'n/a' : fmtPct(sc.faLenient)} note="excluding generator noise" />
                <Detail label="Singleton recall" value={siemAlerts ? 'n/a' : fmtPct(sc.singletonRecall)} note="single noise alerts caught" />
              </>
            )}
            <Detail label="Peak memory" value={fmtRss(run.peakRssMb)} g={grade(run.peakRssMb, TARGETS.peakRamMb)} target={TARGETS.peakRamMb.text} />
            <Detail label="Run time" value={fmtSeconds(run.totalWallS)} g={grade(run.totalWallS, TARGETS.runTimeS)} target={TARGETS.runTimeS.text} />
            <Detail
              label="Rows dropped"
              value={drop === null ? '—' : `${drop.toFixed(drop > 0 && drop < 0.01 ? 4 : 2)} %`}
              note={ing ? `${ing.rowsIn.toLocaleString('en-US')} in · ${ing.dropped.toLocaleString('en-US')} dropped · ${ing.sources} source${ing.sources === 1 ? "" : "s"}` : undefined}
            />
          </div>
          {run.stages.length > 0 && (
            <div className="mt-6">
              <div className="section-label mb-2">Time per stage</div>
              <div className="flex flex-wrap gap-2">
                {run.stages.map((s) => (
                  <span key={s.name} className="inline-flex items-center gap-2 rounded-full border border-line bg-subtle px-3 py-1 text-[12px]">
                    <span className="font-medium text-ink">{s.name}</span>
                    <span className="font-mono text-muted">{fmtSeconds(s.wall_s)}</span>
                    <span className="font-mono text-muted">· {fmtRss(s.peak_rss_mb)}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
