// Dev-only: renders RunStepper with fake RunStatus objects (all states) and the ETA smoothing on a noisy sequence.
// Not part of the product UI; reachable only from `npm run dev` at /?harness=run-stepper.
import type { RunStatus } from '../api'
import { RunStepper } from '../components/RunStepper'
import { fmtEta, smoothEta, type EtaState } from '../lib/addData'

const base: RunStatus = {
  run_id: 'r-demo',
  status: 'running',
  stage: null,
  percent: 0,
  elapsed_s: 4,
  rss_mb: 410,
  peak_rss_mb: 410,
  returncode: null,
  out_dir: 'data/out/demo',
  log: 'data/out/demo/run.log',
}

const CASES: { title: string; st: RunStatus }[] = [
  { title: 'Old backend (no progress keys)', st: { ...base, stage: 'ingest', percent: 20, elapsed_s: 61 } },
  {
    title: 'Reading: ingest with bytes + fraction, ETA from history+live',
    st: {
      ...base,
      stage: 'ingest',
      percent: 20,
      elapsed_s: 214,
      rss_mb: 3810,
      peak_rss_mb: 4020,
      stage_elapsed_s: 206,
      stage_fraction: 0.49,
      stages_done: [{ stage: 'profile', wall_s: 8.1 }],
      bytes_total: 6.5 * 1024 ** 3,
      bytes_done: 3.2 * 1024 ** 3,
      ingest_mb_s: 31.4,
      eta_s: 371,
      eta_basis: 'history+live',
      eta_total_s: 585,
    },
  },
  {
    title: 'Detecting: no stage fraction (indeterminate), ETA null',
    st: {
      ...base,
      stage: 'detect',
      percent: 55,
      elapsed_s: 392,
      rss_mb: 2950,
      peak_rss_mb: 4630,
      stage_elapsed_s: 41.5,
      stage_fraction: null,
      stages_done: [
        { stage: 'profile', wall_s: 8.1 },
        { stage: 'ingest', wall_s: 323.4 },
        { stage: 'lookups', wall_s: 19.0 },
      ],
      bytes_total: 6.5 * 1024 ** 3,
      bytes_done: 6.5 * 1024 ** 3,
      eta_s: null,
      eta_basis: null,
    },
  },
  {
    title: 'Building attack paths: ETA 6 s (Finishing…)',
    st: {
      ...base,
      stage: 'publish',
      percent: 95,
      elapsed_s: 540,
      rss_mb: 640,
      peak_rss_mb: 4630,
      stage_elapsed_s: 1.2,
      stage_fraction: 0.6,
      stages_done: [
        { stage: 'profile', wall_s: 8.1 },
        { stage: 'ingest', wall_s: 323.4 },
        { stage: 'lookups', wall_s: 19.0 },
        { stage: 'detect', wall_s: 120.2 },
        { stage: 'episodes', wall_s: 22.0 },
        { stage: 'link', wall_s: 9.6 },
        { stage: 'incidents', wall_s: 16.9 },
      ],
      eta_s: 6,
      eta_basis: 'live',
    },
  },
  {
    title: 'Succeeded',
    st: {
      ...base,
      status: 'succeeded',
      stage: 'done',
      percent: 100,
      elapsed_s: 548.3,
      peak_rss_mb: 4630,
      returncode: 0,
      stages_done: [
        { stage: 'profile', wall_s: 8.1 },
        { stage: 'ingest', wall_s: 323.4 },
        { stage: 'lookups', wall_s: 19.0 },
        { stage: 'detect', wall_s: 120.2 },
        { stage: 'episodes', wall_s: 22.0 },
        { stage: 'link', wall_s: 9.6 },
        { stage: 'incidents', wall_s: 16.9 },
        { stage: 'publish', wall_s: 3.4 },
      ],
    },
  },
  { title: 'Failed in Linking', st: { ...base, status: 'failed', stage: 'link', percent: 70, elapsed_s: 402, returncode: 1, stages_done: [{ stage: 'ingest', wall_s: 300 }, { stage: 'detect', wall_s: 80 }] } },
]

// Noisy raw ETAs every 2 s within one stage, then a stage change (lifts the 20 % growth cap).
const RAW: { t: number; stage: string; raw: number | null }[] = [
  { t: 10, stage: 'ingest', raw: null },
  { t: 12, stage: 'ingest', raw: 420 },
  { t: 14, stage: 'ingest', raw: 380 },
  { t: 16, stage: 'ingest', raw: 650 },
  { t: 18, stage: 'ingest', raw: 300 },
  { t: 20, stage: 'ingest', raw: 410 },
  { t: 22, stage: 'detect', raw: 900 },
  { t: 24, stage: 'detect', raw: 860 },
  { t: 26, stage: 'detect', raw: -5 },
]

function smoothingRows() {
  let prev: EtaState | null = null
  return RAW.map((r) => {
    prev = smoothEta(prev, r.raw, 'r-demo', r.stage, r.t)
    return { ...r, shown: prev?.eta ?? null }
  })
}

export default function RunStepperHarness() {
  return (
    <div className="mx-auto max-w-[1120px] space-y-5 p-6">
      <h1 className="headline text-[22px]">RunStepper harness (dev only)</h1>
      {CASES.map((c) => (
        <section key={c.title} className="card px-6 py-5">
          <div className="section-label mb-3">{c.title}</div>
          <RunStepper status={c.st} />
        </section>
      ))}
      <section className="card px-6 py-5">
        <div className="section-label mb-3">ETA smoothing (EMA, ≤ 20 % growth per poll within a stage)</div>
        <table className="w-full font-mono text-[12px]">
          <thead>
            <tr className="text-left text-muted">
              <th className="py-1">elapsed_s</th>
              <th>stage</th>
              <th>raw eta_s</th>
              <th>shown (s)</th>
              <th>headline</th>
            </tr>
          </thead>
          <tbody>
            {smoothingRows().map((r) => (
              <tr key={r.t} className="border-t border-line">
                <td className="py-1">{r.t}</td>
                <td>{r.stage}</td>
                <td>{r.raw ?? 'null'}</td>
                <td>{r.shown === null ? 'null' : r.shown.toFixed(1)}</td>
                <td>{fmtEta(r.shown)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}
