// Full log-health report: 10 checks, findings table, seal block, files with SHA-256, authenticity signals.
// Measure, never assert: every number comes from integrity_report.json. Log-derived strings are text only.
import type { IntegrityReport } from '../../types'
import { fmtBytes } from '../../lib/addData'
import { checkLabel, checkStatusStyle, clipEvidence, fmtRangeUtc, findingWhere, isGenerated, scopeLabel, sealLine, severityPill, topFindings, verdictStyle } from '../../lib/integrity'
import { Button, CopyPill } from '../ui'
import { Modal } from './Modal'

const fmtVal = (v: unknown) => (v === null || v === undefined ? '—' : typeof v === 'number' ? v.toLocaleString('en-US') : String(v))

function Section({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="border-t border-line px-6 py-4" aria-label={title}>
      <div className="mb-2.5 flex items-center gap-3">
        <h3 className="section-label">{title}</h3>
        {right && <div className="ml-auto text-[12px] text-muted">{right}</div>}
      </div>
      {children}
    </section>
  )
}

export function IntegrityPanel({ report, onClose }: { report: IntegrityReport; onClose: () => void }) {
  const vs = verdictStyle(report.verdict)
  const findings = topFindings(report.findings ?? [], report.findings?.length ?? 0)
  const seal = report.seal
  const a = report.authenticity
  const gen = isGenerated(report)

  return (
    <Modal labelledBy="integrity-panel-title" onClose={onClose} width="max-w-[1040px]" className="border-line">
      <header className={`flex flex-wrap items-center gap-x-4 gap-y-2 border-b px-6 py-4 ${vs.bg} ${vs.border}`}>
        <div className="min-w-0 flex-1">
          <div className="section-label">Log health report · {scopeLabel(report)}</div>
          <h2 id="integrity-panel-title" className={`headline mt-0.5 text-[20px] ${vs.ink}`}>
            {vs.label} · trust score <span className="font-mono tabular-nums">{report.trust_score}</span> / 100
            {gen && <span className="ml-2 inline-flex h-6 items-center rounded-full border border-med/70 bg-med-bg px-2.5 align-middle text-[12px] font-semibold text-med-ink">Looks generated</span>}
          </h2>
          <p className="mt-1 text-[13px] break-words text-ink-2">{report.summary}</p>
        </div>
        <Button onClick={onClose}>Close</Button>
      </header>

      <div className="max-h-[72vh] overflow-y-auto">
        <div className="flex flex-wrap gap-x-6 gap-y-1 px-6 py-3 text-[12px] text-ink-2">
          <span>
            set <span className="font-mono text-ink">{report.set}</span>
          </span>
          <span>
            generated <span className="font-mono text-ink">{report.generated_at}</span>
          </span>
          {report.inputs && (
            <>
              <span>
                <span className="font-semibold text-ink tabular-nums">{fmtVal(report.inputs.files)}</span> file(s) ·{' '}
                <span className="font-semibold text-ink tabular-nums">{fmtBytes(report.inputs.bytes)}</span>
              </span>
              <span>
                events checked <span className="font-semibold text-ink tabular-nums">{fmtVal(report.inputs.events_rows)}</span>
              </span>
            </>
          )}
          {typeof report.wall_s === 'number' && <span>check took <span className="font-semibold text-ink tabular-nums">{report.wall_s.toFixed(1)} s</span></span>}
        </div>

        <Section title="Checks" right={`${report.checks.filter((c) => c.status !== 'skipped').length} of ${report.checks.length} ran`}>
          <ul className="grid gap-2 sm:grid-cols-2">
            {report.checks.map((c) => {
              const st = checkStatusStyle(c.status)
              return (
                <li key={c.id} className="flex items-start gap-2.5 rounded-lg border border-line bg-subtle px-3 py-2">
                  <span className={`mt-0.5 inline-flex h-5 w-[62px] shrink-0 items-center justify-center rounded-full border text-[10px] font-semibold tracking-[0.06em] uppercase ${st.pill}`}>{st.label}</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-medium text-ink">{checkLabel(c.id)}</div>
                    <div className="text-[11px] break-words text-muted">
                      <span className="font-mono">{c.id}</span>
                      {c.findings > 0 && ` · ${c.findings.toLocaleString('en-US')} finding(s)`}
                      {c.reason && ` · ${c.reason}`}
                    </div>
                  </div>
                </li>
              )
            })}
          </ul>
        </Section>

        <Section title="Findings" right={findings.length ? `${findings.length}` : undefined}>
          {findings.length === 0 ? (
            <p className="text-[13px] text-muted">No findings.</p>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-line">
              <table className="w-full min-w-[720px] border-collapse text-left text-[12px]">
                <thead>
                  <tr className="bg-subtle">
                    <th className="section-label w-[86px] px-3 py-2">Severity</th>
                    <th className="section-label px-3 py-2">Finding</th>
                    <th className="section-label w-[200px] px-3 py-2">Where</th>
                    <th className="section-label w-[190px] px-3 py-2">When (UTC)</th>
                    <th className="section-label w-[60px] px-3 py-2 text-right">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f, i) => (
                    <tr key={`${f.check}-${i}`} className="border-t border-line align-top">
                      <td className="px-3 py-2">
                        <span className={`inline-flex h-5 items-center rounded-full border px-2 text-[10px] font-semibold tracking-[0.06em] uppercase ${severityPill(f.severity)}`}>{f.severity}</span>
                      </td>
                      <td className="px-3 py-2">
                        <div className="font-semibold break-words text-ink">{f.title}</div>
                        <div className="text-[11px] text-muted">
                          <span className="font-mono">{f.check}</span>
                          {f.detail && <span className="break-words"> · {clipEvidence(f.detail)}</span>}
                        </div>
                        {f.evidence?.slice(0, 3).map((ev, j) => (
                          <pre key={j} className="mt-1 rounded-md border border-line bg-white px-2 py-1 font-mono text-[11px] leading-snug whitespace-pre-wrap break-all text-ink-2">
                            {clipEvidence(ev)}
                          </pre>
                        ))}
                      </td>
                      <td className="px-3 py-2 font-mono text-[11px] break-words text-ink-2">{findingWhere(f) ?? '—'}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-ink-2">{fmtRangeUtc(f.start_ts_ms, f.end_ts_ms)?.replace(/ UTC$/, '') ?? '—'}</td>
                      <td className="px-3 py-2 text-right font-mono text-ink tabular-nums">{fmtVal(f.count)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        <Section title="Seal" right={seal ? <span className="font-mono">{seal.status}</span> : undefined}>
          <p className="text-[13px] text-ink">{sealLine(report)}</p>
          {seal && seal.status !== 'absent' && (
            <dl className="mt-2 grid gap-x-6 gap-y-1 text-[12px] text-ink-2 sm:grid-cols-[auto_1fr]">
              {seal.path && (
                <>
                  <dt className="text-muted">Manifest</dt>
                  <dd className="font-mono break-all">{seal.path}</dd>
                </>
              )}
              <dt className="text-muted">Keyed (HMAC)</dt>
              <dd>{seal.keyed ? 'yes' : 'no'}</dd>
              <dt className="text-muted">Files checked</dt>
              <dd className="tabular-nums">{fmtVal(seal.files_checked)}</dd>
              {(['modified', 'missing', 'added'] as const).map((k) =>
                seal[k].length ? (
                  <div key={k} className="contents">
                    <dt className="text-muted capitalize">{k}</dt>
                    <dd className="font-mono break-all">{seal[k].join(', ')}</dd>
                  </div>
                ) : null,
              )}
            </dl>
          )}
        </Section>

        <Section title="Files" right={report.files?.length ? `${report.files.length}` : undefined}>
          {!report.files?.length ? (
            <p className="text-[13px] text-muted">No files listed.</p>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-line">
              <table className="w-full min-w-[720px] border-collapse text-left text-[12px]">
                <thead>
                  <tr className="bg-subtle">
                    <th className="section-label px-3 py-2">File</th>
                    <th className="section-label w-[90px] px-3 py-2 text-right">Size</th>
                    <th className="section-label px-3 py-2">SHA-256</th>
                    <th className="section-label w-[110px] px-3 py-2">Problems</th>
                  </tr>
                </thead>
                <tbody>
                  {report.files.map((f) => (
                    <tr key={f.file} className="border-t border-line align-middle">
                      <td className="px-3 py-2 font-mono text-[11px] break-all text-ink">{f.file}</td>
                      <td className="px-3 py-2 text-right text-ink-2 tabular-nums">{fmtBytes(f.size)}</td>
                      <td className="px-3 py-2">
                        {f.sha256 ? (
                          <div className="flex items-center gap-2">
                            <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink-2" title={f.sha256}>
                              {f.sha256}
                            </code>
                            <CopyPill text={f.sha256} />
                          </div>
                        ) : (
                          <span className="text-muted">—</span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-[11px] text-ink-2">
                        {[f.zeroed_bytes > 0 ? `${f.zeroed_bytes.toLocaleString('en-US')} zeroed bytes` : null, f.truncated_tail ? 'truncated end' : null].filter(Boolean).join(' · ') || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        <Section title="Authenticity (machine-generated?)" right={a ? <span className="font-mono">{a.label}</span> : undefined}>
          {!a ? (
            <p className="text-[13px] text-muted">{report.scope === 'quick' ? 'Not assessed in the quick check: runs after the full analysis.' : 'Not assessed for this data.'}</p>
          ) : (
            <>
              <p className="text-[13px] text-ink">
                Score <span className="font-mono font-semibold tabular-nums">{a.score}</span> / 100 (higher = more machine-generated). Separate from the trust verdict.
                {a.reason && <span className="text-muted"> {a.reason}</span>}
              </p>
              {a.signals.length > 0 && (
                <div className="mt-2 overflow-x-auto rounded-lg border border-line">
                  <table className="w-full min-w-[640px] border-collapse text-left text-[12px]">
                    <thead>
                      <tr className="bg-subtle">
                        <th className="section-label px-3 py-2">Signal</th>
                        <th className="section-label w-[90px] px-3 py-2 text-right">Value</th>
                        <th className="section-label w-[90px] px-3 py-2 text-right">Threshold</th>
                        <th className="section-label w-[80px] px-3 py-2">Fired</th>
                        <th className="section-label px-3 py-2">Detail</th>
                      </tr>
                    </thead>
                    <tbody>
                      {a.signals.map((s) => (
                        <tr key={s.id} className="border-t border-line align-top">
                          <td className="px-3 py-2 font-mono text-[11px] text-ink">{s.id}</td>
                          <td className="px-3 py-2 text-right font-mono tabular-nums">{fmtVal(s.value)}</td>
                          <td className="px-3 py-2 text-right font-mono text-muted tabular-nums">{fmtVal(s.threshold)}</td>
                          <td className="px-3 py-2">{s.fired ? <span className="font-semibold text-med-ink">yes</span> : <span className="text-muted">no</span>}</td>
                          <td className="px-3 py-2 break-words text-ink-2">{clipEvidence(s.detail)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </Section>
      </div>
    </Modal>
  )
}
