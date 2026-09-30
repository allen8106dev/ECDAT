import { useEffect, useState } from 'react'
import { X, MagnifyingGlass, CaretRight } from '@phosphor-icons/react'
import { requestJson } from '../../api'
import type { Finding, Report } from '../../types'

const SEVERITY_ORDER = ['critical', 'high', 'review', 'safe', 'info']
const SEVERITY_LABELS: Record<string, string> = { safe: 'Safe', review: 'Review', high: 'High', critical: 'Critical', info: 'Info' }
const CHIP_CLASS: Record<string, string> = { all: 'active-all', safe: 'active-safe', review: 'active-review', high: 'active-high', critical: 'active-critical', info: '' }

function DetailPanel({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const ra = finding.riskAssessment
  return (
    <div className={`detail-panel open`} role="complementary" aria-label="Finding detail">
      <div className="detail-header">
        <div>
          <div style={{ fontWeight: 600, fontSize: 14 }}>{finding.pattern}</div>
          <span className={`badge badge-${finding.severity === 'critical' ? 'critical' : finding.severity === 'high' ? 'high' : finding.severity === 'safe' ? 'safe' : 'review'}`} style={{ marginTop: 6 }}>
            {SEVERITY_LABELS[finding.severity] ?? finding.severity}
          </span>
        </div>
        <button className="btn btn-ghost" style={{ padding: 8 }} onClick={onClose} aria-label="Close panel"><X size={16} /></button>
      </div>

      <div className="detail-body">
        {/* Evidence */}
        <div>
          <div className="detail-section-label">Evidence</div>
          <div className="detail-kv">
            {[
              ['File', finding.file],
              ['Location', finding.line !== null ? `Line ${finding.line}` : `Byte offset ${finding.offset}`],
              ['Kind', finding.kind],
              ['Confidence', finding.confidence],
              ['Pattern', finding.pattern],
            ].map(([k, v]) => (
              <div key={k} className="detail-kv-row">
                <span className="detail-kv-key">{k}</span>
                <span className={`detail-kv-val ${k === 'File' || k === 'Pattern' ? 'mono' : ''}`}>{v}</span>
              </div>
            ))}
            <div className="detail-kv-row">
              <span className="detail-kv-key">Evidence</span>
              <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--ink)', overflowWrap: 'anywhere' }}>{finding.evidence}</code>
            </div>
          </div>
        </div>

        {/* Risk */}
        {ra && (
          <div>
            <div className="detail-section-label">Risk breakdown</div>
            <div style={{ display: 'flex', gap: 16, marginBottom: 14 }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 28, fontWeight: 700, letterSpacing: '-0.03em', color: 'var(--navy)' }}>{ra.risk_score}<span style={{ fontSize: 14, fontWeight: 400 }}>/10</span></div>
                <div style={{ fontSize: 10, color: 'var(--ink-muted)' }}>Risk score</div>
              </div>
              {ra.urgency_score != null && (
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 28, fontWeight: 700, letterSpacing: '-0.03em', color: ra.at_risk_now ? 'var(--coral-ink)' : 'var(--teal-ink)' }}>{ra.urgency_score.toFixed(1)}</div>
                  <div style={{ fontSize: 10, color: 'var(--ink-muted)' }}>Urgency</div>
                </div>
              )}
            </div>
            <div className="risk-bar-row">
              {[
                { label: 'Quantum vulnerable', val: finding.quantum_vulnerable ? 1 : 0 },
                { label: 'At risk now', val: ra.at_risk_now ? 1 : 0 },
                { label: 'Crypto Agility Score', val: (finding.cryptoAgilityScore ?? 0) / 100 },
              ].map(({ label, val }) => (
                <div key={label} style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 10 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--ink-muted)' }}>
                    <span>{label}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--ink)' }}>{label === 'Crypto Agility Score' ? (finding.cryptoAgilityScore ?? '—') : val ? 'Yes' : 'No'}</span>
                  </div>
                  <div className="risk-bar-track">
                    <div className="risk-bar-fill" style={{ width: `${val * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommendation */}
        {finding.recommendation && (
          <div>
            <div className="detail-section-label">Recommendation</div>
            <div className="rec-callout">
              <div className="rec-callout-label">Suggested replacement</div>
              {finding.recommendation}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function Inventory() {
  const [report, setReport] = useState<Report | null>(null)
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<Finding | null>(null)
  const PAGE_SIZE = 50

  useEffect(() => {
    const id = localStorage.getItem('ecdat-last-scan')
    if (!id) return
    requestJson<Report>(`/scans/${id}/result?include_cbom=false`).then(setReport).catch(() => {})
  }, [])

  const filtered = (report?.findings ?? []).filter(f =>
    (severity === 'all' || f.severity === severity) &&
    `${f.file} ${f.pattern} ${f.kind}`.toLowerCase().includes(query.toLowerCase())
  ).sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))

  const visible = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
  const severityCounts = Object.fromEntries(SEVERITY_ORDER.map(s => [s, (report?.findings ?? []).filter(f => f.severity === s).length]))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, position: 'relative' }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', margin: '0 0 6px' }}>Inventory</h1>
        <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: 0 }}>All cryptographic assets found in the last scan.</p>
      </div>

      {!report && (
        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--ink-muted)', fontSize: 13, background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)' }}>
          No scan loaded. Run a scan from the Scan screen first.
        </div>
      )}

      {report && (
        <>
          {/* Filter row */}
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
            {/* Search */}
            <div style={{ position: 'relative', flex: '1 1 200px', minWidth: 180 }}>
              <MagnifyingGlass size={14} style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', color: 'var(--ink-muted)' }} />
              <input className="input-field" style={{ paddingLeft: 32 }} aria-label="Search findings" placeholder="Search algorithm, path…" value={query} onChange={e => { setQuery(e.target.value); setPage(0) }} />
            </div>
            {/* Chips */}
            <button onClick={() => { setSeverity('all'); setPage(0) }} className={`chip ${severity === 'all' ? 'active-all' : ''}`}>All <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>{report.findings.length}</span></button>
            {SEVERITY_ORDER.filter(s => severityCounts[s] > 0).map(s => (
              <button key={s} onClick={() => { setSeverity(s); setPage(0) }} className={`chip ${severity === s ? CHIP_CLASS[s] : ''}`}>
                {SEVERITY_LABELS[s]} <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>{severityCounts[s]}</span>
              </button>
            ))}
          </div>

          {/* Table */}
          <div style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Asset / Severity</th>
                    <th>File</th>
                    <th>Evidence</th>
                    <th style={{ textAlign: 'right' }}>Risk</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((f, i) => (
                    <tr key={`${page}-${i}`} onClick={() => setSelected(f)} style={{ cursor: 'pointer' }}>
                      <td>
                        <strong style={{ fontSize: 13, display: 'block' }}>{f.pattern}</strong>
                        <span className={`badge badge-${f.severity === 'critical' ? 'critical' : f.severity === 'high' ? 'high' : f.severity === 'safe' ? 'safe' : 'review'}`} style={{ marginTop: 5 }}>
                          {SEVERITY_LABELS[f.severity] ?? f.severity}
                        </span>
                      </td>
                      <td className="cell-mono" style={{ maxWidth: 280, overflowWrap: 'anywhere' }}>
                        {f.file}
                        <small style={{ display: 'block', marginTop: 4, color: 'var(--ink-muted)' }}>
                          {f.line !== null ? `Line ${f.line}` : `Offset ${f.offset}`} · {f.kind}
                        </small>
                      </td>
                      <td>
                        <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--ink)', overflowWrap: 'anywhere' }}>{f.evidence}</code>
                        <small style={{ display: 'block', marginTop: 4, color: 'var(--ink-muted)', fontSize: 10 }}>{f.confidence} confidence</small>
                      </td>
                      <td className="cell-num">
                        {f.riskAssessment ? (
                          <span style={{ fontSize: 18, fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--ink)' }}>{f.riskAssessment.risk_score}<span style={{ fontSize: 11, fontWeight: 400, color: 'var(--ink-muted)' }}>/10</span></span>
                        ) : '—'}
                      </td>
                      <td><CaretRight size={14} style={{ color: 'var(--ink-muted)' }} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {!filtered.length && (
              <div style={{ padding: '48px', textAlign: 'center', color: 'var(--ink-muted)', fontSize: 13 }}>
                {report.findings.length ? 'No findings match these filters.' : 'No cryptographic signatures were found.'}
              </div>
            )}

            {/* Pagination */}
            {filtered.length > PAGE_SIZE && (
              <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 10, padding: '14px 20px', borderTop: '1px solid var(--hairline)', fontSize: 12, color: 'var(--ink-muted)' }}>
                <span>Page {page + 1} of {Math.ceil(filtered.length / PAGE_SIZE)}</span>
                <button className="btn" style={{ padding: '6px 12px', fontSize: 12 }} disabled={page === 0} onClick={() => setPage(p => p - 1)}>Previous</button>
                <button className="btn" style={{ padding: '6px 12px', fontSize: 12 }} disabled={(page + 1) * PAGE_SIZE >= filtered.length} onClick={() => setPage(p => p + 1)}>Next</button>
              </div>
            )}
          </div>

          <p style={{ fontSize: 11, color: 'var(--ink-muted)', lineHeight: 1.8, margin: 0 }}>
            Findings are discovery evidence, not proof of a vulnerability. Comments and unused code can match. Binary analysis inspects symbols and strings, not arbitrary runtime behaviour.
          </p>
        </>
      )}

      {/* Slide-in detail panel */}
      {selected && <DetailPanel finding={selected} onClose={() => setSelected(null)} />}
      {selected && <div style={{ position: 'fixed', inset: 0, background: 'rgba(21,22,26,0.15)', zIndex: 99 }} onClick={() => setSelected(null)} />}
    </div>
  )
}
