import { useEffect, useState } from 'react'
import { CheckCircle, WarningCircle, ChartBar } from '@phosphor-icons/react'
import { requestJson, fetchHistory, verifyAudit } from '../../api'
import type { Report, ScanSummary, AuditVerifyResult } from '../../types'

const DEMO_REPORT_KEY = 'ecdat-last-scan'

function SeverityBar({ label, value, max, colourVar }: { label: string; value: number; max: number; colourVar: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--ink-muted)' }}>
        <span>{label}</span><span style={{ fontFamily: 'var(--font-mono)', color: 'var(--ink)' }}>{value}</span>
      </div>
      <div className="risk-bar-track">
        <div className="risk-bar-fill" style={{ width: `${pct}%`, background: colourVar }} />
      </div>
    </div>
  )
}

export default function Overview() {
  const [report, setReport] = useState<Report | null>(null)
  const [history, setHistory] = useState<ScanSummary[]>([])
  const [audit, setAudit] = useState<AuditVerifyResult | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const id = localStorage.getItem(DEMO_REPORT_KEY)
    const tasks = [
      fetchHistory(10).then(setHistory).catch(() => {}),
      verifyAudit().then(setAudit).catch(() => {}),
      ...(id ? [requestJson<Report>(`/scans/${id}/result?include_cbom=false`).then(setReport).catch(() => {})] : []),
    ]
    Promise.all(tasks).finally(() => setLoading(false))
  }, [])

  const findings = report?.findings ?? []
  const safe     = findings.filter(f => f.severity === 'safe').length
  const review   = findings.filter(f => f.severity === 'review').length
  const high     = findings.filter(f => f.severity === 'high').length
  const critical = findings.filter(f => f.severity === 'critical').length
  const total    = findings.length
  const rs       = report?.risk_summary

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 28 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', margin: '0 0 6px' }}>Overview</h1>
        <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: 0 }}>Cryptographic posture at a glance.</p>
      </div>

      {loading && <div style={{ color: 'var(--ink-muted)', fontSize: 13 }}>Loading…</div>}

      {!loading && !report && (
        <div className="notice notice-info" style={{ display: 'flex', gap: 12, padding: '16px 20px', borderRadius: 'var(--radius-md)', background: 'var(--navy-10)', color: 'var(--navy)', fontSize: 13 }}>
          <ChartBar size={18} weight="light" style={{ flexShrink: 0, marginTop: 1 }} />
          No scan loaded yet. Run a scan from the <strong>&nbsp;Scan&nbsp;</strong> screen to see results here.
        </div>
      )}

      {report && (
        <>
          {/* Stat cards */}
          <div className="stat-grid">
            <div className="stat-card"><div className="stat-label">Total cryptographic assets</div><div className="stat-value stat-ink">{total}</div><div className="stat-sub">{new Set(findings.map(f => f.pattern)).size} algorithm types</div></div>
            <div className="stat-card"><div className="stat-label">Quantum-vulnerable</div><div className="stat-value stat-coral">{rs?.quantum_vulnerable_assets ?? '—'}</div><div className="stat-sub">assets at risk</div></div>
            <div className="stat-card"><div className="stat-label">High severity</div><div className="stat-value stat-rose">{high}</div><div className="stat-sub">findings flagged</div></div>
            <div className="stat-card"><div className="stat-label">PQC-ready / Safe</div><div className="stat-value stat-teal">{safe}</div><div className="stat-sub">compliant assets</div></div>
            <div className="stat-card"><div className="stat-label">Patches proposed</div><div className="stat-value stat-navy">{report.patches?.length ?? 0}</div><div className="stat-sub">review-only diffs</div></div>
          </div>

          {/* Audit status */}
          {audit && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 20px', borderRadius: 'var(--radius-md)', border: '1px solid var(--hairline)', background: 'var(--canvas-warm)' }}>
              {audit.is_valid
                ? <><CheckCircle size={18} weight="light" style={{ color: 'var(--teal-ink)', flexShrink: 0 }} /><span style={{ fontSize: 13, color: 'var(--teal-ink)', fontWeight: 500 }}>Chain verified — {audit.reports_verified} reports verified, {audit.records} records</span></>
                : <><WarningCircle size={18} weight="light" style={{ color: 'var(--coral-ink)', flexShrink: 0 }} /><span style={{ fontSize: 13, color: 'var(--coral-ink)', fontWeight: 500 }}>Chain broken at record {audit.broken_index}</span></>
              }
            </div>
          )}

          {/* Risk distribution */}
          <div style={{ background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', padding: '22px 24px' }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 18 }}>Risk distribution</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <SeverityBar label="Safe" value={safe} max={total} colourVar="var(--teal)" />
              <SeverityBar label="Review" value={review} max={total} colourVar="var(--navy)" />
              <SeverityBar label="High" value={high} max={total} colourVar="var(--rose)" />
              <SeverityBar label="Critical" value={critical} max={total} colourVar="var(--coral)" />
            </div>
          </div>

          {/* Top offenders */}
          {findings.filter(f => f.severity === 'high' || f.severity === 'critical').length > 0 && (
            <div style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
              <div style={{ padding: '18px 22px', borderBottom: '1px solid var(--hairline)', fontSize: 13, fontWeight: 600 }}>Top offenders</div>
              <table className="data-table">
                <thead><tr><th>Asset</th><th>Severity</th><th>Location</th></tr></thead>
                <tbody>
                  {findings.filter(f => f.severity === 'high' || f.severity === 'critical').slice(0, 8).map((f, i) => (
                    <tr key={i}>
                      <td><strong style={{ fontSize: 13 }}>{f.pattern}</strong></td>
                      <td>
                        <span className={`badge badge-${f.severity === 'critical' ? 'critical' : 'high'}`}>
                          {f.severity === 'critical' ? 'Critical' : 'High'}
                        </span>
                      </td>
                      <td className="cell-mono">{f.file}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* Recent history */}
      {history.length > 0 && (
        <div style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
          <div style={{ padding: '18px 22px', borderBottom: '1px solid var(--hairline)', fontSize: 13, fontWeight: 600 }}>Recent scans</div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {history.slice(0, 5).map(s => (
              <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 22px', borderBottom: '1px solid var(--hairline)', fontSize: 12 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.source}</div>
                  <div style={{ color: 'var(--ink-muted)', fontSize: 11, marginTop: 2 }}>{s.findings} findings</div>
                </div>
                {s.quantum_vulnerable != null && <span className="badge badge-coral" style={{ background: 'var(--coral-16)', color: 'var(--coral-ink)' }}>{s.quantum_vulnerable} vulnerable</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
