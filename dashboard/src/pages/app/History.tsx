import { useEffect, useState } from 'react'
import { GitBranch, Upload, Monitor } from '@phosphor-icons/react'
import { fetchHistory, requestJson } from '../../api'
import type { ScanSummary, Report } from '../../types'

const SEV_DOT: Record<string, string> = { safe: 'var(--teal)', review: 'var(--navy)', high: 'var(--rose)', critical: 'var(--coral)' }
const SEV_LABEL: Record<string, string> = { safe: 'Safe', review: 'Review', high: 'High', critical: 'Critical' }

function SourceIcon({ source }: { source: string }) {
  if (source.startsWith('http')) return <GitBranch size={16} weight="light" style={{ color: 'var(--ink-muted)', flexShrink: 0 }} />
  if (source.toLowerCase().includes('upload') || source.toLowerCase().includes('.zip') || source.toLowerCase().includes('.tar')) return <Upload size={16} weight="light" style={{ color: 'var(--ink-muted)', flexShrink: 0 }} />
  return <Monitor size={16} weight="light" style={{ color: 'var(--ink-muted)', flexShrink: 0 }} />
}

function SeverityCluster({ findings, report }: { findings: number; report?: Report }) {
  if (!report) return <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--ink-muted)' }}>{findings} findings</span>
  const byLevel = ['safe', 'review', 'high', 'critical'].filter(s => report.findings.some(f => f.severity === s))
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
      {byLevel.map(s => (
        <div key={s} title={SEV_LABEL[s]} style={{ width: 9, height: 9, borderRadius: '50%', background: SEV_DOT[s] }} />
      ))}
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--ink-muted)', marginLeft: 4 }}>{findings}</span>
    </div>
  )
}

export default function History() {
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [active, setActive] = useState<string | null>(null)
  const [reports, setReports] = useState<Record<string, Report>>({})

  useEffect(() => {
    fetchHistory(50).then(setScans).catch(() => {}).finally(() => setLoading(false))
  }, [])

  function loadReport(id: string) {
    if (reports[id]) { setActive(id); return }
    requestJson<Report>(`/scans/${id}/result?include_cbom=false`).then(r => {
      setReports(prev => ({ ...prev, [id]: r }))
      setActive(id)
    }).catch(() => {})
  }

  const selectedReport = active ? reports[active] : undefined

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', margin: '0 0 6px' }}>History</h1>
        <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: 0 }}>Past scans, most recent first.</p>
      </div>

      {loading && <div style={{ color: 'var(--ink-muted)', fontSize: 13 }}>Loading…</div>}

      {!loading && scans.length === 0 && (
        <div style={{ padding: '48px', textAlign: 'center', color: 'var(--ink-muted)', fontSize: 13, background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)' }}>
          No scan history yet. Run your first scan from the Scan screen.
        </div>
      )}

      {scans.length > 0 && (
        <div style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
          {scans.map((s, i) => (
            <div key={s.id}
              style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '14px 22px', borderBottom: i < scans.length - 1 ? '1px solid var(--hairline)' : 'none', cursor: 'pointer', background: active === s.id ? 'var(--navy-8)' : 'var(--canvas)', transition: 'background 0.13s' }}
              onClick={() => loadReport(s.id)}
            >
              <SourceIcon source={s.source} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 500, fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.source}</div>
                <div style={{ fontSize: 11, color: 'var(--ink-muted)', marginTop: 2 }}>
                  {s.timestamp ? new Date(s.timestamp).toLocaleString() : 'Unknown time'}
                </div>
              </div>
              <SeverityCluster findings={s.findings} report={reports[s.id]} />
            </div>
          ))}
        </div>
      )}

      {/* Selected scan summary */}
      {selectedReport && (
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>{selectedReport.source}</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(120px,1fr))', gap: 12 }}>
            {[
              { label: 'Findings', value: selectedReport.findings.length },
              { label: 'Quantum-vuln', value: selectedReport.risk_summary?.quantum_vulnerable_assets ?? '—' },
              { label: 'Files', value: selectedReport.stats.files_scanned },
              { label: 'Duration', value: `${selectedReport.stats.duration_seconds}s` },
            ].map(({ label, value }) => (
              <div key={label} style={{ background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-md)', padding: '14px 16px' }}>
                <div style={{ fontSize: 10, color: 'var(--ink-muted)', marginBottom: 4 }}>{label}</div>
                <div style={{ fontSize: 20, fontWeight: 700, letterSpacing: '-0.02em' }}>{value}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
