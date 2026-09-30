import { useState, useEffect } from 'react'
import { CheckCircle, WarningCircle } from '@phosphor-icons/react'
import { verifyAudit, requestJson } from '../../api'
import type { AuditVerifyResult, Report } from '../../types'

// Demo chain data — replaced by real data when a scan is loaded
const buildChain = (report: Report | null) => {
  if (!report) return []
  return [
    { event: 'Scan initiated', timestamp: new Date().toISOString(), prevHash: '0000000000000000', hash: report.audit_block_hash ?? 'pending' },
  ]
}

export default function Audit() {
  const [auditResult, setAuditResult] = useState<AuditVerifyResult | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [verifyDone, setVerifyDone] = useState(false)
  const [report, setReport] = useState<Report | null>(null)
  const [tamperDemo, setTamperDemo] = useState(false)

  useEffect(() => {
    const id = localStorage.getItem('ecdat-last-scan')
    if (!id) return
    requestJson<Report>(`/scans/${id}/result?include_cbom=false`).then(setReport).catch(() => {})
  }, [])

  async function doVerify() {
    setVerifying(true)
    try {
      const r = await verifyAudit()
      setAuditResult(r); setVerifyDone(true)
    } catch (e) {
      setAuditResult({ is_valid: false, broken_index: null, records: 0, reports_verified: 0, error: String(e) })
      setVerifyDone(true)
    } finally { setVerifying(false) }
  }

  const chain = buildChain(report)
  // Demo: if tamperDemo, flip the first block's hash display
  const displayChain = tamperDemo && chain.length > 0
    ? [{ ...chain[0], hash: chain[0].hash.replace(/[a-f]/g, 'x') }, ...chain.slice(1)]
    : chain

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', margin: '0 0 6px' }}>Audit chain</h1>
        <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: 0 }}>Tamper-evident record of every scan. Each block commits the CBOM hash.</p>
      </div>

      {/* Verify */}
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <button
          className={`btn ${verifyDone && auditResult?.is_valid ? 'btn-primary' : 'btn-navy'}`}
          style={{ gap: 8 }}
          onClick={doVerify}
          disabled={verifying}
        >
          {verifying ? 'Verifying…' : verifyDone && auditResult?.is_valid ? <><CheckCircle size={15} /> Chain verified</> : 'Verify audit chain'}
        </button>
        {verifyDone && auditResult && !auditResult.is_valid && (
          <span style={{ fontSize: 13, color: 'var(--coral-ink)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <WarningCircle size={15} weight="light" />
            {auditResult.error ?? `Chain broken at record ${auditResult.broken_index}`}
          </span>
        )}
        {verifyDone && auditResult?.is_valid && (
          <span style={{ fontSize: 13, color: 'var(--teal-ink)' }}>
            {auditResult.reports_verified} reports verified · {auditResult.records} records
          </span>
        )}
      </div>

      {/* Tamper demo toggle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 18px', background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-md)', fontSize: 13 }}>
        <span style={{ flex: 1, color: 'var(--ink-muted)' }}>Tamper-check demo — flip a block hash to see chain break detection</span>
        <button
          className={`btn ${tamperDemo ? 'btn-navy' : ''}`}
          style={{ padding: '6px 14px', fontSize: 12 }}
          onClick={() => setTamperDemo(!tamperDemo)}
        >
          {tamperDemo ? 'Reset chain' : 'Simulate tamper'}
        </button>
      </div>

      {/* Chain */}
      {chain.length === 0 && (
        <div style={{ padding: '48px', textAlign: 'center', color: 'var(--ink-muted)', fontSize: 13, background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)' }}>
          No audit records yet. Run a scan to create the first block.
        </div>
      )}

      <div className="chain-list">
        {displayChain.map((block, i) => {
          const isBroken = tamperDemo && i === 0
          return (
            <div key={i} className="chain-item">
              <div className="chain-connector">
                <div className={`chain-dot ${isBroken ? 'broken' : ''}`} />
                {i < displayChain.length - 1 && <div className={`chain-line ${isBroken ? 'broken' : ''}`} />}
              </div>
              <div className={`chain-card ${isBroken ? 'broken' : ''}`} style={{ marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{block.event}</div>
                  {isBroken && (
                    <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--coral-ink)', display: 'flex', alignItems: 'center', gap: 4 }}>
                      <WarningCircle size={13} weight="light" /> Chain broken at block {i}
                    </span>
                  )}
                </div>
                <div className="chain-hash">
                  <span style={{ color: 'var(--ink-muted)' }}>Timestamp: </span>{new Date(block.timestamp).toLocaleString()}<br />
                  <span style={{ color: 'var(--ink-muted)' }}>Prev hash:&nbsp; </span>{block.prevHash}<br />
                  <span style={{ color: 'var(--ink-muted)' }}>Hash:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; </span>
                  <span style={{ color: isBroken ? 'var(--coral-ink)' : 'var(--ink)' }}>{block.hash}</span>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
