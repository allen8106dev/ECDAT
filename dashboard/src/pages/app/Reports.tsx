import { useState, useEffect } from 'react'
import { FileJs, FilePdf, DownloadSimple } from '@phosphor-icons/react'
import { requestJson, API } from '../../api'
import type { Report } from '../../types'

function DownloadCard({
  Icon, title, description, onDownload, busy,
}: { Icon: React.ElementType; title: string; description: string; onDownload: () => void; busy?: boolean }) {
  return (
    <div className="card" style={{ padding: 28, display: 'flex', flexDirection: 'column', gap: 0 }}>
      <Icon size={24} weight="light" style={{ color: 'var(--navy)', marginBottom: 14 }} />
      <div style={{ fontWeight: 600, fontSize: 15, color: 'var(--ink)', marginBottom: 6 }}>{title}</div>
      <div style={{ fontSize: 13, color: 'var(--ink-muted)', lineHeight: 1.7, flex: 1, marginBottom: 20 }}>{description}</div>
      <button className="btn btn-navy" style={{ gap: 8, alignSelf: 'flex-start' }} onClick={onDownload} disabled={busy}>
        <DownloadSimple size={15} /> {busy ? 'Preparing…' : 'Download'}
      </button>
    </div>
  )
}

export default function Reports() {
  const [report, setReport] = useState<Report | null>(null)
  const [pdfBusy, setPdfBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const id = localStorage.getItem('ecdat-last-scan')
    if (!id) return
    requestJson<Report>(`/scans/${id}/result?include_cbom=false`).then(setReport).catch(() => {})
  }, [])

  function download(path: string, name: string) {
    const link = document.createElement('a'); link.href = `${API}${path}`; link.download = name; link.click()
  }

  async function downloadPdf() {
    if (!report) return
    setPdfBusy(true); setError('')
    try {
      const r = await fetch(`${API}/scans/${report.id}/report.pdf`, { signal: AbortSignal.timeout(30000) })
      if (!r.ok) throw new Error(`PDF export failed (HTTP ${r.status})`)
      const blob = await r.blob()
      if (!blob.type.includes('application/pdf')) throw new Error('Backend did not return a PDF.')
      const href = URL.createObjectURL(blob)
      const link = document.createElement('a'); link.href = href; link.download = `ecdat-${report.id}.pdf`; link.click()
      setTimeout(() => URL.revokeObjectURL(href), 1000)
    } catch (e) { setError(String(e)) } finally { setPdfBusy(false) }
  }

  async function downloadSigned() {
    if (!report) return
    try {
      const r = await fetch(`${API}/scans/${report.id}/signed.zip`, { signal: AbortSignal.timeout(30000) })
      if (!r.ok) { setError('Signed export failed.'); return }
      const href = URL.createObjectURL(await r.blob())
      const link = document.createElement('a'); link.href = href; link.download = `ecdat-${report.id}-signed.zip`; link.click()
      setTimeout(() => URL.revokeObjectURL(href), 1000)
    } catch (e) { setError(String(e)) }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', margin: '0 0 6px' }}>Reports</h1>
        <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: 0 }}>Download scan results in your preferred format.</p>
      </div>

      {!report && (
        <div style={{ padding: '48px', textAlign: 'center', color: 'var(--ink-muted)', fontSize: 13, background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)' }}>
          No scan loaded. Run a scan first to generate reports.
        </div>
      )}

      {error && (
        <div style={{ display: 'flex', gap: 10, padding: '12px 16px', borderRadius: 'var(--radius-md)', background: 'var(--coral-16)', color: 'var(--coral-ink)', fontSize: 13 }}>
          {error}
        </div>
      )}

      {report && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(260px,1fr))', gap: 20 }}>
            <DownloadCard
              Icon={FileJs}
              title="Download CBOM (JSON)"
              description="Cryptography Bill of Materials — CycloneDX 1.4 format. Machine-readable, suitable for toolchain integration."
              onDownload={() => download(`/scans/${report.id}/cbom?download=true`, `cbom-${report.id}.json`)}
            />
            <DownloadCard
              Icon={FileJs}
              title="Full report (JSON)"
              description="Complete scan findings, risk profile, dependency graphs, and audit block hash in one JSON file."
              onDownload={() => download(`/scans/${report.id}/report.json`, `ecdat-${report.id}.json`)}
            />
            <DownloadCard
              Icon={FilePdf}
              title="Executive report (PDF)"
              description="Summary report for stakeholders — findings overview, Mosca analysis, risk distribution."
              onDownload={downloadPdf}
              busy={pdfBusy}
            />
            <DownloadCard
              Icon={FilePdf}
              title="Signed bundle (PDF + JSON)"
              description="Signed ZIP containing the PDF and JSON reports, verifiable against the backend's public key."
              onDownload={downloadSigned}
            />
          </div>

          <div style={{ fontSize: 11, color: 'var(--ink-muted)', lineHeight: 1.8, padding: '4px 0' }}>
            Scan ID: <code style={{ fontFamily: 'var(--font-mono)' }}>{report.id}</code> · Source: {report.source}
          </div>
        </>
      )}
    </div>
  )
}
