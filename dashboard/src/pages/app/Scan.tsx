import { useEffect, useRef, useState } from 'react'
import { GitBranch, Upload, ArrowRight, Play, Warning } from '@phosphor-icons/react'
import { requestJson, validateJob, checkHealth, profileParams } from '../../api'
import { droppedFiles, prepareUpload, selectedFiles } from '../../uploads'
import type { Job, RiskProfile, Report } from '../../types'
import { API } from '../../api'

const STAGES: { key: string; label: string }[] = [
  { key: 'queued',      label: 'Queued' },
  { key: 'downloading', label: 'Downloading' },
  { key: 'scanning',    label: 'Scanning' },
  { key: 'completed',   label: 'Complete' },
]

function stageIndex(status: string) {
  return STAGES.findIndex(s => s.key === status)
}

function Stepper({ status }: { status: string }) {
  const current = stageIndex(status)
  return (
    <div className="stepper">
      {STAGES.map((s, i) => {
        const done   = i < current
        const active = i === current
        return (
          <div key={s.key} className="step">
            {i > 0 && <div className={`step-connector ${done || active ? 'done' : ''}`} />}
            <div className={`step-dot ${done ? 'done' : active ? 'active' : 'pending'}`}>
              {done ? '✓' : i + 1}
            </div>
            <span className={`step-label ${active ? 'active' : ''}`}>{s.label}</span>
          </div>
        )
      })}
    </div>
  )
}

export default function Scan() {
  const [url, setUrl] = useState('')
  const [gitRef, setGitRef] = useState('')
  const [scanMode, setScanMode] = useState('standard')
  const [profile, setProfile] = useState<RiskProfile>({ data_lifetime_years: 10, migration_time_years: 3, criticality: 5, crqc_arrival_years: 10 })
  const [job, setJob] = useState<Job | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [dragging, setDragging] = useState(false)
  const [uploadProgress, setUploadProgress] = useState<number | null>(null)
  const [report, setReport] = useState<Report | null>(null)

  const fileInput    = useRef<HTMLInputElement>(null)
  const folderInput  = useRef<HTMLInputElement>(null)
  const active       = useRef(false)
  const alive        = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])

  // Poll for job completion
  const jobId = job?.id
  useEffect(() => {
    if (!jobId) return
    let disposed = false
    let timer: ReturnType<typeof setTimeout>
    let failures = 0
    const ctrl = new AbortController()
    const poll = async () => {
      try {
        const next = validateJob(await requestJson(`/scans/${jobId}`, { signal: ctrl.signal }))
        if (disposed) return
        if (next.status === 'completed') {
          const r = await requestJson<Report>(`/scans/${jobId}/result?include_cbom=false`, { signal: ctrl.signal })
          if (disposed) return
          setReport(r); setJob(next); setBusy(false); active.current = false
          localStorage.setItem('ecdat-last-scan', jobId)
          return
        }
        if (next.status === 'failed') {
          setJob(next); setError(next.error || 'Scan failed.'); setBusy(false); active.current = false; return
        }
        setJob(next); failures = 0
      } catch (e) {
        if (disposed) return
        if (++failures >= 5) { setError(`Connection lost. ${String(e)}`); setBusy(false); active.current = false; return }
      }
      timer = setTimeout(poll, 800)
    }
    timer = setTimeout(poll, 300)
    return () => { disposed = true; ctrl.abort(); clearTimeout(timer) }
  }, [jobId])

  function begin() {
    if (active.current) return false
    active.current = true; setBusy(true); setError(''); setReport(null); setJob(null)
    return true
  }
  function accepted(next: Job) {
    const v = validateJob(next); setJob(v); setUploadProgress(null)
  }
  function failed(e: unknown) { setError(String(e)); setBusy(false); setUploadProgress(null); active.current = false }

  async function startRepo(demo = false) {
    if (!begin()) return
    try {
      const health = await checkHealth()
      if (health.version !== '2.0.0') throw new Error('An older ECDAT backend is running. Restart it and refresh.')
      accepted(await requestJson(demo ? `/scan?${profileParams(profile, scanMode)}` : '/scans/repository', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        ...(demo ? {} : { body: JSON.stringify({ url: url.trim(), ref: gitRef.trim(), ...profile, scan_mode: scanMode }) }),
      }))
    } catch (e) { failed(e) }
  }

  async function upload(entries: ReturnType<typeof droppedFiles> | ReturnType<typeof selectedFiles>) {
    if (!begin()) return
    try {
      const file = prepareUpload(await entries)
      const health = await checkHealth()
      if (health.version !== '2.0.0') throw new Error('An older ECDAT backend is running. Restart it and refresh.')
      setUploadProgress(0)
      const xhr = new XMLHttpRequest()
      xhr.open('POST', `${API}/scans/upload?filename=${encodeURIComponent(file.name)}&${profileParams(profile, scanMode)}`)
      xhr.setRequestHeader('Content-Type', 'application/octet-stream')
      xhr.timeout = 180000
      xhr.upload.onprogress = e => { if (e.lengthComputable) setUploadProgress(Math.round(e.loaded / e.total * 100)) }
      xhr.onerror = () => failed('Upload interrupted. Re-select the file and retry.')
      xhr.ontimeout = () => failed('Upload timed out. Try a smaller archive.')
      xhr.onload = () => {
        try {
          const data = JSON.parse(xhr.responseText)
          if (xhr.status >= 400) throw new Error(data.detail || 'Upload failed.')
          accepted(data)
        } catch (e) { failed(e) }
      }
      xhr.send(file)
    } catch (e) { failed(e) }
  }

  function setNum(key: keyof RiskProfile, val: string) {
    const n = Number(val)
    if (Number.isFinite(n)) setProfile(p => ({ ...p, [key]: n }))
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 28 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', margin: '0 0 6px' }}>Scan</h1>
        <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: 0 }}>Import a repository or upload a codebase to start your cryptographic inventory.</p>
      </div>

      {!busy && !report && (
        <>
          {/* Entry cards */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
            {/* Repo card */}
            <div className="card" style={{ padding: 28 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
                <GitBranch size={20} weight="light" style={{ color: 'var(--navy)' }} />
                <div style={{ fontWeight: 600, fontSize: 15 }}>Scan a repository</div>
                <span style={{ marginLeft: 'auto', fontSize: 9, letterSpacing: '0.08em', color: 'var(--ink-muted)', background: 'var(--canvas-warm)', padding: '3px 8px', borderRadius: 4, textTransform: 'uppercase', border: '1px solid var(--hairline)' }}>GIT</span>
              </div>
              <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: '0 0 20px', lineHeight: 1.7 }}>Scan an HTTPS clone URL from any Git host.</p>
              <form onSubmit={e => { e.preventDefault(); void startRepo() }}>
                <label className="input-label">Repository URL</label>
                <input className="input-field" type="text" required placeholder="https://github.com/owner/repository" value={url} onChange={e => setUrl(e.target.value)} disabled={busy} style={{ marginBottom: 14 }} />
                <label className="input-label">Branch, tag or commit <span style={{ color: 'var(--ink-muted)', fontWeight: 400 }}>(optional)</span></label>
                <input className="input-field" placeholder="Default branch" value={gitRef} onChange={e => setGitRef(e.target.value)} disabled={busy} style={{ marginBottom: 20 }} />
                <button className="btn btn-primary btn-full" disabled={busy || !url.trim()} type="submit">
                  Scan repository <ArrowRight size={15} />
                </button>
              </form>
            </div>

            {/* Upload card */}
            <div className="card" style={{ padding: 28 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
                <Upload size={20} weight="light" style={{ color: 'var(--navy)' }} />
                <div style={{ fontWeight: 600, fontSize: 15 }}>Upload your codebase</div>
              </div>
              <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: '0 0 16px', lineHeight: 1.7 }}>Drop a folder, repository archive, container export or source file.</p>
              <button
                type="button"
                className={`dropzone ${dragging ? 'drag-over' : ''}`}
                disabled={busy}
                onClick={() => fileInput.current?.click()}
                onDragOver={e => { e.preventDefault(); setDragging(true) }}
                onDragLeave={() => setDragging(false)}
                onDrop={e => { e.preventDefault(); setDragging(false); if (!busy) void upload(droppedFiles(e.dataTransfer.items, e.dataTransfer.files)) }}
              >
                <Upload size={32} weight="light" className="dropzone-icon" />
                <strong className="dropzone-title">Drag &amp; drop files or a folder</strong>
                <span className="dropzone-hint">or <b>browse files</b></span>
                <span className="dropzone-note">Folders · ZIP · TAR.GZ · JAR · binaries — up to 128 MiB</span>
              </button>
              <button type="button" className="btn btn-ghost btn-full" style={{ marginTop: 8 }} disabled={busy} onClick={() => folderInput.current?.click()}>
                Choose folder
              </button>
              <input ref={fileInput} type="file" multiple hidden onChange={e => { if (e.target.files?.length) void upload(selectedFiles(e.target.files)); e.target.value = '' }} />
              <input ref={folderInput} type="file" multiple hidden {...{ webkitdirectory: '' }} onChange={e => { if (e.target.files?.length) void upload(selectedFiles(e.target.files)); e.target.value = '' }} />
            </div>
          </div>

          {/* Demo row */}
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 10, fontSize: 13, color: 'var(--ink-muted)', padding: '4px 0' }}>
            <span>Want to see how it works?</span>
            <button className="btn btn-ghost" disabled={busy} onClick={() => void startRepo(true)} style={{ fontSize: 13, gap: 6 }}>
              <Play size={13} weight="fill" /> Replay demo scan
            </button>
          </div>

          {/* Risk profile */}
          <details style={{ background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', padding: '18px 24px' }}>
            <summary style={{ fontSize: 13, fontWeight: 600, cursor: 'pointer', color: 'var(--ink)' }}>Mosca risk profile for this scan</summary>
            <p style={{ fontSize: 12, color: 'var(--ink-muted)', margin: '12px 0 16px', lineHeight: 1.7 }}>These values drive the urgency score. They are embedded in the report.</p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 14 }}>
              {([
                ['data_lifetime_years', 'Data lifetime (years)'],
                ['migration_time_years', 'Migration time (years)'],
                ['criticality', 'Business criticality (1–10)'],
                ['crqc_arrival_years', 'CRQC horizon (years)'],
              ] as [keyof RiskProfile, string][]).map(([key, label]) => (
                <div key={key}>
                  <label className="input-label">{label}</label>
                  <input className="input-field" type="number" min={key === 'criticality' ? 1 : 0} max={key === 'criticality' ? 10 : 100} value={profile[key]} onChange={e => setNum(key, e.target.value)} disabled={busy} />
                </div>
              ))}
            </div>
          </details>

          {/* Scan mode */}
          <div style={{ background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', padding: '18px 24px' }}>
            <label className="input-label">Scan budget</label>
            <select className="input-field" value={scanMode} onChange={e => setScanMode(e.target.value)} disabled={busy} style={{ marginBottom: 10 }}>
              <option value="standard">Standard — up to 20,000 findings / 2 minutes</option>
              <option value="large">Large codebase — up to 200,000 findings / 10 minutes</option>
            </select>
            <p style={{ fontSize: 12, color: 'var(--ink-muted)', margin: 0, lineHeight: 1.7 }}>Use Large for crypto-heavy projects such as OpenSSL.</p>
          </div>
        </>
      )}

      {/* Error */}
      {error && (
        <div style={{ display: 'flex', gap: 12, padding: '14px 18px', borderRadius: 'var(--radius-md)', background: 'var(--coral-16)', color: 'var(--coral-ink)', fontSize: 13 }} role="alert">
          <Warning size={18} weight="light" style={{ flexShrink: 0, marginTop: 1 }} />
          {error}
        </div>
      )}

      {/* Progress stepper */}
      {busy && job && (
        <div className="card" style={{ padding: 28 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
            {uploadProgress !== null ? `Uploading · ${uploadProgress}%` : `${job.status}…`}
          </div>
          <div style={{ fontSize: 12, color: 'var(--ink-muted)', marginBottom: 16 }}>{job.source}</div>
          <Stepper status={job.status} />
        </div>
      )}

      {/* Result summary */}
      {report && (
        <div className="card" style={{ padding: 28 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
            <span className="badge badge-safe">Completed</span>
            <span style={{ fontSize: 13, fontWeight: 500 }}>{report.source}</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(130px,1fr))', gap: 14 }}>
            {[
              { label: 'Files scanned', value: report.stats.files_scanned },
              { label: 'Findings',      value: report.findings.length },
              { label: 'Dependencies',  value: report.stats.dependencies_found ?? 0 },
              { label: 'Duration',      value: `${report.stats.duration_seconds}s` },
            ].map(({ label, value }) => (
              <div key={label} style={{ background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-md)', padding: '16px 18px' }}>
                <div style={{ fontSize: 11, color: 'var(--ink-muted)', marginBottom: 6 }}>{label}</div>
                <div style={{ fontSize: 24, fontWeight: 700, letterSpacing: '-0.02em' }}>{value}</div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 18, fontSize: 12, color: 'var(--ink-muted)', lineHeight: 1.7 }}>
            Scan complete. Visit <strong>Inventory</strong> to explore findings, <strong>Risk &amp; Migration</strong> for the Mosca analysis, or <strong>Reports</strong> to download.
          </div>
        </div>
      )}
    </div>
  )
}
