import { useEffect, useRef, useState } from 'react'
import { ShieldCheck, UploadCloud, GitBranch, Search, Download, FileCode2, Box, Binary, LoaderCircle, ArrowRight, AlertTriangle } from 'lucide-react'

import { droppedFiles, prepareUpload, selectedFiles } from './uploads'
import type { UploadEntry } from './uploads'

const API = import.meta.env.VITE_API_URL || '/api'
type Stats = { files_scanned?: number; files_skipped?: number; archives_opened?: number; text_files?: number; binary_files?: number; duration_seconds?: number; dependencies_found?: number; container_manifests_found?: number }
type Job = { id: string; source: string; status: string; stats: Stats; error?: string }
type RawFinding = { file: string; line: number | null; offset: number | null; pattern: string; evidence: string; kind: string; severity: string; confidence: string; recommendation: string }
type RiskAssessment = { at_risk_now: boolean; urgency_score: number | null; risk_score: number }
type RiskProfile = { data_lifetime_years: number; migration_time_years: number; criticality: number; crqc_arrival_years: number }
type Finding = RawFinding & { classification?: string; quantum_vulnerable?: boolean; riskAssessment?: RiskAssessment; cryptoAgilityScore?: number; metadata?: Record<string, unknown> }
type RiskSummary = { assets_assessed: number; quantum_vulnerable_assets: number; at_risk_now: number; average_crypto_agility_score: number | null }
type Patch = { file: string; changes: string[]; diff: string[]; review_required: boolean }
type Report = { id: string; source: string; findings: Finding[]; patches?: Patch[]; stats: Stats; warnings: string[]; partial: boolean; cbom: unknown; profile: RiskProfile; risk_summary?: RiskSummary; audit_block_hash?: string; audit_error?: string }
async function jsonResponse(response: Response) {
  const data = await response.json().catch(() => { throw new Error(`Scanner returned an invalid response (HTTP ${response.status}). Check the API connection.`) })
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail))
  return data
}
async function requestJson(path: string, options: RequestInit = {}) {
  const timeout = new AbortController()
  const timer = setTimeout(() => timeout.abort(), 15000)
  const abort = () => timeout.abort()
  options.signal?.addEventListener('abort', abort, { once: true })
  if (options.signal?.aborted) timeout.abort()
  try {
    return await fetch(`${API}${path}`, { ...options, signal: timeout.signal }).then(jsonResponse)
  } catch (error) {
    if (timeout.signal.aborted && !options.signal?.aborted) {
      throw new Error('The scanner did not respond within 15 seconds. Check the backend connection and retry.')
    }
    throw error
  } finally {
    clearTimeout(timer)
    options.signal?.removeEventListener('abort', abort)
  }
}
function validateJob(value: unknown): Job {
  const job = value as Partial<Job> | null
  if (!job || typeof job.id !== 'string' || !/^[a-f0-9]{32}$/.test(job.id) ||
      !['queued', 'downloading', 'scanning', 'completed', 'failed'].includes(job.status || '') ||
      typeof job.source !== 'string' || !job.stats || typeof job.stats !== 'object') {
    throw new Error('The dashboard is connected to an outdated or incompatible backend. Restart the ECDAT backend and refresh this page.')
  }
  return job as Job
}
function download(data: unknown, name: string) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }))
  const link = document.createElement('a'); link.href = url; link.download = name; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export default function App() {
  const [url, setUrl] = useState('')
  const [ref, setRef] = useState('')
  const [job, setJob] = useState<Job | null>(null)
  const [report, setReport] = useState<Report | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [dragging, setDragging] = useState(false)
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [page, setPage] = useState(0)
  const [audit, setAudit] = useState('')
  const [uploadProgress, setUploadProgress] = useState<number | null>(null)
  const [profile, setProfile] = useState<RiskProfile>({ data_lifetime_years: 10, migration_time_years: 3, criticality: 5, crqc_arrival_years: 10 })
  const input = useRef<HTMLInputElement>(null)
  const folderInput = useRef<HTMLInputElement>(null)
  const active = useRef(false)
  const alive = useRef(true)
  const jobId = job?.id
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])

  useEffect(() => {
    if (!jobId) return
    let disposed = false
    let timer: ReturnType<typeof setTimeout>
    let failures = 0
    const controller = new AbortController()
    const poll = async () => {
      try {
        const next = validateJob(await requestJson(`/scans/${jobId}`, { signal: controller.signal }))
        if (disposed) return
        if (next.status === 'completed') {
          const result: Report = await requestJson(`/scans/${jobId}/result`, { signal: controller.signal })
          if (disposed) return
          setReport(result); setPage(0); setJob(next); setBusy(false); active.current = false
          return
        }
        if (next.status === 'failed') {
          setJob(next); setError(next.error || 'Scan failed.'); setBusy(false); active.current = false
          return
        }
        setJob(next)
        failures = 0
      } catch (e) {
        if (disposed) return
        if (++failures >= 5) {
          setError(`Connection lost. ${String(e)} Refresh to reconnect to this scan.`)
          setBusy(false); active.current = false
          return
        }
      }
      timer = setTimeout(poll, 800)
    }
    timer = setTimeout(poll, 300)
    return () => { disposed = true; controller.abort(); clearTimeout(timer) }
  }, [jobId])

  useEffect(() => {
    const id = localStorage.getItem('ecdat-last-scan')
    if (!id) return
    requestJson(`/scans/${id}`).then(validateJob).then(async (saved: Job) => {
      if (!alive.current || active.current) return
      if (saved.status === 'completed') {
        const result = await requestJson(`/scans/${id}/result`)
        if (!alive.current || active.current) return
        setReport(result); setJob(saved)
      } else if (saved.status !== 'failed') {
        active.current = true; setBusy(true); setJob(saved)
      }
    }).catch(() => { /* No saved report on this backend. */ })
  }, [])

  function begin() {
    if (active.current) return false
    active.current = true; setBusy(true); setError(''); setReport(null); setJob(null); setAudit(''); setQuery(''); setSeverity('all')
    return true
  }
  function accepted(next: Job) {
    const valid = validateJob(next)
    setJob(valid); setUploadProgress(null); localStorage.setItem('ecdat-last-scan', valid.id)
  }
  function failed(e: unknown) { setError(String(e)); setBusy(false); setUploadProgress(null); active.current = false }
  function profileQuery() {
    return new URLSearchParams(Object.entries(profile).map(([key, value]) => [key, String(value)])).toString()
  }
  function setProfileNumber(key: keyof RiskProfile, value: string) {
    const next = Number(value)
    if (Number.isFinite(next)) setProfile(current => ({ ...current, [key]: next }))
  }
  async function startGithub(demo = false) {
    if (!begin()) return
    try {
      const health = await requestJson('/')
      if (health.version !== '2.0.0') throw new Error('An older ECDAT backend is still running. Restart the backend, then refresh this page and retry.')
      accepted(await requestJson(demo ? `/scan?${profileQuery()}` : '/scans/github', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        ...(demo ? {} : { body: JSON.stringify({ url: url.trim(), ref: ref.trim(), ...profile }) }),
      }))
    } catch (e) { failed(e) }
  }
  async function upload(entries: UploadEntry[] | Promise<UploadEntry[]>) {
    if (!begin()) return
    try {
      const file = prepareUpload(await entries)
      const health = await requestJson('/')
      if (health.version !== '2.0.0') throw new Error('An older ECDAT backend is running. Restart it and refresh this page.')
    setUploadProgress(0)
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${API}/scans/upload?filename=${encodeURIComponent(file.name)}&${profileQuery()}`)
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')
    xhr.timeout = 180000
    xhr.upload.onprogress = e => { if (e.lengthComputable) setUploadProgress(Math.round(e.loaded / e.total * 100)) }
    xhr.onerror = () => failed('The upload connection was interrupted or a selected file could not be read. Re-select the file or folder and retry at http://localhost:5173/.')
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
  const findings = report?.findings.filter(f => (severity === 'all' || f.severity === severity) && `${f.file} ${f.pattern} ${f.kind}`.toLowerCase().includes(query.toLowerCase())) || []
  const visible = findings.slice(page * 50, (page + 1) * 50)
  const high = report?.findings.filter(f => f.severity === 'high').length || 0
  const stats = report?.stats || job?.stats || {}
  return (
    <div className="app-shell">
      <header><div className="brand"><ShieldCheck size={30} /><div>ECDAT<span>CRYPTOGRAPHIC DISCOVERY</span></div></div><span className="local-tag">Unified scanner <span>v2.0</span></span></header>
      <main>
        <section className="intro"><div className="eyebrow">VISIBILITY BEFORE VULNERABILITY</div><h1>Discover the cryptography<br />inside your codebase.</h1><p>One scan for source code, configuration, compiled binaries and container archives. Trace cryptographic evidence back to where it lives.</p><div className="coverage"><span><FileCode2 size={16} /> Any source language</span><span><Binary size={16} /> Binary signatures</span><span><Box size={16} /> Container layers</span></div></section>
        <details className="risk-profile"><summary>Risk context for this scan</summary><p>Mosca risk compares how long data must remain protected, expected migration time and your CRQC planning horizon. These values are included in the report.</p><div className="risk-inputs"><label>Data lifetime (years)<input type="number" min="0" max="100" value={profile.data_lifetime_years} onChange={e => setProfileNumber('data_lifetime_years', e.target.value)} disabled={busy} /></label><label>Migration time (years)<input type="number" min="0" max="100" value={profile.migration_time_years} onChange={e => setProfileNumber('migration_time_years', e.target.value)} disabled={busy} /></label><label>Business criticality (1–10)<input type="number" min="1" max="10" value={profile.criticality} onChange={e => setProfileNumber('criticality', e.target.value)} disabled={busy} /></label><label>CRQC planning horizon (years)<input type="number" min="0" max="100" value={profile.crqc_arrival_years} onChange={e => setProfileNumber('crqc_arrival_years', e.target.value)} disabled={busy} /></label></div></details>
        <section className="input-grid" aria-label="Start a scan">
          <div className="panel"><div className="panel-title"><GitBranch size={22} /><h2>Import a repository</h2><span className="tag">PUBLIC GITHUB</span></div><p>Scan a repository directly from its GitHub URL.</p><form onSubmit={e => { e.preventDefault(); void startGithub() }}><label htmlFor="repo">Repository URL</label><input id="repo" type="url" required placeholder="https://github.com/owner/repository" value={url} onChange={e => setUrl(e.target.value)} disabled={busy} /><label htmlFor="branch">Branch, tag or commit <span className="muted">(optional)</span></label><input id="branch" placeholder="Default branch" value={ref} onChange={e => setRef(e.target.value)} disabled={busy} /><button className="primary" disabled={busy || !url.trim()} type="submit">Scan repository <ArrowRight size={17} /></button></form></div>
          <div className="panel">
            <div className="panel-title"><UploadCloud size={22} /><h2>Upload your codebase</h2></div>
            <p>Drop a folder, repository archive, container export or source file.</p>
            <button type="button" className={`dropzone ${dragging ? 'dragging' : ''}`} disabled={busy}
              onClick={() => input.current?.click()}
              onDragOver={e => { e.preventDefault(); setDragging(true) }}
              onDragLeave={() => setDragging(false)}
              onDrop={e => { e.preventDefault(); setDragging(false); if (!busy) void upload(droppedFiles(e.dataTransfer.items, e.dataTransfer.files)) }}>
              <UploadCloud size={35} /><strong>Drag & drop files or a folder here</strong>
              <span>or <b>browse files</b></span><small>Folders, ZIP, TAR, TAR.GZ, JAR, binaries or source files - up to 128 MiB</small>
            </button>
            <button type="button" className="text-button" disabled={busy} onClick={() => folderInput.current?.click()}>Choose folder</button>
            <input ref={input} type="file" multiple hidden onChange={e => { if (e.target.files?.length) void upload(selectedFiles(e.target.files)); e.target.value = '' }} />
            <input ref={folderInput} type="file" multiple hidden {...{ webkitdirectory: '' }} onChange={e => { if (e.target.files?.length) void upload(selectedFiles(e.target.files)); e.target.value = '' }} />
            <div className="upload-note">Folder structure is preserved. For containers, upload an archive from <code>docker save</code> or an OCI image export.</div>
          </div>
        </section>
        <div className="demo-row"><span>Want to see how it works?</span><button className="text-button" disabled={busy} onClick={() => void startGithub(true)}>Scan the bundled demo <ArrowRight size={14} /></button></div>
        {error && <div className="notice error" role="alert"><AlertTriangle size={20} />{error}</div>}
        {busy && <div className="panel progress" role="status" aria-live="polite"><LoaderCircle className="spin" /><div><strong>{uploadProgress !== null ? `Uploading · ${uploadProgress}%` : `${job?.status || 'Submitting'}…`}</strong><p>{job?.source || 'Preparing your scan'}{stats.files_scanned ? ` · ${stats.files_scanned} files inspected` : ''}</p></div><span>Runs in the background</span></div>}
        {report && <section className="results">
          {report.audit_error && <div className="notice warning" role="alert"><AlertTriangle size={20} />{report.audit_error}</div>}
          <div className="results-heading"><div className="eyebrow">SCAN RESULTS</div><h2>{report.source}</h2><div className="actions"><button onClick={() => download(report, `ecdat-${report.id}.json`)}><Download size={16} /> Full report</button><button onClick={() => download(report.cbom, `cbom-${report.id}.json`)}><Download size={16} /> CBOM</button><button onClick={async () => { try { const data = await requestJson('/audit/verify'); setAudit(data.is_valid ? `Audit verified · ${data.reports_verified} reports and ${data.records} records match` : `Audit check failed${data.report_errors?.length ? ` · ${data.report_errors.length} report mismatch(es)` : ''}`) } catch (e) { setAudit(String(e)) } }}><ShieldCheck size={16} /> Verify audit</button></div>{audit && <p role="status">{audit}</p>}</div>
          <div className="metrics"><div><span>Files inspected</span><strong>{stats.files_scanned}</strong><small>{stats.binary_files} binary · {stats.text_files} text</small></div><div><span>Crypto evidence</span><strong>{report.findings.length}</strong><small>{new Set(report.findings.map(f => f.pattern)).size} algorithm / asset types</small></div><div><span>Dependencies</span><strong>{stats.dependencies_found ?? 0}</strong><small>{stats.container_manifests_found ?? 0} container manifests</small></div><div><span>High priority</span><strong className={high ? 'danger' : ''}>{high}</strong><small>Requires contextual review</small></div><div><span>Scan duration</span><strong>{stats.duration_seconds}s</strong><small>{stats.archives_opened} archives opened</small></div></div>
          {report.risk_summary && <div className="risk-summary"><div><span>Quantum-vulnerable assets</span><strong>{report.risk_summary.quantum_vulnerable_assets}</strong></div><div><span>At risk under your Mosca profile</span><strong className={report.risk_summary.at_risk_now ? 'danger' : ''}>{report.risk_summary.at_risk_now}</strong></div><div><span>Crypto-Agility Score</span><strong>{report.risk_summary.average_crypto_agility_score ?? '—'}</strong><small>0 = least ready, 100 = most ready</small></div><p>Profile: data lifetime {report.profile.data_lifetime_years}y · migration {report.profile.migration_time_years}y · CRQC horizon {report.profile.crqc_arrival_years}y · criticality {report.profile.criticality}/10.</p></div>}
          {report.partial && <div className="notice warning"><AlertTriangle size={20} /><div><strong>Partial coverage · {stats.files_skipped} entries skipped</strong><details><summary>See coverage details</summary><ul>{report.warnings.map((warning, i) => <li key={i}>{warning}</li>)}</ul>{(stats.files_skipped || 0) > report.warnings.length && <p>Only the first 200 warnings are shown.</p>}</details></div></div>}
          <div className="panel findings"><div className="toolbar"><h2>Findings <span className="tag">{findings.length}</span></h2><div className="filters"><div className="search"><Search size={16} /><input aria-label="Search findings" placeholder="Search algorithm or path" value={query} onChange={e => { setQuery(e.target.value); setPage(0) }} /></div><select aria-label="Filter by priority" value={severity} onChange={e => { setSeverity(e.target.value); setPage(0) }}><option value="all">All priorities</option><option value="high">High priority</option><option value="review">Review</option><option value="info">Informational</option></select></div></div>
          <div className="table-scroll"><table><thead><tr><th>Asset / priority</th><th>Location</th><th>Evidence</th><th>Risk</th><th>Recommendation</th></tr></thead><tbody>{visible.map((f, i) => <tr key={`${page}-${i}`}><td><strong>{f.pattern}</strong><span className={`severity ${f.severity}`}>{f.severity}</span></td><td className="location">{f.file}<small>{f.line !== null ? `Line ${f.line}` : `Byte offset ${f.offset}`} · {f.kind}</small></td><td><code>{f.evidence}</code><small>{f.confidence} confidence</small></td><td>{f.riskAssessment ? <><strong>{f.riskAssessment.risk_score}/10</strong><small>{f.quantum_vulnerable ? (f.riskAssessment.at_risk_now ? 'Quantum risk now' : 'Quantum vulnerable') : f.classification}</small><small>CAS {f.cryptoAgilityScore}</small></> : '—'}</td><td>{f.recommendation}</td></tr>)}</tbody></table></div>
          {!findings.length && <div className="empty">{report.findings.length ? 'No findings match these filters.' : 'No matching cryptographic signatures were found in the inspected content.'}</div>}
          {findings.length > 50 && <div className="pagination"><span>Page {page + 1} of {Math.ceil(findings.length / 50)}</span><button disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button><button disabled={(page + 1) * 50 >= findings.length} onClick={() => setPage(page + 1)}>Next</button></div>}</div>
          {!!report.patches?.length && <div className="panel patches"><div className="patch-heading"><h2>Review-only remediation patches <span className="tag">{report.patches.length}</span></h2><p>These diffs are suggestions. They are never applied to uploaded or GitHub code.</p></div>{report.patches.map((patch, index) => <details key={index}><summary><strong>{patch.file}</strong><span>{patch.changes.join(' · ')}</span></summary><pre>{patch.diff.join('\n')}</pre></details>)}</div>}
          <p className="disclaimer">Signature matches are discovery evidence, not proof of a vulnerability or secure implementation. Comments and documentation can match. Binary findings use visible strings, not decompilation. Container results include historical layers, not a reconstructed runtime filesystem.</p>
        </section>}
        {!busy && !report && <div className="empty-state"><ShieldCheck size={26} /><div><strong>Your next scan starts here</strong><p>Import a repository or upload a file to build your cryptographic inventory.</p></div></div>}
      </main><footer><span>ECDAT · Enterprise Cryptographic Discovery & Analysis Tool</span><span>Static inspection · Uploaded code is never executed</span></footer>
    </div>
  )
}
