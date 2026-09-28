import { useState, useEffect, useCallback, type ReactNode } from 'react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Occurrence {
  location: string
  line?: number
}

interface Evidence {
  occurrences: Occurrence[]
}

interface RiskAssessment {
  at_risk_now: boolean
  reasoning?: string
}

interface PropertyItem {
  name: string
  value: string
}

interface Component {
  name: string
  evidence?: Evidence
  properties?: PropertyItem[]
  riskAssessment?: RiskAssessment
  cryptoAgilityScore?: number
}


interface AuditStatus {
  is_valid: boolean
  broken_index?: number | null
}

interface Patch {
  file: string
  diff: string[]
  changes?: string[]
}

// ─── Constants ────────────────────────────────────────────────────────────────

const API = 'http://127.0.0.1:8000'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function getRecommendation(comp: Component): string {
  const props = comp.properties ?? []
  const rec = props.find(p =>
    ['recommendation', 'Recommendation', 'migration_path', 'note'].includes(p.name)
  )
  return rec?.value ?? props[0]?.value ?? '—'
}

function getCasColor(score: number): string {
  if (score < 40) return 'text-red-500'
  if (score < 70) return 'text-yellow-500'
  return 'text-emerald-500'
}

function getRingColor(score: number): string {
  if (score < 40) return '#ef4444'
  if (score < 70) return '#f59e0b'
  return '#10b981'
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Badge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold ${
        ok
          ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-400'
          : 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400'
      }`}
    >
      {label}
    </span>
  )
}

function Card({ title, children, className = '' }: { title: string; children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-2xl bg-white dark:bg-slate-800 shadow-sm border border-slate-200 dark:border-slate-700 p-6 ${className}`}>
      <h2 className="text-lg font-semibold text-slate-700 dark:text-slate-200 mb-4">{title}</h2>
      {children}
    </div>
  )
}

function Spinner() {
  return (
    <svg
      className="animate-spin h-5 w-5 text-indigo-500"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  )
}

// ─── CAS Ring ─────────────────────────────────────────────────────────────────

function CASRing({ score }: { score: number }) {
  const radius = 52
  const circ = 2 * Math.PI * radius
  const offset = circ - (score / 100) * circ
  const color = getRingColor(score)

  return (
    <div className="flex flex-col items-center gap-3">
      <svg width="140" height="140" viewBox="0 0 140 140">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="#e2e8f0" strokeWidth="12" />
        <circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 70 70)"
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
        <text x="70" y="70" textAnchor="middle" dominantBaseline="central" fontSize="26" fontWeight="700" fill={color}>
          {score.toFixed(1)}
        </text>
      </svg>
      <p className="text-sm text-slate-500 dark:text-slate-400">
        Average Crypto Agility Score
      </p>
      <span
        className={`text-xs font-semibold px-3 py-1 rounded-full ${
          score < 40
            ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400'
            : score < 70
            ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-400'
            : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-400'
        }`}
      >
        {score < 40 ? 'Critical' : score < 70 ? 'Moderate' : 'Healthy'}
      </span>
    </div>
  )
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [components, setComponents] = useState<Component[]>([])
  const [audit, setAudit] = useState<AuditStatus | null>(null)
  const [patches, setPatches] = useState<Patch[]>([])
  const [loadingData, setLoadingData] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [scanMsg, setScanMsg] = useState<string | null>(null)

  // ── Fetch all data ──
  const fetchAll = useCallback(async () => {
    setLoadingData(true)
    setError(null)
    try {
      const [cbomRes, auditRes, patchRes] = await Promise.allSettled([
        fetch(`${API}/cbom`).then(r => r.json()),
        fetch(`${API}/audit/verify`).then(r => r.json()),
        fetch(`${API}/patches`).then(r => r.json()),
      ])
      if (cbomRes.status === 'fulfilled') {
        setComponents((cbomRes.value as { components: Component[] }).components ?? [])
      }
      if (auditRes.status === 'fulfilled') setAudit(auditRes.value)
      if (patchRes.status === 'fulfilled') setPatches(patchRes.value)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoadingData(false)
    }
  }, [])

  useEffect(() => { fetchAll() }, [fetchAll])

  // ── Run scan ──
  const runScan = async () => {
    setScanning(true)
    setScanMsg(null)
    try {
      const res = await fetch(`${API}/scan`, { method: 'POST' })
      const data = await res.json()
      setScanMsg(`✓ Scan complete — ${data.components_found ?? '?'} components found`)
      await fetchAll()
    } catch (e) {
      setScanMsg(`✗ Scan failed: ${String(e)}`)
    } finally {
      setScanning(false)
    }
  }

  // ── Re-verify audit ──
  const reVerify = async () => {
    setVerifying(true)
    try {
      const res = await fetch(`${API}/audit/verify`)
      setAudit(await res.json())
    } finally {
      setVerifying(false)
    }
  }

  const avgCAS =
    components.length > 0
      ? components.reduce((sum, c) => sum + (c.cryptoAgilityScore ?? 0), 0) / components.length
      : 0

  // ─────────────────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-900 text-slate-900 dark:text-slate-100 font-sans">

      {/* ── Header ── */}
      <header className="sticky top-0 z-20 bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700 shadow-sm">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-bold text-indigo-600 dark:text-indigo-400 tracking-tight leading-tight">
              ECDAT
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Enterprise Cryptographic Discovery &amp; Analysis Tool
            </p>
          </div>
          <div className="flex items-center gap-3">
            {scanMsg && (
              <span className={`text-sm font-medium ${scanMsg.startsWith('✓') ? 'text-emerald-600' : 'text-red-500'}`}>
                {scanMsg}
              </span>
            )}
            <button
              onClick={runScan}
              disabled={scanning}
              className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 disabled:opacity-60 text-white text-sm font-semibold px-4 py-2 transition-colors"
            >
              {scanning ? <><Spinner /> Scanning…</> : '▶ Run Scan'}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">

        {/* ── Loading / Error state ── */}
        {loadingData && (
          <div className="flex items-center gap-3 text-slate-500 dark:text-slate-400">
            <Spinner /> <span>Loading data from backend…</span>
          </div>
        )}
        {error && (
          <div className="rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 p-4 text-red-700 dark:text-red-400 text-sm">
            ⚠ {error} — make sure the FastAPI server is running on port 8000 and has been scanned.
          </div>
        )}

        {/* ── Top row: CAS Overview + Audit Trail ── */}
        {!loadingData && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

            {/* CAS Overview */}
            <Card title="CAS Overview">
              {components.length === 0 ? (
                <p className="text-sm text-slate-400">No data — run a scan first.</p>
              ) : (
                <div className="flex justify-center">
                  <CASRing score={avgCAS} />
                </div>
              )}
            </Card>

            {/* Audit Trail */}
            <Card title="Audit Trail">
              {audit == null ? (
                <p className="text-sm text-slate-400">No audit log — run a scan first.</p>
              ) : (
                <div className="flex flex-col gap-4">
                  <div className="flex items-center gap-3">
                    {audit.is_valid ? (
                      <span className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-semibold text-base">
                        <span className="text-xl">✓</span> Audit Chain Verified
                      </span>
                    ) : (
                      <span className="flex items-center gap-2 text-red-600 dark:text-red-400 font-semibold text-base">
                        <span className="text-xl">✗</span> Tampering Detected at block {audit.broken_index ?? '?'}
                      </span>
                    )}
                  </div>
                  <button
                    onClick={reVerify}
                    disabled={verifying}
                    className="self-start inline-flex items-center gap-2 rounded-lg border border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-700 text-sm font-medium px-4 py-2 transition-colors"
                  >
                    {verifying ? <><Spinner /> Verifying…</> : '↻ Re-verify'}
                  </button>
                </div>
              )}
            </Card>
          </div>
        )}

        {/* ── Risk Heatmap ── */}
        {!loadingData && components.length > 0 && (
          <Card title="Risk Heatmap">
            <div className="flex flex-wrap gap-3">
              {components.map((comp, i) => {
                const risk = comp.riskAssessment?.at_risk_now ?? false
                return (
                  <div
                    key={i}
                    title={risk ? 'AT RISK' : 'OK'}
                    className={`flex items-center justify-center rounded-xl px-4 py-3 text-xs font-semibold text-white text-center max-w-[130px] break-words shadow-sm ${
                      risk
                        ? 'bg-red-500 dark:bg-red-600'
                        : 'bg-emerald-500 dark:bg-emerald-600'
                    }`}
                  >
                    {comp.name}
                  </div>
                )
              })}
            </div>
          </Card>
        )}

        {/* ── Findings Table ── */}
        {!loadingData && components.length > 0 && (
          <Card title="Findings" className="overflow-hidden">
            <div className="overflow-x-auto -mx-6 -mb-6 px-6">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-700 text-left text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    <th className="pb-3 pr-4 font-semibold">Algorithm</th>
                    <th className="pb-3 pr-4 font-semibold">File</th>
                    <th className="pb-3 pr-4 font-semibold">Line</th>
                    <th className="pb-3 pr-4 font-semibold">Recommendation</th>
                    <th className="pb-3 pr-4 font-semibold">Risk</th>
                    <th className="pb-3 font-semibold">CAS</th>
                  </tr>
                </thead>
                <tbody>
                  {components.map((comp, i) => {
                    const occ = comp.evidence?.occurrences?.[0]
                    const filePath = occ?.location ?? '—'
                    const fileName = filePath.split(/[\\/]/).pop() ?? filePath
                    const line = occ?.line ?? '—'
                    const risk = comp.riskAssessment?.at_risk_now ?? false
                    const cas = comp.cryptoAgilityScore ?? 0
                    return (
                      <tr
                        key={i}
                        className="border-b border-slate-100 dark:border-slate-700/50 hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors"
                      >
                        <td className="py-3 pr-4 font-mono font-semibold text-indigo-600 dark:text-indigo-400">
                          {comp.name}
                        </td>
                        <td className="py-3 pr-4 text-slate-600 dark:text-slate-300 truncate max-w-[180px]" title={filePath}>
                          {fileName}
                        </td>
                        <td className="py-3 pr-4 text-slate-500 dark:text-slate-400">{String(line)}</td>
                        <td className="py-3 pr-4 text-slate-600 dark:text-slate-300 max-w-[200px]">
                          {getRecommendation(comp)}
                        </td>
                        <td className="py-3 pr-4">
                          <Badge ok={!risk} label={risk ? 'AT RISK' : 'OK'} />
                        </td>
                        <td className={`py-3 font-bold tabular-nums ${getCasColor(cas)}`}>
                          {cas}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {/* ── Patch Viewer ── */}
        {!loadingData && patches.length > 0 && (
          <Card title="Patch Viewer">
            <div className="space-y-6">
              {patches.map((patch, pi) => (
                <div key={pi}>
                  <p className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-2 font-mono">
                    📄 {patch.file}
                  </p>
                  <div className="rounded-lg overflow-hidden border border-slate-200 dark:border-slate-700 text-xs font-mono">
                    {patch.diff.length === 0 ? (
                      <p className="px-4 py-3 text-slate-400">No diff available.</p>
                    ) : (
                      patch.diff.map((line, li) => {
                        const isAdd = line.startsWith('+')
                        const isDel = line.startsWith('-')
                        return (
                          <div
                            key={li}
                            className={`px-4 py-0.5 whitespace-pre-wrap break-all ${
                              isAdd
                                ? 'bg-emerald-50 dark:bg-emerald-900/25 text-emerald-700 dark:text-emerald-400'
                                : isDel
                                ? 'bg-red-50 dark:bg-red-900/25 text-red-700 dark:text-red-400'
                                : 'bg-slate-50 dark:bg-slate-800 text-slate-500 dark:text-slate-400'
                            }`}
                          >
                            {line}
                          </div>
                        )
                      })
                    )}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}

        {/* ── Empty state ── */}
        {!loadingData && components.length === 0 && !error && (
          <div className="rounded-2xl border-2 border-dashed border-slate-300 dark:border-slate-600 p-12 text-center">
            <p className="text-slate-400 dark:text-slate-500 text-lg">No scan data yet.</p>
            <p className="text-slate-400 dark:text-slate-500 text-sm mt-1">
              Click <strong>Run Scan</strong> to analyse your demo-data directory.
            </p>
          </div>
        )}

      </main>
    </div>
  )
}
