import { useEffect, useState } from 'react'

type Scan = { id: string; timestamp?: string; score: number | null; partial: boolean; profile: unknown; findings: number }
export default function HistoryPanel({ api, source, currentId, profile, onLoad }: { api: string; source: string; currentId: string; profile: unknown; onLoad: (id: string) => void }) {
  const [scans, setScans] = useState<Scan[]>([])
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    fetch(`${api}/history?source=${encodeURIComponent(source)}`, { signal: controller.signal }).then(async response => {
      if (!response.ok) throw new Error('History could not be loaded.')
      const data = await response.json(); setScans(data.scans); setError('')
    }).catch(e => { if (!controller.signal.aborted) setError(String(e)) })
    return () => controller.abort()
  }, [api, source, currentId])
  const matching = scans.filter(scan => JSON.stringify(scan.profile) === JSON.stringify(profile) && scan.score !== null).slice(0, 20).reverse()
  return <details className="scan-insights"><summary>Scan history &amp; application readiness</summary><p>Application CAS counts each file/asset pair once. The trend compares the same source and risk profile; partial scans may have different coverage.</p>{error && <p role="alert">{error}</p>}
    {matching.length > 1 && <svg role="img" aria-label="Application crypto-agility scores from oldest to newest scan" viewBox="0 0 600 140" style={{ width: '100%', maxWidth: 700 }}><line x1="15" y1="120" x2="580" y2="120" stroke="#ccd5e1" /><polyline fill="none" stroke="#346bd4" strokeWidth="3" points={matching.map((scan, i) => `${20 + i * 550 / (matching.length - 1)},${120 - (scan.score || 0)}`).join(' ')} />{matching.map((scan, i) => <g key={scan.id}><circle cx={20 + i * 550 / (matching.length - 1)} cy={120 - (scan.score || 0)} r="4" fill="#346bd4" /><title>{scan.timestamp}: {scan.score}/100</title></g>)}</svg>}
    <ul>{scans.slice(0, 20).map(scan => <li key={scan.id}><button onClick={() => onLoad(scan.id)}>{scan.timestamp || scan.id}</button> · CAS {scan.score ?? 'unavailable'} · {scan.findings} findings{scan.partial ? ' · partial coverage' : ''}</li>)}</ul>{!scans.length && !error && <p>No saved scans for this source.</p>}
  </details>
}
