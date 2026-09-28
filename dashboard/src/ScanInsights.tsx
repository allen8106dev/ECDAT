import { useMemo, useState } from 'react'
import { priorities, summarize } from './insights'
import type { Evidence } from './insights'
import './insights.css'

export default function ScanInsights({ findings, onFile }: { findings: Evidence[]; onFile: (file: string) => void }) {
  const assets = useMemo(() => summarize(findings), [findings])
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState('')
  const matches = assets.filter(asset => asset.name.toLowerCase().includes(search.toLowerCase()))
  const visible = matches.slice(0, 15)
  const active = assets.find(asset => asset.name === selected) || visible[0]
  const files = active ? [...active.files.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])) : []
  return <section className="scan-insights" aria-label="Scan insights">
    <h2>Risk overview &amp; asset map</h2>
    <p>Counts represent evidence records, including repeated references. Select an asset to explore its files.</p>
    <label>Find an asset <input value={search} onChange={e => { setSearch(e.target.value); setSelected('') }} placeholder="e.g. RSA, SHA256" /></label>
    {!assets.length ? <p>No crypto evidence was detected within scan coverage.</p> : <div className="insights-grid">
      <div className="heatmap-scroll"><table className="heatmap"><caption>Detection priority heatmap · showing {visible.length} of {matches.length} matching assets</caption><thead><tr><th>Asset</th>{priorities.map(p => <th key={p}>{p}</th>)}</tr></thead><tbody>{visible.map(asset => <tr key={asset.name}><th><button aria-pressed={active?.name === asset.name} onClick={() => setSelected(asset.name)}>{asset.name}</button></th>{asset.counts.map((count, i) => <td key={i} className={count ? `heat-${priorities[i]}` : ''}>{count}</td>)}</tr>)}</tbody></table>{!matches.length && <p>No matching assets.</p>}</div>
      <div className="asset-map"><h3>{active ? active.name : 'Select an asset'}</h3><p>Observed file → asset links. These links do not establish runtime or transitive dependencies.</p>{active && <><p>{active.total} records across {files.length} files. Showing the 12 files with most evidence; use the findings search for others.</p><ul>{files.slice(0, 12).map(([file, count]) => <li key={file}><button title={file} onClick={() => onFile(file)}>{file}</button><span aria-label={`${count} records`}>{count} → {active.name}</span></li>)}</ul></>}</div>
    </div>}
  </section>
}
