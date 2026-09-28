import { useState } from 'react'
export type Graph = { manifest: string; nodes: { id: string; name: string; version: string }[]; edges: { from: string; to: string }[]; unresolved: { from: string; name: string }[] }
export default function DependencyGraph({ graphs }: { graphs: Graph[] }) {
  const [search, setSearch] = useState('')
  if (!graphs.length) return null
  return <details className="scan-insights"><summary>Resolved package dependencies</summary><p>Relationships declared in npm lockfiles. This is package dependency evidence, not proof of runtime crypto use. Other ecosystems are not resolved here.</p><label>Find a package <input value={search} onChange={event => setSearch(event.target.value)} /></label>{graphs.map(graph => {
    const nodes = new Map(graph.nodes.map(node => [node.id, node]))
    const edges = graph.edges.filter(edge => `${edge.from} ${edge.to}`.toLowerCase().includes(search.toLowerCase()))
    return <div key={graph.manifest}><h3>{graph.manifest}</h3><p>{graph.nodes.length} packages · {graph.edges.length} relationships · {graph.unresolved.length} unresolved. Showing up to 50 matching relationships.</p><ul>{edges.slice(0, 50).map((edge, i) => <li key={i}><button onClick={() => setSearch(edge.from)}>{nodes.get(edge.from)?.name || 'root'}</button> → <button onClick={() => setSearch(edge.to)}>{nodes.get(edge.to)?.name} {nodes.get(edge.to)?.version}</button></li>)}</ul></div>
  })}</details>
}
