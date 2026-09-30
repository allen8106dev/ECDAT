import { useEffect, useState } from 'react'
import { requestJson } from '../../api'
import type { Report, Graph, GraphNode, GraphEdge } from '../../types'

const SEV_DOT: Record<string, string> = {
  critical: 'var(--coral)', high: 'var(--rose)', review: 'var(--navy)', safe: 'var(--teal)',
}

function GraphView({ graph }: { graph: Graph }) {
  const [selected, setSelected] = useState<string | null>(null)
  const nodeCount = graph.nodes.length
  // Simple force-free layout: arrange in a grid
  const cols = Math.ceil(Math.sqrt(nodeCount))
  const spacing = 120

  return (
    <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: 520, border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', background: 'var(--canvas)' }}>
      <svg width={Math.max(cols * spacing + 80, 600)} height={Math.max(Math.ceil(nodeCount / cols) * spacing + 80, 300)} style={{ display: 'block' }}>
        {/* Edges */}
        {graph.edges.map((e: GraphEdge, i: number) => {
          const si = graph.nodes.findIndex((n: GraphNode) => n.id === e.source)
          const ti = graph.nodes.findIndex((n: GraphNode) => n.id === e.target)
          if (si < 0 || ti < 0) return null
          const sx = (si % cols) * spacing + 60, sy = Math.floor(si / cols) * spacing + 60
          const tx = (ti % cols) * spacing + 60, ty = Math.floor(ti / cols) * spacing + 60
          return <line key={i} x1={sx} y1={sy} x2={tx} y2={ty} stroke="var(--hairline)" strokeWidth={1} />
        })}
        {/* Nodes */}
        {graph.nodes.map((n: GraphNode, i: number) => {
          const x = (i % cols) * spacing + 60
          const y = Math.floor(i / cols) * spacing + 60
          const isSelected = selected === n.id
          return (
            <g key={n.id} onClick={() => setSelected(isSelected ? null : n.id)} style={{ cursor: 'pointer' }}>
              <circle cx={x} cy={y} r={24} fill="var(--canvas-warm)" stroke={isSelected ? 'var(--navy)' : 'var(--hairline)'} strokeWidth={isSelected ? 2 : 1} />
              {/* Severity dot inside node */}
              {n.kind && SEV_DOT[n.kind] && <circle cx={x + 14} cy={y - 14} r={5} fill={SEV_DOT[n.kind]} />}
              <text x={x} y={y + 4} textAnchor="middle" fontSize={9} fill="var(--ink-muted)" fontFamily="var(--font-mono)">
                {(n.label || n.id).slice(0, 10)}
              </text>
              {isSelected && (
                <foreignObject x={x - 80} y={y + 28} width={160} height={60}>
                  <div style={{ background: 'var(--canvas)', border: '1px solid var(--navy)', borderRadius: 8, padding: '6px 10px', fontSize: 10, color: 'var(--ink)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                    {n.label || n.id}
                  </div>
                </foreignObject>
              )}
            </g>
          )
        })}
      </svg>
    </div>
  )
}

export default function Dependencies() {
  const [graphs, setGraphs] = useState<Graph[]>([])

  useEffect(() => {
    const id = localStorage.getItem('ecdat-last-scan')
    if (!id) return
    requestJson<Report>(`/scans/${id}/result?include_cbom=false`).then(r => setGraphs(r.dependency_graphs ?? [])).catch(() => {})
  }, [])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', margin: '0 0 6px' }}>Dependencies</h1>
        <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: 0 }}>Dependency graph — nodes with severity dots, click to inspect.</p>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 12, color: 'var(--ink-muted)' }}>
        {[['safe', 'Safe'], ['review', 'Review'], ['high', 'High'], ['critical', 'Critical']].map(([k, label]) => (
          <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: SEV_DOT[k] }} />
            {label}
          </div>
        ))}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 16, height: 16, borderRadius: '50%', background: 'var(--canvas-warm)', border: '2px solid var(--navy)' }} />
          Selected
        </div>
      </div>

      {graphs.length === 0 && (
        <div style={{ padding: '48px', textAlign: 'center', color: 'var(--ink-muted)', fontSize: 13, background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)' }}>
          No dependency graph data. Run a scan that includes dependency analysis.
        </div>
      )}

      {graphs.map((g, i) => (
        <div key={i}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>Graph {i + 1} — {g.nodes.length} nodes, {g.edges.length} edges</div>
          <GraphView graph={g} />
        </div>
      ))}
    </div>
  )
}
