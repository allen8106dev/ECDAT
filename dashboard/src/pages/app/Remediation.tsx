import { useEffect, useState } from 'react'
import { Check, X } from '@phosphor-icons/react'
import { requestJson } from '../../api'
import type { Report, Patch } from '../../types'

export default function Remediation() {
  const [report, setReport] = useState<Report | null>(null)
  const [expanded, setExpanded] = useState<number | null>(null)

  useEffect(() => {
    const id = localStorage.getItem('ecdat-last-scan')
    if (!id) return
    requestJson<Report>(`/scans/${id}/result?include_cbom=false`).then(setReport).catch(() => {})
  }, [])

  const patches = report?.patches ?? []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', margin: '0 0 6px' }}>Remediation</h1>
        <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: 0 }}>Review-only patch suggestions. Nothing is applied automatically.</p>
      </div>

      {/* Guidance note */}
      <div style={{ background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
        <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--navy)', marginBottom: 4 }}>Guidance only — not auto-patched</div>
        <div style={{ fontSize: 12, color: 'var(--ink-muted)', lineHeight: 1.7 }}>
          These diffs are suggestions generated from scanner findings. They are never applied to uploaded or cloned code. Review each change carefully before adopting it.
        </div>
      </div>

      {!report && (
        <div style={{ padding: '48px', textAlign: 'center', color: 'var(--ink-muted)', fontSize: 13, background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)' }}>
          No scan loaded. Run a scan first.
        </div>
      )}

      {report && patches.length === 0 && (
        <div style={{ padding: '48px', textAlign: 'center', color: 'var(--ink-muted)', fontSize: 13, background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)' }}>
          No patch suggestions were generated for this scan.
        </div>
      )}

      {patches.map((patch: Patch, index: number) => (
        <div key={index} style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
          {/* Header */}
          <button
            style={{ display: 'flex', width: '100%', alignItems: 'flex-start', gap: 12, padding: '16px 22px', background: 'none', border: 'none', borderBottom: expanded === index ? '1px solid var(--hairline)' : 'none', cursor: 'pointer', textAlign: 'left' }}
            onClick={() => setExpanded(expanded === index ? null : index)}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--ink)', display: 'block', marginBottom: 4 }}>{patch.file}</code>
              <div style={{ fontSize: 11, color: 'var(--ink-muted)' }}>{patch.changes.join(' · ')}</div>
            </div>
            {patch.review_required && (
              <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.06em', color: 'var(--rose-ink)', background: 'var(--rose-14)', padding: '3px 8px', borderRadius: 4, flexShrink: 0 }}>REVIEW REQUIRED</span>
            )}
            <span style={{ fontSize: 18, color: 'var(--ink-muted)', fontWeight: 300, flexShrink: 0 }}>{expanded === index ? '−' : '+'}</span>
          </button>

          {/* Diff */}
          {expanded === index && (
            <div>
              <div className="diff-block" style={{ borderRadius: 0, border: 'none', margin: 0 }}>
                {patch.diff.map((line, li) => {
                  const removed = line.startsWith('-')
                  const added   = line.startsWith('+')
                  return (
                    <div key={li} className={`diff-line ${removed ? 'diff-line-removed' : added ? 'diff-line-added' : 'diff-line-context'}`}>
                      {line}
                    </div>
                  )
                })}
              </div>
              {/* Actions */}
              <div style={{ display: 'flex', gap: 10, padding: '14px 22px', borderTop: '1px solid var(--hairline)' }}>
                <button className="btn btn-primary" style={{ gap: 7 }}>
                  <Check size={14} /> Approve
                </button>
                <button className="btn btn-ghost" style={{ gap: 7 }}>
                  <X size={14} /> Reject
                </button>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
