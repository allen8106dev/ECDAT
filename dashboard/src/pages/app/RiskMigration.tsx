import { useEffect, useState } from 'react'
import { requestJson } from '../../api'
import type { Report, RiskProfile } from '../../types'

const TARGET_ALGORITHMS: Record<string, string> = {
  'RSA': 'ML-KEM-768',
  'ECDH': 'ML-KEM-768',
  'ECDSA': 'ML-DSA-65',
  'DSA': 'ML-DSA-65',
  'RSA-PSS': 'ML-DSA-87',
  'ED25519': 'SLH-DSA-SHAKE-128s',
  'DEFAULT': 'ML-KEM-768 / ML-DSA-65',
}

function moscaUrgent(p: RiskProfile): boolean {
  return (p.data_lifetime_years + p.migration_time_years) > p.crqc_arrival_years
}

function DotRow({ value, max = 5 }: { value: number; max?: number }) {
  return (
    <div style={{ display: 'flex', gap: 3 }}>
      {Array.from({ length: max }).map((_, i) => (
        <div key={i} style={{ width: 7, height: 7, borderRadius: '50%', background: i < value ? 'var(--navy)' : 'var(--hairline)' }} />
      ))}
    </div>
  )
}

const SEV_COLOURS: Record<string, string> = {
  safe: 'var(--teal-12)', review: 'var(--navy-10)', high: 'var(--rose-14)', critical: 'var(--coral-16)',
}
const SEV_LABEL: Record<string, string> = { safe: 'Safe', review: 'Review', high: 'High', critical: 'Critical' }

export default function RiskMigration() {
  const [report, setReport] = useState<Report | null>(null)
  const [profile, setProfile] = useState<RiskProfile>({ data_lifetime_years: 10, migration_time_years: 3, criticality: 5, crqc_arrival_years: 10 })

  useEffect(() => {
    const id = localStorage.getItem('ecdat-last-scan')
    if (!id) return
    requestJson<Report>(`/scans/${id}/result?include_cbom=false`).then(r => {
      setReport(r)
      if (r.profile) setProfile(r.profile)
    }).catch(() => {})
  }, [])

  const urgent = moscaUrgent(profile)
  const findings = report?.findings ?? []

  // Build severity heatmap grid (by file prefix buckets × severity)
  const files = [...new Set(findings.map(f => f.file.split('/')[0] || f.file))].slice(0, 8)
  const sevs: (keyof typeof SEV_COLOURS)[] = ['critical', 'high', 'review', 'safe']

  // Build migration table rows from unique patterns
  const migrationRows = Object.values(
    findings.reduce<Record<string, { pattern: string; role: string; count: number; severity: string }>>((acc, f) => {
      if (!acc[f.pattern]) acc[f.pattern] = { pattern: f.pattern, role: f.kind, count: 0, severity: f.severity }
      acc[f.pattern].count++
      return acc
    }, {})
  ).sort((a, b) => sevs.indexOf(a.severity as typeof sevs[0]) - sevs.indexOf(b.severity as typeof sevs[0])).slice(0, 15)

  function setNum(key: keyof RiskProfile, val: string) {
    const n = Number(val)
    if (Number.isFinite(n)) setProfile(p => ({ ...p, [key]: n }))
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 28 }}>
      <div>
        <h1 style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.02em', margin: '0 0 6px' }}>Risk &amp; Migration</h1>
        <p style={{ fontSize: 13, color: 'var(--ink-muted)', margin: 0 }}>Mosca equation, heatmap, and migration planning table.</p>
      </div>

      {/* Mosca planner */}
      <div className="card" style={{ padding: 28 }}>
        <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 18 }}>Mosca planner</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(200px,1fr))', gap: 20, marginBottom: 24 }}>
          {([
            ['data_lifetime_years', 'Data lifetime (X)', 0, 100],
            ['migration_time_years', 'Migration time (Y)', 0, 100],
            ['crqc_arrival_years', 'CRQC horizon (Z)', 0, 100],
            ['criticality', 'Criticality (1–10)', 1, 10],
          ] as [keyof RiskProfile, string, number, number][]).map(([key, label, min, max]) => (
            <div key={key}>
              <label className="input-label">{label}</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <input
                  type="range" min={min} max={max} value={profile[key]}
                  onChange={e => setNum(key, e.target.value)}
                  style={{ flex: 1, accentColor: 'var(--navy)' }}
                />
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 14, fontWeight: 600, color: 'var(--navy)', minWidth: 28, textAlign: 'right' }}>{profile[key]}</span>
              </div>
            </div>
          ))}
        </div>
        {/* Result banner */}
        <div style={{ borderRadius: 'var(--radius-md)', padding: '16px 22px', background: urgent ? 'var(--coral)' : 'var(--teal)', color: 'var(--ink)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: 16, marginBottom: 4 }}>
              {urgent ? '⚠ Migration is urgent' : '✓ Migration timeline is adequate'}
            </div>
            <div style={{ fontSize: 13 }}>
              X + Y = {profile.data_lifetime_years + profile.migration_time_years}y &nbsp;{urgent ? '>' : '≤'}&nbsp; Z = {profile.crqc_arrival_years}y
            </div>
          </div>
        </div>
      </div>

      {/* Heatmap */}
      {report && files.length > 0 && (
        <div style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
          <div style={{ padding: '18px 22px', borderBottom: '1px solid var(--hairline)', fontSize: 13, fontWeight: 600 }}>Severity heatmap by module</div>
          <div style={{ overflowX: 'auto', padding: 20 }}>
            <table style={{ borderCollapse: 'separate', borderSpacing: 4, fontSize: 11 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '0 8px 8px 0', color: 'var(--ink-muted)', fontWeight: 500, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Module</th>
                  {sevs.map(s => <th key={s} style={{ padding: '0 4px 8px', color: 'var(--ink-muted)', fontWeight: 500, fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{SEV_LABEL[s]}</th>)}
                </tr>
              </thead>
              <tbody>
                {files.map(file => (
                  <tr key={file}>
                    <td style={{ padding: '4px 12px 4px 0', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--ink-muted)', whiteSpace: 'nowrap' }}>{file}</td>
                    {sevs.map(s => {
                      const count = findings.filter(f => (f.file.split('/')[0] || f.file) === file && f.severity === s).length
                      const opacity = Math.min(0.15 + (count / 20) * 0.85, 1)
                      return (
                        <td key={s} style={{ padding: 4 }}>
                          <div title={`${count} ${s} findings`} style={{
                            width: 52, height: 32, borderRadius: 6,
                            background: count === 0 ? 'var(--canvas-warm)' : SEV_COLOURS[s],
                            opacity: count === 0 ? 1 : opacity,
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: count > 0 ? 600 : 400,
                            color: count === 0 ? 'var(--hairline)' : 'var(--ink)',
                            border: '1px solid var(--hairline)',
                          }}>{count || '·'}</div>
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Migration table */}
      {report && migrationRows.length > 0 && (
        <div style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
          <div style={{ padding: '18px 22px', borderBottom: '1px solid var(--hairline)', fontSize: 13, fontWeight: 600 }}>Migration targets</div>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Current algorithm</th>
                  <th>Role</th>
                  <th>Target (PQC)</th>
                  <th>Status</th>
                  <th>Effort</th>
                </tr>
              </thead>
              <tbody>
                {migrationRows.map(({ pattern, role, count, severity }) => (
                  <tr key={pattern}>
                    <td><code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--ink)' }}>{pattern}</code><small style={{ display: 'block', color: 'var(--ink-muted)', fontSize: 10, marginTop: 3 }}>{count} occurrence{count !== 1 ? 's' : ''}</small></td>
                    <td style={{ color: 'var(--ink-muted)', fontSize: 12 }}>{role}</td>
                    <td><code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--teal-ink)' }}>{TARGET_ALGORITHMS[pattern] ?? TARGET_ALGORITHMS.DEFAULT}</code></td>
                    <td>
                      <span className={`badge badge-${severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : severity === 'safe' ? 'safe' : 'review'}`}>
                        {SEV_LABEL[severity] ?? severity}
                      </span>
                    </td>
                    <td><DotRow value={severity === 'critical' ? 5 : severity === 'high' ? 4 : severity === 'review' ? 2 : 1} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {!report && (
        <div style={{ padding: '48px', textAlign: 'center', color: 'var(--ink-muted)', fontSize: 13, background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)' }}>
          No scan loaded. Run a scan from the Scan screen first.
        </div>
      )}
    </div>
  )
}
