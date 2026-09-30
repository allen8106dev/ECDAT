import { Link } from 'react-router-dom'
import { ShieldCheck, ArrowRight, Play, ChartBar, Upload, MagnifyingGlass, Table, FileArrowDown } from '@phosphor-icons/react'

const pipelineStages = [
  { n: 1, title: 'Scan', snippet: 'scanner.directory("./src")', highlight: 'found 142 cryptographic assets' },
  { n: 2, title: 'Analyse', snippet: 'risk_engine.assess_findings(findings, profile)', highlight: 'urgency_score: 8.4' },
  { n: 3, title: 'CBOM', snippet: 'cbom_builder.build_cbom(findings)', highlight: 'specVersion: "1.4"' },
  { n: 4, title: 'Audit', snippet: 'chain.add_scan_record(cbom)', highlight: 'hash: "a3f9…c21b"' },
]

const roadmap = [
  { label: 'Container layer scanner', status: 'done' },
  { label: 'Signed export bundles', status: 'done' },
  { label: 'Mosca risk planner', status: 'done' },
  { label: 'Migration target table (ML-KEM / ML-DSA / SLH-DSA)', status: 'done' },
  { label: 'GitHub PR bot', status: 'in-progress' },
  { label: 'CI/CD pipeline integration', status: 'upcoming' },
  { label: 'Team workspace & access control', status: 'upcoming' },
]

export default function Home() {
  return (
    <div style={{ fontFamily: 'var(--font-ui)', color: 'var(--ink)' }}>
      {/* Nav */}
      <nav style={{
        display: 'flex', alignItems: 'center', gap: 32, padding: '0 max(5vw, 28px)',
        height: 60, borderBottom: '1px solid var(--hairline)', background: 'var(--canvas)',
        position: 'sticky', top: 0, zIndex: 20
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, color: 'var(--purple)', fontWeight: 700, fontSize: 17, letterSpacing: '-0.02em' }}>
          <ShieldCheck size={22} weight="duotone" />
          <span style={{ color: 'var(--ink)' }}>Quantis</span>
        </div>
        <div style={{ flex: 1 }} />
        <Link to="/about" style={{ fontSize: 13, color: 'var(--ink-muted)', textDecoration: 'none' }}>About</Link>
        <Link to="/app/overview" className="btn btn-primary" style={{ fontSize: 13, padding: '8px 18px' }}>
          Open app <ArrowRight size={14} />
        </Link>
      </nav>

      {/* Hero */}
      <section style={{ position: 'relative', background: 'var(--canvas-warm)', padding: 'clamp(64px,10vw,120px) max(5vw,48px) clamp(64px,10vw,100px)', overflow: 'hidden' }}>
        <div className="hero-wash" />
        <div style={{ position: 'relative', maxWidth: 900, margin: '0 auto' }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.14em', color: 'var(--ink-muted)', textTransform: 'uppercase', marginBottom: 20 }}>
            Quantum-safe cryptography
          </div>
          <h1 style={{ fontSize: 'clamp(38px,6vw,64px)', fontWeight: 750, letterSpacing: '-0.04em', lineHeight: 1.1, margin: '0 0 24px', maxWidth: 800 }}>
            Discover every cryptographic asset before{' '}
            <span style={{ color: 'var(--purple-ink)' }}>quantum</span>{' '}
            breaks them.
          </h1>
          <p style={{ fontSize: 16, color: 'var(--ink-muted)', lineHeight: 1.8, maxWidth: 560, margin: '0 0 36px' }}>
            One scan for source code, binaries, container layers, and infrastructure. Full CBOM, Mosca risk scoring, tamper-evident audit chain.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
            <Link to="/app/scan" className="btn btn-primary" style={{ fontSize: 14, padding: '12px 24px' }}>
              Start a scan <ArrowRight size={15} />
            </Link>
            <a href="https://www.youtube.com/@QuantisIN" target="_blank" rel="noreferrer"
               className="btn" style={{ fontSize: 14, padding: '12px 24px' }}>
              <Play size={14} weight="fill" /> Watch on YouTube
            </a>
          </div>
        </div>
      </section>

      {/* Problem */}
      <section style={{ background: 'var(--canvas)', padding: 'clamp(56px,8vw,96px) max(5vw,48px)' }}>
        <div style={{ maxWidth: 1120, margin: '0 auto', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 64, alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.12em', color: 'var(--navy)', textTransform: 'uppercase', marginBottom: 16 }}>
              The problem
            </div>
            <h2 style={{ fontSize: 'clamp(26px,3.5vw,40px)', fontWeight: 700, letterSpacing: '-0.03em', lineHeight: 1.2, margin: '0 0 20px' }}>
              Most codebases don't know what cryptography they use.
            </h2>
            <p style={{ fontSize: 14, color: 'var(--ink-muted)', lineHeight: 1.9, marginBottom: 16 }}>
              Algorithms are embedded in dependencies, baked into binaries, and configured across infrastructure — invisible until it's too late. NIST's PQC standards are final. The migration window is closing.
            </p>
            <p style={{ fontSize: 14, color: 'var(--ink-muted)', lineHeight: 1.9 }}>
              Quantis gives you a complete cryptographic inventory, so you know exactly what needs to change and when.
            </p>
          </div>
          <div style={{ display: 'grid', gap: 16 }}>
            {[
              { label: 'Algorithm types detected', value: '47+', colour: 'var(--navy)' },
              { label: 'Risk factors in Mosca model', value: '4', colour: 'var(--teal-ink)' },
              { label: 'Export formats', value: 'CBOM · PDF · CSV · Signed ZIP', colour: 'var(--ink-muted)', isText: true },
            ].map(({ label, value, colour, isText }) => (
              <div key={label} style={{ background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', padding: '20px 24px' }}>
                <div style={{ fontSize: isText ? 18 : 36, fontWeight: 700, letterSpacing: isText ? 0 : '-0.03em', color: colour, marginBottom: 6 }}>{value}</div>
                <div style={{ fontSize: 12, color: 'var(--ink-muted)' }}>{label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pipeline */}
      <section style={{ background: 'var(--canvas-warm)', padding: 'clamp(56px,8vw,96px) max(5vw,48px)' }}>
        <div style={{ maxWidth: 1120, margin: '0 auto' }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.12em', color: 'var(--navy)', textTransform: 'uppercase', marginBottom: 16 }}>
            How it works
          </div>
          <h2 style={{ fontSize: 'clamp(24px,3vw,36px)', fontWeight: 700, letterSpacing: '-0.03em', margin: '0 0 48px' }}>
            Four stages, one scan.
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 20 }}>
            {pipelineStages.map(({ n, title, snippet, highlight }) => (
              <div key={n} style={{ background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', padding: '22px 24px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                  <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700, color: 'var(--navy)', flexShrink: 0 }}>{n}</div>
                  <div style={{ fontWeight: 600, fontSize: 14 }}>{title}</div>
                </div>
                <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--ink-muted)', background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 8, padding: '12px 14px', margin: 0, overflowX: 'auto', lineHeight: 1.7 }}>
                  <span>{snippet}</span>{'\n'}
                  <span style={{ color: 'var(--teal-ink)' }}>{'# '}{highlight}</span>
                </pre>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* What you get */}
      <section style={{ background: 'var(--canvas)', padding: 'clamp(56px,8vw,96px) max(5vw,48px)' }}>
        <div style={{ maxWidth: 1120, margin: '0 auto' }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.12em', color: 'var(--navy)', textTransform: 'uppercase', marginBottom: 16 }}>
            What you get
          </div>
          <h2 style={{ fontSize: 'clamp(24px,3vw,36px)', fontWeight: 700, letterSpacing: '-0.03em', margin: '0 0 40px' }}>
            Every screen, purpose-built.
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(260px,1fr))', gap: 16 }}>
            {[
              { Icon: ChartBar,         label: 'Overview',   desc: 'Headline stats, risk distribution chart, audit-chain status.' },
              { Icon: Upload,           label: 'Scan',        desc: 'Repository URL, file upload, or demo replay with real-time stepper.' },
              { Icon: MagnifyingGlass,  label: 'Inventory',   desc: 'Dense findings table with filter chips and a slide-in detail panel.' },
              { Icon: FileArrowDown,    label: 'Reports',     desc: 'CBOM JSON, findings PDF, and signed audit-chain export.' },
            ].map(({ Icon, label, desc }) => (
              <div key={label} style={{ background: 'var(--canvas-warm)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)', padding: '22px 24px' }}>
                <Icon size={22} weight="light" style={{ color: 'var(--navy)', marginBottom: 14 }} />
                <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 8 }}>{label}</div>
                <div style={{ fontSize: 13, color: 'var(--ink-muted)', lineHeight: 1.7 }}>{desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Roadmap */}
      <section style={{ background: 'var(--canvas-warm)', padding: 'clamp(56px,8vw,96px) max(5vw,48px)' }}>
        <div style={{ maxWidth: 720, margin: '0 auto' }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.12em', color: 'var(--navy)', textTransform: 'uppercase', marginBottom: 16 }}>
            Roadmap
          </div>
          <h2 style={{ fontSize: 'clamp(22px,2.5vw,32px)', fontWeight: 700, letterSpacing: '-0.03em', margin: '0 0 36px' }}>
            What's shipped and what's next.
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0, position: 'relative' }}>
            {roadmap.map(({ label, status }, i) => (
              <div key={label} style={{ display: 'flex', gap: 20, alignItems: 'flex-start', paddingBottom: i < roadmap.length - 1 ? 24 : 0 }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0 }}>
                  <div style={{ width: 10, height: 10, borderRadius: '50%', background: status === 'done' ? 'var(--navy)' : status === 'in-progress' ? 'var(--teal)' : 'var(--hairline)', border: '2px solid', borderColor: status === 'done' ? 'var(--navy)' : status === 'in-progress' ? 'var(--teal)' : 'var(--ink-muted)', flexShrink: 0, marginTop: 4 }} />
                  {i < roadmap.length - 1 && <div style={{ width: 1, flex: 1, background: 'var(--hairline)', minHeight: 20, marginTop: 4 }} />}
                </div>
                <div style={{ paddingBottom: 4 }}>
                  <div style={{ fontSize: 13, fontWeight: status === 'upcoming' ? 400 : 500, color: status === 'upcoming' ? 'var(--ink-muted)' : 'var(--ink)' }}>{label}</div>
                  <div style={{ fontSize: 10, color: status === 'done' ? 'var(--teal-ink)' : status === 'in-progress' ? 'var(--navy)' : 'var(--ink-muted)', marginTop: 2, fontWeight: 500, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                    {status === 'done' ? 'Shipped' : status === 'in-progress' ? 'In progress' : 'Upcoming'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section style={{ position: 'relative', background: 'var(--canvas-warm)', padding: 'clamp(64px,10vw,100px) max(5vw,48px)', textAlign: 'center', overflow: 'hidden' }}>
        <div className="hero-wash" />
        <div style={{ position: 'relative', maxWidth: 600, margin: '0 auto' }}>
          <h2 style={{ fontSize: 'clamp(26px,4vw,44px)', fontWeight: 750, letterSpacing: '-0.04em', margin: '0 0 20px' }}>
            Know your cryptographic posture.
          </h2>
          <p style={{ fontSize: 15, color: 'var(--ink-muted)', margin: '0 0 32px', lineHeight: 1.7 }}>
            Start with the demo scan — no setup required.
          </p>
          <Link to="/app/scan" className="btn btn-primary" style={{ fontSize: 15, padding: '14px 32px' }}>
            Open app <ArrowRight size={15} />
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer style={{ borderTop: '1px solid var(--hairline)', padding: '22px max(5vw,28px)', display: 'flex', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap', color: 'var(--ink-muted)', fontSize: 11 }}>
        <span>Quantis · ECDAT — Enterprise Cryptographic Discovery &amp; Analysis Tool</span>
        <span>Static inspection · Uploaded code is never executed</span>
      </footer>
    </div>
  )
}
