import { Link } from 'react-router-dom'
import { ShieldCheck, ArrowRight } from '@phosphor-icons/react'

const team = [
  { name: 'Atharva Kulkarni', role: 'Founder & Lead Engineer' },
  { name: 'Quantis Team', role: 'Core contributors' },
]

// Fixed palette rotation: navy → purple → teal → rose → coral → repeat
const tileColors = [
  { bg: 'var(--navy)',   text: 'white' },
  { bg: 'var(--purple)', text: 'white' },
  { bg: 'var(--teal)',   text: 'white' },
  { bg: 'var(--rose)',   text: 'var(--ink)' },
  { bg: 'var(--coral)',  text: 'var(--ink)' },
]

const principles = [
  { title: 'Discovery before remediation', body: 'You cannot fix what you cannot see. Quantis gives you a complete cryptographic inventory before prescribing any action.' },
  { title: 'Honest risk, not threat theatre', body: 'Risk scores are derived from your own Mosca inputs — data lifetime, migration time, CRQC horizon, and criticality. The model is transparent and project-defined.' },
  { title: 'Evidence-grade audit', body: 'Every scan is recorded in a tamper-evident blockchain so findings remain verifiable long after they are filed.' },
  { title: 'Guidance only, no auto-patching', body: 'Remediation suggestions are review-only diffs. Code is never modified automatically. The engineer decides.' },
]

const standards = [
  'NIST FIPS 203 — ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism)',
  'NIST FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Algorithm)',
  'NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)',
  'IETF CycloneDX 1.4 — Cryptography Bill of Materials (CBOM)',
  'NIST SP 800-208 — Hash-based signature schemes',
]

export default function About() {
  return (
    <div style={{ fontFamily: 'var(--font-ui)', color: 'var(--ink)' }}>
      {/* Nav */}
      <nav style={{ display: 'flex', alignItems: 'center', gap: 32, padding: '0 max(5vw,28px)', height: 60, borderBottom: '1px solid var(--hairline)', background: 'var(--canvas)', position: 'sticky', top: 0, zIndex: 20 }}>
        <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: 9, color: 'var(--ink)', textDecoration: 'none', fontWeight: 700, fontSize: 17, letterSpacing: '-0.02em' }}>
          <ShieldCheck size={22} weight="duotone" style={{ color: 'var(--purple)' }} />
          Quantis
        </Link>
        <div style={{ flex: 1 }} />
        <Link to="/" style={{ fontSize: 13, color: 'var(--ink-muted)', textDecoration: 'none' }}>Home</Link>
        <Link to="/app/overview" className="btn btn-primary" style={{ fontSize: 13, padding: '8px 18px' }}>
          Open app <ArrowRight size={14} />
        </Link>
      </nav>

      {/* Page header */}
      <section style={{ padding: 'clamp(48px,8vw,80px) max(5vw,48px) 40px', background: 'var(--canvas)' }}>
        <div style={{ maxWidth: 780 }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.12em', color: 'var(--navy)', textTransform: 'uppercase', marginBottom: 16 }}>
            About
          </div>
          <h1 style={{ fontSize: 'clamp(28px,4vw,48px)', fontWeight: 750, letterSpacing: '-0.04em', lineHeight: 1.15, margin: '0 0 20px' }}>
            Quantis is a quantum-readiness scanner for engineering teams.
          </h1>
          <p style={{ fontSize: 15, color: 'var(--ink-muted)', lineHeight: 1.9, maxWidth: 640 }}>
            Built to answer a simple question that most organisations cannot yet answer: what cryptography is running in our systems, and is any of it at risk when cryptographically relevant quantum computers arrive?
          </p>
        </div>
      </section>

      {/* Mission & Principles */}
      <section style={{ padding: 'clamp(40px,6vw,72px) max(5vw,48px)', background: 'var(--canvas)' }}>
        <div style={{ maxWidth: 780 }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.12em', color: 'var(--navy)', textTransform: 'uppercase', marginBottom: 16 }}>
            Principles
          </div>
          <div style={{ display: 'grid', gap: 28 }}>
            {principles.map(({ title, body }) => (
              <div key={title}>
                <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--ink)', marginBottom: 8 }}>{title}</div>
                <p style={{ fontSize: 14, color: 'var(--ink-muted)', lineHeight: 1.85, margin: 0 }}>{body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Where Quantis fits */}
      <section style={{ padding: 'clamp(40px,6vw,64px) max(5vw,48px)', background: 'var(--canvas)' }}>
        <div style={{ maxWidth: 780 }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.12em', color: 'var(--navy)', textTransform: 'uppercase', marginBottom: 16 }}>
            Where Quantis fits
          </div>
          <p style={{ fontSize: 14, color: 'var(--ink-muted)', lineHeight: 1.9, margin: '0 0 16px' }}>
            Quantis is a discovery and prioritisation tool — it sits before migration planning, not after. It tells you what exists, how risky it is under your specific parameters, and what the recommended replacements are. Acting on those recommendations is the work of your engineering team.
          </p>
          <p style={{ fontSize: 13, color: 'var(--ink-muted)', lineHeight: 1.8, margin: 0, fontStyle: 'italic' }}>
            Risk scores are computed from project-defined Mosca inputs (data lifetime, migration time, CRQC horizon, business criticality) and are not absolute vulnerability ratings. The same algorithm can be low-risk for one project and high-risk for another.
          </p>
        </div>
      </section>

      {/* Team — canvas-warm band */}
      <section style={{ background: 'var(--canvas-warm)', padding: 'clamp(48px,7vw,80px) max(5vw,48px)', borderTop: '1px solid var(--hairline)', borderBottom: '1px solid var(--hairline)' }}>
        <div style={{ maxWidth: 780 }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.12em', color: 'var(--navy)', textTransform: 'uppercase', marginBottom: 24 }}>
            Team
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {team.map(({ name, role }, i) => {
              const tile = tileColors[i % tileColors.length]
              const initials = name.split(' ').map(w => w[0]).slice(0, 2).join('')
              return (
                <div key={name} style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '14px 20px', background: 'var(--canvas)', border: '1px solid var(--hairline)', borderRadius: 'var(--radius-lg)' }}>
                  <div style={{ width: 40, height: 40, borderRadius: 12, background: tile.bg, color: tile.text, display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: 14, flexShrink: 0, letterSpacing: '0.02em' }}>
                    {initials}
                  </div>
                  <div>
                    <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--ink)' }}>{name}</div>
                    <div style={{ fontSize: 12, color: 'var(--ink-muted)', marginTop: 2 }}>{role}</div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </section>

      {/* Standards strip */}
      <section style={{ padding: 'clamp(40px,6vw,64px) max(5vw,48px)', background: 'var(--canvas)' }}>
        <div style={{ maxWidth: 780 }}>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.12em', color: 'var(--navy)', textTransform: 'uppercase', marginBottom: 20 }}>
            Standards
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {standards.map(s => (
              <div key={s} style={{ fontSize: 13, color: 'var(--ink-muted)', lineHeight: 1.6, paddingBottom: 10, borderBottom: '1px solid var(--hairline)' }}>
                {s}
              </div>
            ))}
          </div>
        </div>
      </section>

      <footer style={{ borderTop: '1px solid var(--hairline)', padding: '22px max(5vw,28px)', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12, color: 'var(--ink-muted)', fontSize: 11 }}>
        <span>Quantis · ECDAT</span>
        <Link to="/" style={{ color: 'var(--ink-muted)', textDecoration: 'none' }}>← Back to home</Link>
      </footer>
    </div>
  )
}
