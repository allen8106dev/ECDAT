import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom'
import {
  ShieldCheck, ChartBar, Scan as ScanIcon, Table, ShareNetwork, ArrowsClockwise,
  Bandaids, ClockCounterClockwise, Link, FileArrowDown, Play
} from '@phosphor-icons/react'
import Home from './pages/Home'
import About from './pages/About'
import Overview from './pages/app/Overview'
import Scan from './pages/app/Scan'
import Inventory from './pages/app/Inventory'
import Dependencies from './pages/app/Dependencies'
import RiskMigration from './pages/app/RiskMigration'
import Remediation from './pages/app/Remediation'
import History from './pages/app/History'
import Audit from './pages/app/Audit'
import Reports from './pages/app/Reports'
import './index.css'

const API = import.meta.env.VITE_API_URL || '/api'

const appNav = [
  { to: '/app/overview',     label: 'Overview',     Icon: ChartBar },
  { to: '/app/scan',         label: 'Scan',         Icon: ScanIcon },
  { to: '/app/inventory',    label: 'Inventory',    Icon: Table },
  { to: '/app/dependencies', label: 'Dependencies', Icon: ShareNetwork },
  { to: '/app/risk',         label: 'Risk & Migration', Icon: ArrowsClockwise },
  { to: '/app/remediation',  label: 'Remediation',  Icon: Bandaids },
  { to: '/app/history',      label: 'History',      Icon: ClockCounterClockwise },
  { to: '/app/audit',        label: 'Audit',        Icon: Link },
  { to: '/app/reports',      label: 'Reports',      Icon: FileArrowDown },
]

function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-mark"><ShieldCheck size={26} weight="duotone" /></div>
        <div>
          <div className="logo-name">Quantis</div>
          <span className="logo-sub">ECDAT</span>
        </div>
      </div>
      <nav className="sidebar-nav">
        <div className="nav-section-label">App</div>
        {appNav.map(({ to, label, Icon }) => (
          <NavLink key={to} to={to} className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}>
            <Icon size={18} weight="light" />
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  )
}

function Topbar() {
  const loc = useLocation()
  const screen = appNav.find(n => loc.pathname.startsWith(n.to))
  return (
    <header className="topbar">
      <span className="topbar-title">{screen?.label ?? 'Quantis'}</span>
      <span className="demo-pill">Demo data</span>
      <a href="https://www.youtube.com/@QuantisIN" target="_blank" rel="noreferrer" className="yt-link">
        <Play size={13} weight="fill" />
        Watch on YouTube
      </a>
    </header>
  )
}

function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="app-layout">
      <Sidebar />
      <div className="app-content">
        <Topbar />
        <div className="page-body">{children}</div>
      </div>
    </div>
  )
}

export { API }

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Marketing */}
        <Route path="/" element={<Home />} />
        <Route path="/about" element={<About />} />

        {/* App */}
        <Route path="/app/overview"     element={<AppLayout><Overview /></AppLayout>} />
        <Route path="/app/scan"         element={<AppLayout><Scan /></AppLayout>} />
        <Route path="/app/inventory"    element={<AppLayout><Inventory /></AppLayout>} />
        <Route path="/app/dependencies" element={<AppLayout><Dependencies /></AppLayout>} />
        <Route path="/app/risk"         element={<AppLayout><RiskMigration /></AppLayout>} />
        <Route path="/app/remediation"  element={<AppLayout><Remediation /></AppLayout>} />
        <Route path="/app/history"      element={<AppLayout><History /></AppLayout>} />
        <Route path="/app/audit"        element={<AppLayout><Audit /></AppLayout>} />
        <Route path="/app/reports"      element={<AppLayout><Reports /></AppLayout>} />

        {/* Fallback */}
        <Route path="*" element={<AppLayout><Overview /></AppLayout>} />
      </Routes>
    </BrowserRouter>
  )
}
