import { BarChart3, ChevronDown, History, LogOut, Menu, Plus, X } from 'lucide-react'
import { ReactNode, useState } from 'react'
import { NavLink } from 'react-router-dom'
import Brand from './Brand'

interface Props { children: ReactNode; title: string; eyebrow?: string; actions?: ReactNode }

export default function AppShell({ children, title, eyebrow, actions }: Props) {
  const [menuOpen, setMenuOpen] = useState(false)
  return (
    <div className="app-shell">
      <aside className={`sidebar ${menuOpen ? 'sidebar--open' : ''}`}>
        <div className="sidebar__top">
          <Brand />
          <button className="icon-button sidebar__close" onClick={() => setMenuOpen(false)} aria-label="Cerrar menú"><X size={20} /></button>
        </div>
        <nav className="nav" aria-label="Navegación principal">
          <span className="nav__label">Workspace</span>
          <NavLink to="/dashboard"><BarChart3 size={18} /> Resumen</NavLink>
          <NavLink to="/analisis/nuevo"><Plus size={18} /> Nuevo análisis</NavLink>
          <NavLink to="/historial"><History size={18} /> Historial</NavLink>
        </nav>
        <div className="sidebar__status">
          <div className="system-status"><span className="status-dot" /> Sistema operativo</div>
          <p>Motor de análisis listo</p>
        </div>
        <NavLink to="/login" className="sidebar__user">
          <span className="avatar">CP</span>
          <span><strong>casper@intel.dev</strong><small>Analista</small></span>
          <LogOut size={17} />
        </NavLink>
      </aside>
      {menuOpen && <button className="scrim" onClick={() => setMenuOpen(false)} aria-label="Cerrar menú" />}
      <div className="workspace">
        <header className="topbar">
          <button className="icon-button menu-button" onClick={() => setMenuOpen(true)} aria-label="Abrir menú"><Menu size={21} /></button>
          <div className="page-heading">
            {eyebrow && <span>{eyebrow}</span>}
            <h1>{title}</h1>
          </div>
          <div className="topbar__actions">
            {actions}
            <button className="profile-button"><span className="avatar avatar--small">CP</span><ChevronDown size={15} /></button>
          </div>
        </header>
        <main className="main-content">{children}</main>
      </div>
    </div>
  )
}
