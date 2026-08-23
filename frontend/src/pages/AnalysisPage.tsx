import { AlertTriangle, ArrowLeft, Calendar, Check, ChevronRight, Clock3, Copy, ExternalLink, FileKey2, Globe2, Info, Network, RefreshCw, Server, ShieldCheck, Trash2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom'
import AppShell from '../components/AppShell'
import ScoreRing from '../components/ScoreRing'
import StatusBadge from '../components/StatusBadge'
import UrlScanner from '../components/UrlScanner'
import { mockAnalyses } from '../data/mockAnalyses'
import type { Analysis } from '../types'

export default function AnalysisPage({ mode }: { mode: 'new' | 'result' | 'detail' }) {
  const { id } = useParams()
  const location = useLocation()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(mode === 'result' && Boolean(location.state?.loading))
  const [activeTab, setActiveTab] = useState('overview')
  const [copied, setCopied] = useState(false)
  const analysis: Analysis = mockAnalyses.find((item) => item.id === id) ?? mockAnalyses[0]

  useEffect(() => {
    if (!loading) return
    const timer = window.setTimeout(() => setLoading(false), 1800)
    return () => window.clearTimeout(timer)
  }, [loading])

  if (mode === 'new') return <AppShell title="Nuevo análisis" eyebrow="ESCÁNER"><div className="new-analysis"><div className="new-analysis__copy"><span className="radar-icon"><Globe2 size={26} /></span><h2>¿Qué superficie quieres analizar?</h2><p>Introduce una URL pública. Revisaremos su resolución DNS, respuesta HTTP, certificado TLS y cabeceras de seguridad.</p></div><UrlScanner prominent /><div className="scope-grid"><span><Network size={17} /><strong>DNS</strong><small>IPs y resolución</small></span><span><Server size={17} /><strong>HTTP</strong><small>Estado y redirecciones</small></span><span><FileKey2 size={17} /><strong>SSL/TLS</strong><small>Certificado y vigencia</small></span><span><ShieldCheck size={17} /><strong>Headers</strong><small>Políticas de seguridad</small></span></div></div></AppShell>

  if (loading) return <AppShell title="Analizando objetivo" eyebrow="ESCÁNER"><div className="scan-loading"><div className="radar-loader"><Globe2 size={30} /></div><span className="eyebrow">ANÁLISIS EN CURSO</span><h2>{location.state?.url ?? 'https://github.com'}</h2><p>Estamos inspeccionando la superficie. Esto es una simulación visual y no realiza ninguna petición.</p><div className="progress-track"><span /></div><div className="scan-steps"><span className="done"><Check size={15} /> Validando URL</span><span className="done"><Check size={15} /> Resolviendo DNS</span><span className="active"><span className="spinner" /> Inspeccionando TLS</span><span>Evaluando cabeceras</span></div></div></AppShell>

  const headerStats = {
    good: analysis.headers.filter((h) => h.status === 'GOOD').length,
    warning: analysis.headers.filter((h) => h.status === 'WARNING').length,
    missing: analysis.headers.filter((h) => h.status === 'MISSING').length,
  }
  return (
    <AppShell title="Resultado del análisis" eyebrow={mode === 'detail' ? `ANÁLISIS / ${analysis.id.toUpperCase()}` : 'ANÁLISIS COMPLETADO'} actions={<button className="button button--ghost button--small" onClick={() => setLoading(true)}><RefreshCw size={15} /> Reanalizar</button>}>
      <Link className="back-link" to={mode === 'detail' ? '/historial' : '/dashboard'}><ArrowLeft size={15} /> {mode === 'detail' ? 'Volver al historial' : 'Volver al resumen'}</Link>
      <section className="result-hero">
        <div className="result-target"><span className="favicon favicon--large">{analysis.domain[0].toUpperCase()}</span><div><div className="result-target__title"><h2>{analysis.domain}</h2><StatusBadge status={analysis.score >= 80 ? 'GOOD' : 'WARNING'} label={analysis.status} /></div><a href="#target">{analysis.url} <ExternalLink size={13} /></a><p><Calendar size={14} /> 23 ago 2026, 10:42 <span>•</span><Clock3 size={14} /> {analysis.duration} ms <span>•</span> ID: <code>{analysis.id}</code></p></div></div>
        <div className="score-summary"><ScoreRing score={analysis.score} grade={analysis.grade} /><div><h3>Postura mejorable</h3><p>Se han detectado {headerStats.warning + headerStats.missing} puntos que conviene revisar.</p><div className="mini-stats"><span className="good">{headerStats.good} correctos</span><span className="warn">{headerStats.warning} alertas</span><span className="bad">{headerStats.missing} ausentes</span></div></div></div>
      </section>
      <nav className="tabs" aria-label="Secciones del resultado">
        {[['overview', 'Vista general'], ['dns', 'DNS'], ['http', 'HTTP'], ['ssl', 'SSL/TLS'], ['headers', 'Security headers']].map(([key, label]) => <button key={key} className={activeTab === key ? 'active' : ''} onClick={() => setActiveTab(key)}>{label}{key === 'headers' && <span>{analysis.headers.length}</span>}</button>)}
      </nav>
      {activeTab === 'overview' && <Overview analysis={analysis} setTab={setActiveTab} />}
      {activeTab === 'dns' && <DnsPanel analysis={analysis} copied={copied} copy={() => { navigator.clipboard?.writeText(analysis.dns.ips[0]); setCopied(true); window.setTimeout(() => setCopied(false), 1200) }} />}
      {activeTab === 'http' && <HttpPanel analysis={analysis} />}
      {activeTab === 'ssl' && <SslPanel analysis={analysis} />}
      {activeTab === 'headers' && <HeadersPanel analysis={analysis} />}
      <section className="danger-zone"><div><Trash2 size={18} /><span><strong>Eliminar este análisis</strong><small>Se eliminarán permanentemente todos los resultados asociados.</small></span></div><button className="button button--danger-outline" onClick={() => navigate('/historial')}>Eliminar análisis</button></section>
    </AppShell>
  )
}

function Overview({ analysis, setTab }: { analysis: Analysis; setTab: (tab: string) => void }) {
  const cards = [
    { tab: 'dns', icon: Network, title: 'Resolución DNS', badge: <StatusBadge status="GOOD" />, rows: [['Direcciones IP', `${analysis.dns.ips.length} resueltas`], ['Principal', analysis.dns.ips[0]], ['Proveedor', analysis.dns.provider]] },
    { tab: 'http', icon: Server, title: 'Respuesta HTTP', badge: <StatusBadge status="GOOD" label={`${analysis.http.statusCode} OK`} />, rows: [['URL final', analysis.http.finalUrl], ['Servidor', analysis.http.server], ['Respuesta', `${analysis.http.totalResponseTimeMs} ms`]] },
    { tab: 'ssl', icon: FileKey2, title: 'Certificado SSL/TLS', badge: <StatusBadge status={analysis.ssl.status} />, rows: [['Emitido para', analysis.domain], ['Emisor', analysis.ssl.issuer], ['Expira en', `${analysis.ssl.daysUntilExpiration} días`]] },
  ]
  return <div className="result-grid"><section className="result-modules">{cards.map(({ tab, icon: Icon, title, badge, rows }) => <article className="module-card" key={tab}><div className="module-card__heading"><span><Icon size={18} />{title}</span>{badge}</div><dl>{rows.map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl><button className="module-card__link" onClick={() => setTab(tab)}>Ver detalles <ChevronRight size={15} /></button></article>)}</section><section className="panel findings"><div className="panel__heading"><div><span className="panel__eyebrow">HALLAZGOS</span><h2>Prioridades de mejora</h2></div><button className="text-link" onClick={() => setTab('headers')}>Ver todos</button></div><div className="finding finding--warning"><AlertTriangle size={18} /><div><strong>Content Security Policy permisiva</strong><p>La directiva permite scripts inline. Usa nonces o hashes para reducir el riesgo de XSS.</p></div><span>Media</span></div><div className="finding finding--critical"><Info size={18} /><div><strong>Permissions-Policy ausente</strong><p>Añade la cabecera para limitar el acceso a funciones sensibles del navegador.</p></div><span>Alta</span></div></section></div>
}

function DnsPanel({ analysis, copied, copy }: { analysis: Analysis; copied: boolean; copy: () => void }) {
  return <section className="detail-panel"><div className="detail-panel__heading"><span className="detail-icon"><Network size={20} /></span><div><h2>Resolución DNS</h2><p>Direcciones y metadatos del dominio resuelto.</p></div><StatusBadge status="GOOD" /></div><div className="detail-columns"><dl className="detail-list"><div><dt>Dominio</dt><dd>{analysis.domain}</dd></div><div><dt>Proveedor</dt><dd>{analysis.dns.provider}</dd></div><div><dt>Ubicación estimada</dt><dd>{analysis.dns.location}</dd></div></dl><div className="ip-list"><span>DIRECCIONES RESUELTAS</span>{analysis.dns.ips.map((ip) => <div key={ip}><code>{ip}</code><button className="icon-button" onClick={copy}>{copied ? <Check size={16} /> : <Copy size={16} />}</button></div>)}</div></div></section>
}

function HttpPanel({ analysis }: { analysis: Analysis }) {
  return <section className="detail-panel"><div className="detail-panel__heading"><span className="detail-icon"><Server size={20} /></span><div><h2>Comportamiento HTTP</h2><p>Respuesta, destino y tiempos observados.</p></div><StatusBadge status="GOOD" label={`${analysis.http.statusCode} OK`} /></div><dl className="detail-list detail-list--grid"><div><dt>Código de estado</dt><dd>{analysis.http.statusCode} OK</dd></div><div><dt>Tiempo total</dt><dd>{analysis.http.totalResponseTimeMs} ms</dd></div><div><dt>Content-Type</dt><dd>{analysis.http.contentType}</dd></div><div><dt>Servidor</dt><dd>{analysis.http.server}</dd></div><div><dt>URL final</dt><dd>{analysis.http.finalUrl}</dd></div><div><dt>Redirecciones</dt><dd>{analysis.http.redirects}</dd></div></dl></section>
}

function SslPanel({ analysis }: { analysis: Analysis }) {
  return <section className="detail-panel"><div className="detail-panel__heading"><span className="detail-icon"><FileKey2 size={20} /></span><div><h2>Certificado SSL/TLS</h2><p>Identidad, emisor y ventana de validez.</p></div><StatusBadge status={analysis.ssl.status} /></div><div className="certificate"><div className="certificate__status"><ShieldCheck size={34} /><strong>Conexión protegida</strong><span>El certificado es válido y de confianza.</span></div><dl className="detail-list"><div><dt>Sujeto</dt><dd>{analysis.ssl.subject}</dd></div><div><dt>Emisor</dt><dd>{analysis.ssl.issuer}</dd></div><div><dt>Válido desde</dt><dd>{analysis.ssl.validFrom}</dd></div><div><dt>Válido hasta</dt><dd>{analysis.ssl.validUntil}</dd></div></dl></div></section>
}

function HeadersPanel({ analysis }: { analysis: Analysis }) {
  return <section className="detail-panel"><div className="detail-panel__heading"><span className="detail-icon"><ShieldCheck size={20} /></span><div><h2>Security headers</h2><p>Evaluación de políticas HTTP que protegen el navegador.</p></div><span className="header-count">{analysis.headers.filter((h) => h.present).length}/{analysis.headers.length} presentes</span></div><div className="headers-list">{analysis.headers.map((header) => <article key={header.name}><div className="header-row"><span className={`header-state header-state--${header.status.toLowerCase()}`}>{header.status === 'GOOD' ? <Check size={15} /> : <AlertTriangle size={15} />}</span><div><strong>{header.name}</strong><code>{header.value ?? 'Cabecera no detectada'}</code></div><StatusBadge status={header.status} /></div>{header.recommendation && <p><Info size={14} /> {header.recommendation}</p>}</article>)}</div></section>
}
