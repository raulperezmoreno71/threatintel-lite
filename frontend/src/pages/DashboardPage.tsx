import { ArrowRight, CheckCircle2, Clock3, Globe2, ShieldAlert, TrendingUp } from 'lucide-react'
import { Link } from 'react-router-dom'
import AppShell from '../components/AppShell'
import AnalysisTable from '../components/AnalysisTable'
import UrlScanner from '../components/UrlScanner'
import { chartData, mockAnalyses } from '../data/mockAnalyses'

export default function DashboardPage() {
  return (
    <AppShell title="Resumen de seguridad" eyebrow="23 agosto 2026">
      <div className="dashboard-welcome"><div><h2>Buenos días, Casper.</h2><p>Este es el estado actual de tus superficies analizadas.</p></div><span className="system-status"><span className="status-dot" /> Todos los sistemas operativos</span></div>
      <UrlScanner prominent />
      <section className="stat-grid">
        <article className="stat-card"><span className="stat-card__icon"><Globe2 size={19} /></span><div><p>Análisis totales</p><strong>128</strong><small><TrendingUp size={13} /> 14 esta semana</small></div></article>
        <article className="stat-card"><span className="stat-card__icon stat-card__icon--green"><CheckCircle2 size={19} /></span><div><p>Score medio</p><strong>78<span>/100</span></strong><small><TrendingUp size={13} /> 6 puntos este mes</small></div></article>
        <article className="stat-card"><span className="stat-card__icon stat-card__icon--amber"><ShieldAlert size={19} /></span><div><p>Alertas abiertas</p><strong>9</strong><small>3 requieren atención</small></div></article>
        <article className="stat-card"><span className="stat-card__icon stat-card__icon--blue"><Clock3 size={19} /></span><div><p>Tiempo medio</p><strong>612<span> ms</span></strong><small>Respuesta de objetivos</small></div></article>
      </section>
      <div className="dashboard-grid">
        <section className="panel trend-panel"><div className="panel__heading"><div><span className="panel__eyebrow">TENDENCIA</span><h2>Score de seguridad</h2></div><select aria-label="Periodo"><option>Últimos 7 días</option></select></div><div className="chart"><div className="chart__labels"><span>100</span><span>75</span><span>50</span><span>25</span><span>0</span></div><div className="chart__plot">{chartData.map((n, i) => <div className="chart__column" key={i}><span style={{ height: `${n}%` }}><i>{n}</i></span><small>{['L', 'M', 'X', 'J', 'V', 'S', 'D'][i]}</small></div>)}</div></div></section>
        <section className="panel posture-panel"><div className="panel__heading"><div><span className="panel__eyebrow">DISTRIBUCIÓN</span><h2>Postura actual</h2></div></div><div className="donut" aria-label="78 por ciento saludable"><div><strong>78%</strong><span>Saludable</span></div></div><div className="legend"><span><i className="legend--good" /> Seguro <b>76</b></span><span><i className="legend--warn" /> A revisar <b>34</b></span><span><i className="legend--bad" /> Crítico <b>18</b></span></div></section>
      </div>
      <section className="panel recent-panel"><div className="panel__heading"><div><span className="panel__eyebrow">ACTIVIDAD</span><h2>Análisis recientes</h2></div><Link className="text-link" to="/historial">Ver historial <ArrowRight size={15} /></Link></div><AnalysisTable analyses={mockAnalyses.slice(0, 4)} compact /></section>
    </AppShell>
  )
}
