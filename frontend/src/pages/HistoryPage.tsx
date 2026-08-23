import { Download, Plus } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import AppShell from '../components/AppShell'
import AnalysisTable from '../components/AnalysisTable'
import { mockAnalyses } from '../data/mockAnalyses'

export default function HistoryPage() {
  const [items, setItems] = useState(mockAnalyses)
  return (
    <AppShell title="Historial de análisis" eyebrow="INTELIGENCIA" actions={<Link className="button button--primary button--small" to="/analisis/nuevo"><Plus size={16} /> Nuevo análisis</Link>}>
      <div className="page-intro"><div><h2>Todos los análisis</h2><p>Consulta y compara la postura de seguridad de tus objetivos.</p></div><button className="button button--ghost"><Download size={16} /> Exportar CSV</button></div>
      <section className="panel history-panel"><div className="filter-row"><button className="filter-chip filter-chip--active">Todos <span>{items.length}</span></button><button className="filter-chip">Seguros <span>{items.filter((x) => x.score >= 80).length}</span></button><button className="filter-chip">Con alertas <span>{items.filter((x) => x.score < 80).length}</span></button></div><AnalysisTable analyses={items} onDelete={(id) => setItems((current) => current.filter((item) => item.id !== id))} /></section>
      <p className="mock-caption">Los cambios de esta tabla son locales y se restauran al recargar la página.</p>
    </AppShell>
  )
}
