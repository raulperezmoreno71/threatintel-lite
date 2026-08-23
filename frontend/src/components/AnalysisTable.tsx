import { ArrowUpRight, MoreHorizontal, Search, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import type { Analysis } from '../types'

interface Props { analyses: Analysis[]; compact?: boolean; onDelete?: (id: string) => void }

export default function AnalysisTable({ analyses, compact, onDelete }: Props) {
  const [query, setQuery] = useState('')
  const [confirm, setConfirm] = useState<string | null>(null)
  const shown = useMemo(() => analyses.filter((item) => item.domain.toLowerCase().includes(query.toLowerCase())), [analyses, query])
  return (
    <>
      {!compact && <div className="table-tools"><label className="search-field"><Search size={17} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Buscar por dominio…" /></label><span>{shown.length} análisis</span></div>}
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Objetivo</th><th>Fecha</th><th>Estado</th><th>Score</th><th>Tiempo</th><th><span className="sr-only">Acciones</span></th></tr></thead>
          <tbody>
            {shown.map((item) => (
              <tr key={item.id}>
                <td><Link className="target-cell" to={`/analisis/${item.id}`}><span className="favicon">{item.domain[0].toUpperCase()}</span><span><strong>{item.domain}</strong><small>{item.url}</small></span></Link></td>
                <td><span className="date-cell">{new Intl.DateTimeFormat('es', { day: '2-digit', month: 'short', year: 'numeric' }).format(new Date(item.createdAt))}<small>{new Intl.DateTimeFormat('es', { hour: '2-digit', minute: '2-digit' }).format(new Date(item.createdAt))}</small></span></td>
                <td><span className={`dot-label ${item.status === 'Completado' ? 'dot-label--good' : 'dot-label--warn'}`}>{item.status}</span></td>
                <td><span className={`grade grade--${item.grade.toLowerCase()}`}>{item.grade}</span><strong className="score-number">{item.score}</strong></td>
                <td className="mono muted">{item.duration} ms</td>
                <td><div className="row-actions"><Link className="icon-button" to={`/analisis/${item.id}`} aria-label={`Ver ${item.domain}`}><ArrowUpRight size={17} /></Link>{onDelete ? <button className="icon-button icon-button--danger" onClick={() => setConfirm(item.id)} aria-label={`Eliminar ${item.domain}`}><Trash2 size={16} /></button> : <button className="icon-button"><MoreHorizontal size={18} /></button>}</div></td>
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length === 0 && <div className="empty-state"><Search size={28} /><h3>Sin resultados</h3><p>No hay análisis que coincidan con “{query}”.</p></div>}
      </div>
      {confirm && <div className="modal-backdrop" role="presentation"><div className="modal" role="dialog" aria-modal="true" aria-labelledby="delete-title"><span className="modal__danger"><Trash2 size={22} /></span><h2 id="delete-title">Eliminar análisis</h2><p>Esta acción eliminará el análisis y todos sus resultados asociados. No se puede deshacer.</p><div className="modal__actions"><button className="button button--ghost" onClick={() => setConfirm(null)}>Cancelar</button><button className="button button--danger" onClick={() => { onDelete?.(confirm); setConfirm(null) }}>Eliminar análisis</button></div></div></div>}
    </>
  )
}
