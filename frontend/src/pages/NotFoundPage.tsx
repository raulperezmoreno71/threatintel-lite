import { ArrowLeft, Radar } from 'lucide-react'
import { Link } from 'react-router-dom'

export default function NotFoundPage() {
  return <main className="not-found"><Radar size={48} /><span>ERROR 404</span><h1>Señal no encontrada</h1><p>La ruta que buscas no forma parte de esta superficie.</p><Link className="button button--primary" to="/dashboard"><ArrowLeft size={17} /> Volver al dashboard</Link></main>
}
