import { Link } from 'react-router-dom'
import './NotFoundPage.css'

function NotFoundPage() {
  return (
    <main className="not-found-page">
      <div>
        <p className="not-found-page__code">404</p>
        <h1>Página no encontrada</h1>
        <p>La dirección que has solicitado no existe.</p>
        <Link to="/">Volver a la página principal</Link>
      </div>
    </main>
  )
}

export default NotFoundPage
