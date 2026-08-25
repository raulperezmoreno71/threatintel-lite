import { Link } from 'react-router-dom'
import './FinalCTA.css'

function FinalCTA() {
  return (
    <section className="final-cta" aria-labelledby="final-cta-title">
      <div className="final-cta__content">
        <div className="final-cta__panel">
          <p className="final-cta__eyebrow">Tu próximo análisis</p>

          <h2 id="final-cta-title">Comprueba la seguridad de una URL</h2>

          <p className="final-cta__description">
            Obtén un informe técnico organizado por módulos, con puntuación,
            calificación y recomendaciones para interpretar cada resultado.
          </p>

          <nav className="final-cta__actions" aria-label="Acciones para comenzar">
            <Link className="final-cta__primary-action" to="/register">
              Empieza a analizar
              <span aria-hidden="true">→</span>
            </Link>
            <Link className="final-cta__secondary-action" to="/login">
              Ya tengo una cuenta
            </Link>
          </nav>

          <p className="final-cta__support">
            <span aria-hidden="true">✓</span>
            Evaluación y calificación global de seguridad incluidas
          </p>
        </div>
      </div>
    </section>
  )
}

export default FinalCTA
