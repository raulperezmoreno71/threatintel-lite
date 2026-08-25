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

          <div className="final-cta__actions" role="group" aria-label="Acciones para comenzar">
            <button className="final-cta__primary-action" type="button">
              Analizar una URL
              <span aria-hidden="true">→</span>
            </button>
            <button className="final-cta__secondary-action" type="button">
              Crear una cuenta
            </button>
          </div>

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
