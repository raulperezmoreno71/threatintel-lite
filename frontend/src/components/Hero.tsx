import './Hero.css'

const analysisAreas = ['DNS', 'HTTP', 'Redirecciones', 'SSL/TLS', 'Cabeceras']

function Hero() {
  return (
    <section className="hero" aria-labelledby="hero-title">
      <div className="hero__content">
        <div className="hero__copy">
          <p className="hero__eyebrow">
            <span aria-hidden="true" />
            Análisis web centralizado
          </p>

          <h1 id="hero-title">
            Analiza la seguridad de una URL en <span>un solo informe</span>
          </h1>

          <p className="hero__description">
            ThreatIntel Lite revisa DNS, respuesta HTTP, redirecciones, certificado
            SSL/TLS y cabeceras de seguridad para ofrecerte una puntuación global
            clara y accionable.
          </p>

          <div className="hero__actions" role="group" aria-label="Acciones principales">
            <button className="hero__primary-action" type="button">
              Analizar una URL
              <span aria-hidden="true">→</span>
            </button>
            <button className="hero__secondary-action" type="button">
              Ver qué analizamos
            </button>
          </div>

          <ul className="hero__features" aria-label="Áreas incluidas en el análisis">
            {analysisAreas.map((area) => (
              <li key={area}>
                <span aria-hidden="true">✓</span>
                {area}
              </li>
            ))}
          </ul>
        </div>

        <div className="hero__visual" aria-hidden="true">
          <div className="report-card">
            <div className="report-card__header">
              <div className="report-card__window-controls">
                <span />
                <span />
                <span />
              </div>
              <span>Ejemplo de informe</span>
            </div>

            <div className="report-card__target">
              <div>
                <span className="report-card__label">URL analizada</span>
                <strong>https://ejemplo.com</strong>
              </div>
              <span className="report-card__status">Análisis completo</span>
            </div>

            <div className="report-card__summary">
              <div className="report-card__score">
                <div className="report-card__score-ring">
                  <strong>84</strong>
                  <span>/ 100</span>
                </div>
                <div>
                  <span className="report-card__label">Puntuación global</span>
                  <strong>Seguridad buena</strong>
                </div>
              </div>
              <span className="report-card__grade">B</span>
            </div>

            <div className="report-card__modules">
              <div>
                <span className="report-card__module-icon">D</span>
                <span><strong>DNS</strong>Resuelto</span>
                <i />
              </div>
              <div>
                <span className="report-card__module-icon">H</span>
                <span><strong>HTTP</strong>Respuesta 200</span>
                <i />
              </div>
              <div>
                <span className="report-card__module-icon">S</span>
                <span><strong>SSL/TLS</strong>Certificado válido</span>
                <i />
              </div>
              <div>
                <span className="report-card__module-icon">C</span>
                <span><strong>Cabeceras</strong>5 de 6 configuradas</span>
                <i className="report-card__warning" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

export default Hero
