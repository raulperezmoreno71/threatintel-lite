import './Footer.css'

function Footer() {
  return (
    <footer className="site-footer">
      <div className="site-footer__content">
        <div className="site-footer__main">
          <div className="site-footer__about">
            <div className="site-footer__brand" aria-label="ThreatIntel Lite">
              <span className="site-footer__mark" aria-hidden="true">T</span>
              <strong>ThreatIntel <span>Lite</span></strong>
            </div>
            <p>
              Análisis técnico de URLs con evaluación de DNS, HTTP, SSL/TLS,
              cabeceras y puntuación de seguridad.
            </p>
          </div>

          <nav className="site-footer__links" aria-label="Enlaces del proyecto">
            <a href="https://github.com/raulperezmoreno71/threatintel-lite">
              <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <path d="M12 2.8a9.5 9.5 0 0 0-3 18.5c.5.1.7-.2.7-.5v-1.9c-2.8.6-3.4-1.2-3.4-1.2-.5-1.2-1.1-1.5-1.1-1.5-.9-.6.1-.6.1-.6 1 0 1.6 1 1.6 1 .9 1.6 2.4 1.1 3 .9.1-.7.4-1.1.7-1.4-2.3-.3-4.6-1.1-4.6-4.7 0-1 .4-1.9 1-2.6-.1-.3-.4-1.3.1-2.6 0 0 .8-.3 2.7 1a9.3 9.3 0 0 1 4.9 0c1.8-1.3 2.7-1 2.7-1 .5 1.3.2 2.3.1 2.6.6.7 1 1.6 1 2.6 0 3.7-2.3 4.5-4.6 4.7.4.3.7 1 .7 1.9v2.8c0 .4.2.6.7.5A9.5 9.5 0 0 0 12 2.8Z" />
              </svg>
              Proyecto en GitHub
            </a>
            <a href="https://www.linkedin.com/in/ra%C3%BAl-p%C3%A9rez-moreno-ba0aab3a7/">
              <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <path d="M6.4 8.2H3.3V18h3.1V8.2ZM4.9 3.3a1.8 1.8 0 1 0 0 3.6 1.8 1.8 0 0 0 0-3.6ZM18.7 12.4c0-3-1.6-4.4-3.7-4.4-1.7 0-2.5 1-2.9 1.6V8.2H9V18h3.1v-4.9c0-1.3.2-2.6 1.9-2.6 1.6 0 1.7 1.5 1.7 2.7V18h3v-5.6Z" />
              </svg>
              Autor en LinkedIn
            </a>
          </nav>
        </div>

        <div className="site-footer__bottom">
          <small>© 2026 ThreatIntel Lite</small>
          <small>Proyecto de análisis de seguridad web</small>
        </div>
      </div>
    </footer>
  )
}

export default Footer
