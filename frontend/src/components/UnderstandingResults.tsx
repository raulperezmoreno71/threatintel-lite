import './UnderstandingResults.css'

function UnderstandingResults() {
  return (
    <section className="understanding-results" aria-labelledby="understanding-results-title">
      <div className="understanding-results__content">
        <p className="understanding-results__eyebrow">Interpretar el informe</p>
        <h2 id="understanding-results-title">Qué significan los resultados</h2>
        <p className="understanding-results__intro">
          El informe reúne señales técnicas observables de la URL analizada. Te ayuda a
          detectar configuraciones que conviene revisar, pero no sustituye una auditoría
          de seguridad completa.
        </p>

        <div className="understanding-results__grid">
          <article>
            <h3>¿Qué se comprueba?</h3>
            <p>
              La resolución DNS, la respuesta HTTP y sus redirecciones, el certificado
              SSL/TLS cuando se usa HTTPS y seis cabeceras de seguridad de la respuesta.
            </p>
          </article>
          <article>
            <h3>¿Cómo se obtiene la puntuación?</h3>
            <p>
              Las cabeceras evaluadas se combinan en una puntuación ponderada de 0 a 100
              y una calificación de la A a la F. Consulta cada módulo para entender las
              recomendaciones concretas.
            </p>
          </article>
          <article>
            <h3>¿Qué no demuestra el informe?</h3>
            <p>
              Una buena nota no garantiza que una web esté libre de vulnerabilidades.
              El análisis no es una prueba de penetración ni verifica el código interno
              de la aplicación.
            </p>
          </article>
        </div>
      </div>
    </section>
  )
}

export default UnderstandingResults
