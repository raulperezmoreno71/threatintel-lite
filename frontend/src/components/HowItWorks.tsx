import HowItWorksStep from './HowItWorksStep'
import './HowItWorks.css'

const steps = [
  {
    number: 1,
    title: 'Introduce la URL',
    description: 'Escribe la dirección HTTP o HTTPS de la web que quieres comprobar.',
  },
  {
    number: 2,
    title: 'Ejecuta el análisis',
    description: 'ThreatIntel Lite examina DNS, HTTP, redirecciones, SSL/TLS y cabeceras de seguridad.',
  },
  {
    number: 3,
    title: 'Revisa el informe',
    description: 'Consulta los resultados por módulo, la puntuación global, la calificación y las recomendaciones disponibles.',
  },
]

function HowItWorks() {
  return (
    <section className="how-it-works" aria-labelledby="how-it-works-title">
      <div className="how-it-works__content">
        <header className="how-it-works__header">
          <p className="how-it-works__eyebrow">Proceso de análisis</p>
          <h2 id="how-it-works-title">Cómo funciona el análisis de seguridad</h2>
          <p className="how-it-works__intro">
            De una URL a un informe técnico organizado en tres pasos sencillos.
          </p>
        </header>

        <ol className="how-it-works__steps">
          {steps.map((step) => (
            <HowItWorksStep
              key={step.number}
              number={step.number}
              title={step.title}
              description={step.description}
            />
          ))}
        </ol>
      </div>
    </section>
  )
}

export default HowItWorks
