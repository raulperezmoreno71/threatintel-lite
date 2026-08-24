import AnalysisFeatureCard from './AnalysisFeatureCard'
import './AnalysisFeatures.css'

const analysisFeatures = [
    {
        title: 'DNS',
        description: 'Resolución del dominio e IPs asociadas.',
    },
    {
        title: 'HTTP',
        description: 'Código de estado, tipo de contenido, servidor y tiempo de respuesta.',
    },
    {
        title: 'Redirecciones',
        description: 'Seguimiento de la cadena de redirecciones hasta la URL final.',
    },
    {
        title: 'SSL/TLS',
        description: 'Emisor, validez, vencimiento y estado del certificado de seguridad.',
    },
    {
        title: 'Cabeceras de seguridad',
        description: 'Evaluación de cabeceras HTTP clave con recomendaciones de seguridad.',
    },
    {
        title: 'Puntuación de seguridad',
        description: 'Puntuación global y calificación de seguridad de la A a la F.',
    },
]

function AnalysisFeatures() {
    return (
        <section className="analysis-features" aria-labelledby="analysis-features-title">
            <div className="analysis-features__content">
                <header className="analysis-features__header">
                    <p className="analysis-features__eyebrow">Cobertura del análisis</p>
                    <h2 id="analysis-features-title">Qué analiza ThreatIntel Lite</h2>
                    <p className="analysis-features__intro">
                        Una visión unificada de los principales aspectos técnicos y de
                        seguridad que determinan cómo responde y se protege una URL.
                    </p>
                </header>

                <ul className="analysis-features__grid">
                    {analysisFeatures.map((feature) => (
                        <li key={feature.title}>
                            <AnalysisFeatureCard
                                title={feature.title}
                                description={feature.description}
                            />
                        </li>
                    ))}
                </ul>
            </div>
        </section>
    )
}

export default AnalysisFeatures
