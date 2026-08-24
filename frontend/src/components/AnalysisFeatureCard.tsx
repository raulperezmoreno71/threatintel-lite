import './AnalysisFeatureCard.css'

type AnalysisFeatureCardProps = {
    title: string
    description: string
}

function AnalysisFeatureCard({
    title,
    description,
}: AnalysisFeatureCardProps) {
    return (
        <article className="analysis-card">
            <div className="analysis-card__top" aria-hidden="true">
                <span className="analysis-card__icon">
                    <svg viewBox="0 0 24 24" focusable="false">
                        <path d="M12 3 19 6v5c0 4.5-2.7 8-7 10-4.3-2-7-5.5-7-10V6l7-3Z" />
                        <path d="m9.2 12 1.8 1.8 3.9-4" />
                    </svg>
                </span>
                <span className="analysis-card__index" />
            </div>
            <h3>{title}</h3>
            <p>{description}</p>
        </article>
    )
}

export default AnalysisFeatureCard
