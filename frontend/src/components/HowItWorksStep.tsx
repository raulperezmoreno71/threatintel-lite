import './HowItWorksStep.css'

type HowItWorksStepProps = {
  number: number
  title: string
  description: string
}

function HowItWorksStep({
  number,
  title,
  description,
}: HowItWorksStepProps) {
  return (
    <li className="how-it-works-step">
      <span className="how-it-works-step__number" aria-hidden="true">
        0{number}
      </span>
      <div className="how-it-works-step__copy">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </li>
  )
}

export default HowItWorksStep
