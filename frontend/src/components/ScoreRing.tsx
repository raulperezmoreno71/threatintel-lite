export default function ScoreRing({ score, grade, size = 'large' }: { score: number; grade: string; size?: 'small' | 'large' }) {
  const tone = score >= 90 ? 'excellent' : score >= 70 ? 'warning' : 'critical'
  return (
    <div className={`score-ring score-ring--${size} score-ring--${tone}`} style={{ '--score': score } as React.CSSProperties}>
      <div><strong>{score}</strong><span>/100</span>{size === 'large' && <em>Grado {grade}</em>}</div>
    </div>
  )
}
