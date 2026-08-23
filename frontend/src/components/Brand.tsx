import { ShieldCheck } from 'lucide-react'
import { Link } from 'react-router-dom'

export default function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link className={`brand ${compact ? 'brand--compact' : ''}`} to="/dashboard" aria-label="ThreatIntel Lite">
      <span className="brand__mark"><ShieldCheck size={20} strokeWidth={2.2} /></span>
      {!compact && <span>ThreatIntel <strong>Lite</strong></span>}
    </Link>
  )
}
