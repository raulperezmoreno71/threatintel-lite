import { AlertTriangle, CheckCircle2, CircleMinus, XCircle } from 'lucide-react'
import type { RiskStatus } from '../types'

export default function StatusBadge({ status, label }: { status: RiskStatus | 'INFO'; label?: string }) {
  const Icon = status === 'GOOD' ? CheckCircle2 : status === 'WARNING' ? AlertTriangle : status === 'CRITICAL' ? XCircle : CircleMinus
  const words = { GOOD: 'Correcto', WARNING: 'Revisar', CRITICAL: 'Crítico', MISSING: 'Ausente', INFO: 'Info' }
  return <span className={`badge badge--${status.toLowerCase()}`}><Icon size={13} />{label ?? words[status]}</span>
}
