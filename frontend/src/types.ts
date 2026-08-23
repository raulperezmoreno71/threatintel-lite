export type RiskStatus = 'GOOD' | 'WARNING' | 'CRITICAL' | 'MISSING'

export interface HeaderCheck {
  name: string
  present: boolean
  value: string | null
  status: RiskStatus
  recommendation: string | null
}

export interface Analysis {
  id: string
  url: string
  domain: string
  createdAt: string
  duration: number
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  status: 'Completado' | 'Con alertas'
  dns: { ips: string[]; provider: string; location: string }
  http: {
    statusCode: number
    contentType: string
    server: string
    finalUrl: string
    totalResponseTimeMs: number
    redirects: number
  }
  ssl: {
    issuer: string
    subject: string
    validFrom: string
    validUntil: string
    daysUntilExpiration: number
    status: RiskStatus
    recommendation: string | null
  }
  headers: HeaderCheck[]
}
