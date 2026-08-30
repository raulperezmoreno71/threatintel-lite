export type LoginResponse = {
    id: number
    email: string
    status: string
    message: string
}

export type ApiErrorResponse = {
    status: number
    error: string
    message: string
    path: string
}

export type UserResponse = {
    id: number
    email: string
    status: string
}

export type AnalyzeResponse = {
    message: string,
    url: string,
    domain: string,
    dns: DnsAnalysisResult,
    http: HttpAnalysisResult,
    ssl: SslAnalysisResult | null,
    securityHeaders: SecurityHeadersAnalysisResult,
    securityAssessment: SecurityAssessmentResult
}

export type DnsAnalysisResult = {
    ips: string[]
}

export type HttpAnalysisResult = {
    statusCode: number,
    contentType: string | null,
    server: string | null,
    contentLength: number | null,
    finalUrl: string,
    totalResponseTimeMs: number,
    redirectChain: RedirectStep[]
}

export type RedirectStep = {
    url: string,
    statusCode: number,
    location: string | null,
    responseTimeMs: number
}

export type SslAnalysisResult = {
    issuer: string,
    subject: string,
    validFrom: string,
    validUntil: string,
    daysUntilExpiration: number,
    status: string,
    recommendation: string | null
}

export type SecurityHeadersAnalysisResult = {
    strictTransportSecurity: SecurityHeaderResult,
    contentSecurityPolicy: SecurityHeaderResult,
    xFrameOptions: SecurityHeaderResult,
    xContentTypeOptions: SecurityHeaderResult,
    referrerPolicy: SecurityHeaderResult,
    permissionsPolicy: SecurityHeaderResult
}

export type SecurityHeaderResult = {
    present: boolean,
    value: string | null,
    status: string,
    recommendation: string | null
}

export type SecurityAssessmentResult = {
    score: number,
    grade: string,
    goodHeaders: number,
    warningHeaders: number,
    missingHeaders: number
}