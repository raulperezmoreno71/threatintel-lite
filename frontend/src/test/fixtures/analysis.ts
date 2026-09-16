import type {
  AnalyzeResponse,
  AnalysisHistoryResponse,
  DnsAnalysisResult,
  HttpAnalysisResult,
  SecurityAssessmentResult,
  SecurityHeadersAnalysisResult,
  SslAnalysisResult,
} from '../../types'

type AnalysisFixtureOverrides = Partial<
  Omit<AnalyzeResponse, 'dns' | 'http' | 'ssl' | 'securityHeaders' | 'securityAssessment'>
> & {
  dns?: Partial<DnsAnalysisResult>
  http?: Partial<HttpAnalysisResult>
  ssl?: Partial<SslAnalysisResult> | null
  securityHeaders?: Partial<SecurityHeadersAnalysisResult>
  securityAssessment?: Partial<SecurityAssessmentResult>
}

export function createAnalysisFixture(
  overrides: AnalysisFixtureOverrides = {},
): AnalyzeResponse {
  const analysis: AnalyzeResponse = {
    message: 'URL analyzed successfully',
    url: 'http://example.com',
    domain: 'example.com',
    dns: {
      ips: ['93.184.216.34', '2001:db8::1'],
    },
    http: {
      statusCode: 200,
      contentType: 'text/html; charset=UTF-8',
      server: 'nginx',
      contentLength: 2048,
      finalUrl: 'https://example.com',
      totalResponseTimeMs: 180,
      redirectChain: [
        {
          url: 'http://example.com',
          statusCode: 301,
          location: 'https://example.com',
          responseTimeMs: 45,
        },
        {
          url: 'https://example.com',
          statusCode: 200,
          location: null,
          responseTimeMs: 135,
        },
      ],
    },
    ssl: {
      issuer: "CN=Let's Encrypt Authority",
      subject: 'CN=example.com',
      validFrom: '2026-08-01',
      validUntil: '2026-11-01',
      daysUntilExpiration: 46,
      status: 'GOOD',
      recommendation: null,
    },
    securityHeaders: {
      strictTransportSecurity: {
        present: true,
        value: 'max-age=31536000; includeSubDomains',
        status: 'GOOD',
        recommendation: null,
      },
      contentSecurityPolicy: {
        present: true,
        value: "default-src 'self'",
        status: 'GOOD',
        recommendation: null,
      },
      xFrameOptions: {
        present: true,
        value: 'DENY',
        status: 'GOOD',
        recommendation: null,
      },
      xContentTypeOptions: {
        present: true,
        value: 'nosniff',
        status: 'GOOD',
        recommendation: null,
      },
      referrerPolicy: {
        present: true,
        value: 'strict-origin-when-cross-origin',
        status: 'GOOD',
        recommendation: null,
      },
      permissionsPolicy: {
        present: false,
        value: null,
        status: 'MISSING',
        recommendation: 'Add a Permissions-Policy header.',
      },
    },
    securityAssessment: {
      score: 90,
      grade: 'A',
      goodHeaders: 5,
      warningHeaders: 0,
      missingHeaders: 1,
    },
  }

  return {
    ...analysis,
    ...overrides,
    dns: {
      ...analysis.dns,
      ...overrides.dns,
    },
    http: {
      ...analysis.http,
      ...overrides.http,
    },
    ssl: overrides.ssl === null
      ? null
      : {
          ...analysis.ssl!,
          ...overrides.ssl,
        },
    securityHeaders: {
      ...analysis.securityHeaders,
      ...overrides.securityHeaders,
    },
    securityAssessment: {
      ...analysis.securityAssessment,
      ...overrides.securityAssessment,
    },
  }
}

type AnalysisHistoryFixtureOverrides = AnalysisFixtureOverrides & {
  id?: number
  createdAt?: string
}

export function createAnalysisHistoryFixture(
  overrides: AnalysisHistoryFixtureOverrides = {},
): AnalysisHistoryResponse {
  const { id = 1, createdAt = '2026-09-16T10:30:00', ...analysisOverrides } = overrides

  return {
    ...createAnalysisFixture(analysisOverrides),
    id,
    createdAt,
  }
}
