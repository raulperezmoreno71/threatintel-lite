import type { Analysis } from '../types'

const githubHeaders: Analysis['headers'] = [
  { name: 'Strict-Transport-Security', present: true, value: 'max-age=31536000; includeSubDomains; preload', status: 'GOOD', recommendation: null },
  { name: 'Content-Security-Policy', present: true, value: "default-src 'none'; script-src 'self' 'unsafe-inline'", status: 'WARNING', recommendation: "Evita 'unsafe-inline'. Utiliza nonces o hashes para scripts en línea." },
  { name: 'X-Frame-Options', present: true, value: 'deny', status: 'GOOD', recommendation: null },
  { name: 'X-Content-Type-Options', present: true, value: 'nosniff', status: 'GOOD', recommendation: null },
  { name: 'Referrer-Policy', present: true, value: 'strict-origin-when-cross-origin', status: 'GOOD', recommendation: null },
  { name: 'Permissions-Policy', present: false, value: null, status: 'MISSING', recommendation: 'Añade Permissions-Policy para restringir funciones del navegador innecesarias.' },
]

export const mockAnalyses: Analysis[] = [
  {
    id: 'an_8f31c9', url: 'https://github.com/', domain: 'github.com', createdAt: '2026-08-23T10:42:00', duration: 640,
    score: 75, grade: 'C', status: 'Con alertas',
    dns: { ips: ['140.82.121.3', '140.82.121.4'], provider: 'GitHub, Inc.', location: 'San Francisco, US' },
    http: { statusCode: 200, contentType: 'text/html; charset=utf-8', server: 'github.com', finalUrl: 'https://github.com/', totalResponseTimeMs: 640, redirects: 0 },
    ssl: { issuer: 'Sectigo Public Server Authentication CA DV E36', subject: 'CN=github.com', validFrom: '03 jul 2026', validUntil: '30 sep 2026', daysUntilExpiration: 38, status: 'GOOD', recommendation: null },
    headers: githubHeaders,
  },
  {
    id: 'an_b280ad', url: 'https://cloudflare.com/', domain: 'cloudflare.com', createdAt: '2026-08-22T16:18:00', duration: 384,
    score: 94, grade: 'A', status: 'Completado',
    dns: { ips: ['104.16.132.229', '104.16.133.229'], provider: 'Cloudflare, Inc.', location: 'Global Anycast' },
    http: { statusCode: 200, contentType: 'text/html; charset=UTF-8', server: 'cloudflare', finalUrl: 'https://www.cloudflare.com/', totalResponseTimeMs: 384, redirects: 1 },
    ssl: { issuer: 'Google Trust Services WE1', subject: 'CN=cloudflare.com', validFrom: '11 ago 2026', validUntil: '09 nov 2026', daysUntilExpiration: 78, status: 'GOOD', recommendation: null },
    headers: githubHeaders.map((h) => ({ ...h, status: 'GOOD', present: true, value: h.value ?? 'camera=(), microphone=()', recommendation: null })),
  },
  {
    id: 'an_19e7d2', url: 'http://legacy-demo.test/', domain: 'legacy-demo.test', createdAt: '2026-08-21T09:05:00', duration: 1120,
    score: 42, grade: 'F', status: 'Con alertas',
    dns: { ips: ['192.0.2.42'], provider: 'Example Network', location: 'Madrid, ES' },
    http: { statusCode: 200, contentType: 'text/html', server: 'Apache/2.4', finalUrl: 'http://legacy-demo.test/', totalResponseTimeMs: 1120, redirects: 0 },
    ssl: { issuer: 'No disponible', subject: 'No disponible', validFrom: '—', validUntil: '—', daysUntilExpiration: 0, status: 'CRITICAL', recommendation: 'Configura HTTPS con un certificado TLS válido.' },
    headers: githubHeaders.map((h, i) => i < 2 ? { ...h, status: 'WARNING' } : { ...h, present: false, value: null, status: 'MISSING', recommendation: `Añade la cabecera ${h.name}.` }),
  },
  {
    id: 'an_77ca04', url: 'https://vercel.com/', domain: 'vercel.com', createdAt: '2026-08-19T14:31:00', duration: 521,
    score: 86, grade: 'B', status: 'Completado',
    dns: { ips: ['76.76.21.21'], provider: 'Vercel, Inc.', location: 'Global Edge' },
    http: { statusCode: 200, contentType: 'text/html; charset=utf-8', server: 'Vercel', finalUrl: 'https://vercel.com/', totalResponseTimeMs: 521, redirects: 0 },
    ssl: { issuer: 'Let’s Encrypt E6', subject: 'CN=vercel.com', validFrom: '19 jul 2026', validUntil: '17 oct 2026', daysUntilExpiration: 55, status: 'GOOD', recommendation: null },
    headers: githubHeaders.map((h, i) => i === 5 ? h : { ...h, status: 'GOOD', recommendation: null }),
  },
  {
    id: 'an_d13f88', url: 'https://mozilla.org/', domain: 'mozilla.org', createdAt: '2026-08-17T11:20:00', duration: 712,
    score: 91, grade: 'A', status: 'Completado',
    dns: { ips: ['44.236.72.93'], provider: 'Amazon AWS', location: 'Oregon, US' },
    http: { statusCode: 200, contentType: 'text/html', server: 'nginx', finalUrl: 'https://www.mozilla.org/', totalResponseTimeMs: 712, redirects: 1 },
    ssl: { issuer: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1', subject: 'CN=mozilla.org', validFrom: '02 jun 2026', validUntil: '01 sep 2027', daysUntilExpiration: 374, status: 'GOOD', recommendation: null },
    headers: githubHeaders.map((h) => ({ ...h, status: h.present ? 'GOOD' : 'WARNING' })),
  },
]

export const chartData = [62, 75, 58, 82, 78, 91, 75]
