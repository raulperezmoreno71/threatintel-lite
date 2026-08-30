import type { AnalyzeResponse } from '../types'
import './AnalysisResults.css'

type AnalysisResultsProps = {
  analysis: AnalyzeResponse
}

type StatusTone = 'good' | 'warning' | 'missing' | 'critical' | 'neutral'

const numberFormatter = new Intl.NumberFormat('es-ES')

function getStatusTone(status: string): StatusTone {
  switch (status.toUpperCase()) {
    case 'GOOD':
      return 'good'
    case 'WARNING':
      return 'warning'
    case 'MISSING':
      return 'missing'
    case 'CRITICAL':
      return 'critical'
    default:
      return 'neutral'
  }
}

function getStatusLabel(status: string) {
  switch (status.toUpperCase()) {
    case 'GOOD':
      return 'Correcto'
    case 'WARNING':
      return 'Advertencia'
    case 'MISSING':
      return 'Ausente'
    case 'CRITICAL':
      return 'Crítico'
    default:
      return status
  }
}

function StatusBadge({ status }: { status: string }) {
  const tone = getStatusTone(status)

  return (
    <span className={`analysis-status analysis-status--${tone}`}>
      <span aria-hidden="true" />
      {getStatusLabel(status)}
    </span>
  )
}

function AnalysisResults({ analysis }: AnalysisResultsProps) {
  const { dns, http, ssl, securityAssessment } = analysis
  const safeScore = Math.min(100, Math.max(0, securityAssessment.score))

  const securityHeaders = [
    {
      name: 'Strict-Transport-Security',
      shortName: 'HSTS',
      result: analysis.securityHeaders.strictTransportSecurity,
    },
    {
      name: 'Content-Security-Policy',
      shortName: 'CSP',
      result: analysis.securityHeaders.contentSecurityPolicy,
    },
    {
      name: 'X-Frame-Options',
      shortName: 'XFO',
      result: analysis.securityHeaders.xFrameOptions,
    },
    {
      name: 'X-Content-Type-Options',
      shortName: 'XCTO',
      result: analysis.securityHeaders.xContentTypeOptions,
    },
    {
      name: 'Referrer-Policy',
      shortName: 'RP',
      result: analysis.securityHeaders.referrerPolicy,
    },
    {
      name: 'Permissions-Policy',
      shortName: 'PP',
      result: analysis.securityHeaders.permissionsPolicy,
    },
  ]

  return (
    <section className="analysis-results" aria-labelledby="analysis-results-title">
      <header className="analysis-results__header">
        <div>
          <p>Informe de seguridad</p>
          <h2 id="analysis-results-title">Resultado del análisis</h2>
        </div>
        <span className="analysis-results__complete">
          <span aria-hidden="true" />
          Análisis completado
        </span>
      </header>

      <div className="analysis-results__target">
        <div>
          <span>URL analizada</span>
          <strong>{analysis.url}</strong>
        </div>
        <div>
          <span>Dominio</span>
          <strong>{analysis.domain}</strong>
        </div>
      </div>

      <div className="analysis-overview">
        <article className="analysis-score-card">
          <div className="analysis-score-card__top">
            <div>
              <p>Evaluación global</p>
              <h3>Postura de seguridad</h3>
            </div>
            <span className="analysis-score-card__grade" aria-label={`Calificación ${securityAssessment.grade}`}>
              {securityAssessment.grade}
            </span>
          </div>

          <div className="analysis-score-card__value">
            <strong>{securityAssessment.score}</strong>
            <span>/ 100</span>
          </div>

          <div
            className="analysis-score-card__meter"
            role="meter"
            aria-label="Puntuación de seguridad"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={safeScore}
          >
            <span style={{ width: `${safeScore}%` }} />
          </div>
        </article>

        <div className="analysis-header-summary" aria-label="Resumen de cabeceras de seguridad">
          <article className="analysis-header-summary__item analysis-header-summary__item--good">
            <span>Correctas</span>
            <strong>{securityAssessment.goodHeaders}</strong>
            <small>Cabeceras bien configuradas</small>
          </article>
          <article className="analysis-header-summary__item analysis-header-summary__item--warning">
            <span>Advertencias</span>
            <strong>{securityAssessment.warningHeaders}</strong>
            <small>Requieren revisión</small>
          </article>
          <article className="analysis-header-summary__item analysis-header-summary__item--missing">
            <span>Ausentes</span>
            <strong>{securityAssessment.missingHeaders}</strong>
            <small>No detectadas</small>
          </article>
        </div>
      </div>

      <div className="analysis-technical-grid">
        <article className="analysis-panel analysis-panel--dns">
          <header className="analysis-panel__header">
            <span className="analysis-panel__icon" aria-hidden="true">DNS</span>
            <div>
              <p>Resolución de red</p>
              <h3>DNS e IPs</h3>
            </div>
          </header>

          {dns.ips.length > 0 ? (
            <ul className="analysis-ip-list">
              {dns.ips.map((ip) => (
                <li key={ip}>
                  <span aria-hidden="true" />
                  <code>{ip}</code>
                </li>
              ))}
            </ul>
          ) : (
            <p className="analysis-empty-value">No se encontraron direcciones IP.</p>
          )}
        </article>

        <article className="analysis-panel analysis-panel--http">
          <header className="analysis-panel__header">
            <span className="analysis-panel__icon" aria-hidden="true">HTTP</span>
            <div>
              <p>Respuesta del servidor</p>
              <h3>Información HTTP</h3>
            </div>
            <span className="analysis-http-code">{http.statusCode}</span>
          </header>

          <dl className="analysis-detail-list">
            <div>
              <dt>Servidor</dt>
              <dd>{http.server ?? 'No identificado'}</dd>
            </div>
            <div>
              <dt>Tipo de contenido</dt>
              <dd>{http.contentType ?? 'No informado'}</dd>
            </div>
            <div>
              <dt>Tamaño declarado</dt>
              <dd>
                {http.contentLength === null
                  ? 'No informado'
                  : `${numberFormatter.format(http.contentLength)} bytes`}
              </dd>
            </div>
            <div>
              <dt>Tiempo total</dt>
              <dd className="analysis-detail-list__highlight">{numberFormatter.format(http.totalResponseTimeMs)} ms</dd>
            </div>
            <div className="analysis-detail-list__wide">
              <dt>URL final</dt>
              <dd>{http.finalUrl}</dd>
            </div>
          </dl>
        </article>
      </div>

      <article className="analysis-panel analysis-redirects">
        <header className="analysis-panel__header">
          <span className="analysis-panel__icon" aria-hidden="true">R</span>
          <div>
            <p>Recorrido HTTP</p>
            <h3>Cadena de redirecciones</h3>
          </div>
          <span className="analysis-panel__count">{http.redirectChain.length} pasos</span>
        </header>

        {http.redirectChain.length > 0 ? (
          <ol className="analysis-redirect-list">
            {http.redirectChain.map((redirect, index) => (
              <li key={`${redirect.url}-${index}`}>
                <span className="analysis-redirect-list__step" aria-hidden="true">
                  {String(index + 1).padStart(2, '0')}
                </span>
                <div className="analysis-redirect-list__content">
                  <div>
                    <strong>{redirect.url}</strong>
                    <span className="analysis-http-code">{redirect.statusCode}</span>
                  </div>
                  <p>
                    {redirect.location
                      ? <>Redirige a <span>{redirect.location}</span></>
                      : 'Respuesta final sin nueva ubicación'}
                  </p>
                </div>
                <span className="analysis-redirect-list__time">{numberFormatter.format(redirect.responseTimeMs)} ms</span>
              </li>
            ))}
          </ol>
        ) : (
          <p className="analysis-empty-value">No se registraron pasos HTTP.</p>
        )}
      </article>

      <article className="analysis-panel analysis-ssl">
        <header className="analysis-panel__header">
          <span className="analysis-panel__icon" aria-hidden="true">TLS</span>
          <div>
            <p>Certificado digital</p>
            <h3>Seguridad SSL/TLS</h3>
          </div>
          {ssl && <StatusBadge status={ssl.status} />}
        </header>

        {ssl ? (
          <>
            <div className="analysis-ssl__layout">
              <dl className="analysis-detail-list analysis-detail-list--ssl">
                <div className="analysis-detail-list__wide">
                  <dt>Emisor</dt>
                  <dd>{ssl.issuer}</dd>
                </div>
                <div className="analysis-detail-list__wide">
                  <dt>Sujeto</dt>
                  <dd>{ssl.subject}</dd>
                </div>
                <div>
                  <dt>Válido desde</dt>
                  <dd>{ssl.validFrom}</dd>
                </div>
                <div>
                  <dt>Válido hasta</dt>
                  <dd>{ssl.validUntil}</dd>
                </div>
              </dl>

              <div className="analysis-ssl__expiration">
                <span>Días hasta expiración</span>
                <strong>{ssl.daysUntilExpiration}</strong>
                <small>Según la fecha del certificado</small>
              </div>
            </div>

            {ssl.recommendation && (
              <div className="analysis-recommendation analysis-recommendation--ssl">
                <strong>Recomendación</strong>
                <p>{ssl.recommendation}</p>
              </div>
            )}
          </>
        ) : (
          <div className="analysis-empty-state">
            <strong>Información SSL/TLS no disponible</strong>
            <p>Este análisis no incluye datos de certificado.</p>
          </div>
        )}
      </article>

      <section className="analysis-security-headers" aria-labelledby="security-headers-title">
        <header className="analysis-security-headers__header">
          <div>
            <p>Configuración defensiva</p>
            <h3 id="security-headers-title">Cabeceras de seguridad</h3>
          </div>
          <span>6 comprobaciones</span>
        </header>

        <div className="analysis-security-headers__grid">
          {securityHeaders.map(({ name, shortName, result }) => (
            <article className="security-header-card" key={name}>
              <header>
                <span className="security-header-card__short" aria-hidden="true">{shortName}</span>
                <div>
                  <h4>{name}</h4>
                  <span>{result.present ? 'Detectada' : 'No detectada'}</span>
                </div>
                <StatusBadge status={result.status} />
              </header>

              <div className="security-header-card__value">
                <span>Valor recibido</span>
                {shortName === 'CSP' && result.value ? (
                  <details className="security-header-value">
                    <summary>
                      <code className="security-header-value__preview">{result.value}</code>
                      <span className="security-header-value__action">
                        <span className="security-header-value__open">Leer valor completo</span>
                        <span className="security-header-value__close">Mostrar menos</span>
                      </span>
                    </summary>
                    <code className="security-header-value__full">{result.value}</code>
                  </details>
                ) : (
                  <code>{result.value ?? 'No informado'}</code>
                )}
              </div>

              {result.recommendation && (
                <div className="analysis-recommendation">
                  <strong>Recomendación</strong>
                  <p>{result.recommendation}</p>
                </div>
              )}
            </article>
          ))}
        </div>
      </section>
    </section>
  )
}

export default AnalysisResults
