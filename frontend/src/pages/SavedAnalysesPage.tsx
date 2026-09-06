import { useEffect, useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { getSavedAnalyses } from '../api/AnalysisHistoryApi'
import { logout } from '../api/AuthApi'
import type { AnalysisHistoryResponse } from '../types'
import './SavedAnalysesPage.css'

const dateFormatter = new Intl.DateTimeFormat('es-ES', {
  dateStyle: 'medium',
  timeStyle: 'short',
})

function formatAnalysisDate(createdAt: string) {
  const normalizedDate = createdAt.includes('T') ? createdAt : createdAt.replace(' ', 'T')
  const date = new Date(normalizedDate)

  return Number.isNaN(date.getTime())
    ? 'Fecha no disponible'
    : dateFormatter.format(date)
}

function SavedAnalysesPage() {
  const [analyses, setAnalyses] = useState<AnalysisHistoryResponse[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const navigate = useNavigate()

  async function handleLogout() {
    try {
      await logout()
    } finally {
      navigate('/login')
    }
  }

  useEffect(() => {
    let isPageMounted = true

    async function loadSavedAnalyses() {
      try {
        const data = await getSavedAnalyses()

        if (isPageMounted) {
          setAnalyses(data)
        }
      } catch (error) {
        if (!isPageMounted || !(error instanceof Error)) {
          return
        }

        if (error.message === 'UNAUTHORIZED') {
          navigate('/login', {
            state: {
              message: 'Tu sesión ha caducado. Vuelve a iniciar sesión.',
            },
          })
          return
        }

        setLoadError(error.message)
      } finally {
        if (isPageMounted) {
          setIsLoading(false)
        }
      }
    }

    loadSavedAnalyses()

    return () => {
      isPageMounted = false
    }
  }, [navigate])

  return (
    <div className="saved-analyses-page">
      <header className="saved-analyses-header">
        <div className="saved-analyses-header__content">
          <div className="saved-analyses-header__left">
            <Link className="saved-analyses-header__brand" to="/" aria-label="Ir a ThreatIntel Lite">
              <span className="saved-analyses-header__mark" aria-hidden="true">T</span>
              <span>ThreatIntel <strong>Lite</strong></span>
            </Link>
            <button className="saved-analyses-header__logout" type="button" onClick={handleLogout}>
              Cerrar sesión
            </button>
          </div>

          <nav className="saved-analyses-header__navigation" aria-label="Navegación del dashboard">
            <NavLink className="saved-analyses-header__nav-link" to="/dashboard">
              Analizar URL
            </NavLink>
            <NavLink className="saved-analyses-header__nav-link" to="/analyses">
              Mis análisis
            </NavLink>
          </nav>
        </div>
      </header>

      <main className="saved-analyses-main">
        <section className="saved-analyses-intro" aria-labelledby="saved-analyses-title">
          <p>Historial de seguridad</p>
          <h1 id="saved-analyses-title">Mis análisis guardados</h1>
          <span>Consulta y revisa los análisis que decidas conservar.</span>
          <Link className="saved-analyses-intro__back" to="/dashboard">
            <span aria-hidden="true">←</span>
            Volver al dashboard
          </Link>
        </section>

        <section className="saved-analyses-content" aria-labelledby="saved-analyses-list-title">
          <header className="saved-analyses-content__header">
            <div>
              <p>Resultados conservados</p>
              <h2 id="saved-analyses-list-title">Historial de análisis</h2>
            </div>
            <span className="saved-analyses-content__count">
              {isLoading ? 'Cargando…' : `${analyses.length} ${analyses.length === 1 ? 'análisis' : 'análisis'}`}
            </span>
          </header>

          {isLoading && (
            <div className="saved-analyses-loading" aria-live="polite">
              <span aria-hidden="true" />
              Cargando tus análisis guardados…
            </div>
          )}

          {loadError && (
            <div className="saved-analyses-error" role="alert">
              <strong>No se han podido cargar los análisis.</strong>
              <p>{loadError}</p>
            </div>
          )}

          {!isLoading && !loadError && analyses.length === 0 && (
            <div className="saved-analyses-empty">
            <span className="saved-analyses-empty__icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" focusable="false">
                <path d="M6 3h9l3 3v15H6Z" />
                <path d="M9 10h6M9 14h4" />
                <path d="m9 18 1.5 1.5L14 16" />
              </svg>
            </span>
            <h3>Aún no tienes análisis guardados</h3>
            <p>
              Cuando guardes un resultado desde el dashboard, aparecerá aquí para que puedas consultarlo más adelante.
            </p>
            <Link className="saved-analyses-empty__action" to="/dashboard">
              Ir al dashboard
              <span aria-hidden="true">→</span>
            </Link>
          </div>
          )}

          {!isLoading && !loadError && analyses.length > 0 && (
            <div className="saved-analyses-list">
              {analyses.map((analysis) => (
                <article className="saved-analysis-card" key={analysis.id}>
                  <div className="saved-analysis-card__target">
                    <span>Dominio analizado</span>
                    <h3>{analysis.domain}</h3>
                    <p>{analysis.url}</p>
                  </div>

                  <div className="saved-analysis-card__score" aria-label={`Puntuación ${analysis.securityAssessment.score} de 100`}>
                    <span>Puntuación</span>
                    <strong>{analysis.securityAssessment.score}</strong>
                    <small>Grado {analysis.securityAssessment.grade}</small>
                  </div>

                  <dl className="saved-analysis-card__details">
                    <div>
                      <dt>Guardado</dt>
                      <dd>{formatAnalysisDate(analysis.createdAt)}</dd>
                    </div>
                    <div>
                      <dt>HTTP</dt>
                      <dd>{analysis.http.statusCode}</dd>
                    </div>
                    <div>
                      <dt>Respuesta</dt>
                      <dd>{analysis.http.totalResponseTimeMs} ms</dd>
                    </div>
                  </dl>

                  <ul className="saved-analysis-card__headers" aria-label="Resumen de cabeceras">
                    <li className="saved-analysis-card__headers--good">
                      <strong>{analysis.securityAssessment.goodHeaders}</strong> correctas
                    </li>
                    <li className="saved-analysis-card__headers--warning">
                      <strong>{analysis.securityAssessment.warningHeaders}</strong> advertencias
                    </li>
                    <li className="saved-analysis-card__headers--missing">
                      <strong>{analysis.securityAssessment.missingHeaders}</strong> ausentes
                    </li>
                  </ul>

                  <Link className="saved-analysis-card__action" to={`/analyses/${analysis.id}`}>
                    Ver análisis completo
                    <span aria-hidden="true">→</span>
                  </Link>
                </article>
              ))}
            </div>
          )}
        </section>
      </main>
    </div>
  )
}

export default SavedAnalysesPage
