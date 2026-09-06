import { useEffect, useState } from 'react'
import { Link, NavLink, useNavigate, useParams } from 'react-router-dom'
import { getSavedAnalysis } from '../api/AnalysisHistoryApi'
import { logout } from '../api/AuthApi'
import AnalysisResults from '../components/AnalysisResults'
import type { AnalysisHistoryResponse } from '../types'
import './SavedAnalysesPage.css'
import './AnalysisDetailPage.css'

function AnalysisDetailPage() {
  const { analysisId } = useParams()
  const parsedAnalysisId = Number(analysisId)
  const isValidAnalysisId = Number.isInteger(parsedAnalysisId) && parsedAnalysisId > 0
  const [analysis, setAnalysis] = useState<AnalysisHistoryResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    if (!isValidAnalysisId) {
      return
    }

    let isPageMounted = true

    async function loadAnalysis() {
      try {
        const data = await getSavedAnalysis(parsedAnalysisId)

        if (isPageMounted) {
          setAnalysis(data)
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

    loadAnalysis()

    return () => {
      isPageMounted = false
    }
  }, [isValidAnalysisId, navigate, parsedAnalysisId])

  async function handleLogout() {
    try {
      await logout()
    } finally {
      navigate('/login')
    }
  }

  return (
    <div className="saved-analyses-page analysis-detail-page">
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

      <main className="analysis-detail-main">
        <section className="analysis-detail-intro" aria-labelledby="analysis-detail-title">
          <p>Análisis guardado</p>
          <h1 id="analysis-detail-title">Detalle del análisis</h1>
          <span>Consulta el informe técnico completo que guardaste anteriormente.</span>
          <Link className="analysis-detail-intro__back" to="/analyses">
            <span aria-hidden="true">←</span>
            Volver a mis análisis
          </Link>
        </section>

        {!isValidAnalysisId && (
          <div className="saved-analyses-error" role="alert">
            <strong>No se ha podido cargar el análisis.</strong>
            <p>El identificador del análisis no es válido.</p>
          </div>
        )}

        {isValidAnalysisId && isLoading && (
          <div className="saved-analyses-loading" aria-live="polite">
            <span aria-hidden="true" />
            Cargando el análisis guardado…
          </div>
        )}

        {isValidAnalysisId && loadError && (
          <div className="saved-analyses-error" role="alert">
            <strong>No se ha podido cargar el análisis.</strong>
            <p>{loadError}</p>
          </div>
        )}

        {isValidAnalysisId && analysis && <AnalysisResults analysis={analysis} />}
      </main>
    </div>
  )
}

export default AnalysisDetailPage
