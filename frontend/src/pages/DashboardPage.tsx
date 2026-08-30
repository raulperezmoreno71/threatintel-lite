import { useEffect, useState } from 'react'
import type { SubmitEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { getCurrentUser, logout } from '../api/AuthApi'
import type { AnalyzeResponse, UserResponse } from '../types'
import { analyzeUrl } from '../api/AnalyzeApi'
import AnalysisResults from '../components/AnalysisResults'
import './DashboardPage.css'

function DashboardPage() {
    const [user, setUser] = useState<UserResponse | null>(null)
    const [error, setError] = useState('')
    const [url, setUrl] = useState('')
    const [analysis, setAnalysis] = useState<AnalyzeResponse | null>(null)
    const [isAnalyzing, setIsAnalyzing] = useState(false)
    const [analysisError, setAnalysisError] = useState('')

    const navigate = useNavigate()

    useEffect(() => {
        getCurrentUser()
        .then(setUser)
        .catch(error => {
            if (error.message === 'UNAUTHORIZED') {
                navigate('/login', {
                    state: {
                        message: 'Tu sesión ha caducado. Vuelve a iniciar sesión.'
                    }
                })
                return
            }

            setError(error.message)
        })
    }, [navigate])

    async function handleLogout() {
        try {
            await logout()
            navigate('/login')
        } catch (error) {
            if (error instanceof Error) {
                setError(error.message)
            }
        }
    }

    async function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
        event.preventDefault()

        setAnalysis(null)
        setAnalysisError('')

        setIsAnalyzing(true)

        try{
            const result = await analyzeUrl(url)
            setAnalysis(result)
        } catch (error) {
            if (error instanceof Error) {
                setAnalysisError(error.message)
            }
        } finally {
            setIsAnalyzing(false)
        }

    }

    const accountStatus = user?.status === 'ACTIVE'
        ? 'Activa'
        : user?.status ?? (error ? 'No disponible' : 'Cargando…')

    return (
        <div className="dashboard-page">
            <header className="dashboard-header">
                <div className="dashboard-header__content">
                    <Link className="dashboard-header__brand" to="/" aria-label="Ir a ThreatIntel Lite">
                        <span className="dashboard-header__mark" aria-hidden="true">T</span>
                        <span>ThreatIntel <strong>Lite</strong></span>
                    </Link>

                    <div className="dashboard-header__account">
                        {user && <span className="dashboard-header__email">{user.email}</span>}
                        <button className="dashboard-header__logout" type="button" onClick={handleLogout}>
                            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                                <path d="M10 5H5v14h5" />
                                <path d="M14 8l4 4-4 4" />
                                <path d="M8 12h10" />
                            </svg>
                            Cerrar sesión
                        </button>
                    </div>
                </div>
            </header>

            <main className="dashboard-main">
                <section className="dashboard-welcome" aria-labelledby="dashboard-title">
                    <p className="dashboard-welcome__eyebrow">Panel de seguridad</p>
                    <h1 id="dashboard-title">Bienvenido</h1>
                    <p>
                        {user
                            ? <>Sesión iniciada como <strong>{user.email}</strong>.</>
                            : 'Estamos preparando tu espacio de trabajo…'}
                    </p>
                </section>

                {error && (
                    <div className="dashboard-error" role="alert">
                        <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                            <path d="M12 8v5" />
                            <path d="M12 16.5v.1" />
                            <path d="M10.3 4.2 3 17a2 2 0 0 0 1.7 3h14.6a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z" />
                        </svg>
                        <span>{error}</span>
                    </div>
                )}

                <section className="dashboard-analyze" aria-labelledby="analyze-title">
                    <div className="dashboard-analyze__heading">
                        <span className="dashboard-analyze__icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" focusable="false">
                                <circle cx="11" cy="11" r="6" />
                                <path d="m16 16 4 4" />
                                <path d="M8.5 11h5" />
                            </svg>
                        </span>
                        <div>
                            <p>Nuevo análisis</p>
                            <h2 id="analyze-title">Analiza la seguridad de una URL</h2>
                        </div>
                    </div>

                    <p id="analyze-description" className="dashboard-analyze__description">
                        Introduce una dirección HTTP o HTTPS para preparar su análisis técnico.
                    </p>

                    <form
                        className="dashboard-analyze__form"
                        aria-describedby="analyze-description"
                        aria-busy={isAnalyzing}
                        onSubmit={handleSubmit}
                    >
                        <label htmlFor="analysis-url">URL que quieres analizar</label>
                        <div className="dashboard-analyze__controls">
                            <input
                                id="analysis-url"
                                name="url"
                                type="url"
                                inputMode="url"
                                autoComplete="url"
                                placeholder="https://ejemplo.com"
                                value={url}
                                onChange={(event) => setUrl(event.target.value)}
                                required
                            />
                            <button type="submit" disabled={isAnalyzing}>
                                {isAnalyzing && <span className="dashboard-analyze__spinner" aria-hidden="true" />}
                                {isAnalyzing ? 'Analizando…' : 'Analizar URL'}
                                {!isAnalyzing && <span aria-hidden="true">→</span>}
                            </button>
                        </div>
                    </form>

                    {analysisError && (
                        <div className="dashboard-analysis-error" role="alert">
                            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                                <path d="M12 8v5" />
                                <path d="M12 16.5v.1" />
                                <path d="M10.3 4.2 3 17a2 2 0 0 0 1.7 3h14.6a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z" />
                            </svg>
                            <span>{analysisError}</span>
                        </div>
                    )}

                    <ul className="dashboard-analyze__modules" aria-label="Módulos incluidos en el análisis">
                        <li>DNS</li>
                        <li>HTTP</li>
                        <li>SSL/TLS</li>
                        <li>Cabeceras</li>
                    </ul>
                </section>

                {analysis && <AnalysisResults analysis={analysis} />}

                <section className="dashboard-summary" aria-labelledby="summary-title">
                    <div className="dashboard-summary__heading">
                        <div>
                            <p>Vista general</p>
                            <h2 id="summary-title">Resumen de actividad</h2>
                        </div>
                        <span>Datos de tu cuenta</span>
                    </div>

                    <dl className="dashboard-summary__grid">
                        <div>
                            <dt>Análisis guardados</dt>
                            <dd>
                                <strong>—</strong>
                                <span>Sin datos cargados</span>
                            </dd>
                        </div>
                        <div>
                            <dt>Última puntuación</dt>
                            <dd>
                                <strong>{analysis?.securityAssessment.score ?? '—'}</strong>
                                <span>
                                    {analysis
                                        ? `Calificación ${analysis.securityAssessment.grade}`
                                        : 'Pendiente de análisis'}
                                </span>
                            </dd>
                        </div>
                        <div>
                            <dt>Estado de la cuenta</dt>
                            <dd>
                                <strong className="dashboard-summary__status">{accountStatus}</strong>
                                <span>{user?.email ?? 'Verificando la sesión'}</span>
                            </dd>
                        </div>
                    </dl>
                </section>
            </main>
        </div>
    )
}

export default DashboardPage
