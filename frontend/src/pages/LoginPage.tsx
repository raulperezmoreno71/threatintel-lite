import { useState } from 'react'
import type { SubmitEvent } from 'react'
import { Link } from 'react-router-dom'
import { login } from '../api/AuthApi'
import './LoginPage.css'

function LoginPage() {
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')
    const [isLoading, setIsLoading] = useState(false)

    async function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
        event.preventDefault()

        if (isLoading) return

        setError('')
        setIsLoading(true)

        try {
            await login(email.trim(), password)
        } catch (error) {
            if (error instanceof Error) {
                setError(error.message)
            } else {
                setError('No se ha podido iniciar sesión. Inténtalo de nuevo.')
            }
        } finally {
            setIsLoading(false)
        }
    }

    return (
        <main className="login-page">
            <div className="login-page__content">
                <Link className="login-page__brand" to="/" aria-label="Volver a ThreatIntel Lite">
                    <span className="login-page__brand-mark" aria-hidden="true">T</span>
                    <span>ThreatIntel <strong>Lite</strong></span>
                </Link>

                <section className="login-card" aria-labelledby="login-title">
                    <div className="login-card__icon" aria-hidden="true">
                        <svg viewBox="0 0 24 24" focusable="false">
                            <path d="M12 3 19 6v5c0 4.5-2.7 8-7 10-4.3-2-7-5.5-7-10V6l7-3Z" />
                            <path d="M9.5 11.5a2.5 2.5 0 1 1 5 0v1.2" />
                            <path d="M9 12.7h6v4H9z" />
                        </svg>
                    </div>

                    <div className="login-card__heading">
                        <p>Acceso a tu cuenta</p>
                        <h1 id="login-title">Iniciar sesión</h1>
                        <span>Continúa con tus análisis de seguridad web.</span>
                    </div>

                    <form className="login-form" onSubmit={handleSubmit} aria-busy={isLoading}>
                        <div className="login-form__field">
                            <label htmlFor="email">Correo electrónico</label>
                            <input
                                id="email"
                                type="email"
                                name="email"
                                autoComplete="email"
                                placeholder="nombre@ejemplo.com"
                                value={email}
                                onChange={(event) => setEmail(event.target.value)}
                                required
                            />
                        </div>

                        <div className="login-form__field">
                            <label htmlFor="password">Contraseña</label>
                            <input
                                id="password"
                                type="password"
                                name="password"
                                autoComplete="current-password"
                                placeholder="Introduce tu contraseña"
                                value={password}
                                onChange={(event) => setPassword(event.target.value)}
                                required
                            />
                        </div>

                        {error && (
                            <div className="login-form__error" role="alert">
                                <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                                    <path d="M12 8v5" />
                                    <path d="M12 16.5v.1" />
                                    <path d="M10.3 4.2 3 17a2 2 0 0 0 1.7 3h14.6a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z" />
                                </svg>
                                <span>{error}</span>
                            </div>
                        )}

                        <button className="login-form__submit" type="submit" disabled={isLoading}>
                            {isLoading && <span className="login-form__spinner" aria-hidden="true" />}
                            {isLoading ? 'Iniciando sesión…' : 'Iniciar sesión'}
                        </button>
                    </form>

                    <p className="login-card__register">
                        ¿No tienes una cuenta? <Link to="/register">Crear una cuenta</Link>
                    </p>
                </section>
            </div>
        </main>
    )
}

export default LoginPage
