import { useState } from 'react'
import type { SubmitEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { register } from '../api/AuthApi'
import './RegisterPage.css'

function RegisterPage() {
    const navigate = useNavigate()
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [passwordConfirmation, setPasswordConfirmation] = useState('')
    const [error, setError] = useState('')
    const [isLoading, setIsLoading] = useState(false)
    const passwordsDoNotMatch = passwordConfirmation !== '' && password !== passwordConfirmation

    async function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
        event.preventDefault()

        if (isLoading) {
            return
        }

        setError('')

        if (password !== passwordConfirmation) {
            setError('Las contraseñas no coinciden.')
            return
        }

        setIsLoading(true)

        try {
            await register(email.trim(), password)
            navigate('/login', {
                state: {
                    message: 'Cuenta creada correctamente. Inicia sesión para continuar.',
                },
            })
        } catch (error) {
            if (error instanceof Error) {
                setError(error.message)
            } else {
                setError('No se ha podido crear la cuenta. Inténtalo de nuevo.')
            }
        } finally {
            setIsLoading(false)
        }
    }

    return (
        <main className="register-page">
            <div className="register-page__content">
                <Link className="register-page__brand" to="/" aria-label="Volver a ThreatIntel Lite">
                    <span className="register-page__brand-mark" aria-hidden="true">T</span>
                    <span>ThreatIntel <strong>Lite</strong></span>
                </Link>

                <section className="register-card" aria-labelledby="register-title">
                    <div className="register-card__icon" aria-hidden="true">
                        <svg viewBox="0 0 24 24" focusable="false">
                            <path d="M12 3 19 6v5c0 4.5-2.7 8-7 10-4.3-2-7-5.5-7-10V6l7-3Z" />
                            <path d="M12 8v8M8 12h8" />
                        </svg>
                    </div>

                    <div className="register-card__heading">
                        <p>Empieza a analizar</p>
                        <h1 id="register-title">Crear una cuenta</h1>
                        <span>Guarda y consulta tus análisis de seguridad web.</span>
                    </div>

                    <form className="register-form" onSubmit={handleSubmit} aria-busy={isLoading}>
                        <div className="register-form__field">
                            <label htmlFor="register-email">Correo electrónico</label>
                            <input
                                id="register-email"
                                type="email"
                                name="email"
                                autoComplete="email"
                                placeholder="nombre@ejemplo.com"
                                value={email}
                                onChange={(event) => setEmail(event.target.value)}
                                required
                            />
                        </div>

                        <div className="register-form__field">
                            <label htmlFor="register-password">Contraseña</label>
                            <input
                                id="register-password"
                                type="password"
                                name="password"
                                autoComplete="new-password"
                                placeholder="Crea una contraseña"
                                value={password}
                                onChange={(event) => setPassword(event.target.value)}
                                required
                            />
                        </div>

                        <div className="register-form__field">
                            <label htmlFor="register-password-confirmation">Repite la contraseña</label>
                            <input
                                id="register-password-confirmation"
                                type="password"
                                name="passwordConfirmation"
                                autoComplete="new-password"
                                placeholder="Repite la contraseña"
                                value={passwordConfirmation}
                                onChange={(event) => setPasswordConfirmation(event.target.value)}
                                aria-invalid={passwordsDoNotMatch}
                                aria-describedby={passwordsDoNotMatch ? 'register-password-match-error' : undefined}
                                required
                            />
                            {passwordsDoNotMatch && (
                                <span id="register-password-match-error" className="register-form__field-error">
                                    Las contraseñas no coinciden.
                                </span>
                            )}
                        </div>

                        {error && (
                            <div className="register-form__error" role="alert">
                                <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                                    <path d="M12 8v5" />
                                    <path d="M12 16.5v.1" />
                                    <path d="M10.3 4.2 3 17a2 2 0 0 0 1.7 3h14.6a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z" />
                                </svg>
                                <span>{error}</span>
                            </div>
                        )}

                        <button className="register-form__submit" type="submit" disabled={isLoading}>
                            {isLoading && <span className="register-form__spinner" aria-hidden="true" />}
                            {isLoading ? 'Creando cuenta…' : 'Crear cuenta'}
                        </button>
                    </form>

                    <p className="register-card__login">
                        ¿Ya tienes una cuenta? <Link to="/login">Iniciar sesión</Link>
                    </p>
                </section>

                <Link className="register-page__home-link" to="/">
                    <span aria-hidden="true">←</span>
                    Volver a la página principal
                </Link>
            </div>
        </main>
    )
}

export default RegisterPage
