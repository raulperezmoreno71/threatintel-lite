import { useState } from 'react'
import type { SubmitEvent } from 'react'
import { Link } from 'react-router-dom'
import './ChangePasswordPage.css'
import { changePassword } from '../api/AuthApi'

function ChangePasswordPage() {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newPasswordConfirmation, setNewPasswordConfirmation] = useState('')
  const [successfulMessage, setSuccessfulMessage] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const passwordsDoNotMatch = newPasswordConfirmation !== '' && newPassword !== newPasswordConfirmation

  async function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget

    if (isLoading) {
      return
    }

    setSuccessfulMessage('')
    setError('')

    if (newPassword !== newPasswordConfirmation) {
      setError('Las contraseñas nuevas no coinciden.')
      return
    }

    setIsLoading(true)

    try {
      await changePassword(currentPassword, newPassword)
      setSuccessfulMessage('Contraseña cambiada con éxito.')
      setCurrentPassword('')
      setNewPassword('')
      setNewPasswordConfirmation('')
      form.reset()
    } catch (error) {
      if (error instanceof Error) {
        setError(error.message)
      } else {
        setError('No se ha podido cambiar la contraseña. Inténtalo de nuevo.')
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <main className="change-password-page">
      <div className="change-password-page__content">
        <Link className="change-password-page__brand" to="/" aria-label="Ir a ThreatIntel Lite">
          <span className="change-password-page__brand-mark" aria-hidden="true">T</span>
          <span>ThreatIntel <strong>Lite</strong></span>
        </Link>

        <section className="change-password-card" aria-labelledby="change-password-title">
          <div className="change-password-card__icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" focusable="false">
              <rect x="5" y="10" width="14" height="10" rx="2" />
              <path d="M8 10V7a4 4 0 0 1 8 0v3" />
              <path d="M12 14v2" />
            </svg>
          </div>

          <div className="change-password-card__heading">
            <p>Seguridad de la cuenta</p>
            <h1 id="change-password-title">Cambiar contraseña</h1>
            <span>Confirma tu identidad antes de establecer una contraseña nueva.</span>
          </div>

          <form className="change-password-form" onSubmit={handleSubmit} aria-busy={isLoading}>
            <div className="change-password-form__field">
              <label htmlFor="current-password">Contraseña actual</label>
              <input
                id="current-password"
                name="currentPassword"
                type="password"
                autoComplete="current-password"
                placeholder="Introduce tu contraseña actual"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
                required
              />
            </div>

            <div className="change-password-form__field">
              <label htmlFor="new-password">Nueva contraseña</label>
              <input
                id="new-password"
                name="newPassword"
                type="password"
                autoComplete="new-password"
                placeholder="Introduce la nueva contraseña"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                required
              />
            </div>

            <div className="change-password-form__field">
              <label htmlFor="new-password-confirmation">Repite la nueva contraseña</label>
              <input
                id="new-password-confirmation"
                name="newPasswordConfirmation"
                type="password"
                autoComplete="new-password"
                placeholder="Confirma la nueva contraseña"
                value={newPasswordConfirmation}
                onChange={(event) => setNewPasswordConfirmation(event.target.value)}
                aria-invalid={passwordsDoNotMatch}
                aria-describedby={passwordsDoNotMatch ? 'change-password-match-error' : undefined}
                required
              />
              {passwordsDoNotMatch && (
                <span id="change-password-match-error" className="change-password-form__field-error">
                  Las contraseñas nuevas no coinciden.
                </span>
              )}
            </div>

            {successfulMessage && (
              <div className="change-password-form__message change-password-form__message--success" role="status" aria-live="polite">
                <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                  <path d="m7 12 3 3 7-7" />
                  <circle cx="12" cy="12" r="9" />
                </svg>
                <span>{successfulMessage}</span>
              </div>
            )}

            {error && (
              <div className="change-password-form__message change-password-form__message--error" role="alert">
                <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                  <path d="M12 8v5" />
                  <path d="M12 16.5v.1" />
                  <path d="M10.3 4.2 3 17a2 2 0 0 0 1.7 3h14.6a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0Z" />
                </svg>
                <span>{error}</span>
              </div>
            )}

            <button className="change-password-form__submit" type="submit" disabled={isLoading}>
              {isLoading && <span className="change-password-form__spinner" aria-hidden="true" />}
              {isLoading ? 'Actualizando contraseña…' : 'Actualizar contraseña'}
            </button>
          </form>
        </section>

        <Link className="change-password-page__back" to="/dashboard">
          <span aria-hidden="true">←</span>
          Volver al dashboard
        </Link>
      </div>
    </main>
  )
}

export default ChangePasswordPage
