import { screen, waitFor } from '@testing-library/react'
import { Route, Routes, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { changePassword, getCurrentUser } from '../api/AuthApi'
import { renderWithRouter } from '../test/renderWithRouter'
import ChangePasswordPage from './ChangePasswordPage'

vi.mock('../api/AuthApi', () => ({
  changePassword: vi.fn(),
  getCurrentUser: vi.fn(),
}))

const changePasswordMock = vi.mocked(changePassword)
const getCurrentUserMock = vi.mocked(getCurrentUser)

function LoginDestination() {
  const location = useLocation()
  const state = location.state as { message?: string } | null

  return (
    <main>
      <h1>Login de prueba</h1>
      {state?.message && <p>{state.message}</p>}
    </main>
  )
}

function renderChangePasswordPage() {
  return renderWithRouter(
    <Routes>
      <Route path="/change-password" element={<ChangePasswordPage />} />
      <Route path="/login" element={<LoginDestination />} />
    </Routes>,
    { route: '/change-password' },
  )
}

async function fillPasswordForm(
  user: ReturnType<typeof renderChangePasswordPage>['user'],
  newPassword = 'NewStrongPassword123!',
  confirmation = newPassword,
) {
  await user.type(screen.getByLabelText('Contraseña actual'), 'CurrentPassword123!')
  await user.type(screen.getByLabelText('Nueva contraseña'), newPassword)
  await user.type(screen.getByLabelText('Repite la nueva contraseña'), confirmation)
}

describe('ChangePasswordPage', () => {
  beforeEach(() => {
    changePasswordMock.mockReset()
    getCurrentUserMock.mockReset()

    getCurrentUserMock.mockResolvedValue({
      id: 1,
      email: 'user@example.com',
      status: 'ACTIVE',
    })
    changePasswordMock.mockResolvedValue(undefined)
  })

  test('renders the form and checks the current session', async () => {
    renderChangePasswordPage()

    expect(screen.getByRole('heading', { name: 'Cambiar contraseña' })).toBeVisible()
    expect(screen.getByLabelText('Contraseña actual')).toBeVisible()
    expect(screen.getByLabelText('Nueva contraseña')).toBeVisible()
    expect(screen.getByLabelText('Repite la nueva contraseña')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Actualizar contraseña' })).toBeEnabled()
    await waitFor(() => expect(getCurrentUserMock).toHaveBeenCalledOnce())
  })

  test('redirects to login when the session has expired', async () => {
    getCurrentUserMock.mockRejectedValue(new Error('UNAUTHORIZED'))

    renderChangePasswordPage()

    expect(await screen.findByRole('heading', { name: 'Login de prueba' })).toBeVisible()
    expect(screen.getByText('Tu sesión ha caducado. Vuelve a iniciar sesión.')).toBeVisible()
  })

  test('shows unexpected errors while checking the current session', async () => {
    getCurrentUserMock.mockRejectedValue(new Error('Could not connect to the API'))

    renderChangePasswordPage()

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not connect to the API')
    expect(changePasswordMock).not.toHaveBeenCalled()
  })

  test('marks a different confirmation as invalid and prevents submission', async () => {
    const { user } = renderChangePasswordPage()

    await fillPasswordForm(user, 'NewStrongPassword123!', 'DifferentPassword123!')

    const confirmationInput = screen.getByLabelText('Repite la nueva contraseña')
    expect(confirmationInput).toHaveAttribute('aria-invalid', 'true')
    expect(confirmationInput).toHaveAccessibleDescription('Las contraseñas nuevas no coinciden.')

    await user.click(screen.getByRole('button', { name: 'Actualizar contraseña' }))

    expect(screen.getByRole('alert')).toHaveTextContent('Las contraseñas nuevas no coinciden.')
    expect(changePasswordMock).not.toHaveBeenCalled()
  })

  test('changes the password and clears the form', async () => {
    const { user } = renderChangePasswordPage()
    await fillPasswordForm(user)

    await user.click(screen.getByRole('button', { name: 'Actualizar contraseña' }))

    expect(changePasswordMock).toHaveBeenCalledOnce()
    expect(changePasswordMock).toHaveBeenCalledWith(
      'CurrentPassword123!',
      'NewStrongPassword123!',
    )
    expect(await screen.findByRole('status')).toHaveTextContent('Contraseña cambiada con éxito.')
    expect(screen.getByLabelText('Contraseña actual')).toHaveValue('')
    expect(screen.getByLabelText('Nueva contraseña')).toHaveValue('')
    expect(screen.getByLabelText('Repite la nueva contraseña')).toHaveValue('')
  })

  test('shows the API error when changing the password fails', async () => {
    changePasswordMock.mockRejectedValue(new Error('The current password is incorrect'))
    const { user } = renderChangePasswordPage()
    await fillPasswordForm(user)

    await user.click(screen.getByRole('button', { name: 'Actualizar contraseña' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The current password is incorrect',
    )
    expect(screen.getByLabelText('Contraseña actual')).toHaveValue('CurrentPassword123!')
  })

  test('shows a fallback message for an unexpected rejected value', async () => {
    changePasswordMock.mockRejectedValue('unexpected failure')
    const { user } = renderChangePasswordPage()
    await fillPasswordForm(user)

    await user.click(screen.getByRole('button', { name: 'Actualizar contraseña' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'No se ha podido cambiar la contraseña. Inténtalo de nuevo.',
    )
  })

  test('disables the form submission while the request is pending', async () => {
    let resolveChangePassword!: () => void
    changePasswordMock.mockReturnValue(new Promise((resolve) => {
      resolveChangePassword = resolve
    }))
    const { user } = renderChangePasswordPage()
    await fillPasswordForm(user)

    await user.click(screen.getByRole('button', { name: 'Actualizar contraseña' }))

    const pendingButton = screen.getByRole('button', { name: 'Actualizando contraseña…' })
    expect(pendingButton).toBeDisabled()
    expect(pendingButton.closest('form')).toHaveAttribute('aria-busy', 'true')
    expect(changePasswordMock).toHaveBeenCalledOnce()

    resolveChangePassword()

    expect(await screen.findByRole('status')).toHaveTextContent('Contraseña cambiada con éxito.')
  })
})
