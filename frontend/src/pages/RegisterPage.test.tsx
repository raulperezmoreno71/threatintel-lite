import { screen } from '@testing-library/react'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { Route, Routes, useLocation } from 'react-router-dom'
import { register } from '../api/AuthApi'
import { renderWithRouter } from '../test/renderWithRouter'
import type { RegisterResponse } from '../types'
import RegisterPage from './RegisterPage'

vi.mock('../api/AuthApi', () => ({
  register: vi.fn(),
}))

const registerMock = vi.mocked(register)

function LoginDestination() {
  const location = useLocation()
  const state = location.state as { message?: string } | null

  return (
    <main>
      <h1>Destino de inicio de sesión</h1>
      {state?.message && <p>{state.message}</p>}
    </main>
  )
}

function renderRegisterPage() {
  return renderWithRouter(
    <Routes>
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/login" element={<LoginDestination />} />
    </Routes>,
    { route: '/register' },
  )
}

describe('RegisterPage', () => {
  beforeEach(() => {
    registerMock.mockReset()
  })

  test('renders the registration form', () => {
    renderRegisterPage()

    expect(screen.getByRole('heading', { name: 'Crear una cuenta' })).toBeVisible()
    expect(screen.getByLabelText('Correo electrónico')).toBeVisible()
    expect(screen.getByLabelText('Contraseña')).toBeVisible()
    expect(screen.getByLabelText('Repite la contraseña')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Crear cuenta' })).toBeEnabled()
  })

  test('does not register when password confirmation does not match', async () => {
    const { user } = renderRegisterPage()

    await user.type(screen.getByLabelText('Correo electrónico'), 'user@example.com')
    await user.type(screen.getByLabelText('Contraseña'), 'StrongPassword123!')
    await user.type(screen.getByLabelText('Repite la contraseña'), 'DifferentPassword123!')
    await user.click(screen.getByRole('button', { name: 'Crear cuenta' }))

    expect(screen.getByLabelText('Repite la contraseña'))
      .toHaveAccessibleDescription('Las contraseñas no coinciden.')
    expect(screen.getByLabelText('Repite la contraseña')).toBeInvalid()
    expect(screen.getByRole('alert')).toHaveTextContent('Las contraseñas no coinciden.')
    expect(registerMock).not.toHaveBeenCalled()
  })

  test('registers the user and redirects to login', async () => {
    registerMock.mockResolvedValue({
      email: 'user@example.com',
      status: 'ACTIVE',
    })
    const { user } = renderRegisterPage()

    await user.type(screen.getByLabelText('Correo electrónico'), '  user@example.com  ')
    await user.type(screen.getByLabelText('Contraseña'), 'StrongPassword123!')
    await user.type(screen.getByLabelText('Repite la contraseña'), 'StrongPassword123!')
    await user.click(screen.getByRole('button', { name: 'Crear cuenta' }))

    expect(registerMock).toHaveBeenCalledOnce()
    expect(registerMock).toHaveBeenCalledWith('user@example.com', 'StrongPassword123!')
    expect(await screen.findByRole('heading', { name: 'Destino de inicio de sesión' })).toBeVisible()
    expect(screen.getByText('Cuenta creada correctamente. Inicia sesión para continuar.')).toBeVisible()
  })

  test('shows the API error when registration fails', async () => {
    registerMock.mockRejectedValue(new Error('Email is already registered'))
    const { user } = renderRegisterPage()

    await user.type(screen.getByLabelText('Correo electrónico'), 'user@example.com')
    await user.type(screen.getByLabelText('Contraseña'), 'StrongPassword123!')
    await user.type(screen.getByLabelText('Repite la contraseña'), 'StrongPassword123!')
    await user.click(screen.getByRole('button', { name: 'Crear cuenta' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Email is already registered')
    expect(screen.getByRole('heading', { name: 'Crear una cuenta' })).toBeVisible()
  })

  test('disables the submit button while registration is pending', async () => {
    let resolveRegistration!: (response: RegisterResponse) => void
    registerMock.mockReturnValue(new Promise((resolve) => {
      resolveRegistration = resolve
    }))
    const { user } = renderRegisterPage()

    await user.type(screen.getByLabelText('Correo electrónico'), 'user@example.com')
    await user.type(screen.getByLabelText('Contraseña'), 'StrongPassword123!')
    await user.type(screen.getByLabelText('Repite la contraseña'), 'StrongPassword123!')
    await user.click(screen.getByRole('button', { name: 'Crear cuenta' }))

    expect(await screen.findByRole('button', { name: 'Creando cuenta…' })).toBeDisabled()
    expect(registerMock).toHaveBeenCalledOnce()

    resolveRegistration({
      email: 'user@example.com',
      status: 'ACTIVE',
    })

    expect(await screen.findByRole('heading', { name: 'Destino de inicio de sesión' })).toBeVisible()
  })
})
