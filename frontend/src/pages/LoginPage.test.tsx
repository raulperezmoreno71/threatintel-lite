import { screen, waitFor } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { getCurrentUser, login } from '../api/AuthApi'
import { renderWithRouter, type RenderWithRouterOptions } from '../test/renderWithRouter'
import type { LoginResponse } from '../types'
import LoginPage from './LoginPage'

vi.mock('../api/AuthApi', () => ({
  getCurrentUser: vi.fn(),
  login: vi.fn(),
}))

const getCurrentUserMock = vi.mocked(getCurrentUser)
const loginMock = vi.mocked(login)

function DashboardDestination() {
  return <h1>Dashboard de prueba</h1>
}

function renderLoginPage(route: RenderWithRouterOptions['route'] = '/login') {
  return renderWithRouter(
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/dashboard" element={<DashboardDestination />} />
    </Routes>,
    { route },
  )
}

describe('LoginPage', () => {
  beforeEach(() => {
    getCurrentUserMock.mockReset()
    loginMock.mockReset()
    getCurrentUserMock.mockRejectedValue(new Error('UNAUTHORIZED'))
  })

  test('renders the login form and checks the current session', async () => {
    renderLoginPage()

    expect(screen.getByRole('heading', { name: 'Iniciar sesión' })).toBeVisible()
    expect(screen.getByLabelText('Correo electrónico')).toBeVisible()
    expect(screen.getByLabelText('Contraseña')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Iniciar sesión' })).toBeEnabled()
    await waitFor(() => expect(getCurrentUserMock).toHaveBeenCalledOnce())
  })

  test('redirects to the dashboard when a valid session already exists', async () => {
    getCurrentUserMock.mockResolvedValue({
      id: 1,
      email: 'user@example.com',
      status: 'ACTIVE',
    })

    renderLoginPage()

    expect(await screen.findByRole('heading', { name: 'Dashboard de prueba' })).toBeVisible()
    expect(loginMock).not.toHaveBeenCalled()
  })

  test('logs in with trimmed email and redirects to the dashboard', async () => {
    loginMock.mockResolvedValue({
      id: 1,
      email: 'user@example.com',
      status: 'ACTIVE',
      message: 'Login successful',
    })
    const { user } = renderLoginPage()
    await waitFor(() => expect(getCurrentUserMock).toHaveBeenCalledOnce())

    await user.type(screen.getByLabelText('Correo electrónico'), '  user@example.com  ')
    await user.type(screen.getByLabelText('Contraseña'), 'StrongPassword123!')
    await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))

    expect(loginMock).toHaveBeenCalledOnce()
    expect(loginMock).toHaveBeenCalledWith('user@example.com', 'StrongPassword123!')
    expect(await screen.findByRole('heading', { name: 'Dashboard de prueba' })).toBeVisible()
  })

  test('shows the authentication error when login fails', async () => {
    loginMock.mockRejectedValue(new Error('Invalid email or password'))
    const { user } = renderLoginPage()

    await user.type(screen.getByLabelText('Correo electrónico'), 'user@example.com')
    await user.type(screen.getByLabelText('Contraseña'), 'WrongPassword')
    await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password')
    expect(screen.getByRole('heading', { name: 'Iniciar sesión' })).toBeVisible()
  })

  test('shows unexpected errors while checking the current session', async () => {
    getCurrentUserMock.mockRejectedValue(new Error('Could not connect to the API'))

    renderLoginPage()

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not connect to the API')
    expect(loginMock).not.toHaveBeenCalled()
  })

  test('shows a message received through navigation state', async () => {
    renderLoginPage({
      pathname: '/login',
      state: {
        message: 'Tu sesión ha caducado. Vuelve a iniciar sesión.',
      },
    })

    expect(screen.getByText('Tu sesión ha caducado. Vuelve a iniciar sesión.')).toBeVisible()
    await waitFor(() => expect(getCurrentUserMock).toHaveBeenCalledOnce())
  })

  test('disables the submit button while login is pending', async () => {
    let resolveLogin!: (response: LoginResponse) => void
    loginMock.mockReturnValue(new Promise((resolve) => {
      resolveLogin = resolve
    }))
    const { user } = renderLoginPage()

    await user.type(screen.getByLabelText('Correo electrónico'), 'user@example.com')
    await user.type(screen.getByLabelText('Contraseña'), 'StrongPassword123!')
    await user.click(screen.getByRole('button', { name: 'Iniciar sesión' }))

    expect(await screen.findByRole('button', { name: 'Iniciando sesión…' })).toBeDisabled()
    expect(loginMock).toHaveBeenCalledOnce()

    resolveLogin({
      id: 1,
      email: 'user@example.com',
      status: 'ACTIVE',
      message: 'Login successful',
    })

    expect(await screen.findByRole('heading', { name: 'Dashboard de prueba' })).toBeVisible()
  })
})
