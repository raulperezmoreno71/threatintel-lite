import { screen, waitFor } from '@testing-library/react'
import { Route, Routes, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { getCurrentUser, logout } from '../api/AuthApi'
import { analyzeUrl } from '../api/AnalyzeApi'
import { PendingAnalysisUnavailableError, saveAnalysis } from '../api/AnalysisHistoryApi'
import { createAnalysisFixture } from '../test/fixtures/analysis'
import { renderWithRouter } from '../test/renderWithRouter'
import type { AnalyzeResponse } from '../types'
import DashboardPage from './DashboardPage'

vi.mock('../api/AuthApi', () => ({
  getCurrentUser: vi.fn(),
  logout: vi.fn(),
}))

vi.mock('../api/AnalyzeApi', () => ({
  analyzeUrl: vi.fn(),
}))

vi.mock('../api/AnalysisHistoryApi', () => ({
  saveAnalysis: vi.fn(),
  PendingAnalysisUnavailableError: class extends Error {},
}))

const getCurrentUserMock = vi.mocked(getCurrentUser)
const logoutMock = vi.mocked(logout)
const analyzeUrlMock = vi.mocked(analyzeUrl)
const saveAnalysisMock = vi.mocked(saveAnalysis)

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

function renderDashboardPage() {
  return renderWithRouter(
    <Routes>
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/login" element={<LoginDestination />} />
    </Routes>,
    { route: '/dashboard' },
  )
}

async function waitForAuthenticatedUser() {
  const userReferences = await screen.findAllByText('user@example.com')
  expect(userReferences.length).toBeGreaterThan(0)
}

async function runSuccessfulAnalysis(
  user: ReturnType<typeof renderDashboardPage>['user'],
  analysis: AnalyzeResponse = createAnalysisFixture(),
) {
  analyzeUrlMock.mockResolvedValue(analysis)

  await user.type(screen.getByLabelText('URL que quieres analizar'), analysis.url)
  await user.click(screen.getByRole('button', { name: 'Analizar URL' }))

  expect(analyzeUrlMock).toHaveBeenCalledOnce()
  expect(analyzeUrlMock).toHaveBeenCalledWith(analysis.url)
  expect(await screen.findByRole('heading', { name: 'Resultado del análisis' })).toBeVisible()

  return analysis
}

describe('DashboardPage', () => {
  beforeEach(() => {
    getCurrentUserMock.mockReset()
    logoutMock.mockReset()
    analyzeUrlMock.mockReset()
    saveAnalysisMock.mockReset()

    getCurrentUserMock.mockResolvedValue({
      id: 1,
      email: 'user@example.com',
      status: 'ACTIVE',
    })
    logoutMock.mockResolvedValue(undefined)
  })

  test('loads and displays the authenticated user', async () => {
    renderDashboardPage()

    expect(screen.getByRole('heading', { name: 'Bienvenido' })).toBeVisible()
    await waitForAuthenticatedUser()
    expect(screen.getByText('Activa')).toBeVisible()
    expect(getCurrentUserMock).toHaveBeenCalledOnce()
  })

  test('redirects to login when the session has expired', async () => {
    getCurrentUserMock.mockRejectedValue(new Error('UNAUTHORIZED'))

    renderDashboardPage()

    expect(await screen.findByRole('heading', { name: 'Login de prueba' })).toBeVisible()
    expect(screen.getByText('Tu sesión ha caducado. Vuelve a iniciar sesión.')).toBeVisible()
  })

  test('shows unexpected errors while loading the current user', async () => {
    getCurrentUserMock.mockRejectedValue(new Error('Could not connect to the API'))

    renderDashboardPage()

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not connect to the API')
    expect(screen.getByText('No disponible')).toBeVisible()
  })

  test('analyzes a URL and displays its result', async () => {
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()

    const analysis = await runSuccessfulAnalysis(user)

    expect(screen.getByLabelText('Calificación A')).toBeVisible()
    expect(screen.getByRole('meter', { name: 'Puntuación de seguridad' }))
      .toHaveAttribute('aria-valuenow', String(analysis.securityAssessment.score))
  })

  test('disables analysis submission while the request is pending', async () => {
    let resolveAnalysis!: (analysis: AnalyzeResponse) => void
    analyzeUrlMock.mockReturnValue(new Promise((resolve) => {
      resolveAnalysis = resolve
    }))
    const analysis = createAnalysisFixture()
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()

    await user.type(screen.getByLabelText('URL que quieres analizar'), analysis.url)
    await user.click(screen.getByRole('button', { name: 'Analizar URL' }))

    expect(await screen.findByRole('button', { name: 'Analizando…' })).toBeDisabled()

    resolveAnalysis(analysis)

    expect(await screen.findByRole('heading', { name: 'Resultado del análisis' })).toBeVisible()
  })

  test('shows an analysis error without removing the dashboard', async () => {
    analyzeUrlMock.mockRejectedValue(new Error('URL protocol must be HTTP or HTTPS'))
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()

    await user.type(screen.getByLabelText('URL que quieres analizar'), 'ftp://example.com')
    await user.click(screen.getByRole('button', { name: 'Analizar URL' }))

    expect(await screen.findByRole('alert'))
      .toHaveTextContent('URL protocol must be HTTP or HTTPS')
    expect(screen.getByRole('heading', { name: 'Bienvenido' })).toBeVisible()
  })

  test('redirects to login when analysis reports an expired session', async () => {
    analyzeUrlMock.mockRejectedValue(new Error('UNAUTHORIZED'))
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()

    await user.type(screen.getByLabelText('URL que quieres analizar'), 'https://example.com')
    await user.click(screen.getByRole('button', { name: 'Analizar URL' }))

    expect(await screen.findByRole('heading', { name: 'Login de prueba' })).toBeVisible()
    expect(screen.getByText('Tu sesión ha caducado. Vuelve a iniciar sesión.')).toBeVisible()
  })

  test('saves the completed analysis and displays confirmation', async () => {
    let resolveSave!: () => void
    saveAnalysisMock.mockReturnValue(new Promise((resolve) => {
      resolveSave = resolve
    }))
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()
    const analysis = await runSuccessfulAnalysis(user)

    await user.click(screen.getByRole('button', { name: 'Guardar análisis' }))

    expect(saveAnalysisMock).toHaveBeenCalledOnce()
    expect(saveAnalysisMock).toHaveBeenCalledWith(analysis.pendingAnalysisId)
    expect(screen.getByRole('button', { name: 'Guardando…' })).toBeDisabled()

    resolveSave()

    expect(await screen.findByText('Análisis guardado correctamente.')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Análisis guardado' })).toBeDisabled()
  })

  test('prevents another analysis while saving the current result', async () => {
    let resolveSave!: () => void
    saveAnalysisMock.mockReturnValue(new Promise((resolve) => { resolveSave = resolve }))
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()
    await runSuccessfulAnalysis(user)
    await user.click(screen.getByRole('button', { name: 'Guardar análisis' }))
    expect(screen.getByRole('button', { name: 'Analizar URL' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Analizar URL' }))
    expect(analyzeUrlMock).toHaveBeenCalledOnce()
    resolveSave()
    expect(await screen.findByText('Análisis guardado correctamente.')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Analizar URL' })).toBeEnabled()
  })

  test('shows an error when saving the analysis fails', async () => {
    saveAnalysisMock.mockRejectedValue(new Error('Could not save the analysis'))
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()
    await runSuccessfulAnalysis(user)

    await user.click(screen.getByRole('button', { name: 'Guardar análisis' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not save the analysis')
    expect(screen.getByRole('button', { name: 'Guardar análisis' })).toBeEnabled()
  })

  test('keeps the report visible after expiration and allows a new analysis', async () => {
    saveAnalysisMock.mockRejectedValueOnce(new PendingAnalysisUnavailableError('El resultado ha caducado. Vuelve a analizar la URL.'))
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()
    await runSuccessfulAnalysis(user)
    await user.click(screen.getByRole('button', { name: 'Guardar análisis' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('El resultado ha caducado')
    expect(screen.getByRole('button', { name: 'Guardar análisis' })).toBeDisabled()
    expect(screen.getByRole('heading', { name: 'Resultado del análisis' })).toBeVisible()
    analyzeUrlMock.mockResolvedValue(createAnalysisFixture({ pendingAnalysisId: 'new-pending-id' }))
    await user.click(screen.getByRole('button', { name: 'Analizar URL' }))
    expect(await screen.findByRole('button', { name: 'Guardar análisis' })).toBeEnabled()
    saveAnalysisMock.mockResolvedValueOnce(undefined)
    await user.click(screen.getByRole('button', { name: 'Guardar análisis' }))
    expect(saveAnalysisMock).toHaveBeenLastCalledWith('new-pending-id')
  })

  test('allows retry with the same identifier after a temporary save failure', async () => {
    saveAnalysisMock.mockRejectedValueOnce(new Error('Temporary error')).mockResolvedValueOnce(undefined)
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()
    const analysis = await runSuccessfulAnalysis(user)
    await user.click(screen.getByRole('button', { name: 'Guardar análisis' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Temporary error')
    await user.click(screen.getByRole('button', { name: 'Guardar análisis' }))
    expect(await screen.findByText('Análisis guardado correctamente.')).toBeVisible()
    expect(saveAnalysisMock).toHaveBeenNthCalledWith(1, analysis.pendingAnalysisId)
    expect(saveAnalysisMock).toHaveBeenNthCalledWith(2, analysis.pendingAnalysisId)
  })

  test('asks for confirmation before discarding an analysis', async () => {
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()
    await runSuccessfulAnalysis(user)

    await user.click(screen.getByRole('button', { name: 'Descartar análisis' }))

    const dialog = screen.getByRole('dialog', { name: '¿Descartar este análisis?' })
    expect(dialog).toBeVisible()

    await user.click(screen.getByRole('button', { name: 'No, conservarlo' }))
    await waitFor(() => expect(dialog).not.toHaveAttribute('open'))
    expect(screen.getByRole('heading', { name: 'Resultado del análisis' })).toBeVisible()

    await user.click(screen.getByRole('button', { name: 'Descartar análisis' }))
    await user.click(screen.getByRole('button', { name: 'Sí, descartar' }))

    expect(screen.queryByRole('heading', { name: 'Resultado del análisis' })).not.toBeInTheDocument()
  })

  test('logs out and redirects to login', async () => {
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()

    await user.click(screen.getByRole('button', { name: 'Cerrar sesión' }))

    expect(logoutMock).toHaveBeenCalledOnce()
    expect(await screen.findByRole('heading', { name: 'Login de prueba' })).toBeVisible()
  })

  test('shows an error when logout fails', async () => {
    logoutMock.mockRejectedValue(new Error('No se ha podido cerrar sesión'))
    const { user } = renderDashboardPage()
    await waitForAuthenticatedUser()

    await user.click(screen.getByRole('button', { name: 'Cerrar sesión' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('No se ha podido cerrar sesión')
    expect(screen.getByRole('heading', { name: 'Bienvenido' })).toBeVisible()
  })
})
