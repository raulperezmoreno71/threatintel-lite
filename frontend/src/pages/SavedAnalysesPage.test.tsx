import { screen } from '@testing-library/react'
import { Route, Routes, useLocation, useParams } from 'react-router-dom'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { getSavedAnalyses } from '../api/AnalysisHistoryApi'
import { logout } from '../api/AuthApi'
import { createAnalysisHistoryFixture } from '../test/fixtures/analysis'
import { renderWithRouter } from '../test/renderWithRouter'
import SavedAnalysesPage from './SavedAnalysesPage'

vi.mock('../api/AnalysisHistoryApi', () => ({
  getSavedAnalyses: vi.fn(),
}))

vi.mock('../api/AuthApi', () => ({
  logout: vi.fn(),
}))

const getSavedAnalysesMock = vi.mocked(getSavedAnalyses)
const logoutMock = vi.mocked(logout)

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

function AnalysisDetailDestination() {
  const { analysisId } = useParams()

  return <h1>Detalle del análisis {analysisId}</h1>
}

function renderSavedAnalysesPage() {
  return renderWithRouter(
    <Routes>
      <Route path="/analyses" element={<SavedAnalysesPage />} />
      <Route path="/analyses/:analysisId" element={<AnalysisDetailDestination />} />
      <Route path="/login" element={<LoginDestination />} />
    </Routes>,
    { route: '/analyses' },
  )
}

describe('SavedAnalysesPage', () => {
  beforeEach(() => {
    getSavedAnalysesMock.mockReset()
    logoutMock.mockReset()

    getSavedAnalysesMock.mockResolvedValue([])
    logoutMock.mockResolvedValue(undefined)
  })

  test('shows a loading state while saved analyses are being requested', () => {
    getSavedAnalysesMock.mockReturnValue(new Promise(() => {}))

    renderSavedAnalysesPage()

    expect(screen.getByText('Cargando tus análisis guardados…')).toBeVisible()
    expect(screen.getByText('Cargando…')).toBeVisible()
    expect(getSavedAnalysesMock).toHaveBeenCalledOnce()
  })

  test('shows the empty state when the user has no saved analyses', async () => {
    renderSavedAnalysesPage()

    expect(await screen.findByRole('heading', { name: 'Aún no tienes análisis guardados' }))
      .toBeVisible()
    expect(screen.getByText('0 análisis')).toBeVisible()
    expect(screen.getByRole('link', { name: 'Ir al dashboard' }))
      .toHaveAttribute('href', '/dashboard')
  })

  test('renders saved analyses and their security summary', async () => {
    const firstAnalysis = createAnalysisHistoryFixture()
    const secondAnalysis = createAnalysisHistoryFixture({
      id: 2,
      url: 'https://openai.com',
      domain: 'openai.com',
      createdAt: '2026-09-15 08:15:00',
      http: {
        statusCode: 204,
        totalResponseTimeMs: 95,
      },
      securityAssessment: {
        score: 75,
        grade: 'B',
        goodHeaders: 4,
        warningHeaders: 1,
        missingHeaders: 1,
      },
    })
    getSavedAnalysesMock.mockResolvedValue([firstAnalysis, secondAnalysis])

    renderSavedAnalysesPage()

    expect(await screen.findByRole('heading', { name: 'example.com' })).toBeVisible()
    expect(screen.getByRole('heading', { name: 'openai.com' })).toBeVisible()
    expect(screen.getByText('2 análisis')).toBeVisible()
    expect(screen.getByLabelText('Puntuación 90 de 100')).toHaveTextContent('Grado A')
    expect(screen.getByLabelText('Puntuación 75 de 100')).toHaveTextContent('Grado B')
    expect(screen.getByText('204')).toBeVisible()
    expect(screen.getByText('95 ms')).toBeVisible()

    const detailLinks = screen.getAllByRole('link', { name: 'Ver análisis completo' })
    expect(detailLinks[0]).toHaveAttribute('href', '/analyses/1')
    expect(detailLinks[1]).toHaveAttribute('href', '/analyses/2')
  })

  test('shows a fallback when an analysis date is invalid', async () => {
    getSavedAnalysesMock.mockResolvedValue([
      createAnalysisHistoryFixture({ createdAt: 'invalid-date' }),
    ])

    renderSavedAnalysesPage()

    expect(await screen.findByText('Fecha no disponible')).toBeVisible()
  })

  test('navigates to the selected analysis detail', async () => {
    getSavedAnalysesMock.mockResolvedValue([
      createAnalysisHistoryFixture({ id: 42 }),
    ])
    const { user } = renderSavedAnalysesPage()

    await user.click(await screen.findByRole('link', { name: 'Ver análisis completo' }))

    expect(screen.getByRole('heading', { name: 'Detalle del análisis 42' })).toBeVisible()
  })

  test('shows an error when saved analyses cannot be loaded', async () => {
    getSavedAnalysesMock.mockRejectedValue(new Error('Could not load saved analyses'))

    renderSavedAnalysesPage()

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'No se han podido cargar los análisis.Could not load saved analyses',
    )
    expect(screen.queryByText('Aún no tienes análisis guardados')).not.toBeInTheDocument()
  })

  test('redirects to login when the session has expired', async () => {
    getSavedAnalysesMock.mockRejectedValue(new Error('UNAUTHORIZED'))

    renderSavedAnalysesPage()

    expect(await screen.findByRole('heading', { name: 'Login de prueba' })).toBeVisible()
    expect(screen.getByText('Tu sesión ha caducado. Vuelve a iniciar sesión.')).toBeVisible()
  })

  test('logs out and redirects to login', async () => {
    const { user } = renderSavedAnalysesPage()

    await user.click(screen.getByRole('button', { name: 'Cerrar sesión' }))

    expect(logoutMock).toHaveBeenCalledOnce()
    expect(await screen.findByRole('heading', { name: 'Login de prueba' })).toBeVisible()
  })
})
