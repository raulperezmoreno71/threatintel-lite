import { screen } from '@testing-library/react'
import { Route, Routes, useLocation } from 'react-router-dom'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { getSavedAnalysis } from '../api/AnalysisHistoryApi'
import { logout } from '../api/AuthApi'
import { createAnalysisHistoryFixture } from '../test/fixtures/analysis'
import { renderWithRouter } from '../test/renderWithRouter'
import AnalysisDetailPage from './AnalysisDetailPage'

vi.mock('../api/AnalysisHistoryApi', () => ({
  getSavedAnalysis: vi.fn(),
}))

vi.mock('../api/AuthApi', () => ({
  logout: vi.fn(),
}))

const getSavedAnalysisMock = vi.mocked(getSavedAnalysis)
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

function AnalysesDestination() {
  return <h1>Historial de prueba</h1>
}

function renderAnalysisDetailPage(analysisId = '42') {
  return renderWithRouter(
    <Routes>
      <Route path="/analyses/:analysisId" element={<AnalysisDetailPage />} />
      <Route path="/analyses" element={<AnalysesDestination />} />
      <Route path="/login" element={<LoginDestination />} />
    </Routes>,
    { route: `/analyses/${analysisId}` },
  )
}

describe('AnalysisDetailPage', () => {
  beforeEach(() => {
    getSavedAnalysisMock.mockReset()
    logoutMock.mockReset()

    getSavedAnalysisMock.mockResolvedValue(createAnalysisHistoryFixture({ id: 42 }))
    logoutMock.mockResolvedValue(undefined)
  })

  test('requests the numeric route identifier and shows a loading state', () => {
    getSavedAnalysisMock.mockReturnValue(new Promise(() => {}))

    renderAnalysisDetailPage('42')

    expect(screen.getByText('Cargando el análisis guardado…')).toBeVisible()
    expect(getSavedAnalysisMock).toHaveBeenCalledOnce()
    expect(getSavedAnalysisMock).toHaveBeenCalledWith(42)
  })

  test('renders the complete saved analysis returned by the API', async () => {
    const analysis = createAnalysisHistoryFixture({
      id: 42,
      url: 'https://openai.com',
      domain: 'openai.com',
      securityAssessment: {
        score: 82,
        grade: 'B',
      },
    })
    getSavedAnalysisMock.mockResolvedValue(analysis)

    renderAnalysisDetailPage()

    expect(await screen.findByRole('heading', { name: 'Resultado del análisis' })).toBeVisible()
    expect(screen.getByText(analysis.url)).toBeVisible()
    expect(screen.getByText(analysis.domain)).toBeVisible()
    expect(screen.getByLabelText('Calificación B')).toBeVisible()
    expect(screen.getByRole('meter', { name: 'Puntuación de seguridad' }))
      .toHaveAttribute('aria-valuenow', '82')
    expect(screen.queryByRole('button', { name: 'Guardar análisis' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Descartar análisis' })).not.toBeInTheDocument()
  })

  test.each(['not-a-number', '0', '-1', '1.5'])(
    'rejects the invalid analysis identifier "%s" without calling the API',
    (analysisId) => {
      renderAnalysisDetailPage(analysisId)

      expect(screen.getByRole('alert')).toHaveTextContent(
        'El identificador del análisis no es válido.',
      )
      expect(getSavedAnalysisMock).not.toHaveBeenCalled()
    },
  )

  test('shows an error when the analysis cannot be loaded', async () => {
    getSavedAnalysisMock.mockRejectedValue(new Error('Analysis not found'))

    renderAnalysisDetailPage()

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'No se ha podido cargar el análisis.Analysis not found',
    )
    expect(screen.queryByText('Cargando el análisis guardado…')).not.toBeInTheDocument()
  })

  test('redirects to login when the session has expired', async () => {
    getSavedAnalysisMock.mockRejectedValue(new Error('UNAUTHORIZED'))

    renderAnalysisDetailPage()

    expect(await screen.findByRole('heading', { name: 'Login de prueba' })).toBeVisible()
    expect(screen.getByText('Tu sesión ha caducado. Vuelve a iniciar sesión.')).toBeVisible()
  })

  test('returns to the saved analyses list', async () => {
    const { user } = renderAnalysisDetailPage()

    await user.click(screen.getByRole('link', { name: 'Volver a mis análisis' }))

    expect(screen.getByRole('heading', { name: 'Historial de prueba' })).toBeVisible()
  })

  test('logs out and redirects to login', async () => {
    const { user } = renderAnalysisDetailPage()

    await user.click(screen.getByRole('button', { name: 'Cerrar sesión' }))

    expect(logoutMock).toHaveBeenCalledOnce()
    expect(await screen.findByRole('heading', { name: 'Login de prueba' })).toBeVisible()
  })
})
