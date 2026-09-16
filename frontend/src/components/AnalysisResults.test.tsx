import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import { createAnalysisFixture } from '../test/fixtures/analysis'
import AnalysisResults from './AnalysisResults'

describe('AnalysisResults', () => {
  test('renders the analyzed target and security score', () => {
    const analysis = createAnalysisFixture()

    render(<AnalysisResults analysis={analysis} />)

    expect(screen.getByRole('heading', { name: 'Resultado del análisis' })).toBeVisible()
    expect(screen.getAllByText('http://example.com')).not.toHaveLength(0)
    expect(screen.getByText('example.com')).toBeVisible()
    expect(screen.getByLabelText('Calificación A')).toBeVisible()

    const meter = screen.getByRole('meter', { name: 'Puntuación de seguridad' })
    expect(meter).toHaveAttribute('aria-valuemin', '0')
    expect(meter).toHaveAttribute('aria-valuemax', '100')
    expect(meter).toHaveAttribute('aria-valuenow', '90')
  })

  test('renders DNS, HTTP and redirect information', () => {
    const analysis = createAnalysisFixture()
    const formattedContentLength = new Intl.NumberFormat('es-ES').format(
      analysis.http.contentLength!,
    )

    render(<AnalysisResults analysis={analysis} />)

    expect(screen.getByText('93.184.216.34')).toBeVisible()
    expect(screen.getByText('2001:db8::1')).toBeVisible()
    expect(screen.getByText('nginx')).toBeVisible()
    expect(screen.getByText('text/html; charset=UTF-8')).toBeVisible()
    expect(screen.getByText(`${formattedContentLength} bytes`)).toBeVisible()
    expect(screen.getByText('180 ms')).toBeVisible()
    expect(screen.getByText('2 pasos')).toBeVisible()
    expect(screen.getByText('Redirige a', { exact: false })).toHaveTextContent('https://example.com')
    expect(screen.getByText('Respuesta final sin nueva ubicación')).toBeVisible()
  })

  test('renders empty states for unavailable network information', () => {
    const analysis = createAnalysisFixture({
      dns: {
        ips: [],
      },
      http: {
        server: null,
        contentType: null,
        contentLength: null,
        redirectChain: [],
      },
    })

    render(<AnalysisResults analysis={analysis} />)

    expect(screen.getByText('No se encontraron direcciones IP.')).toBeVisible()
    const httpPanel = screen.getByRole('heading', { name: 'Información HTTP' })
      .closest('article')

    expect(httpPanel).not.toBeNull()
    expect(within(httpPanel!).getByText('No identificado')).toBeVisible()
    expect(within(httpPanel!).getAllByText('No informado')).toHaveLength(2)
    expect(screen.getByText('0 pasos')).toBeVisible()
    expect(screen.getByText('No se registraron pasos HTTP.')).toBeVisible()
  })

  test('renders TLS certificate data and its recommendation', () => {
    const analysis = createAnalysisFixture({
      ssl: {
        status: 'WARNING',
        daysUntilExpiration: 15,
        recommendation: 'Renew the SSL certificate before it expires.',
      },
    })

    render(<AnalysisResults analysis={analysis} />)

    expect(screen.getByRole('heading', { name: 'Seguridad SSL/TLS' })).toBeVisible()
    expect(screen.getByText("CN=Let's Encrypt Authority")).toBeVisible()
    expect(screen.getByText('CN=example.com')).toBeVisible()
    expect(screen.getByText('Advertencia')).toBeVisible()
    expect(screen.getByText('Renew the SSL certificate before it expires.')).toBeVisible()
  })

  test('shows an explicit empty state when TLS data is unavailable', () => {
    const analysis = createAnalysisFixture({ ssl: null })

    render(<AnalysisResults analysis={analysis} />)

    expect(screen.getByText('Información SSL/TLS no disponible')).toBeVisible()
    expect(screen.getByText('Este análisis no incluye datos de certificado.')).toBeVisible()
  })

  test('renders all security headers and their recommendations', () => {
    const analysis = createAnalysisFixture()

    render(<AnalysisResults analysis={analysis} />)

    const headersSection = screen.getByRole('heading', { name: 'Cabeceras de seguridad' })
      .closest('section')

    expect(headersSection).not.toBeNull()
    const section = within(headersSection!)
    expect(section.getByRole('heading', { name: 'Strict-Transport-Security' })).toBeVisible()
    expect(section.getByRole('heading', { name: 'Content-Security-Policy' })).toBeVisible()
    expect(section.getByRole('heading', { name: 'X-Frame-Options' })).toBeVisible()
    expect(section.getByRole('heading', { name: 'X-Content-Type-Options' })).toBeVisible()
    expect(section.getByRole('heading', { name: 'Referrer-Policy' })).toBeVisible()
    expect(section.getByRole('heading', { name: 'Permissions-Policy' })).toBeVisible()
    expect(section.getByText('Add a Permissions-Policy header.')).toBeVisible()
  })

  test('only renders actions when both callbacks are available', () => {
    const analysis = createAnalysisFixture()
    const { rerender } = render(<AnalysisResults analysis={analysis} />)

    expect(screen.queryByRole('contentinfo', { name: 'Acciones del análisis' })).not.toBeInTheDocument()

    rerender(
      <AnalysisResults
        analysis={analysis}
        onDiscard={vi.fn()}
        onSave={vi.fn()}
      />,
    )

    expect(screen.getByRole('contentinfo', { name: 'Acciones del análisis' })).toBeVisible()
  })

  test('calls the discard and save actions', async () => {
    const user = userEvent.setup()
    const onDiscard = vi.fn()
    const onSave = vi.fn().mockResolvedValue(undefined)

    render(
      <AnalysisResults
        analysis={createAnalysisFixture()}
        onDiscard={onDiscard}
        onSave={onSave}
      />,
    )

    await user.click(screen.getByRole('button', { name: 'Descartar análisis' }))
    await user.click(screen.getByRole('button', { name: 'Guardar análisis' }))

    expect(onDiscard).toHaveBeenCalledOnce()
    expect(onSave).toHaveBeenCalledOnce()
  })

  test('represents saving, error and saved states', () => {
    const analysis = createAnalysisFixture()
    const onDiscard = vi.fn()
    const onSave = vi.fn().mockResolvedValue(undefined)
    const { rerender } = render(
      <AnalysisResults
        analysis={analysis}
        onDiscard={onDiscard}
        onSave={onSave}
        isSaving
        saveError="Could not save the analysis"
      />,
    )

    expect(screen.getByRole('button', { name: 'Descartar análisis' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Guardando…' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Guardando…' })).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByRole('alert')).toHaveTextContent('Could not save the analysis')

    rerender(
      <AnalysisResults
        analysis={analysis}
        onDiscard={onDiscard}
        onSave={onSave}
        isSaved
      />,
    )

    expect(screen.getByRole('button', { name: 'Análisis guardado' })).toBeDisabled()
    expect(screen.getByText('Análisis guardado correctamente.')).toBeVisible()
  })
})
