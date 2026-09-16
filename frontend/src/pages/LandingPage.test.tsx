import { screen, within } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { describe, expect, test } from 'vitest'
import { renderWithRouter } from '../test/renderWithRouter'
import LandingPage from './LandingPage'

function RegisterDestination() {
  return <h1>Registro de prueba</h1>
}

function renderLandingPage() {
  return renderWithRouter(
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/register" element={<RegisterDestination />} />
    </Routes>,
  )
}

describe('LandingPage', () => {
  test('renders the main product information and page sections', () => {
    renderLandingPage()

    expect(screen.getByRole('heading', {
      level: 1,
      name: 'Analiza la seguridad de una URL en un solo informe',
    })).toBeVisible()
    expect(screen.getByRole('heading', { name: 'Qué analiza ThreatIntel Lite' })).toBeVisible()
    expect(screen.getByRole('heading', {
      name: 'Cómo funciona el análisis de seguridad',
    })).toBeVisible()
    expect(screen.getByRole('heading', { name: 'Comprueba la seguridad de una URL' }))
      .toBeVisible()
    expect(screen.getByText('© 2026 ThreatIntel Lite')).toBeVisible()
  })

  test('lists the analysis areas and the three process steps', () => {
    renderLandingPage()

    const analysisAreas = screen.getByRole('list', {
      name: 'Áreas incluidas en el análisis',
    })
    for (const area of ['DNS', 'HTTP', 'Redirecciones', 'SSL/TLS', 'Cabeceras']) {
      expect(within(analysisAreas).getByText(area)).toBeVisible()
    }

    expect(screen.getByRole('heading', { name: 'Introduce la URL' })).toBeVisible()
    expect(screen.getByRole('heading', { name: 'Ejecuta el análisis' })).toBeVisible()
    expect(screen.getByRole('heading', { name: 'Revisa el informe' })).toBeVisible()
  })

  test('provides the expected authentication and section links', () => {
    renderLandingPage()

    expect(screen.getByRole('link', { name: 'Iniciar sesión' })).toHaveAttribute('href', '/login')
    expect(screen.getByRole('link', { name: 'Registrarse' })).toHaveAttribute('href', '/register')
    expect(screen.getByRole('link', { name: 'Ya tengo una cuenta' })).toHaveAttribute(
      'href',
      '/login',
    )
    expect(screen.getByRole('link', { name: 'Ver qué analizamos' })).toHaveAttribute(
      'href',
      '#analysis-features',
    )

    const primaryActions = screen.getAllByRole('link', { name: 'Empieza a analizar' })
    expect(primaryActions).toHaveLength(2)
    for (const action of primaryActions) {
      expect(action).toHaveAttribute('href', '/register')
    }
  })

  test('navigates to registration from the primary call to action', async () => {
    const { user } = renderLandingPage()

    await user.click(screen.getAllByRole('link', { name: 'Empieza a analizar' })[0])

    expect(screen.getByRole('heading', { name: 'Registro de prueba' })).toBeVisible()
  })

  test('links to the project and author profiles', () => {
    renderLandingPage()

    expect(screen.getByRole('link', { name: 'Proyecto en GitHub' })).toHaveAttribute(
      'href',
      'https://github.com/raulperezmoreno71/threatintel-lite',
    )
    expect(screen.getByRole('link', { name: 'Autor en LinkedIn' })).toHaveAttribute(
      'href',
      'https://www.linkedin.com/in/raul-perez-moreno/',
    )
  })
})
