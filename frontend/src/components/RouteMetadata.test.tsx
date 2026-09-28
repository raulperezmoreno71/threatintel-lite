import { cleanup } from '@testing-library/react'
import { afterEach, describe, expect, test } from 'vitest'
import { renderWithRouter } from '../test/renderWithRouter'
import RouteMetadata from './RouteMetadata'

afterEach(() => {
  cleanup()
  document.querySelector('meta[name="robots"]')?.remove()
  document.querySelector('link[rel="canonical"]')?.remove()
})

describe('RouteMetadata', () => {
  test('keeps only the landing page indexable and canonical', () => {
    renderWithRouter(<RouteMetadata />)

    expect(document.title).toBe('ThreatIntel Lite | Análisis de seguridad web')
    expect(document.querySelector('meta[name="robots"]')).toBeNull()
    expect(document.querySelector('link[rel="canonical"]')).toHaveAttribute(
      'href',
      'https://threatintel.raulperezmoreno.dev/',
    )
  })

  test.each(['/login', '/login/', '/register', '/dashboard', '/analyses', '/analyses/42', '/change-password', '/missing'])(
    'marks %s as noindex without a landing canonical',
    (route) => {
      renderWithRouter(<RouteMetadata />, { route })

      expect(document.querySelector('meta[name="robots"]')).toHaveAttribute('content', 'noindex')
      expect(document.querySelector('link[rel="canonical"]')).toBeNull()
    },
  )
})
