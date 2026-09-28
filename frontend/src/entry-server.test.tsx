import { act, StrictMode } from 'react'
import { hydrateRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { describe, expect, test } from 'vitest'
import App from './App'
import { renderLandingPage } from './entry-server'

describe('pre-rendered landing page', () => {
  test('contains useful content and crawlable links before client JavaScript runs', () => {
    const html = renderLandingPage()

    expect(html).toContain('<h1 id="hero-title">')
    expect(html).toContain('Analiza la seguridad de una URL')
    expect(html).toContain('Qué significan los resultados')
    expect(html).toContain('href="/register"')
  })

  test('hydrates the pre-rendered page without replacing its content', async () => {
    window.history.replaceState({}, '', '/')
    const container = document.createElement('div')
    container.id = 'root'
    container.innerHTML = renderLandingPage()
    document.body.append(container)
    const originalContent = container.innerHTML

    let root: ReturnType<typeof hydrateRoot> | undefined
    try {
      await act(async () => {
        root = hydrateRoot(
          container,
          <StrictMode>
            <BrowserRouter>
              <App />
            </BrowserRouter>
          </StrictMode>,
        )
      })

      expect(container.innerHTML).toBe(originalContent)
    } finally {
      await act(async () => root?.unmount())
      container.remove()
    }
  })
})
