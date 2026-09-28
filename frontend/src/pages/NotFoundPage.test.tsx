import { screen } from '@testing-library/react'
import { expect, test } from 'vitest'
import { renderWithRouter } from '../test/renderWithRouter'
import NotFoundPage from './NotFoundPage'

test('explains an unknown route and links back to the public page', () => {
  renderWithRouter(<NotFoundPage />, { route: '/ruta-inexistente' })

  expect(screen.getByRole('heading', { name: 'Página no encontrada' })).toBeVisible()
  expect(screen.getByRole('link', { name: 'Volver a la página principal' }))
    .toHaveAttribute('href', '/')
})
