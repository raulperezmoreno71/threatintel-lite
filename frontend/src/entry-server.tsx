import { renderToString } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import LandingPage from './pages/LandingPage'

export function renderLandingPage() {
  return renderToString(
    <MemoryRouter initialEntries={['/']}>
      <LandingPage />
    </MemoryRouter>,
  )
}
