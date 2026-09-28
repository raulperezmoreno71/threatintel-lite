import { StrictMode } from 'react'
import { createRoot, hydrateRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App.tsx'

const root = document.getElementById('root')!
const app = (
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>
)

if (window.location.pathname === '/' && root.hasChildNodes()) {
  hydrateRoot(root, app)
} else {
  // Evita mostrar la portada si un servidor SPA usa index.html como fallback.
  root.replaceChildren()
  createRoot(root).render(app)
}
