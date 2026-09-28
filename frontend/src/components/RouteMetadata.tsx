import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'

const SITE_URL = 'https://threatintel.raulperezmoreno.dev/'
const LANDING_TITLE = 'ThreatIntel Lite | Análisis de seguridad web'

const routeTitles: Record<string, string> = {
  '/login': 'Iniciar sesión | ThreatIntel Lite',
  '/register': 'Crear una cuenta | ThreatIntel Lite',
  '/dashboard': 'Dashboard | ThreatIntel Lite',
  '/analyses': 'Mis análisis | ThreatIntel Lite',
  '/change-password': 'Cambiar contraseña | ThreatIntel Lite',
}

function RouteMetadata() {
  const { pathname } = useLocation()

  useEffect(() => {
    const routePath = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname
    const isLanding = routePath === '/'
    const title = routePath.startsWith('/analyses/')
      ? 'Detalle del análisis | ThreatIntel Lite'
      : routeTitles[routePath] ?? 'Página no encontrada | ThreatIntel Lite'

    document.title = isLanding ? LANDING_TITLE : title

    let robots = document.querySelector<HTMLMetaElement>('meta[name="robots"]')
    if (isLanding) {
      robots?.remove()
    } else {
      if (!robots) {
        robots = document.createElement('meta')
        robots.name = 'robots'
        document.head.append(robots)
      }
      robots.content = 'noindex'
    }

    let canonical = document.querySelector<HTMLLinkElement>('link[rel="canonical"]')
    if (isLanding) {
      if (!canonical) {
        canonical = document.createElement('link')
        canonical.rel = 'canonical'
        document.head.append(canonical)
      }
      canonical.href = SITE_URL
    } else {
      canonical?.remove()
    }
  }, [pathname])

  return null
}

export default RouteMetadata
