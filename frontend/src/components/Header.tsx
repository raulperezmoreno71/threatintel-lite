import { Link } from 'react-router-dom'
import './Header.css'

function Header() {
  return (
    <header className="site-header">
      <div className="site-header__content">
        <div className="site-header__brand" aria-label="ThreatIntel Lite">
          <span className="site-header__mark" aria-hidden="true">T</span>
          <span>ThreatIntel <strong>Lite</strong></span>
        </div>

        <nav className="site-header__actions" aria-label="Acceso de usuario">
          <Link className="site-header__login" to="/login">
            Iniciar sesión
          </Link>
          <Link className="site-header__register" to="/register">
            Registrarse
          </Link>
        </nav>
      </div>
    </header>
  )
}

export default Header
