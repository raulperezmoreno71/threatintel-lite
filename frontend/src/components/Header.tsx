import './Header.css'

function Header() {
  return (
    <header className="site-header">
      <div className="site-header__content">
        <div className="site-header__brand" aria-label="ThreatIntel Lite">
          <span className="site-header__mark" aria-hidden="true">T</span>
          <span>ThreatIntel <strong>Lite</strong></span>
        </div>

        <div className="site-header__actions">
          <button className="site-header__login" type="button">
            Iniciar sesión
          </button>
          <button className="site-header__register" type="button">
            Registrarse
          </button>
        </div>
      </div>
    </header>
  )
}

export default Header
