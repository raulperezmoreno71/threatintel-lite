import { Link } from 'react-router-dom'
import './RegisterPage.css'

function RegisterPage() {
    return (
        <main className="register-page">
            <div className="register-page__content">
                <h1>Crear una cuenta</h1>
                <Link className="register-page__home-link" to="/">
                    <span aria-hidden="true">←</span>
                    Volver a la página principal
                </Link>
            </div>
        </main>
    )
}

export default RegisterPage
