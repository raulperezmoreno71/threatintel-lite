import { useEffect, useState } from "react"
import { getCurrentUser, logout } from "../api/AuthApi"
import { useNavigate } from "react-router-dom"
import type { UserResponse } from "../types"

function DashboardPage() {
    const [user, setUser] = useState<UserResponse | null>(null)
    const [error, setError] = useState('')
    const navigate = useNavigate()

    useEffect(() => {
        getCurrentUser()
        .then(setUser)
        .catch(error => {
            if (error.message === 'UNAUTHORIZED') {
                navigate('/login', {
                    state: {
                        message: 'Tu sesión ha caducado. Vuelve a iniciar sesión.'
                    }
                })
                return
            }

            setError(error.message)
        })
    }, [navigate])

    async function handleLogout() {
        try {
            await logout()
            navigate('/login')
        } catch (error) {
            if (error instanceof Error) {
                setError(error.message)
            }
        }
    }

    return (
        <main>
            <h1>Dashboard</h1>
            
            {user && (
                <p>Bienvenido, {user.email}</p>
            )}

            {error && (
                <p>{error}</p>
            )}

            <button onClick={handleLogout}>Cerrar sesión</button>
        </main>
    )
}

export default DashboardPage