import { useState } from "react"
import type { SubmitEvent } from "react"
import { login } from "../api/AuthApi"

function LoginPage() {

    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [error, setError] = useState('')

    async function handleSubmit(event: SubmitEvent<HTMLFormElement>) {
        event.preventDefault()

        setError('')

        try {
            const result = await login(email, password)

            console.log(result)
        } catch (error) {
            if (error instanceof Error) {
                setError(error.message)
            }
        }
    }

    return (
        <main>
            <section>
                <h1>Iniciar sesión</h1>

                <form onSubmit={handleSubmit}>
                    <div>
                        <label htmlFor="email">Correo electrónico</label>
                        <input 
                            id="email" 
                            type="email" 
                            name="email"
                            value={email}
                            onChange={(event) => setEmail(event.target.value)}
                        />
                    </div>

                    <div>
                        <label htmlFor="password">Contraseña</label>
                        <input 
                            id="password" 
                            type="password" 
                            name="password"
                            value={password}
                            onChange={(event) => setPassword(event.target.value)}
                        />
                    </div>

                    {error && <p>{error}</p>}

                    <button type="submit">Iniciar sesión</button>
                </form>
            </section>
        </main>
    )
}

export default LoginPage