import type { LoginResponse, ApiErrorResponse } from '../types'

export async function login(
    email: string,
    password: string,
): Promise<LoginResponse> {
    const response = await fetch('http://localhost:8080/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email,
            password,
        }),
    })

    if (!response.ok) {
        if (response.status === 401) {
            throw new Error('Correo o contraseña incorrectos.')
        }

        const errorData: ApiErrorResponse = await response.json()
        throw new Error(errorData.message)
    }

    const data: LoginResponse = await response.json()

    return data
}
