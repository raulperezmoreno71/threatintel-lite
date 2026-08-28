import type { LoginResponse, ApiErrorResponse } from '../types'

export async function login(
    email: string,
    password: string,
): Promise<LoginResponse> {
    const response = await fetch('http://localhost:8080/api/auth/login', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email,
            password,   
        }),
    })

    if (!response.ok) {
        const errorData: ApiErrorResponse = await response.json()
        throw new Error(errorData.message)
    }

    const data: LoginResponse = await response.json()

    return data
}
