import type { LoginResponse, RegisterResponse, ApiErrorResponse, UserResponse } from '../types'
import { apiFetch } from './ApiClient'

export async function login(
    email: string,
    password: string,
): Promise<LoginResponse> {
    const response = await apiFetch('http://localhost:8080/api/auth/login', {
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
        const errorData: ApiErrorResponse = await response.json()
        throw new Error(errorData.message)
    }

    const data: LoginResponse = await response.json()

    return data
}

export async function register(
    email: string,
    password: string,
): Promise<RegisterResponse> {
    const response = await apiFetch('http://localhost:8080/api/auth/register', {
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
        const errorData: ApiErrorResponse = await response.json()
        throw new Error(errorData.message)
    }

    const data: RegisterResponse = await response.json()

    return data
}

export async function getCurrentUser(): Promise<UserResponse> {
    const response = await apiFetch(
        'http://localhost:8080/api/auth/me',
        {
            method: 'GET'
        }
    )

    if (!response.ok) {
        const errorData: ApiErrorResponse = await response.json()
        throw new Error(errorData.message)
    }

    const data: UserResponse = await response.json()

    return data
}

export async function logout(): Promise<void> {
    const response = await apiFetch('http://localhost:8080/api/auth/logout', {
        method: 'POST',
    })

    if (!response.ok) {
        throw new Error('No se ha podido cerrar sesión')
    }
}

export async function changePassword(
    currentPassword: string,
    newPassword: string
): Promise<void> {
    const response = await fetch('http://localhost:8080/api/auth/change-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        credentials: 'include',
        body: JSON.stringify({
            currentPassword,
            newPassword
        })
    })

    if (!response.ok) {
        const errorData = await response
            .json()
            .catch(() => null) as ApiErrorResponse | null

        throw new Error(errorData?.message || 'No se ha podido cambiar la contraseña')
    }
}
