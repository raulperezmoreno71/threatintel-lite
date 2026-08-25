export type LoginResponse = {
    id: number
    email: string
    status: string
    message: string
    token: string
}

export type ApiErrorResponse = {
    status: number
    error: string
    message: string
    path: string
}