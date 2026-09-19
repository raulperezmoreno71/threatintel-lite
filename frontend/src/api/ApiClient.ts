const API_URL = import.meta.env.VITE_API_URL ?? ''

function getCookie(name: string): string | null {
    const cookies = document.cookie.split('; ')

    for (const cookie of cookies) {
        const [cookieName, ...cookieValue] = cookie.split('=')

        if (cookieName === name) {
            return decodeURIComponent(cookieValue.join('='))
        }
    }

    return null
} 

export async function apiFetch(
    url: string,
    options: RequestInit = {}
): Promise<Response> {
    const csrfToken = getCookie('XSRF-TOKEN')
    const headers = new Headers(options.headers)

    if (csrfToken) {
        headers.set('X-XSRF-TOKEN', csrfToken)
    }

    const response = await fetch(`${API_URL}${url}`, {
        ...options,
        headers,
        credentials: 'include'
    })

    if (response.status === 401) {
        throw new Error('UNAUTHORIZED')
    }

    return response
}