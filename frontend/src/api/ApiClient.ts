export async function apiFetch(
    url: string,
    options: RequestInit = {}
): Promise<Response> {
    const response = await fetch(url, {
        ...options,
        credentials: 'include'
    })

    if (response.status === 401) {
        throw new Error('UNAUTHORIZED')
    }

    return response
}