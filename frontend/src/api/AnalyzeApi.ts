import { apiFetch } from "./ApiClient";
import type { AnalyzeResponse, ApiErrorResponse } from "../types";

export async function analyzeUrl(
    url: string
): Promise<AnalyzeResponse> {
    
    const response = await apiFetch('http://localhost:8080/api/analyze', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            url
        })
    })

    if (!response.ok) {
        const errorData: ApiErrorResponse = await response.json()
        throw new Error(errorData.message)
    }

    const data: AnalyzeResponse = await response.json()

    return data
}