import { apiFetch } from './ApiClient'
import type { AnalyzeResponse, ApiErrorResponse } from '../types'

export async function saveAnalysis(analysis: AnalyzeResponse): Promise<void> {
  const response = await apiFetch('http://localhost:8080/api/analyses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(analysis),
  })

  if (!response.ok) {
    const errorData: ApiErrorResponse = await response.json()
    throw new Error(errorData.message)
  }
}
