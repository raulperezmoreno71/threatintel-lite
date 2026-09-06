import { apiFetch } from './ApiClient'
import type { AnalyzeResponse, AnalysisHistoryResponse, ApiErrorResponse } from '../types'

export async function getSavedAnalyses(): Promise<AnalysisHistoryResponse[]> {
  const response = await apiFetch('http://localhost:8080/api/analyses', {
    method: 'GET',
  })

  if (!response.ok) {
    const errorData: ApiErrorResponse = await response.json()
    throw new Error(errorData.message)
  }

  const data: AnalysisHistoryResponse[] = await response.json()

  return data
}

export async function getSavedAnalysis(id: number): Promise<AnalysisHistoryResponse> {
  const response = await apiFetch(`http://localhost:8080/api/analyses/${id}`, {
    method: 'GET',
  })

  if (!response.ok) {
    const errorData: ApiErrorResponse = await response.json()
    throw new Error(errorData.message)
  }

  const data: AnalysisHistoryResponse = await response.json()

  return data
}

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
