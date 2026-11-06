import { apiFetch } from './ApiClient'
import type { AnalysisHistoryResponse, ApiErrorResponse } from '../types'

export async function getSavedAnalyses(): Promise<AnalysisHistoryResponse[]> {
  const response = await apiFetch('/api/analyses', {
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
  const response = await apiFetch(`/api/analyses/${id}`, {
    method: 'GET',
  })

  if (!response.ok) {
    const errorData: ApiErrorResponse = await response.json()
    throw new Error(errorData.message)
  }

  const data: AnalysisHistoryResponse = await response.json()

  return data
}

export class PendingAnalysisUnavailableError extends Error {}

export async function saveAnalysis(pendingAnalysisId: string): Promise<void> {
  const response = await apiFetch('/api/analyses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ pendingAnalysisId }),
  })

  if (!response.ok) {
    const errorData: ApiErrorResponse = await response.json()
    if (response.status === 404) {
      throw new PendingAnalysisUnavailableError('Este resultado ha caducado o ya no está disponible. Revisa Mis análisis por si ya se guardó, o vuelve a analizar la URL para guardarlo.')
    }
    throw new Error(errorData.message)
  }
}
