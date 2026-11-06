import { beforeEach, expect, test, vi } from 'vitest'
import { apiFetch } from './ApiClient'
import { PendingAnalysisUnavailableError, saveAnalysis } from './AnalysisHistoryApi'
vi.mock('./ApiClient', () => ({ apiFetch: vi.fn() }))
const fetchMock = vi.mocked(apiFetch)
beforeEach(() => fetchMock.mockReset())

test('sends only the server-generated identifier', async () => {
  fetchMock.mockResolvedValue(new Response(null, { status: 201 }))
  await saveAnalysis('pending-id')
  expect(fetchMock).toHaveBeenCalledWith('/api/analyses', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pendingAnalysisId: 'pending-id' }),
  })
})

test('turns missing or expired drafts into an actionable error', async () => {
  fetchMock.mockResolvedValue(new Response(JSON.stringify({ message: 'unavailable' }), { status: 404 }))
  await expect(saveAnalysis('expired-id')).rejects.toBeInstanceOf(PendingAnalysisUnavailableError)
})

test('preserves temporary save errors so the user can retry', async () => {
  fetchMock.mockResolvedValue(new Response(JSON.stringify({ message: 'Temporary failure' }), { status: 500 }))
  await expect(saveAnalysis('pending-id')).rejects.toThrow('Temporary failure')
})
