import { apiClient } from './client'
import type { HealthResponse } from '../types'

/**
 * Calls the REAL backend /api/v1/health endpoint (live DB + Redis checks),
 * not a mocked value. This is what the Module 1 System Status page renders,
 * proving frontend <-> backend <-> Postgres/Redis connectivity end to end.
 */
export async function fetchHealth(): Promise<HealthResponse> {
  const response = await apiClient.get<HealthResponse>('/api/v1/health')
  return response.data
}
