import { apiClient } from './client'
import type {
  SessionTrustScore,
  TrustScoreConfigResponse,
  TrustScoreHistoryResponse,
} from '../types'

/**
 * Typed wrappers over the Module 5 trust-score read endpoints. The score is
 * computed server-side at session creation (Section 6 factor table) — there is
 * nothing to POST here.
 */

export async function getSessionTrustScore(
  sessionId: string,
): Promise<SessionTrustScore> {
  const { data } = await apiClient.get<SessionTrustScore>(
    `/api/v1/trust-score/${sessionId}`,
  )
  return data
}

export async function getTrustScoreConfig(): Promise<TrustScoreConfigResponse> {
  const { data } = await apiClient.get<TrustScoreConfigResponse>(
    '/api/v1/trust-score/config',
  )
  return data
}

export async function getUserTrustHistory(
  userId: number,
): Promise<TrustScoreHistoryResponse> {
  const { data } = await apiClient.get<TrustScoreHistoryResponse>(
    `/api/v1/trust-score/user/${userId}/history`,
  )
  return data
}
