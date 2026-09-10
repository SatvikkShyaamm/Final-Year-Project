import { apiClient } from './client'
import type { MFAChallenge, MFAChallengeListResponse, MFAChallengeRecord } from '../types'

/**
 * Typed wrappers over the Module 6 MFA endpoints. `verifyMfa` lives in
 * api/auth.ts (it's part of the login flow); these are the admin feed + the
 * step-up path.
 */

export async function listMfaChallenges(
  statusFilter?: string,
): Promise<MFAChallengeListResponse> {
  const { data } = await apiClient.get<MFAChallengeListResponse>('/api/v1/mfa/challenges', {
    params: statusFilter ? { status: statusFilter } : undefined,
  })
  return data
}

export async function getMfaChallenge(id: string): Promise<MFAChallengeRecord> {
  const { data } = await apiClient.get<MFAChallengeRecord>(`/api/v1/mfa/challenge/${id}`)
  return data
}

/** Step-up: an authenticated user requests a fresh challenge. */
export async function createStepUpChallenge(): Promise<MFAChallenge> {
  const { data } = await apiClient.post<MFAChallenge>('/api/v1/mfa/challenge')
  return data
}
