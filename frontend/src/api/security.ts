import { apiClient } from './client'
import type {
  SecurityEventConfigResponse,
  SecurityEventListResponse,
  SecurityEventRequest,
  SecurityEventResult,
} from '../types'

/**
 * Typed wrappers over the Module 7 continuous-evaluation endpoints.
 *
 * `ingestSecurityEvent` is admin-only today and doubles as this project's
 * demo/testing hook for the flow described in Section 8/14 of
 * MASTER_PROJECT_CONTEXT.docx ("Simulate Unknown VPN", "Simulate Abnormal
 * Download", ...) until Module 9 gives it dedicated attacker-facing buttons
 * of its own — it will call this exact same endpoint.
 */

export async function ingestSecurityEvent(
  body: SecurityEventRequest,
): Promise<SecurityEventResult> {
  const { data } = await apiClient.post<SecurityEventResult>('/api/v1/security/events', body)
  return data
}

export async function listSecurityEvents(
  sessionId?: string,
): Promise<SecurityEventListResponse> {
  const { data } = await apiClient.get<SecurityEventListResponse>('/api/v1/security/events', {
    params: sessionId ? { session_id: sessionId } : undefined,
  })
  return data
}

export async function getSecurityConfig(): Promise<SecurityEventConfigResponse> {
  const { data } = await apiClient.get<SecurityEventConfigResponse>('/api/v1/security/config')
  return data
}
