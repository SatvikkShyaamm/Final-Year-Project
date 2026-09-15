import { apiClient } from './client'
import type {
  HeartbeatResult,
  SecurityEventConfigResponse,
  SecurityEventListResponse,
  SecurityEventRequest,
  SecurityEventResult,
  SecurityEventSource,
} from '../types'

/**
 * Typed wrappers over the Module 7 continuous-evaluation endpoints.
 *
 * `ingestSecurityEvent` is admin-only today and doubles as this project's
 * demo/testing hook for the flow described in Section 8/14 of
 * MASTER_PROJECT_CONTEXT.docx ("Simulate Unknown VPN", "Simulate Abnormal
 * Download", ...) until Module 9 gives it dedicated attacker-facing buttons
 * of its own — it will call this exact same endpoint.
 *
 * `sendHeartbeat` is Section 18's (2026-09-15) automatic counterpart —
 * SessionProvider calls it on a timer for any authenticated user with an
 * open session; see its own module docstring for the detection mechanism.
 */

export async function ingestSecurityEvent(
  body: SecurityEventRequest,
): Promise<SecurityEventResult> {
  const { data } = await apiClient.post<SecurityEventResult>('/api/v1/security/events', body)
  return data
}

export async function listSecurityEvents(
  sessionId?: string,
  source?: SecurityEventSource,
): Promise<SecurityEventListResponse> {
  const { data } = await apiClient.get<SecurityEventListResponse>('/api/v1/security/events', {
    params: {
      ...(sessionId ? { session_id: sessionId } : {}),
      ...(source ? { source } : {}),
    },
  })
  return data
}

export async function getSecurityConfig(): Promise<SecurityEventConfigResponse> {
  const { data } = await apiClient.get<SecurityEventConfigResponse>('/api/v1/security/config')
  return data
}

/** No body — the caller's own current active session is resolved
 * server-side; this request's real IP/User-Agent are read there. */
export async function sendHeartbeat(): Promise<HeartbeatResult> {
  const { data } = await apiClient.post<HeartbeatResult>('/api/v1/security/heartbeat')
  return data
}
