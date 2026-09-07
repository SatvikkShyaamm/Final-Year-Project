import { apiClient } from './client'
import type { Session, SessionListResponse } from '../types'

/**
 * Typed wrappers over the Module 3 session REST endpoints. The live session
 * *state* is driven by the WebSocket (see ws/socket.ts); these are for the
 * admin dashboard feed and the portal's "my current session" card.
 */

export async function listSessions(
  includeTerminated = false,
): Promise<SessionListResponse> {
  const { data } = await apiClient.get<SessionListResponse>('/api/v1/sessions', {
    params: { include_terminated: includeTerminated },
  })
  return data
}

export async function getCurrentSession(): Promise<Session | null> {
  const { data } = await apiClient.get<Session | null>('/api/v1/sessions/current')
  return data
}

export async function terminateSession(sessionId: string): Promise<void> {
  await apiClient.delete(`/api/v1/sessions/${sessionId}`)
}
