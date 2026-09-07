import { createContext } from 'react'
import type { Session, SessionSocketStatus } from '../types'

/**
 * Client-side view of the caller's own session (Module 3). Split from the
 * provider component and the hook so each file has a single kind of export.
 */
export interface SessionContextValue {
  /** State of this client's signalling WebSocket. */
  socketStatus: SessionSocketStatus
  /** Backend session id once the socket has been established. */
  sessionId: string | null
  /** Full session record from GET /sessions/current (refreshed on connect). */
  session: Session | null
  /** Why the session ended, if the server told us (admin / timeout / logout). */
  endedReason: string | null
  /** Re-fetch GET /sessions/current. */
  refresh: () => Promise<void>
}

export const SessionContext = createContext<SessionContextValue | null>(null)
