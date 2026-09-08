import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { getCurrentSession } from '../api/sessions'
import { useAuth } from '../auth/useAuth'
import { getToken } from '../auth/tokenStore'
import { SessionSocket } from '../ws/socket'
import type { Session, SessionSocketStatus } from '../types'
import { SessionContext } from './context'

/**
 * Opens the signalling WebSocket for the whole app once the user is
 * authenticated (Module 3), and tears it down on logout / auth loss. Also
 * keeps a copy of GET /sessions/current so the portal can show session
 * details. No-ops while unauthenticated.
 *
 * A server-driven end (session.terminated — admin terminate, idle/lifetime
 * sweep, and later a Module 7 risk-based revocation) means "this session's
 * network access is over," but the JWT is still technically valid: without
 * this, the client would sit on the same page with a dead socket, and a
 * refresh would silently open a brand-new session with the same token. That
 * defeats the point of terminating it. So on session.terminated this calls
 * `forceLogout()`, which drops the token client-side; ProtectedRoute's
 * existing status check then sends the user back to /login on its own — no
 * extra navigation logic needed here. A page refresh while still ACTIVE is
 * unaffected: the tab is torn down by the browser before any message can
 * arrive, so the valid JWT correctly opens a fresh session on reload, per
 * docs/architecture.md.
 */
export function SessionProvider({ children }: { children: ReactNode }) {
  const { status, forceLogout } = useAuth()

  const [socketStatus, setSocketStatus] = useState<SessionSocketStatus>('idle')
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [endedReason, setEndedReason] = useState<string | null>(null)
  const socketRef = useRef<SessionSocket | null>(null)

  const refresh = useCallback(async () => {
    try {
      setSession(await getCurrentSession())
    } catch {
      setSession(null)
    }
  }, [])

  useEffect(() => {
    if (status !== 'authenticated') return
    const token = getToken()
    if (!token) return

    const socket = new SessionSocket(token, {
      onStatusChange: (next) => {
        setSocketStatus(next)
        if (next === 'connecting' || next === 'connected') setEndedReason(null)
      },
      onEstablished: (id) => {
        setSessionId(id)
        void refresh()
      },
      onTerminated: (reason) => {
        setEndedReason(reason)
        setSession(null)
        setSessionId(null)
        // The backend already ended this session (admin / sweep / etc.) — an
        // unexpired JWT must not silently reopen a new one behind it. Drop
        // it client-side; ProtectedRoute takes it from here.
        forceLogout()
      },
    })
    socketRef.current = socket
    socket.connect()

    return () => {
      socket.close()
      socketRef.current = null
      setSocketStatus('idle')
      setSessionId(null)
      setSession(null)
    }
  }, [status, refresh, forceLogout])

  const value = useMemo(
    () => ({ socketStatus, sessionId, session, endedReason, refresh }),
    [socketStatus, sessionId, session, endedReason, refresh],
  )

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
