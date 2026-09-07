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
 */
export function SessionProvider({ children }: { children: ReactNode }) {
  const { status } = useAuth()

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
  }, [status, refresh])

  const value = useMemo(
    () => ({ socketStatus, sessionId, session, endedReason, refresh }),
    [socketStatus, sessionId, session, endedReason, refresh],
  )

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
