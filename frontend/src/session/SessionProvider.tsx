import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { getCurrentSession } from '../api/sessions'
import { sendHeartbeat } from '../api/security'
import { useAuth } from '../auth/useAuth'
import { getToken } from '../auth/tokenStore'
import { SessionSocket } from '../ws/socket'
import type {
  MFAChallenge,
  Session,
  SessionSocketStatus,
  TrustReverifyRequiredMessage,
  TrustUpdatedMessage,
} from '../types'
import { SessionContext } from './context'
import { ReverifyModal } from './ReverifyModal'

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
 *
 * Also runs the Module 7 Section 18 heartbeat (2026-09-15): a small
 * periodic authenticated HTTP call, separate from the WebSocket's own ping,
 * while a session is open — see app/services/trust_score/heartbeat.py for
 * why this can't just be done over the WS connection itself (its real IP/
 * User-Agent are fixed at handshake). Any resulting trust.updated /
 * trust.reverify_required / session.terminated arrives back on the existing
 * socket via the onMessage/onTerminated handlers below, exactly as it would
 * for a manual admin Trigger — the heartbeat call's own response is
 * best-effort and otherwise ignored here.
 */
export function SessionProvider({ children }: { children: ReactNode }) {
  const { status, forceLogout } = useAuth()

  const [socketStatus, setSocketStatus] = useState<SessionSocketStatus>('idle')
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [endedReason, setEndedReason] = useState<string | null>(null)
  // Module 7: a pending continuous re-verification challenge for THIS tab's
  // own session, pushed down its signalling socket as `trust.reverify_required`.
  const [reverifyChallenge, setReverifyChallenge] = useState<MFAChallenge | null>(null)
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
        setReverifyChallenge(null)
        // The backend already ended this session (admin / sweep / a Module 7
        // risk-based revocation / etc.) — an unexpired JWT must not silently
        // reopen a new one behind it. Drop it client-side; ProtectedRoute
        // takes it from here.
        forceLogout()
      },
      onMessage: (message) => {
        // Module 7: a mid-session security event dropped THIS session into
        // MEDIUM risk (reverify_required) or a pending one just succeeded
        // (reverified). Neither message ends the session by itself -- a
        // failed/expired/exhausted re-verification instead arrives as the
        // ordinary `session.terminated` push handled by onTerminated above.
        //
        // Bug fix (2026-09-14): `session` state was only ever populated once,
        // from GET /sessions/current at onEstablished -- so the portal's
        // Trust/Risk display went stale the moment a live event recomputed
        // the score server-side, even though this very push already carries
        // the new value. Apply it here instead of discarding it, and
        // re-fetch on `trust.reverified` (which carries no score of its own,
        // since reverifying doesn't restore it -- see docs/architecture.md)
        // so `current_action` and everything else falls back in sync with
        // the server's authoritative row.
        if (message.type === 'trust.reverify_required') {
          const push = message as unknown as TrustReverifyRequiredMessage
          setReverifyChallenge(push.challenge)
          setSession((prev) =>
            prev
              ? {
                  ...prev,
                  trust_score: push.trust_score,
                  risk_level: push.risk_level,
                  current_action: 'reverify_required',
                }
              : prev,
          )
        } else if (message.type === 'trust.reverified') {
          setReverifyChallenge(null)
          void refresh()
        } else if (message.type === 'trust.updated') {
          // 2026-09-14: a mid-session event recomputed the score but stayed
          // within the same risk band (no challenge, no revoke) -- apply it
          // so the portal's number tracks every step live, the same
          // granularity the admin's Live Sessions table already has by
          // polling the DB directly.
          const push = message as unknown as TrustUpdatedMessage
          setSession((prev) =>
            prev
              ? { ...prev, trust_score: push.trust_score, risk_level: push.risk_level }
              : prev,
          )
        }
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
      setReverifyChallenge(null)
    }
  }, [status, refresh, forceLogout])

  // Module 7 Section 18 (2026-09-15) — the passive-detection heartbeat.
  // Only runs once a session is actually established, and stops the moment
  // it ends (sessionId -> null re-runs this effect's cleanup). A missed or
  // failed heartbeat is not itself suspicious (Section 18's own documented
  // assumption) — the existing WS ping / idle-timeout sweep already cover a
  // genuinely dead connection, so failures here are swallowed, not retried
  // or surfaced to the user.
  useEffect(() => {
    if (!sessionId) return

    const configuredSeconds = Number(import.meta.env.VITE_HEARTBEAT_INTERVAL_SECONDS)
    const intervalMs =
      Number.isFinite(configuredSeconds) && configuredSeconds > 0
        ? configuredSeconds * 1000
        : 20_000

    const id = window.setInterval(() => {
      void sendHeartbeat().catch(() => {
        // best-effort — see the effect comment above
      })
    }, intervalMs)

    return () => window.clearInterval(id)
  }, [sessionId])

  const value = useMemo(
    () => ({ socketStatus, sessionId, session, endedReason, refresh }),
    [socketStatus, sessionId, session, endedReason, refresh],
  )

  return (
    <SessionContext.Provider value={value}>
      {children}
      {reverifyChallenge && (
        <ReverifyModal
          challenge={reverifyChallenge}
          onVerified={() => setReverifyChallenge(null)}
        />
      )}
    </SessionContext.Provider>
  )
}
