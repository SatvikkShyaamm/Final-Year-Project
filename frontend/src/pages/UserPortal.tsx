import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'
import { useSession } from '../session/useSession'
import { AclBadge } from '../components/common/AclBadge'
import type { SessionSocketStatus } from '../types'

/**
 * End-user portal. Module 3 adds the live session card: it reflects the
 * backend session opened by the signalling WebSocket, and a logout here walks
 * the server-side FSM S2 -> S3 (Logout -> WebSocket Closed -> Session
 * Terminated). Trust score / access state land here in Modules 5 and 6.
 */
export function UserPortal() {
  const { user, logout } = useAuth()
  const { socketStatus, sessionId, session, endedReason } = useSession()
  const navigate = useNavigate()

  async function handleLogout() {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="mx-auto max-w-2xl p-8 text-[color:var(--color-text)]">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">User Portal</h1>
        <button
          onClick={handleLogout}
          className="rounded-lg border border-[color:var(--color-border)] px-3 py-1.5 text-sm hover:bg-[color:var(--color-surface-alt)]"
        >
          Log out
        </button>
      </div>

      <div className="mt-6 rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6">
        <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
          Signed in as
        </p>
        <p className="mt-1 text-lg font-semibold">{user?.username}</p>
        <p className="text-sm text-[color:var(--color-text-muted)]">{user?.email}</p>
        <p className="mt-2 text-xs text-[color:var(--color-text-muted)]">Role: {user?.role}</p>
      </div>

      <div className="mt-4 rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6">
        <div className="flex items-center justify-between">
          <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
            Current session
          </p>
          <SocketPill status={socketStatus} />
        </div>

        {session ? (
          <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
            <Row label="Session ID" value={session.id} mono />
            <Row label="State" value={session.state} />
            <Row
              label="Opened"
              value={new Date(session.created_at + 'Z').toLocaleTimeString()}
            />
            <Row label="Duration" value={<LiveDuration since={session.created_at} />} />
            <Row label="IP" value={session.ip_address ?? '—'} />
            <Row label="ACL" value={<AclBadge state={session.acl_status ?? 'none'} />} />
          </dl>
        ) : endedReason ? (
          <p className="mt-3 text-sm text-[color:var(--color-risk-high)]">
            Session ended ({endedReason}). Log out and back in to start a new one.
          </p>
        ) : sessionId ? (
          <p className="mt-3 text-sm text-[color:var(--color-text-muted)]">
            Session {sessionId.slice(0, 12)}… — loading details…
          </p>
        ) : (
          <p className="mt-3 text-sm text-[color:var(--color-text-muted)]">
            Opening a session…
          </p>
        )}
      </div>

      <p className="mt-6 text-sm text-[color:var(--color-text-muted)]">
        Trust score and access grant/restrict/revoke state will appear here once
        Modules 5 and 6 are implemented.
      </p>
    </div>
  )
}

function Row({
  label,
  value,
  mono = false,
}: {
  label: string
  value: ReactNode
  mono?: boolean
}) {
  return (
    <>
      <dt className="text-[color:var(--color-text-muted)]">{label}</dt>
      <dd className={mono ? 'truncate font-mono text-xs' : ''}>{value}</dd>
    </>
  )
}

function SocketPill({ status }: { status: SessionSocketStatus }) {
  const map: Record<SessionSocketStatus, { label: string; className: string }> = {
    idle: { label: 'idle', className: 'text-[color:var(--color-text-muted)]' },
    connecting: { label: 'connecting…', className: 'text-[color:var(--color-risk-medium)]' },
    connected: { label: 'connected', className: 'text-[color:var(--color-risk-low)]' },
    disconnected: { label: 'disconnected', className: 'text-[color:var(--color-risk-high)]' },
  }
  const { label, className } = map[status]
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs ${className}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      WebSocket {label}
    </span>
  )
}

function LiveDuration({ since }: { since: string }) {
  const startMs = useMemo(() => new Date(since + 'Z').getTime(), [since])
  const [seconds, setSeconds] = useState(() =>
    Math.max(0, Math.floor((Date.now() - startMs) / 1000)),
  )
  useEffect(() => {
    const t = window.setInterval(() => {
      setSeconds(Math.max(0, Math.floor((Date.now() - startMs) / 1000)))
    }, 1000)
    return () => window.clearInterval(t)
  }, [startMs])
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return <span>{m > 0 ? `${m}m ${s}s` : `${s}s`}</span>
}
