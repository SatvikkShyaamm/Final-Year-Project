import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { ingestSecurityEvent } from '../../api/security'
import { listSessions, terminateSession } from '../../api/sessions'
import { AclBadge } from '../../components/common/AclBadge'
import { RiskBadge } from '../../components/common/RiskBadge'
import type { SecurityEventType, Session } from '../../types'

/**
 * Module 3 — real Live Session Monitoring. Polls GET /api/v1/sessions every
 * few seconds and renders whatever the backend reports. ACL column is real
 * from Module 4; Trust / Risk from Module 5. The "Simulate" column is
 * Module 7's testing/demo hook (POST /security/events) for the continuous
 * re-evaluation flow in Section 8/14 of MASTER_PROJECT_CONTEXT.docx --
 * Module 9 gives attackers dedicated buttons of their own later, calling
 * this exact same endpoint.
 */
const EVENT_TYPES: { value: SecurityEventType; label: string }[] = [
  { value: 'ip_change', label: 'IP change' },
  { value: 'vpn_detected', label: 'VPN detected' },
  { value: 'unknown_device', label: 'Unknown device' },
  { value: 'abnormal_request_rate', label: 'Abnormal request rate' },
  { value: 'large_download', label: 'Large download' },
  { value: 'multiple_failed_logins', label: 'Multiple failed logins' },
]
// A sample unrecognised-VPN/proxy IP from the default TRUST_KNOWN_VPN_CIDRS_RAW
// sample, so "VPN detected" has a realistic classifiable source out of the box.
const SAMPLE_UNKNOWN_VPN_IP = '185.220.100.7'
const POLL_MS = 5000

export function LiveSessions() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [activeCount, setActiveCount] = useState(0)
  const [includeTerminated, setIncludeTerminated] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [simulateEvent, setSimulateEvent] = useState<Record<string, SecurityEventType>>({})

  const load = useCallback(async () => {
    try {
      const data = await listSessions(includeTerminated)
      setSessions(data.sessions)
      setActiveCount(data.active_count)
      setError(null)
    } catch {
      setError('Could not load sessions from the backend.')
    }
  }, [includeTerminated])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), POLL_MS)
    return () => window.clearInterval(timer)
  }, [load])

  async function handleTerminate(id: string) {
    setBusyId(id)
    try {
      await terminateSession(id)
      await load()
    } catch {
      setError('Failed to terminate that session.')
    } finally {
      setBusyId(null)
    }
  }

  async function handleSimulate(id: string) {
    const eventType = simulateEvent[id] ?? EVENT_TYPES[0].value
    setBusyId(id)
    try {
      const ipAddress = eventType === 'vpn_detected' ? SAMPLE_UNKNOWN_VPN_IP : undefined
      await ingestSecurityEvent({ session_id: id, event_type: eventType, ip_address: ipAddress })
      await load()
    } catch {
      setError('Failed to ingest that security event.')
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div>
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Live Session Monitoring</h1>
          <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
            {activeCount} active session{activeCount === 1 ? '' : 's'} · auto-refreshing
          </p>
        </div>
        <label className="flex items-center gap-2 text-xs text-[color:var(--color-text-muted)]">
          <input
            type="checkbox"
            checked={includeTerminated}
            onChange={(e) => setIncludeTerminated(e.target.checked)}
          />
          show terminated
        </label>
      </div>

      {error && (
        <p className="mt-4 text-sm text-[color:var(--color-risk-high)]">{error}</p>
      )}

      <div className="mt-6 overflow-x-auto rounded-xl border border-[color:var(--color-border)]">
        <table className="w-full min-w-[1180px] text-left text-sm">
          <thead className="bg-[color:var(--color-surface)] text-xs uppercase tracking-wide text-[color:var(--color-text-muted)]">
            <tr>
              <Th>User</Th>
              <Th>Session ID</Th>
              <Th>IP</Th>
              <Th>Device</Th>
              <Th>Login</Th>
              <Th>Duration</Th>
              <Th>WebSocket</Th>
              <Th>State</Th>
              <Th>Trust</Th>
              <Th>Risk</Th>
              <Th>ACL</Th>
              <Th>Action</Th>
              <Th> </Th>
              <Th>Simulate (Module 7)</Th>
            </tr>
          </thead>
          <tbody>
            {sessions.length === 0 && (
              <tr>
                <td
                  colSpan={14}
                  className="px-4 py-8 text-center text-[color:var(--color-text-muted)]"
                >
                  No sessions. Log in from the user portal to open one.
                </td>
              </tr>
            )}
            {sessions.map((s) => (
              <tr
                key={s.id}
                className="border-t border-[color:var(--color-border)] bg-[color:var(--color-bg)]"
              >
                <Td>{s.username ?? `#${s.user_id}`}</Td>
                <Td className="font-mono text-xs">{s.id.slice(0, 12)}…</Td>
                <Td>{s.ip_address ?? '—'}</Td>
                <Td className="max-w-[180px] truncate" title={s.user_agent ?? ''}>
                  {shortDevice(s.user_agent)}
                </Td>
                <Td>{new Date(s.created_at + 'Z').toLocaleTimeString()}</Td>
                <Td>{formatDuration(s.duration_seconds)}</Td>
                <Td>
                  <WsBadge connected={s.ws_connected} />
                </Td>
                <Td>
                  <StateBadge state={s.state} reason={s.termination_reason} />
                </Td>
                <Td className="tabular-nums">
                  {s.trust_score ?? <span className="text-[color:var(--color-text-muted)]">—</span>}
                </Td>
                <Td>
                  {s.risk_level ? (
                    <RiskBadge level={s.risk_level} />
                  ) : (
                    <span className="text-[color:var(--color-text-muted)]">—</span>
                  )}
                </Td>
                <Td>
                  <AclBadge state={s.acl_status ?? 'none'} />
                </Td>
                <Td>
                  {s.current_action === 'reverify_required' ? (
                    <span className="rounded-full border border-[color:var(--color-risk-medium)]/30 bg-[color:var(--color-risk-medium)]/15 px-2 py-0.5 text-xs text-[color:var(--color-risk-medium)]">
                      reverify pending
                    </span>
                  ) : (
                    <span className="text-[color:var(--color-text-muted)]">—</span>
                  )}
                </Td>
                <Td>
                  {s.state === 'active' && (
                    <button
                      onClick={() => handleTerminate(s.id)}
                      disabled={busyId === s.id}
                      className="rounded-md border border-[color:var(--color-border)] px-2 py-1 text-xs text-[color:var(--color-risk-high)] hover:bg-[color:var(--color-surface-alt)] disabled:opacity-50"
                    >
                      {busyId === s.id ? '…' : 'Terminate'}
                    </button>
                  )}
                </Td>
                <Td>
                  {s.state === 'active' && (
                    <div className="flex items-center gap-1.5">
                      <select
                        value={simulateEvent[s.id] ?? EVENT_TYPES[0].value}
                        onChange={(e) =>
                          setSimulateEvent((cur) => ({
                            ...cur,
                            [s.id]: e.target.value as SecurityEventType,
                          }))
                        }
                        className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-bg)] px-1.5 py-1 text-xs text-[color:var(--color-text)]"
                      >
                        {EVENT_TYPES.map((t) => (
                          <option key={t.value} value={t.value}>
                            {t.label}
                          </option>
                        ))}
                      </select>
                      <button
                        onClick={() => handleSimulate(s.id)}
                        disabled={busyId === s.id}
                        className="rounded-md border border-[color:var(--color-border)] px-2 py-1 text-xs hover:bg-[color:var(--color-surface-alt)] disabled:opacity-50"
                      >
                        {busyId === s.id ? '…' : 'Trigger'}
                      </button>
                    </div>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Th({ children }: { children: ReactNode }) {
  return <th className="px-4 py-2 font-medium">{children}</th>
}

function Td({
  children,
  className = '',
  title,
}: {
  children: ReactNode
  className?: string
  title?: string
}) {
  return (
    <td className={`px-4 py-2 align-middle ${className}`} title={title}>
      {children}
    </td>
  )
}

function WsBadge({ connected }: { connected: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs ${
        connected
          ? 'text-[color:var(--color-risk-low)]'
          : 'text-[color:var(--color-text-muted)]'
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          connected
            ? 'bg-[color:var(--color-risk-low)]'
            : 'bg-[color:var(--color-text-muted)]'
        }`}
      />
      {connected ? 'connected' : 'closed'}
    </span>
  )
}

function StateBadge({
  state,
  reason,
}: {
  state: string
  reason: string | null
}) {
  if (state === 'active') {
    return (
      <span className="rounded-full border border-[color:var(--color-risk-low)]/30 bg-[color:var(--color-risk-low)]/15 px-2 py-0.5 text-xs text-[color:var(--color-risk-low)]">
        active
      </span>
    )
  }
  return (
    <span
      className="rounded-full border border-[color:var(--color-border)] px-2 py-0.5 text-xs text-[color:var(--color-text-muted)]"
      title={reason ?? undefined}
    >
      {reason ? `terminated · ${reason}` : 'terminated'}
    </span>
  )
}

function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${sec}s`
  return `${sec}s`
}

function shortDevice(userAgent: string | null): string {
  if (!userAgent) return '—'
  const browser =
    /Edg\//.test(userAgent) ? 'Edge'
    : /Firefox\//.test(userAgent) ? 'Firefox'
    : /Chrome\//.test(userAgent) ? 'Chrome'
    : /Safari\//.test(userAgent) ? 'Safari'
    : 'client'
  const os =
    /Windows/.test(userAgent) ? 'Windows'
    : /Mac OS X/.test(userAgent) ? 'macOS'
    : /Android/.test(userAgent) ? 'Android'
    : /Linux/.test(userAgent) ? 'Linux'
    : ''
  return os ? `${browser} · ${os}` : browser
}
