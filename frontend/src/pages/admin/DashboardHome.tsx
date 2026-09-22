import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { clearAccountLockout, getDashboardOverview, listLockedAccounts } from '../../api/dashboard'
import { useDashboardSocket } from '../../ws/useDashboardSocket'
import type { DashboardOverview, LockedAccount } from '../../types'

/**
 * Module 8 — Dashboard Home. Section 5's stat cards, all real aggregates
 * over Modules 2-7's own state (GET /dashboard/overview), plus the admin
 * "Locked Accounts" panel — the unlock UI explicitly deferred from the
 * Module 6/7 lockout hardening passes to "a natural fit for Module 8"
 * (Project status.md sections 17b/18). Polls on an interval, and also
 * refetches immediately on a live `/ws/dashboard` push (Section 5's
 * "real-time updates via WebSocket" requirement) — the socket is a
 * "something changed" signal only; every number here still comes from REST.
 */
const POLL_MS = 5000

const CARDS: { key: keyof Omit<DashboardOverview, 'generated_at'>; label: string; suffix?: string }[] = [
  { key: 'active_users', label: 'Active Users' },
  { key: 'active_sessions', label: 'Active Sessions' },
  { key: 'average_trust_score', label: 'Average Trust Score' },
  { key: 'high_risk_sessions', label: 'High-Risk Sessions' },
  { key: 'mfa_requests_pending', label: 'MFA Requests' },
  { key: 'revoked_sessions', label: 'Revoked Sessions' },
  { key: 'current_acl_rules', label: 'Current ACL Rules' },
  { key: 'avg_authorization_latency_ms', label: 'Avg. Authorization Latency', suffix: 'ms' },
  { key: 'avg_revocation_latency_ms', label: 'Avg. Revocation Latency', suffix: 'ms' },
]

export function DashboardHome() {
  const [overview, setOverview] = useState<DashboardOverview | null>(null)
  const [locked, setLocked] = useState<LockedAccount[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<number | null>(null)
  const { tick } = useDashboardSocket()

  const load = useCallback(async () => {
    try {
      const [ov, lockouts] = await Promise.all([getDashboardOverview(), listLockedAccounts()])
      setOverview(ov)
      setLocked(lockouts.accounts)
      setError(null)
    } catch {
      setError('Could not load the dashboard overview from the backend.')
    }
  }, [])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), POLL_MS)
    return () => window.clearInterval(timer)
  }, [load])

  // A live push (session opened/closed, ACL change, MFA event, continuous
  // evaluation event) means the numbers above are already stale — refetch
  // right away instead of waiting for the next poll tick.
  useEffect(() => {
    if (tick > 0) void load()
  }, [tick, load])

  async function handleUnlock(userId: number) {
    setBusyId(userId)
    try {
      await clearAccountLockout(userId)
      await load()
    } catch {
      setError('Failed to clear that lockout.')
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-semibold">Dashboard Home</h1>
      <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
      </p>

      {error && <p className="mt-4 text-sm text-[color:var(--color-risk-high)]">{error}</p>}

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {CARDS.map(({ key, label, suffix }) => (
          <StatCard key={key} label={label} value={overview?.[key] ?? null} suffix={suffix} />
        ))}
      </div>

      <div className="mt-8">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Locked Accounts</h2>
          <span className="text-xs text-[color:var(--color-text-muted)]">
            {overview?.locked_out_accounts ?? 0} currently locked
          </span>
        </div>
        

        <div className="mt-4 overflow-x-auto rounded-xl border border-[color:var(--color-border)]">
          <table className="w-full min-w-[640px] text-left text-sm">
            <thead className="bg-[color:var(--color-surface)] text-xs uppercase tracking-wide text-[color:var(--color-text-muted)]">
              <tr>
                <Th>User</Th>
                <Th>Lock type</Th>
                <Th>Tier</Th>
                <Th>Unlocks in</Th>
                <Th> </Th>
              </tr>
            </thead>
            <tbody>
              {locked.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-[color:var(--color-text-muted)]">
                    No accounts are currently locked out.
                  </td>
                </tr>
              )}
              {locked.map((row) => (
                <tr
                  key={`${row.user_id}-${row.lock_type}`}
                  className="border-t border-[color:var(--color-border)] bg-[color:var(--color-bg)]"
                >
                  <Td>{row.username ?? `#${row.user_id}`}</Td>
                  <Td>
                    <LockTypeBadge type={row.lock_type} />
                  </Td>
                  <Td className="tabular-nums">{row.tier ?? '—'}</Td>
                  <Td className="tabular-nums">{formatDuration(row.retry_after_seconds)}</Td>
                  <Td>
                    <button
                      onClick={() => handleUnlock(row.user_id)}
                      disabled={busyId === row.user_id}
                      className="rounded-md border border-[color:var(--color-border)] px-2 py-1 text-xs hover:bg-[color:var(--color-surface-alt)] disabled:opacity-50"
                    >
                      {busyId === row.user_id ? '…' : 'Unlock'}
                    </button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function StatCard({
  label,
  value,
  suffix,
}: {
  label: string
  value: number | null | undefined
  suffix?: string
}) {
  const display =
    value === null || value === undefined
      ? '—'
      : suffix
        ? `${Math.round(value * 10) / 10}${suffix}`
        : String(value)
  return (
    <div className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-5">
      <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
        {label}
      </p>
      <p className="mt-2 text-2xl font-semibold">{display}</p>
    </div>
  )
}

function LockTypeBadge({ type }: { type: 'mfa' | 'risk' }) {
  const label = type === 'mfa' ? 'MFA lockout' : 'Risk lockout'
  return (
    <span className="rounded-full border border-[color:var(--color-risk-high)]/30 bg-[color:var(--color-risk-high)]/15 px-2 py-0.5 text-xs text-[color:var(--color-risk-high)]">
      {label}
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

function Th({ children }: { children: ReactNode }) {
  return <th className="px-4 py-2 font-medium">{children}</th>
}

function Td({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <td className={`px-4 py-2 align-middle ${className}`}>{children}</td>
}
