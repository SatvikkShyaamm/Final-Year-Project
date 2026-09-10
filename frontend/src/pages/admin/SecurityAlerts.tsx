import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { listMfaChallenges } from '../../api/mfa'
import { RiskBadge } from '../../components/common/RiskBadge'
import type { MFAChallengeListResponse, MFAChallengeRecord } from '../../types'

/**
 * Module 6 makes this page real for the first time: the MFA events feed
 * (challenge triggered / verified / failed / expired), from
 * GET /api/v1/mfa/challenges. IP-change / VPN / large-download / session-revoked
 * alerts arrive with Modules 7-9 and will fold into this same feed.
 */
const POLL_MS = 5000

export function SecurityAlerts() {
  const [data, setData] = useState<MFAChallengeListResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setData(await listMfaChallenges())
      setError(null)
    } catch {
      setError('Could not load MFA events from the backend.')
    }
  }, [])

  useEffect(() => {
    void load()
    const t = window.setInterval(() => void load(), POLL_MS)
    return () => window.clearInterval(t)
  }, [load])

  const rows = data?.challenges ?? []
  const counts = data?.counts ?? {}

  return (
    <div>
      <h1 className="text-2xl font-semibold">Security Alerts</h1>
      <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
        Adaptive MFA events (Module 6). IP change, VPN, unknown device, abnormal
        requests, large download and session-revoked alerts join this feed with
        Modules 7-9.
      </p>

      {error && (
        <p className="mt-4 text-sm text-[color:var(--color-risk-high)]">{error}</p>
      )}

      <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Triggered" value={rows.length} />
        <Stat label="Pending" value={counts.pending ?? 0} />
        <Stat label="Verified" value={counts.verified ?? 0} tone="low" />
        <Stat
          label="Failed / expired"
          value={(counts.failed ?? 0) + (counts.expired ?? 0)}
          tone="high"
        />
      </div>

      <div className="mt-6 overflow-x-auto rounded-xl border border-[color:var(--color-border)]">
        <table className="w-full min-w-[820px] text-left text-sm">
          <thead className="bg-[color:var(--color-surface)] text-xs uppercase tracking-wide text-[color:var(--color-text-muted)]">
            <tr>
              <Th>Time</Th>
              <Th>User</Th>
              <Th>Trigger</Th>
              <Th>Trust / Risk</Th>
              <Th>Status</Th>
              <Th>Attempts</Th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td
                  colSpan={6}
                  className="px-4 py-8 text-center text-[color:var(--color-text-muted)]"
                >
                  No MFA events yet. A MEDIUM-risk login raises one.
                </td>
              </tr>
            )}
            {rows.map((c) => (
              <Row key={c.id} c={c} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Row({ c }: { c: MFAChallengeRecord }) {
  return (
    <tr className="border-t border-[color:var(--color-border)] bg-[color:var(--color-bg)]">
      <Td>{new Date(c.created_at + 'Z').toLocaleTimeString()}</Td>
      <Td>{c.username ?? `#${c.user_id}`}</Td>
      <Td className="text-xs">{c.reason}</Td>
      <Td>
        <span className="tabular-nums">{c.trust_score ?? '—'}</span>
        {c.risk_level && <span className="ml-2"><RiskBadge level={c.risk_level} /></span>}
      </Td>
      <Td>
        <StatusBadge status={c.status} />
      </Td>
      <Td className="tabular-nums">
        {c.attempts}/{c.max_attempts}
      </Td>
    </tr>
  )
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    verified:
      'border-[color:var(--color-risk-low)]/30 bg-[color:var(--color-risk-low)]/15 text-[color:var(--color-risk-low)]',
    pending:
      'border-[color:var(--color-risk-medium)]/30 bg-[color:var(--color-risk-medium)]/15 text-[color:var(--color-risk-medium)]',
    failed:
      'border-[color:var(--color-risk-high)]/30 bg-[color:var(--color-risk-high)]/15 text-[color:var(--color-risk-high)]',
    expired: 'border-[color:var(--color-border)] text-[color:var(--color-text-muted)]',
  }
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs ${
        map[status] ?? map.expired
      }`}
    >
      {status}
    </span>
  )
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string
  value: number
  tone?: 'low' | 'high'
}) {
  const color =
    tone === 'low'
      ? 'text-[color:var(--color-risk-low)]'
      : tone === 'high'
        ? 'text-[color:var(--color-risk-high)]'
        : 'text-[color:var(--color-text)]'
  return (
    <div className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
        {label}
      </p>
      <p className={`mt-1 text-lg font-semibold ${color}`}>{value}</p>
    </div>
  )
}

function Th({ children }: { children: ReactNode }) {
  return <th className="px-4 py-2 font-medium">{children}</th>
}

function Td({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <td className={`px-4 py-2 align-middle ${className}`}>{children}</td>
}
