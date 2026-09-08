import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { getAclStatus, listAclRules } from '../../api/acl'
import { AclBadge } from '../../components/common/AclBadge'
import type { ACLRule, ACLRuleListResponse, ACLStatusResponse } from '../../types'

/**
 * Module 4 — real ACL Monitor. Polls the backend's ACL rule records and the
 * enforcement-plane status. Every row here is a persisted acl_rules row bound
 * to a session; nothing is UI-only.
 */
const POLL_MS = 5000

export function ACLMonitor() {
  const [data, setData] = useState<ACLRuleListResponse | null>(null)
  const [status, setStatus] = useState<ACLStatusResponse | null>(null)
  const [includeRemoved, setIncludeRemoved] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const [rules, st] = await Promise.all([
        listAclRules({ includeRemoved }),
        getAclStatus(),
      ])
      setData(rules)
      setStatus(st)
      setError(null)
    } catch {
      setError('Could not load ACL state from the backend.')
    }
  }, [includeRemoved])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), POLL_MS)
    return () => window.clearInterval(timer)
  }, [load])

  const rules = data?.rules ?? []

  return (
    <div>
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold">ACL Monitor</h1>
          <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
            Session-bound network allow-list entries · auto-refreshing
          </p>
        </div>
        <label className="flex items-center gap-2 text-xs text-[color:var(--color-text-muted)]">
          <input
            type="checkbox"
            checked={includeRemoved}
            onChange={(e) => setIncludeRemoved(e.target.checked)}
          />
          show removed
        </label>
      </div>

      {error && (
        <p className="mt-4 text-sm text-[color:var(--color-risk-high)]">{error}</p>
      )}

      <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        <Stat label="Enforcement" value={status?.enforcement_backend ?? '…'} />
        <Stat
          label="L-PEP worker"
          value={
            status
              ? status.worker_enabled
                ? 'in-process'
                : 'external'
              : '…'
          }
        />
        <Stat label="Queue depth" value={status ? String(status.queue_depth) : '…'} />
        <Stat label="Active rules" value={data ? String(data.active_count) : '…'} />
        <Stat
          label="Avg auth latency"
          value={fmtMs(data?.avg_authorization_latency_ms)}
        />
        <Stat
          label="Avg revoke latency"
          value={fmtMs(data?.avg_revocation_latency_ms)}
        />
      </div>

      <div className="mt-6 overflow-x-auto rounded-xl border border-[color:var(--color-border)]">
        <table className="w-full min-w-[1000px] text-left text-sm">
          <thead className="bg-[color:var(--color-surface)] text-xs uppercase tracking-wide text-[color:var(--color-text-muted)]">
            <tr>
              <Th>Rule</Th>
              <Th>User</Th>
              <Th>Client IP</Th>
              <Th>Resource</Th>
              <Th>ipset</Th>
              <Th>State</Th>
              <Th>Enforcement</Th>
              <Th>Created</Th>
              <Th>Removed</Th>
              <Th>Auth ms</Th>
              <Th>Revoke ms</Th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 && (
              <tr>
                <td
                  colSpan={11}
                  className="px-4 py-8 text-center text-[color:var(--color-text-muted)]"
                >
                  No ACL rules. They are created automatically when a session
                  opens.
                </td>
              </tr>
            )}
            {rules.map((r) => (
              <Row key={r.id} rule={r} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Row({ rule }: { rule: ACLRule }) {
  return (
    <tr className="border-t border-[color:var(--color-border)] bg-[color:var(--color-bg)]">
      <Td className="font-mono text-xs" title={`session ${rule.session_id}`}>
        {rule.id.slice(0, 10)}…
      </Td>
      <Td>{rule.username ?? `#${rule.user_id}`}</Td>
      <Td className="font-mono text-xs">{rule.client_ip}</Td>
      <Td>{rule.resource}</Td>
      <Td className="font-mono text-xs">{rule.ipset_name}</Td>
      <Td title={rule.last_error ?? undefined}>
        <AclBadge state={rule.state} />
        {rule.removal_reason && (
          <span className="ml-2 text-xs text-[color:var(--color-text-muted)]">
            {rule.removal_reason}
          </span>
        )}
      </Td>
      <Td>{rule.enforcement}</Td>
      <Td>{new Date(rule.created_at + 'Z').toLocaleTimeString()}</Td>
      <Td>
        {rule.removed_at
          ? new Date(rule.removed_at + 'Z').toLocaleTimeString()
          : '—'}
      </Td>
      <Td>{rule.authorization_latency_ms ?? '—'}</Td>
      <Td>{rule.revocation_latency_ms ?? '—'}</Td>
    </tr>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
        {label}
      </p>
      <p className="mt-1 text-lg font-semibold">{value}</p>
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

function fmtMs(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—'
  return `${value.toFixed(1)} ms`
}
