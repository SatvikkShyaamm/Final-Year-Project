import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { getDashboardAnalytics } from '../../api/dashboard'
import { useDashboardSocket } from '../../ws/useDashboardSocket'
import type { CountBucket, DashboardAnalytics } from '../../types'

/**
 * Module 8 — Analytics. Section 5's charts, all real counts over Modules
 * 2-7's own rows (GET /dashboard/analytics) — there is no synthetic/sample
 * data path here (see app/services/dashboard/service.py's own docstring on
 * why a multi-day failed-login trend is intentionally absent rather than
 * fabricated). Polls on an interval and also refetches on a live
 * `/ws/dashboard` push, same pattern as Dashboard Home.
 */
const POLL_MS = 5000
const CHART_COLOR = 'var(--color-accent)'

export function Analytics() {
  const [data, setData] = useState<DashboardAnalytics | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { tick } = useDashboardSocket()

  const load = useCallback(async () => {
    try {
      setData(await getDashboardAnalytics(14))
      setError(null)
    } catch {
      setError('Could not load analytics from the backend.')
    }
  }, [])

  useEffect(() => {
    void load()
    const timer = window.setInterval(() => void load(), POLL_MS)
    return () => window.clearInterval(timer)
  }, [load])

  useEffect(() => {
    if (tick > 0) void load()
  }, [tick, load])

  return (
    <div>
      <h1 className="text-2xl font-semibold">Analytics</h1>
      

      {error && <p className="mt-4 text-sm text-[color:var(--color-risk-high)]">{error}</p>}

      {!data ? (
        <p className="mt-6 text-sm text-[color:var(--color-text-muted)]">Loading…</p>
      ) : (
        <div className="mt-6 grid gap-4 lg:grid-cols-2">
          <ChartCard title="Login activity" subtitle="Sessions opened per day, last 14 days" full>
            <LineTrend data={data.login_activity} />
          </ChartCard>

          <ChartCard title="ACL latency" subtitle="Live averages">
            <div className="grid grid-cols-2 gap-4">
              <LatencyStat label="Authorization" value={data.avg_authorization_latency_ms} />
              <LatencyStat label="Revocation" value={data.avg_revocation_latency_ms} />
            </div>
          </ChartCard>

          <ChartCard title="Risk levels" subtitle="Active sessions, current band">
            <BarBreakdown data={data.risk_levels} />
          </ChartCard>

          <ChartCard title="Trust score distribution" subtitle="Active sessions, 10-point buckets">
            <BarBreakdown data={data.trust_score_distribution} />
          </ChartCard>

          <ChartCard title="MFA events" subtitle="mfa_challenges by status">
            <BarBreakdown data={data.mfa_events} />
          </ChartCard>

          <ChartCard title="Revoked sessions" subtitle="Terminated sessions by reason">
            <BarBreakdown data={data.revoked_sessions} />
          </ChartCard>

          <ChartCard title="Security alerts" subtitle="Continuous-evaluation events by type" full>
            <BarBreakdown data={data.security_alerts} />
          </ChartCard>
        </div>
      )}
    </div>
  )
}

function ChartCard({
  title,
  subtitle,
  full,
  children,
}: {
  title: string
  subtitle: string
  full?: boolean
  children: ReactNode
}) {
  return (
    <div
      className={`rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-5 ${
        full ? 'lg:col-span-2' : ''
      }`}
    >
      <p className="text-sm font-semibold">{title}</p>
      <p className="text-xs text-[color:var(--color-text-muted)]">{subtitle}</p>
      <div className="mt-3 h-56">{children}</div>
    </div>
  )
}

function BarBreakdown({ data }: { data: CountBucket[] }) {
  if (data.every((d) => d.count === 0)) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-[color:var(--color-text-muted)]">
        No data yet.
      </div>
    )
  }
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: -16 }}>
        <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" />
        <XAxis dataKey="label" stroke="var(--color-text-muted)" fontSize={10} interval={0} angle={-20} textAnchor="end" height={40} />
        <YAxis allowDecimals={false} stroke="var(--color-text-muted)" fontSize={11} />
        <Tooltip
          contentStyle={{
            background: 'var(--color-surface-alt)',
            border: '1px solid var(--color-border)',
            fontSize: 12,
          }}
        />
        <Bar dataKey="count" fill={CHART_COLOR} radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

function LineTrend({ data }: { data: CountBucket[] }) {
  if (data.every((d) => d.count === 0)) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-[color:var(--color-text-muted)]">
        No sessions opened in this window yet.
      </div>
    )
  }
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: -16 }}>
        <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" />
        <XAxis dataKey="label" stroke="var(--color-text-muted)" fontSize={10} />
        <YAxis allowDecimals={false} stroke="var(--color-text-muted)" fontSize={11} />
        <Tooltip
          contentStyle={{
            background: 'var(--color-surface-alt)',
            border: '1px solid var(--color-border)',
            fontSize: 12,
          }}
        />
        <Line type="monotone" dataKey="count" stroke={CHART_COLOR} strokeWidth={2} dot={{ r: 3 }} />
      </LineChart>
    </ResponsiveContainer>
  )
}

function LatencyStat({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="rounded-lg border border-[color:var(--color-border)] p-4 text-center">
      <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
        {label}
      </p>
      <p className="mt-1 text-2xl font-semibold">{value != null ? `${value} ms` : '—'}</p>
    </div>
  )
}
