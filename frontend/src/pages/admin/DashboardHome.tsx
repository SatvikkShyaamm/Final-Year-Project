import { PlaceholderCard } from '../../components/common/PlaceholderCard'

const OVERVIEW_METRICS = [
  'Active Users',
  'Active Sessions',
  'Average Trust Score',
  'High-Risk Sessions',
  'MFA Requests',
  'Revoked Sessions',
  'Current ACL Rules',
  'Avg. Authorization Latency',
  'Avg. Revocation Latency',
]

export function DashboardHome() {
  return (
    <div>
      <h1 className="text-2xl font-semibold">Dashboard Home</h1>
      <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
        Real-time overview — populated once Modules 2-7 produce real sessions, trust
        scores, and ACL state to aggregate.
      </p>

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {OVERVIEW_METRICS.map((metric) => (
          <div
            key={metric}
            className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-5"
          >
            <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
              {metric}
            </p>
            <p className="mt-2 text-2xl font-semibold text-[color:var(--color-text-muted)]">—</p>
          </div>
        ))}
      </div>

      <div className="mt-6">
        <PlaceholderCard
          title="Overview data"
          module="Module 8 (Security Dashboard)"
          description="These cards will read live aggregates from the backend once sessions, trust scores, and ACL state exist to aggregate. They render the real metric names now so the layout doesn't need to change later."
        />
      </div>
    </div>
  )
}
