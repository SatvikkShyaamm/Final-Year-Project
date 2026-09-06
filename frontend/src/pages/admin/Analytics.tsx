import { PlaceholderCard } from '../../components/common/PlaceholderCard'

export function Analytics() {
  return (
    <div>
      <h1 className="text-2xl font-semibold">Analytics</h1>
      <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
        Login activity, trust score distribution, MFA events, revoked sessions,
        security alerts, risk levels, authorization/revocation latency — charted with
        Recharts once real data exists.
      </p>
      <div className="mt-6">
        <PlaceholderCard
          title="Analytics charts"
          module="Module 8 (Security Dashboard)"
          description="Recharts is already installed; charts are wired up once Modules 2-7 produce data to plot."
        />
      </div>
    </div>
  )
}
