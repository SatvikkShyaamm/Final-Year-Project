import { PlaceholderCard } from '../../components/common/PlaceholderCard'

export function TrustScorePage() {
  return (
    <div>
      <h1 className="text-2xl font-semibold">Trust Score Monitoring</h1>
      <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
        Current score, risk level, score history, and the weighted factors behind each
        score (known device, known IP, VPN detected, abnormal behaviour, ...).
      </p>
      <div className="mt-6">
        <PlaceholderCard
          title="Trust score panel"
          module="Module 5 (Trust Score Engine)"
          description="Requires the trust score calculation and storage to exist first."
        />
      </div>
    </div>
  )
}
