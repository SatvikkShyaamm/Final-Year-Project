import { PlaceholderCard } from '../../components/common/PlaceholderCard'

export function SecurityAlerts() {
  return (
    <div>
      <h1 className="text-2xl font-semibold">Security Alerts</h1>
      <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
        IP changes, VPN detections, unknown devices, abnormal request rates, large
        downloads, failed logins, MFA events, ACL removals, session revocations.
      </p>
      <div className="mt-6">
        <PlaceholderCard
          title="Alerts feed"
          module="Module 7 (Continuous Trust Evaluation) + Module 9"
          description="Requires continuous monitoring and attack simulation to generate real events."
        />
      </div>
    </div>
  )
}
