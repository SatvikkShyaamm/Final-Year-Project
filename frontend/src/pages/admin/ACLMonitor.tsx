import { PlaceholderCard } from '../../components/common/PlaceholderCard'

export function ACLMonitor() {
  return (
    <div>
      <h1 className="text-2xl font-semibold">ACL Monitor</h1>
      <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
        Active/removed ACL rules, user-to-resource mapping, creation and removal
        timestamps.
      </p>
      <div className="mt-6">
        <PlaceholderCard
          title="ACL rules table"
          module="Module 4 (Dynamic ACL Management)"
          description="Requires the ACL controller (ipset integration) to exist first."
        />
      </div>
    </div>
  )
}
