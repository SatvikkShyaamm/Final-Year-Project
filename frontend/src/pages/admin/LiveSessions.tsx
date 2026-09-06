import { PlaceholderCard } from '../../components/common/PlaceholderCard'

export function LiveSessions() {
  return (
    <div>
      <h1 className="text-2xl font-semibold">Live Session Monitoring</h1>
      <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
        Username · Session ID · IP · Device · Login time · Duration · Trust Score · Risk
        Level · WebSocket Status · ACL Status · Current Action
      </p>
      <div className="mt-6">
        <PlaceholderCard
          title="Live sessions table"
          module="Module 3 (Session Lifecycle) + Module 8"
          description="Requires real WebSocket sessions to exist first."
        />
      </div>
    </div>
  )
}
