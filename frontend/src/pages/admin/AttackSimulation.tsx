import { PlaceholderCard } from '../../components/common/PlaceholderCard'

const SIMULATIONS = [
  'Simulate IP Change',
  'Simulate VPN',
  'Simulate Unknown Device',
  'Simulate Large Download',
  'Simulate Abnormal Requests',
  'Simulate Multiple Failed Login',
  'Simulate Session Termination',
]

export function AttackSimulation() {
  return (
    <div>
      <h1 className="text-2xl font-semibold">Attack Simulation</h1>
      <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
        Buttons below will call POST /api/v1/simulate/&#123;event_type&#125; and trigger
        the real backend security logic — never just change on-screen text.
      </p>

      <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2">
        {SIMULATIONS.map((label) => (
          <button
            key={label}
            disabled
            className="cursor-not-allowed rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-4 py-3 text-left text-sm text-[color:var(--color-text-muted)] opacity-60"
          >
            {label}
          </button>
        ))}
      </div>

      <div className="mt-6">
        <PlaceholderCard
          title="Attack simulation controls"
          module="Module 9 (Attack Simulation)"
          description="Disabled until Modules 5-7 exist for these buttons to actually affect."
        />
      </div>
    </div>
  )
}
