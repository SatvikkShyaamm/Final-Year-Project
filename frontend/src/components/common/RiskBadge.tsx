import type { RiskLevel } from '../../types'

const STYLES: Record<RiskLevel, string> = {
  LOW: 'bg-[color:var(--color-risk-low)]/15 text-[color:var(--color-risk-low)] border-[color:var(--color-risk-low)]/30',
  MEDIUM:
    'bg-[color:var(--color-risk-medium)]/15 text-[color:var(--color-risk-medium)] border-[color:var(--color-risk-medium)]/30',
  HIGH: 'bg-[color:var(--color-risk-high)]/15 text-[color:var(--color-risk-high)] border-[color:var(--color-risk-high)]/30',
}

/**
 * Small reusable pill used everywhere a risk level is shown (live sessions
 * table, trust score panel, alerts feed, ...) so the color mapping only
 * lives in one place.
 */
export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${STYLES[level]}`}
    >
      {level}
    </span>
  )
}
