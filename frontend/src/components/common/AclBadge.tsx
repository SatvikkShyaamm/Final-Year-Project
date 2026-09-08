/**
 * Small pill for an ACL rule's state (Module 4). Used in the Live Sessions
 * ACL column and the ACL Monitor table so the colour mapping lives in one
 * place. Accepts the extra "none" sentinel the session view uses when a
 * session has no ACL rule.
 */
type AclDisplayState =
  | 'pending'
  | 'active'
  | 'removing'
  | 'removed'
  | 'failed'
  | 'none'

const STYLES: Record<AclDisplayState, string> = {
  active:
    'border-[color:var(--color-risk-low)]/30 bg-[color:var(--color-risk-low)]/15 text-[color:var(--color-risk-low)]',
  pending:
    'border-[color:var(--color-risk-medium)]/30 bg-[color:var(--color-risk-medium)]/15 text-[color:var(--color-risk-medium)]',
  removing:
    'border-[color:var(--color-risk-medium)]/30 bg-[color:var(--color-risk-medium)]/15 text-[color:var(--color-risk-medium)]',
  failed:
    'border-[color:var(--color-risk-high)]/30 bg-[color:var(--color-risk-high)]/15 text-[color:var(--color-risk-high)]',
  removed: 'border-[color:var(--color-border)] text-[color:var(--color-text-muted)]',
  none: 'border-[color:var(--color-border)] text-[color:var(--color-text-muted)]',
}

export function AclBadge({ state }: { state: string }) {
  const key = (state in STYLES ? state : 'none') as AclDisplayState
  const label = key === 'none' ? 'no ACL' : key
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs ${STYLES[key]}`}
    >
      {label}
    </span>
  )
}
