import { useState } from 'react'
import type { FormEvent } from 'react'
import { axiosErrorDetail, verifyMfa } from '../api/auth'
import type { MFAChallenge } from '../types'

/**
 * Module 7 — continuous trust re-verification prompt.
 *
 * The backend pushes a `trust.reverify_required` message down this tab's own
 * signalling WebSocket when a mid-session security event (an unrecognised
 * VPN, an IP change, an abnormal request rate, ...) drops this session's
 * live trust score into MEDIUM risk (see docs/architecture.md's Module 7
 * section). Completing it reuses the exact same emailed one-time-code
 * mechanism as the Module 6 login step (`POST /mfa/verify`) -- there is no
 * separate re-verification method, and TOTP is never reintroduced here.
 *
 * Failing, exhausting, or simply ignoring this prompt revokes the session
 * server-side; SessionProvider's existing `onTerminated` handling (force
 * logout back to /login) takes over from there exactly as it does for any
 * other server-driven end -- this component doesn't need to know about that
 * path at all.
 */
export function ReverifyModal({
  challenge,
  onVerified,
}: {
  challenge: MFAChallenge
  onVerified: () => void
}) {
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await verifyMfa({ mfa_token: challenge.mfa_token, code: code.trim() })
      onVerified()
    } catch (err) {
      const detail = axiosErrorDetail(err)
      const codeErr =
        detail && typeof detail === 'object' && 'code' in detail
          ? String((detail as { code: unknown }).code)
          : null
      if (codeErr === 'expired' || codeErr === 'exhausted') {
        setError(
          codeErr === 'expired'
            ? 'This verification request timed out — the session is being ended.'
            : 'Too many incorrect codes — the session is being ended.',
        )
      } else {
        const left =
          detail && typeof detail === 'object' && 'attempts_remaining' in detail
            ? Number((detail as { attempts_remaining: unknown }).attempts_remaining)
            : null
        setError(
          `Invalid code${left != null ? ` — ${left} attempt${left === 1 ? '' : 's'} left` : ''}.`,
        )
      }
      setCode('')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4">
      <div className="w-full max-w-sm rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6 text-[color:var(--color-text)]">
        <h2 className="text-lg font-semibold">Re-verify it's you</h2>
        <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
          Trust score {challenge.trust_score ?? '—'} ·{' '}
          <span className="text-[color:var(--color-risk-medium)]">
            {challenge.risk_level ?? 'elevated risk'}
          </span>{' '}
          — something changed on this session, so we emailed a fresh verification
          code to your registered address.
        </p>

        <form onSubmit={handleSubmit} className="mt-5 space-y-4">
          <label className="block">
            <span className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
              6-digit code
            </span>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 8))}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              required
              className="mt-1 w-full rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-bg)] px-3 py-2 text-center font-mono text-lg tracking-[0.3em] text-[color:var(--color-text)] outline-none focus:border-[color:var(--color-accent)]"
            />
          </label>

          {challenge.dev_code && (
            <p className="text-xs text-[color:var(--color-text-muted)]">
              dev environment (no SMTP configured) — current code:{' '}
              <span className="font-mono">{challenge.dev_code}</span>
            </p>
          )}

          {error && <p className="text-sm text-[color:var(--color-risk-high)]">{error}</p>}

          <button
            type="submit"
            disabled={submitting || code.length < 6}
            className="w-full rounded-lg bg-[color:var(--color-accent)] px-3 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {submitting ? 'Verifying…' : 'Verify'}
          </button>
        </form>
      </div>
    </div>
  )
}
