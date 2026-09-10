import { useState } from 'react'
import type { FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { authErrorMessage, axiosErrorDetail } from '../api/auth'
import { useAuth } from '../auth/useAuth'
import type { MFAChallenge, User } from '../types'

/**
 * Module 2 auth entry point + the Module 6 MFA step.
 *
 * Credentials -> POST /auth/login. The backend replies with a trust-score
 * decision: an access token (LOW risk), an MFA challenge (MEDIUM), or 403
 * (HIGH). A first-ever login has no history and always lands in MEDIUM. Every
 * MFA challenge — the first one and every one after — is a one-time code
 * emailed to the address the user registered with; there is no authenticator
 * app (TOTP was removed 2026-09-10 — see Project status.md section 11).
 */
type Mode = 'login' | 'register'
type Step = 'credentials' | 'mfa' | 'restart'

export function Login() {
  const { login, verifyMfa, register } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const redirectTo = (location.state as { from?: string } | null)?.from ?? null

  const [mode, setMode] = useState<Mode>('login')
  const [step, setStep] = useState<Step>('credentials')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [challenge, setChallenge] = useState<MFAChallenge | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  function routeOnward(user: User) {
    navigate(
      redirectTo ?? (user.role === 'admin' ? '/admin' : '/portal'),
      { replace: true },
    )
  }

  function resetToCredentials() {
    setStep('credentials')
    setChallenge(null)
    setCode('')
    setError(null)
  }

  async function handleCredentials(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      if (mode === 'register') {
        routeOnward(await register({ username, email, password }))
        return
      }
      const outcome = await login({ username, password })
      if (outcome.kind === 'authenticated') {
        routeOnward(outcome.user)
      } else {
        setChallenge(outcome.challenge)
        setStep('mfa')
      }
    } catch (err) {
      setError(
        authErrorMessage(
          err,
          mode === 'login'
            ? 'Login failed. Check your username and password.'
            : 'Registration failed. Try a different username or email.',
        ),
      )
    } finally {
      setSubmitting(false)
    }
  }

  async function handleVerify(event: FormEvent) {
    event.preventDefault()
    if (!challenge) return
    setError(null)
    setSubmitting(true)
    try {
      routeOnward(await verifyMfa(challenge.mfa_token, code.trim()))
    } catch (err) {
      const detail = axiosErrorDetail(err)
      const codeErr =
        detail && typeof detail === 'object' && 'code' in detail
          ? String((detail as { code: unknown }).code)
          : null
      if (codeErr === 'expired' || codeErr === 'exhausted') {
        setError(
          codeErr === 'expired'
            ? 'That verification request timed out. Please sign in again.'
            : 'Too many incorrect codes. Please sign in again.',
        )
        setStep('restart')
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

  const mustStartOver = step === 'restart'

  return (
    <div className="flex min-h-screen items-center justify-center bg-[color:var(--color-bg)] px-4 text-[color:var(--color-text)]">
      <div className="w-full max-w-sm rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-8">
        <div className="mb-6 text-center">
          <p className="text-sm font-semibold tracking-wide">ZTSAACM</p>
          <p className="text-xs text-[color:var(--color-text-muted)]">Security Dashboard</p>
        </div>

        {step === 'credentials' && (
          <>
            <h1 className="text-lg font-semibold">
              {mode === 'login' ? 'Sign in' : 'Create an account'}
            </h1>
            <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
              {mode === 'login'
                ? 'Authenticate to open a Zero Trust session.'
                : 'The first account created becomes the administrator.'}
            </p>

            <form onSubmit={handleCredentials} className="mt-6 space-y-4">
              <Field label="Username" value={username} onChange={setUsername}
                autoComplete="username" required />
              {mode === 'register' && (
                <Field label="Email" type="email" value={email} onChange={setEmail}
                  autoComplete="email" required />
              )}
              <Field label="Password" type="password" value={password} onChange={setPassword}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'} required />

              {error && <p className="text-sm text-[color:var(--color-risk-high)]">{error}</p>}

              <button type="submit" disabled={submitting}
                className="w-full rounded-lg bg-[color:var(--color-accent)] px-3 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50">
                {submitting ? 'Please wait…' : mode === 'login' ? 'Sign in' : 'Create account'}
              </button>
            </form>

            <button type="button"
              onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(null) }}
              className="mt-4 w-full text-center text-xs text-[color:var(--color-text-muted)] hover:text-[color:var(--color-text)]">
              {mode === 'login' ? 'No account yet? Register' : 'Already registered? Sign in'}
            </button>
          </>
        )}

        {step === 'mfa' && challenge && (
          <>
            <h1 className="text-lg font-semibold">Verify it's you</h1>
            <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
              Trust score {challenge.trust_score ?? '—'} ·{' '}
              <span className="text-[color:var(--color-risk-medium)]">
                {challenge.risk_level ?? 'elevated risk'}
              </span>{' '}
              — we emailed a verification code to your registered address.
            </p>

            <form onSubmit={handleVerify} className="mt-5 space-y-4">
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

              <button type="submit" disabled={submitting || code.length < 6}
                className="w-full rounded-lg bg-[color:var(--color-accent)] px-3 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50">
                {submitting ? 'Verifying…' : 'Verify'}
              </button>
            </form>

            <button type="button" onClick={resetToCredentials}
              className="mt-4 w-full text-center text-xs text-[color:var(--color-text-muted)] hover:text-[color:var(--color-text)]">
              ← Back to sign in
            </button>
          </>
        )}

        {mustStartOver && (
          <>
            <h1 className="text-lg font-semibold">Verification needed again</h1>
            {error && <p className="mt-2 text-sm text-[color:var(--color-risk-high)]">{error}</p>}
            <button type="button" onClick={resetToCredentials}
              className="mt-5 w-full rounded-lg bg-[color:var(--color-accent)] px-3 py-2 text-sm font-medium text-white hover:opacity-90">
              Start over
            </button>
          </>
        )}
      </div>
    </div>
  )
}

function Field({
  label,
  value,
  onChange,
  type = 'text',
  autoComplete,
  required,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  type?: string
  autoComplete?: string
  required?: boolean
}) {
  return (
    <label className="block">
      <span className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
        {label}
      </span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={autoComplete}
        required={required}
        className="mt-1 w-full rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-bg)] px-3 py-2 text-sm text-[color:var(--color-text)] outline-none focus:border-[color:var(--color-accent)]"
      />
    </label>
  )
}
