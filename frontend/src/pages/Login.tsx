import { useState } from 'react'
import type { FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { authErrorMessage } from '../api/auth'
import { useAuth } from '../auth/useAuth'
import type { User } from '../types'

/**
 * Module 2 — Authentication entry point.
 *
 * POSTs to /api/v1/auth/login (or /register), the auth context stores the
 * returned JWT, and we route on by role: admins into the SOC dashboard,
 * everyone else into the user portal. Modules 5/6 will insert a risk check
 * and an optional MFA step between "credentials accepted" and this redirect.
 */
type Mode = 'login' | 'register'

export function Login() {
  const { login, register } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const redirectTo = (location.state as { from?: string } | null)?.from ?? null

  const [mode, setMode] = useState<Mode>('login')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  function routeOnward(user: User) {
    if (redirectTo) {
      navigate(redirectTo, { replace: true })
    } else {
      navigate(user.role === 'admin' ? '/admin' : '/portal', { replace: true })
    }
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      const user =
        mode === 'login'
          ? await login({ username, password })
          : await register({ username, email, password })
      routeOnward(user)
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

  return (
    <div className="flex min-h-screen items-center justify-center bg-[color:var(--color-bg)] px-4 text-[color:var(--color-text)]">
      <div className="w-full max-w-sm rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-8">
        <div className="mb-6 text-center">
          <p className="text-sm font-semibold tracking-wide">ZTSAACM</p>
          <p className="text-xs text-[color:var(--color-text-muted)]">Security Dashboard</p>
        </div>

        <h1 className="text-lg font-semibold">
          {mode === 'login' ? 'Sign in' : 'Create an account'}
        </h1>
        <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
          {mode === 'login'
            ? 'Authenticate to open a Zero Trust session.'
            : 'The first account created becomes the administrator.'}
        </p>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <Field
            label="Username"
            value={username}
            onChange={setUsername}
            autoComplete="username"
            required
          />

          {mode === 'register' && (
            <Field
              label="Email"
              type="email"
              value={email}
              onChange={setEmail}
              autoComplete="email"
              required
            />
          )}

          <Field
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
            required
          />

          {error && (
            <p className="text-sm text-[color:var(--color-risk-high)]">{error}</p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-lg bg-[color:var(--color-accent)] px-3 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {submitting
              ? 'Please wait…'
              : mode === 'login'
                ? 'Sign in'
                : 'Create account'}
          </button>
        </form>

        <button
          type="button"
          onClick={() => {
            setMode(mode === 'login' ? 'register' : 'login')
            setError(null)
          }}
          className="mt-4 w-full text-center text-xs text-[color:var(--color-text-muted)] hover:text-[color:var(--color-text)]"
        >
          {mode === 'login'
            ? "No account yet? Register"
            : 'Already registered? Sign in'}
        </button>
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
