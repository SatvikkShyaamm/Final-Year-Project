/**
 * Placeholder for Module 2 — Authentication.
 *
 * Will POST to /api/v1/auth/login, store the returned JWT, and route into
 * either the risk-based MFA step (Module 6) or straight to the user
 * portal / admin dashboard.
 */
export function Login() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-[color:var(--color-bg)] text-[color:var(--color-text)]">
      <div className="w-full max-w-sm rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-8 text-center">
        <h1 className="text-xl font-semibold">Login</h1>
        <p className="mt-2 text-sm text-[color:var(--color-text-muted)]">
          Authentication is implemented in Module 2. This screen is a routing
          placeholder for now.
        </p>
      </div>
    </div>
  )
}
