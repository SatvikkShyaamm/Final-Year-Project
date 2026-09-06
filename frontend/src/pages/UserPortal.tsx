import { useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'

/**
 * End-user portal. Module 2 makes it a real authenticated page: it shows who
 * you are signed in as and lets you log out. Session status, trust score, and
 * access grant/restrict/revoke state are layered on here by Modules 3, 5, 6.
 */
export function UserPortal() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  async function handleLogout() {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="mx-auto max-w-2xl p-8 text-[color:var(--color-text)]">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">User Portal</h1>
        <button
          onClick={handleLogout}
          className="rounded-lg border border-[color:var(--color-border)] px-3 py-1.5 text-sm hover:bg-[color:var(--color-surface-alt)]"
        >
          Log out
        </button>
      </div>

      <div className="mt-6 rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6">
        <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
          Signed in as
        </p>
        <p className="mt-1 text-lg font-semibold">{user?.username}</p>
        <p className="text-sm text-[color:var(--color-text-muted)]">{user?.email}</p>
        <p className="mt-2 text-xs text-[color:var(--color-text-muted)]">
          Role: {user?.role}
        </p>
      </div>

      <p className="mt-6 text-sm text-[color:var(--color-text-muted)]">
        Session status, trust score, and access state will appear here once
        Modules 3, 5, and 6 are implemented.
      </p>
    </div>
  )
}
