import { Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../../auth/useAuth'
import { useSession } from '../../session/useSession'
import { Sidebar } from './Sidebar'

export function AdminLayout() {
  const { user, logout } = useAuth()
  const { socketStatus } = useSession()
  const navigate = useNavigate()

  async function handleLogout() {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex min-h-screen bg-[color:var(--color-bg)] text-[color:var(--color-text)]">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-8 py-3">
          <span className="text-sm text-[color:var(--color-text-muted)]">
            Zero Trust Security Operations
          </span>
          <div className="flex items-center gap-4 text-sm">
            <span
              className={`inline-flex items-center gap-1.5 text-xs ${
                socketStatus === 'connected'
                  ? 'text-[color:var(--color-risk-low)]'
                  : socketStatus === 'connecting'
                    ? 'text-[color:var(--color-risk-medium)]'
                    : 'text-[color:var(--color-text-muted)]'
              }`}
              title="Your session signalling WebSocket"
            >
              <span className="h-1.5 w-1.5 rounded-full bg-current" />
              session {socketStatus}
            </span>
            <span className="text-[color:var(--color-text-muted)]">
              {user?.username}
              <span className="ml-2 rounded-full border border-[color:var(--color-border)] px-2 py-0.5 text-xs uppercase tracking-wide">
                {user?.role}
              </span>
            </span>
            <button
              onClick={handleLogout}
              className="rounded-lg border border-[color:var(--color-border)] px-3 py-1.5 text-[color:var(--color-text)] hover:bg-[color:var(--color-surface-alt)]"
            >
              Log out
            </button>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-8">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
