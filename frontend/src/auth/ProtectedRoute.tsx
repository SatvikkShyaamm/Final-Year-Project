import { Navigate, Outlet, useLocation } from 'react-router-dom'
import { useAuth } from './useAuth'

/**
 * Route guard (Module 2). Wrap route subtrees that require a logged-in user;
 * pass `requireAdmin` for the SOC dashboard, which is admin-only.
 *
 * While the persisted token is still being validated against /auth/me we
 * render a neutral placeholder rather than briefly flashing the login page.
 */
export function ProtectedRoute({ requireAdmin = false }: { requireAdmin?: boolean }) {
  const { status, isAdmin } = useAuth()
  const location = useLocation()

  if (status === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[color:var(--color-bg)] text-sm text-[color:var(--color-text-muted)]">
        Checking session…
      </div>
    )
  }

  if (status === 'unauthenticated') {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  if (requireAdmin && !isAdmin) {
    // Authenticated but not authorised for the admin area — send to the portal.
    return <Navigate to="/portal" replace />
  }

  return <Outlet />
}
