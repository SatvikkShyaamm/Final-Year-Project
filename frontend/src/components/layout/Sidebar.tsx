import { NavLink } from 'react-router-dom'

/**
 * Admin dashboard navigation. Every section from the project spec (Module 8)
 * has a route from Module 1 onward, even though most bodies are placeholders
 * until their owning module lands.
 */
const NAV_ITEMS = [
  { to: '/admin', label: 'Dashboard Home', end: true },
  { to: '/admin/sessions', label: 'Live Sessions' },
  { to: '/admin/trust-score', label: 'Trust Score' },
  { to: '/admin/alerts', label: 'Security Alerts' },
  { to: '/admin/acl', label: 'ACL Monitor' },
  { to: '/admin/analytics', label: 'Analytics' },
  { to: '/admin/simulation', label: 'Attack Simulation' },
  { to: '/admin/status', label: 'System Status' },
]

export function Sidebar() {
  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-[color:var(--color-border)] bg-[color:var(--color-surface)]">
      <div className="px-5 py-5">
        <p className="text-sm font-semibold tracking-wide text-[color:var(--color-text)]">
          ZTSAACM
        </p>
        <p className="text-xs text-[color:var(--color-text-muted)]">Security Dashboard</p>
      </div>
      <nav className="flex-1 space-y-1 px-3">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `block rounded-lg px-3 py-2 text-sm transition-colors ${
                isActive
                  ? 'bg-[color:var(--color-accent)]/15 text-[color:var(--color-accent)]'
                  : 'text-[color:var(--color-text-muted)] hover:bg-[color:var(--color-surface-alt)] hover:text-[color:var(--color-text)]'
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
      <div className="border-t border-[color:var(--color-border)] px-5 py-4 text-xs text-[color:var(--color-text-muted)]">
        Module 3 — Session Lifecycle
      </div>
    </aside>
  )
}
