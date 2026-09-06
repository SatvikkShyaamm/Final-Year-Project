import { useEffect, useState } from 'react'
import { fetchHealth } from '../../api/health'
import type { HealthResponse } from '../../types'

/**
 * The one page in Module 1 that is NOT a placeholder: it calls the real
 * backend /health endpoint (live Postgres + Redis checks) and renders
 * whatever comes back. This is the actual proof, visible in the browser,
 * that frontend -> backend -> database/redis connectivity works end to end.
 */
export function SystemStatus() {
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const data = await fetchHealth()
      setHealth(data)
    } catch {
      setError(
        'Could not reach the backend at the configured VITE_API_BASE_URL. Is it running?',
      )
      setHealth(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  return (
    <div>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">System Status</h1>
          <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
            Live check against the backend's /api/v1/health endpoint.
          </p>
        </div>
        <button
          onClick={load}
          className="rounded-lg border border-[color:var(--color-border)] px-3 py-1.5 text-sm text-[color:var(--color-text)] hover:bg-[color:var(--color-surface-alt)]"
        >
          Refresh
        </button>
      </div>

      <div className="mt-6 rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6">
        {loading && <p className="text-sm text-[color:var(--color-text-muted)]">Checking…</p>}

        {!loading && error && (
          <p className="text-sm text-[color:var(--color-risk-high)]">{error}</p>
        )}

        {!loading && health && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <StatusRow label="Overall status" value={health.status} ok={health.status === 'ok'} />
            <StatusRow
              label="Database"
              value={health.dependencies.database}
              ok={health.dependencies.database === 'connected'}
            />
            <StatusRow
              label="Redis"
              value={health.dependencies.redis}
              ok={health.dependencies.redis === 'connected'}
            />
          </div>
        )}
      </div>
    </div>
  )
}

function StatusRow({ label, value, ok }: { label: string; value: string; ok: boolean }) {
  return (
    <div className="rounded-lg border border-[color:var(--color-border)] p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
        {label}
      </p>
      <p
        className={`mt-1 text-lg font-semibold ${
          ok ? 'text-[color:var(--color-risk-low)]' : 'text-[color:var(--color-risk-high)]'
        }`}
      >
        {value}
      </p>
    </div>
  )
}
