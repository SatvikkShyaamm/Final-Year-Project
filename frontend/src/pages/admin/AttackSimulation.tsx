import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { listSimulationScenarios, runSimulation } from '../../api/simulation'
import { listSessions } from '../../api/sessions'
import { RiskBadge } from '../../components/common/RiskBadge'
import type {
  RiskLevel,
  Session,
  SimulationResult,
  SimulationScenarioInfo,
  SimulationScenarioKey,
} from '../../types'

/**
 * Module 9 — Attack Simulation. Every button below calls
 * POST /api/v1/simulate/{scenario} and triggers the real backend logic --
 * Module 7's continuous evaluation (score recompute, re-verify, revoke,
 * account-lockout escalation, all unchanged) or Module 3's session
 * termination -- never just changes on-screen text. See
 * backend/app/services/simulation for exactly which existing function each
 * scenario calls; "Simulate Multiple Failed Login" in particular drives the
 * real Section-27 detector against every active session on the target
 * account, not a synthetic shortcut.
 *
 * This is a dedicated, polished surface alongside (not instead of)
 * LiveSessions.tsx's own per-row "Simulate (Module 7)" control -- that one
 * stays as a quick single-event tester; this page is Section 5's actual
 * eight named scenarios, including the two dedicated VPN buttons and the
 * two scenarios (failed_login, session_termination) LiveSessions doesn't
 * offer at all.
 */
const SESSION_POLL_MS = 5000

export function AttackSimulation() {
  const [scenarios, setScenarios] = useState<SimulationScenarioInfo[]>([])
  const [sessions, setSessions] = useState<Session[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [busyScenario, setBusyScenario] = useState<SimulationScenarioKey | null>(null)
  const [history, setHistory] = useState<SimulationResult[]>([])
  const [error, setError] = useState<string | null>(null)

  const loadSessions = useCallback(async () => {
    try {
      const data = await listSessions(false)
      setSessions(data.sessions)
      setSelectedId((cur) =>
        cur && data.sessions.some((s) => s.id === cur) ? cur : (data.sessions[0]?.id ?? null),
      )
    } catch {
      setError('Could not load active sessions from the backend.')
    }
  }, [])

  useEffect(() => {
    void loadSessions()
    void listSimulationScenarios()
      .then((r) => setScenarios(r.scenarios))
      .catch(() => setError('Could not load the simulation scenario catalogue.'))
    const timer = window.setInterval(() => void loadSessions(), SESSION_POLL_MS)
    return () => window.clearInterval(timer)
  }, [loadSessions])

  async function handleRun(scenario: SimulationScenarioKey) {
    if (!selectedId) return
    setBusyScenario(scenario)
    setError(null)
    try {
      const result = await runSimulation(scenario, selectedId)
      setHistory((h) => [result, ...h].slice(0, 20))
      await loadSessions()
    } catch (err) {
      const detail =
        typeof err === 'object' && err !== null && 'response' in err
          ? (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
          : null
      setError(typeof detail === 'string' ? detail : 'That simulation could not be run.')
    } finally {
      setBusyScenario(null)
    }
  }

  const selectedSession = sessions.find((s) => s.id === selectedId) ?? null

  return (
    <div>
      <h1 className="text-2xl font-semibold">Attack Simulation</h1>
      <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
        Buttons below call <code className="rounded bg-[color:var(--color-surface-alt)] px-1">
          POST /api/v1/simulate/&#123;scenario&#125;
        </code>{' '}
        and trigger the real backend security logic against the selected session
        — never just on-screen text.
      </p>

      {error && <p className="mt-4 text-sm text-[color:var(--color-risk-high)]">{error}</p>}

      <div className="mt-6 rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-5">
        <label className="block text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
          Target session
        </label>
        <select
          value={selectedId ?? ''}
          onChange={(e) => setSelectedId(e.target.value || null)}
          className="mt-2 w-full max-w-md rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-bg)] px-3 py-2 text-sm text-[color:var(--color-text)]"
        >
          {sessions.length === 0 && <option value="">no active sessions</option>}
          {sessions.map((s) => (
            <option key={s.id} value={s.id}>
              {(s.username ?? `#${s.user_id}`) + ' · ' + s.id.slice(0, 8) + '…'}
            </option>
          ))}
        </select>
        {selectedSession && (
          <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-4">
            <Row label="Trust score" value={selectedSession.trust_score ?? '—'} />
            <Row
              label="Risk"
              value={
                selectedSession.risk_level ? (
                  <RiskBadge level={selectedSession.risk_level} />
                ) : (
                  '—'
                )
              }
            />
            <Row label="ACL" value={selectedSession.acl_status ?? 'none'} />
            <Row label="Action" value={selectedSession.current_action ?? '—'} />
          </dl>
        )}
      </div>

      <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2">
        {scenarios.map(({ scenario, label }) => (
          <button
            key={scenario}
            onClick={() => handleRun(scenario)}
            disabled={!selectedId || busyScenario !== null}
            className="rounded-lg border border-[color:var(--color-border)] bg-[color:var(--color-surface)] px-4 py-3 text-left text-sm hover:bg-[color:var(--color-surface-alt)] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busyScenario === scenario ? '…running' : label}
          </button>
        ))}
      </div>

      <div className="mt-8">
        <h2 className="text-lg font-semibold">Recent results</h2>
        <div className="mt-3 overflow-x-auto rounded-xl border border-[color:var(--color-border)]">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="bg-[color:var(--color-surface)] text-xs uppercase tracking-wide text-[color:var(--color-text-muted)]">
              <tr>
                <Th>Scenario</Th>
                <Th>Session</Th>
                <Th>Score</Th>
                <Th>Risk</Th>
                <Th>Action / State</Th>
              </tr>
            </thead>
            <tbody>
              {history.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-[color:var(--color-text-muted)]">
                    Run a scenario above to see its effect here.
                  </td>
                </tr>
              )}
              {history.map((r, i) => (
                <tr
                  key={i}
                  className="border-t border-[color:var(--color-border)] bg-[color:var(--color-bg)]"
                >
                  <Td className="text-xs">{r.scenario}</Td>
                  <Td className="font-mono text-xs">{r.session_id.slice(0, 12)}…</Td>
                  <Td className="tabular-nums text-xs">
                    {r.previous_score != null && r.new_score != null
                      ? `${r.previous_score} → ${r.new_score}`
                      : '—'}
                  </Td>
                  <Td>
                    {r.previous_risk && r.new_risk ? (
                      <span className="flex items-center gap-1">
                        <RiskBadge level={r.previous_risk as RiskLevel} />
                        <span className="text-xs">→</span>
                        <RiskBadge level={r.new_risk as RiskLevel} />
                      </span>
                    ) : (
                      '—'
                    )}
                  </Td>
                  <Td className="text-xs">{r.action ?? r.state ?? '—'}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-[color:var(--color-text-muted)]">{label}</dt>
      <dd className="text-sm">{value}</dd>
    </div>
  )
}

function Th({ children }: { children: ReactNode }) {
  return <th className="px-4 py-2 font-medium">{children}</th>
}

function Td({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <td className={`px-4 py-2 align-middle ${className}`}>{children}</td>
}
