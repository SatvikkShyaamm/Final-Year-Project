import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { listSessions } from '../../api/sessions'
import {
  getSessionTrustScore,
  getTrustScoreConfig,
  getUserTrustHistory,
} from '../../api/trustScore'
import { RiskBadge } from '../../components/common/RiskBadge'
import type {
  RiskLevel,
  Session,
  SessionTrustScore,
  TrustScoreConfigResponse,
  TrustScoreHistoryResponse,
} from '../../types'

/**
 * Module 5 — real Trust Score Monitoring. Pick a session, see its static score
 * (computed at session creation from the Section-6 factor table), the exact
 * per-factor breakdown behind it, that user's score history, and the live
 * weight table. All values are real backend state.
 */
const POLL_MS = 5000

export function TrustScorePage() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [score, setScore] = useState<SessionTrustScore | null>(null)
  const [history, setHistory] = useState<TrustScoreHistoryResponse | null>(null)
  const [config, setConfig] = useState<TrustScoreConfigResponse | null>(null)
  const [showConfig, setShowConfig] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadSessions = useCallback(async () => {
    try {
      const data = await listSessions(true)
      setSessions(data.sessions)
      setSelectedId((cur) =>
        cur && data.sessions.some((s) => s.id === cur)
          ? cur
          : (data.sessions[0]?.id ?? null),
      )
      setError(null)
    } catch {
      setError('Could not load sessions from the backend.')
    }
  }, [])

  useEffect(() => {
    void loadSessions()
    void getTrustScoreConfig().then(setConfig).catch(() => undefined)
    const t = window.setInterval(() => void loadSessions(), POLL_MS)
    return () => window.clearInterval(t)
  }, [loadSessions])

  useEffect(() => {
    if (!selectedId) {
      setScore(null)
      setHistory(null)
      return
    }
    let cancelled = false
    async function load() {
      try {
        const s = await getSessionTrustScore(selectedId as string)
        if (cancelled) return
        setScore(s)
        const h = await getUserTrustHistory(s.user_id)
        if (!cancelled) setHistory(h)
      } catch {
        if (!cancelled) setError('Could not load the trust score for that session.')
      }
    }
    void load()
    const t = window.setInterval(load, POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(t)
    }
  }, [selectedId])

  const chartData = useMemo(
    () =>
      (history?.entries ?? [])
        .slice()
        .reverse()
        .map((e, i) => ({
          i: i + 1,
          score: e.trust_score ?? null,
          label: new Date(e.created_at + 'Z').toLocaleString(),
        })),
    [history],
  )

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Trust Score Monitoring</h1>
          <p className="mt-1 text-sm text-[color:var(--color-text-muted)]">
            Static score at session creation · Section-6 factor table · auto-refreshing
          </p>
        </div>
        <label className="text-xs text-[color:var(--color-text-muted)]">
          Session&nbsp;
          <select
            value={selectedId ?? ''}
            onChange={(e) => setSelectedId(e.target.value || null)}
            className="rounded-md border border-[color:var(--color-border)] bg-[color:var(--color-bg)] px-2 py-1 text-xs text-[color:var(--color-text)]"
          >
            {sessions.length === 0 && <option value="">no sessions</option>}
            {sessions.map((s) => (
              <option key={s.id} value={s.id}>
                {(s.username ?? `#${s.user_id}`) + ' · ' + s.id.slice(0, 8) + '… · ' + s.state}
              </option>
            ))}
          </select>
        </label>
      </div>

      {error && (
        <p className="mt-4 text-sm text-[color:var(--color-risk-high)]">{error}</p>
      )}

      {!score ? (
        <p className="mt-6 text-sm text-[color:var(--color-text-muted)]">
          {sessions.length === 0
            ? 'No sessions yet — open one from the user portal.'
            : 'Select a session.'}
        </p>
      ) : (
        <div className="mt-6 grid gap-4 lg:grid-cols-3">
          {/* score + meter */}
          <div className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6">
            <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
              {score.username ?? `user #${score.user_id}`}
            </p>
            <div className="mt-2 flex items-baseline gap-3">
              <span className="text-4xl font-semibold">{score.trust_score ?? '—'}</span>
              <span className="text-sm text-[color:var(--color-text-muted)]">/ 100</span>
              {score.risk_level && <RiskBadge level={score.risk_level as RiskLevel} />}
            </div>
            <ScoreMeter value={score.trust_score ?? 0} risk={score.risk_level} />
            <p className="mt-3 text-xs text-[color:var(--color-text-muted)]">
              evaluated{' '}
              {score.evaluated_at
                ? new Date(score.evaluated_at + 'Z').toLocaleString()
                : '—'}
            </p>
          </div>

          {/* factor breakdown */}
          <div className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6 lg:col-span-2">
            <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
              Factors affecting score
            </p>
            <table className="mt-3 w-full text-left text-sm">
              <tbody>
                {score.factors.map((f, idx) => (
                  <tr
                    key={idx}
                    className="border-t border-[color:var(--color-border)] first:border-t-0"
                  >
                    <td className="py-1.5 font-mono text-xs">{f.factor_name}</td>
                    <td className="py-1.5 text-xs text-[color:var(--color-text-muted)]">
                      {f.reason}
                    </td>
                    <td
                      className={`py-1.5 text-right font-semibold tabular-nums ${
                        f.factor_kind === 'negative'
                          ? 'text-[color:var(--color-risk-high)]'
                          : f.factor_kind === 'positive'
                            ? 'text-[color:var(--color-risk-low)]'
                            : 'text-[color:var(--color-text)]'
                      }`}
                    >
                      {f.weight_applied > 0 ? `+${f.weight_applied}` : f.weight_applied}
                    </td>
                  </tr>
                ))}
                <tr className="border-t-2 border-[color:var(--color-border)]">
                  <td className="py-1.5 text-xs font-semibold uppercase tracking-wide">
                    Total
                  </td>
                  <td />
                  <td className="py-1.5 text-right font-semibold tabular-nums">
                    {score.trust_score ?? '—'}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          {/* history chart */}
          <div className="rounded-xl border border-[color:var(--color-border)] bg-[color:var(--color-surface)] p-6 lg:col-span-3">
            <div className="flex items-center justify-between">
              <p className="text-xs font-medium uppercase tracking-wide text-[color:var(--color-text-muted)]">
                {score.username ?? 'user'} — trust score history
              </p>
              <p className="text-xs text-[color:var(--color-text-muted)]">
                avg {history?.average_trust_score ?? '—'}
              </p>
            </div>
            <div className="mt-3 h-48">
              {chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chartData} margin={{ top: 8, right: 12, bottom: 4, left: -16 }}>
                    <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" />
                    <XAxis dataKey="i" stroke="var(--color-text-muted)" fontSize={11} />
                    <YAxis domain={[0, 100]} stroke="var(--color-text-muted)" fontSize={11} />
                    <ReferenceLine y={80} stroke="var(--color-risk-low)" strokeDasharray="2 2" />
                    <ReferenceLine y={50} stroke="var(--color-risk-medium)" strokeDasharray="2 2" />
                    <Tooltip
                      contentStyle={{
                        background: 'var(--color-surface-alt)',
                        border: '1px solid var(--color-border)',
                        fontSize: 12,
                      }}
                      labelFormatter={(_, p) => p?.[0]?.payload?.label ?? ''}
                    />
                    <Line
                      type="monotone"
                      dataKey="score"
                      stroke="var(--color-accent)"
                      strokeWidth={2}
                      dot={{ r: 3 }}
                      connectNulls
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-sm text-[color:var(--color-text-muted)]">
                  No history yet for this user.
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* config reference */}
      <div className="mt-6">
        <button
          onClick={() => setShowConfig((v) => !v)}
          className="text-xs text-[color:var(--color-text-muted)] hover:text-[color:var(--color-text)]"
        >
          {showConfig ? '▾' : '▸'} Weight table &amp; risk bands (live config)
        </button>
        {showConfig && config && (
          <div className="mt-3 overflow-x-auto rounded-xl border border-[color:var(--color-border)]">
            <table className="w-full min-w-[600px] text-left text-sm">
              <thead className="bg-[color:var(--color-surface)] text-xs uppercase tracking-wide text-[color:var(--color-text-muted)]">
                <tr>
                  <Th>Factor</Th>
                  <Th>Kind</Th>
                  <Th>Weight</Th>
                  <Th>Applies when</Th>
                </tr>
              </thead>
              <tbody>
                {config.factors.map((f) => (
                  <tr
                    key={f.factor_name}
                    className="border-t border-[color:var(--color-border)] bg-[color:var(--color-bg)]"
                  >
                    <td className="px-4 py-1.5 font-mono text-xs">{f.factor_name}</td>
                    <td className="px-4 py-1.5 text-xs">{f.factor_kind}</td>
                    <td className="px-4 py-1.5 tabular-nums">
                      {f.factor_kind === 'negative' ? `-${f.weight}` : `+${f.weight}`}
                    </td>
                    <td className="px-4 py-1.5 text-xs text-[color:var(--color-text-muted)]">
                      {f.applies_when}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="border-t border-[color:var(--color-border)] px-4 py-2 text-xs text-[color:var(--color-text-muted)]">
              Risk bands — LOW {config.risk_bands.LOW} · MEDIUM {config.risk_bands.MEDIUM} ·
              HIGH {config.risk_bands.HIGH}. Failed-login penalty at{' '}
              {config.failed_login_threshold}+ attempts in{' '}
              {config.failed_login_window_minutes} min.
              {config.known_vpn_list_is_static_sample &&
                ' Known-VPN list is a static demo sample, not a live feed.'}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

function ScoreMeter({ value, risk }: { value: number; risk: RiskLevel | null }) {
  const pct = Math.max(0, Math.min(100, value))
  const color =
    risk === 'LOW'
      ? 'var(--color-risk-low)'
      : risk === 'HIGH'
        ? 'var(--color-risk-high)'
        : 'var(--color-risk-medium)'
  return (
    <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-[color:var(--color-surface-alt)]">
      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
    </div>
  )
}

function Th({ children }: { children: ReactNode }) {
  return <th className="px-4 py-2 font-medium">{children}</th>
}
