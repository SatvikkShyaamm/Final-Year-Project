/**
 * Shared frontend types.
 *
 * Kept minimal in Module 1 — only the shape of the real /health endpoint.
 * Each later module adds its own types here (User, Session, TrustScore,
 * MFAChallenge, ACLRule, SecurityAlert, ...) mirroring backend/app/schemas.
 */

export interface HealthResponse {
  status: 'ok' | 'degraded'
  project: string
  environment: string
  dependencies: {
    database: 'connected' | 'unreachable'
    redis: 'connected' | 'unreachable'
  }
}

/** Risk tiers used across the dashboard from Module 5 onward. */
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH'

/* --------------------------------------------------------------------------
 * Module 2 — Authentication
 * Mirrors backend/app/schemas/auth.py. Keep these in sync when the backend
 * contract changes.
 * ---------------------------------------------------------------------- */

export type UserRole = 'user' | 'admin'

export interface User {
  id: number
  username: string
  email: string
  role: UserRole
  is_active: boolean
  created_at: string
  last_login_at: string | null
}

/** Response of POST /auth/register, POST /mfa/verify, and the allow branch of
 * POST /auth/login. */
export interface AuthToken {
  access_token: string
  token_type: 'bearer'
  expires_in: number
  user: User
}

export interface LoginCredentials {
  username: string
  password: string
}

export interface RegisterPayload {
  username: string
  email: string
  password: string
}

/* --------------------------------------------------------------------------
 * Module 6 — Adaptive MFA
 * Mirrors backend/app/schemas/mfa.py + the LoginResponse in schemas/auth.py.
 * ---------------------------------------------------------------------- */

export interface MFAEnrollment {
  secret: string
  provisioning_uri: string
  digits: number
  interval_seconds: number
}

export type MFAChallengeStatus = 'pending' | 'verified' | 'failed' | 'expired'

/** A live challenge to satisfy — from /auth/login or POST /mfa/challenge. */
export interface MFAChallenge {
  challenge_id: string
  mfa_token: string
  method: string
  reason: string
  status: MFAChallengeStatus
  expires_at: string
  attempts_remaining: number
  max_attempts: number
  trust_score: number | null
  risk_level: RiskLevel | null
  enrollment: MFAEnrollment | null
  dev_code: string | null
}

/** POST /auth/login response — `mfa_required` is the discriminator. */
export interface LoginResponse {
  mfa_required: boolean
  decision: 'allow' | 'mfa'
  trust_score: number | null
  risk_level: RiskLevel | null
  access_token: string | null
  token_type: 'bearer' | null
  expires_in: number | null
  user: User | null
  mfa: MFAChallenge | null
}

/** Read-only challenge record (admin feed / status poll). */
export interface MFAChallengeRecord {
  id: string
  user_id: number
  username: string | null
  method: string
  reason: string
  status: MFAChallengeStatus
  attempts: number
  max_attempts: number
  trust_score: number | null
  risk_level: RiskLevel | null
  created_at: string
  expires_at: string
  verified_at: string | null
}

export interface MFAChallengeListResponse {
  challenges: MFAChallengeRecord[]
  counts: Record<string, number>
  generated_at: string
}

/* --------------------------------------------------------------------------
 * Module 3 — Session Lifecycle
 * Mirrors backend/app/schemas/session.py.
 * ---------------------------------------------------------------------- */

export type SessionState = 'active' | 'terminated'

export interface Session {
  id: string
  user_id: number
  username: string | null
  ip_address: string | null
  user_agent: string | null
  state: SessionState
  ws_connected: boolean
  created_at: string
  last_seen_at: string
  terminated_at: string | null
  termination_reason: string | null
  duration_seconds: number
  /** Reserved — filled in by Modules 4/5. Always null in Module 3. */
  trust_score: number | null
  risk_level: RiskLevel | null
  acl_status: string | null
}

export interface SessionListResponse {
  sessions: Session[]
  active_count: number
  generated_at: string
}

/** State of the client's own signalling WebSocket. */
export type SessionSocketStatus =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'disconnected'

/* --------------------------------------------------------------------------
 * Module 4 — Dynamic ACL Management
 * Mirrors backend/app/schemas/acl.py.
 * ---------------------------------------------------------------------- */

export type ACLState = 'pending' | 'active' | 'removing' | 'removed' | 'failed'

export interface ACLRule {
  id: string
  session_id: string
  user_id: number
  username: string | null
  client_ip: string
  resource: string
  ipset_name: string
  state: ACLState
  enforcement: 'ipset' | 'simulated'
  created_at: string
  activated_at: string | null
  removed_at: string | null
  authorization_latency_ms: number | null
  revocation_latency_ms: number | null
  removal_reason: string | null
  last_error: string | null
}

export interface ACLRuleListResponse {
  rules: ACLRule[]
  active_count: number
  enforcement_backend: string
  avg_authorization_latency_ms: number | null
  avg_revocation_latency_ms: number | null
  generated_at: string
}

export interface ACLStatusResponse {
  enforcement_backend: string
  worker_enabled: boolean
  queue_depth: number
  active_rules: number
  kernel_entries: Record<string, number>
  generated_at: string
}

/* --------------------------------------------------------------------------
 * Module 5 — Trust Score Engine
 * Mirrors backend/app/schemas/trust_score.py.
 * ---------------------------------------------------------------------- */

export type FactorKind = 'baseline' | 'positive' | 'negative'

export interface TrustFactor {
  factor_name: string
  factor_kind: FactorKind
  weight_applied: number
  reason: string
}

export interface SessionTrustScore {
  session_id: string
  user_id: number
  username: string | null
  trust_score: number | null
  risk_level: RiskLevel | null
  evaluated_at: string | null
  factors: TrustFactor[]
}

export interface TrustScoreHistoryEntry {
  session_id: string
  trust_score: number | null
  risk_level: RiskLevel | null
  created_at: string
  ip_address: string | null
  state: SessionState
}

export interface TrustScoreHistoryResponse {
  user_id: number
  username: string | null
  entries: TrustScoreHistoryEntry[]
  average_trust_score: number | null
}

export interface TrustFactorCatalogEntry {
  factor_name: string
  factor_kind: FactorKind
  weight: number
  applies_when: string
}

export interface TrustScoreConfigResponse {
  baseline: number
  risk_bands: Record<string, string>
  factors: TrustFactorCatalogEntry[]
  failed_login_threshold: number
  failed_login_window_minutes: number
  approved_vpn_cidrs: string[]
  known_vpn_cidrs: string[]
  known_vpn_list_is_static_sample: boolean
  generated_at: string
}
