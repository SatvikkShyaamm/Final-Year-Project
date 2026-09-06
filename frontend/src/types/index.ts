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

/** Response of POST /auth/login and POST /auth/register. */
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
