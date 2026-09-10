import { apiClient } from './client'
import type {
  AuthToken,
  LoginCredentials,
  LoginResponse,
  RegisterPayload,
  User,
} from '../types'

/**
 * Typed wrappers over the auth endpoints. All token handling (storage, header
 * injection, 401 handling) lives in the axios client and the auth context.
 *
 * Module 6: /auth/login is now a risk decision — it returns either an access
 * token (LOW) or an MFA challenge (MEDIUM), or fails 403 (HIGH). Completing the
 * challenge at /mfa/verify returns a normal AuthToken.
 */

export async function login(credentials: LoginCredentials): Promise<LoginResponse> {
  const { data } = await apiClient.post<LoginResponse>('/api/v1/auth/login', credentials)
  return data
}

export async function verifyMfa(body: {
  mfa_token: string
  code: string
}): Promise<AuthToken> {
  const { data } = await apiClient.post<AuthToken>('/api/v1/mfa/verify', body)
  return data
}

export async function register(payload: RegisterPayload): Promise<AuthToken> {
  const { data } = await apiClient.post<AuthToken>('/api/v1/auth/register', payload)
  return data
}

export async function fetchCurrentUser(): Promise<User> {
  const { data } = await apiClient.get<User>('/api/v1/auth/me')
  return data
}

export async function logout(): Promise<void> {
  // Best-effort server notification; the real state change is dropping the
  // token on the client (the JWT is stateless).
  try {
    await apiClient.post('/api/v1/auth/logout')
  } catch {
    /* ignore — logout must always succeed locally */
  }
}

/** Pull a human-readable message out of an axios error from these endpoints. */
export function authErrorMessage(error: unknown, fallback: string): string {
  const detail = axiosErrorDetail(error)
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg)
  if (detail && typeof detail === 'object' && 'message' in detail) {
    return String((detail as { message: unknown }).message)
  }
  return fallback
}

/** The raw `detail` payload of a FastAPI error response (string, list, or the
 * structured objects Module 6's block / MFA-verify errors return). */
export function axiosErrorDetail(error: unknown): unknown {
  if (typeof error === 'object' && error !== null && 'response' in error) {
    return (error as { response?: { data?: { detail?: unknown } } }).response?.data
      ?.detail
  }
  return undefined
}
