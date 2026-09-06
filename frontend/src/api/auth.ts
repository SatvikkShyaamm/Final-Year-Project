import { apiClient } from './client'
import type {
  AuthToken,
  LoginCredentials,
  RegisterPayload,
  User,
} from '../types'

/**
 * Typed wrappers over the Module 2 backend auth endpoints. All token handling
 * (storage, header injection, 401 handling) lives in the axios client and the
 * auth context — these functions just describe the HTTP contract.
 */

export async function login(credentials: LoginCredentials): Promise<AuthToken> {
  const { data } = await apiClient.post<AuthToken>('/api/v1/auth/login', credentials)
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
  if (typeof error === 'object' && error !== null && 'response' in error) {
    const detail = (error as { response?: { data?: { detail?: unknown } } })
      .response?.data?.detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail) && detail[0]?.msg) return String(detail[0].msg)
  }
  return fallback
}
