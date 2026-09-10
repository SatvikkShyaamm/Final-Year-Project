import { createContext } from 'react'
import type {
  LoginCredentials,
  MFAChallenge,
  RegisterPayload,
  User,
} from '../types'

/**
 * Auth context shape (Module 2, + the Module 6 MFA step). Split from the
 * provider component and the `useAuth` hook so each file has a single kind of
 * export (keeps the fast-refresh / only-export-components lint rule happy).
 */
export type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated'

/** Result of `login()` — either straight in, or an MFA challenge to satisfy. */
export type LoginOutcome =
  | { kind: 'authenticated'; user: User }
  | { kind: 'mfa_required'; challenge: MFAChallenge }

export interface AuthContextValue {
  user: User | null
  status: AuthStatus
  isAdmin: boolean
  login: (credentials: LoginCredentials) => Promise<LoginOutcome>
  /** Complete the Module 6 MFA step with the mfa_token from a `mfa_required`
   * outcome and the code emailed to the user's registered address. Resolves
   * to the now-authenticated user. */
  verifyMfa: (mfaToken: string, code: string) => Promise<User>
  register: (payload: RegisterPayload) => Promise<User>
  logout: () => Promise<void>
  /**
   * Locally drop the token and mark the app logged out, WITHOUT calling
   * /auth/logout. For when the backend has already ended this session on its
   * own (admin terminate, idle/lifetime sweep, a future risk-based
   * revocation) and pushed session.terminated — the server already knows;
   * this just brings the client's auth state in line with it so
   * ProtectedRoute sends the user back to /login. `logout()` above is for
   * the user's own "Log out" click, which should still notify the server.
   */
  forceLogout: () => void
}

export const AuthContext = createContext<AuthContextValue | null>(null)
