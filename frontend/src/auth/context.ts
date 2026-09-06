import { createContext } from 'react'
import type { LoginCredentials, RegisterPayload, User } from '../types'

/**
 * Auth context shape (Module 2). Split from the provider component and the
 * `useAuth` hook so each file has a single kind of export (keeps the
 * fast-refresh / only-export-components lint rule happy).
 */
export type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated'

export interface AuthContextValue {
  user: User | null
  status: AuthStatus
  isAdmin: boolean
  login: (credentials: LoginCredentials) => Promise<User>
  register: (payload: RegisterPayload) => Promise<User>
  logout: () => Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)
