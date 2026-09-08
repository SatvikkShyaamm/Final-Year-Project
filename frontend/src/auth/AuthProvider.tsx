import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import {
  fetchCurrentUser,
  login as apiLogin,
  logout as apiLogout,
  register as apiRegister,
} from '../api/auth'
import type { LoginCredentials, RegisterPayload, User } from '../types'
import { AuthContext } from './context'
import type { AuthStatus } from './context'
import { clearToken, getToken, setToken } from './tokenStore'

/**
 * Holds the authenticated user for the whole app (Module 2).
 *
 * On mount it rehydrates from a persisted JWT by calling /auth/me — so a
 * page refresh keeps you logged in, but a token the backend now rejects
 * (expired, wrong secret, deleted user) cleanly falls back to logged-out.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [status, setStatus] = useState<AuthStatus>(
    getToken() ? 'loading' : 'unauthenticated',
  )

  useEffect(() => {
    if (!getToken()) return
    let cancelled = false
    fetchCurrentUser()
      .then((me) => {
        if (cancelled) return
        setUser(me)
        setStatus('authenticated')
      })
      .catch(() => {
        if (cancelled) return
        clearToken()
        setUser(null)
        setStatus('unauthenticated')
      })
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (credentials: LoginCredentials) => {
    const auth = await apiLogin(credentials)
    setToken(auth.access_token)
    setUser(auth.user)
    setStatus('authenticated')
    return auth.user
  }, [])

  const register = useCallback(async (payload: RegisterPayload) => {
    const auth = await apiRegister(payload)
    setToken(auth.access_token)
    setUser(auth.user)
    setStatus('authenticated')
    return auth.user
  }, [])

  const logout = useCallback(async () => {
    await apiLogout()
    clearToken()
    setUser(null)
    setStatus('unauthenticated')
  }, [])

  /**
   * Local-only counterpart to `logout()` — no /auth/logout call. Used when
   * the *server* already ended this session (session.terminated arrived on
   * the signalling socket) rather than the user asking to leave. See the
   * doc comment on AuthContextValue.forceLogout.
   */
  const forceLogout = useCallback(() => {
    clearToken()
    setUser(null)
    setStatus('unauthenticated')
  }, [])

  const value = useMemo(
    () => ({
      user,
      status,
      isAdmin: user?.role === 'admin',
      login,
      register,
      logout,
      forceLogout,
    }),
    [user, status, login, register, logout, forceLogout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
